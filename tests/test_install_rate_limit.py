"""Public checks behind Tele2's carrier-grade NAT (report 2026-09-25, 'shared IP').

Hundreds to thousands of phones leave through one public IPv4. Limited per
IP (60/h, 5 fresh/min), one busy gateway would 429 everyone behind it and
the phone's background link check would silently stop working. A client
that sends a valid `X-Cleanway-Install: <UUID>` is limited per install
instead, under a much higher per-IP ceiling. No header — or a malformed one
— means exactly the old per-IP behaviour.
"""
from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.models.schemas import DomainResult, RiskLevel
from api.routers import public as public_router
from api.services import rate_limiter

CGNAT_IP = {"x-forwarded-for": "100.64.12.34"}


class _CountingRedis:
    """INCR+TTL (the limiter's Lua), GET/SETEX for the public cache."""

    def __init__(self):
        self.counts: dict[str, int] = {}
        self.kv: dict[str, str] = {}

    async def eval(self, _script, _numkeys, key, *args):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def ttl(self, key):
        return 60

    async def get(self, key):
        return None  # always a cache miss: every request is a fresh check

    async def setex(self, key, ttl, value):
        self.kv[key] = value


@pytest.fixture
def counting_redis(monkeypatch):
    fake = _CountingRedis()

    async def _get():
        return fake

    monkeypatch.setattr(rate_limiter, "get_redis", _get)
    monkeypatch.setattr("api.services.cache.get_redis", _get)
    return fake


@pytest.fixture
def limits(monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "benchmark_bypass_token", "", raising=False)
    monkeypatch.setattr(s, "public_rate_limit_per_window", 3, raising=False)
    monkeypatch.setattr(s, "public_install_rate_limit_per_window", 3, raising=False)
    monkeypatch.setattr(s, "public_install_ip_ceiling_per_window", 8, raising=False)
    monkeypatch.setattr(s, "public_fresh_checks_per_minute", 100, raising=False)
    monkeypatch.setattr(s, "public_fresh_ip_ceiling_per_minute", 100, raising=False)
    return s


@pytest.fixture
def quick_analysis(monkeypatch):
    from api.services import analyzer

    async def _analyze(domain, *a, **k):
        return DomainResult(domain=domain, score=10, level=RiskLevel.safe, reasons=[],
                            verdict_basis="heuristics")

    async def _not_listed(d):
        return False

    monkeypatch.setattr(analyzer, "analyze_domain", _analyze)
    monkeypatch.setattr(public_router, "is_listed", _not_listed)


def _get(client, install=None, domain="obscure-shop.ru"):
    headers = dict(CGNAT_IP)
    if install is not None:
        headers["X-Cleanway-Install"] = install
    return client.get(f"/api/v1/public/check/{domain}", headers=headers)


# ── Header validation ──

class _Req:
    def __init__(self, value):
        self.headers = {} if value is None else {"X-Cleanway-Install": value}


@pytest.mark.parametrize("value", [
    None, "", "not-a-uuid", "12345", "0" * 36,
    "3f2b1c9e-7a4d-4e8b-9c1a-2b3c4d5e6f7", "3f2b1c9e7a4d4e8b9c1a2b3c4d5e6f70",
    "3f2b1c9e-7a4d-4e8b-9c1a-2b3c4d5e6f70 x", "3f2b1c9e-7a4d-4e8b-9c1a-2b3c4d5e6f70\nx",
    "{3f2b1c9e-7a4d-4e8b-9c1a-2b3c4d5e6f70}", "../../etc/passwd",
])
def test_malformed_header_is_ignored(value):
    assert rate_limiter.install_key(_Req(value)) is None


def test_surrounding_whitespace_is_tolerated():
    """Leading/trailing whitespace is HTTP's optional whitespace around a
    header value; proxies may add it. Anything inside the value is not."""
    raw = "3f2b1c9e-7a4d-4e8b-9c1a-2b3c4d5e6f70"
    assert rate_limiter.install_key(_Req(f"  {raw} ")) == rate_limiter.install_key(_Req(raw))


def test_valid_header_becomes_a_hash_not_the_id():
    raw = str(uuid.uuid4())
    key = rate_limiter.install_key(_Req(raw))
    assert key is not None and len(key) == 32
    assert raw.replace("-", "") not in key
    assert rate_limiter.install_key(_Req(raw.upper())) == key  # case-insensitive


# ── Hourly limit on the route ──

def test_without_header_behaviour_is_unchanged(counting_redis, limits, quick_analysis):
    client = TestClient(app)
    codes = [_get(client).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]


def test_many_installs_behind_one_ip_are_not_starved(counting_redis, limits, quick_analysis):
    """Six phones, one IP: per-IP limiting would have cut them off at 3."""
    client = TestClient(app)
    installs = [str(uuid.uuid4()) for _ in range(4)]
    codes = [_get(client, i).status_code for i in installs for _ in range(2)]
    assert codes == [200] * 8


def test_each_install_keeps_its_own_limit(counting_redis, limits, quick_analysis):
    client = TestClient(app)
    one = str(uuid.uuid4())
    codes = [_get(client, one).status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]
    assert _get(client, str(uuid.uuid4())).status_code == 200


def test_ip_ceiling_still_bounds_one_address(counting_redis, limits, quick_analysis):
    """Random ids per request cannot buy unlimited checks from one IP."""
    client = TestClient(app)
    codes = [_get(client, str(uuid.uuid4())).status_code for _ in range(9)]
    assert codes[:8] == [200] * 8
    assert codes[8] == 429
    assert _get(client, "garbage").status_code == 200  # header-less bucket is separate


def test_malformed_header_falls_back_to_ip_limit(counting_redis, limits, quick_analysis):
    client = TestClient(app)
    codes = [_get(client, "not-a-uuid").status_code for _ in range(4)]
    assert codes == [200, 200, 200, 429]


def test_install_id_never_stored_raw(counting_redis, limits, quick_analysis):
    raw = str(uuid.uuid4())
    _get(TestClient(app), raw)
    assert not any(raw in k for k in counting_redis.counts)
    assert any(k.startswith("rate:install:public_check:") for k in counting_redis.counts)


# ── The per-minute fresh-analysis cap ──

def test_fresh_cap_is_per_install_under_an_ip_ceiling(counting_redis, limits, quick_analysis):
    limits.public_rate_limit_per_window = 1000
    limits.public_install_rate_limit_per_window = 1000
    limits.public_install_ip_ceiling_per_window = 1000
    limits.public_fresh_checks_per_minute = 2
    limits.public_fresh_ip_ceiling_per_minute = 5
    client = TestClient(app)

    one = str(uuid.uuid4())
    assert [_get(client, one, f"fresh-a{i}-cwtest.ru").status_code for i in range(3)] == [200, 200, 429]
    # Other phones on the same IP still get fresh checks, up to the ceiling.
    others = [_get(client, str(uuid.uuid4()), f"fresh-b{i}-cwtest.ru").status_code for i in range(4)]
    assert others == [200, 200, 200, 429]


def test_fresh_cap_without_header_is_per_ip(counting_redis, limits, quick_analysis):
    limits.public_rate_limit_per_window = 1000
    limits.public_fresh_checks_per_minute = 2
    client = TestClient(app)
    assert [_get(client, None, f"fresh-a{i}-cwtest.ru").status_code for i in range(3)] == [200, 200, 429]


def test_benchmark_bypass_also_skips_the_fresh_cap(counting_redis, limits, quick_analysis):
    """config.benchmark_bypass_token promises to skip the 5/min cap too; the
    inline cap ignored it, so the weekly benchmark got 429s."""
    limits.benchmark_bypass_token = "bench-token-for-tests"
    limits.public_fresh_checks_per_minute = 1
    client = TestClient(app)
    headers = {**CGNAT_IP, "X-Cleanway-Benchmark": "bench-token-for-tests"}
    codes = [client.get(f"/api/v1/public/check/fresh-c{i}-cwtest.ru", headers=headers).status_code for i in range(3)]
    assert codes == [200, 200, 200]

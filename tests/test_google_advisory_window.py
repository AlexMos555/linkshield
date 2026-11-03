"""A verdict resting on Google is kept no longer than Google's answer is valid.

Web Risk's rules for warnings (docs.cloud.google.com/web-risk/docs/
user-warnings, read 2026-11-04): a warning can be shown only while "a URL
matches a threat entry and the cached response is still valid at the time a
warning is shown. Under no other circumstances may a warning be shown." The
Web Risk client caches a match until its expireTime, at most an hour
(web_risk.positive_ttl). The public check kept the whole verdict for a day,
the signed-in check for up to 15 minutes, and every client cached the answer
again on top — so a warning signed "Advisory provided by Google" could appear
a day after Google answered, after Google had delisted the site.

Now: the life left in Google's cached answer (safe_browsing.
threat_seconds_left) caps both server caches, and the public response says
it (`advisory_ttl`) so the extension, the app and the website cap theirs.
"""
from __future__ import annotations

import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.models.schemas import DomainReason, DomainResult, RiskLevel
from api.routers import public as public_router
from api.services import cache as cache_service
from api.services import google_advisory
from api.services import safe_browsing as sb
from api.services.safe_browsing import CheckResult, CheckStatus, ThreatMatch


class _Redis:
    """get / ttl / setex, plus what the public route touches on the way."""

    def __init__(self) -> None:
        self.kv: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def get(self, key):
        return self.kv.get(key)

    async def ttl(self, key):
        if key not in self.kv:
            return -2
        return self.ttls.get(key, -1)

    async def setex(self, key, ttl, value):
        self.kv[key] = value
        self.ttls[key] = int(ttl)
        return True

    async def eval(self, *a, **k):
        return 1

    def pipeline(self):
        class _Pipe:
            def __init__(self):
                self.n = 0

            def sismember(self, *a):
                self.n += 1

            async def execute(self):
                return [False] * self.n

        return _Pipe()


@pytest.fixture
def redis(monkeypatch):
    fake = _Redis()

    async def _get():
        return fake

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    monkeypatch.setattr(sb, "get_redis", _get)
    return fake


@pytest.fixture(autouse=True)
def no_competitors(monkeypatch):
    """The cache-hit path asks Cloudflare's filter too: not from a test."""
    async def _none(*a, **k):
        return []

    monkeypatch.setattr("api.services.competitor_verdicts.gather_competitor_verdicts", _none)


@pytest.fixture
def web_risk(monkeypatch):
    """Web Risk is the active backend (production since 2026-11-03)."""
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "web_risk_api_key", "test-key", raising=False)
    sb.reset_client()
    yield
    sb.reset_client()


def _threat(domain: str) -> str:
    return json.dumps(CheckResult(
        status=CheckStatus.threat,
        matches=(ThreatMatch(url=f"http://{domain}/", threat_type="SOCIAL_ENGINEERING", cache_duration=1200),),
    ).to_dict())


def _google_result(domain: str = "flagged.example") -> DomainResult:
    return DomainResult(
        domain=domain, score=80, level=RiskLevel.dangerous, verdict_basis="threat_intel",
        reasons=[DomainReason(signal="safe_browsing", detail="Google lists this site as possibly unsafe", weight=80)],
    )


def _other_result(domain: str = "other.example") -> DomainResult:
    return DomainResult(
        domain=domain, score=80, level=RiskLevel.dangerous, verdict_basis="threat_intel",
        reasons=[DomainReason(signal="phishstats", detail="Listed in PhishStats", weight=80)],
    )


# ── How long Google's answer is still valid ──────────────────────────


def test_life_left_is_the_cached_matchs_own(redis, web_risk):
    redis.kv["wr:flagged.example"] = _threat("flagged.example")
    redis.ttls["wr:flagged.example"] = 1200
    # One second kept back: Redis rounds a TTL to the second.
    assert asyncio.run(sb.threat_seconds_left("flagged.example")) == 1199


def test_no_life_left_for_a_safe_answer_or_none(redis, web_risk):
    redis.kv["wr:delisted.example"] = json.dumps(CheckResult(status=CheckStatus.safe).to_dict())
    redis.ttls["wr:delisted.example"] = 300
    assert asyncio.run(sb.threat_seconds_left("delisted.example")) == 0
    assert asyncio.run(sb.threat_seconds_left("never-asked.example")) == 0


def test_no_life_left_when_redis_is_down(monkeypatch, web_risk):
    async def _boom():
        raise ConnectionError("down")

    monkeypatch.setattr(sb, "get_redis", _boom)
    assert asyncio.run(sb.threat_seconds_left("flagged.example")) == 0


def test_the_active_backends_cache_is_the_one_read(redis, monkeypatch):
    """Safe Browsing v4 (no Web Risk key) keeps its answers under gsb:."""
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "web_risk_api_key", "", raising=False)
    monkeypatch.setattr(settings, "google_safe_browsing_key", "test-key", raising=False)
    sb.reset_client()
    try:
        redis.kv["gsb:flagged.example"] = _threat("flagged.example")
        redis.ttls["gsb:flagged.example"] = 600
        redis.kv["wr:flagged.example"] = _threat("flagged.example")
        redis.ttls["wr:flagged.example"] = 3000
        assert asyncio.run(sb.threat_seconds_left("flagged.example")) == 599
    finally:
        sb.reset_client()


def test_only_a_verdict_with_googles_reason_has_a_window(redis, web_risk):
    redis.kv["wr:flagged.example"] = _threat("flagged.example")
    redis.ttls["wr:flagged.example"] = 900
    assert asyncio.run(google_advisory.seconds_left(_google_result())) == 899
    assert asyncio.run(google_advisory.seconds_left(_other_result())) is None


# ── The public check's cache ─────────────────────────────────────────


def test_public_cache_keeps_a_google_verdict_only_while_googles_answer_lives():
    day = public_router._PUBLIC_CACHE_TTL_SECONDS
    assert public_router._public_cache_ttl(_google_result(), google_left=600) == 600
    assert public_router._public_cache_ttl(_google_result(), google_left=0) == 0
    assert public_router._public_cache_ttl(_other_result()) == day
    # A window longer than the usual lifetime never stretches it.
    assert public_router._public_cache_ttl(_google_result(), google_left=10 * day) == day


def test_public_cache_write_is_capped_and_skipped_without_a_window(redis, web_risk):
    redis.kv["wr:flagged.example"] = _threat("flagged.example")
    redis.ttls["wr:flagged.example"] = 1200
    asyncio.run(public_router._put_public_cache(_google_result()))
    key = public_router._PUBLIC_CACHE_PREFIX + "flagged.example"
    assert redis.ttls[key] == 1199

    # Google's answer is gone (expired, never cached, Redis lost it): the
    # verdict is not kept at all.
    asyncio.run(public_router._put_public_cache(_google_result("gone.example")))
    assert public_router._PUBLIC_CACHE_PREFIX + "gone.example" not in redis.kv

    asyncio.run(public_router._put_public_cache(_other_result()))
    assert redis.ttls[public_router._PUBLIC_CACHE_PREFIX + "other.example"] == public_router._PUBLIC_CACHE_TTL_SECONDS


def _analyzer_returns(monkeypatch, result: DomainResult) -> list[str]:
    calls: list[str] = []

    async def _analyze(domain, *a, **k):
        calls.append(domain)
        return result.model_copy(update={"domain": domain})

    from api.services import analyzer
    monkeypatch.setattr(analyzer, "analyze_domain", _analyze)
    return calls


def test_response_says_how_long_googles_part_stays_valid(redis, web_risk, monkeypatch):
    redis.kv["wr:flagged.example"] = _threat("flagged.example")
    redis.ttls["wr:flagged.example"] = 1500
    _analyzer_returns(monkeypatch, _google_result())
    body = TestClient(app).get("/api/v1/public/check/flagged.example").json()
    assert body["reason_codes"] == ["safe_browsing"]
    assert body["advisory_ttl"] == 1499


def test_response_has_no_window_without_googles_reason(redis, web_risk, monkeypatch):
    _analyzer_returns(monkeypatch, _other_result())
    body = TestClient(app).get("/api/v1/public/check/other.example").json()
    assert body["advisory_ttl"] is None


def test_response_window_is_zero_when_googles_answer_cannot_be_read(redis, web_risk, monkeypatch):
    """A fresh hit whose answer Redis did not keep: shown to this request,
    kept by no one."""
    _analyzer_returns(monkeypatch, _google_result())
    body = TestClient(app).get("/api/v1/public/check/flagged.example").json()
    assert body["advisory_ttl"] == 0
    assert public_router._PUBLIC_CACHE_PREFIX + "flagged.example" not in redis.kv


def test_cached_google_verdict_counts_down(redis, web_risk, monkeypatch):
    redis.kv["wr:flagged.example"] = _threat("flagged.example")
    redis.ttls["wr:flagged.example"] = 700
    redis.kv[public_router._PUBLIC_CACHE_PREFIX + "flagged.example"] = _google_result().model_dump_json()
    redis.ttls[public_router._PUBLIC_CACHE_PREFIX + "flagged.example"] = 690
    calls = _analyzer_returns(monkeypatch, _google_result())
    body = TestClient(app).get("/api/v1/public/check/flagged.example").json()
    assert calls == []
    assert body["advisory_ttl"] == 699


def test_cached_google_verdict_without_googles_answer_is_a_miss(redis, web_risk, monkeypatch):
    """The public copy outlived Google's answer (Redis evicted the shorter
    key): it is never served — the site is checked again."""
    redis.kv[public_router._PUBLIC_CACHE_PREFIX + "flagged.example"] = _google_result().model_dump_json()
    redis.ttls[public_router._PUBLIC_CACHE_PREFIX + "flagged.example"] = 690
    calls = _analyzer_returns(monkeypatch, _other_result())
    body = TestClient(app).get("/api/v1/public/check/flagged.example").json()
    assert calls == ["flagged.example"]
    assert body["reason_codes"] == ["phishstats"]


# ── The signed-in check's cache ──────────────────────────────────────


def test_signed_in_cache_keeps_a_google_verdict_only_while_googles_answer_lives(redis, web_risk):
    redis.kv["wr:flagged.example"] = _threat("flagged.example")
    redis.ttls["wr:flagged.example"] = 120
    asyncio.run(cache_service.cache_result(_google_result()))
    assert redis.ttls["check:flagged.example"] == 119

    asyncio.run(cache_service.cache_result(_google_result("gone.example")))
    assert "check:gone.example" not in redis.kv

    asyncio.run(cache_service.cache_result(_other_result()))
    assert redis.ttls["check:other.example"] == 300  # cache_ttl_dangerous, as before


def test_signed_in_cache_drops_a_google_verdict_whose_answer_is_gone(redis, web_risk):
    redis.kv["check:flagged.example"] = _google_result().model_dump_json()
    redis.ttls["check:flagged.example"] = 100
    assert asyncio.run(cache_service.get_cached_result("flagged.example")) is None
    redis.kv["wr:flagged.example"] = _threat("flagged.example")
    redis.ttls["wr:flagged.example"] = 200
    assert asyncio.run(cache_service.get_cached_result("flagged.example")) is not None

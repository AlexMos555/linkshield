"""GET /api/v1/blocklist/dns — the artifact the Android shield syncs.

The phone decides blocks locally on the FIRST lookup from this list; the
list is written by scripts/refresh_dangerous_domains.py into Redis
(`dangerous_domains:mobile:v1` + `:meta`) in the same transaction as the DoH
gateway's set. The router only serves bytes + validators — no per-request
computation, so it can never be the slow part.
"""
from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

BODY = "# cleanway-dns-blocklist v1 generated=1755530000 count=3 status=ok\nlist-canary.cleanway.ai\nphish.example\nscotiabano.com\n"
SHA = hashlib.sha256(BODY.encode()).hexdigest()


class _FakeRedis:
    def __init__(self, text=BODY, meta=None):
        self.text = text
        self.meta = meta if meta is not None else {"version": "1755530000", "sha256": SHA, "count": "3", "generated_at": "1755530000"}
        self.calls = 0

    async def get(self, key):
        return self.text if key == "dangerous_domains:mobile:v1" else None

    async def hgetall(self, key):
        return self.meta if key == "dangerous_domains:mobile:v1:meta" else {}

    async def incr(self, k):
        self.calls += 1
        return 1

    async def expire(self, k, s):
        return True

    async def ttl(self, k):
        return 3600

    async def eval(self, *a, **kw):
        return 1

    async def evalsha(self, *a, **kw):
        return 1


@pytest.fixture
def client(monkeypatch):
    from api.main import app
    from api.services import cache as cache_mod
    from api.services import rate_limiter
    fake = _FakeRedis()

    async def _r():
        return fake

    monkeypatch.setattr(cache_mod, "get_redis", _r)
    monkeypatch.setattr(rate_limiter, "get_redis", _r)
    return TestClient(app), fake


def test_serves_text_with_validators(client):
    c, _ = client
    r = c.get("/api/v1/blocklist/dns")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/plain")
    assert r.text == BODY
    assert r.headers["etag"] == f'"{SHA}"'
    assert r.headers["x-cleanway-blocklist-version"] == "1755530000"
    assert r.headers["x-cleanway-blocklist-count"] == "3"
    assert "max-age=1800" in r.headers["cache-control"]


def test_if_none_match_returns_304(client):
    c, _ = client
    r = c.get("/api/v1/blocklist/dns", headers={"If-None-Match": f'"{SHA}"'})
    assert r.status_code == 304
    assert r.headers["etag"] == f'"{SHA}"'
    assert r.content == b""


def test_weak_if_none_match_from_gzipping_edge_returns_304(client):
    c, _ = client
    r = c.get("/api/v1/blocklist/dns", headers={"If-None-Match": f'W/"{SHA}"'})
    assert r.status_code == 304


def test_missing_artifact_is_503_with_retry_after(monkeypatch):
    from api.main import app
    from api.services import cache as cache_mod
    from api.services import rate_limiter
    fake = _FakeRedis(text=None, meta={})

    async def _r():
        return fake

    monkeypatch.setattr(cache_mod, "get_redis", _r)
    monkeypatch.setattr(rate_limiter, "get_redis", _r)
    r = TestClient(app).get("/api/v1/blocklist/dns")
    assert r.status_code == 503
    assert r.headers["retry-after"] == "600"


def test_sha_mismatch_between_meta_and_body_is_503(monkeypatch):
    """A half-written or tampered artifact must never be served — the phone
    verifies sha256(text)==ETag and would reject it anyway; fail loudly here."""
    from api.main import app
    from api.services import cache as cache_mod
    from api.services import rate_limiter
    fake = _FakeRedis(meta={"version": "1", "sha256": "0" * 64, "count": "3"})

    async def _r():
        return fake

    monkeypatch.setattr(cache_mod, "get_redis", _r)
    monkeypatch.setattr(rate_limiter, "get_redis", _r)
    r = TestClient(app).get("/api/v1/blocklist/dns")
    assert r.status_code == 503


def test_health_reports_blocklist_age(client):
    c, _ = client
    r = c.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body.get("blocklist_version") == "1755530000"
    assert isinstance(body.get("blocklist_age_s"), int)


def test_artifact_format_helper():
    """The publisher's format function — one place that knows the header."""
    from api.services.blocklist_artifact import render_artifact, parse_header
    text = render_artifact({"b.example", "a.example"}, generated=1755530000)
    lines = text.split("\n")
    assert lines[0] == "# cleanway-dns-blocklist v1 generated=1755530000 count=3 status=ok"
    # canary always injected, names sorted, trailing newline
    assert lines[1:4] == ["a.example", "b.example", "list-canary.cleanway.ai"]
    assert text.endswith("\n")
    assert parse_header(lines[0]) == {"version": "v1", "generated": 1755530000, "count": 3, "status": "ok"}
    revoked = render_artifact(set(), generated=5, revoked=True)
    assert revoked.startswith("# cleanway-dns-blocklist v1 generated=5 count=0 status=revoked")

"""Tests for /health/deep — the hard healthcheck used by external monitors.

Critical that this endpoint:
  1. Returns 200 only when EVERY downstream is up
  2. Returns 503 when ANY downstream is down
  3. Names the failed component in the body (so on-call sees what to fix
     without ssh'ing into Railway)

Strategy: we mock httpx.AsyncClient + the Redis fake so the test doesn't
need the network. This mirrors how tests/test_payments_webhook.py handles
the same problem.
"""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def configured_settings(monkeypatch):
    """Pretend Supabase env is filled in so the deep check tries to probe."""
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_anon_key", "fake_anon_key", raising=False)
    return s


class _FakeRedis:
    """Just enough to satisfy the deep health check."""

    def __init__(self, fail: bool = False):
        self.fail = fail

    async def ping(self):
        if self.fail:
            raise ConnectionError("redis down")
        return True


def _patch_redis(monkeypatch, fail: bool = False):
    fake = _FakeRedis(fail=fail)

    async def _get_redis():
        return fake

    # main.py imports get_redis at module scope, so we have to patch the
    # *consumer's* reference. Patching api.services.cache.get_redis would
    # leave main.py's bound name pointing at the original.
    monkeypatch.setattr("api.main.get_redis", _get_redis)
    return fake


def _patch_httpx(monkeypatch, status_code: int = 200, raises: Exception | None = None):
    """Stub httpx.AsyncClient so the supabase check returns a fixed shape."""
    import httpx as _httpx

    class _Resp:
        def __init__(self, code: int):
            self.status_code = code

    class _Client:
        def __init__(self, *_a, **_k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return None

        async def get(self, url: str, headers: dict[str, Any] | None = None, **_kw):
            if raises:
                raise raises
            return _Resp(status_code)

    monkeypatch.setattr(_httpx, "AsyncClient", _Client)


@pytest.fixture
def client():
    from api.main import app
    return TestClient(app)


# ─── Happy path ──────────────────────────────────────────────────


def test_deep_healthy_returns_200(client, configured_settings, monkeypatch):
    _patch_redis(monkeypatch, fail=False)
    _patch_httpx(monkeypatch, status_code=200)

    resp = client.get("/health/deep")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["components"]["redis"] == {"ok": True}
    assert body["components"]["supabase"]["ok"] is True


def test_deep_supabase_401_still_counts_as_up(client, configured_settings, monkeypatch):
    """A 401 from Supabase means it's reachable + rejecting auth — that's a
    successful CONNECTIVITY probe even if the credentials are bad. We test
    here that this is treated as healthy (i.e. the deep check does NOT page
    on-call when Supabase is up and the anon key happens to be expired)."""
    _patch_redis(monkeypatch, fail=False)
    _patch_httpx(monkeypatch, status_code=401)

    resp = client.get("/health/deep")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["components"]["supabase"]["ok"] is True
    assert body["components"]["supabase"]["status"] == 401


# ─── Failure paths ──────────────────────────────────────────────


def test_deep_redis_down_returns_503(client, configured_settings, monkeypatch):
    _patch_redis(monkeypatch, fail=True)
    _patch_httpx(monkeypatch, status_code=200)

    resp = client.get("/health/deep")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["components"]["redis"]["ok"] is False
    assert body["components"]["redis"]["error"] == "ConnectionError"
    # supabase is still up — make sure deep check pinpoints which one broke
    assert body["components"]["supabase"]["ok"] is True


def test_deep_supabase_500_returns_503(client, configured_settings, monkeypatch):
    _patch_redis(monkeypatch, fail=False)
    _patch_httpx(monkeypatch, status_code=500)

    resp = client.get("/health/deep")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["components"]["supabase"]["ok"] is False
    assert body["components"]["supabase"]["status"] == 500
    # redis still up
    assert body["components"]["redis"]["ok"] is True


def test_deep_supabase_network_error_returns_503(client, configured_settings, monkeypatch):
    """If Supabase doesn't even respond (DNS, connection refused, timeout),
    we want the same 503 with error name in the body."""
    _patch_redis(monkeypatch, fail=False)
    _patch_httpx(monkeypatch, raises=ConnectionError("no route to host"))

    resp = client.get("/health/deep")
    assert resp.status_code == 503
    body = resp.json()
    assert body["components"]["supabase"]["ok"] is False
    assert body["components"]["supabase"]["error"] == "ConnectionError"


def test_deep_supabase_not_configured_returns_503(client, monkeypatch):
    """If env is empty (e.g. someone wiped Railway vars), we must page —
    not silently treat as healthy."""
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "", raising=False)
    monkeypatch.setattr(s, "supabase_anon_key", "", raising=False)
    _patch_redis(monkeypatch, fail=False)

    resp = client.get("/health/deep")
    assert resp.status_code == 503
    body = resp.json()
    assert body["components"]["supabase"]["ok"] is False
    assert body["components"]["supabase"]["error"] == "not_configured"


def test_deep_both_down_returns_503(client, configured_settings, monkeypatch):
    _patch_redis(monkeypatch, fail=True)
    _patch_httpx(monkeypatch, raises=ConnectionError("redis went too"))

    resp = client.get("/health/deep")
    assert resp.status_code == 503
    body = resp.json()
    # Both should be flagged ok=False — the JSON body is meant to give a
    # complete picture, not just the first failure encountered.
    assert body["components"]["redis"]["ok"] is False
    assert body["components"]["supabase"]["ok"] is False


# ─── Existing /health is still soft ─────────────────────────────


def test_soft_health_still_returns_200_when_redis_down(client, monkeypatch):
    """Make sure I didn't accidentally break the existing /health endpoint
    while adding /health/deep — it must stay soft (200 even on degradation)
    so Railway doesn't cycle pods on a transient Redis blip."""
    _patch_redis(monkeypatch, fail=True)

    resp = client.get("/health")
    # Soft endpoint never 503's — Railway healthcheck stays green.
    assert resp.status_code == 200
    body = resp.json()
    assert body["redis"] == "down"
    # Status field is informational — "degraded" is a soft signal.
    assert body["status"] in ("ok", "degraded")

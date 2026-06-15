"""GDPR Art. 17 — account deletion with 30-day grace.

Privacy Policy §9: "Delete your account from Settings. All server-side
data is permanently removed within 30 days."

Implementation: soft-delete via users.deletion_requested_at. Hard
purge happens in a periodic job 30 days later (not exercised by this
test suite — that's an ops concern). What we test here:

  - DELETE /api/v1/user/account → 200, PATCHes users with timestamp
  - Response carries restore deadline (now + 30d)
  - POST /api/v1/user/account/restore → clears the field
  - 503 when Supabase env missing (no silent failure)
  - 500 when Supabase rejects the PATCH (don't lie about success)
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier


class _SupabaseStub:
    def __init__(self) -> None:
        self.patches: List[Dict[str, Any]] = []
        self.patch_status = 204

    def build(self):
        stub = self

        class _Resp:
            def __init__(self, status: int):
                self.status_code = status

            def json(self):
                return {}

        class _Client:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def patch(self, url: str, params=None, json=None, headers=None, **_kw):
                stub.patches.append(
                    {"url": url, "params": dict(params or {}), "body": json or {}}
                )
                return _Resp(stub.patch_status)

        return _Client


@pytest.fixture
def supabase_ok(monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    return s


@pytest.fixture
def supabase_stub(monkeypatch):
    import httpx as _httpx

    stub = _SupabaseStub()
    monkeypatch.setattr(_httpx, "AsyncClient", stub.build())
    return stub


@pytest.fixture
def authed_user():
    return AuthUser(id="user-77", email="bob@gmail.com", tier=UserTier.free)


class _FakeRedis:
    """Stand-in for the soft-delete + tier cache. restore_account
    requires a working Redis to drop the deleted:{uid} flag; if Redis
    is down the endpoint now returns 503 instead of silently 200-ing
    with a stuck lock flag (audit finding #6)."""

    def __init__(self) -> None:
        self._kv: dict[str, str] = {}

    async def get(self, key: str):
        return self._kv.get(key)

    async def setex(self, key: str, _ttl: int, val: str):
        self._kv[key] = val
        return True

    async def delete(self, *keys: str):
        for k in keys:
            self._kv.pop(k, None)
        return len(keys)

    async def set(self, key: str, val: str, **_kw):
        self._kv[key] = val
        return True


@pytest.fixture
def fake_redis(monkeypatch):
    fake = _FakeRedis()

    async def _get():
        return fake

    # Cover both the cache module re-export and the direct call site
    # in user.py — both are import-time-bound.
    monkeypatch.setattr("api.services.cache.get_redis", _get)
    return fake


@pytest.fixture
def client(authed_user, fake_redis):
    from api.main import app
    from api.services.auth import get_current_user, get_current_user_including_deleted

    async def _override():
        return authed_user

    # restore_account uses the soft-delete-bypass dependency so a
    # locked-out user can still reach it. Override both so tests work
    # whether the endpoint uses the strict or the bypass variant.
    app.dependency_overrides[get_current_user] = _override
    app.dependency_overrides[get_current_user_including_deleted] = _override
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


# ─── DELETE /api/v1/user/account ───────────────────────────────


def test_delete_account_sets_deletion_timestamp(client, supabase_ok, supabase_stub):
    resp = client.delete("/api/v1/user/account")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["grace_period_days"] == 30
    # Timestamp shape: ISO-8601
    deleted_at = datetime.fromisoformat(body["deleted_at"].replace("Z", "+00:00"))
    restore_until = datetime.fromisoformat(body["restore_until"].replace("Z", "+00:00"))
    assert (restore_until - deleted_at) == timedelta(days=30)
    # And it actually PATCHed the right user
    assert len(supabase_stub.patches) == 1
    patch = supabase_stub.patches[0]
    assert patch["url"].endswith("/rest/v1/users")
    assert patch["params"] == {"id": "eq.user-77"}
    assert "deletion_requested_at" in patch["body"]
    assert patch["body"]["deletion_requested_at"] is not None


def test_delete_account_503_when_supabase_missing(client, authed_user, monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "", raising=False)

    resp = client.delete("/api/v1/user/account")
    assert resp.status_code == 503


def test_delete_account_500_on_upstream_reject(client, supabase_ok, supabase_stub):
    """Don't lie: if Supabase 4xx-s the PATCH, the user must see 500
    so they retry rather than think their account is queued for
    deletion when it isn't."""
    supabase_stub.patch_status = 409

    resp = client.delete("/api/v1/user/account")
    assert resp.status_code == 500


# ─── POST /api/v1/user/account/restore ─────────────────────────


def test_restore_account_clears_timestamp(client, supabase_ok, supabase_stub):
    resp = client.post("/api/v1/user/account/restore")
    assert resp.status_code == 200
    assert resp.json() == {"restored": True}
    assert len(supabase_stub.patches) == 1
    patch = supabase_stub.patches[0]
    assert patch["body"]["deletion_requested_at"] is None
    assert patch["params"] == {"id": "eq.user-77"}


def test_restore_account_503_when_redis_unreachable(
    authed_user, supabase_ok, supabase_stub, monkeypatch
):
    """If the Supabase clear succeeds but Redis is down, the lock flag
    persists and the user stays 410-ed on every subsequent request —
    same UX as "restore didn't work". Return 503 so the client retries
    instead of silently 200-ing into a stuck state.

    Re-builds the client fixture without our fake_redis so the real
    get_redis path tries (and fails) to connect.
    """
    async def _boom():
        raise ConnectionError("simulated Redis outage")

    monkeypatch.setattr("api.services.cache.get_redis", _boom)

    from api.main import app
    from api.services.auth import get_current_user, get_current_user_including_deleted

    async def _override():
        return authed_user

    app.dependency_overrides[get_current_user] = _override
    app.dependency_overrides[get_current_user_including_deleted] = _override
    try:
        resp = TestClient(app).post("/api/v1/user/account/restore")
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 503
    body = resp.json()
    assert "retry" in str(body).lower(), body
    # Supabase clear DID land before the Redis failure — that's by design
    # (Supabase is the source of truth for whether hard-purge will fire).
    # A retry is idempotent because the field is already null.
    assert len(supabase_stub.patches) == 1
    assert supabase_stub.patches[0]["body"]["deletion_requested_at"] is None

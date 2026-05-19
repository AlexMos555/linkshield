"""Soft-delete account-lock — 410 Gone during the 30-day grace window.

Privacy Policy §9 promises "delete your account" — that has to be more
than a flag in the DB. After clicking delete, the user must stop being
able to consume API resources (and stop being charged, though the
Stripe-side cancellation flows through the Portal). This module's
contract:

  1. Account in grace (deleted:{user_id} flag in Redis) → 410 from any
     endpoint that uses get_current_user
  2. EXCEPT /api/v1/user/account/restore (the way out) and
     /api/v1/user/export (GDPR Art. 15 — still entitled to access)
  3. Redis blip → fail-open (better one user briefly past the gate
     than the whole API offline on a Redis blip)
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier


class _FakeRedis:
    """Just enough Redis surface for the auth gate + restore unlock."""

    def __init__(self, deleted: bool = False) -> None:
        self._kv: dict[str, str] = {}
        if deleted:
            self._kv["deleted:user-lock"] = "1"

    async def get(self, key: str):
        return self._kv.get(key)

    async def setex(self, key: str, ttl: int, val: str):
        self._kv[key] = val
        return True

    async def delete(self, key: str):
        self._kv.pop(key, None)
        return 1

    async def set(self, key, val, **_kw):
        self._kv[key] = val
        return True

    async def ping(self):
        return True


@pytest.fixture
def locked_user():
    return AuthUser(id="user-lock", email="z@gmail.com", tier=UserTier.free)


def _patch_token_verify(monkeypatch, user: AuthUser):
    """Skip JWT verification by stubbing the underlying decode call."""
    import jwt as _jwt

    def _fake_decode(*_a, **_kw):
        return {"sub": user.id, "email": user.email}

    monkeypatch.setattr(_jwt, "decode", _fake_decode)


def _patch_resolver(monkeypatch, user: AuthUser):
    """Skip the tier resolver's Supabase lookup."""
    async def _fake(_uid: str):
        return user.tier

    monkeypatch.setattr("api.services.auth._resolve_user_tier", _fake)


@pytest.fixture
def app_with_redis(monkeypatch, locked_user):
    """Wire a FakeRedis seeded with the deletion flag. The flag is what
    triggers the 410. Use get_redis monkeypatch at the module path the
    auth code reads from (lazy import inside get_current_user)."""
    fake = _FakeRedis(deleted=True)

    async def _get():
        return fake

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    _patch_token_verify(monkeypatch, locked_user)
    _patch_resolver(monkeypatch, locked_user)
    from api.main import app
    return app, fake


@pytest.fixture
def client_locked(app_with_redis):
    app, _ = app_with_redis
    return TestClient(app)


# ─── 410 on regular endpoints ─────────────────────────────────


def test_locked_user_gets_410_on_check(client_locked):
    """A soft-deleted user hitting /api/v1/check during grace must
    receive 410 Gone, not 200. (This endpoint goes through
    get_current_user_no_disposable which wraps get_current_user, so
    the lock takes effect on it as well.)"""
    resp = client_locked.post(
        "/api/v1/check",
        json={"domains": ["example.com"]},
        headers={"Authorization": "Bearer fake-jwt"},
    )
    assert resp.status_code == 410, resp.text
    body = resp.json()
    # Response carries the restore URL so a confused user knows the
    # way out without reading docs.
    assert "restore" in str(body).lower()


def test_locked_user_gets_410_on_user_settings(client_locked):
    """user/settings uses plain get_current_user — same lock."""
    resp = client_locked.get(
        "/api/v1/user/settings",
        headers={"Authorization": "Bearer fake-jwt"},
    )
    assert resp.status_code == 410


# ─── Bypass on /restore + /export ─────────────────────────────


def test_locked_user_can_reach_restore(client_locked, monkeypatch):
    """/user/account/restore depends on get_current_user_including_deleted
    — must NOT 410. Supabase isn't configured in the test, so the
    handler returns 503; the key thing is it's not 410."""
    resp = client_locked.post(
        "/api/v1/user/account/restore",
        headers={"Authorization": "Bearer fake-jwt"},
    )
    assert resp.status_code != 410, (
        f"restore endpoint must bypass the soft-delete gate, got {resp.status_code}"
    )


def test_locked_user_can_reach_export(client_locked):
    """GDPR Art. 15: soft-deleted users still have right of access."""
    resp = client_locked.get(
        "/api/v1/user/export",
        headers={"Authorization": "Bearer fake-jwt"},
    )
    assert resp.status_code != 410


# ─── Redis-down fail-open ─────────────────────────────────────


def test_redis_unreachable_fails_open(monkeypatch, locked_user):
    """If Redis is down, we DON'T want the whole API behind 410 — that
    would be a worse incident than briefly letting a deleted user past
    the gate. The lock fails open."""
    async def _boom():
        raise ConnectionError("redis down")

    monkeypatch.setattr("api.services.cache.get_redis", _boom)
    _patch_token_verify(monkeypatch, locked_user)
    _patch_resolver(monkeypatch, locked_user)

    from api.main import app
    client = TestClient(app)
    resp = client.get(
        "/api/v1/user/settings",
        headers={"Authorization": "Bearer fake-jwt"},
    )
    # 503 (Supabase not configured in test) or anything else, just
    # NOT 410 — that would mean the lock engaged on a Redis blip.
    assert resp.status_code != 410

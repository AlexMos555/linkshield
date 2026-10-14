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
  3. Redis unreachable → the users row (deletion_requested_at) decides;
     Redis AND the database unreachable → 503, never "allowed" and never
     a 410 for everyone. No database configured (local dev) → open.
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
    """Skip JWT verification by stubbing the signature + claims check
    (tests/test_jwt_verification.py covers the real one)."""

    def _fake_verify(_token):
        return {"sub": user.id, "email": user.email}

    monkeypatch.setattr("api.services.auth._verify_supabase_token", _fake_verify)


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


# ─── Redis down → the database decides ───────────────────────


def _client_with_redis_down(monkeypatch, user: AuthUser) -> TestClient:
    async def _boom():
        raise ConnectionError("redis down")

    monkeypatch.setattr("api.services.cache.get_redis", _boom)
    _patch_token_verify(monkeypatch, user)
    _patch_resolver(monkeypatch, user)

    from api.main import app
    return TestClient(app)


def test_redis_down_deleted_account_is_still_locked(monkeypatch, locked_user, account_store):
    """The gate used to fail open on a Redis blip: a deleted account kept
    full API access for as long as Redis was down. Now the users row
    (deletion_requested_at) answers instead."""
    account_store.deletion_requested.add(locked_user.id)
    client = _client_with_redis_down(monkeypatch, locked_user)
    resp = client.get(
        "/api/v1/user/settings",
        headers={"Authorization": "Bearer fake-jwt"},
    )
    assert resp.status_code == 410, resp.text
    assert "restore" in str(resp.json()).lower()


def test_redis_down_live_account_passes_the_gate(monkeypatch, locked_user, account_store):
    """A Redis outage must not lock out every account that isn't deleted."""
    client = _client_with_redis_down(monkeypatch, locked_user)
    resp = client.get(
        "/api/v1/user/settings",
        headers={"Authorization": "Bearer fake-jwt"},
    )
    # 503 "Database not configured" from the handler itself is possible in
    # the test env; the gate's own answers (410 / auth 503) are not.
    assert resp.status_code != 410
    assert "auth_unavailable" not in resp.text
    assert account_store.deletion_checks == [locked_user.id]


def test_redis_and_database_down_answers_503(monkeypatch, locked_user, account_store):
    """Neither source can answer: a retryable 503 — never a silent "allowed"
    (a deleted account would slip through) and never a 410 (that would tell
    every live user their account is being deleted)."""
    account_store.fail = True
    client = _client_with_redis_down(monkeypatch, locked_user)
    resp = client.get(
        "/api/v1/user/settings",
        headers={"Authorization": "Bearer fake-jwt"},
    )
    assert resp.status_code == 503, resp.text
    assert resp.json()["detail"]["code"] == "auth_unavailable"


def test_redis_down_without_a_database_configured_stays_open(monkeypatch, locked_user):
    """Local dev without Supabase: no users row to consult — not a 410."""
    client = _client_with_redis_down(monkeypatch, locked_user)
    resp = client.get(
        "/api/v1/user/settings",
        headers={"Authorization": "Bearer fake-jwt"},
    )
    assert resp.status_code != 410


def test_redis_flag_present_skips_the_database(app_with_redis, account_store):
    """Fast path: the Redis flag answers, no per-request database read."""
    app, _ = app_with_redis
    resp = TestClient(app).get(
        "/api/v1/user/settings",
        headers={"Authorization": "Bearer fake-jwt"},
    )
    assert resp.status_code == 410
    assert account_store.deletion_checks == []


def test_redis_up_without_flag_does_not_read_the_database(monkeypatch, locked_user, account_store):
    """Redis answered "no flag": the hot path stays one Redis GET."""
    fake = _FakeRedis(deleted=False)

    async def _get():
        return fake

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    _patch_token_verify(monkeypatch, locked_user)
    _patch_resolver(monkeypatch, locked_user)
    from api.main import app

    resp = TestClient(app).get(
        "/api/v1/user/settings",
        headers={"Authorization": "Bearer fake-jwt"},
    )
    assert resp.status_code != 410
    assert account_store.deletion_checks == []


def test_postgrest_store_reads_deletion_requested_at(monkeypatch):
    """The production store asks for the one column, by id, with the
    service key, and treats a set timestamp as "deletion requested"."""
    import asyncio

    from api.services.account_store import AccountStoreError, PostgrestAccountStore

    calls: list[dict] = []
    answers: list = [
        [{"deletion_requested_at": "2026-10-01T00:00:00+00:00"}],
        [{"deletion_requested_at": None}],
        [],
    ]

    async def _fake_call(self, method, path, **kwargs):
        calls.append({"method": method, "path": path, **kwargs})
        return answers.pop(0)

    monkeypatch.setattr(PostgrestAccountStore, "_call", _fake_call)
    store = PostgrestAccountStore("https://db.example", "service-key")
    assert asyncio.run(store.is_deletion_requested("user-lock")) is True
    assert asyncio.run(store.is_deletion_requested("user-lock")) is False
    assert asyncio.run(store.is_deletion_requested("user-lock")) is False
    assert calls[0]["method"] == "get"
    assert calls[0]["path"] == "/rest/v1/users"
    assert calls[0]["params"]["id"] == "eq.user-lock"
    assert calls[0]["params"]["select"] == "deletion_requested_at"

    async def _boom(self, method, path, **kwargs):
        raise AccountStoreError("down")

    monkeypatch.setattr(PostgrestAccountStore, "_call", _boom)
    with pytest.raises(AccountStoreError):
        asyncio.run(store.is_deletion_requested("user-lock"))

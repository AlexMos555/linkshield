"""GDPR export / account delete / restore — the edges that protect users.

Requests go through the REAL auth dependencies with signed ES256 test
tokens (tests/jwt_helpers.py) wherever authentication itself is the point:
no token, forged token, missing / garbage / stale `iat`, another user's
id in the query, a soft-deleted account, an unlinked device. The
reauth-window boundary is pinned with a frozen clock. Supabase is
tests/supabase_rest_stub.FakeSupabase.

Invariants:
  - a failed or timed-out write is never reported as success, and the
    side effects that follow it (lock flag, sign-out, alert, audit row)
    do not happen;
  - every export query is scoped to the token's subject, whatever the
    request says;
  - a Redis outage never undoes a deletion and never fakes a restore;
  - a restore only clears a deletion still inside the 30-day window, in
    the same UPDATE, so it can never race the purge of a row the purge
    has already listed.
"""
from __future__ import annotations

import asyncio
import time
import types

import httpx
import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier
from tests.jwt_helpers import SigningKey, install_fake_jwks
from tests.supabase_rest_stub import FakeSupabase

ACCOUNT = "33333333-3333-4333-8333-333333333333"
OTHER = "44444444-4444-4444-8444-444444444444"
REVOKED_INSTALL = "browser-install-revoked-01"
KEY = SigningKey()
EXPORT_TABLES = {"users", "subscriptions", "entitlements", "user_settings", "devices", "weekly_aggregates",
                 "rate_limits", "scam_analyses", "families", "family_members", "family_member_keys",
                 "family_invites", "family_alerts", "orgs", "org_members", "brand_watchlist", "sms_reports",
                 "feedback_reports", "audit_log"}
# Keys of the export: the tables, plus the alerts the user sent (family_alerts read twice).
EXPORT_KEYS = EXPORT_TABLES | {"family_alerts_sent"}


@pytest.fixture(autouse=True)
def _jwks(monkeypatch):
    install_fake_jwks(monkeypatch, KEY)


@pytest.fixture(autouse=True)
def _alerts(security_events):
    return security_events


@pytest.fixture
def sb(monkeypatch) -> FakeSupabase:
    from api import config

    monkeypatch.setattr(config.get_settings(), "supabase_service_key", "fake-key", raising=False)
    stub = FakeSupabase()
    monkeypatch.setattr(httpx, "AsyncClient", stub.client())
    return stub


@pytest.fixture
def client(fake_redis, account_store, monkeypatch):
    from api.main import app
    from api.services import rate_limiter

    async def _fake():
        return fake_redis

    monkeypatch.setattr(rate_limiter, "get_redis", _fake)
    yield TestClient(app)
    app.dependency_overrides.clear()


def _auth(sub: str = ACCOUNT, **kw) -> dict:
    return {"Authorization": f"Bearer {KEY.token(sub, **kw)}"}


def _export_reads(sb: FakeSupabase) -> list[dict]:
    return [c for c in sb.to("GET", "/rest/v1/") if c["url"].rsplit("/", 1)[-1] in EXPORT_TABLES
            and "select" in c["params"] and "limit" in c["params"]]


# ─── GET /export: who may read what ──────────────────────────────


@pytest.mark.parametrize("headers", [
    {},
    {"Authorization": "Bearer not-a-jwt"},
    {"Authorization": f"Bearer {SigningKey().token(ACCOUNT)}"},  # signed by a key Supabase never issued
    {"Authorization": f"Bearer {KEY.token(ACCOUNT, iat_ago=7200, ttl=3600)}"},  # expired
])
def test_export_refuses_missing_forged_and_expired_tokens(client, sb, headers, _alerts):
    resp = client.get("/api/v1/user/export", headers=headers)
    assert resp.status_code == 401
    assert _export_reads(sb) == []
    assert ("user_export", ACCOUNT) not in _alerts


def test_export_is_scoped_to_the_token_subject_whatever_the_query_says(client, sb):
    resp = client.get(f"/api/v1/user/export?user_id={OTHER}&id={OTHER}", headers=_auth())
    assert resp.status_code == 200, resp.text
    assert resp.json()["user_id"] == ACCOUNT
    reads = _export_reads(sb)
    assert {c["url"].rsplit("/", 1)[-1] for c in reads} == EXPORT_TABLES
    for c in reads:
        assert OTHER not in str(c)
        assert [v for v in c["params"].values() if v.startswith("eq.")] == [f"eq.{ACCOUNT}"]
        assert c["params"]["limit"] == "5000"


def test_soft_deleted_account_can_still_export_but_nothing_else(client, sb, fake_redis):
    asyncio.run(fake_redis.setex(f"deleted:{ACCOUNT}", 60, "1"))
    assert client.get("/api/v1/user/export", headers=_auth()).status_code == 200
    assert client.get("/api/v1/user/settings", headers=_auth()).status_code == 410


def test_export_from_an_unlinked_device_is_refused_even_when_the_marker_is_lost(client, sb, account_store):
    # strict check: the devices row decides when Redis has no marker
    account_store.add_device(ACCOUNT, REVOKED_INSTALL, revoked_at="2026-10-01T00:00:00+00:00")
    resp = client.get("/api/v1/user/export", headers={**_auth(), "X-Device-Id": REVOKED_INSTALL})
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "device_revoked"
    assert _export_reads(sb) == []


def test_export_device_check_with_redis_and_database_down_is_503_not_a_download(
    client, sb, account_store, redis_down, _alerts
):
    account_store.fail = True
    resp = client.get("/api/v1/user/export", headers={**_auth(), "X-Device-Id": REVOKED_INSTALL})
    assert resp.status_code == 503
    assert _export_reads(sb) == []
    assert ("user_export", ACCOUNT) not in _alerts


def test_export_with_a_malformed_device_id_is_not_treated_as_revoked(client, sb):
    resp = client.get("/api/v1/user/export", headers={**_auth(), "X-Device-Id": "x y"})
    assert resp.status_code == 200


# ─── GET /export: Supabase failing mid-export ────────────────────


def test_timeouts_mid_export_are_flagged_per_table_never_shown_as_empty(client, sb):
    sb.on("GET", "/rest/v1/audit_log", exc=httpx.ReadTimeout("slow"))
    sb.on("GET", "/rest/v1/devices", exc=httpx.ConnectError("reset"))
    sb.on("GET", "/rest/v1/entitlements", status=401, body={"message": "bad key"})
    sb.on("GET", "/rest/v1/users", body=[{"id": ACCOUNT}])

    body = client.get("/api/v1/user/export", headers=_auth()).json()

    assert body["tables"]["audit_log"] == {"error": "ReadTimeout"}
    assert body["tables"]["devices"] == {"error": "ConnectError"}
    assert body["tables"]["entitlements"] == {"error": "upstream returned 401"}
    # The tables read after the failures are still there.
    assert body["tables"]["users"] == [{"id": ACCOUNT}]
    assert set(body["tables"]) == EXPORT_KEYS


# ─── DELETE /account: the reauth window ──────────────────────────

NOW_TS = 1_800_000_000


def _as(user: AuthUser):
    from api.main import app
    from api.services.auth import get_current_user, get_current_user_including_deleted

    async def _dep():
        return user

    app.dependency_overrides[get_current_user] = _dep
    app.dependency_overrides[get_current_user_including_deleted] = _dep


@pytest.fixture
def frozen_clock(monkeypatch):
    from api.services import auth

    monkeypatch.setattr(auth, "time", types.SimpleNamespace(time=lambda: NOW_TS, monotonic=time.monotonic))


@pytest.mark.parametrize("issued_at, allowed", [
    (NOW_TS, True),
    (NOW_TS - 599, True),
    (NOW_TS - 600, True),    # exactly at the limit: still fresh
    (NOW_TS - 601, False),   # one second over
    (None, False),           # no iat on the user: never "fresh"
])
def test_delete_reauth_window_boundary(client, sb, frozen_clock, _alerts, issued_at, allowed):
    _as(AuthUser(id=ACCOUNT, email="p@example.com", tier=UserTier.free, issued_at=issued_at))
    resp = client.delete("/api/v1/user/account", headers={"Authorization": "Bearer t"})
    if allowed:
        assert resp.status_code == 200, resp.text
        assert len(sb.to("PATCH", "/rest/v1/users")) == 1
    else:
        assert resp.status_code == 401
        assert resp.json()["detail"]["code"] == "reauth_required"
        assert sb.writes() == []  # nothing marked, cancelled or signed out
        assert _alerts == [("reauth_required", ACCOUNT)]


@pytest.mark.parametrize("claims", [
    {"drop": ("iat",)},
    {"iat": "yesterday"},
    {"iat": int(time.time()) + 3600},   # issued in the future
])
def test_delete_with_a_missing_or_garbage_iat_is_refused(client, sb, claims):
    resp = client.delete("/api/v1/user/account", headers=_auth(**claims))
    assert resp.status_code == 401
    assert sb.writes() == []


def test_delete_with_a_real_token_eleven_minutes_old_needs_reauth(client, sb):
    resp = client.delete("/api/v1/user/account", headers=_auth(iat_ago=660))
    assert resp.status_code == 401
    assert resp.json()["detail"]["code"] == "reauth_required"
    assert sb.writes() == []


def test_delete_accepts_a_fractional_iat(client, sb):
    resp = client.delete("/api/v1/user/account", headers=_auth(iat=time.time() - 30.7))
    assert resp.status_code == 200, resp.text


# ─── DELETE /account: partial failures ───────────────────────────


@pytest.mark.parametrize("failure", [{"exc": httpx.ReadTimeout("slow")}, {"exc": httpx.ConnectError("down")},
                                     {"status": 400}])
def test_delete_that_did_not_land_reports_failure_and_has_no_side_effects(
    client, sb, fake_redis, _alerts, failure
):
    sb.on("PATCH", "/rest/v1/users", **failure)
    resp = client.delete("/api/v1/user/account", headers=_auth())
    assert resp.status_code == 500
    assert f"deleted:{ACCOUNT}" not in fake_redis._kv
    assert sb.to("POST", "/auth/v1/logout") == []
    assert sb.to("POST", "/rest/v1/audit_log") == []
    assert ("account_delete", ACCOUNT) not in _alerts


def test_delete_success_locks_signs_out_and_audits(client, sb, fake_redis, _alerts):
    asyncio.run(fake_redis.setex(f"tier:{ACCOUNT}", 300, "personal"))
    resp = client.delete("/api/v1/user/account", headers=_auth())
    assert resp.status_code == 200, resp.text
    assert fake_redis._kv[f"deleted:{ACCOUNT}"] == "1"
    assert fake_redis._ttls[f"deleted:{ACCOUNT}"] == 30 * 24 * 3600
    assert f"tier:{ACCOUNT}" not in fake_redis._kv
    # The auth gate cached "not deleted" on the way in; it goes at once.
    assert f"notdeleted:{ACCOUNT}" not in fake_redis._kv
    (logout,) = sb.to("POST", "/auth/v1/logout")
    assert logout["params"] == {"scope": "global"}
    (audit,) = sb.to("POST", "/rest/v1/audit_log")
    assert audit["json"]["action"] == "account.delete_requested"
    assert audit["json"]["target_id"] == ACCOUNT
    assert ("account_delete", ACCOUNT) in _alerts


def test_redis_down_after_the_database_write_still_deletes_and_locks(client, sb, account_store, redis_down):
    resp = client.delete("/api/v1/user/account", headers=_auth())
    assert resp.status_code == 200, resp.text
    (patch,) = sb.to("PATCH", "/rest/v1/users")
    assert patch["params"] == {"id": f"eq.{ACCOUNT}"} and patch["json"]["deletion_requested_at"]
    assert len(sb.to("POST", "/auth/v1/logout")) == 1
    # With the flag lost, the gate reads deletion_requested_at from the row.
    account_store.deletion_requested.add(ACCOUNT)
    assert client.get("/api/v1/user/settings", headers=_auth()).status_code == 410


def test_delete_without_a_bearer_token_skips_the_global_sign_out(client, sb, frozen_clock):
    _as(AuthUser(id=ACCOUNT, email=None, tier=UserTier.free, issued_at=NOW_TS))
    assert client.delete("/api/v1/user/account").status_code == 200
    assert sb.to("POST", "/auth/v1/logout") == []


# ─── POST /account/restore ───────────────────────────────────────


def _restore_lands(sb: FakeSupabase) -> None:
    """PostgREST's answer to the conditional PATCH: the row it updated."""
    sb.on("PATCH", "/rest/v1/users", status=200, body=[{"id": ACCOUNT}])


def test_restore_only_clears_a_deletion_still_inside_the_window(client, sb, fake_redis):
    from datetime import datetime, timezone

    asyncio.run(fake_redis.setex(f"deleted:{ACCOUNT}", 60, "1"))
    _restore_lands(sb)
    assert client.post("/api/v1/user/account/restore", headers=_auth()).status_code == 200
    (patch,) = sb.to("PATCH", "/rest/v1/users")
    assert patch["params"]["id"] == f"eq.{ACCOUNT}"
    assert patch["params"]["select"] == "id"
    assert patch["headers"]["Prefer"] == "return=representation"
    clause = patch["params"]["or"]
    prefix = '(deletion_requested_at.is.null,deletion_requested_at.gt."'
    assert clause.startswith(prefix) and clause.endswith('")'), clause
    cutoff = datetime.fromisoformat(clause[len(prefix):-2])
    age_days = (datetime.now(timezone.utc) - cutoff).total_seconds() / 86400
    assert 29.99 < age_days < 30.01


def test_restore_after_the_window_is_refused_and_keeps_the_lock(client, sb, fake_redis):
    """Past 30 days the purge may already be deleting the account: the UPDATE
    matches no row, and the user is told so instead of 'restored'."""
    asyncio.run(fake_redis.setex(f"deleted:{ACCOUNT}", 60, "1"))
    sb.on("PATCH", "/rest/v1/users", status=200, body=[])
    resp = client.post("/api/v1/user/account/restore", headers=_auth())
    assert resp.status_code == 410
    assert resp.json()["detail"]["code"] == "restore_window_closed"
    assert fake_redis._kv.get(f"deleted:{ACCOUNT}") == "1"
    assert sb.to("POST", "/rest/v1/audit_log") == []


@pytest.mark.parametrize("answer", [{"status": 204}, {"status": 200, "body": {"id": ACCOUNT}},
                                    {"status": 200, "body": b"<html>proxy</html>"}])
def test_restore_without_a_row_list_is_not_reported_as_restored(client, sb, fake_redis, answer):
    asyncio.run(fake_redis.setex(f"deleted:{ACCOUNT}", 60, "1"))
    sb.on("PATCH", "/rest/v1/users", **answer)
    resp = client.post("/api/v1/user/account/restore", headers=_auth())
    assert resp.status_code == 500
    assert fake_redis._kv.get(f"deleted:{ACCOUNT}") == "1"
    assert sb.to("POST", "/rest/v1/audit_log") == []


@pytest.mark.parametrize("failure", [{"status": 409}, {"exc": httpx.ReadTimeout("slow")}])
def test_restore_that_did_not_land_keeps_the_lock(client, sb, fake_redis, failure):
    asyncio.run(fake_redis.setex(f"deleted:{ACCOUNT}", 60, "1"))
    sb.on("PATCH", "/rest/v1/users", **failure)
    resp = client.post("/api/v1/user/account/restore", headers=_auth())
    assert resp.status_code == 500
    assert fake_redis._kv.get(f"deleted:{ACCOUNT}") == "1"
    assert sb.to("POST", "/rest/v1/audit_log") == []


def test_restore_rides_out_one_redis_blip(client, sb, fake_redis, monkeypatch):
    asyncio.run(fake_redis.setex(f"deleted:{ACCOUNT}", 60, "1"))
    from api.services import cache

    real = cache.get_redis
    attempts = {"n": 0}

    async def _flaky():
        attempts["n"] += 1
        if attempts["n"] == 1:
            raise ConnectionError("blip")
        return await real()

    # The auth path reads the flag first: let it through, then fail once.
    _as(AuthUser(id=ACCOUNT, email=None, tier=UserTier.free))
    monkeypatch.setattr(cache, "get_redis", _flaky)
    _restore_lands(sb)
    resp = client.post("/api/v1/user/account/restore", headers=_auth())
    assert resp.status_code == 200, resp.text
    assert f"deleted:{ACCOUNT}" not in fake_redis._kv
    (audit,) = sb.to("POST", "/rest/v1/audit_log")
    assert audit["json"]["action"] == "account.restored"


def test_soft_deleted_user_restores_with_a_real_token_and_is_let_back_in(client, sb, fake_redis):
    asyncio.run(fake_redis.setex(f"deleted:{ACCOUNT}", 60, "1"))
    assert client.get("/api/v1/user/settings", headers=_auth()).status_code == 410
    _restore_lands(sb)
    resp = client.post("/api/v1/user/account/restore", headers=_auth())
    assert resp.json() == {"restored": True}
    (patch,) = sb.to("PATCH", "/rest/v1/users")
    assert patch["params"]["id"] == f"eq.{ACCOUNT}" and patch["json"] == {"deletion_requested_at": None}
    assert client.get("/api/v1/user/settings", headers=_auth()).status_code == 200


def test_restore_without_database_is_503(client, monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_service_key", "", raising=False)
    monkeypatch.setattr(s, "supabase_secret_key", "", raising=False)
    _as(AuthUser(id=ACCOUNT, email=None, tier=UserTier.free))
    assert client.post("/api/v1/user/account/restore").status_code == 503

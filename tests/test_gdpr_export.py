"""GDPR Art. 15 — data export endpoint.

Privacy Policy §9 promises: "Access: export all your server-side data
from Settings." This file pins:

  - 200 path returns all expected tables for the caller
  - filter is `eq.{user_id}` on the right column per table (no leak
    of other users' rows)
  - family_alerts export excludes ciphertext/nonce (those are useless
    without the device-local private key and bloat the response)
  - upstream Supabase failure on one table → other tables still
    populate; failure surfaces per-table, not 500 for the whole export
  - 503 when Supabase env is absent (no silent empty exports)
  - beyond the tables: the Supabase Auth record (allow-listed) and the
    Redis whitelist / referral records are in it too
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier


class _SupabaseStub:
    """Captures GET URLs + params so we can assert what the export reads."""

    def __init__(self) -> None:
        self.gets: List[Dict[str, Any]] = []
        self.status_overrides: Dict[str, int] = {}

    def build(self):
        stub = self

        class _Resp:
            def __init__(self, status: int, body: Any):
                self.status_code = status
                self._body = body

            def json(self):
                return self._body

        class _Client:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def get(self, url: str, params=None, headers=None, **_kw):
                stub.gets.append({"url": url, "params": dict(params or {})})
                for needle, status in stub.status_overrides.items():
                    if needle in url:
                        return _Resp(status, {})
                if "/auth/v1/admin/users/" in url:
                    return _Resp(200, {"email": "alice@gmail.com", "created_at": "2026-09-01T10:00:00Z",
                                       "identities": [{"provider": "email"}], "recovery_token": "secret"})
                # Default: 200 with one fake row echoing the table name
                table = url.rsplit("/", 1)[-1]
                return _Resp(200, [{"_table": table}])

            async def post(self, *_a, **_kw):  # unused on this path
                return _Resp(200, {})

        return _Client


# export key → (table, column holding the account id)
EXPECTED_FILTER = {
    "users": ("users", "id"),
    "subscriptions": ("subscriptions", "user_id"),
    "entitlements": ("entitlements", "account_id"),
    "user_settings": ("user_settings", "user_id"),
    "devices": ("devices", "user_id"),
    "weekly_aggregates": ("weekly_aggregates", "user_id"),
    "rate_limits": ("rate_limits", "user_id"),
    "scam_analyses": ("scam_analyses", "user_id"),
    "families": ("families", "owner_id"),
    "family_members": ("family_members", "user_id"),
    "family_member_keys": ("family_member_keys", "user_id"),
    "family_invites": ("family_invites", "inviter_id"),
    "family_alerts": ("family_alerts", "recipient_user_id"),
    "family_alerts_sent": ("family_alerts", "sender_user_id"),
    "orgs": ("orgs", "admin_user_id"),
    "org_members": ("org_members", "user_id"),
    "brand_watchlist": ("brand_watchlist", "user_id"),
    "sms_reports": ("sms_reports", "reporter_user_id"),
    "feedback_reports": ("feedback_reports", "user_id"),
    "audit_log": ("audit_log", "actor_user_id"),
}


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
    return AuthUser(id="user-42", email="alice@gmail.com", tier=UserTier.free)


@pytest.fixture
def client(authed_user):
    from api.main import app
    from api.services.auth import get_current_user, get_current_user_including_deleted

    async def _override():
        return authed_user

    # /user/export uses the soft-delete-bypass dependency (GDPR Art. 15
    # says deleted users still get to access their data). Override both.
    app.dependency_overrides[get_current_user] = _override
    app.dependency_overrides[get_current_user_including_deleted] = _override
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


# ─── Happy path ─────────────────────────────────────────────────


def test_export_returns_all_user_tables(client, supabase_ok, supabase_stub):
    resp = client.get("/api/v1/user/export")
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["user_id"] == "user-42"
    assert body["email"] == "alice@gmail.com"
    assert body["schema_version"] == 2
    assert "generated_at" in body

    # Every table keyed on the account is in the export. scam_analyses,
    # families, family_invites, family_member_keys, orgs, org_members,
    # brand_watchlist, sms_reports, rate_limits and the alerts the user
    # sent were missing until schema_version 2.
    assert set(body["tables"].keys()) == set(EXPECTED_FILTER)


def test_export_filters_by_user_id_per_table(client, supabase_ok, supabase_stub):
    """No cross-user leak: every Supabase query must scope to the
    authed user's id via the right filter column."""
    client.get("/api/v1/user/export")
    queried = []
    for got in supabase_stub.gets:
        if "/rest/v1/" not in got["url"]:
            continue
        table = got["url"].rsplit("/", 1)[-1]
        eq = {k: v for k, v in got["params"].items() if v.startswith("eq.")}
        assert eq and set(eq.values()) == {"eq.user-42"}, f"{table}: {got['params']}"
        (column,) = eq
        queried.append((table, column))
    expected = sorted((EXPECTED_FILTER[key][0], EXPECTED_FILTER[key][1]) for key in EXPECTED_FILTER)
    assert sorted(queried) == expected


def test_export_includes_the_auth_record_and_the_redis_records(client, supabase_ok, supabase_stub, fake_redis):
    """Not only the tables: the sign-in record (Supabase Auth) of the caller,
    and the sites they marked safe (Redis, a year) — both promised by
    "everything the server holds"."""
    import asyncio

    asyncio.run(fake_redis.sadd("whitelist:user-42", "my-bank.example"))

    body = client.get("/api/v1/user/export").json()

    (auth_read,) = [g for g in supabase_stub.gets if "/auth/v1/" in g["url"]]
    assert auth_read["url"].endswith("/auth/v1/admin/users/user-42")
    assert body["auth_user"]["email"] == "alice@gmail.com"
    assert body["auth_user"]["identities"] == [
        {"provider": "email", "created_at": None, "last_sign_in_at": None, "updated_at": None}
    ]
    assert "secret" not in str(body["auth_user"])
    assert body["whitelist"] == ["my-bank.example"]
    assert body["referral"]["record"] is None


def test_secrets_are_left_out_of_the_export(client, supabase_ok, supabase_stub):
    """Invite code and PIN hashes are secrets (a 4-digit PIN's bcrypt is
    brute-forced in seconds), an org's SSO config holds credentials."""
    client.get("/api/v1/user/export")
    selects = {(g["url"].rsplit("/", 1)[-1], g["params"]["select"]) for g in supabase_stub.gets
               if "/rest/v1/" in g["url"]}
    by_table = {}
    for table, select in selects:
        by_table.setdefault(table, []).append(select)
    for select in by_table["family_invites"]:
        assert select != "*" and "hash" not in select
    for select in by_table["orgs"]:
        assert select != "*" and "sso" not in select
    for select in by_table["family_alerts"]:
        assert select != "*" and "payload" not in select and "nonce" not in select


def test_family_alerts_export_excludes_ciphertext(client, supabase_ok, supabase_stub):
    """Ciphertext + nonce are useless without the device-local private
    key (would just bloat the export and tempt clients to think they
    can decrypt server-side, which they can't)."""
    client.get("/api/v1/user/export")
    reads = [g for g in supabase_stub.gets if g["url"].endswith("family_alerts")]
    assert len(reads) == 2  # alerts received and alerts sent
    for fa in reads:
        select = fa["params"].get("select", "")
        for forbidden in ("ciphertext", "nonce", "encrypted_payload", "sender_pubkey"):
            assert forbidden not in select, (
                f"family_alerts export must not include {forbidden}; got select={select!r}"
            )


# ─── Failure paths ──────────────────────────────────────────────


def test_export_503_when_supabase_not_configured(client, authed_user, monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "", raising=False)

    resp = client.get("/api/v1/user/export")
    assert resp.status_code == 503


def test_export_partial_failure_surfaces_per_table(
    client, supabase_ok, supabase_stub
):
    """If one table errors upstream, we still return the others and
    flag the failed one — better than 500 on a single transient hiccup."""
    supabase_stub.status_overrides["devices"] = 502

    resp = client.get("/api/v1/user/export")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tables"]["devices"] == {"error": "upstream returned 502"}
    # Other tables still populated
    assert isinstance(body["tables"]["users"], list)


# ─── security alerts ────────────────────────────────────────────


def test_every_export_is_reported_for_anomaly_alerts(client, supabase_ok, supabase_stub, security_events):
    assert client.get("/api/v1/user/export").status_code == 200
    assert security_events == [("user_export", "user-42")]

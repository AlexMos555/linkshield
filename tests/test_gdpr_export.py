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
                # Default: 200 with one fake row echoing the table name
                table = url.rsplit("/", 1)[-1]
                return _Resp(200, [{"_table": table}])

            async def post(self, *_a, **_kw):  # unused on this path
                return _Resp(200, {})

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
    assert body["schema_version"] == 1
    assert "generated_at" in body

    # Every promised table is included in the export.
    expected_tables = {
        "users",
        "subscriptions",
        "user_settings",
        "devices",
        "weekly_aggregates",
        "family_members",
        "family_alerts",
        "feedback_reports",
        "audit_log",
    }
    assert set(body["tables"].keys()) == expected_tables


def test_export_filters_by_user_id_per_table(client, supabase_ok, supabase_stub):
    """No cross-user leak: every Supabase query must scope to the
    authed user's id via the right filter column."""
    client.get("/api/v1/user/export")
    # Map (table → expected filter column)
    expected_filter = {
        "users": "id",
        "subscriptions": "user_id",
        "user_settings": "user_id",
        "devices": "user_id",
        "weekly_aggregates": "user_id",
        "family_members": "user_id",
        "family_alerts": "recipient_user_id",
        "feedback_reports": "user_id",
        "audit_log": "actor_user_id",
    }
    for got in supabase_stub.gets:
        table = got["url"].rsplit("/", 1)[-1]
        filter_col = expected_filter.get(table)
        assert filter_col, f"unexpected table queried: {table}"
        assert got["params"].get(filter_col) == "eq.user-42", (
            f"{table} not filtered by {filter_col}=eq.user-42: {got['params']}"
        )


def test_family_alerts_export_excludes_ciphertext(client, supabase_ok, supabase_stub):
    """Ciphertext + nonce are useless without the device-local private
    key (would just bloat the export and tempt clients to think they
    can decrypt server-side, which they can't)."""
    client.get("/api/v1/user/export")
    fa = next(g for g in supabase_stub.gets if g["url"].endswith("family_alerts"))
    select = fa["params"].get("select", "")
    for forbidden in ("ciphertext", "nonce"):
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

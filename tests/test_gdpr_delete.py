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


@pytest.fixture
def client(authed_user):
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

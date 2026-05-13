"""Tests for api.services.audit_log.

Two layers:
  1. The `write()` helper itself — its contract is fire-and-forget,
     never raising even when Supabase is unreachable or unconfigured,
     correctly hashing the actor IP, and posting the right shape.
  2. Integration — privileged endpoints (account delete/restore) now
     emit audit rows. We pin those wirings here so they don't get
     accidentally dropped during future refactors.
"""
from __future__ import annotations

import hashlib
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier


class _SupabaseRecorder:
    def __init__(self) -> None:
        self.audit_posts: List[Dict[str, Any]] = []
        self.other_posts: List[Dict[str, Any]] = []
        self.post_status = 204
        self.patches: List[Dict[str, Any]] = []

    def build(self):
        recorder = self

        class _Resp:
            def __init__(self, status: int):
                self.status_code = status
                self.text = ""

            def json(self):
                return [{"ok": True}]

        class _Client:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def post(self, url, headers=None, json=None, params=None):
                if "/rest/v1/audit_log" in url:
                    recorder.audit_posts.append(json or {})
                else:
                    recorder.other_posts.append({"url": url, "body": json or {}})
                return _Resp(recorder.post_status)

            async def patch(self, url, headers=None, json=None, params=None):
                recorder.patches.append(
                    {"url": url, "body": json or {}, "params": dict(params or {})}
                )
                return _Resp(204)

        return _Client


@pytest.fixture
def supabase_ok(monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    return s


@pytest.fixture
def supabase_recorder(monkeypatch):
    import httpx as _httpx

    rec = _SupabaseRecorder()
    monkeypatch.setattr(_httpx, "AsyncClient", rec.build())
    return rec


# ─── audit_log.write() unit tests ─────────────────────────────


@pytest.mark.asyncio
async def test_write_posts_to_audit_log_endpoint(supabase_ok, supabase_recorder):
    from api.services import audit_log

    await audit_log.write(
        action="account.delete_requested",
        target_kind="user",
        target_id="user-42",
        actor_user_id="user-42",
        meta={"reason": "self-service"},
    )
    assert len(supabase_recorder.audit_posts) == 1
    row = supabase_recorder.audit_posts[0]
    assert row["action"] == "account.delete_requested"
    assert row["target_kind"] == "user"
    assert row["target_id"] == "user-42"
    assert row["actor_user_id"] == "user-42"
    assert row["meta"] == {"reason": "self-service"}


@pytest.mark.asyncio
async def test_write_hashes_ip_with_sha256_prefix(supabase_ok, supabase_recorder):
    from api.services import audit_log

    await audit_log.write(
        action="any.thing",
        target_kind="user",
        target_id="u",
        actor_ip="203.0.113.7",
    )
    row = supabase_recorder.audit_posts[0]
    # 16-hex-char prefix of sha256 hex — predictable so we can pin it.
    expected = hashlib.sha256(b"203.0.113.7").hexdigest()[:16]
    assert row["actor_ip_hash"] == expected


@pytest.mark.asyncio
async def test_write_omits_ip_when_none(supabase_ok, supabase_recorder):
    """System events (Stripe webhook, purge cron) have no caller IP.
    actor_ip_hash must be NULL in those rows, not the empty-string
    hash of "" or similar nonsense."""
    from api.services import audit_log

    await audit_log.write(
        action="account.hard_deleted",
        target_kind="user",
        target_id="u",
    )
    assert supabase_recorder.audit_posts[0]["actor_ip_hash"] is None


@pytest.mark.asyncio
async def test_write_never_raises_when_supabase_unconfigured(monkeypatch):
    """No env → log + return. Calling code does NOT want to handle
    this case for every audit-relevant operation."""
    from api import config
    from api.services import audit_log

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "", raising=False)

    # Should not raise.
    await audit_log.write(
        action="account.delete_requested",
        target_kind="user",
        target_id="u",
    )


@pytest.mark.asyncio
async def test_write_never_raises_on_network_failure(supabase_ok, monkeypatch):
    """Connection error → log + return. Same fire-and-forget contract."""
    import httpx as _httpx
    from api.services import audit_log

    class _BoomClient:
        def __init__(self, *_a, **_k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return None

        async def post(self, *_a, **_kw):
            raise ConnectionError("network down")

    monkeypatch.setattr(_httpx, "AsyncClient", _BoomClient)
    # Should not raise.
    await audit_log.write(action="x", target_kind="u", target_id="u")


# ─── Integration: GDPR endpoints emit audit rows ───────────────


@pytest.fixture
def authed_user():
    return AuthUser(id="user-audit", email="z@gmail.com", tier=UserTier.free)


@pytest.fixture
def client(authed_user):
    from api.main import app
    from api.services.auth import get_current_user

    async def _override():
        return authed_user

    app.dependency_overrides[get_current_user] = _override
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


def test_delete_account_writes_audit_row(client, supabase_ok, supabase_recorder):
    resp = client.delete("/api/v1/user/account")
    assert resp.status_code == 200
    # PATCH set deletion_requested_at; POST went to audit_log.
    audit_rows = [
        p for p in supabase_recorder.audit_posts
        if p.get("action") == "account.delete_requested"
    ]
    assert len(audit_rows) == 1
    row = audit_rows[0]
    assert row["target_id"] == "user-audit"
    assert row["actor_user_id"] == "user-audit"
    assert "restore_until" in row.get("meta", {})


def test_restore_account_writes_audit_row(client, supabase_ok, supabase_recorder):
    resp = client.post("/api/v1/user/account/restore")
    assert resp.status_code == 200
    audit_rows = [
        p for p in supabase_recorder.audit_posts
        if p.get("action") == "account.restored"
    ]
    assert len(audit_rows) == 1
    assert audit_rows[0]["target_id"] == "user-audit"

"""Tests for /api/v1/feedback/report — anonymous submission path.

The endpoint historically required `get_current_user` (any caller had
to pass a Bearer JWT). The Outlook add-in lives in Office.js with no
Cleanway session yet, so phishing reports from there 401-ed silently.

After the fix, the endpoint uses `get_optional_user`: anonymous calls
go through, with `user_id=null` in the persisted row. Authenticated
calls still attach the user_id as before.

Backend invariants pinned here:
  - 200 OK without an Authorization header
  - 200 OK with a valid token (user_id flows to DB row)
  - 400 on bad report_type
  - 422 on missing required fields
"""
from __future__ import annotations

from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier


class _SupabaseRecorder:
    """Captures POSTs to /rest/v1/feedback_reports for assertion."""

    def __init__(self) -> None:
        self.posts: List[Dict[str, Any]] = []

    def build(self):
        recorder = self

        class _Resp:
            def __init__(self, status: int):
                self.status_code = status

            def json(self):
                return [{"ok": True}]

        class _Client:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def post(self, url, headers=None, json=None, **_kw):
                if "/rest/v1/feedback_reports" in url:
                    recorder.posts.append(json or {})
                return _Resp(201)

        return _Client


@pytest.fixture
def supabase_ok(monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    return s


@pytest.fixture
def fake_supabase(monkeypatch):
    import httpx as _httpx

    rec = _SupabaseRecorder()
    monkeypatch.setattr(_httpx, "AsyncClient", rec.build())
    return rec


@pytest.fixture
def client():
    from api.main import app
    return TestClient(app)


# ─── Anonymous path ─────────────────────────────────────────────


def test_anonymous_report_accepted(client, supabase_ok, fake_supabase):
    """No Authorization header → still 200, persists with user_id=null."""
    resp = client.post(
        "/api/v1/feedback/report",
        json={
            "domain": "evil-bank.tk",
            "report_type": "false_negative",
            "comment": "[outlook] subject=\"Account locked\"",
        },
    )
    assert resp.status_code == 200, resp.text
    assert len(fake_supabase.posts) == 1
    row = fake_supabase.posts[0]
    assert row["domain"] == "evil-bank.tk"
    assert row["report_type"] == "false_negative"
    assert row["user_id"] is None  # anonymous


def test_anonymous_rejects_bad_report_type(client, supabase_ok, fake_supabase):
    resp = client.post(
        "/api/v1/feedback/report",
        json={"domain": "x.com", "report_type": "phishing"},  # invalid value
    )
    assert resp.status_code == 400
    assert fake_supabase.posts == []


def test_anonymous_missing_domain_422(client, supabase_ok, fake_supabase):
    resp = client.post(
        "/api/v1/feedback/report",
        json={"report_type": "false_negative"},
    )
    assert resp.status_code == 422


# ─── Authenticated path still works ────────────────────────────


def test_authenticated_report_attaches_user_id(client, supabase_ok, fake_supabase):
    """When a JWT is present, user_id flows to the persisted row."""
    from api.main import app
    from api.services.auth import get_current_user, get_current_user_including_deleted, get_optional_user

    fake_user = AuthUser(id="user-42", email="alice@gmail.com", tier=UserTier.free)

    async def _override():
        return fake_user

    app.dependency_overrides[get_current_user] = _override
    app.dependency_overrides[get_current_user_including_deleted] = _override
    app.dependency_overrides[get_optional_user] = _override
    try:
        resp = client.post(
            "/api/v1/feedback/report",
            json={"domain": "scam.example", "report_type": "false_negative"},
            headers={"Authorization": "Bearer doesnt-matter"},
        )
        assert resp.status_code == 200, resp.text
        assert len(fake_supabase.posts) == 1
        assert fake_supabase.posts[0]["user_id"] == "user-42"
    finally:
        app.dependency_overrides.clear()

"""
POST /api/v1/auth/extension-session — the browser extension's own session.

cleanway.ai/extension/connect calls this with the website's access token and
hands the result to the extension. Pinned here:

- the session is opened for the address in the VERIFIED token, never one from
  the request body, via admin/generate_link (no email sent) + /verify;
- the answer carries the new pair and is marked no-store;
- a session that resolves to a different user is refused, not returned;
- upstream failures are a 502 with no token in the logs;
- the sensitive-action limit is consulted, and an unconfigured server says 503.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List

import httpx
import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier

USER = AuthUser(id="user-123", email="ann@example.com", tier=UserTier.free)
NEW_ACCESS = "new-access-token-for-the-extension"
NEW_REFRESH = "new-refresh-token-abc"


class _Resp:
    def __init__(self, status: int, body: Any):
        self.status_code = status
        self._body = body

    def json(self) -> Any:
        return self._body


class _FakeClient:
    """Records calls; answers generate_link and verify from `script`."""

    calls: List[Dict[str, Any]] = []
    script: Dict[str, Any] = {}

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url: str, headers=None, json=None):
        _FakeClient.calls.append({"url": url, "headers": headers or {}, "json": json})
        for suffix, answer in _FakeClient.script.items():
            if url.endswith(suffix):
                if isinstance(answer, Exception):
                    raise answer
                return answer
        raise AssertionError(f"unexpected POST {url}")


def _ok_script(user_id: str = USER.id) -> Dict[str, Any]:
    return {
        "/auth/v1/admin/generate_link": _Resp(
            200,
            {"id": user_id, "email": USER.email, "hashed_token": "hashed-xyz", "verification_type": "magiclink"},
        ),
        "/auth/v1/verify": _Resp(
            200,
            {
                "access_token": NEW_ACCESS,
                "refresh_token": NEW_REFRESH,
                "expires_at": 1_900_000_000,
                "expires_in": 3600,
                "user": {"id": user_id, "email": USER.email},
            },
        ),
    }


@pytest.fixture
def client(monkeypatch):
    from api import config
    from api.main import app
    from api.services.auth import get_current_user

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "https://proj.supabase.co", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "service-key-test", raising=False)
    monkeypatch.setattr(settings, "supabase_anon_key", "anon-key-test", raising=False)

    limited: List[str] = []

    async def _limit(user, category):
        limited.append(category)
        return 9

    monkeypatch.setattr("api.routers.auth.check_sensitive_action_limit", _limit)
    monkeypatch.setattr("api.routers.auth.httpx.AsyncClient", _FakeClient)
    _FakeClient.calls = []
    _FakeClient.script = _ok_script()

    app.dependency_overrides[get_current_user] = lambda: USER
    c = TestClient(app)
    c.limited = limited  # type: ignore[attr-defined]
    try:
        yield c
    finally:
        app.dependency_overrides.clear()


def _post(c: TestClient, **kw):
    return c.post("/api/v1/auth/extension-session", headers={"Authorization": "Bearer web-token"}, **kw)


def test_opens_a_new_session_for_the_token_owner(client):
    resp = _post(client, json={"email": "mallory@evil.test"})
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"access_token": NEW_ACCESS, "refresh_token": NEW_REFRESH, "expires_at": 1_900_000_000}
    assert resp.headers["cache-control"] == "no-store"

    link, verify = _FakeClient.calls
    assert link["url"] == "https://proj.supabase.co/auth/v1/admin/generate_link"
    # The address comes from the verified token, never the body.
    assert link["json"] == {"type": "magiclink", "email": "ann@example.com"}
    assert link["headers"]["Authorization"] == "Bearer service-key-test"
    assert verify["url"] == "https://proj.supabase.co/auth/v1/verify"
    assert verify["json"] == {"type": "magiclink", "token_hash": "hashed-xyz"}
    # /verify is public: the anon key as apikey, no service-key Bearer.
    assert verify["headers"]["apikey"] == "anon-key-test"
    assert "Authorization" not in verify["headers"]
    assert client.limited == ["extension_session"]


def test_supabase_js_shaped_link_answer_is_accepted(client):
    _FakeClient.script["/auth/v1/admin/generate_link"] = _Resp(
        200, {"properties": {"hashed_token": "h2", "verification_type": "signup"}, "user": {"id": USER.id}}
    )
    resp = _post(client)
    assert resp.status_code == 200
    assert _FakeClient.calls[1]["json"] == {"type": "signup", "token_hash": "h2"}


def test_expires_at_falls_back_to_expires_in(client):
    body = _FakeClient.script["/auth/v1/verify"]._body
    del body["expires_at"]
    resp = _post(client)
    assert resp.status_code == 200
    assert resp.json()["expires_at"] > 1_600_000_000


def test_session_for_another_user_is_refused(client):
    _FakeClient.script = _ok_script(user_id="someone-else")
    resp = _post(client)
    assert resp.status_code == 409
    assert NEW_REFRESH not in resp.text


@pytest.mark.parametrize(
    "suffix,answer",
    [
        ("/auth/v1/admin/generate_link", _Resp(422, {"msg": "nope"})),
        ("/auth/v1/admin/generate_link", _Resp(200, {"id": USER.id})),
        ("/auth/v1/verify", _Resp(403, {"msg": "expired"})),
        ("/auth/v1/verify", _Resp(200, {"user": {"id": USER.id}})),
        ("/auth/v1/verify", httpx.ConnectTimeout("slow")),
    ],
)
def test_upstream_failures_are_502_without_tokens_in_logs(client, caplog, suffix, answer):
    _FakeClient.script[suffix] = answer
    with caplog.at_level(logging.DEBUG):
        resp = _post(client)
    assert resp.status_code == 502
    text = caplog.text + resp.text
    assert NEW_REFRESH not in text and NEW_ACCESS not in text and "hashed-xyz" not in text


def test_unconfigured_server_is_503(client, monkeypatch):
    from api import config

    monkeypatch.setattr(config.get_settings(), "supabase_service_key", "", raising=False)
    assert _post(client).status_code == 503
    assert _FakeClient.calls == []


def test_account_without_email_is_409(client):
    from api.main import app
    from api.services.auth import get_current_user

    app.dependency_overrides[get_current_user] = lambda: AuthUser(id="u", email=None, tier=UserTier.free)
    assert _post(client).status_code == 409
    assert _FakeClient.calls == []


def test_requires_a_signed_in_user():
    from api.main import app

    app.dependency_overrides.clear()
    resp = TestClient(app).post("/api/v1/auth/extension-session")
    assert resp.status_code == 401

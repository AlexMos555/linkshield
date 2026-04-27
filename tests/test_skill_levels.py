"""
Tests for skill-level resolution + device override endpoints.

Covers the wiring between:
  users.skill_level / .voice_alerts_enabled / .font_scale  (account default)
  devices.skill_level_override / .voice_alerts_enabled / .font_scale  (per-device)

Family Hub use case: admin sets Granny Mode on grandmother's phone
without touching her account-level default. The extension queries
GET /effective on render to know which UX mode to use.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier


@pytest.fixture
def authed_user():
    return AuthUser(id="user-skill", email="u@test.com", tier=UserTier.free)


@pytest.fixture
def supabase_ok(monkeypatch):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "service-key-test", raising=False)
    return settings


@pytest.fixture
def app(authed_user):
    from api.main import app as fastapi_app
    from api.services.auth import get_current_user, get_optional_user

    fastapi_app.dependency_overrides[get_current_user] = lambda: authed_user
    fastapi_app.dependency_overrides[get_optional_user] = lambda: authed_user
    yield fastapi_app
    fastapi_app.dependency_overrides.clear()


@pytest.fixture
def client(app):
    return TestClient(app)


class FakeSupabase:
    """Stand-in routing GET/PATCH on /users + /devices."""

    def __init__(
        self,
        user_row: Optional[Dict[str, Any]] = None,
        device_row: Optional[Dict[str, Any]] = None,
    ):
        self.user_row = user_row
        self.device_row = device_row
        self.patch_calls: List[Dict[str, Any]] = []

    def build(self):
        fake = self

        class _Resp:
            def __init__(self, status: int, body: Any):
                self.status_code = status
                self._body = body

            def json(self):
                return self._body

        class _MockClient:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def get(self, url, params=None, headers=None):
                if "/rest/v1/users" in url:
                    return _Resp(200, [fake.user_row] if fake.user_row else [])
                if "/rest/v1/devices" in url:
                    return _Resp(200, [fake.device_row] if fake.device_row else [])
                return _Resp(404, [])

            async def patch(self, url, params=None, json=None, headers=None):
                fake.patch_calls.append({"url": url, "params": params, "json": json})
                # Merge into device_row
                if "/rest/v1/devices" in url:
                    fake.device_row = {**(fake.device_row or {}), **(json or {})}
                return _Resp(204, "")

        return _MockClient


@pytest.fixture
def fake_sb(monkeypatch):
    import httpx as _httpx

    fake = FakeSupabase()
    monkeypatch.setattr(_httpx, "AsyncClient", fake.build())
    return fake


# ─── GET /effective ───────────────────────────────────────────────


def test_effective_falls_back_to_user_default_when_no_override(
    client, supabase_ok, fake_sb
):
    fake_sb.user_row = {
        "skill_level": "granny",
        "voice_alerts_enabled": True,
        "font_scale": 1.5,
    }
    fake_sb.device_row = None

    resp = client.get("/api/v1/user/device/dev-hash-1/effective")
    assert resp.status_code == 200
    body = resp.json()
    assert body["skill_level"] == "granny"
    assert body["voice_alerts_enabled"] is True
    assert body["font_scale"] == 1.5
    assert body["skill_source"] == "user_default"
    assert body["voice_source"] == "user_default"
    assert body["font_source"] == "user_default"


def test_effective_uses_device_override_when_set(client, supabase_ok, fake_sb):
    fake_sb.user_row = {
        "skill_level": "regular",
        "voice_alerts_enabled": False,
        "font_scale": 1.0,
    }
    # Family Hub admin set grandma's specific phone to Granny Mode
    fake_sb.device_row = {
        "skill_level_override": "granny",
        "voice_alerts_enabled": True,
        "font_scale": 1.8,
    }

    resp = client.get("/api/v1/user/device/grandma-phone/effective")
    body = resp.json()
    assert body["skill_level"] == "granny"
    assert body["voice_alerts_enabled"] is True
    assert body["font_scale"] == 1.8
    assert body["skill_source"] == "device_override"
    assert body["voice_source"] == "device_override"
    assert body["font_source"] == "device_override"


def test_effective_partial_override_only_some_fields(client, supabase_ok, fake_sb):
    """Device sets only font_scale; skill_level + voice come from user."""
    fake_sb.user_row = {
        "skill_level": "regular",
        "voice_alerts_enabled": False,
        "font_scale": 1.0,
    }
    fake_sb.device_row = {
        "skill_level_override": None,
        "voice_alerts_enabled": None,
        "font_scale": 1.4,
    }

    resp = client.get("/api/v1/user/device/dev-hash-2/effective")
    body = resp.json()
    assert body["skill_level"] == "regular"
    assert body["skill_source"] == "user_default"
    assert body["font_scale"] == 1.4
    assert body["font_source"] == "device_override"


def test_effective_returns_safe_defaults_when_supabase_missing(
    client, monkeypatch
):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "", raising=False)

    resp = client.get("/api/v1/user/device/anything/effective")
    body = resp.json()
    assert body["skill_level"] == "regular"
    assert body["voice_alerts_enabled"] is False
    assert body["font_scale"] == 1.0


# ─── PATCH /overrides ────────────────────────────────────────────


def test_patch_overrides_persists_skill(client, supabase_ok, fake_sb):
    fake_sb.user_row = {"skill_level": "regular", "voice_alerts_enabled": False, "font_scale": 1.0}
    resp = client.patch(
        "/api/v1/user/device/dev-1/overrides",
        json={"skill_level_override": "granny", "voice_alerts_enabled": True, "font_scale": 1.6},
    )
    assert resp.status_code == 200
    assert len(fake_sb.patch_calls) == 1
    sent = fake_sb.patch_calls[0]["json"]
    assert sent["skill_level_override"] == "granny"
    assert sent["voice_alerts_enabled"] is True
    assert sent["font_scale"] == 1.6
    # Effective should reflect the new override
    body = resp.json()
    assert body["skill_level"] == "granny"
    assert body["skill_source"] == "device_override"


def test_patch_clear_overrides_resets_to_defaults(client, supabase_ok, fake_sb):
    fake_sb.user_row = {"skill_level": "regular", "voice_alerts_enabled": False, "font_scale": 1.0}
    fake_sb.device_row = {
        "skill_level_override": "granny",
        "voice_alerts_enabled": True,
        "font_scale": 1.8,
    }

    resp = client.patch(
        "/api/v1/user/device/dev-1/overrides",
        json={"clear_overrides": True},
    )
    assert resp.status_code == 200
    sent = fake_sb.patch_calls[0]["json"]
    assert sent["skill_level_override"] is None
    assert sent["voice_alerts_enabled"] is False
    assert sent["font_scale"] == 1.0


def test_patch_rejects_out_of_range_font_scale(client, supabase_ok, fake_sb):
    for bad in (0.5, 0.79, 2.51, 5.0):
        resp = client.patch(
            "/api/v1/user/device/dev-1/overrides",
            json={"font_scale": bad},
        )
        assert resp.status_code == 422, f"expected 422 for font_scale={bad}"


def test_patch_returns_503_when_supabase_missing(client, monkeypatch):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "", raising=False)

    resp = client.patch(
        "/api/v1/user/device/dev-1/overrides",
        json={"skill_level_override": "granny"},
    )
    assert resp.status_code == 503

"""
Tests for /api/v1/user/settings — Skill Levels foundation.

Covers:
- GET defaults when Supabase unreachable or user row missing
- GET parses existing user row
- PUT validates font_scale, locale, PIN format
- PUT persists partial updates (skill_level only, locale only, etc.)
- PIN hashing never leaks PIN back to client
- parental_pin="" clears PIN
"""
from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, SkillLevel, UserTier


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def authed_user():
    return AuthUser(id="user-abc", email="u@test.com", tier=UserTier.free)


@pytest.fixture
def supabase_ok(monkeypatch):
    """Force config to look as if Supabase creds are present."""
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(
        settings, "supabase_service_key", "service-key-test", raising=False
    )
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
    """
    Minimal Supabase REST stand-in. Supports GET /rest/v1/users (select) +
    PATCH /rest/v1/users. Keyed by id eq.user-abc.
    """

    def __init__(self) -> None:
        self.row: Dict[str, Any] = {
            "skill_level": "regular",
            "preferred_locale": "en",
            "voice_alerts_enabled": False,
            "font_scale": 1.0,
            "parental_pin_hash": None,
        }
        self.patch_calls: List[Dict[str, Any]] = []

    def build_mock_client(self):
        fake = self  # capture

        class _Resp:
            def __init__(self, status: int, body: Any):
                self.status_code = status
                self._body = body

            def json(self):
                return self._body

        class _MockAsyncClient:
            def __init__(self, *_args, **_kwargs):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def get(self, url, params=None, headers=None):
                # Return array with one row
                return _Resp(200, [fake.row])

            async def patch(self, url, params=None, json=None, headers=None):
                # Record + merge
                fake.patch_calls.append(json or {})
                fake.row.update(json or {})
                return _Resp(200, [fake.row])

        return _MockAsyncClient


@pytest.fixture
def fake_supabase(monkeypatch):
    import httpx as _httpx

    fake = FakeSupabase()
    monkeypatch.setattr(_httpx, "AsyncClient", fake.build_mock_client())
    return fake


# ─── GET /user/settings ──────────────────────────────────────────────────────


def test_get_settings_returns_defaults_when_supabase_unconfigured(
    client, monkeypatch
):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "", raising=False)

    resp = client.get("/api/v1/user/settings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["skill_level"] == "regular"
    assert body["preferred_locale"] == "en"
    assert body["voice_alerts_enabled"] is False
    assert body["font_scale"] == 1.0
    assert body["parental_pin_set"] is False


def test_get_settings_parses_supabase_row(
    client, supabase_ok, fake_supabase
):
    fake_supabase.row.update(
        {
            "skill_level": "granny",
            "preferred_locale": "ru",
            "voice_alerts_enabled": True,
            "font_scale": 1.4,
            "parental_pin_hash": "some-bcrypt-hash-will-be-here",
        }
    )
    resp = client.get("/api/v1/user/settings")
    assert resp.status_code == 200
    body = resp.json()
    assert body["skill_level"] == "granny"
    assert body["preferred_locale"] == "ru"
    assert body["voice_alerts_enabled"] is True
    assert body["font_scale"] == 1.4
    # PIN hash is NEVER returned — only the derived boolean flag
    assert "parental_pin_hash" not in body
    assert "parental_pin" not in body
    assert body["parental_pin_set"] is True


def test_get_settings_unknown_skill_level_falls_back_to_default(
    client, supabase_ok, fake_supabase
):
    fake_supabase.row["skill_level"] = "invalid-value"
    resp = client.get("/api/v1/user/settings")
    assert resp.status_code == 200
    # Should fall back to default without 500
    assert resp.json()["skill_level"] == "regular"


# ─── PUT /user/settings ──────────────────────────────────────────────────────


def test_put_settings_updates_skill_level(client, supabase_ok, fake_supabase):
    resp = client.put("/api/v1/user/settings", json={"skill_level": "kids"})
    assert resp.status_code == 200
    assert resp.json()["skill_level"] == "kids"
    assert fake_supabase.patch_calls[-1] == {"skill_level": "kids"}


def test_put_settings_updates_locale(client, supabase_ok, fake_supabase):
    resp = client.put("/api/v1/user/settings", json={"preferred_locale": "es"})
    assert resp.status_code == 200
    assert resp.json()["preferred_locale"] == "es"


def test_put_settings_rejects_invalid_locale(client, supabase_ok, fake_supabase):
    resp = client.put("/api/v1/user/settings", json={"preferred_locale": "jp"})
    assert resp.status_code == 422


def test_put_settings_rejects_font_scale_out_of_range(
    client, supabase_ok, fake_supabase
):
    for bad in (0.5, 3.0, -1.0, 99.0):
        resp = client.put("/api/v1/user/settings", json={"font_scale": bad})
        assert resp.status_code == 422, f"font_scale={bad} should be rejected"


def test_put_settings_accepts_font_scale_in_range(client, supabase_ok, fake_supabase):
    for good in (0.8, 1.0, 1.3, 2.5):
        resp = client.put("/api/v1/user/settings", json={"font_scale": good})
        assert resp.status_code == 200
        assert resp.json()["font_scale"] == good


def test_put_settings_rejects_bad_pin(client, supabase_ok, fake_supabase):
    for bad in ("12", "12345", "abcd", "12a4"):
        resp = client.put("/api/v1/user/settings", json={"parental_pin": bad})
        assert resp.status_code == 422, f"pin={bad!r} should be rejected"


def test_put_settings_sets_pin_and_hashes_it(client, supabase_ok, fake_supabase):
    resp = client.put("/api/v1/user/settings", json={"parental_pin": "1234"})
    assert resp.status_code == 200
    body = resp.json()
    # PIN itself must never be echoed back
    assert "parental_pin" not in body
    # But the flag flips on
    assert body["parental_pin_set"] is True
    # Hash was stored in the "DB"
    hash_stored = fake_supabase.row["parental_pin_hash"]
    assert hash_stored is not None
    # It is a bcrypt hash, not the plaintext
    assert hash_stored != "1234"
    assert hash_stored.startswith("$2")  # bcrypt marker


def test_put_settings_clears_pin_when_empty_string(
    client, supabase_ok, fake_supabase
):
    fake_supabase.row["parental_pin_hash"] = "some-old-hash"
    resp = client.put("/api/v1/user/settings", json={"parental_pin": ""})
    assert resp.status_code == 200
    assert resp.json()["parental_pin_set"] is False
    assert fake_supabase.row["parental_pin_hash"] is None


def test_put_settings_omitting_pin_leaves_it_alone(
    client, supabase_ok, fake_supabase
):
    existing_hash = "$2b$12$existing"
    fake_supabase.row["parental_pin_hash"] = existing_hash
    resp = client.put("/api/v1/user/settings", json={"skill_level": "pro"})
    assert resp.status_code == 200
    # Untouched
    assert fake_supabase.row["parental_pin_hash"] == existing_hash


def test_put_settings_empty_body_returns_current(client, supabase_ok, fake_supabase):
    resp = client.put("/api/v1/user/settings", json={})
    assert resp.status_code == 200
    assert fake_supabase.patch_calls == []  # no PATCH made


def test_put_settings_multi_field_update(client, supabase_ok, fake_supabase):
    resp = client.put(
        "/api/v1/user/settings",
        json={
            "skill_level": "granny",
            "preferred_locale": "ru",
            "voice_alerts_enabled": True,
            "font_scale": 1.3,
        },
    )
    assert resp.status_code == 200
    last = fake_supabase.patch_calls[-1]
    assert last["skill_level"] == "granny"
    assert last["preferred_locale"] == "ru"
    assert last["voice_alerts_enabled"] is True
    assert last["font_scale"] == 1.3


def test_put_settings_503_when_supabase_unconfigured(client, monkeypatch):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "", raising=False)

    resp = client.put("/api/v1/user/settings", json={"skill_level": "kids"})
    assert resp.status_code == 503


# ─── Schema sanity ───────────────────────────────────────────────────────────


def test_skill_level_enum_values():
    assert SkillLevel.kids.value == "kids"
    assert SkillLevel.regular.value == "regular"
    assert SkillLevel.granny.value == "granny"
    assert SkillLevel.pro.value == "pro"

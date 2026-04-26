"""
Tests for Pricing v2 50-threat freemium counter + detail gating.

Block UI is FREE FOREVER (ethical baseline). What gets gated for free users
past the threshold is the *detail* panel — domain history, scheme breakdown,
annotated screenshots. This counter feeds that gating decision.

Covers:
- GET /threats/status returns zero-state when Supabase unreachable
- GET reads existing counter + nudge fields
- POST /threats/increment adds N, persists, returns updated state
- Validation: count must be ≥ 1
- Gating logic across tiers and threshold boundary
- First-crossing transition sets `nudge_shown_at` exactly once
- Pro/Family/Business tiers are NEVER gated, regardless of counter
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier
from api.routers.user import (
    FREEMIUM_DETAIL_GATING_THRESHOLD,
    _is_gated,
)


# ─── Pure-function unit tests ──────────────────────────────────────


class TestGatingLogic:
    def test_free_tier_below_threshold_not_gated(self):
        assert _is_gated("free", 0) is False
        assert _is_gated("free", FREEMIUM_DETAIL_GATING_THRESHOLD - 1) is False

    def test_free_tier_at_threshold_gated(self):
        assert _is_gated("free", FREEMIUM_DETAIL_GATING_THRESHOLD) is True

    def test_free_tier_far_past_threshold_gated(self):
        assert _is_gated("free", 9999) is True

    @pytest.mark.parametrize("tier", ["personal", "family", "business"])
    def test_paid_tiers_never_gated(self, tier):
        assert _is_gated(tier, 0) is False
        assert _is_gated(tier, FREEMIUM_DETAIL_GATING_THRESHOLD * 100) is False


# ─── HTTP integration tests ────────────────────────────────────────


@pytest.fixture
def free_user():
    return AuthUser(id="user-free", email="free@test.com", tier=UserTier.free)


@pytest.fixture
def paid_user():
    return AuthUser(id="user-paid", email="paid@test.com", tier=UserTier.personal)


@pytest.fixture
def supabase_ok(monkeypatch):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(
        settings, "supabase_service_key", "service-key-test", raising=False
    )
    return settings


def _make_app(authed: AuthUser):
    from api.main import app as fastapi_app
    from api.services.auth import get_current_user, get_optional_user

    fastapi_app.dependency_overrides[get_current_user] = lambda: authed
    fastapi_app.dependency_overrides[get_optional_user] = lambda: authed
    return fastapi_app


@pytest.fixture
def free_client(free_user):
    app = _make_app(free_user)
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def paid_client(paid_user):
    app = _make_app(paid_user)
    yield TestClient(app)
    app.dependency_overrides.clear()


class FakeUserSettings:
    """Minimal stand-in for /rest/v1/user_settings GET + POST upsert."""

    def __init__(self, initial: Optional[Dict[str, Any]] = None):
        self.row: Optional[Dict[str, Any]] = initial
        self.post_calls: List[Dict[str, Any]] = []

    def build_mock_client(self):
        fake = self

        class _Resp:
            def __init__(self, status: int, body: Any):
                self.status_code = status
                self._body = body

            def json(self):
                return self._body

        class _MockAsyncClient:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def get(self, url, params=None, headers=None):
                return _Resp(200, [fake.row] if fake.row else [])

            async def post(self, url, json=None, headers=None, params=None):
                fake.post_calls.append(json or {})
                # Upsert merges into the canonical row
                fake.row = {**(fake.row or {}), **(json or {})}
                return _Resp(201, "")

        return _MockAsyncClient


@pytest.fixture
def fake_us(monkeypatch):
    import httpx as _httpx

    fake = FakeUserSettings()
    monkeypatch.setattr(_httpx, "AsyncClient", fake.build_mock_client())
    return fake


# ─── GET /threats/status ───────────────────────────────────────────


def test_status_returns_zero_when_supabase_missing(free_client, monkeypatch):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "", raising=False)

    resp = free_client.get("/api/v1/user/threats/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["threats_blocked_lifetime"] == 0
    assert body["threshold"] == FREEMIUM_DETAIL_GATING_THRESHOLD
    assert body["gated"] is False
    assert body["tier"] == "free"
    assert body["nudge_shown_at"] is None
    assert body["nudge_count"] == 0


def test_status_reflects_db_counter_below_threshold(
    free_client, supabase_ok, fake_us
):
    fake_us.row = {
        "threats_blocked_lifetime": 12,
        "threshold_nudge_shown_at": None,
        "threshold_nudge_count": 0,
    }
    resp = free_client.get("/api/v1/user/threats/status")
    body = resp.json()
    assert body["threats_blocked_lifetime"] == 12
    assert body["gated"] is False
    assert body["tier"] == "free"


def test_status_gated_for_free_user_at_threshold(
    free_client, supabase_ok, fake_us
):
    fake_us.row = {
        "threats_blocked_lifetime": FREEMIUM_DETAIL_GATING_THRESHOLD,
        "threshold_nudge_shown_at": "2026-04-25T12:00:00+00:00",
        "threshold_nudge_count": 1,
    }
    resp = free_client.get("/api/v1/user/threats/status")
    body = resp.json()
    assert body["gated"] is True
    assert body["nudge_shown_at"] == "2026-04-25T12:00:00+00:00"
    assert body["nudge_count"] == 1


def test_status_paid_user_never_gated_even_past_threshold(
    paid_client, supabase_ok, fake_us
):
    fake_us.row = {
        "threats_blocked_lifetime": 9999,
        "threshold_nudge_shown_at": None,
        "threshold_nudge_count": 0,
    }
    resp = paid_client.get("/api/v1/user/threats/status")
    body = resp.json()
    assert body["threats_blocked_lifetime"] == 9999
    assert body["gated"] is False
    assert body["tier"] == "personal"


# ─── POST /threats/increment ───────────────────────────────────────


def test_increment_adds_count_and_persists(free_client, supabase_ok, fake_us):
    fake_us.row = {
        "threats_blocked_lifetime": 5,
        "threshold_nudge_shown_at": None,
        "threshold_nudge_count": 0,
    }
    resp = free_client.post("/api/v1/user/threats/increment", json={"count": 3})
    assert resp.status_code == 200
    body = resp.json()
    assert body["threats_blocked_lifetime"] == 8
    assert body["gated"] is False

    # Verify upsert payload
    assert len(fake_us.post_calls) == 1
    sent = fake_us.post_calls[0]
    assert sent["threats_blocked_lifetime"] == 8
    assert sent["user_id"] == "user-free"


def test_increment_default_count_is_one(free_client, supabase_ok, fake_us):
    fake_us.row = {"threats_blocked_lifetime": 0}
    resp = free_client.post("/api/v1/user/threats/increment", json={})
    assert resp.status_code == 200
    assert resp.json()["threats_blocked_lifetime"] == 1


def test_increment_rejects_zero_or_negative(free_client, supabase_ok, fake_us):
    fake_us.row = {"threats_blocked_lifetime": 0}
    for bad in (0, -1, -100):
        resp = free_client.post(
            "/api/v1/user/threats/increment", json={"count": bad}
        )
        assert resp.status_code == 422, f"expected 422 for count={bad}"


def test_increment_rejects_huge_count(free_client, supabase_ok, fake_us):
    fake_us.row = {"threats_blocked_lifetime": 0}
    resp = free_client.post(
        "/api/v1/user/threats/increment", json={"count": 1_000_000}
    )
    assert resp.status_code == 422


def test_increment_first_crossing_sets_nudge_timestamp(
    free_client, supabase_ok, fake_us
):
    """Free user crosses 49 → 50: server should stamp nudge_shown_at."""
    fake_us.row = {
        "threats_blocked_lifetime": FREEMIUM_DETAIL_GATING_THRESHOLD - 1,
        "threshold_nudge_shown_at": None,
        "threshold_nudge_count": 0,
    }
    resp = free_client.post(
        "/api/v1/user/threats/increment", json={"count": 1}
    )
    body = resp.json()
    assert body["threats_blocked_lifetime"] == FREEMIUM_DETAIL_GATING_THRESHOLD
    assert body["gated"] is True
    assert body["nudge_shown_at"] is not None
    # Persisted with the timestamp
    assert fake_us.post_calls[0]["threshold_nudge_shown_at"] is not None


def test_increment_subsequent_does_not_overwrite_nudge_timestamp(
    free_client, supabase_ok, fake_us
):
    """Already-stamped nudge stays put on later increments."""
    earlier = "2026-04-20T10:00:00+00:00"
    fake_us.row = {
        "threats_blocked_lifetime": FREEMIUM_DETAIL_GATING_THRESHOLD + 5,
        "threshold_nudge_shown_at": earlier,
        "threshold_nudge_count": 1,
    }
    resp = free_client.post(
        "/api/v1/user/threats/increment", json={"count": 7}
    )
    body = resp.json()
    assert body["threats_blocked_lifetime"] == FREEMIUM_DETAIL_GATING_THRESHOLD + 12
    assert body["gated"] is True
    assert body["nudge_shown_at"] == earlier


def test_increment_paid_user_crossing_threshold_does_not_stamp_nudge(
    paid_client, supabase_ok, fake_us
):
    """Paid users never get the gating nudge, even when crossing the boundary."""
    fake_us.row = {
        "threats_blocked_lifetime": FREEMIUM_DETAIL_GATING_THRESHOLD - 1,
        "threshold_nudge_shown_at": None,
        "threshold_nudge_count": 0,
    }
    resp = paid_client.post(
        "/api/v1/user/threats/increment", json={"count": 5}
    )
    body = resp.json()
    assert body["gated"] is False
    assert body["nudge_shown_at"] is None
    assert fake_us.post_calls[0]["threshold_nudge_shown_at"] is None


def test_increment_returns_503_when_supabase_missing(free_client, monkeypatch):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "", raising=False)

    resp = free_client.post(
        "/api/v1/user/threats/increment", json={"count": 1}
    )
    assert resp.status_code == 503

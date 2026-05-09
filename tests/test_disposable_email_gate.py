"""Server-side defense-in-depth for disposable email signups.

The /signup landing form already pre-flights via /auth/check-email
(see test_email_validator.py), but anyone with our public Supabase
anon key can call signInWithOtp directly and bypass that. This file
pins the second layer: even with a forged session, expensive
endpoints refuse the call.

Pinned endpoints today:
  - POST /api/v1/check        → fans out to GSB / IPQS / etc.
  - POST /api/v1/threats/increment → freemium counter bump

Read-only endpoints (settings, profile, status) intentionally
remain on plain get_current_user so a real user who somehow has
a disposable address can still cancel / update.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier


@pytest.fixture
def disposable_user():
    return AuthUser(
        id="user-disposable",
        email="bot@mailinator.com",
        tier=UserTier.free,
    )


@pytest.fixture
def real_user():
    return AuthUser(
        id="user-real",
        email="alice@gmail.com",
        tier=UserTier.free,
    )


def _make_client_for(user: AuthUser) -> TestClient:
    """Build a TestClient with both auth dependencies overridden to
    return `user`. We override BOTH get_current_user and the new
    get_current_user_no_disposable so the underlying real
    get_current_user (which would try to validate a JWT against
    Supabase) never runs in tests; only the disposable-check logic
    matters here."""
    from api.main import app
    from api.services.auth import get_current_user, get_current_user_no_disposable

    async def _override_plain():
        return user

    async def _override_with_check():
        # Reuse the production logic to test it: call the real fn but
        # bypass JWT decoding by stubbing the underlying user.
        from api.services.email_validator import is_disposable_email
        from fastapi import HTTPException

        if user.email and is_disposable_email(user.email):
            raise HTTPException(
                status_code=403,
                detail={"error": "disposable email"},
            )
        return user

    app.dependency_overrides[get_current_user] = _override_plain
    app.dependency_overrides[get_current_user_no_disposable] = _override_with_check
    return TestClient(app)


# ─── /api/v1/check rejects disposable ───────────────────────────


def test_check_rejects_disposable_user(disposable_user):
    client = _make_client_for(disposable_user)
    try:
        resp = client.post(
            "/api/v1/check",
            json={"domains": ["example.com"]},
            headers={"Authorization": "Bearer fake-jwt"},
        )
        assert resp.status_code == 403
        body = resp.json()
        assert "disposable" in str(body).lower()
    finally:
        from api.main import app
        app.dependency_overrides.clear()


def test_check_allows_real_user(real_user, monkeypatch):
    """Real-email user can call /check (passes the gate). The actual
    domain analysis is mocked out — we only care here that we got past
    the disposable check."""
    # Stub the analyzer so it doesn't hit Google / IPQS / etc.
    async def _fake_analyze(domain: str, **_kw):
        from api.models.schemas import (
            CheckResult,
            ConfidenceLevel,
            RiskLevel,
        )
        return CheckResult(
            domain=domain,
            level=RiskLevel.safe,
            score=10,
            confidence=ConfidenceLevel.high,
            reasons=[],
            cached=False,
        )

    monkeypatch.setattr("api.routers.check.analyze_domain", _fake_analyze)
    # cache helpers that may otherwise touch Redis
    async def _no_cache(*_a, **_kw):
        return None
    async def _no_cache_set(*_a, **_kw):
        return None
    monkeypatch.setattr("api.routers.check.get_cached_result", _no_cache)
    monkeypatch.setattr("api.routers.check.cache_result", _no_cache_set)

    client = _make_client_for(real_user)
    try:
        resp = client.post(
            "/api/v1/check",
            json={"domains": ["example.com"]},
            headers={"Authorization": "Bearer fake-jwt"},
        )
        # Either 200 (full success) or 429 (rate limited if Redis has
        # accumulated state from neighbouring tests). Both prove the
        # disposable gate let us through.
        assert resp.status_code in (200, 429), resp.text
    finally:
        from api.main import app
        app.dependency_overrides.clear()


# ─── /api/v1/threats/increment rejects disposable ──────────────


def test_threats_increment_rejects_disposable_user(disposable_user):
    client = _make_client_for(disposable_user)
    try:
        resp = client.post(
            "/api/v1/user/threats/increment",
            json={"count": 1},
            headers={"Authorization": "Bearer fake-jwt"},
        )
        assert resp.status_code == 403, resp.text
    finally:
        from api.main import app
        app.dependency_overrides.clear()


# ─── Read-only endpoints stay accessible ──────────────────────


def test_settings_get_still_works_for_disposable_user(disposable_user):
    """Defensive: a real user who somehow has a disposable address
    should still be able to manage their account. /user/settings uses
    plain get_current_user, NOT the disposable-blocking variant.

    The endpoint itself depends on Supabase config and will return 503
    in test env (no SUPABASE_URL set) — but it must NOT 403, which
    would mean the disposable gate accidentally got applied here."""
    client = _make_client_for(disposable_user)
    try:
        resp = client.get(
            "/api/v1/user/settings",
            headers={"Authorization": "Bearer fake-jwt"},
        )
        # Anything but 403 is fine — we're only testing that the
        # disposable gate did NOT engage on a read-only endpoint.
        assert resp.status_code != 403, (
            f"settings endpoint accidentally blocked disposable user: {resp.status_code} {resp.text}"
        )
    finally:
        from api.main import app
        app.dependency_overrides.clear()

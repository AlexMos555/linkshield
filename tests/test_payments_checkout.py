"""Regression tests for /api/v1/payments/checkout end-to-end wiring.

This file exists because three silent failure modes converged to make
the entire Stripe checkout pipeline non-functional in production:

  1. Landing PricingClient POSTed `/api/v1/payments/checkout`; backend
     exposed `/api/v1/payments/create-checkout`. Result: 404 on every
     "Subscribe" click. The client showed a generic error.

  2. api.routers.payments.PRICE_IDS was a local hardcoded dict of 4
     placeholders ("price_PERSONAL_MONTHLY" etc.) — never resolved to
     real Stripe price IDs even after the operator ran
     scripts/create_stripe_prices.py and pasted env vars into Railway.

  3. api.services.pricing.STRIPE_PRICE_IDS — read by the public
     /api/v1/pricing endpoint that the landing renders — was a
     SEPARATE hardcoded dict of 24 placeholders. Same problem.

All three are fixed by reading env vars STRIPE_PRICE_{PLAN}_T{TIER}_{INTERVAL}
at module import time. Tests below pin the canonical URL, the resolver
shape, and the error paths.
"""
from __future__ import annotations

import importlib
import sys

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier


@pytest.fixture
def authed_user():
    return AuthUser(id="user-checkout", email="alice@gmail.com", tier=UserTier.free)


@pytest.fixture
def stripe_configured(monkeypatch):
    """Pretend Stripe is set up so the endpoint proceeds to price lookup."""
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "stripe_secret_key", "sk_test_dummy", raising=False)
    return s


@pytest.fixture
def real_price_env(monkeypatch):
    """Populate STRIPE_PRICE_* env vars + force module reload so the
    pricing module's import-time dict gets the values."""
    fake_prices = {
        "STRIPE_PRICE_PERSONAL_T1_MONTHLY": "price_real_personal_monthly",
        "STRIPE_PRICE_PERSONAL_T1_YEARLY": "price_real_personal_yearly",
        "STRIPE_PRICE_FAMILY_T1_MONTHLY": "price_real_family_monthly",
        "STRIPE_PRICE_FAMILY_T1_YEARLY": "price_real_family_yearly",
        "STRIPE_PRICE_BUSINESS_T1_MONTHLY": "price_real_business_monthly",
        "STRIPE_PRICE_BUSINESS_T1_YEARLY": "price_real_business_yearly",
    }
    for k, v in fake_prices.items():
        monkeypatch.setenv(k, v)
    # Force re-import so the import-time dict comprehension runs again.
    sys.modules.pop("api.services.pricing", None)
    sys.modules.pop("api.routers.payments", None)
    importlib.import_module("api.services.pricing")
    importlib.import_module("api.routers.payments")
    yield fake_prices
    # Cleanup: pop modules so subsequent tests rebuild without our env.
    sys.modules.pop("api.services.pricing", None)
    sys.modules.pop("api.routers.payments", None)


@pytest.fixture
def stripe_stub(monkeypatch):
    """Stub stripe.checkout.Session.create so we can capture the price_id
    that the handler actually sends — that's the whole point of these
    tests. Also short-circuits the Stripe network call."""
    import stripe

    captured: list[dict] = []

    class _FakeSession:
        url = "https://checkout.stripe.com/c/fake_session"

    def _fake_create(**kwargs):
        captured.append(kwargs)
        return _FakeSession()

    monkeypatch.setattr(stripe.checkout.Session, "create", _fake_create)
    return captured


@pytest.fixture
def client(authed_user):
    from api.main import app
    from api.services.auth import get_current_user, get_current_user_including_deleted

    async def _override():
        return authed_user

    app.dependency_overrides[get_current_user] = _override
    app.dependency_overrides[get_current_user_including_deleted] = _override
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


# ─── Route exists on the URL the client actually POSTs to ──────


def test_checkout_route_at_canonical_path(client, stripe_configured, real_price_env, stripe_stub):
    """Landing PricingClient POSTs /api/v1/payments/checkout. This
    test exists because the route used to live at /create-checkout and
    every client click returned 404."""
    resp = client.post(
        "/api/v1/payments/checkout",
        json={"plan": "personal_monthly"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["checkout_url"].startswith("https://checkout.stripe.com/")


def test_create_checkout_legacy_alias_still_works(
    client, stripe_configured, real_price_env, stripe_stub
):
    """/create-checkout kept as alias for any caller pinned to the old
    name. Both paths must produce identical behaviour."""
    resp = client.post(
        "/api/v1/payments/create-checkout",
        json={"plan": "personal_monthly"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 200, resp.text


# ─── Real price IDs (env-driven) reach Stripe ─────────────────


def test_checkout_uses_real_price_id_from_env(
    client, stripe_configured, real_price_env, stripe_stub
):
    """The whole point: when STRIPE_PRICE_* env vars are populated, the
    handler must pass those values to stripe.checkout.Session.create —
    not the legacy placeholder."""
    client.post(
        "/api/v1/payments/checkout",
        json={"plan": "family_yearly"},
        headers={"Authorization": "Bearer fake"},
    )
    assert len(stripe_stub) == 1
    line_items = stripe_stub[0].get("line_items", [])
    assert len(line_items) == 1
    assert line_items[0]["price"] == "price_real_family_yearly"


def test_checkout_business_plan_supported(
    client, stripe_configured, real_price_env, stripe_stub
):
    """`business_monthly` must resolve correctly — the old hardcoded
    PRICE_IDS dict didn't include business at all (silent 400)."""
    resp = client.post(
        "/api/v1/payments/checkout",
        json={"plan": "business_monthly"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 200
    assert stripe_stub[0]["line_items"][0]["price"] == "price_real_business_monthly"


# ─── Error paths ─────────────────────────────────────────────


def test_checkout_rejects_malformed_plan(
    client, stripe_configured, real_price_env, stripe_stub
):
    """Without an underscore, the legacy-key parser can't split. 400 with
    a helpful message, NOT 500 from a downstream Stripe rejection."""
    resp = client.post(
        "/api/v1/payments/checkout",
        json={"plan": "garbage"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 400
    assert "Invalid plan" in resp.json()["detail"]
    assert stripe_stub == []


def test_checkout_rejects_unknown_plan_name(
    client, stripe_configured, real_price_env, stripe_stub
):
    """Plan is well-formed (`enterprise_monthly`) but the plan name
    isn't in STRIPE_PRICE_IDS. Same 400."""
    resp = client.post(
        "/api/v1/payments/checkout",
        json={"plan": "enterprise_monthly"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 400
    assert stripe_stub == []


def test_checkout_rejects_unknown_interval(
    client, stripe_configured, real_price_env, stripe_stub
):
    """`personal_quarterly` — valid plan name but unsupported interval."""
    resp = client.post(
        "/api/v1/payments/checkout",
        json={"plan": "personal_quarterly"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 400
    assert stripe_stub == []


def test_checkout_500_when_stripe_key_missing(client, authed_user, monkeypatch):
    """No STRIPE_SECRET_KEY in env → 500 before any Stripe call."""
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "stripe_secret_key", "", raising=False)

    resp = client.post(
        "/api/v1/payments/checkout",
        json={"plan": "personal_monthly"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 500


# ─── Idempotency-key on Stripe Checkout ────────────────────────


def test_checkout_passes_idempotency_key(
    client, stripe_configured, real_price_env, stripe_stub
):
    """Double-click on Subscribe within the same 5-minute window must
    NOT create two pending Checkout sessions on Stripe. We do this
    by passing an idempotency_key derived from (user, plan, 5-min
    bucket) — Stripe returns the same session for identical keys
    within a 24h replay window."""
    client.post(
        "/api/v1/payments/checkout",
        json={"plan": "personal_monthly"},
        headers={"Authorization": "Bearer fake"},
    )
    assert len(stripe_stub) == 1
    idem = stripe_stub[0].get("idempotency_key")
    assert idem is not None, "idempotency_key not passed to Stripe"
    # Key shape: contains user id + plan so different users + plans
    # don't collide. The 5-min bucket trails as a numeric suffix.
    assert "user-checkout" in idem
    assert "personal_monthly" in idem


def test_checkout_different_plan_yields_different_idem_key(
    client, stripe_configured, real_price_env, stripe_stub
):
    """Switching plan within the same minute must NOT return the
    previous plan's checkout URL — different plan = different key
    = different Stripe session."""
    client.post(
        "/api/v1/payments/checkout",
        json={"plan": "personal_monthly"},
        headers={"Authorization": "Bearer fake"},
    )
    client.post(
        "/api/v1/payments/checkout",
        json={"plan": "family_yearly"},
        headers={"Authorization": "Bearer fake"},
    )
    assert len(stripe_stub) == 2
    k1 = stripe_stub[0]["idempotency_key"]
    k2 = stripe_stub[1]["idempotency_key"]
    assert k1 != k2, f"different plans must produce different keys: {k1} == {k2}"

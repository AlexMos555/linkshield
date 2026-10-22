"""Failure-path hardening for POST /api/v1/payments/checkout and /portal.

Complements tests/test_payments_checkout.py. Money rule under test: when
Stripe or Supabase can't answer, the user gets a clean 5xx and nothing is
half-created — no Checkout session after a failed "does this user already
pay?" lookup, no portal link for a customer we couldn't identify.
"""
from __future__ import annotations

import sys

import pytest
import stripe
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier
from tests.test_payments_checkout import _row, _SubscriptionsStub

AUTH = {"Authorization": "Bearer fake"}


@pytest.fixture(autouse=True)
def _checkout_ready(stripe_checkout_ready):
    """Webhook secret + real-looking price ids: checkout gets as far as Stripe."""


@pytest.fixture
def client():
    from api.main import app
    from api.services.auth import get_current_user, get_current_user_including_deleted

    async def _user():
        return AuthUser(id="user-checkout", email="alice@gmail.com", tier=UserTier.free)

    app.dependency_overrides[get_current_user] = _user
    app.dependency_overrides[get_current_user_including_deleted] = _user
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.fixture
def subs_db(monkeypatch, account_store):
    """The caller's subscriptions row (httpx stub) + an empty in-memory
    entitlements store, so only the row decides "already pays"."""
    import httpx as _httpx
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    stub = _SubscriptionsStub()
    monkeypatch.setattr(_httpx, "AsyncClient", stub.build())
    return stub


class _SessionRecorder(list):
    """Checkout Session creations seen by Stripe; set `fail` to make
    Stripe reject the next ones with that exception."""

    fail: Exception | None = None


@pytest.fixture
def session_calls(monkeypatch):
    calls = _SessionRecorder()

    class _Session:
        url = "https://checkout.stripe.com/c/fake"

    async def _create(**kwargs):
        calls.append(kwargs)
        if calls.fail is not None:
            raise calls.fail
        return _Session()

    monkeypatch.setattr(stripe.checkout.Session, "create_async", _create)
    return calls


def _checkout(client, **body):
    return client.post("/api/v1/payments/checkout", json={"plan": "devices_monthly", **body}, headers=AUTH)


# ─── Checkout ──────────────────────────────────────────────────────


@pytest.mark.parametrize("error", [
    stripe.InvalidRequestError("No such price: 'price_placeholder'", "line_items[0][price]"),
    stripe.APIConnectionError("simulated Stripe outage"),
    stripe.CardError("card declined", None, "card_declined"),
])
def test_stripe_rejecting_the_session_is_a_clean_500(client, fake_stripe, subs_db, session_calls, error):
    """An unconfigured / unknown price, a Stripe outage or any API error:
    one generic 500, never the Stripe error text (it can carry ids)."""
    subs_db.row = _row()
    session_calls.fail = error
    resp = _checkout(client)
    assert resp.status_code == 500
    assert resp.json()["detail"] == "Failed to create checkout session"
    assert len(session_calls) == 1


def test_checkout_without_the_stripe_library_is_500(client, subs_db, monkeypatch):
    monkeypatch.setitem(sys.modules, "stripe", None)
    resp = _checkout(client)
    assert resp.status_code == 500 and resp.json()["detail"] == "Stripe not configured"


def test_legacy_customer_lookup_outage_is_503_and_no_session(client, fake_stripe, subs_db, session_calls, monkeypatch):
    """A pre-migration-021 row: the customer must be derived from the old
    subscription. Stripe down → we can't know who the customer is; minting
    a second customer (and maybe a second subscription) is worse than a 503."""
    subs_db.row = _row(status="cancelled", provider_subscription_id="sub_legacy")

    async def _down(sub_id, **_params):
        raise stripe.APIConnectionError("simulated Stripe outage")

    monkeypatch.setattr(stripe.Subscription, "retrieve_async", _down)
    resp = _checkout(client)
    assert resp.status_code == 503
    assert session_calls == []


def test_legacy_subscription_deleted_in_stripe_falls_back_to_email(client, fake_stripe, subs_db, session_calls):
    """The old subscription no longer exists in Stripe (wiped test data,
    deleted customer): there is no customer to reuse, checkout proceeds by
    email — and the trial stays used (the row had a subscription)."""
    subs_db.row = _row(status="cancelled", provider_subscription_id="sub_wiped")
    resp = _checkout(client)
    assert resp.status_code == 200, resp.text
    kwargs = session_calls[0]
    assert kwargs["customer_email"] == "alice@gmail.com" and "customer" not in kwargs
    assert "trial_period_days" not in kwargs["subscription_data"]
    assert subs_db.patches == []


def test_row_from_another_store_is_not_treated_as_a_stripe_customer(client, fake_stripe, subs_db, session_calls):
    """A provider_subscription_id from Google Play is not a Stripe id: no
    Stripe lookup with it, checkout goes by email."""
    subs_db.row = _row(status="cancelled", provider="google_play", provider_subscription_id="GPA.1234")
    resp = _checkout(client)
    assert resp.status_code == 200, resp.text
    assert session_calls[0]["customer_email"] == "alice@gmail.com"


# ─── Portal ────────────────────────────────────────────────────────


def _portal(client):
    return client.post("/api/v1/payments/portal", headers=AUTH)


def test_portal_without_stripe_key_is_500(client, subs_db, monkeypatch):
    from api import config

    monkeypatch.setattr(config.get_settings(), "stripe_secret_key", "", raising=False)
    resp = _portal(client)
    assert resp.status_code == 500 and resp.json()["detail"] == "Stripe not configured"


def test_portal_supabase_outage_is_503(client, subs_db, fake_stripe):
    subs_db.get_status = 500
    resp = _portal(client)
    assert resp.status_code == 503
    assert fake_stripe.portal_calls == []


def test_portal_stripe_error_is_a_clean_500(client, subs_db, fake_stripe, monkeypatch):
    subs_db.row = _row(tier="personal", stripe_customer_id="cus_mine")

    async def _down(**_params):
        raise stripe.APIConnectionError("simulated Stripe outage")

    monkeypatch.setattr(stripe.billing_portal.Session, "create_async", _down)
    resp = _portal(client)
    assert resp.status_code == 500
    assert resp.json()["detail"] == "Failed to create portal session"


def test_portal_for_a_customer_gone_from_stripe_is_404(client, subs_db, fake_stripe):
    """Legacy row whose subscription Stripe no longer knows: no customer,
    so no portal — never a guess by email."""
    subs_db.row = _row(tier="personal", provider_subscription_id="sub_wiped")
    resp = _portal(client)
    assert resp.status_code == 404
    assert fake_stripe.portal_calls == []

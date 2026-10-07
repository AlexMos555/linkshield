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
    pricing module's import-time dict gets the values.

    Every PPP tier gets its own id. A request without a country is
    priced at tier 2 — the tier /api/v1/pricing/for-country shows when
    no cc is given — so tier 2 carries the short names the assertions
    below use; the other tiers are suffixed `_t{n}`."""
    fake_prices = {}
    for plan in ("personal", "family", "business"):
        for interval in ("monthly", "yearly"):
            for tier in (1, 2, 3, 4):
                suffix = "" if tier == 2 else f"_t{tier}"
                fake_prices[f"STRIPE_PRICE_{plan.upper()}_T{tier}_{interval.upper()}"] = (
                    f"price_real_{plan}_{interval}{suffix}"
                )
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
    """Stub stripe.checkout.Session.create_async so we can capture the
    price_id that the handler actually sends — that's the whole point
    of these tests. Also short-circuits the Stripe network call.

    Patches BOTH create_async (production path post backend-async-2
    fix) and the legacy sync create() so the fixture still works if a
    future revert switches back."""
    import stripe

    captured: list[dict] = []

    class _FakeSession:
        url = "https://checkout.stripe.com/c/fake_session"

    async def _fake_create_async(**kwargs):
        captured.append(kwargs)
        return _FakeSession()

    def _fake_create(**kwargs):
        captured.append(kwargs)
        return _FakeSession()

    monkeypatch.setattr(stripe.checkout.Session, "create_async", _fake_create_async)
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


# ─── One paid subscription per user ───────────────────────────
#
# Every user has a subscriptions row (migration 010 seeds free/active),
# and UNIQUE(user_id) means a second Stripe subscription would silently
# overwrite the first on our side while Stripe keeps billing both.


class _SubscriptionsStub:
    """httpx.AsyncClient stand-in serving the caller's subscriptions row."""

    def __init__(self) -> None:
        self.row: dict | None = None
        self.get_status = 200
        self.patches: list[dict] = []

    def build(self):
        stub = self

        class _Resp:
            def __init__(self, status: int, body=None):
                self.status_code = status
                self._body = body
                self.text = ""

            def json(self):
                return self._body

        class _Client:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def get(self, url, params=None, headers=None, **_kw):
                if stub.get_status != 200:
                    return _Resp(stub.get_status, {"message": "boom"})
                return _Resp(200, [stub.row] if stub.row else [])

            async def patch(self, url, params=None, json=None, headers=None, **_kw):
                stub.patches.append({"url": url, "params": dict(params or {}), "body": json})
                return _Resp(204)

            async def post(self, url, json=None, headers=None, **_kw):
                return _Resp(201, [])

        return _Client


@pytest.fixture
def subs_db(monkeypatch):
    import httpx as _httpx
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    stub = _SubscriptionsStub()
    monkeypatch.setattr(_httpx, "AsyncClient", stub.build())
    return stub


def _row(**kw):
    row = {
        "user_id": "user-checkout",
        "tier": "free",
        "status": "active",
        "provider": "stripe",
        "provider_subscription_id": None,
        "stripe_customer_id": None,
        "trial_used_at": None,
    }
    row.update(kw)
    return row


def _checkout(client, **body):
    return client.post(
        "/api/v1/payments/checkout",
        json={"plan": "personal_monthly", **body},
        headers={"Authorization": "Bearer fake"},
    )


@pytest.mark.parametrize("status", ["active", "past_due"])
def test_checkout_refused_when_paid_subscription_exists(
    client, stripe_configured, stripe_stub, subs_db, status
):
    subs_db.row = _row(tier="personal", status=status, provider_subscription_id="sub_1",
                       stripe_customer_id="cus_1")
    resp = _checkout(client, plan="family_monthly")
    assert resp.status_code == 409, resp.text
    assert resp.json()["detail"]["code"] == "subscription_already_active"
    assert stripe_stub == []


def test_checkout_allowed_for_seeded_free_row(client, stripe_configured, stripe_stub, subs_db):
    """The free/active row every user gets at signup is NOT a paid
    subscription."""
    subs_db.row = _row()
    resp = _checkout(client)
    assert resp.status_code == 200, resp.text
    assert len(stripe_stub) == 1


def test_checkout_503_when_subscription_lookup_fails(
    client, stripe_configured, stripe_stub, subs_db
):
    """Can't tell whether they already pay → don't risk a second
    subscription."""
    subs_db.get_status = 500
    resp = _checkout(client)
    assert resp.status_code == 503
    assert stripe_stub == []


def test_first_checkout_gets_the_trial(client, stripe_configured, stripe_stub, subs_db):
    subs_db.row = _row()
    _checkout(client)
    kwargs = stripe_stub[0]
    assert kwargs["subscription_data"]["trial_period_days"] == 14
    assert kwargs["metadata"]["trial"] == "1"


def test_trial_not_offered_after_it_was_used(client, stripe_configured, stripe_stub, subs_db):
    subs_db.row = _row(status="cancelled", trial_used_at="2026-09-01T00:00:00+00:00",
                       stripe_customer_id="cus_1")
    resp = _checkout(client)
    assert resp.status_code == 200, resp.text
    kwargs = stripe_stub[0]
    assert "trial_period_days" not in kwargs["subscription_data"]
    assert kwargs["metadata"]["trial"] == "0"


def test_trial_not_offered_to_a_returning_legacy_subscriber(
    client, stripe_configured, stripe_stub, subs_db, fake_stripe
):
    """Rows from before trial_used_at existed: a past Stripe
    subscription means the trial was already had."""
    subs_db.row = _row(status="cancelled", provider_subscription_id="sub_old")
    fake_stripe.add_subscription("sub_old", "cus_old", status="canceled")
    _checkout(client)
    assert "trial_period_days" not in stripe_stub[0]["subscription_data"]


def test_checkout_reuses_stored_stripe_customer(client, stripe_configured, stripe_stub, subs_db):
    subs_db.row = _row(status="cancelled", stripe_customer_id="cus_existing",
                       trial_used_at="2026-09-01T00:00:00+00:00")
    _checkout(client)
    kwargs = stripe_stub[0]
    assert kwargs["customer"] == "cus_existing"
    assert "customer_email" not in kwargs


def test_checkout_derives_and_stores_customer_for_legacy_row(
    client, stripe_configured, stripe_stub, subs_db, fake_stripe
):
    subs_db.row = _row(status="cancelled", provider_subscription_id="sub_legacy")
    fake_stripe.add_subscription("sub_legacy", "cus_legacy", status="canceled")
    _checkout(client)
    assert stripe_stub[0]["customer"] == "cus_legacy"
    assert any(p["body"] == {"stripe_customer_id": "cus_legacy"} for p in subs_db.patches)


def test_first_checkout_without_customer_uses_email(client, stripe_configured, stripe_stub, subs_db):
    subs_db.row = _row()
    _checkout(client)
    kwargs = stripe_stub[0]
    assert kwargs["customer_email"] == "alice@gmail.com"
    assert "customer" not in kwargs


# ─── Charged price == shown price ─────────────────────────────


@pytest.mark.parametrize("cc", ["US", "IN", "TH", "BR", None])
@pytest.mark.parametrize("plan,interval", [("personal", "monthly"), ("family", "yearly")])
def test_checkout_charges_the_price_the_pricing_page_shows(
    client, stripe_configured, stripe_stub, cc, plan, interval
):
    """/api/v1/pricing/for-country shows a regional (PPP) price; checkout
    used to charge tier 1 regardless. Both must resolve through the same
    country → tier function for the same request country."""
    from api.services.pricing import STRIPE_PRICE_IDS, country_to_tier

    q = f"?cc={cc}" if cc else ""
    shown = client.get(f"/api/v1/pricing/for-country{q}").json()
    shown_price = shown["plans"][plan][interval]["stripe_price_id"]

    body = {"plan": f"{plan}_{interval}"}
    if cc:
        body["country"] = cc
    resp = client.post(
        "/api/v1/payments/checkout", json=body, headers={"Authorization": "Bearer fake"}
    )
    assert resp.status_code == 200, resp.text
    charged = stripe_stub[0]["line_items"][0]["price"]
    assert charged == shown_price
    assert charged == STRIPE_PRICE_IDS[plan][country_to_tier(cc)][interval]


def test_checkout_rejects_malformed_country(client, stripe_configured, stripe_stub):
    resp = client.post(
        "/api/v1/payments/checkout",
        json={"plan": "personal_monthly", "country": "USA"},
        headers={"Authorization": "Bearer fake"},
    )
    assert resp.status_code == 422
    assert stripe_stub == []


# ─── Customer portal uses the stored customer ─────────────────


def test_portal_uses_stored_customer_id(client, subs_db, fake_stripe):
    subs_db.row = _row(tier="personal", stripe_customer_id="cus_mine")
    resp = client.post("/api/v1/payments/portal", headers={"Authorization": "Bearer fake"})
    assert resp.status_code == 200, resp.text
    assert fake_stripe.portal_calls[0]["customer"] == "cus_mine"


def test_portal_derives_customer_from_legacy_subscription(client, subs_db, fake_stripe):
    subs_db.row = _row(tier="personal", provider_subscription_id="sub_leg")
    fake_stripe.add_subscription("sub_leg", "cus_leg")
    resp = client.post("/api/v1/payments/portal", headers={"Authorization": "Bearer fake"})
    assert resp.status_code == 200, resp.text
    assert fake_stripe.portal_calls[0]["customer"] == "cus_leg"


def test_portal_404_without_a_customer(client, subs_db, fake_stripe):
    """No stored customer → 404. Never fall back to an email search
    (fake_stripe raises if Customer.list is called)."""
    subs_db.row = _row()
    resp = client.post("/api/v1/payments/portal", headers={"Authorization": "Bearer fake"})
    assert resp.status_code == 404
    assert fake_stripe.portal_calls == []

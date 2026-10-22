"""Failure-path hardening for api/services/stripe_billing.py.

These helpers back checkout, the portal, account deletion and the GDPR
purge. Their contract (module docstring): any Supabase / Stripe failure
RAISES BillingError — "DB down" must never look like "free user" and a
failed cancel must never look like "nothing left to bill". The only
tolerated "nothing to do" answer is Stripe saying the object is gone
(resource_missing).
"""
from __future__ import annotations

from typing import Any

import pytest
import stripe

from api.services import stripe_billing as sb


@pytest.fixture
def supabase(monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    return s


@pytest.fixture
def no_supabase(monkeypatch):
    from api import config

    monkeypatch.setattr(config.get_settings(), "supabase_url", "", raising=False)


class _Http:
    """httpx.AsyncClient stand-in: `rows` answers GETs, `error` makes every
    call raise, `status` overrides the GET status. Records PATCHes."""

    def __init__(self) -> None:
        self.rows: list[dict] = []
        self.error: Exception | None = None
        self.status = 200
        self.calls: list[tuple[str, dict]] = []

    def install(self, monkeypatch) -> "_Http":
        import httpx as _httpx

        http = self

        class _Resp:
            def __init__(self, status: int, body: Any) -> None:
                self.status_code = status
                self._body = body

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
                http.calls.append(("GET", dict(params or {})))
                if http.error:
                    raise http.error
                return _Resp(http.status, http.rows)

            async def patch(self, url, params=None, json=None, headers=None, **_kw):
                http.calls.append(("PATCH", {"params": dict(params or {}), "json": json}))
                if http.error:
                    raise http.error
                return _Resp(204, None)

        monkeypatch.setattr(_httpx, "AsyncClient", _Client)
        return self


@pytest.fixture
def http(monkeypatch):
    return _Http().install(monkeypatch)


def _outage(*_a, **_k):
    raise stripe.APIConnectionError("simulated Stripe outage")


async def _async_outage(*_a, **_k):
    _outage()


def _row(**kw) -> dict:
    row = {"user_id": "u1", "tier": "personal", "status": "active", "provider": "stripe",
           "provider_subscription_id": None, "stripe_customer_id": None, "trial_used_at": None}
    row.update(kw)
    return row


# ─── plain(): older stripe-python objects ──────────────────────────


def test_plain_falls_back_to_to_dict_recursive_on_older_stripe_python():
    class _OldObject:
        def to_dict(self):  # no `recursive` keyword before stripe-python 15
            return {"shallow": True}

        def to_dict_recursive(self):
            return {"deep": {"nested": True}}

    assert sb.plain(_OldObject()) == {"deep": {"nested": True}}


def test_plain_uses_to_dict_when_there_is_no_recursive_variant():
    class _OldestObject:
        def to_dict(self):
            return {"shallow": True}

    assert sb.plain(_OldestObject()) == {"shallow": True}


@pytest.mark.parametrize("value", [{"id": "sub_1"}, ["a"], "sub_1", None])
def test_plain_leaves_already_plain_data_alone(value):
    assert sb.plain(value) is value


# ─── fetch_subscription_row ────────────────────────────────────────


@pytest.mark.parametrize("filters", [
    {},
    {"user_id": "u1", "customer_id": "cus_1"},
    {"user_id": "", "subscription_id": None},
])
@pytest.mark.asyncio
async def test_fetch_needs_exactly_one_filter(filters, supabase, http):
    """Two filters would be an AND nobody meant; none would return a random
    user's row. Both are programming errors, refused before any query."""
    with pytest.raises(ValueError):
        await sb.fetch_subscription_row(**filters)
    assert http.calls == []


@pytest.mark.asyncio
async def test_fetch_network_failure_is_a_billing_error(supabase, http):
    import httpx as _httpx

    http.error = _httpx.ConnectTimeout("supabase timed out")
    with pytest.raises(sb.BillingError):
        await sb.fetch_subscription_row(user_id="u1")


@pytest.mark.asyncio
async def test_fetch_non_200_is_a_billing_error_not_no_row(supabase, http):
    http.status = 401
    with pytest.raises(sb.BillingError):
        await sb.fetch_subscription_row(customer_id="cus_1")


@pytest.mark.asyncio
async def test_fetch_without_supabase_means_no_row(no_supabase, http):
    assert await sb.fetch_subscription_row(user_id="u1") is None
    assert http.calls == []


@pytest.mark.asyncio
async def test_fetch_queries_by_the_one_given_column(supabase, http):
    http.rows = [_row(provider_subscription_id="sub_1")]
    assert (await sb.fetch_subscription_row(subscription_id="sub_1"))["user_id"] == "u1"
    assert http.calls[0][1]["provider_subscription_id"] == "eq.sub_1"


# ─── stripe_client / resolve_customer_id ───────────────────────────


def test_stripe_client_without_key_is_a_billing_error(monkeypatch):
    from api import config

    monkeypatch.setattr(config.get_settings(), "stripe_secret_key", "", raising=False)
    with pytest.raises(sb.BillingError, match="stripe_not_configured"):
        sb.stripe_client()


@pytest.mark.asyncio
async def test_resolve_customer_never_asks_stripe_about_another_stores_subscription(fake_stripe, monkeypatch):
    monkeypatch.setattr(stripe.Subscription, "retrieve_async", _async_outage)
    row = _row(provider="google_play", provider_subscription_id="GPA.1")
    assert await sb.resolve_customer_id(row) is None


@pytest.mark.asyncio
async def test_resolve_customer_for_a_subscription_gone_from_stripe_is_none(fake_stripe):
    assert await sb.resolve_customer_id(_row(provider_subscription_id="sub_wiped")) is None


@pytest.mark.asyncio
async def test_resolve_customer_stripe_outage_is_a_billing_error(fake_stripe, monkeypatch):
    monkeypatch.setattr(stripe.Subscription, "retrieve_async", _async_outage)
    with pytest.raises(sb.BillingError):
        await sb.resolve_customer_id(_row(provider_subscription_id="sub_1"))


@pytest.mark.asyncio
async def test_resolve_customer_reads_an_expanded_customer_object(fake_stripe):
    fake_stripe.add_subscription("sub_x", "unused")["customer"] = {"id": "cus_expanded"}
    assert await sb.resolve_customer_id(_row(provider_subscription_id="sub_x")) == "cus_expanded"


# ─── store_customer_id (best effort) ───────────────────────────────


@pytest.mark.asyncio
async def test_store_customer_without_supabase_does_nothing(no_supabase, http):
    await sb.store_customer_id("u1", "cus_1")
    assert http.calls == []


@pytest.mark.asyncio
async def test_store_customer_failure_is_swallowed(supabase, http, caplog):
    """Best effort by design: the id is derived again next time."""
    import httpx as _httpx

    http.error = _httpx.ConnectError("supabase down")
    await sb.store_customer_id("u1", "cus_1")
    assert any(r.message == "stripe_customer_id_store_failed" for r in caplog.records)


# ─── cancel_subscription_now ───────────────────────────────────────


@pytest.mark.parametrize("terminal", ["canceled", "incomplete_expired"])
@pytest.mark.asyncio
async def test_cancel_of_a_terminal_subscription_is_a_no_op(fake_stripe, terminal):
    fake_stripe.add_subscription("sub_t", "cus_1", status=terminal)
    assert await sb.cancel_subscription_now("sub_t") is False
    assert fake_stripe.cancel_calls == []


@pytest.mark.asyncio
async def test_cancel_of_a_subscription_stripe_no_longer_has_is_a_no_op(fake_stripe):
    assert await sb.cancel_subscription_now("sub_missing") is False


@pytest.mark.asyncio
async def test_cancel_is_immediate_without_proration_or_final_invoice(fake_stripe):
    fake_stripe.add_subscription("sub_live", "cus_1", status="past_due")
    assert await sb.cancel_subscription_now("sub_live") is True
    assert fake_stripe.cancel_calls == [("sub_live", {"prorate": False, "invoice_now": False})]


@pytest.mark.asyncio
async def test_cancel_outage_is_a_billing_error(fake_stripe):
    fake_stripe.add_subscription("sub_live", "cus_1")
    fake_stripe.fail_cancel = True
    with pytest.raises(sb.BillingError):
        await sb.cancel_subscription_now("sub_live")


# ─── cancel_user_subscriptions (account deletion / GDPR purge) ─────


@pytest.mark.asyncio
async def test_user_without_a_row_has_nothing_to_cancel(supabase, http, fake_stripe):
    assert await sb.cancel_user_subscriptions("u1") == []
    assert fake_stripe.list_calls == []


@pytest.mark.asyncio
async def test_user_who_never_used_stripe_has_nothing_to_cancel(supabase, http, fake_stripe):
    http.rows = [_row(tier="free")]
    assert await sb.cancel_user_subscriptions("u1") == []
    assert fake_stripe.list_calls == []


@pytest.mark.asyncio
async def test_every_live_subscription_of_the_customer_is_cancelled(supabase, http, fake_stripe):
    """Two Checkout sessions completed → two live subscriptions, only the
    last one on our row. Both must stop billing; terminal ones are skipped."""
    http.rows = [_row(stripe_customer_id="cus_1", provider_subscription_id="sub_b")]
    fake_stripe.add_subscription("sub_a", "cus_1", status="active")
    fake_stripe.add_subscription("sub_b", "cus_1", status="trialing")
    fake_stripe.add_subscription("sub_old", "cus_1", status="canceled")
    fake_stripe.add_subscription("sub_other_user", "cus_2", status="active")
    assert sorted(await sb.cancel_user_subscriptions("u1")) == ["sub_a", "sub_b"]
    assert sorted(c[0] for c in fake_stripe.cancel_calls) == ["sub_a", "sub_b"]


@pytest.mark.asyncio
async def test_listing_outage_is_a_billing_error(supabase, http, fake_stripe):
    """Account deletion must not proceed believing nothing bills."""
    http.rows = [_row(stripe_customer_id="cus_1")]
    fake_stripe.fail_list = True
    with pytest.raises(sb.BillingError):
        await sb.cancel_user_subscriptions("u1")


@pytest.mark.asyncio
async def test_customer_gone_from_stripe_means_nothing_to_cancel(supabase, http, fake_stripe, monkeypatch):
    http.rows = [_row(stripe_customer_id="cus_gone")]

    async def _gone(**_params):
        raise stripe.InvalidRequestError("No such customer", "customer", code="resource_missing")

    monkeypatch.setattr(stripe.Subscription, "list_async", _gone)
    assert await sb.cancel_user_subscriptions("u1") == []
    assert fake_stripe.cancel_calls == []


@pytest.mark.asyncio
async def test_legacy_row_whose_subscription_is_gone_cancels_nothing(supabase, http, fake_stripe):
    """No stored customer and the stored subscription is unknown to Stripe:
    the customer can't be derived, the subscription itself is tried and
    found gone — nothing left to bill, not an error."""
    http.rows = [_row(provider_subscription_id="sub_wiped")]
    assert await sb.cancel_user_subscriptions("u1") == []
    assert fake_stripe.cancel_calls == []


@pytest.mark.asyncio
async def test_legacy_row_derives_the_customer_and_cancels_through_it(supabase, http, fake_stripe):
    http.rows = [_row(provider_subscription_id="sub_leg")]
    fake_stripe.add_subscription("sub_leg", "cus_leg", status="active")
    assert await sb.cancel_user_subscriptions("u1") == ["sub_leg"]
    assert fake_stripe.list_calls[0]["customer"] == "cus_leg"

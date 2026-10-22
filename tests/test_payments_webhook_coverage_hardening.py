"""Failure-path hardening for the Stripe webhook (api/routers/payments.py).

Complements tests/test_payments_webhook.py (happy paths, the basic
idempotency gate, refunds/disputes). Here: forged / expired / tampered /
malformed deliveries, the idempotency gate's Redis edge cases (lease race,
done-marker and release failures, Redis down), Stripe API errors while
attributing an event, and money transitions (past_due → canceled → deleted,
refunds that can't be classified, refunds whose cancel fails).

Most tests await `stripe_webhook` directly with a real Starlette Request
built from raw ASGI messages. That is the same endpoint function the router
serves; the reason for not going through TestClient is a coverage.py
artifact: under the full middleware stack the tracer loses this frame after
`await request.body()` (lines it demonstrably executes are reported as
missed), so the gate's branches would look untested. The few tests that are
about the HTTP edge itself (body size cap) do use TestClient.
"""
from __future__ import annotations

import json
import sys
import time
from typing import Any, Optional

import pytest
import stripe
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.requests import Request

from tests.test_payments_webhook import (
    WEBHOOK_SECRET,
    FakeRedis,
    FakeSubscriptionsTable,
    _invoice_charge,
    _paid_row,
    _sign,
)


# ─── Fixtures / helpers ────────────────────────────────────────────


@pytest.fixture
def billing(monkeypatch):
    """Supabase + Stripe configured, Supabase served by an in-memory table."""
    import httpx as _httpx
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "fake_service_key", raising=False)
    monkeypatch.setattr(settings, "stripe_webhook_secret", WEBHOOK_SECRET, raising=False)
    monkeypatch.setattr(settings, "stripe_secret_key", "sk_test_dummy", raising=False)
    table = FakeSubscriptionsTable()
    monkeypatch.setattr(_httpx, "AsyncClient", table.build())
    return table


def _install_redis(monkeypatch, fake) -> Any:
    async def _get():
        return fake

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    return fake


@pytest.fixture
def redis(monkeypatch):
    return _install_redis(monkeypatch, FakeRedis())


def _request(body: bytes, headers: dict[str, str]) -> Request:
    delivered = {"done": False}

    async def receive():
        if delivered["done"]:
            return {"type": "http.disconnect"}
        delivered["done"] = True
        return {"type": "http.request", "body": body, "more_body": False}

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/payments/webhook",
        "query_string": b"",
        "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
    }
    return Request(scope, receive)


def _envelope(event_type: str, data: dict, event_id: Optional[str] = "evt_hard_1") -> bytes:
    body: dict[str, Any] = {"type": event_type, "object": "event", "data": {"object": data}}
    if event_id is not None:
        body["id"] = event_id
    return json.dumps(body).encode()


async def _deliver_raw(payload: bytes, signature: Optional[str]) -> tuple[int, Any]:
    """Await the webhook endpoint; return (status_code, body_or_detail)."""
    import api.routers.payments as payments

    headers = {} if signature is None else {"stripe-signature": signature}
    try:
        return 200, await payments.stripe_webhook(_request(payload, headers))
    except HTTPException as e:
        return e.status_code, e.detail


async def _deliver(event_type: str, data: dict, event_id: Optional[str] = "evt_hard_1") -> tuple[int, Any]:
    payload = _envelope(event_type, data, event_id)
    return await _deliver_raw(payload, _sign(payload))


def _checkout_session(user_id: str = "user-h", sub: Optional[str] = "sub_h") -> dict:
    return {
        "metadata": {"user_id": user_id, "plan": "devices_monthly"},
        "subscription": sub,
        "customer": "cus_h",
    }


# ─── Signature verification ────────────────────────────────────────


@pytest.mark.asyncio
async def test_missing_signature_header_is_400_and_nothing_is_written(billing, redis, security_events):
    status, detail = await _deliver_raw(_envelope("checkout.session.completed", _checkout_session()), None)
    assert status == 400 and detail == "Invalid signature"
    assert security_events == [("webhook_signature_invalid", "stripe")]
    assert billing.posts == [] and redis.kv == {}


@pytest.mark.asyncio
async def test_correctly_signed_but_expired_delivery_is_refused(billing, redis, security_events):
    """A captured delivery replayed after Stripe's 5-minute tolerance must
    not be accepted even though its HMAC is genuine."""
    payload = _envelope("checkout.session.completed", _checkout_session())
    status, _ = await _deliver_raw(payload, _sign(payload, t=int(time.time()) - 3600))
    assert status == 400
    assert billing.posts == [] and redis.kv == {}


@pytest.mark.asyncio
async def test_tampered_body_with_the_original_signature_is_refused(billing, redis, security_events):
    original = _envelope("checkout.session.completed", _checkout_session(user_id="victim"))
    tampered = _envelope("checkout.session.completed", _checkout_session(user_id="attacker"))
    status, _ = await _deliver_raw(tampered, _sign(original))
    assert status == 400
    assert billing.posts == []


@pytest.mark.asyncio
async def test_signature_made_with_another_secret_is_refused(billing, redis, security_events):
    payload = _envelope("checkout.session.completed", _checkout_session())
    status, _ = await _deliver_raw(payload, _sign(payload, secret="whsec_attacker_guess"))
    assert status == 400
    assert billing.posts == []


@pytest.mark.asyncio
async def test_validly_signed_body_that_is_not_json_is_400(billing, redis, security_events):
    payload = b"definitely not json {"
    status, _ = await _deliver_raw(payload, _sign(payload))
    assert status == 400
    assert billing.posts == [] and redis.kv == {}


@pytest.mark.asyncio
async def test_webhook_secret_pasted_with_whitespace_still_verifies(billing, redis, monkeypatch):
    """Env vars pasted into a dashboard often carry a trailing newline; the
    secret is stripped before use, so genuine events keep verifying."""
    from api import config

    monkeypatch.setattr(config.get_settings(), "stripe_webhook_secret", f"  {WEBHOOK_SECRET}\n", raising=False)
    status, body = await _deliver("customer.subscription.trial_will_end", {"id": "sub_t", "metadata": {}})
    assert status == 200 and body == {"status": "ok"}


@pytest.mark.asyncio
async def test_stripe_library_missing_is_a_500_not_a_crash(billing, monkeypatch):
    monkeypatch.setitem(sys.modules, "stripe", None)  # `import stripe` → ImportError
    status, detail = await _deliver_raw(b"{}", "t=1,v1=x")
    assert status == 500 and detail == "Stripe not configured"


def test_oversized_webhook_body_is_413_before_any_handler_runs(billing, redis):
    """The global body cap (1 MiB) applies to the webhook too: a huge body
    is refused at the edge, never parsed or verified."""
    from api.main import app

    payload = b"{" + b" " * (1024 * 1024) + b"}"
    resp = TestClient(app).post(
        "/api/v1/payments/webhook", content=payload, headers={"stripe-signature": _sign(payload)}
    )
    assert resp.status_code == 413
    assert billing.posts == [] and redis.kv == {}


# ─── Idempotency gate ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_replayed_event_is_applied_once(billing, redis):
    first = await _deliver("checkout.session.completed", _checkout_session(), event_id="evt_replay")
    second = await _deliver("checkout.session.completed", _checkout_session(), event_id="evt_replay")
    assert first == (200, {"status": "ok"})
    assert second == (200, {"status": "ok", "duplicate": True})
    assert len(billing.posts) == 1
    assert redis.kv["stripe:event:evt_replay"] == "done"


@pytest.mark.asyncio
async def test_marker_written_by_the_previous_gate_counts_as_done(billing, redis):
    redis.kv["stripe:event:evt_old_gate"] = "1"
    status, body = await _deliver("checkout.session.completed", _checkout_session(), event_id="evt_old_gate")
    assert status == 200 and body["duplicate"] is True
    assert billing.posts == []


@pytest.mark.asyncio
async def test_event_without_id_is_processed_without_the_gate(billing, monkeypatch):
    """No id → nothing to dedupe on; the event is still applied (every
    handler is an upsert) and Redis is never consulted for it."""
    class _NoGateRedis(FakeRedis):
        async def set(self, key, value, nx=False, ex=None):
            raise AssertionError(f"gate touched for an id-less event: {key}")

    _install_redis(monkeypatch, _NoGateRedis())
    status, body = await _deliver("checkout.session.completed", _checkout_session(), event_id=None)
    assert status == 200 and body == {"status": "ok"}
    assert billing.posts[0]["user_id"] == "user-h"


class _LeaseRaceRedis(FakeRedis):
    """SET NX loses `losses` times while GET sees no key: another worker's
    lease expired between our SET and our GET."""

    def __init__(self, losses: int) -> None:
        super().__init__()
        self.losses = losses
        self.nx_attempts = 0

    async def set(self, key, value, nx=False, ex=None):
        if nx and key.startswith("stripe:event:"):
            self.nx_attempts += 1
            if self.losses > 0:
                self.losses -= 1
                return None
        return await super().set(key, value, nx=nx, ex=ex)

    async def get(self, key):
        return None


@pytest.mark.asyncio
async def test_lease_that_expires_between_set_and_get_is_reclaimed(billing, monkeypatch):
    fake = _install_redis(monkeypatch, _LeaseRaceRedis(losses=1))
    status, body = await _deliver("checkout.session.completed", _checkout_session(), event_id="evt_race")
    assert status == 200 and body == {"status": "ok"}
    assert fake.nx_attempts == 2
    assert fake.kv["stripe:event:evt_race"] == "done"
    assert len(billing.posts) == 1


@pytest.mark.asyncio
async def test_gate_that_keeps_flapping_answers_409_without_processing(billing, monkeypatch):
    """Two lost races in a row: we can't tell who owns the event, so we
    don't process it — Stripe retries later."""
    _install_redis(monkeypatch, _LeaseRaceRedis(losses=99))
    status, _ = await _deliver("checkout.session.completed", _checkout_session(), event_id="evt_flap")
    assert status == 409
    assert billing.posts == []


@pytest.mark.asyncio
async def test_done_marker_failure_still_acknowledges_the_applied_event(billing, monkeypatch):
    """The write landed; only the "done" marker failed. Answering 5xx would
    make Stripe redeliver an event we already applied — 200 is right, and a
    redelivery is harmless (handlers are upserts)."""
    class _DoneFails(FakeRedis):
        async def set(self, key, value, nx=False, ex=None):
            if value == "done":
                raise ConnectionError("redis went away")
            return await super().set(key, value, nx=nx, ex=ex)

    _install_redis(monkeypatch, _DoneFails())
    status, body = await _deliver("checkout.session.completed", _checkout_session(), event_id="evt_nomark")
    assert status == 200 and body == {"status": "ok"}
    assert len(billing.posts) == 1


@pytest.mark.asyncio
async def test_lease_release_failure_after_a_failed_write_is_still_a_500(billing, monkeypatch):
    class _ReleaseFails(FakeRedis):
        async def delete(self, key):
            raise ConnectionError("redis went away")

    fake = _install_redis(monkeypatch, _ReleaseFails())
    billing.post_status = 503
    status, _ = await _deliver("checkout.session.completed", _checkout_session(), event_id="evt_norel")
    assert status == 500
    # The lease stays until it expires on its own; it is never marked done.
    assert fake.kv["stripe:event:evt_norel"] == "processing"


@pytest.mark.asyncio
async def test_redis_down_still_applies_the_event(billing, redis_down):
    status, body = await _deliver("checkout.session.completed", _checkout_session(), event_id="evt_noredis")
    assert status == 200 and body == {"status": "ok"}
    assert len(billing.posts) == 1


@pytest.mark.asyncio
async def test_redis_down_and_supabase_down_is_a_500(billing, redis_down):
    billing.post_status = 500
    status, _ = await _deliver("checkout.session.completed", _checkout_session(), event_id="evt_alldown")
    assert status == 500


@pytest.mark.parametrize("supabase_status", [400, 409, 503])
@pytest.mark.asyncio
async def test_rejected_subscription_write_is_retried_not_acknowledged(billing, redis, supabase_status):
    """A CHECK violation (400), a conflict (409) or an outage (503) on the
    subscriptions upsert must reach Stripe as a 5xx with the lease
    released, so the retry is processed instead of skipped as a duplicate."""
    billing.post_status = supabase_status
    status, _ = await _deliver("customer.subscription.updated", {
        "id": "sub_rej", "status": "past_due", "metadata": {"user_id": "user-rej"},
    }, event_id="evt_rej")
    assert status == 500
    assert "stripe:event:evt_rej" not in redis.kv


@pytest.mark.asyncio
async def test_unknown_event_type_is_acknowledged_and_marked_done(billing, redis):
    status, body = await _deliver("payout.created", {"id": "po_1"}, event_id="evt_unknown")
    assert status == 200 and body == {"status": "ok"}
    assert billing.posts == []
    assert redis.kv["stripe:event:evt_unknown"] == "done"


# ─── Attribution: who is behind a Stripe object ────────────────────
#
# subscription / refund events without our metadata are matched to a user
# by our row, else by the user_id in the metadata of the customer's Stripe
# subscriptions. Stripe failing there must be retried, never guessed.


def _metadata_less_sub(**extra) -> dict:
    return {"id": "sub_anon", "status": "active", "customer": "cus_anon", "metadata": {}, **extra}


@pytest.mark.asyncio
async def test_subscription_nobody_can_be_attributed_to_is_skipped(billing, redis, fake_stripe, account_store):
    status, _ = await _deliver("customer.subscription.updated", _metadata_less_sub())
    assert status == 200
    assert billing.posts == [] and account_store.entitlements == []
    assert fake_stripe.list_calls[0]["customer"] == "cus_anon"


@pytest.mark.asyncio
async def test_user_found_in_a_later_stripe_subscription_of_the_customer(billing, redis, fake_stripe, account_store):
    fake_stripe.add_subscription("sub_other", "cus_anon")  # no metadata.user_id
    fake_stripe.add_subscription("sub_tagged", "cus_anon", metadata={"user_id": "user-legacy"})
    status, _ = await _deliver("customer.subscription.updated", _metadata_less_sub())
    assert status == 200
    assert billing.posts[0]["user_id"] == "user-legacy"
    assert billing.posts[0]["status"] == "active"


@pytest.mark.asyncio
async def test_customer_deleted_in_stripe_means_unattributed_not_an_error(
    billing, redis, fake_stripe, account_store, monkeypatch
):
    async def _gone(**_params):
        raise stripe.InvalidRequestError("No such customer: cus_anon", "customer", code="resource_missing")

    monkeypatch.setattr(stripe.Subscription, "list_async", _gone)
    status, _ = await _deliver("customer.subscription.deleted", _metadata_less_sub())
    assert status == 200
    assert billing.posts == []


@pytest.mark.asyncio
async def test_stripe_outage_while_attributing_is_retried(billing, redis, fake_stripe, account_store):
    fake_stripe.fail_list = True
    status, _ = await _deliver("customer.subscription.updated", _metadata_less_sub(), event_id="evt_attr")
    assert status == 500
    assert billing.posts == []
    assert "stripe:event:evt_attr" not in redis.kv  # the retry will be processed

    fake_stripe.fail_list = False
    fake_stripe.add_subscription("sub_anon", "cus_anon", metadata={"user_id": "user-late"})
    status, _ = await _deliver("customer.subscription.updated", _metadata_less_sub(), event_id="evt_attr")
    assert status == 200
    assert billing.posts[0]["user_id"] == "user-late"


# ─── Checkout completion / status transitions ──────────────────────


@pytest.mark.asyncio
async def test_completed_session_without_subscription_records_no_entitlement(billing, redis, account_store):
    status, _ = await _deliver("checkout.session.completed", _checkout_session(sub=None))
    assert status == 200
    assert billing.posts[0]["status"] == "active"
    assert "provider_subscription_id" not in billing.posts[0]
    assert account_store.entitlements == []
    created = [a for a in billing.audit_posts if a["action"] == "subscription.created"]
    assert created[0]["target_id"] == "user-h"


@pytest.mark.asyncio
async def test_active_past_due_canceled_deleted_lifecycle(billing, redis, account_store):
    """Each Stripe status change lands on both the legacy row and the
    entitlement; a failed renewal keeps access (past_due), cancellation
    removes it, deletion drops the tier to free."""
    sub = {"id": "sub_life", "customer": "cus_life", "metadata": {"user_id": "user-life"}}
    seen = []
    for i, stripe_status in enumerate(["active", "past_due", "active", "canceled"]):
        status, _ = await _deliver(
            "customer.subscription.updated", {**sub, "status": stripe_status}, event_id=f"evt_life_{i}"
        )
        assert status == 200
        ent = [r for r in account_store.entitlements if r["external_id"] == "sub_life"]
        seen.append((billing.posts[-1]["status"], ent[0]["status"]))
    assert seen == [
        ("active", "active"), ("past_due", "past_due"), ("active", "active"), ("cancelled", "cancelled"),
    ]

    status, _ = await _deliver("customer.subscription.deleted", {**sub, "status": "canceled"}, event_id="evt_life_end")
    assert status == 200
    assert billing.posts[-1]["tier"] == "free" and billing.posts[-1]["status"] == "cancelled"


# ─── Refunds ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_full_refund_of_a_charge_without_invoice_revokes_access(billing, redis, fake_stripe, account_store):
    """No invoice on the charge → we can't tell which period it paid for;
    the customer has their money back, so access ends."""
    billing.rows = [_paid_row("user-ni", "sub_ni", "cus_refund")]
    fake_stripe.add_subscription("sub_ni", "cus_refund", latest_invoice="in_latest")
    status, _ = await _deliver("charge.refunded", _invoice_charge(invoice=None))
    assert status == 200
    assert billing.posts[-1]["tier"] == "free" and billing.posts[-1]["status"] == "cancelled"
    assert [c[0] for c in fake_stripe.cancel_calls] == ["sub_ni"]


@pytest.mark.asyncio
async def test_refund_classification_outage_is_retried_and_nothing_changes(billing, redis, fake_stripe, monkeypatch):
    billing.rows = [_paid_row("user-ro", "sub_ro", "cus_refund")]

    async def _down(sub_id, **_params):
        raise stripe.APIConnectionError("simulated Stripe outage")

    monkeypatch.setattr(stripe.Subscription, "retrieve_async", _down)
    status, _ = await _deliver("charge.refunded", _invoice_charge(), event_id="evt_ro")
    assert status == 500
    assert billing.posts == [] and fake_stripe.cancel_calls == []
    assert "stripe:event:evt_ro" not in redis.kv


@pytest.mark.asyncio
async def test_refund_whose_stripe_cancel_fails_keeps_the_row_and_is_retried(billing, redis, fake_stripe):
    """The Stripe subscription is cancelled BEFORE access is revoked: if
    the cancel fails we must not drop the user to free while Stripe keeps
    the subscription able to renew."""
    billing.rows = [_paid_row("user-cf", "sub_cf", "cus_refund")]
    fake_stripe.add_subscription("sub_cf", "cus_refund", latest_invoice="in_latest")
    fake_stripe.fail_cancel = True
    status, _ = await _deliver("charge.refunded", _invoice_charge())
    assert status == 500
    assert billing.posts == []


@pytest.mark.asyncio
async def test_full_refund_for_a_paid_row_without_a_stripe_subscription(billing, redis, fake_stripe, account_store):
    """A paid row with no subscription on file (e.g. a hand-granted plan):
    the refund still ends access, but there is nothing to cancel in Stripe
    and no Stripe entitlement to mark."""
    billing.rows = [_paid_row("user-ns", None, "cus_refund")]
    status, _ = await _deliver("charge.refunded", _invoice_charge())
    assert status == 200
    assert billing.posts[-1]["status"] == "cancelled"
    assert fake_stripe.cancel_calls == [] and account_store.entitlements == []


@pytest.mark.asyncio
async def test_full_refund_for_a_user_who_no_longer_pays_changes_nothing(billing, redis, fake_stripe):
    billing.rows = [{**_paid_row("user-free", "sub_old", "cus_refund"), "tier": "free", "status": "cancelled"}]
    status, _ = await _deliver("charge.refunded", _invoice_charge())
    assert status == 200
    assert billing.posts == [] and fake_stripe.cancel_calls == []
    refund = [a for a in billing.audit_posts if a["action"] == "subscription.refunded"][0]
    assert refund["meta"]["full_refund"] is True and refund["meta"]["access_revoked"] is False


# ─── Disputes ──────────────────────────────────────────────────────


def _dispute(charge: Any, **extra) -> dict:
    return {"id": "dp_h", "object": "dispute", "charge": charge, "amount": 499,
            "currency": "usd", "reason": "fraudulent", **extra}


def _dispute_audit(billing) -> dict:
    rows = [a for a in billing.audit_posts if a["action"] == "subscription.dispute_opened"]
    assert len(rows) == 1
    return rows[0]


@pytest.mark.asyncio
async def test_dispute_with_our_metadata_needs_no_stripe_lookup(billing, redis, fake_stripe):
    status, _ = await _deliver("charge.dispute.created", _dispute("ch_unknown", metadata={"user_id": "user-md"}))
    assert status == 200
    assert _dispute_audit(billing)["actor_user_id"] == "user-md"
    assert billing.posts == []  # disputes never change the tier


@pytest.mark.asyncio
async def test_dispute_with_an_expanded_charge_resolves_via_its_customer(billing, redis, fake_stripe):
    billing.rows = [_paid_row("user-exp", "sub_exp", "cus_exp")]
    status, _ = await _deliver("charge.dispute.created", _dispute({"id": "ch_exp", "customer": "cus_exp"}))
    assert status == 200
    audit = _dispute_audit(billing)
    assert audit["actor_user_id"] == "user-exp" and audit["meta"]["charge_id"] == "ch_exp"


@pytest.mark.asyncio
async def test_dispute_on_a_charge_without_customer_is_logged_unattributed(billing, redis, fake_stripe):
    fake_stripe.charges["ch_guest"] = {"id": "ch_guest", "customer": None}
    status, _ = await _deliver("charge.dispute.created", _dispute("ch_guest"))
    assert status == 200
    assert _dispute_audit(billing)["actor_user_id"] is None
    assert fake_stripe.list_calls == []


@pytest.mark.asyncio
async def test_dispute_charge_lookup_outage_is_retried(billing, redis, fake_stripe, monkeypatch):
    async def _down(charge_id, **_params):
        raise stripe.APIConnectionError("simulated Stripe outage")

    monkeypatch.setattr(stripe.Charge, "retrieve_async", _down)
    status, _ = await _deliver("charge.dispute.created", _dispute("ch_down"), event_id="evt_dp")
    assert status == 500
    assert "stripe:event:evt_dp" not in redis.kv


# ─── Customer deleted ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_customer_deleted_entitlement_failure_is_retried(billing, redis, account_store):
    billing.rows = [_paid_row("user-cdf", "sub_cdf", "cus_cdf")]
    account_store.add_entitlement("user-cdf", external_id="sub_cdf")
    account_store.fail = True
    status, _ = await _deliver("customer.deleted", {"id": "cus_cdf"}, event_id="evt_cdf")
    assert status == 500
    assert "stripe:event:evt_cdf" not in redis.kv

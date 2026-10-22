"""Checkout and provider-event edges: notifications that race the provider's HTTP answer, a
provider without a contract, events that cannot be matched by every reference, STOP SMS /
refund / pending notifications, sandbox payments in production, and the best-effort cancel
at the provider. Plus the seat-code failure paths.
"""
from __future__ import annotations

import time
from dataclasses import replace
from datetime import timedelta

import pytest

from api.billing import scheduler
from api.billing.models import FailureReason, PaymentStatus, ProtectionMode, SubscriptionStatus as S
from api.billing.providers.base import BillingEvent, EventKind, NotConfiguredError, ProviderError
from api.billing.service import cancel as cancel_service
from api.billing.service import checkout as checkout_service
from api.billing.service import seats as seat_service
from api.billing.service.errors import Conflict, NotConfigured, NotFound
from api.billing.service.passes import compute_entitlement
from api.billing.service.webhooks import ingest_webhook
from tests.billing.conftest import NO_MONEY_NUMBER, SUCCESS_NUMBER
from tests.billing.test_flows import CONSENT, _audit_actions, _deliver, _device, _sub, _subscribe
from tests.billing.test_money_safety import _mixplat_checkout, _mixplat_webhook, mixplat_ctx  # noqa: F401 — fixture


async def _payments(ctx, sub_id):
    async with ctx.store.transaction() as tx:
        return list(await tx.list_payments(sub_id))


async def _start(ctx, device, number=SUCCESS_NUMBER, plan="solo"):
    return await checkout_service.start_checkout(ctx, device, plan_code=plan, provider_code="fake", msisdn=number,
                                                 consent_doc_version=CONSENT)


def _account_subs(ctx, device):
    return [s for s in ctx.store.tables.subscriptions.values() if s.payer_account_id == device.account_id]


# ── start_checkout: what can happen while the provider is being called ──


@pytest.mark.asyncio
async def test_a_provider_without_a_contract_closes_the_intent(ctx, fake):
    device, _ = await _device(ctx)

    async def no_contract(**kwargs):
        raise NotConfiguredError("T2 direct billing has no contract yet")

    fake.start_checkout = no_contract
    with pytest.raises(NotConfigured) as err:
        await _start(ctx, device)
    assert err.value.code == "not_configured" and "no contract" in err.value.message
    assert _account_subs(ctx, device) == []
    assert ctx.store.tables.payments == {}
    assert [a.action for a in ctx.store.tables.audit].count("checkout.closed") == 1


@pytest.mark.asyncio
async def test_a_failure_notification_during_the_call_wins_and_the_app_sees_failed(ctx, fake):
    device, _ = await _device(ctx)
    original = fake.start_checkout

    async def declined_meanwhile(**kwargs):
        start = await original(**kwargs)
        await _deliver(ctx, fake, fake.event_payload(start.provider_ref, outcome=FailureReason.NO_MONEY, payment_id=None,
                                                     merchant_payment_id=kwargs["idempotency_key"], event_id="evt-fail"))
        return start

    fake.start_checkout = declined_meanwhile
    result = await _start(ctx, device)
    assert result["status"] == "failed"
    assert _account_subs(ctx, device) == []
    polled = await checkout_service.get_checkout(ctx, device, result["checkout_id"])
    assert polled["status"] == "failed" and polled["failure_reason"] == "no_money"


@pytest.mark.asyncio
async def test_a_refusal_after_a_failure_notification_closes_the_checkout_once(ctx, fake):
    device, _ = await _device(ctx)
    original = fake.start_checkout

    async def declined_then_error(**kwargs):
        start = await original(**kwargs)
        await _deliver(ctx, fake, fake.event_payload(start.provider_ref, outcome=FailureReason.USER_DECLINED,
                                                     merchant_payment_id=kwargs["idempotency_key"], event_id="evt-x"))
        raise ProviderError("MIXPLAT create_payment_form: internal_error")

    fake.start_checkout = declined_then_error
    with pytest.raises(NotConfigured) as err:
        await _start(ctx, device)
    assert err.value.code == "provider_error"
    assert [a.action for a in ctx.store.tables.audit].count("checkout.closed") == 1
    assert "checkout.provider_refused" not in [a.action for a in ctx.store.tables.audit]


@pytest.mark.asyncio
async def test_the_recurrent_reference_from_an_early_notification_is_not_overwritten(ctx, fake, clock):
    """MIXPLAT: the checkout answer names a payment id, the notification the recurrent id renewals need.
    If the notification is committed first, step 3 must not replace the recurrent id."""
    device, _ = await _device(ctx)
    original = fake.start_checkout

    async def paid_meanwhile(**kwargs):
        start = await original(**kwargs)
        await _deliver(ctx, fake, {**fake.event_payload(start.provider_ref, merchant_payment_id=kwargs["idempotency_key"],
                                                        event_id="evt-paid"), "subscription_ref": "R-recurrent"})
        return start

    fake.start_checkout = paid_meanwhile
    result = await _start(ctx, device)
    assert result["status"] == "active"
    sub = await _sub(ctx, result["checkout_id"])
    assert sub.provider_subscription_id == "R-recurrent"
    clock.now = sub.current_period_end
    assert await scheduler.run_renewals(ctx, clock.now) == 1
    assert fake.renewals[0]["provider_subscription_id"] == "R-recurrent"


# ── Matching a notification to a subscription ──


@pytest.mark.asyncio
async def test_a_notification_naming_only_the_checkout_payment_id_is_matched(ctx, fake):
    """No recurrent id, no merchant id: the payment id is the checkout's provider reference."""
    device, _ = await _device(ctx)
    result = await _start(ctx, device, number=NO_MONEY_NUMBER)
    ref = (await _sub(ctx, result["checkout_id"])).provider_subscription_id
    payload = {**fake.event_payload(ref, outcome=FailureReason.NO_MONEY, payment_id=ref, event_id="evt-ref"),
               "subscription_ref": None}
    status, _ = await _deliver(ctx, fake, payload)
    assert status == 200
    assert await _sub(ctx, result["checkout_id"]) is None
    polled = await checkout_service.get_checkout(ctx, device, result["checkout_id"])
    assert polled["failure_reason"] == "no_money"


@pytest.mark.asyncio
async def test_a_notification_with_only_our_merchant_id_is_matched(ctx, fake):
    device, _ = await _device(ctx)
    result = await _start(ctx, device)
    key = checkout_service.checkout_key(result["checkout_id"])
    payload = {**fake.event_payload("unknown-ref", merchant_payment_id=key, event_id="evt-m", amount_kopecks=9900),
               "payment_id": None}
    await _deliver(ctx, fake, payload)
    assert (await _sub(ctx, result["checkout_id"])).status is S.ACTIVE
    assert (await compute_entitlement(ctx, device)).claims.mode is ProtectionMode.FULL


# ── Notification kinds ──


@pytest.mark.asyncio
async def test_a_stop_sms_cancels_and_nothing_is_charged_again(ctx, fake, clock):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")
    sub = await _sub(ctx, sub_id)
    await _deliver(ctx, fake, fake.event_payload(sub.provider_subscription_id, kind="subscription_cancelled",
                                                 payment_id=f"pay_{sub.provider_subscription_id}", event_id="evt-stop"))
    stopped = await _sub(ctx, sub_id)
    assert stopped.status is S.CANCEL_AT_PERIOD_END and stopped.cancel_channel.value == "operator_stop"
    # The checkout payment is not touched by a cancel notification.
    assert [p.status for p in await _payments(ctx, sub_id)] == [PaymentStatus.SUCCEEDED]
    clock.now = stopped.current_period_end
    assert await scheduler.run_renewals(ctx, clock.now) == 0 and fake.renewals == []
    assert await scheduler.run_expiries(ctx, clock.now) == 1
    assert (await _sub(ctx, sub_id)).status is S.LAPSED


@pytest.mark.asyncio
async def test_a_refund_notification_ends_access_and_renewals(ctx, fake, clock):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")
    ref = (await _sub(ctx, sub_id)).provider_subscription_id
    await _deliver(ctx, fake, fake.event_payload(ref, kind="refunded", payment_id=f"pay_{ref}", event_id="evt-ref"))
    sub = await _sub(ctx, sub_id)
    assert sub.status is S.REFUNDED and sub.next_charge_at is None
    assert [p.status for p in await _payments(ctx, sub_id)] == [PaymentStatus.REFUNDED]
    assert (await compute_entitlement(ctx, device)).claims.mode is ProtectionMode.BASIC
    clock.now = sub.current_period_end
    assert await scheduler.run_renewals(ctx, clock.now) == 0


@pytest.mark.asyncio
async def test_a_pending_notification_changes_nothing(ctx, fake):
    device, _ = await _device(ctx)
    result = await _start(ctx, device)
    ref = (await _sub(ctx, result["checkout_id"])).provider_subscription_id
    await _deliver(ctx, fake, fake.event_payload(ref, kind="payment_pending", payment_id="pay-p", event_id="evt-p"))
    sub = await _sub(ctx, result["checkout_id"])
    assert sub.status is S.PENDING
    (row,) = await _payments(ctx, sub.id)
    assert row.status is PaymentStatus.PENDING and row.provider_payment_id == "pay-p"
    (event,) = [r for (p, e), r in ctx.store.tables.events.items() if e == "evt-p"]
    assert event["outcome"] == "pending"


@pytest.mark.asyncio
async def test_a_notification_that_makes_no_sense_in_the_status_is_ignored_and_audited(ctx, fake):
    """A STOP SMS for a checkout that was never paid: no transition, an audit row, the webhook still 200."""
    device, _ = await _device(ctx)
    result = await _start(ctx, device)
    ref = (await _sub(ctx, result["checkout_id"])).provider_subscription_id
    status, _ = await _deliver(ctx, fake, fake.event_payload(ref, kind="subscription_cancelled", event_id="evt-early-stop"))
    assert status == 200
    assert (await _sub(ctx, result["checkout_id"])).status is S.PENDING
    assert "event.ignored" in await _audit_actions(ctx, result["checkout_id"])
    (event,) = [r for (p, e), r in ctx.store.tables.events.items() if e == "evt-early-stop"]
    assert event["outcome"] == "invalid_in_status"


# ── MIXPLAT: a sandbox payment in production; a success with no row to compare with ──


@pytest.mark.asyncio
async def test_a_sandbox_payment_never_activates_a_production_subscription(mixplat_ctx):  # noqa: F811
    mctx, transport = mixplat_ctx
    prod = replace(mctx, settings=mctx.settings.model_copy(update={"billing_mixplat_test": False}))
    _, sub_id, key = await _mixplat_checkout(prod)
    transport.status["P1"] = {"status": "success", "amount": 9900, "currency": "RUB", "merchant_payment_id": key, "test": 1}
    status, _ = await ingest_webhook(prod, provider_code="mixplat", headers={}, body=_mixplat_webhook("P1", key))
    assert status == 200
    assert (await _sub(prod, sub_id)).status is S.PENDING
    assert [p.status for p in await _payments(prod, sub_id)] == [PaymentStatus.PENDING]
    assert "event.test_ignored" in await _audit_actions(prod, sub_id)


@pytest.mark.asyncio
async def test_a_mixplat_success_with_no_payment_row_is_refused(mixplat_ctx):  # noqa: F811
    """The notification's md5 does not cover the amount: without our row there is nothing to check it against."""
    mctx, transport = mixplat_ctx
    _, sub_id, key = await _mixplat_checkout(mctx)
    mctx.store.tables.payments.clear()
    transport.status["P1"] = {"status": "success", "amount": 9900, "currency": "RUB", "recurrent_id": "R1"}
    status, _ = await ingest_webhook(mctx, provider_code="mixplat", headers={}, body=_mixplat_webhook("P1", "", amount=9900))
    assert status == 200
    assert (await _sub(mctx, sub_id)).status is S.PENDING
    async with mctx.store.transaction() as tx:
        (row,) = [a for a in await tx.list_audit(f"subscription:{sub_id}") if a.action == "payment.amount_mismatch"]
    assert row.meta["why"] == "no_payment_row" and row.meta["expected_kopecks"] is None


@pytest.mark.asyncio
async def test_a_success_in_another_currency_is_refused_even_from_a_lenient_provider(ctx, fake):
    device, _ = await _device(ctx)
    result = await _start(ctx, device)
    event = BillingEvent(provider="fake", provider_event_id="evt-usd", kind=EventKind.PAYMENT_SUCCEEDED,
                         occurred_at=time.time(), merchant_payment_id=checkout_service.checkout_key(result["checkout_id"]),
                         amount_kopecks=9900, currency="usd")
    async with ctx.store.transaction() as tx:
        sub, outcome = await checkout_service.apply_provider_event(ctx, tx, event, actor="test")
    assert outcome == "amount_mismatch" and sub.status is S.PENDING
    # ISO 4217 numeric code for the rouble, padded: accepted.
    async with ctx.store.transaction() as tx:
        sub, outcome = await checkout_service.apply_provider_event(
            ctx, tx, replace(event, provider_event_id="evt-643", currency=" 643 "), actor="test")
    assert outcome == "applied" and sub.status is S.ACTIVE


# ── Cancel at the provider is best effort ──


@pytest.mark.asyncio
async def test_a_cancel_succeeds_for_the_person_when_the_provider_cancel_fails(ctx, fake, clock):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")

    async def down(**kwargs):
        raise ProviderError("provider down")

    fake.cancel = down
    result = await cancel_service.cancel_subscription(ctx, device)
    assert result["status"] == "cancel_at_period_end"
    async with ctx.store.transaction() as tx:
        (failed,) = [a for a in await tx.list_audit(f"subscription:{sub_id}") if a.action == "provider.cancel_failed"]
    assert failed.meta == {"provider": "fake", "error": "ProviderError"}
    clock.now = (await _sub(ctx, sub_id)).current_period_end
    assert await scheduler.run_renewals(ctx, clock.now) == 0 and fake.renewals == []


@pytest.mark.asyncio
async def test_a_cancel_with_the_provider_no_longer_registered_still_cancels(ctx, fake):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")
    without_fake = replace(ctx, providers={k: v for k, v in ctx.providers.items() if k != "fake"})
    assert (await cancel_service.cancel_subscription(without_fake, device))["status"] == "cancel_at_period_end"
    assert fake.cancelled == []
    assert "provider.cancel_failed" not in await _audit_actions(ctx, sub_id)


# ── Seats and codes ──


@pytest.mark.asyncio
async def test_a_phone_without_a_subscription_cannot_issue_codes(ctx):
    device, _ = await _device(ctx)
    with pytest.raises(NotFound) as err:
        await seat_service.create_claim_code(ctx, device)
    assert err.value.code == "no_subscription"


@pytest.mark.asyncio
async def test_code_collisions_are_retried_then_refused(ctx, fake, monkeypatch):
    owner, _ = await _device(ctx)
    await _subscribe(ctx, fake, owner, plan="family3")
    monkeypatch.setattr(seat_service, "generate_claim_code", lambda: "424242")
    assert (await seat_service.create_claim_code(ctx, owner))["code"] == "424242"
    with pytest.raises(Conflict) as err:
        await seat_service.create_claim_code(ctx, owner)
    assert err.value.code == "code_collision"
    assert len(ctx.store.tables.claim_codes) == 1


@pytest.mark.asyncio
async def test_a_code_of_a_subscription_that_lapsed_is_invalid(ctx, fake, clock):
    owner, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, owner, plan="family3")
    await cancel_service.cancel_subscription(ctx, owner)
    end = (await _sub(ctx, sub_id)).current_period_end
    clock.now = end - timedelta(hours=1)
    code = (await seat_service.create_claim_code(ctx, owner))["code"]   # still live: a code may be issued
    clock.now = end
    await scheduler.run_expiries(ctx, clock.now)
    relative, _ = await _device(ctx)
    with pytest.raises(NotFound) as err:
        await seat_service.redeem_claim_code(ctx, relative, code=code)
    assert err.value.code == "code_invalid"


@pytest.mark.asyncio
async def test_a_phone_paying_elsewhere_cannot_join_another_subscription(ctx, fake):
    owner, _ = await _device(ctx)
    await _subscribe(ctx, fake, owner, plan="family3")
    code = (await seat_service.create_claim_code(ctx, owner))["code"]
    other, _ = await _device(ctx)
    await _subscribe(ctx, fake, other, plan="solo", number="+79161112233")
    with pytest.raises(Conflict) as err:
        await seat_service.redeem_claim_code(ctx, other, code=code)
    assert err.value.code == "already_subscribed"


@pytest.mark.asyncio
async def test_a_phone_whose_old_subscription_lapsed_can_join_a_family(ctx, fake, clock):
    """Its seat on the lapsed subscription is history: released, then the phone joins."""
    old_payer, _ = await _device(ctx)
    old_sub = await _subscribe(ctx, fake, old_payer, plan="solo", number="+79161112233")
    await cancel_service.cancel_subscription(ctx, old_payer)
    clock.now = (await _sub(ctx, old_sub)).current_period_end
    owner, _ = await _device(ctx)
    await _subscribe(ctx, fake, owner, plan="family3")
    await scheduler.run_expiries(ctx, clock.now)
    assert (await _sub(ctx, old_sub)).status is S.LAPSED
    code = (await seat_service.create_claim_code(ctx, owner))["code"]
    joined = await seat_service.redeem_claim_code(ctx, old_payer, code=code)
    assert joined["seats_used"] == 2
    async with ctx.store.transaction() as tx:
        assert await tx.list_seats(old_sub) == []
        assert (await tx.get_active_seat_for_device(old_payer.id)).subscription_id == joined["subscription_id"]

"""Scheduler money edges: adapter crashes, races with webhooks / cancels / refunds while a
provider call is in flight, a renewal key that was already used, a missing plan version,
checkouts the provider still reports as in progress, and reconciliation answers that cannot
be applied (unknown provider, mismatched amount, repeated every pass).
"""
from __future__ import annotations

import logging
import time
from dataclasses import replace
from datetime import timedelta

import pytest

from api.billing import scheduler
from api.billing.models import FailureReason, Payment, PaymentStatus, SubscriptionStatus as S
from api.billing.providers.base import BillingEvent, EventKind, ProviderError, ProviderUnavailable
from api.billing.service import cancel as cancel_service
from api.billing.service import checkout as checkout_service
from api.billing.service.common import sub_state
from api.billing.state_machine import Charge, RenewalDue, add_months, apply
from tests.billing.conftest import SUCCESS_NUMBER
from tests.billing.test_flows import CONSENT, _audit_actions, _deliver, _device, _sub, _subscribe

OTHER_NUMBER = "+79161112233"


async def _payments(ctx, sub_id):
    async with ctx.store.transaction() as tx:
        return list(await tx.list_payments(sub_id))


async def _renewal_rows(ctx, sub_id):
    return [p for p in await _payments(ctx, sub_id) if p.period_start is not None]


async def _due(ctx, fake, clock, *, number=SUCCESS_NUMBER):
    """An active solo subscription whose renewal is due now."""
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo", number=number)
    period_end = (await _sub(ctx, sub_id)).current_period_end
    clock.now = period_end
    return device, sub_id, period_end


async def _checkout(ctx, number=SUCCESS_NUMBER):
    device, _ = await _device(ctx)
    result = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                                   msisdn=number, consent_doc_version=CONSENT)
    return device, result["checkout_id"]


def _status_event(kind: EventKind, *, event_id: str, amount=None, merchant=None, ref=None) -> BillingEvent:
    return BillingEvent(provider="fake", provider_event_id=event_id, kind=kind, occurred_at=time.time(),
                        provider_subscription_id=ref, merchant_payment_id=merchant, amount_kopecks=amount)


# ── Renewals: what the provider call can do to us ──


@pytest.mark.asyncio
async def test_a_crashing_adapter_leaves_the_charge_pending_and_never_charges_again(ctx, fake, clock, caplog):
    """An adapter bug (not a ProviderError) may have moved money: treat it as an unknown outcome."""
    _, sub_id, _ = await _due(ctx, fake, clock)
    calls = []

    async def crashing(**kwargs):
        calls.append(kwargs["idempotency_key"])
        raise KeyError("payment_id")

    fake.charge_renewal = crashing
    with caplog.at_level(logging.ERROR, logger="cleanway.billing.scheduler"):
        assert await scheduler.run_renewals(ctx, clock.now) == 0
    assert any(r.getMessage() == "billing.renewal.provider_crashed" for r in caplog.records)
    sub = await _sub(ctx, sub_id)
    assert sub.status is S.ACTIVE and sub.charge_pending is True      # not grace: we do not know it failed
    (row,) = await _renewal_rows(ctx, sub_id)
    assert row.status is PaymentStatus.PENDING
    async with ctx.store.transaction() as tx:
        audit = [a for a in await tx.list_audit(f"subscription:{sub_id}") if a.action == "charge.provider_error"]
    assert audit[-1].meta["outcome"] == "unknown" and audit[-1].meta["error"] == "KeyError"
    # The next pass must not call the provider for the same period again.
    assert await scheduler.run_renewals(ctx, clock.now) == 0
    assert calls == [row.idempotency_key]


@pytest.mark.asyncio
async def test_a_success_webhook_during_the_charge_call_is_applied_once(ctx, fake, clock):
    """The aggregator's notification beats the HTTP answer: the period is extended exactly once and
    the reference the notification recorded is kept."""
    _, sub_id, period_end = await _due(ctx, fake, clock)
    original = fake.charge_renewal
    sub = await _sub(ctx, sub_id)

    async def notified_first(**kwargs):
        payment_id = await original(**kwargs)
        await _deliver(ctx, fake, fake.event_payload(sub.provider_subscription_id, payment_id=payment_id,
                                                     merchant_payment_id=kwargs["idempotency_key"],
                                                     event_id="evt-early"))
        return payment_id

    fake.charge_renewal = notified_first
    assert await scheduler.run_renewals(ctx, clock.now) == 1
    renewed = await _sub(ctx, sub_id)
    assert renewed.status is S.ACTIVE and renewed.charge_pending is False
    assert renewed.current_period_end == add_months(period_end, 1)
    (row,) = await _renewal_rows(ctx, sub_id)
    assert row.status is PaymentStatus.SUCCEEDED and row.provider_payment_id == fake.renewals[0]["payment_id"]
    # Not due again until the new period ends.
    assert await scheduler.run_renewals(ctx, clock.now) == 0 and len(fake.renewals) == 1


@pytest.mark.asyncio
async def test_a_cancel_landing_mid_pass_is_honoured_for_the_next_subscription(ctx, fake, clock):
    """Two renewals due; the second payer cancels while the first is being charged: not one kopeck more."""
    first, _ = await _device(ctx)
    second, _ = await _device(ctx)
    a = await _subscribe(ctx, fake, first, plan="solo")
    b = await _subscribe(ctx, fake, second, plan="solo", number=OTHER_NUMBER)
    clock.now = max((await _sub(ctx, a)).current_period_end, (await _sub(ctx, b)).current_period_end)
    refs = {(await _sub(ctx, a)).provider_subscription_id: second, (await _sub(ctx, b)).provider_subscription_id: first}
    original = fake.charge_renewal

    async def cancel_the_other(**kwargs):
        if len(fake.renewals) == 0:
            await cancel_service.cancel_subscription(ctx, refs[kwargs["provider_subscription_id"]])
        return await original(**kwargs)

    fake.charge_renewal = cancel_the_other
    assert await scheduler.run_renewals(ctx, clock.now) == 1
    assert len(fake.renewals) == 1
    statuses = sorted([(await _sub(ctx, a)).status.value, (await _sub(ctx, b)).status.value])
    assert statuses == sorted([S.ACTIVE.value, S.CANCEL_AT_PERIOD_END.value])


@pytest.mark.asyncio
async def test_a_missing_plan_version_is_never_charged_and_is_audited(ctx, fake, clock):
    _, sub_id, _ = await _due(ctx, fake, clock)
    sub = await _sub(ctx, sub_id)
    async with ctx.store.transaction() as tx:
        await tx.update_subscription(replace(sub, plan_version=99), expected_version=sub.row_version)
    assert await scheduler.run_renewals(ctx, clock.now) == 0
    assert fake.renewals == []
    assert (await _sub(ctx, sub_id)).charge_pending is False
    assert await _renewal_rows(ctx, sub_id) == []
    assert "charge.plan_missing" in await _audit_actions(ctx, sub_id)


@pytest.mark.asyncio
async def test_a_renewal_key_that_already_has_a_row_is_never_sent_again(ctx, fake, clock, caplog):
    """A row under this period's key exists although the machine has no charge in flight: a person reconciles."""
    _, sub_id, _ = await _due(ctx, fake, clock)
    sub = await _sub(ctx, sub_id)
    (charge,) = [e for e in apply(sub_state(sub), RenewalDue(), clock.now, ctx.policy()).effects if isinstance(e, Charge)]
    async with ctx.store.transaction() as tx:
        await tx.create_payment(Payment(
            id="settled-elsewhere", subscription_id=sub_id, provider=sub.provider, idempotency_key=charge.idempotency_key,
            amount_kopecks=9900, status=PaymentStatus.SUCCEEDED, created_at=clock.now, period_start=charge.period_start,
        ))
    with caplog.at_level(logging.ERROR, logger="cleanway.billing.scheduler"):
        assert await scheduler.run_renewals(ctx, clock.now) == 0
    assert fake.renewals == []
    assert any(r.getMessage() == "billing.renewal.key_already_used" for r in caplog.records)
    assert "charge.already_settled" in await _audit_actions(ctx, sub_id)
    assert (await _sub(ctx, sub_id)).charge_pending is False


@pytest.mark.asyncio
async def test_a_refusal_after_the_notification_settled_the_charge_keeps_the_period(ctx, fake, clock):
    """The success webhook arrives, then the HTTP call answers with an error: the money was taken, no grace."""
    _, sub_id, period_end = await _due(ctx, fake, clock)
    original = fake.charge_renewal
    ref = (await _sub(ctx, sub_id)).provider_subscription_id

    async def settled_then_refused(**kwargs):
        payment_id = await original(**kwargs)
        await _deliver(ctx, fake, fake.event_payload(ref, payment_id=payment_id, merchant_payment_id=kwargs["idempotency_key"],
                                                     event_id="evt-settled"))
        raise ProviderError("MIXPLAT create_recurrent_payment: duplicate")

    fake.charge_renewal = settled_then_refused
    assert await scheduler.run_renewals(ctx, clock.now) == 0
    sub = await _sub(ctx, sub_id)
    assert sub.status is S.ACTIVE and sub.grace_until is None and sub.attempt == 0
    assert sub.current_period_end == add_months(period_end, 1)
    (row,) = await _renewal_rows(ctx, sub_id)
    assert row.status is PaymentStatus.SUCCEEDED
    assert "payment.failed" not in await _audit_actions(ctx, sub_id)


@pytest.mark.asyncio
async def test_a_refusal_never_reopens_grace_on_a_subscription_refunded_meanwhile(ctx, fake, clock):
    _, sub_id, _ = await _due(ctx, fake, clock)
    ref = (await _sub(ctx, sub_id)).provider_subscription_id

    async def refunded_then_refused(**kwargs):
        await _deliver(ctx, fake, fake.event_payload(ref, kind="refunded", payment_id=f"pay_{ref}", event_id="evt-refund"))
        raise ProviderError("MIXPLAT create_recurrent_payment: recurrent_cancelled")

    fake.charge_renewal = refunded_then_refused
    assert await scheduler.run_renewals(ctx, clock.now) == 0
    sub = await _sub(ctx, sub_id)
    assert sub.status is S.REFUNDED and sub.grace_until is None and sub.next_charge_at is None
    (row,) = await _renewal_rows(ctx, sub_id)
    assert row.status is PaymentStatus.FAILED
    # Nothing is due for a refunded subscription.
    clock.advance(days=3)
    assert await scheduler.run_renewals(ctx, clock.now) == 0


# ── Pending timeouts: the provider is asked before a checkout is thrown away ──


@pytest.mark.asyncio
async def test_a_checkout_still_in_progress_is_kept_then_closed_after_the_max_wait(ctx, fake, clock):
    _, sub_id = await _checkout(ctx)
    asked = []

    async def in_progress(*, provider_ref=None, merchant_payment_id=None):
        asked.append(merchant_payment_id)
        return _status_event(EventKind.PAYMENT_PENDING, event_id=f"st-{len(asked)}", merchant=merchant_payment_id)

    fake.fetch_status = in_progress
    clock.advance(minutes=31)
    assert await scheduler.run_pending_timeouts(ctx, clock.now) == 0
    assert (await _sub(ctx, sub_id)).status is S.PENDING
    clock.now = (await _sub(ctx, sub_id)).created_at + scheduler.CHECKOUT_MAX_WAIT - timedelta(seconds=1)
    assert await scheduler.run_pending_timeouts(ctx, clock.now) == 0
    clock.advance(seconds=1)
    assert await scheduler.run_pending_timeouts(ctx, clock.now) == 1
    assert await _sub(ctx, sub_id) is None
    assert asked == [checkout_service.checkout_key(sub_id)] * 3
    assert "checkout.closed" in await _audit_actions(ctx, sub_id)


@pytest.mark.asyncio
async def test_a_checkout_paid_while_the_provider_was_being_asked_is_not_deleted(ctx, fake, clock):
    _, sub_id = await _checkout(ctx)
    ref = (await _sub(ctx, sub_id)).provider_subscription_id

    async def webhook_meanwhile(*, provider_ref=None, merchant_payment_id=None):
        await _deliver(ctx, fake, fake.event_payload(ref, payment_id="pay-meanwhile", event_id="evt-meanwhile"))
        return None

    fake.fetch_status = webhook_meanwhile
    clock.advance(minutes=31)
    assert await scheduler.run_pending_timeouts(ctx, clock.now) == 0
    assert (await _sub(ctx, sub_id)).status is S.ACTIVE
    assert "checkout.closed" not in await _audit_actions(ctx, sub_id)


@pytest.mark.asyncio
async def test_a_checkout_without_a_payment_row_is_closed_without_asking(ctx, fake, clock):
    _, sub_id = await _checkout(ctx)
    ctx.store.tables.payments.clear()

    async def must_not_ask(**kwargs):
        raise AssertionError("nothing to reconcile")

    fake.fetch_status = must_not_ask
    clock.advance(minutes=31)
    assert await scheduler.run_pending_timeouts(ctx, clock.now) == 1
    assert await _sub(ctx, sub_id) is None


# ── Reconciliation: answers that cannot (or must not) be applied ──


@pytest.mark.asyncio
async def test_a_payment_whose_provider_is_no_longer_registered_waits_and_alerts(ctx, fake, clock, caplog):
    _, sub_id = await _checkout(ctx)
    without_fake = replace(ctx, providers={k: v for k, v in ctx.providers.items() if k != "fake"})
    clock.advance(minutes=31)
    assert await scheduler.run_reconciliation(without_fake, clock.now) == 0
    assert (await _sub(ctx, sub_id)).status is S.PENDING
    clock.advance(hours=24)
    with caplog.at_level(logging.ERROR, logger="cleanway.billing.scheduler"):
        assert await scheduler.run_reconciliation(without_fake, clock.now) == 0
    (alert,) = [r for r in caplog.records if r.getMessage() == "billing.payment.unresolved"]
    assert alert.found == "pending" and alert.age_hours == 24


@pytest.mark.asyncio
async def test_a_reconciled_in_progress_payment_is_reported_after_a_day(ctx, fake, clock, caplog):
    _, sub_id = await _checkout(ctx)

    async def in_progress(*, provider_ref=None, merchant_payment_id=None):
        return _status_event(EventKind.PAYMENT_PENDING, event_id="st", merchant=merchant_payment_id)

    fake.fetch_status = in_progress
    clock.advance(minutes=31)
    with caplog.at_level(logging.ERROR, logger="cleanway.billing.scheduler"):
        assert await scheduler.run_reconciliation(ctx, clock.now) == 0
        assert not [r for r in caplog.records if r.getMessage() == "billing.payment.unresolved"]
        clock.advance(hours=24)
        assert await scheduler.run_reconciliation(ctx, clock.now) == 0
    (alert,) = [r for r in caplog.records if r.getMessage() == "billing.payment.unresolved"]
    assert alert.found == "in_progress" and alert.subscription == sub_id


@pytest.mark.asyncio
async def test_a_reconciled_success_with_the_wrong_amount_is_refused_once_and_never_reapplied(ctx, fake, clock):
    """The provider says 'paid 1 kopeck': no access, one audit row, and the same answer next pass is a no-op."""
    _, sub_id = await _checkout(ctx)
    asked = []

    async def underpaid(*, provider_ref=None, merchant_payment_id=None):
        asked.append(1)
        return _status_event(EventKind.PAYMENT_SUCCEEDED, event_id="status-underpaid", amount=1,
                             merchant=merchant_payment_id, ref=provider_ref)

    fake.fetch_status = underpaid
    clock.advance(minutes=31)
    assert await scheduler.run_reconciliation(ctx, clock.now) == 0
    assert await scheduler.run_reconciliation(ctx, clock.now) == 0
    assert len(asked) == 2
    assert (await _sub(ctx, sub_id)).status is S.PENDING
    assert [p.status for p in await _payments(ctx, sub_id)] == [PaymentStatus.PENDING]
    actions = await _audit_actions(ctx, sub_id)
    assert actions.count("payment.amount_mismatch") == 1
    (row,) = [r for (p, e), r in ctx.store.tables.events.items() if e == "reconcile:status-underpaid"]
    assert row["outcome"] == "amount_mismatch"


def _underpaid_status(asked=None):
    async def underpaid(*, provider_ref=None, merchant_payment_id=None):
        if asked is not None:
            asked.append(1)
        return _status_event(EventKind.PAYMENT_SUCCEEDED, event_id="status-underpaid", amount=1,
                             merchant=merchant_payment_id, ref=provider_ref)
    return underpaid


async def _assert_held_for_review(ctx, sub_id):
    sub = await _sub(ctx, sub_id)
    assert sub is not None and sub.status is S.PENDING
    assert [p.status for p in await _payments(ctx, sub_id)] == [PaymentStatus.PENDING]
    actions = await _audit_actions(ctx, sub_id)
    assert "payment.amount_mismatch" in actions and "checkout.closed" not in actions


@pytest.mark.asyncio
async def test_an_underpaid_checkout_is_never_deleted_by_the_timeout(ctx, fake, clock):
    """Money moved but not the right amount: the checkout and its payment row stay (pending, for a
    person), however many passes run and however long past the timeout and the max wait."""
    _, sub_id = await _checkout(ctx)
    fake.fetch_status = _underpaid_status()
    clock.advance(minutes=31)
    for _ in range(3):
        counts = await scheduler.run_once(ctx, clock.now)
        assert counts["pending_timeouts"] == 0 and counts["reconciled"] == 0
    await _assert_held_for_review(ctx, sub_id)
    clock.now = (await _sub(ctx, sub_id)).created_at + scheduler.CHECKOUT_MAX_WAIT + timedelta(hours=1)
    assert (await scheduler.run_once(ctx, clock.now))["pending_timeouts"] == 0
    await _assert_held_for_review(ctx, sub_id)


@pytest.mark.asyncio
async def test_an_underpaid_checkout_stays_held_when_the_provider_later_goes_quiet(ctx, fake, clock):
    """The mismatch is remembered (audit), not re-derived: a later 'no answer' / 'unknown' from the
    provider does not turn the held checkout back into a deletable one."""
    _, sub_id = await _checkout(ctx)
    fake.fetch_status = _underpaid_status()
    clock.advance(minutes=31)
    assert await scheduler.run_reconciliation(ctx, clock.now) == 0

    async def no_answer(**kwargs):
        return None

    async def unreachable(**kwargs):
        raise ProviderUnavailable("timeout")

    for answer in (no_answer, unreachable):
        fake.fetch_status = answer
        clock.advance(minutes=31)
        assert await scheduler.run_pending_timeouts(ctx, clock.now) == 0
    await _assert_held_for_review(ctx, sub_id)


@pytest.mark.asyncio
async def test_an_underpaid_checkout_from_a_webhook_is_held_too(ctx, fake, clock):
    _, sub_id = await _checkout(ctx)
    ref = (await _sub(ctx, sub_id)).provider_subscription_id
    status, body = await _deliver(ctx, fake, fake.event_payload(ref, amount_kopecks=1, event_id="evt-underpaid"))
    assert status == 200

    async def no_answer(**kwargs):
        return None

    fake.fetch_status = no_answer
    clock.advance(minutes=31)
    assert await scheduler.run_pending_timeouts(ctx, clock.now) == 0
    await _assert_held_for_review(ctx, sub_id)


@pytest.mark.asyncio
async def test_starting_over_does_not_close_an_underpaid_checkout(ctx, fake, clock):
    """A new checkout normally closes the account's unconfirmed one; not one that took money."""
    device, sub_id = await _checkout(ctx)
    ref = (await _sub(ctx, sub_id)).provider_subscription_id
    await _deliver(ctx, fake, fake.event_payload(ref, amount_kopecks=1, event_id="evt-underpaid"))
    again = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                                  msisdn=OTHER_NUMBER, consent_doc_version=CONSENT)
    assert again["checkout_id"] != sub_id
    await _assert_held_for_review(ctx, sub_id)


@pytest.mark.asyncio
async def test_an_underpaid_payment_is_flagged_for_review_after_a_day(ctx, fake, clock, caplog):
    _, sub_id = await _checkout(ctx)
    fake.fetch_status = _underpaid_status()
    clock.advance(minutes=31)
    assert await scheduler.run_reconciliation(ctx, clock.now) == 0
    clock.advance(hours=24)
    with caplog.at_level(logging.ERROR, logger="cleanway.billing.scheduler"):
        assert await scheduler.run_reconciliation(ctx, clock.now) == 0
    (alert,) = [r for r in caplog.records if r.getMessage() == "billing.payment.unresolved"]
    assert alert.found == "needs_review" and alert.subscription == sub_id


@pytest.mark.asyncio
async def test_a_reconciled_renewal_failure_opens_grace(ctx, fake, clock):
    """A renewal whose call timed out and that the provider later reports as failed: grace, retries."""
    _, sub_id, period_end = await _due(ctx, fake, clock)
    original = fake.charge_renewal

    async def timed_out(**kwargs):
        await original(**kwargs)
        raise ProviderUnavailable("ReadTimeout")

    fake.charge_renewal = timed_out
    await scheduler.run_renewals(ctx, clock.now)
    fake.renewal_script[fake.renewals[0]["idempotency_key"]] = FailureReason.NO_MONEY
    clock.advance(minutes=31)
    assert await scheduler.run_reconciliation(ctx, clock.now) == 1
    sub = await _sub(ctx, sub_id)
    assert sub.status is S.GRACE and sub.charge_pending is False and sub.attempt == 1
    assert sub.grace_until == period_end + timedelta(days=ctx.settings.billing_grace_days)
    (row,) = await _renewal_rows(ctx, sub_id)
    assert row.status is PaymentStatus.FAILED and row.failure_reason is FailureReason.NO_MONEY

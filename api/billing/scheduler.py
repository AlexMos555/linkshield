"""Renewals, timeouts, expiries, reconciliation and unmatched-event retries (plan A.8).

NOTHING here is wired to a cron or a startup hook. `run_once()` is what a
scheduled job (every 15 minutes) will call once the founder switches
billing on; until then it is exercised by tests only.

    python -m api.billing.scheduler        # one pass, prints the counts

Money safety (2026-10): a provider is never called inside a database
transaction. Each renewal is its own unit —
  1. commit the payment row (pending, key `{sub}:{period_start}:{attempt}`)
     together with `charge_pending` on the subscription;
  2. call the provider with nothing locked;
  3. commit the outcome in a second transaction.
A later failure (a write, a crash, another subscription's error) can no
longer roll back a charge that was made, and a pass that runs again never
charges a key twice: the row exists and `charge_pending` stops the machine.
An ambiguous answer (timeout, 5xx) leaves the row pending and is settled by
the reconciler, which asks the provider by our own merchant payment id.
"""
from __future__ import annotations

import asyncio
import logging
import sys
import uuid
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from api.billing.context import BillingContext
from api.billing.models import FailureReason, Payment, PaymentStatus, Plan, Subscription, SubscriptionStatus
from api.billing.providers.base import EventKind, ProviderError, ProviderUnavailable, event_from_bytes
from api.billing.service.checkout import apply_provider_event, checkout_key, close_checkout
from api.billing.service.common import sub_state, sub_target, with_state
from api.billing.service.effects import run_effects
from api.billing.state_machine import (
    Charge,
    GraceExpired,
    PaymentFailed,
    PendingTimeout,
    PeriodEnded,
    RenewalDue,
    TermEnded,
    apply,
)

logger = logging.getLogger("cleanway.billing.scheduler")

RECONCILE_AFTER_MINUTES = 30
# A payment the provider still cannot settle after this long needs a person.
UNRESOLVED_ALERT_AFTER = timedelta(hours=24)
# A checkout the provider still reports as in progress is kept this long past the timeout.
CHECKOUT_MAX_WAIT = timedelta(hours=24)
# An unmatched webhook is retried this many passes (≈ 7 days at 15 minutes), then given up loudly.
UNMATCHED_MAX_ATTEMPTS = 7 * 24 * 4
_ACTOR = "system"
_GRANT_PROVIDERS = ("promo", "t2_option")


async def run_pending_timeouts(ctx: BillingContext, now: Optional[datetime] = None) -> int:
    """Checkouts nobody confirmed: gone after `billing_pending_timeout_minutes`.

    Deleting a checkout cascades to its payment row, so the provider is asked
    first: a payment that went through while its webhook was lost is applied,
    not thrown away; a checkout whose status the provider cannot report right
    now, or still reports as in progress, waits for a later pass.
    """
    now = now or ctx.now()
    cutoff = now - timedelta(minutes=ctx.settings.billing_pending_timeout_minutes)
    async with ctx.store.transaction() as tx:
        candidates = list(await tx.list_pending_older_than(cutoff=cutoff))
    removed = 0
    for candidate in candidates:
        async with ctx.store.transaction() as tx:
            payment = await tx.get_payment_by_idempotency_key(checkout_key(candidate.id))
        if payment is not None and payment.status is PaymentStatus.PENDING:
            found = await _reconcile_one(ctx, payment)
            if found in (_SETTLED, _UNKNOWN):
                continue
            if found == _IN_PROGRESS and now - candidate.created_at < CHECKOUT_MAX_WAIT:
                continue
        async with ctx.store.transaction() as tx:
            sub = await tx.get_subscription(candidate.id, for_update=True)
            if sub is None or sub.status is not SubscriptionStatus.PENDING:
                continue
            transition = apply(sub_state(sub), PendingTimeout(), now, ctx.policy())
            if transition.state.status is not None:
                continue
            await run_effects(ctx, tx, sub, transition.effects, actor=_ACTOR)
            await close_checkout(tx, sub, transition.effects, actor=_ACTOR)
            removed += 1
    return removed


async def run_renewals(ctx: BillingContext, now: Optional[datetime] = None) -> int:
    """Charge every due subscription whose provider lets us initiate — one unit each."""
    now = now or ctx.now()
    async with ctx.store.transaction() as tx:
        due = [s.id for s in await tx.list_due_renewals(now=now)
               if (p := ctx.providers.get(s.provider.value)) is not None and p.initiates_renewals]
    charged = 0
    for sub_id in due:
        try:
            if await _renew_one(ctx, sub_id, now):
                charged += 1
        except Exception:  # noqa: BLE001 — one subscription's failure must not stop (or undo) the others
            logger.exception("billing.renewal.failed", extra={"subscription": sub_id})
    return charged


async def _renew_one(ctx: BillingContext, sub_id: str, now: datetime) -> bool:
    prepared = await _prepare_charge(ctx, sub_id, now)
    if prepared is None:
        return False
    sub, payment, plan = prepared
    provider = ctx.providers[sub.provider.value]
    try:
        provider_payment_id = await provider.charge_renewal(
            provider_subscription_id=sub.provider_subscription_id or "", amount_kopecks=plan.price_kopecks,
            idempotency_key=payment.idempotency_key,
        )
    except ProviderUnavailable as e:
        await _charge_outcome_unknown(ctx, sub, payment, e)
        return False
    except ProviderError as e:
        await _charge_refused(ctx, sub, payment, e)
        return False
    except Exception as e:  # noqa: BLE001 — an adapter bug: we cannot know whether money moved
        logger.exception("billing.renewal.provider_crashed", extra={"subscription": sub.id})
        await _charge_outcome_unknown(ctx, sub, payment, e)
        return False
    async with ctx.store.transaction() as tx:
        current = await tx.get_payment(payment.id)
        if current is not None and not current.provider_payment_id:
            await tx.update_payment(replace(current, provider_payment_id=provider_payment_id))
    return True


async def _prepare_charge(ctx: BillingContext, sub_id: str, now: datetime) -> Optional[Tuple[Subscription, Payment, Plan]]:
    """Step 1: the payment row and `charge_pending`, committed together before any call."""
    async with ctx.store.transaction() as tx:
        sub = await tx.get_subscription(sub_id, for_update=True)
        if sub is None or sub.status not in (SubscriptionStatus.ACTIVE, SubscriptionStatus.GRACE):
            return None
        transition = apply(sub_state(sub), RenewalDue(), now, ctx.policy())
        charge = next((e for e in transition.effects if isinstance(e, Charge)), None)
        if charge is None:
            return None
        # The price the subscriber agreed to: their plan version, never today's catalogue.
        plan = await tx.get_plan(sub.plan_code.value, sub.plan_version)
        if plan is None:
            await tx.add_audit(actor=_ACTOR, action="charge.plan_missing", target=sub_target(sub.id),
                               meta={"plan": sub.plan_code.value, "version": sub.plan_version})
            return None
        fresh = Payment(
            id=str(uuid.uuid4()), subscription_id=sub.id, provider=sub.provider, idempotency_key=charge.idempotency_key,
            amount_kopecks=plan.price_kopecks, status=PaymentStatus.PENDING, created_at=now,
            period_start=charge.period_start,
        )
        payment = await tx.create_payment(fresh)
        if payment.id != fresh.id:
            # A row under this key exists although the machine has no charge in flight: never call
            # the provider again for it; a person reconciles (the row says what happened).
            logger.error("billing.renewal.key_already_used", extra={"subscription": sub.id, "status": payment.status.value})
            await tx.add_audit(actor=_ACTOR, action="charge.already_settled", target=sub_target(sub.id),
                               meta={"key": charge.idempotency_key, "status": payment.status.value})
            return None
        updated = await tx.update_subscription(with_state(sub, transition.state), expected_version=sub.row_version)
        await run_effects(ctx, tx, updated, transition.effects, actor=_ACTOR)
    return updated, payment, plan


async def _charge_outcome_unknown(ctx: BillingContext, sub: Subscription, payment: Payment, error: Exception) -> None:
    """No answer: the charge may have happened. The row stays pending and `charge_pending` stays set,
    so nothing charges this period again; the reconciler asks by our merchant payment id."""
    logger.warning("billing.renewal.outcome_unknown", extra={"subscription": sub.id, "error": type(error).__name__})
    async with ctx.store.transaction() as tx:
        await tx.add_audit(actor=_ACTOR, action="charge.provider_error", target=sub_target(sub.id),
                           meta={"error": type(error).__name__, "key": payment.idempotency_key, "outcome": "unknown"})


async def _charge_refused(ctx: BillingContext, sub: Subscription, payment: Payment, error: Exception) -> None:
    """The provider answered and refused: a failed attempt (grace, retries), never a stuck one.
    Should the money turn out to have been taken after all, the success still settles the row."""
    logger.warning("billing.renewal.refused", extra={"subscription": sub.id, "error": str(error)[:120]})
    async with ctx.store.transaction() as tx:
        current = await tx.get_payment(payment.id)
        if current is None or current.status is not PaymentStatus.PENDING:
            return   # a notification settled it meanwhile
        await tx.update_payment(replace(current, status=PaymentStatus.FAILED, failure_reason=FailureReason.OTHER))
        await tx.add_audit(actor=_ACTOR, action="charge.provider_error", target=sub_target(sub.id),
                           meta={"error": type(error).__name__, "key": payment.idempotency_key, "outcome": "refused"})
        locked = await tx.get_subscription(sub.id, for_update=True)
        if locked is None or not locked.charge_pending:
            return
        transition = apply(sub_state(locked), PaymentFailed(FailureReason.OTHER), ctx.now(), ctx.policy())
        updated = await tx.update_subscription(with_state(locked, transition.state), expected_version=locked.row_version)
        await run_effects(ctx, tx, updated, transition.effects, actor=_ACTOR)


async def run_expiries(ctx: BillingContext, now: Optional[datetime] = None) -> int:
    """Grace ran out → lapsed; a cancelled period ended → lapsed; a promo / partner grant's term ended → lapsed."""
    now = now or ctx.now()
    lapsed = 0
    async with ctx.store.transaction() as tx:
        for sub in await tx.list_expiring(now=now):
            if sub.status is SubscriptionStatus.GRACE:
                event = GraceExpired()
            elif sub.status is SubscriptionStatus.CANCEL_AT_PERIOD_END:
                event = PeriodEnded()
            elif sub.provider.value in _GRANT_PROVIDERS:
                event = TermEnded()
            else:
                continue
            transition = apply(sub_state(sub), event, now, ctx.policy())
            if transition.state.status is sub.status:
                continue
            updated = await tx.update_subscription(with_state(sub, transition.state), expected_version=sub.row_version)
            await run_effects(ctx, tx, updated, transition.effects, actor=_ACTOR)
            lapsed += 1
    return lapsed


async def run_reconciliation(ctx: BillingContext, now: Optional[datetime] = None) -> int:
    """Payments pending for 30+ minutes: ask the provider (a lost webhook must not mean 'paid but no access')."""
    now = now or ctx.now()
    cutoff = now - timedelta(minutes=RECONCILE_AFTER_MINUTES)
    settled = 0
    async with ctx.store.transaction() as tx:
        pending = list(await tx.list_pending_payments_older_than(cutoff=cutoff))
    for payment in pending:
        found = await _reconcile_one(ctx, payment)
        if found == _SETTLED:
            settled += 1
        elif now - payment.created_at >= UNRESOLVED_ALERT_AFTER:
            logger.error("billing.payment.unresolved", extra={
                "subscription": payment.subscription_id, "payment": payment.id, "found": found,
                "age_hours": int((now - payment.created_at).total_seconds() // 3600),
            })
    return settled


# What asking the provider about one payment found out.
_SETTLED = "settled"          # the provider's answer was applied
_IN_PROGRESS = "in_progress"  # the provider says the payment is still under way
_PENDING = "pending"          # no final answer (or nothing to ask about, or the answer was not applied)
_UNKNOWN = "unknown"          # the provider could not be asked right now


async def _reconcile_one(ctx: BillingContext, payment: Payment) -> str:
    """Ask the provider about one of our payments — outside any transaction — and apply the answer.

    The question names the provider's reference when we have one, and always
    our own key (merchant_payment_id), so a call whose answer was lost (no
    reference ever recorded) is still found.
    """
    provider = ctx.providers.get(payment.provider.value)
    if provider is None:
        return _PENDING
    async with ctx.store.transaction() as tx:
        sub = await tx.get_subscription(payment.subscription_id)
    if sub is None:
        return _PENDING
    ref = payment.provider_payment_id or (sub.provider_subscription_id if payment.idempotency_key == checkout_key(sub.id) else None)
    try:
        event = await provider.fetch_status(provider_ref=ref, merchant_payment_id=payment.idempotency_key)
    except ProviderError as e:
        async with ctx.store.transaction() as tx:
            await tx.add_audit(actor=_ACTOR, action="reconcile.provider_error", target=sub_target(sub.id),
                               meta={"error": type(e).__name__})
        return _UNKNOWN
    if event is None:
        return _PENDING
    if event.kind is EventKind.PAYMENT_PENDING:
        return _IN_PROGRESS
    event = replace(event, merchant_payment_id=event.merchant_payment_id or payment.idempotency_key)
    async with ctx.store.transaction() as tx:
        event_id = await tx.insert_event(provider=event.provider, provider_event_id=f"reconcile:{event.provider_event_id}",
                                         signature_ok=True, payload_ciphertext=ctx.cipher.encrypt_bytes(b"reconciliation"))
        if event_id is None:
            return _PENDING
        _, outcome = await apply_provider_event(ctx, tx, event, actor=_ACTOR)
        await tx.mark_event_processed(event_id, processed_at=ctx.now(), outcome=outcome)
    return _SETTLED if outcome in ("applied", "deleted") else _PENDING


async def run_unmatched_events(ctx: BillingContext, now: Optional[datetime] = None) -> int:
    """Verified webhooks that matched no subscription when they arrived: try them again.

    One reaches us before the reference it names is recorded (its checkout's
    provider answer was still being committed), or names a payment a person
    must look at. Each is retried for UNMATCHED_MAX_ATTEMPTS passes, then
    marked `unmatched_abandoned` with an error-level log (Sentry).
    """
    now = now or ctx.now()
    async with ctx.store.transaction() as tx:
        rows = list(await tx.list_retryable_events())
    applied = 0
    for row in rows:
        event = event_from_bytes(ctx.cipher.decrypt_bytes(row.event_ciphertext))
        async with ctx.store.transaction() as tx:
            _, outcome = await apply_provider_event(ctx, tx, event, actor=f"provider:{row.provider.value}")
            if outcome == "unmatched" and row.attempts + 1 >= UNMATCHED_MAX_ATTEMPTS:
                outcome = "unmatched_abandoned"
            await tx.retry_event(row.id, processed_at=ctx.now(), outcome=outcome)
        if outcome == "unmatched_abandoned":
            logger.error("billing.webhook.unmatched_abandoned", extra={
                "provider": row.provider.value, "event": row.provider_event_id, "attempts": row.attempts + 1,
            })
        elif outcome != "unmatched":
            applied += 1
    return applied


async def run_once(ctx: BillingContext, now: Optional[datetime] = None) -> Dict[str, int]:
    """One scheduler pass. Order matters: unmatched events and reconciliation first (a lost or
    early webhook must not let the timeout delete a paid checkout), then timeouts, charges, expiries."""
    now = now or ctx.now()
    unmatched = await run_unmatched_events(ctx, now)
    reconciled = await run_reconciliation(ctx, now)
    counts = {
        "pending_timeouts": await run_pending_timeouts(ctx, now),
        "renewals": await run_renewals(ctx, now),
        "expiries": await run_expiries(ctx, now),
        "reconciled": reconciled,
        "unmatched_applied": unmatched,
    }
    logger.info("billing.scheduler.pass", extra=counts)
    return counts


def main() -> int:  # pragma: no cover — ops entry point, exercised by hand
    from api.billing.bootstrap import build_runtime_context

    async def _run() -> Dict[str, int]:
        ctx = await build_runtime_context()
        try:
            return await run_once(ctx)
        finally:
            await ctx.store.close()

    print(asyncio.run(_run()))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

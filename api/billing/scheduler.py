"""Renewals, timeouts, expiries and reconciliation (plan A.8).

NOTHING here is wired to a cron or a startup hook. `run_once()` is what a
scheduled job (every 15 minutes) will call once the founder switches
billing on; until then it is exercised by tests only.

    python -m api.billing.scheduler        # one pass, prints the counts

Idempotency: a renewal's payment row is keyed `{sub}:{period_start}:{attempt}`
(state_machine.idempotency_key), so a pass that runs twice, or a pod that
dies mid-run, can never charge twice.
"""
from __future__ import annotations

import asyncio
import logging
import sys
import uuid
from dataclasses import replace
from datetime import datetime, timedelta
from typing import Dict, Optional

from api.billing.context import BillingContext
from api.billing.models import Payment, PaymentStatus, Subscription, SubscriptionStatus
from api.billing.providers.base import ProviderError
from api.billing.service.checkout import apply_provider_event, checkout_key, close_checkout
from api.billing.service.common import sub_state, sub_target, with_state
from api.billing.service.effects import run_effects
from api.billing.state_machine import (
    Charge,
    GraceExpired,
    PendingTimeout,
    PeriodEnded,
    RenewalDue,
    apply,
)

logger = logging.getLogger("cleanway.billing.scheduler")

RECONCILE_AFTER_MINUTES = 30
_ACTOR = "system"


async def run_pending_timeouts(ctx: BillingContext, now: Optional[datetime] = None) -> int:
    """Checkouts nobody confirmed: gone after `billing_pending_timeout_minutes`.

    Deleting a checkout cascades to its payment row, so the provider is asked
    first: a payment that went through while its webhook was lost is applied,
    not thrown away, and a checkout whose status the provider cannot report
    right now waits for the next pass.
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
            if await _reconcile_one(ctx, payment) in (_SETTLED, _UNKNOWN):
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
    """Charge every due subscription whose provider lets us initiate."""
    now = now or ctx.now()
    charged = 0
    async with ctx.store.transaction() as tx:
        for sub in await tx.list_due_renewals(now=now):
            provider = ctx.providers.get(sub.provider.value)
            if provider is None or not provider.initiates_renewals:
                continue
            if await _charge(ctx, tx, sub, provider, now):
                charged += 1
    return charged


async def _charge(ctx: BillingContext, tx, sub: Subscription, provider, now: datetime) -> bool:
    transition = apply(sub_state(sub), RenewalDue(), now, ctx.policy())
    charge = next((e for e in transition.effects if isinstance(e, Charge)), None)
    if charge is None:
        return False
    plan = ctx.plan(sub.plan_code)
    payment = await tx.create_payment(Payment(
        id=str(uuid.uuid4()), subscription_id=sub.id, provider=sub.provider, idempotency_key=charge.idempotency_key,
        amount_kopecks=plan.price_kopecks, status=PaymentStatus.PENDING, created_at=now, period_start=charge.period_start,
    ))
    if payment.status is not PaymentStatus.PENDING:
        # The row exists from an earlier attempt that already answered; the machine will see its event.
        await tx.add_audit(actor=_ACTOR, action="charge.already_settled", target=sub_target(sub.id),
                           meta={"key": charge.idempotency_key})
        return False
    try:
        provider_payment_id = await provider.charge_renewal(
            provider_subscription_id=sub.provider_subscription_id or "", amount_kopecks=plan.price_kopecks,
            idempotency_key=charge.idempotency_key,
        )
    except ProviderError as e:
        # Nothing was charged as far as we know; the row stays pending for reconciliation.
        await tx.add_audit(actor=_ACTOR, action="charge.provider_error", target=sub_target(sub.id),
                           meta={"error": type(e).__name__, "key": charge.idempotency_key})
        return False
    await tx.update_payment(replace(payment, provider_payment_id=provider_payment_id))
    updated = await tx.update_subscription(with_state(sub, transition.state), expected_version=sub.row_version)
    await run_effects(ctx, tx, updated, transition.effects, actor=_ACTOR)
    return True


async def run_expiries(ctx: BillingContext, now: Optional[datetime] = None) -> int:
    """Grace periods that ran out → lapsed; cancelled periods that ended → lapsed."""
    now = now or ctx.now()
    lapsed = 0
    async with ctx.store.transaction() as tx:
        for sub in await tx.list_expiring(now=now):
            event = GraceExpired() if sub.status is SubscriptionStatus.GRACE else PeriodEnded()
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
        if await _reconcile_one(ctx, payment) == _SETTLED:
            settled += 1
    return settled


# What asking the provider about one payment found out.
_SETTLED = "settled"    # the provider's answer was applied
_PENDING = "pending"    # no final answer yet (or nothing to ask about)
_UNKNOWN = "unknown"    # the provider could not be asked right now


async def _reconcile_one(ctx: BillingContext, payment: Payment) -> str:
    provider = ctx.providers.get(payment.provider.value)
    if provider is None:
        return _PENDING
    async with ctx.store.transaction() as tx:
        sub = await tx.get_subscription(payment.subscription_id)
        if sub is None:
            return _PENDING
        ref = payment.provider_payment_id or (sub.provider_subscription_id if payment.idempotency_key == checkout_key(sub.id) else None)
        if not ref:
            return _PENDING
        try:
            event = await provider.fetch_status(provider_ref=ref)
        except ProviderError as e:
            await tx.add_audit(actor=_ACTOR, action="reconcile.provider_error", target=sub_target(sub.id),
                               meta={"error": type(e).__name__})
            return _UNKNOWN
        if event is None or event.kind.value == "payment_pending":
            return _PENDING
        event_id = await tx.insert_event(provider=event.provider, provider_event_id=f"reconcile:{event.provider_event_id}",
                                         signature_ok=True, payload_ciphertext=ctx.cipher.encrypt_bytes(b"reconciliation"))
        if event_id is None:
            return _PENDING
        _, outcome = await apply_provider_event(ctx, tx, event, actor=_ACTOR)
        await tx.mark_event_processed(event_id, processed_at=ctx.now(), outcome=outcome)
        return _SETTLED if outcome in ("applied", "deleted") else _PENDING


async def run_once(ctx: BillingContext, now: Optional[datetime] = None) -> Dict[str, int]:
    """One scheduler pass. Order matters: reconciliation first (a lost webhook must not
    let the timeout delete a paid checkout), then timeouts, charges and expiries."""
    now = now or ctx.now()
    reconciled = await run_reconciliation(ctx, now)
    counts = {
        "pending_timeouts": await run_pending_timeouts(ctx, now),
        "renewals": await run_renewals(ctx, now),
        "expiries": await run_expiries(ctx, now),
        "reconciled": reconciled,
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

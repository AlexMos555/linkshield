"""Checkout (purchase intent) and applying what the provider says happened."""
from __future__ import annotations

import uuid
from dataclasses import replace
from typing import Any, Dict, Optional, Tuple

from api.billing.consents import UnknownConsentVersion, require_current
from api.billing.context import BillingContext
from api.billing.crypto import InvalidMsisdn, normalize_msisdn
from api.billing.models import (
    CancelChannel,
    Device,
    FailureReason,
    Payment,
    PaymentStatus,
    Plan,
    PlanCode,
    ProviderCode,
    Seat,
    SeatRole,
    Subscription,
    SubscriptionStatus,
)
from api.billing.providers.base import (
    BillingEvent,
    EventKind,
    NotConfiguredError,
    ProviderError,
    ProviderUnavailable,
)
from api.billing.providers.promo import granted_event
from api.billing.providers.registry import checkout_providers
from api.billing.service.common import device_actor, is_live, live_subscription_for_device, sub_state, sub_target, with_state
from api.billing.service.effects import ConsentInfo, run_effects
from api.billing.service.errors import Conflict, Invalid, NotConfigured, NotFound
from api.billing.state_machine import (
    CancelRequested,
    CheckoutStarted,
    InvalidTransition,
    Notify,
    OperatorStop,
    PaymentFailed,
    PaymentSucceeded,
    Refunded,
    SubState,
    apply,
)

_GRANT_PROVIDERS = ("promo", "t2_option")


def checkout_key(sub_id: str) -> str:
    return f"{sub_id}:checkout"


def _plan(ctx: BillingContext, plan_code: str) -> Plan:
    try:
        return ctx.plan(PlanCode(plan_code))
    except ValueError as e:
        raise Invalid("unknown plan", code="unknown_plan") from e


def _msisdn(raw: Optional[str], *, required: bool) -> Optional[str]:
    if not raw:
        if required:
            raise Invalid("phone number required", code="phone_required")
        return None
    try:
        return normalize_msisdn(raw)
    except InvalidMsisdn as e:
        raise Invalid(str(e), code="phone_invalid") from e


async def start_checkout(ctx: BillingContext, device: Device, *, plan_code: str, provider_code: str,
                         msisdn: Optional[str], consent_doc_version: str, consent_method: str = "app_button",
                         ip: Optional[str] = None, allow_grant: bool = False) -> Dict[str, Any]:
    """Create the pending subscription, record the consent, ask the provider to start.

    The owner seat is claimed now so a device can never sit in two checkouts.
    A promo grant activates immediately; anything else waits for the
    provider's notification (or reconciliation).
    """
    plan = _plan(ctx, plan_code)
    provider = ctx.providers.get(provider_code)
    allowed = checkout_providers(ctx.providers) + (_GRANT_PROVIDERS if allow_grant else ())
    if provider is None or provider_code not in allowed:
        raise Invalid("payment provider not available", code="provider_unavailable")
    try:
        doc = require_current(consent_doc_version, ctx.settings.billing_consent_doc_version)
    except UnknownConsentVersion as e:
        raise Invalid("the consent text shown is not current", code="consent_version_stale") from e
    number = _msisdn(msisdn, required=provider_code not in _GRANT_PROVIDERS)
    now = ctx.now()
    sub_id = str(uuid.uuid4())
    async with ctx.store.transaction() as tx:
        if await live_subscription_for_device(tx, device.id) is not None:
            raise Conflict("this phone already has a subscription", code="already_subscribed")
        await _close_restarted_checkouts(ctx, tx, device, now)
        await _drop_stale_seat(tx, device.id, now)
        transition = apply(SubState(sub_id, None), CheckoutStarted(plan.code, consent_method), now, ctx.policy())
        sub = await tx.create_subscription(Subscription(
            id=sub_id, payer_account_id=device.account_id, plan_code=plan.code, plan_version=plan.version,
            provider=ProviderCode(provider_code), status=SubscriptionStatus.PENDING, created_at=now, updated_at=now,
            msisdn_ciphertext=ctx.cipher.encrypt(number) if number else None,
            msisdn_hmac=ctx.hasher.msisdn(number) if number else None,
        ))
        await tx.add_seat(Seat(subscription_id=sub.id, device_id=device.id, role=SeatRole.OWNER, claimed_at=now))
        consent = ConsentInfo(doc=doc, plan=plan, ip_hmac=ctx.hasher.ip(ip) if ip else None)
        await run_effects(ctx, tx, sub, transition.effects, actor=device_actor(device), consent=consent)
        start = await _provider_start(provider, provider_code, plan, number, sub)
        sub = await tx.update_subscription(replace(sub, provider_subscription_id=start.provider_ref),
                                           expected_version=sub.row_version)
        await tx.create_payment(Payment(
            id=str(uuid.uuid4()), subscription_id=sub.id, provider=sub.provider, idempotency_key=checkout_key(sub.id),
            amount_kopecks=plan.price_kopecks if provider_code not in _GRANT_PROVIDERS else 0,
            status=PaymentStatus.PENDING, created_at=now,
        ))
        if start.kind == "granted":
            sub, _ = await apply_provider_event(ctx, tx, granted_event(start.provider_ref), actor="system")
    return {"checkout_id": sub.id, "kind": start.kind, "url": start.url, "sdk_params": start.sdk_params,
            "status": sub.status.value, "provider": provider_code}


async def _provider_start(provider, provider_code: str, plan: Plan, number: Optional[str], sub: Subscription):
    try:
        return await provider.start_checkout(
            plan_product_id=plan.provider_product_ids.get(provider_code, plan.code.value),
            amount_kopecks=plan.price_kopecks, msisdn=number, idempotency_key=checkout_key(sub.id),
            return_url="",
        )
    except NotConfiguredError as e:
        raise NotConfigured(str(e)) from e
    except (ProviderUnavailable, ProviderError) as e:
        raise NotConfigured("payment provider unavailable, try again", code="provider_error") from e


async def _close_restarted_checkouts(ctx: BillingContext, tx, device: Device, now) -> None:
    """A new checkout replaces this account's unconfirmed one (a mistyped number is fixed by
    starting over, not by waiting 30 minutes); the old one is closed as declined."""
    for old in await tx.list_subscriptions_for_account(device.account_id):
        if old.status is not SubscriptionStatus.PENDING:
            continue
        transition = apply(sub_state(old), CancelRequested(CancelChannel.APP), now, ctx.policy())
        await run_effects(ctx, tx, old, transition.effects, actor=device_actor(device))
        await close_checkout(tx, old, transition.effects, actor=device_actor(device))


async def _drop_stale_seat(tx, device_id: str, now) -> None:
    """A seat on a subscription that is no longer live is history; release it."""
    seat = await tx.get_active_seat_for_device(device_id)
    if seat is None:
        return
    sub = await tx.get_subscription(seat.subscription_id)
    if sub is None or not is_live(sub):
        await tx.release_seat(seat.subscription_id, device_id, released_at=now)


async def get_checkout(ctx: BillingContext, device: Device, checkout_id: str) -> Dict[str, Any]:
    """Poll while the SMS is on its way (§2.5 screen 6).

    A failed checkout row is deleted (there never was a subscription), but
    the app still needs the reason for screen 8: it comes from the closing
    audit row, which names the payer account so only they can read it.
    """
    if not _is_uuid(checkout_id):
        raise NotFound("checkout not found")
    async with ctx.store.transaction() as tx:
        sub = await tx.get_subscription(checkout_id)
        if sub is None:
            return _closed_checkout(await tx.list_audit(sub_target(checkout_id)), device, checkout_id)
        if sub.payer_account_id != device.account_id:
            raise NotFound("checkout not found")
        payment = await tx.get_payment_by_idempotency_key(checkout_key(sub.id))
    return {
        "checkout_id": sub.id, "status": sub.status.value, "plan": sub.plan_code.value,
        "failure_reason": payment.failure_reason.value if payment and payment.failure_reason else None,
        "period_end": int(sub.current_period_end.timestamp()) if sub.current_period_end else None,
    }


def _closed_checkout(audit_rows, device: Device, checkout_id: str) -> Dict[str, Any]:
    closed = next((a for a in audit_rows if a.action == "checkout.closed"), None)
    if closed is None or closed.meta.get("account") != device.account_id:
        raise NotFound("checkout not found")
    return {"checkout_id": checkout_id, "status": "failed", "plan": closed.meta.get("plan"),
            "failure_reason": closed.meta.get("reason"), "period_end": None}


async def close_checkout(tx, sub: Subscription, effects, *, actor: str) -> None:
    """Delete a checkout that will never be paid, leaving the reason for its owner."""
    notice = next((e for e in effects if isinstance(e, Notify) and e.kind == "checkout_failed"), None)
    reason = notice.reason.value if notice and notice.reason else FailureReason.OTHER.value
    await tx.add_audit(actor=actor, action="checkout.closed", target=sub_target(sub.id),
                       meta={"account": sub.payer_account_id, "reason": reason, "plan": sub.plan_code.value})
    await tx.delete_subscription(sub.id)


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
        return True
    except (ValueError, AttributeError, TypeError):
        return False


# ── Provider events → state machine ──


async def _resolve(tx, event: BillingEvent) -> Tuple[Optional[Subscription], Optional[Payment]]:
    """Which subscription (and which payment row) a provider event is about."""
    payment = None
    if event.provider_payment_id:
        payment = await tx.get_payment_by_provider_id(event.provider, event.provider_payment_id)
    if payment is None and event.merchant_payment_id:
        payment = await tx.get_payment_by_idempotency_key(event.merchant_payment_id)
    if payment is not None:
        return await tx.get_subscription(payment.subscription_id, for_update=True), payment
    for ref in (event.provider_subscription_id, event.provider_payment_id):
        if ref:
            sub = await tx.get_subscription_by_provider_ref(event.provider, ref)
            if sub is not None:
                sub = await tx.get_subscription(sub.id, for_update=True)
                return sub, await tx.get_payment_by_idempotency_key(checkout_key(sub.id)) if sub else None
    return None, None


def _machine_event(event: BillingEvent, payment: Optional[Payment], external: bool):
    payment_id = event.provider_payment_id or (payment.id if payment else "unknown")
    if event.kind is EventKind.PAYMENT_SUCCEEDED:
        return PaymentSucceeded(payment_id=payment_id, amount_kopecks=event.amount_kopecks or 0, external=external)
    if event.kind is EventKind.PAYMENT_FAILED:
        return PaymentFailed(event.failure or FailureReason.OTHER)
    if event.kind is EventKind.SUBSCRIPTION_CANCELLED:
        return OperatorStop()
    if event.kind is EventKind.REFUNDED:
        return Refunded(payment_id=payment_id)
    return None


async def apply_provider_event(ctx: BillingContext, tx, event: BillingEvent, *, actor: str) -> Tuple[Optional[Subscription], str]:
    """Apply one provider notification. Returns (subscription or None, outcome word)."""
    sub, payment = await _resolve(tx, event)
    if sub is None:
        return None, "unmatched"
    if event.test and not ctx.settings.billing_mixplat_test:
        await tx.add_audit(actor=actor, action="event.test_ignored", target=sub_target(sub.id), meta={"kind": event.kind.value})
        return sub, "ignored_test_event"
    if payment is not None and event.kind is not EventKind.SUBSCRIPTION_CANCELLED:
        payment = await _record_payment(tx, payment, event, sub)
    if event.kind is EventKind.PAYMENT_PENDING:
        return sub, "pending"
    provider = ctx.providers.get(event.provider)
    machine_event = _machine_event(event, payment, external=provider is not None and not provider.initiates_renewals)
    try:
        transition = apply(sub_state(sub), machine_event, ctx.now(), ctx.policy())
    except InvalidTransition as e:
        await tx.add_audit(actor=actor, action="event.ignored", target=sub_target(sub.id),
                           meta={"kind": event.kind.value, "status": sub.status.value, "why": str(e)})
        return sub, "invalid_in_status"
    if transition.state.status is None:
        await run_effects(ctx, tx, sub, transition.effects, actor=actor)
        await close_checkout(tx, sub, transition.effects, actor=actor)
        return None, "deleted"
    updated = with_state(sub, transition.state)
    if event.provider_subscription_id and event.provider_subscription_id != sub.provider_subscription_id:
        updated = replace(updated, provider_subscription_id=event.provider_subscription_id)
    updated = await tx.update_subscription(updated, expected_version=sub.row_version)
    await run_effects(ctx, tx, updated, transition.effects, actor=actor)
    return updated, "applied"


async def _record_payment(tx, payment: Payment, event: BillingEvent, sub: Subscription) -> Payment:
    status = {
        EventKind.PAYMENT_SUCCEEDED: PaymentStatus.SUCCEEDED, EventKind.PAYMENT_FAILED: PaymentStatus.FAILED,
        EventKind.REFUNDED: PaymentStatus.REFUNDED, EventKind.PAYMENT_PENDING: PaymentStatus.PENDING,
    }[event.kind]
    updated = replace(
        payment, status=status, provider_payment_id=event.provider_payment_id or payment.provider_payment_id,
        failure_reason=event.failure if status is PaymentStatus.FAILED else None,
        amount_kopecks=event.amount_kopecks if event.amount_kopecks is not None else payment.amount_kopecks,
    )
    await tx.update_payment(updated)
    return updated

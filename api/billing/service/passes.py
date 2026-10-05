"""What a device is entitled to right now, and the signed pass that says so.

Precedence: a live subscription seat → legacy free → an unexpired trial →
the lapse policy. The pass carries no personal data (plan A.5); the status
dict next to it is what the app's screens need.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from api.billing.context import BillingContext
from api.billing.entitlement import PassClaims
from api.billing.models import (
    Device,
    EntitlementSource,
    LapsePolicy,
    Plan,
    ProtectionMode,
    ProviderCode,
    Subscription,
    SubscriptionStatus,
    Trial,
)
from api.billing.service.common import live_subscription_for_device

_GRANT_PROVIDERS = (ProviderCode.PROMO, ProviderCode.T2_OPTION)


@dataclass(frozen=True)
class Entitlement:
    claims: PassClaims
    token: str
    status: Dict[str, Any]


def _epoch(dt: Optional[datetime]) -> Optional[int]:
    return None if dt is None else int(dt.timestamp())


def _from_subscription(sub: Subscription, now: datetime, ctx: BillingContext) -> Tuple[ProtectionMode, EntitlementSource,
                                                                                      Optional[int], Optional[int]]:
    src = EntitlementSource.PROMO if sub.provider in _GRANT_PROVIDERS else EntitlementSource.SUBSCRIPTION
    until = _epoch(sub.current_period_end)
    if sub.status is SubscriptionStatus.CANCEL_AT_PERIOD_END:
        return ProtectionMode.FULL, src, until, None
    grace_end = sub.grace_until or (
        sub.current_period_end + timedelta(days=ctx.settings.billing_grace_days) if sub.current_period_end else None
    )
    return ProtectionMode.FULL, src, until, _epoch(grace_end)


async def compute_entitlement(ctx: BillingContext, device: Device) -> Entitlement:
    now = ctx.now()
    policy = LapsePolicy(ctx.settings.billing_lapse_policy)
    async with ctx.store.transaction() as tx:
        sub = await live_subscription_for_device(tx, device.id)
        trial = await tx.get_trial_for_device(device.id)
        seat_count = len(await tx.list_seats(sub.id)) if sub else 0
        payer = sub is not None and sub.payer_account_id == device.account_id
        # The version the subscriber signed up for (its price), not today's catalogue.
        sub_plan = (await tx.get_plan(sub.plan_code.value, sub.plan_version) or ctx.plan(sub.plan_code)) if sub else None
    mode, src, until, grace_until, plan = _decide(ctx, device, sub, trial, now, policy)
    iat = int(now.timestamp())
    claims = PassClaims(
        dev=device.id, mode=mode, src=src, lapse_policy=policy, iat=iat,
        exp=iat + ctx.settings.billing_pass_ttl_days * 86400, plan=plan, until=until, grace_until=grace_until,
    )
    status = _status(sub, sub_plan, trial, now, claims, seat_count, payer)
    return Entitlement(claims=claims, token=ctx.signer.sign(claims), status=status)


def _decide(ctx: BillingContext, device: Device, sub: Optional[Subscription], trial: Optional[Trial],
            now: datetime, policy: LapsePolicy):
    if sub is not None:
        mode, src, until, grace_until = _from_subscription(sub, now, ctx)
        return mode, src, until, grace_until, sub.plan_code.value
    if device.legacy_free:
        return ProtectionMode.FULL, EntitlementSource.LEGACY, None, None, None
    if trial is not None and now < trial.ends_at:
        return ProtectionMode.FULL, EntitlementSource.TRIAL, _epoch(trial.ends_at), None, None
    return policy.mode, EntitlementSource.NONE, None, None, None


def _status(sub: Optional[Subscription], plan: Optional[Plan], trial: Optional[Trial], now: datetime,
            claims: PassClaims, seat_count: int, payer: bool) -> Dict[str, Any]:
    status: Dict[str, Any] = {
        "mode": claims.mode.value, "source": claims.src.value, "plan": claims.plan,
        "lapse_policy": claims.lapse_policy.value, "until": claims.until, "grace_until": claims.grace_until,
        "trial_ends_at": _epoch(trial.ends_at) if trial else None,
        "trial_used": trial is not None,
        "subscription": None, "notices": [],
    }
    if sub is not None and plan is not None:
        status["subscription"] = {
            "id": sub.id, "status": sub.status.value, "plan": sub.plan_code.value, "seats_total": plan.seats,
            "seats_used": seat_count, "price_kopecks": plan.price_kopecks, "period_end": _epoch(sub.current_period_end),
            "next_charge_at": _epoch(sub.next_charge_at), "grace_until": _epoch(sub.grace_until),
            "cancel_requested_at": _epoch(sub.cancel_requested_at), "is_payer": payer, "provider": sub.provider.value,
        }
    status["notices"] = _notices(sub, trial, now, claims)
    return status


def _notices(sub: Optional[Subscription], trial: Optional[Trial], now: datetime, claims: PassClaims) -> list:
    """Short machine words the app turns into cards (§2.5): trial ending, grace, lapsed."""
    notices = []
    if claims.src is EntitlementSource.TRIAL and trial is not None:
        days_left = (trial.ends_at - now).days
        if days_left <= 3:
            notices.append("trial_ending")
    if sub is not None and sub.status is SubscriptionStatus.GRACE:
        notices.append("payment_failed_grace")
    if sub is not None and sub.status is SubscriptionStatus.CANCEL_AT_PERIOD_END:
        notices.append("cancelled_until_period_end")
    if claims.src is EntitlementSource.NONE:
        notices.append("basic_mode" if claims.mode is ProtectionMode.BASIC else "protection_off")
    return notices

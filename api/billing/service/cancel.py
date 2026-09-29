"""Cancel (§2.6): one tap in the app, or a phone number on the website. 376-ФЗ:
after a cancel not one more kopeck is charged."""
from __future__ import annotations

from typing import Any, Dict, Optional

from api.billing.context import BillingContext
from api.billing.crypto import InvalidMsisdn, normalize_msisdn
from api.billing.models import CancelChannel, Device, Subscription
from api.billing.service.common import device_actor, is_live, live_subscription_for_device, sub_state, with_state
from api.billing.service.effects import run_effects
from api.billing.service.errors import Forbidden, Invalid, NotFound
from api.billing.state_machine import CancelRequested, apply


async def _cancel(ctx: BillingContext, tx, sub: Subscription, channel: CancelChannel, actor: str) -> Subscription:
    locked = await tx.get_subscription(sub.id, for_update=True)
    transition = apply(sub_state(locked), CancelRequested(channel), ctx.now(), ctx.policy())
    if not transition.effects:
        return locked  # already cancelled — idempotent
    updated = await tx.update_subscription(with_state(locked, transition.state), expected_version=locked.row_version)
    await run_effects(ctx, tx, updated, transition.effects, actor=actor)
    return updated


async def cancel_subscription(ctx: BillingContext, device: Device, *, channel: CancelChannel = CancelChannel.APP) -> Dict[str, Any]:
    async with ctx.store.transaction() as tx:
        sub = await live_subscription_for_device(tx, device.id)
        if sub is None:
            raise NotFound("no subscription on this phone", code="no_subscription")
        if sub.payer_account_id != device.account_id:
            raise Forbidden("only the payer can cancel", code="not_owner")
        updated = await _cancel(ctx, tx, sub, channel, device_actor(device))
    return {"status": updated.status.value,
            "period_end": int(updated.current_period_end.timestamp()) if updated.current_period_end else None,
            "cancel_requested_at": int(updated.cancel_requested_at.timestamp()) if updated.cancel_requested_at else None}


async def cancel_by_phone(ctx: BillingContext, *, msisdn: str, ip: Optional[str]) -> None:
    """The website form. Always the same answer, whether or not the number has a subscription."""
    try:
        number = normalize_msisdn(msisdn)
    except InvalidMsisdn as e:
        raise Invalid(str(e), code="phone_invalid") from e
    digest = ctx.hasher.msisdn(number)
    async with ctx.store.transaction() as tx:
        subs = [s for s in await tx.list_subscriptions_by_msisdn_hmac(digest) if is_live(s)]
        for sub in subs:
            await _cancel(ctx, tx, sub, CancelChannel.WEB, "web")
        await tx.add_audit(actor="web", action="cancel_by_phone.requested", target=f"msisdn:{digest[:16]}",
                           meta={"ip_hmac": ctx.hasher.ip(ip) if ip else None, "cancelled": len(subs)})

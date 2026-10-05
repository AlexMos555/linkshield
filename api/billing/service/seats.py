"""Seats and claim codes (§2.4): the payer adds relatives with a 6-digit code."""
from __future__ import annotations

import uuid
from dataclasses import replace
from datetime import timedelta
from typing import Any, Dict

from api.billing.context import BillingContext
from api.billing.crypto import generate_claim_code, is_claim_code
from api.billing.models import ClaimCode, ClaimPurpose, Device, Seat, SeatRole, Subscription
from api.billing.service.common import device_actor, is_live, live_subscription_for_device, sub_target
from api.billing.service.errors import Conflict, Forbidden, Invalid, NotFound
from api.billing.store.base import ConflictError

CLAIM_INSTALL_URL = "https://cleanway.ai/ru/android"
CLAIM_LINK_SCHEME = "cleanway://claim?code="
_CODE_ATTEMPTS = 5


def _epoch(dt) -> int:
    return int(dt.timestamp())


async def _owned_live_subscription(tx, device: Device) -> Subscription:
    sub = await live_subscription_for_device(tx, device.id)
    if sub is None:
        raise NotFound("no subscription on this phone", code="no_subscription")
    if sub.payer_account_id != device.account_id:
        raise Forbidden("only the payer can do this", code="not_owner")
    return sub


async def create_claim_code(ctx: BillingContext, device: Device) -> Dict[str, Any]:
    """A one-time 6-digit code for a free seat; only its HMAC is stored."""
    now = ctx.now()
    async with ctx.store.transaction() as tx:
        sub = await _owned_live_subscription(tx, device)
        plan = ctx.plan(sub.plan_code)
        used = len(await tx.list_seats(sub.id))
        if used >= plan.seats:
            raise Conflict("no free seats on this plan", code="no_free_seats")
        expires_at = now + timedelta(hours=ctx.settings.billing_claim_code_ttl_hours)
        code = await _new_code(ctx, tx, sub.id, expires_at)
        await tx.add_audit(actor=device_actor(device), action="claim_code.created", target=sub_target(sub.id),
                           meta={"expires_at": _epoch(expires_at)})
    return {"code": code, "expires_at": _epoch(expires_at), "qr_payload": CLAIM_LINK_SCHEME + code,
            "install_url": CLAIM_INSTALL_URL, "seats_used": used, "seats_total": plan.seats}


async def _new_code(ctx: BillingContext, tx, sub_id: str, expires_at, *, purpose: ClaimPurpose = ClaimPurpose.SEAT) -> str:
    for _ in range(_CODE_ATTEMPTS):
        code = generate_claim_code()
        try:
            await tx.create_claim_code(ClaimCode(id=str(uuid.uuid4()), subscription_id=sub_id,
                                                code_hmac=ctx.hasher.claim_code(code), purpose=purpose, expires_at=expires_at))
            return code
        except ConflictError:
            continue
    raise Conflict("could not allocate a code, try again", code="code_collision")


async def redeem_claim_code(ctx: BillingContext, device: Device, *, code: str) -> Dict[str, Any]:
    """'У меня есть код': the phone joins the subscription. Same answer for every bad code."""
    if not is_claim_code(code):
        raise Invalid("a code is 6 digits", code="code_format")
    now = ctx.now()
    async with ctx.store.transaction() as tx:
        # Locked: a concurrent redeemer of the same code waits here and then sees it redeemed.
        claim = await tx.get_claim_code(ctx.hasher.claim_code(code), for_update=True)
        if claim is None or claim.redeemed_at is not None or claim.expires_at <= now:
            raise NotFound("this code is not valid", code="code_invalid")
        sub = await tx.get_subscription(claim.subscription_id, for_update=True)
        if not is_live(sub):
            raise NotFound("this code is not valid", code="code_invalid")
        seat = await tx.get_active_seat_for_device(device.id)
        if seat is not None and seat.subscription_id == sub.id:
            return _joined(ctx, sub, await tx.list_seats(sub.id))
        current = await live_subscription_for_device(tx, device.id)
        if current is not None:
            raise Conflict("this phone already has a subscription", code="already_subscribed")
        if seat is not None:
            await tx.release_seat(seat.subscription_id, device.id, released_at=now)
        seats = await tx.list_seats(sub.id)
        if len(seats) >= ctx.plan(sub.plan_code).seats:
            raise Conflict("no free seats on this plan", code="no_free_seats")
        role = SeatRole.OWNER if claim.purpose is ClaimPurpose.PARTNER_LICENSE and not seats else SeatRole.MEMBER
        await tx.add_seat(Seat(subscription_id=sub.id, device_id=device.id, role=role, claimed_at=now))
        if role is SeatRole.OWNER:
            sub = await tx.update_subscription(replace(sub, payer_account_id=device.account_id), expected_version=sub.row_version)
        if not await tx.redeem_claim_code(claim.id, device_id=device.id, redeemed_at=now):
            raise NotFound("this code is not valid", code="code_invalid")   # used meanwhile; rolls the seat back
        await tx.add_audit(actor=device_actor(device), action="seat.claimed", target=sub_target(sub.id),
                           meta={"role": role.value, "purpose": claim.purpose.value})
        seats = await tx.list_seats(sub.id)
    return _joined(ctx, sub, seats)


def _joined(ctx: BillingContext, sub: Subscription, seats) -> Dict[str, Any]:
    return {"subscription_id": sub.id, "plan": sub.plan_code.value, "seats_used": len(seats),
            "seats_total": ctx.plan(sub.plan_code).seats,
            "period_end": _epoch(sub.current_period_end) if sub.current_period_end else None}


async def list_devices(ctx: BillingContext, device: Device) -> Dict[str, Any]:
    async with ctx.store.transaction() as tx:
        sub = await live_subscription_for_device(tx, device.id)
        if sub is None:
            raise NotFound("no subscription on this phone", code="no_subscription")
        seats = await tx.list_seats(sub.id)
    plan = ctx.plan(sub.plan_code)
    return {
        "subscription_id": sub.id, "plan": plan.code.value, "seats_total": plan.seats, "seats_used": len(seats),
        "is_payer": sub.payer_account_id == device.account_id,
        "devices": [{"device_id": s.device_id, "role": s.role.value, "claimed_at": _epoch(s.claimed_at),
                     "is_this_device": s.device_id == device.id} for s in seats],
    }


async def remove_seat(ctx: BillingContext, device: Device, *, device_id: str) -> None:
    """The payer frees a seat (their own included)."""
    now = ctx.now()
    async with ctx.store.transaction() as tx:
        sub = await _owned_live_subscription(tx, device)
        if not await tx.release_seat(sub.id, device_id, released_at=now):
            raise NotFound("that phone is not in this subscription", code="seat_not_found")
        await tx.add_audit(actor=device_actor(device), action="seat.released", target=sub_target(sub.id),
                           meta={"device": device_id})

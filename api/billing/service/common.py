"""Shared helpers: row ⇄ state-machine state, actors, live subscriptions."""
from __future__ import annotations

from dataclasses import replace
from typing import Optional

from api.billing.models import Device, Subscription, SubscriptionStatus
from api.billing.state_machine import SubState

LIVE_STATUSES = (SubscriptionStatus.ACTIVE, SubscriptionStatus.GRACE, SubscriptionStatus.CANCEL_AT_PERIOD_END)


def sub_state(sub: Subscription) -> SubState:
    return SubState(
        subscription_id=sub.id, status=sub.status, current_period_start=sub.current_period_start,
        current_period_end=sub.current_period_end, grace_until=sub.grace_until, next_charge_at=sub.next_charge_at,
        cancel_requested_at=sub.cancel_requested_at, cancel_channel=sub.cancel_channel, pending_since=sub.created_at,
        attempt=sub.attempt, charge_pending=sub.charge_pending,
    )


def with_state(sub: Subscription, state: SubState) -> Subscription:
    """The row with the machine's new state written into it (status None is the caller's problem)."""
    return replace(
        sub, status=state.status or sub.status, current_period_start=state.current_period_start,
        current_period_end=state.current_period_end, grace_until=state.grace_until, next_charge_at=state.next_charge_at,
        cancel_requested_at=state.cancel_requested_at, cancel_channel=state.cancel_channel, attempt=state.attempt,
        charge_pending=state.charge_pending,
    )


def device_actor(device: Device) -> str:
    return f"device:{device.id}"


def sub_target(sub_id: str) -> str:
    return f"subscription:{sub_id}"


def is_live(sub: Optional[Subscription]) -> bool:
    return sub is not None and sub.status in LIVE_STATUSES


async def live_subscription_for_device(tx, device_id: str) -> Optional[Subscription]:
    """The subscription whose active seat this device holds, if it is still live."""
    seat = await tx.get_active_seat_for_device(device_id)
    if seat is None:
        return None
    sub = await tx.get_subscription(seat.subscription_id)
    return sub if is_live(sub) else None

"""Subscription lifecycle as a pure function (plan A.4).

    apply(state, event, now, policy) -> Transition(state, effects)

Nothing is mutated and nothing is looked up: the caller (the service layer)
loads the row, calls `apply`, writes the returned state and executes the
effects in the same transaction. Every transition is one small handler in
`_HANDLERS`, keyed by (current status, event type); anything not in the
table is an `InvalidTransition`, never a silent no-op.

Invariants the tests pin (tests/billing/test_state_machine.py):
  * after `cancel_requested_at` is set, no Charge effect is ever produced;
  * a period is paid at most once (a success only extends the period when a
    charge for it is pending, settles one of our unsettled charge rows, or
    the provider itself initiated it);
  * a Charge is produced only in `active` or `grace`;
  * the phone's mode after the grace period is exactly `policy.lapse_policy`.
"""
from __future__ import annotations

import calendar
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Mapping, Optional, Tuple, Union

from api.billing.models import (
    CancelChannel,
    ConsentKind,
    FailureReason,
    LapsePolicy,
    PlanCode,
    ProtectionMode,
    SubscriptionStatus,
)

Status = SubscriptionStatus


# ── Policy and state ──


@dataclass(frozen=True)
class Policy:
    grace_days: int = 7
    lapse_policy: LapsePolicy = LapsePolicy.BASIC
    retry_days: Tuple[int, ...] = (1, 3, 5, 7)
    pending_timeout_minutes: int = 30
    period_months: int = 1


@dataclass(frozen=True)
class SubState:
    """The part of a subscription row the lifecycle reads and writes.

    `status=None` means "no subscription": before checkout, or after a
    pending checkout was deleted.
    """
    subscription_id: str
    status: Optional[SubscriptionStatus]
    current_period_start: Optional[datetime] = None
    current_period_end: Optional[datetime] = None
    grace_until: Optional[datetime] = None
    next_charge_at: Optional[datetime] = None
    cancel_requested_at: Optional[datetime] = None
    cancel_channel: Optional[CancelChannel] = None
    pending_since: Optional[datetime] = None
    attempt: int = 0
    charge_pending: bool = False


# ── Events ──


@dataclass(frozen=True)
class CheckoutStarted:
    plan_code: PlanCode
    consent_method: str = "app_button"


@dataclass(frozen=True)
class PaymentSucceeded:
    payment_id: str
    amount_kopecks: int = 0
    # True when the provider charges on its own schedule (RuStore): then no
    # Charge effect of ours precedes the success.
    external: bool = False
    # True when the success settles one of OUR charge rows that had no final
    # answer yet (the call timed out, or we read its error as a refusal):
    # the money was taken for that period, so the period is given even
    # though `charge_pending` is no longer set.
    settles_charge: bool = False


@dataclass(frozen=True)
class PaymentFailed:
    reason: FailureReason = FailureReason.OTHER


@dataclass(frozen=True)
class PendingTimeout:
    pass


@dataclass(frozen=True)
class RenewalDue:
    pass


@dataclass(frozen=True)
class GraceExpired:
    pass


@dataclass(frozen=True)
class CancelRequested:
    channel: CancelChannel = CancelChannel.APP


@dataclass(frozen=True)
class PeriodEnded:
    pass


@dataclass(frozen=True)
class Refunded:
    payment_id: Optional[str] = None


@dataclass(frozen=True)
class OperatorStop:
    pass


@dataclass(frozen=True)
class TermEnded:
    """A fixed-term grant (promo, partner licence) reached its period end; nothing renews it."""


Event = Union[
    CheckoutStarted, PaymentSucceeded, PaymentFailed, PendingTimeout, RenewalDue,
    GraceExpired, CancelRequested, PeriodEnded, Refunded, OperatorStop, TermEnded,
]


# ── Effects ──


@dataclass(frozen=True)
class RecordConsent:
    kind: ConsentKind
    method: str


@dataclass(frozen=True)
class Charge:
    idempotency_key: str
    attempt: int
    period_start: datetime


@dataclass(frozen=True)
class Notify:
    kind: str
    reason: Optional[FailureReason] = None


@dataclass(frozen=True)
class Audit:
    action: str
    meta: Mapping[str, Any]


@dataclass(frozen=True)
class CancelAtProvider:
    pass


@dataclass(frozen=True)
class SetDeviceMode:
    mode: ProtectionMode


@dataclass(frozen=True)
class DeleteSubscription:
    pass


@dataclass(frozen=True)
class NewSubscription:
    plan_code: PlanCode


Effect = Union[
    RecordConsent, Charge, Notify, Audit, CancelAtProvider, SetDeviceMode,
    DeleteSubscription, NewSubscription,
]


@dataclass(frozen=True)
class Transition:
    state: SubState
    effects: Tuple[Effect, ...] = ()


class InvalidTransition(Exception):
    """The event makes no sense in this status; the caller decides what to do."""


# ── Date helpers ──


def add_months(dt: datetime, months: int) -> datetime:
    """Calendar months, day clamped to the target month's length (31 Jan + 1 → 28/29 Feb)."""
    month_index = dt.month - 1 + months
    year = dt.year + month_index // 12
    month = month_index % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def idempotency_key(subscription_id: str, period_start: datetime, attempt: int) -> str:
    """'{sub}:{period_start}:{attempt}' — a retried run can never charge twice."""
    return f"{subscription_id}:{period_start.strftime('%Y%m%dT%H%M%SZ')}:{attempt}"


def _next_retry_at(period_end: datetime, attempt: int, policy: Policy) -> Optional[datetime]:
    """When retry number `attempt` (1-based) is due, or None when retries are exhausted."""
    if attempt < 1 or attempt > len(policy.retry_days):
        return None
    return period_end + timedelta(days=policy.retry_days[attempt - 1])


# ── Handlers ──

Handler = Callable[[SubState, Any, datetime, Policy], Transition]


def _no_op(state: SubState, *_: Any) -> Transition:
    return Transition(state=state, effects=())


def _start_checkout(state: SubState, event: CheckoutStarted, now: datetime, policy: Policy) -> Transition:
    fresh = SubState(subscription_id=state.subscription_id, status=Status.PENDING, pending_since=now)
    effects: Tuple[Effect, ...] = (
        RecordConsent(kind=ConsentKind.SUBSCRIPTION_OFFER, method=event.consent_method),
        Audit(action="subscription.checkout_started", meta={"plan": event.plan_code.value}),
    )
    if state.status is not None:
        # A lapsed or refunded subscription is history; the service inserts a new row.
        effects = (NewSubscription(plan_code=event.plan_code),) + effects
    return Transition(state=fresh, effects=effects)


def _first_payment(state: SubState, event: PaymentSucceeded, now: datetime, policy: Policy) -> Transition:
    end = add_months(now, policy.period_months)
    new = replace(
        state, status=Status.ACTIVE, current_period_start=now, current_period_end=end,
        next_charge_at=end, grace_until=None, attempt=0, charge_pending=False, pending_since=None,
    )
    return Transition(state=new, effects=(
        Audit(action="subscription.activated", meta={"payment_id": event.payment_id}),
        Notify(kind="charged"),
        SetDeviceMode(mode=ProtectionMode.FULL),
    ))


def _pending_failed(state: SubState, event: Any, now: datetime, policy: Policy) -> Transition:
    reason = getattr(event, "reason", FailureReason.TIMEOUT)
    if isinstance(event, PendingTimeout):
        deadline = (state.pending_since or now) + timedelta(minutes=policy.pending_timeout_minutes)
        if now < deadline:
            return _no_op(state)
    if isinstance(event, CancelRequested):
        reason = FailureReason.USER_DECLINED
    gone = SubState(subscription_id=state.subscription_id, status=None)
    return Transition(state=gone, effects=(
        DeleteSubscription(),
        Audit(action="subscription.checkout_failed", meta={"reason": reason.value}),
        Notify(kind="checkout_failed", reason=reason),
    ))


def _renewal_due(state: SubState, event: RenewalDue, now: datetime, policy: Policy) -> Transition:
    due = state.next_charge_at
    if state.cancel_requested_at is not None or state.charge_pending or due is None or now < due:
        return _no_op(state)
    period_start = state.current_period_end or now
    key = idempotency_key(state.subscription_id, period_start, state.attempt)
    new = replace(state, charge_pending=True)
    return Transition(state=new, effects=(
        Charge(idempotency_key=key, attempt=state.attempt, period_start=period_start),
        Audit(action="subscription.charge_requested", meta={"attempt": state.attempt}),
    ))


def _renewal_paid(state: SubState, event: PaymentSucceeded, now: datetime, policy: Policy) -> Transition:
    if not (state.charge_pending or event.external or event.settles_charge):
        return Transition(state=state, effects=(
            Audit(action="payment.unexpected_success", meta={"payment_id": event.payment_id}),
        ))
    # A renewal keeps the anchor date; a recovery from grace starts from the payment.
    start = state.current_period_end if state.status is Status.ACTIVE and state.current_period_end else now
    end = add_months(start, policy.period_months)
    new = replace(
        state, status=Status.ACTIVE, current_period_start=start, current_period_end=end,
        next_charge_at=end, grace_until=None, attempt=0, charge_pending=False,
    )
    return Transition(state=new, effects=(
        Audit(action="subscription.renewed", meta={"payment_id": event.payment_id}),
        Notify(kind="charged"),
        SetDeviceMode(mode=ProtectionMode.FULL),
    ))


def _cancelled_paid(state: SubState, event: PaymentSucceeded, now: datetime, policy: Policy) -> Transition:
    """A charge issued before the cancel that still landed: the days are honoured."""
    if not (state.charge_pending or event.settles_charge):
        return Transition(state=state, effects=(
            Audit(action="payment.unexpected_success", meta={"payment_id": event.payment_id}),
        ))
    start = state.current_period_end or now
    end = add_months(start, policy.period_months)
    new = replace(state, current_period_start=start, current_period_end=end, charge_pending=False, attempt=0)
    return Transition(state=new, effects=(
        Audit(action="payment.after_cancel_honoured", meta={"payment_id": event.payment_id}),
    ))


def _payment_failed(state: SubState, event: PaymentFailed, now: datetime, policy: Policy) -> Transition:
    if not state.charge_pending:
        return Transition(state=state, effects=(
            Audit(action="payment.unexpected_failure", meta={"reason": event.reason.value}),
        ))
    period_end = state.current_period_end or now
    attempt = state.attempt + 1
    grace_until = state.grace_until or (period_end + timedelta(days=policy.grace_days))
    next_at = _next_retry_at(period_end, attempt, policy)
    if next_at is not None and next_at > grace_until:
        next_at = None
    new = replace(
        state, status=Status.GRACE, grace_until=grace_until, next_charge_at=next_at,
        attempt=attempt, charge_pending=False,
    )
    return Transition(state=new, effects=(
        Audit(action="payment.failed", meta={"reason": event.reason.value, "attempt": attempt}),
        Notify(kind="payment_failed", reason=event.reason),
    ))


def _grace_expired(state: SubState, event: GraceExpired, now: datetime, policy: Policy) -> Transition:
    if state.grace_until is None or now < state.grace_until:
        return _no_op(state)
    new = replace(state, status=Status.LAPSED, next_charge_at=None, charge_pending=False)
    return Transition(state=new, effects=(
        Audit(action="subscription.lapsed", meta={"lapse_policy": policy.lapse_policy.value}),
        Notify(kind="lapsed"),
        SetDeviceMode(mode=policy.lapse_policy.mode),
    ))


def _cancel(state: SubState, event: Any, now: datetime, policy: Policy) -> Transition:
    channel = CancelChannel.OPERATOR_STOP if isinstance(event, OperatorStop) else event.channel
    new = replace(
        state, status=Status.CANCEL_AT_PERIOD_END, cancel_requested_at=now, cancel_channel=channel,
        next_charge_at=None, charge_pending=state.charge_pending,
    )
    return Transition(state=new, effects=(
        CancelAtProvider(),
        RecordConsent(kind=ConsentKind.CANCEL, method=channel.value),
        Audit(action="subscription.cancel_requested", meta={"channel": channel.value}),
        Notify(kind="cancelled"),
    ))


def _period_ended(state: SubState, event: PeriodEnded, now: datetime, policy: Policy) -> Transition:
    if state.current_period_end is None or now < state.current_period_end:
        return _no_op(state)
    new = replace(state, status=Status.LAPSED, next_charge_at=None, charge_pending=False)
    return Transition(state=new, effects=(
        Audit(action="subscription.lapsed", meta={"lapse_policy": policy.lapse_policy.value, "after": "cancel"}),
        Notify(kind="lapsed"),
        SetDeviceMode(mode=policy.lapse_policy.mode),
    ))


def _term_ended(state: SubState, event: TermEnded, now: datetime, policy: Policy) -> Transition:
    if state.current_period_end is None or now < state.current_period_end:
        return _no_op(state)
    new = replace(state, status=Status.LAPSED, next_charge_at=None, charge_pending=False)
    return Transition(state=new, effects=(
        Audit(action="subscription.lapsed", meta={"lapse_policy": policy.lapse_policy.value, "after": "term_end"}),
        Notify(kind="lapsed"),
        SetDeviceMode(mode=policy.lapse_policy.mode),
    ))


def _refunded(state: SubState, event: Refunded, now: datetime, policy: Policy) -> Transition:
    new = replace(state, status=Status.REFUNDED, next_charge_at=None, charge_pending=False)
    return Transition(state=new, effects=(
        Audit(action="subscription.refunded", meta={"payment_id": event.payment_id}),
        Notify(kind="refunded"),
        SetDeviceMode(mode=policy.lapse_policy.mode),
    ))


_HANDLERS: Dict[Tuple[Optional[SubscriptionStatus], type], Handler] = {
    (None, CheckoutStarted): _start_checkout,
    (Status.LAPSED, CheckoutStarted): _start_checkout,
    (Status.REFUNDED, CheckoutStarted): _start_checkout,
    (Status.PENDING, PaymentSucceeded): _first_payment,
    (Status.PENDING, PaymentFailed): _pending_failed,
    (Status.PENDING, PendingTimeout): _pending_failed,
    (Status.PENDING, CancelRequested): _pending_failed,
    (Status.ACTIVE, RenewalDue): _renewal_due,
    (Status.ACTIVE, PaymentSucceeded): _renewal_paid,
    (Status.ACTIVE, PaymentFailed): _payment_failed,
    (Status.ACTIVE, CancelRequested): _cancel,
    (Status.ACTIVE, OperatorStop): _cancel,
    (Status.ACTIVE, Refunded): _refunded,
    (Status.ACTIVE, TermEnded): _term_ended,
    (Status.GRACE, RenewalDue): _renewal_due,
    (Status.GRACE, PaymentSucceeded): _renewal_paid,
    (Status.GRACE, PaymentFailed): _payment_failed,
    (Status.GRACE, GraceExpired): _grace_expired,
    (Status.GRACE, CancelRequested): _cancel,
    (Status.GRACE, OperatorStop): _cancel,
    (Status.GRACE, Refunded): _refunded,
    (Status.CANCEL_AT_PERIOD_END, PeriodEnded): _period_ended,
    (Status.CANCEL_AT_PERIOD_END, RenewalDue): _no_op,
    (Status.CANCEL_AT_PERIOD_END, PaymentSucceeded): _cancelled_paid,
    (Status.CANCEL_AT_PERIOD_END, PaymentFailed): _no_op,
    (Status.CANCEL_AT_PERIOD_END, CancelRequested): _no_op,
    (Status.CANCEL_AT_PERIOD_END, OperatorStop): _no_op,
    (Status.CANCEL_AT_PERIOD_END, Refunded): _refunded,
    (Status.LAPSED, Refunded): _refunded,
}


def allowed_events(status: Optional[SubscriptionStatus]) -> Tuple[type, ...]:
    """Event types the table accepts in `status` (for the exhaustive test)."""
    return tuple(event for (s, event) in _HANDLERS if s is status)


def apply(state: SubState, event: Event, now: datetime, policy: Policy) -> Transition:
    """Pure transition. Raises InvalidTransition for a (status, event) pair not in the table."""
    handler = _HANDLERS.get((state.status, type(event)))
    if handler is None:
        status = state.status.value if state.status else "none"
        raise InvalidTransition(f"{type(event).__name__} is not valid in status {status}")
    return handler(state, event, now, policy)

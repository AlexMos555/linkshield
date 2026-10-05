"""apply() — every transition of plan A.4, and the invariants under random sequences.

  * the table is exhaustive: each (status, event) pair either has a handler
    or raises InvalidTransition — no silent acceptance;
  * after cancel_requested_at, no Charge is ever produced;
  * a Charge is produced only in active / grace;
  * one period is paid at most once;
  * the phone's mode after the grace period is exactly policy.lapse_policy.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

from api.billing.models import (
    CancelChannel,
    ConsentKind,
    FailureReason,
    LapsePolicy,
    PlanCode,
    ProtectionMode,
    SubscriptionStatus as S,
)
from api.billing.state_machine import (
    Audit,
    CancelAtProvider,
    CancelRequested,
    Charge,
    CheckoutStarted,
    DeleteSubscription,
    GraceExpired,
    InvalidTransition,
    NewSubscription,
    Notify,
    OperatorStop,
    PaymentFailed,
    PaymentSucceeded,
    PendingTimeout,
    PeriodEnded,
    Policy,
    RecordConsent,
    Refunded,
    RenewalDue,
    SetDeviceMode,
    SubState,
    add_months,
    allowed_events,
    apply,
    idempotency_key,
)

T0 = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)
POLICY = Policy(grace_days=7, lapse_policy=LapsePolicy.BASIC, retry_days=(1, 3, 5, 7))
SUB = "sub-1"

ALL_EVENTS = (
    CheckoutStarted(plan_code=PlanCode.SOLO), PaymentSucceeded(payment_id="p"), PaymentFailed(),
    PendingTimeout(), RenewalDue(), GraceExpired(), CancelRequested(), PeriodEnded(), Refunded(), OperatorStop(),
)
ALL_STATUSES = (None,) + tuple(S)


def _effects_of(transition, kind):
    return [e for e in transition.effects if isinstance(e, kind)]


def _active(now=T0) -> SubState:
    """A subscription that was just paid for the first time at `now`."""
    pending = apply(SubState(SUB, None), CheckoutStarted(PlanCode.SOLO), now, POLICY).state
    return apply(pending, PaymentSucceeded(payment_id="p1"), now, POLICY).state


# ── Dates ──


def test_add_months_clamps_to_month_end():
    assert add_months(datetime(2026, 1, 31), 1) == datetime(2026, 2, 28)
    assert add_months(datetime(2028, 1, 31), 1) == datetime(2028, 2, 29)
    assert add_months(datetime(2026, 12, 15), 1) == datetime(2027, 1, 15)
    assert add_months(datetime(2026, 3, 31), 12) == datetime(2027, 3, 31)


def test_idempotency_key_has_no_colon_in_the_date():
    key = idempotency_key(SUB, T0, 2)
    assert key == "sub-1:20261001T120000Z:2"


# ── The table is exhaustive ──


@pytest.mark.parametrize("status", ALL_STATUSES)
@pytest.mark.parametrize("event", ALL_EVENTS, ids=lambda e: type(e).__name__)
def test_every_pair_is_either_handled_or_rejected(status, event):
    state = SubState(SUB, status, current_period_end=T0, grace_until=T0, next_charge_at=T0, pending_since=T0)
    if type(event) in allowed_events(status):
        apply(state, event, T0, POLICY)
    else:
        with pytest.raises(InvalidTransition):
            apply(state, event, T0, POLICY)


def test_table_matches_plan_a4():
    assert set(allowed_events(None)) == {CheckoutStarted}
    assert set(allowed_events(S.PENDING)) == {PaymentSucceeded, PaymentFailed, PendingTimeout, CancelRequested}
    assert set(allowed_events(S.ACTIVE)) == {RenewalDue, PaymentSucceeded, PaymentFailed, CancelRequested, OperatorStop, Refunded}
    assert set(allowed_events(S.GRACE)) == {RenewalDue, PaymentSucceeded, PaymentFailed, GraceExpired, CancelRequested, OperatorStop, Refunded}
    assert set(allowed_events(S.LAPSED)) == {CheckoutStarted, Refunded}
    assert set(allowed_events(S.REFUNDED)) == {CheckoutStarted}


# ── Checkout ──


def test_checkout_records_consent_and_goes_pending():
    t = apply(SubState(SUB, None), CheckoutStarted(PlanCode.FAMILY3, consent_method="sms_code"), T0, POLICY)
    assert t.state.status is S.PENDING
    assert t.state.pending_since == T0
    consent = _effects_of(t, RecordConsent)[0]
    assert consent.kind is ConsentKind.SUBSCRIPTION_OFFER and consent.method == "sms_code"
    assert not _effects_of(t, NewSubscription)


def test_checkout_after_lapse_starts_a_new_subscription():
    lapsed = SubState(SUB, S.LAPSED)
    t = apply(lapsed, CheckoutStarted(PlanCode.SOLO), T0, POLICY)
    assert t.state.status is S.PENDING
    assert _effects_of(t, NewSubscription)[0].plan_code is PlanCode.SOLO


def test_first_payment_opens_a_calendar_month_period():
    t = apply(SubState(SUB, S.PENDING, pending_since=T0), PaymentSucceeded("p1", 9900), T0, POLICY)
    assert t.state.status is S.ACTIVE
    assert t.state.current_period_start == T0
    assert t.state.current_period_end == T0 + timedelta(days=31)  # Oct → Nov 1
    assert t.state.next_charge_at == t.state.current_period_end
    assert _effects_of(t, SetDeviceMode)[0].mode is ProtectionMode.FULL
    assert _effects_of(t, Notify)[0].kind == "charged"


@pytest.mark.parametrize("event, reason", [
    (PaymentFailed(FailureReason.NO_MONEY), FailureReason.NO_MONEY),
    (PaymentFailed(FailureReason.PASSPORT), FailureReason.PASSPORT),
    (CancelRequested(), FailureReason.USER_DECLINED),
])
def test_pending_failure_deletes_the_subscription_and_names_the_reason(event, reason):
    t = apply(SubState(SUB, S.PENDING, pending_since=T0), event, T0, POLICY)
    assert t.state.status is None
    assert _effects_of(t, DeleteSubscription)
    assert _effects_of(t, Notify)[0] == Notify(kind="checkout_failed", reason=reason)


def test_pending_timeout_only_after_the_configured_wait():
    pending = SubState(SUB, S.PENDING, pending_since=T0)
    early = apply(pending, PendingTimeout(), T0 + timedelta(minutes=29), POLICY)
    assert early.state.status is S.PENDING and early.effects == ()
    late = apply(pending, PendingTimeout(), T0 + timedelta(minutes=30), POLICY)
    assert late.state.status is None
    assert _effects_of(late, Notify)[0].reason is FailureReason.TIMEOUT


# ── Renewals ──


def test_renewal_is_not_charged_before_it_is_due():
    active = _active()
    t = apply(active, RenewalDue(), active.next_charge_at - timedelta(seconds=1), POLICY)
    assert t.effects == () and t.state == active


def test_renewal_due_charges_once_with_an_idempotency_key():
    active = _active()
    due = active.next_charge_at
    t = apply(active, RenewalDue(), due, POLICY)
    charge = _effects_of(t, Charge)[0]
    assert charge == Charge(idempotency_key=idempotency_key(SUB, due, 0), attempt=0, period_start=due)
    assert t.state.charge_pending is True
    # The scheduler running twice must not charge twice.
    again = apply(t.state, RenewalDue(), due, POLICY)
    assert not _effects_of(again, Charge)


def test_renewal_success_extends_from_the_anchor_date():
    active = _active()
    due = active.next_charge_at
    charged = apply(active, RenewalDue(), due, POLICY).state
    paid = apply(charged, PaymentSucceeded("p2"), due + timedelta(hours=2), POLICY)
    assert paid.state.status is S.ACTIVE
    assert paid.state.current_period_start == due
    assert paid.state.current_period_end == add_months(due, 1)
    assert paid.state.charge_pending is False


def test_success_without_a_pending_charge_is_ignored_and_audited():
    active = _active()
    t = apply(active, PaymentSucceeded("dup"), T0, POLICY)
    assert t.state == active
    assert _effects_of(t, Audit)[0].action == "payment.unexpected_success"


def test_provider_initiated_renewal_is_accepted_without_our_charge():
    active = _active()
    t = apply(active, PaymentSucceeded("rustore-1", external=True), active.current_period_end, POLICY)
    assert t.state.current_period_start == active.current_period_end


# ── Grace ──


def _in_grace(reason=FailureReason.NO_MONEY):
    active = _active()
    due = active.next_charge_at
    charged = apply(active, RenewalDue(), due, POLICY).state
    return due, apply(charged, PaymentFailed(reason), due, POLICY)


def test_failed_renewal_opens_seven_day_grace_with_first_retry_tomorrow():
    due, t = _in_grace()
    assert t.state.status is S.GRACE
    assert t.state.grace_until == due + timedelta(days=7)
    assert t.state.next_charge_at == due + timedelta(days=1)
    assert t.state.attempt == 1
    assert _effects_of(t, Notify)[0] == Notify(kind="payment_failed", reason=FailureReason.NO_MONEY)
    # Protection stays full during grace: no mode change effect.
    assert not _effects_of(t, SetDeviceMode)


def test_retries_follow_1_3_5_7_then_stop():
    due, t = _in_grace()
    state = t.state
    seen = []
    for expected_day in (1, 3, 5, 7):
        assert state.next_charge_at == due + timedelta(days=expected_day)
        charged = apply(state, RenewalDue(), state.next_charge_at, POLICY)
        seen.append(_effects_of(charged, Charge)[0].attempt)
        state = apply(charged.state, PaymentFailed(), state.next_charge_at, POLICY).state
    assert seen == [1, 2, 3, 4]
    assert state.next_charge_at is None
    assert state.status is S.GRACE


def test_recovery_in_grace_starts_a_period_from_the_payment_date():
    due, t = _in_grace()
    retry_at = t.state.next_charge_at
    charged = apply(t.state, RenewalDue(), retry_at, POLICY).state
    paid = apply(charged, PaymentSucceeded("p3"), retry_at, POLICY)
    assert paid.state.status is S.ACTIVE
    assert paid.state.current_period_start == retry_at
    assert paid.state.grace_until is None
    assert paid.state.attempt == 0


@pytest.mark.parametrize("policy_mode, expected", [
    (LapsePolicy.BASIC, ProtectionMode.BASIC),
    (LapsePolicy.OFF, ProtectionMode.OFF),
])
def test_grace_expiry_lapses_into_the_configured_policy(policy_mode, expected):
    due, t = _in_grace()
    policy = Policy(lapse_policy=policy_mode)
    early = apply(t.state, GraceExpired(), t.state.grace_until - timedelta(seconds=1), policy)
    assert early.state.status is S.GRACE and early.effects == ()
    lapsed = apply(t.state, GraceExpired(), t.state.grace_until, policy)
    assert lapsed.state.status is S.LAPSED
    assert lapsed.state.next_charge_at is None
    assert _effects_of(lapsed, SetDeviceMode)[0].mode is expected


# ── Cancel ──


@pytest.mark.parametrize("event, channel", [
    (CancelRequested(CancelChannel.APP), CancelChannel.APP),
    (CancelRequested(CancelChannel.WEB), CancelChannel.WEB),
    (OperatorStop(), CancelChannel.OPERATOR_STOP),
])
def test_cancel_stops_future_charges_immediately(event, channel):
    active = _active()
    t = apply(active, event, T0 + timedelta(days=3), POLICY)
    assert t.state.status is S.CANCEL_AT_PERIOD_END
    assert t.state.cancel_requested_at == T0 + timedelta(days=3)
    assert t.state.cancel_channel is channel
    assert t.state.next_charge_at is None
    assert _effects_of(t, CancelAtProvider)
    assert _effects_of(t, RecordConsent)[0].kind is ConsentKind.CANCEL
    # Protection keeps running until the paid period ends.
    assert not _effects_of(t, SetDeviceMode)


def test_cancelled_subscription_lapses_when_the_period_ends():
    cancelled = apply(_active(), CancelRequested(), T0, POLICY).state
    early = apply(cancelled, PeriodEnded(), cancelled.current_period_end - timedelta(seconds=1), POLICY)
    assert early.state.status is S.CANCEL_AT_PERIOD_END
    ended = apply(cancelled, PeriodEnded(), cancelled.current_period_end, POLICY)
    assert ended.state.status is S.LAPSED
    assert _effects_of(ended, SetDeviceMode)[0].mode is ProtectionMode.BASIC


def test_renewal_due_after_cancel_is_a_silent_no_op():
    cancelled = apply(_active(), CancelRequested(), T0, POLICY).state
    t = apply(cancelled, RenewalDue(), cancelled.current_period_end, POLICY)
    assert t.effects == ()


def test_charge_in_flight_before_cancel_is_honoured_when_it_lands():
    active = _active()
    charged = apply(active, RenewalDue(), active.next_charge_at, POLICY).state
    cancelled = apply(charged, CancelRequested(), active.next_charge_at, POLICY).state
    assert cancelled.charge_pending is True
    landed = apply(cancelled, PaymentSucceeded("late"), active.next_charge_at, POLICY)
    assert landed.state.status is S.CANCEL_AT_PERIOD_END
    assert landed.state.current_period_end == add_months(active.next_charge_at, 1)
    assert _effects_of(landed, Audit)[0].action == "payment.after_cancel_honoured"


def test_refund_drops_access_immediately():
    t = apply(_active(), Refunded("p1"), T0, POLICY)
    assert t.state.status is S.REFUNDED
    assert _effects_of(t, SetDeviceMode)[0].mode is ProtectionMode.BASIC


# ── Invariants under random event sequences ──

_RANDOM_EVENTS = (
    lambda: CheckoutStarted(PlanCode.SOLO),
    lambda: PaymentSucceeded(payment_id="p"),
    lambda: PaymentFailed(FailureReason.NO_MONEY),
    PendingTimeout, RenewalDue, GraceExpired, CancelRequested, PeriodEnded, Refunded, OperatorStop,
)


def _random_run(seed: int):
    """Drive a subscription with random events at random times; yield every transition."""
    rng = random.Random(seed)
    state = SubState(SUB, None)
    now = T0
    for _ in range(60):
        now = now + timedelta(hours=rng.randint(0, 24 * 12))
        event = rng.choice(_RANDOM_EVENTS)()
        try:
            transition = apply(state, event, now, POLICY)
        except InvalidTransition:
            continue
        yield state, event, transition
        state = transition.state


@pytest.mark.parametrize("seed", range(300))
def test_invariants_hold_for_random_sequences(seed):
    cancelled = False
    paid_periods = set()
    for before, event, transition in _random_run(seed):
        charges = _effects_of(transition, Charge)
        if charges:
            # Charges only in active/grace and never after a cancel.
            assert before.status in (S.ACTIVE, S.GRACE), (seed, before.status)
            assert before.cancel_requested_at is None and not cancelled
        if isinstance(event, CancelRequested) or isinstance(event, OperatorStop):
            if transition.state.status is S.CANCEL_AT_PERIOD_END:
                cancelled = True
        if isinstance(event, CheckoutStarted):
            cancelled = False
            paid_periods = set()
        after = transition.state
        if after.status is S.ACTIVE and after.current_period_start != before.current_period_start:
            # Every period is paid exactly once.
            assert after.current_period_start not in paid_periods, seed
            paid_periods.add(after.current_period_start)
        if cancelled and after.status is S.CANCEL_AT_PERIOD_END:
            assert after.next_charge_at is None

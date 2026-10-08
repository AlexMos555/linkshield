"""Effective entitlement of an account (api/services/entitlements.py).

The rules from docs/ACCOUNTS_BILLING_PLAN.md §1 / §5: the best ACTIVE row
of any source wins; no active row = free; a paid plan covers 3 devices plus
bought extras; a signed-in free account may link 2. Paid legacy
`subscriptions` rows the webhook wrote before entitlements existed still
count, so nobody who paid is downgraded by the migration.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from api.services import entitlements as ent


def _iso(**delta) -> str:
    return (datetime.now(timezone.utc) + timedelta(**delta)).isoformat()


def _row(**kw):
    row = {"source": "stripe", "external_id": "sub_1", "plan": "personal",
           "status": "active", "device_limit": 3, "period_end": None}
    row.update(kw)
    return row


def _run(coro):
    return asyncio.run(coro)


# ─── config defaults ───────────────────────────────────────────────


def test_device_limits_are_config_values_with_the_founders_numbers():
    from api.config import get_settings

    s = get_settings()
    assert s.plan_included_devices == 3
    assert s.free_account_device_limit == 2
    assert ent.included_devices() == 3
    assert ent.free_device_limit() == 2


def test_device_limits_follow_config(monkeypatch):
    from api.config import get_settings

    monkeypatch.setattr(get_settings(), "plan_included_devices", 5)
    monkeypatch.setattr(get_settings(), "free_account_device_limit", 1)
    assert ent.free_entitlement().device_limit == 1
    assert ent.effective_entitlement([_row(device_limit=None)]).device_limit == 5


# ─── effective_entitlement ─────────────────────────────────────────


def test_no_rows_is_free_with_the_free_device_limit():
    e = ent.effective_entitlement([])
    assert e.plan == "free" and e.status == "free"
    assert e.source is None and not e.is_paid
    assert e.device_limit == 2


@pytest.mark.parametrize("status", ["active", "trialing", "past_due"])
def test_active_statuses_grant_the_plan(status):
    e = ent.effective_entitlement([_row(status=status, plan="family")])
    assert e.is_paid and e.plan == "family" and e.status == status
    assert e.source == "stripe" and e.device_limit == 3


@pytest.mark.parametrize("status", ["pending", "paused", "cancelled", "expired", "refunded"])
def test_ended_statuses_grant_nothing(status):
    assert not ent.effective_entitlement([_row(status=status)]).is_paid


def test_period_end_in_the_past_beyond_grace_is_expired():
    assert not ent.effective_entitlement([_row(period_end=_iso(days=-10))]).is_paid


def test_period_end_within_grace_still_counts():
    # One late renewal webhook must not lock a paying person out.
    assert ent.effective_entitlement([_row(period_end=_iso(hours=-5))]).is_paid


def test_best_row_has_most_devices_then_latest_end():
    rows = [
        _row(external_id="a", device_limit=3, period_end=_iso(days=30)),
        _row(external_id="b", source="google_play", device_limit=5, period_end=_iso(days=2)),
        _row(external_id="c", device_limit=5, period_end=_iso(days=20), status="cancelled"),
    ]
    best = ent.effective_entitlement(rows)
    assert best.external_id == "b" and best.device_limit == 5 and best.source == "google_play"

    rows = [
        _row(external_id="soon", period_end=_iso(days=2)),
        _row(external_id="open", source="promo", period_end=None),
        _row(external_id="later", period_end=_iso(days=40)),
    ]
    assert ent.effective_entitlement(rows).external_id == "open"


# ─── get_effective_entitlement / has_active_entitlement ───────────


def test_store_rows_from_any_source_count(account_store):
    account_store.add_entitlement("acc", source="operator_ru", external_id="op-1", plan="personal")
    e = _run(ent.get_effective_entitlement("acc", legacy_row=None))
    assert e.source == "operator_ru" and e.is_paid
    assert _run(ent.has_active_entitlement("acc", legacy_row=None)) == e


def test_free_account_has_no_active_entitlement(account_store):
    assert _run(ent.has_active_entitlement("nobody", legacy_row=None)) is None


def test_paid_legacy_subscription_without_an_entitlement_row_still_counts(account_store):
    legacy = {"user_id": "acc", "tier": "family", "status": "active", "provider": "stripe",
              "provider_subscription_id": "sub_legacy", "current_period_end": None}
    e = _run(ent.get_effective_entitlement("acc", legacy_row=legacy))
    assert e.is_paid and e.source == "stripe" and e.plan == "family"
    assert e.external_id == "sub_legacy" and e.device_limit == 3


def test_entitlement_row_overrides_its_legacy_copy(account_store):
    # The webhook already marked this subscription cancelled in entitlements;
    # a stale legacy row must not resurrect it.
    account_store.add_entitlement("acc", external_id="sub_legacy", status="cancelled")
    legacy = {"user_id": "acc", "tier": "personal", "status": "active", "provider": "stripe",
              "provider_subscription_id": "sub_legacy"}
    assert not _run(ent.get_effective_entitlement("acc", legacy_row=legacy)).is_paid


def test_free_legacy_row_is_not_paid(account_store):
    legacy = {"user_id": "acc", "tier": "free", "status": "active", "provider": "stripe"}
    assert not _run(ent.get_effective_entitlement("acc", legacy_row=legacy)).is_paid


def test_store_failure_is_an_error_never_free(account_store):
    account_store.fail = True
    with pytest.raises(ent.EntitlementError):
        _run(ent.get_effective_entitlement("acc", legacy_row=None))


def test_unconfigured_database_means_nobody_paid(monkeypatch):
    # Local dev without Supabase: same default as fetch_subscription_row.
    from api.config import get_settings
    from api.services import account_store as store_module

    store_module.set_account_store(None)
    monkeypatch.setattr(get_settings(), "supabase_url", "", raising=False)
    assert not _run(ent.get_effective_entitlement("acc")).is_paid


# ─── writers ──────────────────────────────────────────────────────


def test_record_entitlement_upserts_on_source_and_external_id(account_store):
    _run(ent.record_entitlement(account_id="acc", source="stripe", external_id="sub_9",
                                status="trialing", plan="family"))
    _run(ent.record_entitlement(account_id="acc", source="stripe", external_id="sub_9",
                                status="active", period_end="2026-11-07T00:00:00+00:00",
                                device_limit=4))
    assert len(account_store.entitlements) == 1
    row = account_store.entitlements[0]
    assert row["status"] == "active" and row["plan"] == "family"
    assert row["device_limit"] == 4 and row["period_end"].startswith("2026-11-07")


def test_record_entitlement_rejects_unknown_source_and_status(account_store):
    with pytest.raises(ValueError):
        _run(ent.record_entitlement(account_id="a", source="paypal", external_id="x", status="active"))
    with pytest.raises(ValueError):
        _run(ent.record_entitlement(account_id="a", source="stripe", external_id="x", status="refunding"))


def test_record_entitlement_store_failure_raises(account_store):
    account_store.fail = True
    with pytest.raises(ent.EntitlementError):
        _run(ent.record_entitlement(account_id="a", source="stripe", external_id="x", status="active"))


def test_end_source_entitlements_only_touches_that_source(account_store):
    account_store.add_entitlement("acc", source="stripe", external_id="s1")
    account_store.add_entitlement("acc", source="promo", external_id="p1")
    _run(ent.end_source_entitlements(account_id="acc", source="stripe"))
    by_source = {r["source"]: r["status"] for r in account_store.entitlements}
    assert by_source == {"stripe": "cancelled", "promo": "active"}


# ─── Stripe mapping ───────────────────────────────────────────────


@pytest.mark.parametrize("stripe_status,expected", [
    ("active", "active"), ("trialing", "trialing"), ("past_due", "past_due"),
    ("incomplete", "pending"), ("paused", "paused"), ("unpaid", "expired"),
    ("incomplete_expired", "expired"), ("canceled", "cancelled"), ("brand_new", "expired"),
    (None, "expired"),
])
def test_stripe_status_mapping(stripe_status, expected):
    assert ent.stripe_status(stripe_status) == expected


def test_stripe_device_limit_counts_extra_device_items(monkeypatch):
    from api.config import get_settings

    sub = {"items": {"data": [
        {"price": {"id": "price_personal"}, "quantity": 1},
        {"price": {"id": "price_extra"}, "quantity": 2},
    ]}}
    # Not configured: only the included devices.
    assert ent.stripe_device_limit(sub) == 3
    monkeypatch.setattr(get_settings(), "stripe_price_extra_device", "price_extra")
    assert ent.stripe_device_limit(sub) == 5
    assert ent.stripe_device_limit({}) == 3

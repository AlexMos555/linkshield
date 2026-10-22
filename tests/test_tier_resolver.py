"""Tier resolver (api/services/auth.py) — the tier every limit reads.

The tier is the plan of the account's EFFECTIVE ENTITLEMENT
(api/services/entitlements.py): the best active `entitlements` row of any
source — Stripe, Google Play / App Store through RevenueCat, the operator
subscription, promo — or a paid legacy `subscriptions` row the table does
not know yet. That is the answer the account screen shows; the resolver
used to read only `subscriptions`, where migration 010 gives every account
a tier='free' row, so a store purchase read "paid" on the account screen
while every limit stayed free.

Pinned here:
  * past_due keeps the paid tier during Stripe's dunning window;
  * store / promo plans count although the subscriptions row says free;
  * an entitlement row past its end date + grace, an add-on alone, or a
    cancelled Stripe row behind a stale legacy copy grant nothing;
  * a failed or slow lookup is reported as such — (free, False) — and is
    cached for seconds, not minutes, falling back to the last confirmed
    paid tier: a short Supabase outage must not put payers on free limits.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from api.models.schemas import UserTier

# Migration 010 seeds this row for every account.
FREE_ROW = {"user_id": "u", "tier": "free", "status": "active", "provider": None,
            "provider_subscription_id": None, "current_period_end": None}


def _iso(**delta) -> str:
    return (datetime.now(timezone.utc) + timedelta(**delta)).isoformat()


@pytest.fixture
def legacy(monkeypatch):
    """The account's `subscriptions` row as fetch_subscription_row returns it."""
    from api.services import stripe_billing

    state = {"row": dict(FREE_ROW), "error": None, "calls": 0}

    async def _fetch(*, user_id=None, **_kw):
        state["calls"] += 1
        if state["error"] is not None:
            raise state["error"]
        return dict(state["row"], user_id=user_id) if state["row"] else None

    monkeypatch.setattr(stripe_billing, "fetch_subscription_row", _fetch)
    return state


async def _tier(user_id: str):
    from api.services import auth

    return await auth._fetch_tier_from_supabase(user_id)


# ─── where the tier comes from ─────────────────────────────────────


@pytest.mark.asyncio
async def test_store_plan_counts_although_the_subscriptions_row_says_free(account_store, legacy):
    """The bug: every account has a tier='free' subscriptions row, so the
    resolver never looked at entitlements and a Google Play buyer stayed free."""
    account_store.add_entitlement("user-play", source="google_play", external_id="GPA.1",
                                  plan="personal", status="active", period_end=_iso(days=20))
    assert await _tier("user-play") == (UserTier.personal, True)


@pytest.mark.asyncio
@pytest.mark.parametrize("source,status", [
    ("app_store", "trialing"), ("promo", "active"), ("operator_ru", "active"), ("stripe", "past_due"),
])
async def test_every_source_and_active_status_grants_its_plan(account_store, legacy, source, status):
    account_store.add_entitlement("u", source=source, external_id="x-1", plan="family", status=status)
    assert await _tier("u") == (UserTier.family, True)


@pytest.mark.asyncio
async def test_past_due_legacy_row_keeps_paid_tier(account_store, legacy):
    """Stripe is retrying a declined card; the user paid — no downgrade on
    the first failed charge (subscriptions rows from before entitlements)."""
    legacy["row"] = dict(FREE_ROW, tier="personal", status="past_due", provider="stripe",
                         provider_subscription_id="sub_dunning")
    assert await _tier("user-past-due") == (UserTier.personal, True)


@pytest.mark.asyncio
async def test_active_legacy_row_resolves_normally(account_store, legacy):
    legacy["row"] = dict(FREE_ROW, tier="family", provider="stripe", provider_subscription_id="sub_fam")
    assert await _tier("user-active") == (UserTier.family, True)


@pytest.mark.asyncio
async def test_cancelled_user_falls_to_free(account_store, legacy):
    legacy["row"] = dict(FREE_ROW, status="cancelled", provider="stripe")
    account_store.add_entitlement("user-cancelled", external_id="sub_old", status="cancelled")
    assert await _tier("user-cancelled") == (UserTier.free, True)


@pytest.mark.asyncio
async def test_cancelled_entitlement_beats_its_stale_legacy_copy(account_store, legacy):
    """The webhook marked the subscription cancelled in entitlements; a
    legacy row still saying active (an out-of-order event) must not win."""
    legacy["row"] = dict(FREE_ROW, tier="personal", provider="stripe", provider_subscription_id="sub_x")
    account_store.add_entitlement("u", external_id="sub_x", status="cancelled")
    assert await _tier("u") == (UserTier.free, True)


@pytest.mark.asyncio
async def test_entitlement_past_its_end_and_grace_grants_nothing(account_store, legacy):
    account_store.add_entitlement("u", source="google_play", external_id="GPA.9",
                                  status="active", period_end=_iso(days=-10))
    assert await _tier("u") == (UserTier.free, True)


@pytest.mark.asyncio
async def test_extra_device_addon_alone_is_not_a_plan(account_store, legacy):
    account_store.add_entitlement("u", source="google_play", external_id="GPA.2",
                                  plan="extra_devices", device_limit=1)
    assert await _tier("u") == (UserTier.free, True)


@pytest.mark.asyncio
async def test_unknown_plan_name_is_free(account_store, legacy):
    legacy["row"] = dict(FREE_ROW, tier="platinum", provider="stripe", provider_subscription_id="sub_p")
    assert await _tier("u") == (UserTier.free, True)


@pytest.mark.asyncio
async def test_paid_entitlement_skips_the_legacy_lookup(account_store, legacy):
    account_store.add_entitlement("u", source="app_store", external_id="2000001")
    await _tier("u")
    assert legacy["calls"] == 0


# ─── failures are reported, never a silent "free" ──────────────────


@pytest.mark.asyncio
async def test_entitlement_store_failure_is_not_an_answer(account_store, legacy):
    account_store.fail = True
    assert await _tier("u") == (UserTier.free, False)


@pytest.mark.asyncio
async def test_legacy_lookup_failure_is_not_an_answer(account_store, legacy):
    from api.services.stripe_billing import BillingError

    legacy["error"] = BillingError("subscription lookup returned 503")
    assert await _tier("u") == (UserTier.free, False)


@pytest.mark.asyncio
async def test_slow_lookup_gives_up_and_is_not_an_answer(account_store, monkeypatch):
    from api.services import auth, entitlements

    async def _slow(_account_id, **_kw):
        await asyncio.sleep(5)

    monkeypatch.setattr(entitlements, "get_effective_entitlement", _slow)
    monkeypatch.setattr(auth, "_TIER_LOOKUP_TIMEOUT", 0.01)
    assert await _tier("u") == (UserTier.free, False)


# ─── the Redis cache in front of it ────────────────────────────────


def _lookup_answering(monkeypatch, tier: UserTier, confirmed: bool) -> list[str]:
    from api.services import auth

    calls: list[str] = []

    async def _fetch(user_id):
        calls.append(user_id)
        return tier, confirmed

    monkeypatch.setattr(auth, "_fetch_tier_from_supabase", _fetch)
    return calls


@pytest.mark.asyncio
async def test_confirmed_tier_is_cached_five_minutes_and_kept_as_last_known(fake_redis, monkeypatch):
    from api.services import auth

    _lookup_answering(monkeypatch, UserTier.personal, True)
    assert await auth._resolve_user_tier("u1") == UserTier.personal
    assert fake_redis._kv["tier:u1"] == "personal"
    assert fake_redis._ttls["tier:u1"] == auth._TIER_CACHE_TTL == 300
    assert fake_redis._kv["tier_last:u1"] == "personal"
    assert fake_redis._ttls["tier_last:u1"] == auth._TIER_LAST_KNOWN_TTL


@pytest.mark.asyncio
async def test_confirmed_free_writes_no_last_known_key(fake_redis, monkeypatch):
    from api.services import auth

    _lookup_answering(monkeypatch, UserTier.free, True)
    assert await auth._resolve_user_tier("u1") == UserTier.free
    assert fake_redis._ttls["tier:u1"] == 300
    assert "tier_last:u1" not in fake_redis._kv


@pytest.mark.asyncio
async def test_failed_lookup_is_cached_for_seconds_only(fake_redis, monkeypatch):
    from api.services import auth

    _lookup_answering(monkeypatch, UserTier.free, False)
    assert await auth._resolve_user_tier("u1") == UserTier.free
    assert fake_redis._ttls["tier:u1"] == auth._TIER_FAILURE_CACHE_TTL
    assert auth._TIER_FAILURE_CACHE_TTL <= 15


@pytest.mark.asyncio
async def test_failed_lookup_keeps_the_last_confirmed_paid_tier(fake_redis, monkeypatch):
    from api.services import auth

    await fake_redis.setex("tier_last:u1", 3600, "family")
    _lookup_answering(monkeypatch, UserTier.free, False)
    assert await auth._resolve_user_tier("u1") == UserTier.family
    assert fake_redis._kv["tier:u1"] == "family"
    assert fake_redis._ttls["tier:u1"] == auth._TIER_FAILURE_CACHE_TTL


@pytest.mark.asyncio
async def test_cache_hit_skips_the_lookup(fake_redis, monkeypatch):
    from api.services import auth

    await fake_redis.setex("tier:u1", 300, "business")
    calls = _lookup_answering(monkeypatch, UserTier.free, True)
    assert await auth._resolve_user_tier("u1") == UserTier.business
    assert calls == []


@pytest.mark.asyncio
async def test_redis_down_still_resolves(redis_down, monkeypatch):
    from api.services import auth

    _lookup_answering(monkeypatch, UserTier.personal, True)
    assert await auth._resolve_user_tier("u1") == UserTier.personal


@pytest.mark.asyncio
async def test_redis_down_and_a_failed_lookup_is_free(redis_down, monkeypatch):
    from api.services import auth

    _lookup_answering(monkeypatch, UserTier.free, False)
    assert await auth._resolve_user_tier("u1") == UserTier.free

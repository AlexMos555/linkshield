"""Stripe webhook — events applied out of order (api/routers/payments.py).

Stripe does not deliver events in order and retries a failed delivery for
up to 3 days, so an older customer.subscription.updated can arrive after a
newer one. Now that the tier follows `entitlements` (api/services/auth.py),
an old delivery must not roll a subscription back:

  * the entitlement row records the Stripe `created` time of the event that
    wrote it (source_event_at, migration 024) and an OLDER update is skipped
    — neither the entitlement nor the legacy subscriptions row is touched;
  * a subscription that has ended for good (cancelled, refunded) is never
    reopened by an update: Stripe cannot reactivate a canceled subscription;
  * the Redis tier cache is dropped AFTER the entitlement write, so the next
    request reads the new plan, not the one cached in between.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from tests import test_payments_webhook as webhook_tests
from tests.test_payments_webhook import _event, _sign, _stripe_row

# The webhook suite's fixtures: Supabase + the Stripe secret configured, the
# subscriptions table and Redis recorders, the app client.
supabase_ok = webhook_tests.supabase_ok
fake_subscriptions = webhook_tests.fake_subscriptions
fake_redis = webhook_tests.fake_redis
client = webhook_tests.client

T0 = 1_790_000_000  # 2026-09-21, a Stripe `created` epoch


def _post(client, event_type: str, data: Dict[str, Any], *, event_id: str, created: Optional[int] = None):
    body = json.loads(_event(event_type, data).decode())
    body["id"] = event_id
    if created is not None:
        body["created"] = created
    payload = json.dumps(body).encode()
    return client.post("/api/v1/payments/webhook", content=payload, headers={"stripe-signature": _sign(payload)})


def _updated(status: str, sub_id: str = "sub_ord", user_id: str = "user-ord") -> Dict[str, Any]:
    return {"id": sub_id, "status": status, "customer": "cus_ord", "metadata": {"user_id": user_id}}


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def test_an_older_update_does_not_undo_a_newer_one(
    client, supabase_ok, fake_subscriptions, fake_redis, account_store
):
    newer = _post(client, "customer.subscription.updated", _updated("active"), event_id="evt_new", created=T0 + 60)
    assert newer.status_code == 200, newer.text
    row = _stripe_row(account_store, "sub_ord")
    assert row["status"] == "active"
    assert row["source_event_at"] == _iso(T0 + 60)
    writes = len(fake_subscriptions.posts)

    older = _post(client, "customer.subscription.updated", _updated("past_due"), event_id="evt_old", created=T0)
    assert older.status_code == 200, older.text
    row = _stripe_row(account_store, "sub_ord")
    assert row["status"] == "active"
    assert row["source_event_at"] == _iso(T0 + 60)
    assert len(fake_subscriptions.posts) == writes  # the legacy row is left alone too


def test_a_newer_update_applies_after_an_older_one(
    client, supabase_ok, fake_subscriptions, fake_redis, account_store
):
    _post(client, "customer.subscription.updated", _updated("active"), event_id="evt_1", created=T0)
    resp = _post(client, "customer.subscription.updated", _updated("past_due"), event_id="evt_2", created=T0 + 1)
    assert resp.status_code == 200, resp.text
    row = _stripe_row(account_store, "sub_ord")
    assert row["status"] == "past_due"
    assert row["source_event_at"] == _iso(T0 + 1)
    assert fake_subscriptions.posts[-1]["status"] == "past_due"


def test_events_from_the_same_second_both_apply(
    client, supabase_ok, fake_subscriptions, fake_redis, account_store
):
    _post(client, "customer.subscription.updated", _updated("trialing"), event_id="evt_a", created=T0)
    _post(client, "customer.subscription.updated", _updated("active"), event_id="evt_b", created=T0)
    assert _stripe_row(account_store, "sub_ord")["status"] == "active"


def test_an_update_never_reopens_a_cancelled_subscription(
    client, supabase_ok, fake_subscriptions, fake_redis, account_store
):
    account_store.add_entitlement("user-ord", external_id="sub_ord", status="cancelled")
    resp = _post(client, "customer.subscription.updated", _updated("active"), event_id="evt_late")
    assert resp.status_code == 200, resp.text
    assert _stripe_row(account_store, "sub_ord")["status"] == "cancelled"
    assert fake_subscriptions.posts == []


def test_an_update_never_reopens_a_refunded_subscription(
    client, supabase_ok, fake_subscriptions, fake_redis, account_store
):
    account_store.add_entitlement("user-ord", external_id="sub_ord", status="refunded",
                                  source_event_at=_iso(T0))
    resp = _post(client, "customer.subscription.updated", _updated("active"), event_id="evt_late2",
                 created=T0 + 3600)
    assert resp.status_code == 200, resp.text
    assert _stripe_row(account_store, "sub_ord")["status"] == "refunded"


def test_an_unreadable_entitlement_row_is_a_5xx_so_stripe_retries(
    client, supabase_ok, fake_subscriptions, fake_redis, account_store
):
    account_store.fail = True
    resp = _post(client, "customer.subscription.updated", _updated("active"), event_id="evt_down", created=T0)
    assert resp.status_code == 500
    assert fake_subscriptions.posts == []


def test_the_tier_cache_is_dropped_after_the_entitlement_write(
    client, supabase_ok, fake_subscriptions, fake_redis, account_store, monkeypatch
):
    deletions_at_write: list[int] = []
    upsert = account_store.upsert_entitlement

    async def _upsert(row):
        deletions_at_write.append(len(fake_redis.deleted))
        await upsert(row)

    monkeypatch.setattr(account_store, "upsert_entitlement", _upsert)
    resp = _post(client, "customer.subscription.updated", _updated("canceled"), event_id="evt_cache", created=T0)
    assert resp.status_code == 200, resp.text
    assert deletions_at_write, "no entitlement write"
    later = fake_redis.deleted[deletions_at_write[-1]:]
    assert "tier:user-ord" in later


# ─── the guard on its own ──────────────────────────────────────────


def test_no_store_or_no_subscription_id_is_never_stale(monkeypatch):
    import asyncio

    from api.config import get_settings
    from api.routers import payments
    from api.services import account_store as store_module

    store_module.set_account_store(None)
    monkeypatch.setattr(get_settings(), "supabase_url", "", raising=False)
    assert asyncio.run(payments._stale_subscription_event("sub_1", T0)) is False
    assert asyncio.run(payments._stale_subscription_event(None, T0)) is False


def test_an_event_without_a_created_time_is_applied(account_store):
    import asyncio

    from api.routers import payments

    account_store.add_entitlement("u", external_id="sub_t", source_event_at=_iso(T0))
    assert asyncio.run(payments._stale_subscription_event("sub_t", None)) is False
    assert asyncio.run(payments._stale_subscription_event("sub_t", T0 - 1)) is True


def test_stored_event_times_are_read_in_any_iso_form():
    from api.routers.payments import _iso_to_epoch

    assert _iso_to_epoch(_iso(T0)) == T0
    assert _iso_to_epoch("2026-09-21T13:46:40Z") == _iso_to_epoch("2026-09-21T13:46:40")
    assert _iso_to_epoch("not a time") is None
    assert _iso_to_epoch(None) is None and _iso_to_epoch("") is None

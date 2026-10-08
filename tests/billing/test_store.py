"""The store contract, run against MemoryStore always and PostgresStore when
BILLING_TEST_DATABASE_URL points at a database (the migrations are applied
to it first, which is how the SQL in api/billing/migrations/ is verified).
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio

from api.billing.models import (
    CancelChannel,
    ClaimCode,
    ClaimPurpose,
    Consent,
    ConsentKind,
    IdempotentResponse,
    Payment,
    PaymentStatus,
    Plan,
    PlanCode,
    ProviderCode,
    Seat,
    SeatRole,
    Subscription,
    SubscriptionStatus,
    Trial,
)
from api.billing.store.base import ConflictError
from api.billing.store.memory import MemoryStore

PG_URL = os.environ.get("BILLING_TEST_DATABASE_URL", "")
NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


async def _fresh_postgres():
    import asyncpg

    from api.billing.migrate import apply_migrations
    from api.billing.store.postgres import PostgresStore

    conn = await asyncpg.connect(PG_URL)
    try:
        await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        await apply_migrations(conn)
    finally:
        await conn.close()
    return await PostgresStore.connect(PG_URL, max_size=3)


@pytest_asyncio.fixture(params=["memory", "postgres"])
async def store(request):
    if request.param == "memory":
        yield MemoryStore()
        return
    if not PG_URL:
        pytest.skip("BILLING_TEST_DATABASE_URL not set")
    pg = await _fresh_postgres()
    try:
        yield pg
    finally:
        await pg.close()


async def _seed(tx):
    plan = Plan(code=PlanCode.FAMILY3, version=1, seats=3, price_kopecks=27000)
    await tx.upsert_plan(plan)
    account = await tx.create_account(display_label="Ирина")
    device = await tx.create_device(account_id=account, secret_sha256="a" * 64, platform="android",
                                    app_version="1.1.0", legacy_free=False)
    sub = await tx.create_subscription(Subscription(
        id=str(uuid.uuid4()), payer_account_id=account, plan_code=PlanCode.FAMILY3, plan_version=1,
        provider=ProviderCode.FAKE, status=SubscriptionStatus.PENDING, created_at=NOW, updated_at=NOW,
        provider_subscription_id="ref-1", msisdn_ciphertext=b"\x01" + b"x" * 40, msisdn_hmac="h" * 64, operator="t2",
    ))
    return plan, account, device, sub


@pytest.mark.asyncio
async def test_plans_devices_and_lookup_by_secret(store):
    async with store.transaction() as tx:
        plan, account, device, _ = await _seed(tx)
        assert [p.code for p in await tx.list_plans()] == [PlanCode.FAMILY3]
        assert (await tx.get_plan("family3", 1)).price_kopecks == 27000
        await tx.upsert_plan(Plan(code=PlanCode.FAMILY3, version=1, seats=3, price_kopecks=19900, active=False))
        assert await tx.list_plans() == []
        assert len(await tx.list_plans(active_only=False)) == 1
        assert (await tx.get_device(device.id)).account_id == account
        assert (await tx.get_device_by_secret_hash("a" * 64)).id == device.id
        assert await tx.get_device_by_secret_hash("b" * 64) is None
        await tx.touch_device(device.id, seen_at=NOW, app_version=None)
        touched = await tx.get_device(device.id)
        assert touched.last_seen == NOW and touched.app_version == "1.1.0"
        with pytest.raises(ConflictError):
            await tx.create_device(account_id=account, secret_sha256="a" * 64, platform="android",
                                   app_version=None, legacy_free=True)


@pytest.mark.asyncio
async def test_trials_are_one_per_fingerprint(store):
    async with store.transaction() as tx:
        _, _, device, _ = await _seed(tx)
        trial = Trial(device_fingerprint_hmac="fp", device_id=device.id, started_at=NOW, ends_at=NOW + timedelta(days=14))
        await tx.create_trial(trial)
        assert await tx.get_trial_by_fingerprint("fp") == trial
        assert (await tx.get_trial_for_device(device.id)).ends_at == trial.ends_at
        with pytest.raises(ConflictError):
            await tx.create_trial(trial)


@pytest.mark.asyncio
async def test_a_trial_follows_its_phone_to_a_new_install(store):
    async with store.transaction() as tx:
        _, account, device, _ = await _seed(tx)
        reinstalled = await tx.create_device(account_id=account, secret_sha256="b" * 64, platform="android",
                                             app_version="1.2.0", legacy_free=False)
        trial = Trial(device_fingerprint_hmac="fp", device_id=device.id, started_at=NOW, ends_at=NOW + timedelta(days=14))
        await tx.create_trial(trial)
        await tx.rebind_trial("fp", reinstalled.id)
        moved = await tx.get_trial_by_fingerprint("fp")
        assert moved.device_id == reinstalled.id and moved.ends_at == trial.ends_at
        assert await tx.get_trial_for_device(device.id) is None
        assert (await tx.get_trial_for_device(reinstalled.id)).started_at == NOW


@pytest.mark.asyncio
async def test_subscription_round_trip_and_optimistic_lock(store):
    async with store.transaction() as tx:
        _, account, _, sub = await _seed(tx)
        loaded = await tx.get_subscription(sub.id, for_update=True)
        assert loaded.msisdn_ciphertext == sub.msisdn_ciphertext and loaded.operator == "t2"
        assert loaded.row_version == 0
        from dataclasses import replace

        active = replace(loaded, status=SubscriptionStatus.ACTIVE, current_period_start=NOW,
                         current_period_end=NOW + timedelta(days=31), next_charge_at=NOW + timedelta(days=31),
                         cancel_channel=CancelChannel.APP)
        updated = await tx.update_subscription(active, expected_version=0)
        assert updated.row_version == 1 and updated.status is SubscriptionStatus.ACTIVE
        assert updated.cancel_channel is CancelChannel.APP
        with pytest.raises(ConflictError):
            await tx.update_subscription(active, expected_version=0)
        assert (await tx.get_subscription_by_provider_ref("fake", "ref-1")).id == sub.id
        assert [s.id for s in await tx.list_subscriptions_by_msisdn_hmac("h" * 64)] == [sub.id]
        assert [s.id for s in await tx.list_subscriptions_for_account(account)] == [sub.id]
        assert [s.id for s in await tx.list_due_renewals(now=NOW + timedelta(days=31))] == [sub.id]
        assert await tx.list_due_renewals(now=NOW + timedelta(days=30)) == []
        with pytest.raises(ConflictError):
            await tx.create_subscription(replace(sub, id=str(uuid.uuid4())))


@pytest.mark.asyncio
async def test_pending_and_expiring_queries(store):
    async with store.transaction() as tx:
        _, _, _, sub = await _seed(tx)
        assert [s.id for s in await tx.list_pending_older_than(cutoff=NOW)] == [sub.id]
        assert await tx.list_pending_older_than(cutoff=NOW - timedelta(seconds=1)) == []
        from dataclasses import replace

        grace = replace(sub, status=SubscriptionStatus.GRACE, grace_until=NOW + timedelta(days=7))
        await tx.update_subscription(grace, expected_version=0)
        assert await tx.list_expiring(now=NOW + timedelta(days=6)) == []
        assert [s.id for s in await tx.list_expiring(now=NOW + timedelta(days=7))] == [sub.id]
        await tx.delete_subscription(sub.id)
        assert await tx.get_subscription(sub.id) is None


@pytest.mark.asyncio
async def test_expiring_includes_fixed_term_grants_whose_term_ended(store):
    """Promo and partner grants are never renewed, so their period end is their end (2026-10 fix)."""
    from dataclasses import replace

    async with store.transaction() as tx:
        _, account, _, paid = await _seed(tx)
        end = NOW + timedelta(days=30)
        paid = await tx.update_subscription(replace(paid, status=SubscriptionStatus.ACTIVE, current_period_start=NOW,
                                                    current_period_end=end, next_charge_at=end), expected_version=0)
        grants = []
        for provider in (ProviderCode.PROMO, ProviderCode.T2_OPTION):
            grants.append(await tx.create_subscription(Subscription(
                id=str(uuid.uuid4()), payer_account_id=account, plan_code=PlanCode.FAMILY3, plan_version=1,
                provider=provider, status=SubscriptionStatus.ACTIVE, created_at=NOW, updated_at=NOW,
                provider_subscription_id=f"{provider.value}-1", current_period_start=NOW, current_period_end=end,
            )))
        assert await tx.list_expiring(now=end - timedelta(seconds=1)) == []
        assert {s.id for s in await tx.list_expiring(now=end)} == {g.id for g in grants}


@pytest.mark.asyncio
async def test_unmatched_events_are_kept_for_retry(store):
    async with store.transaction() as tx:
        unmatched = await tx.insert_event(provider="fake", provider_event_id="evt-u", signature_ok=True,
                                          payload_ciphertext=b"\x01body", event_ciphertext=b"\x01event")
        await tx.mark_event_processed(unmatched, processed_at=NOW, outcome="unmatched")
        applied = await tx.insert_event(provider="fake", provider_event_id="evt-a", signature_ok=True,
                                        payload_ciphertext=b"\x01body", event_ciphertext=b"\x01event")
        await tx.mark_event_processed(applied, processed_at=NOW, outcome="applied")
        legacy = await tx.insert_event(provider="fake", provider_event_id="evt-l", signature_ok=True,
                                       payload_ciphertext=b"\x01body")
        await tx.mark_event_processed(legacy, processed_at=NOW, outcome="unmatched")
        (row,) = await tx.list_retryable_events()
        assert row.id == unmatched and row.provider_event_id == "evt-u" and row.event_ciphertext == b"\x01event"
        assert row.attempts == 0 and row.outcome == "unmatched" and row.signature_ok is True
        await tx.retry_event(unmatched, processed_at=NOW, outcome="unmatched")
        assert (await tx.list_retryable_events())[0].attempts == 1
        await tx.retry_event(unmatched, processed_at=NOW, outcome="applied")
        assert await tx.list_retryable_events() == []


@pytest.mark.asyncio
async def test_seats_one_live_seat_per_device(store):
    async with store.transaction() as tx:
        _, account, device, sub = await _seed(tx)
        await tx.add_seat(Seat(subscription_id=sub.id, device_id=device.id, role=SeatRole.OWNER, claimed_at=NOW))
        assert (await tx.get_active_seat_for_device(device.id)).role is SeatRole.OWNER
        assert len(await tx.list_seats(sub.id)) == 1
        with pytest.raises(ConflictError):
            await tx.add_seat(Seat(subscription_id=sub.id, device_id=device.id, role=SeatRole.MEMBER, claimed_at=NOW))
        assert await tx.release_seat(sub.id, device.id, released_at=NOW) is True
        assert await tx.release_seat(sub.id, device.id, released_at=NOW) is False
        assert await tx.get_active_seat_for_device(device.id) is None
        assert await tx.list_seats(sub.id) == []
        assert len(await tx.list_seats(sub.id, active_only=False)) == 1


@pytest.mark.asyncio
async def test_claim_codes(store):
    async with store.transaction() as tx:
        _, _, device, sub = await _seed(tx)
        code = ClaimCode(id=str(uuid.uuid4()), subscription_id=sub.id, code_hmac="c" * 64, purpose=ClaimPurpose.SEAT,
                         expires_at=NOW + timedelta(hours=24))
        await tx.create_claim_code(code)
        assert (await tx.get_claim_code("c" * 64)).id == code.id
        assert await tx.get_claim_code("d" * 64) is None
        with pytest.raises(ConflictError):
            await tx.create_claim_code(code)
        assert (await tx.get_claim_code("c" * 64, for_update=True)).redeemed_at is None
        assert await tx.redeem_claim_code(code.id, device_id=device.id, redeemed_at=NOW) is True
        redeemed = await tx.get_claim_code("c" * 64)
        assert redeemed.redeemed_at == NOW and redeemed.redeemed_by_device == device.id
        # Single use: a second redemption (e.g. by a transaction holding a stale copy) changes nothing.
        assert await tx.redeem_claim_code(code.id, device_id=device.id, redeemed_at=NOW + timedelta(minutes=1)) is False
        assert (await tx.get_claim_code("c" * 64)).redeemed_at == NOW


@pytest.mark.asyncio
async def test_payments_are_idempotent_by_key(store):
    async with store.transaction() as tx:
        _, _, _, sub = await _seed(tx)
        payment = Payment(id=str(uuid.uuid4()), subscription_id=sub.id, provider=ProviderCode.FAKE,
                          idempotency_key=f"{sub.id}:20261001T120000Z:0", amount_kopecks=27000,
                          status=PaymentStatus.PENDING, created_at=NOW)
        first = await tx.create_payment(payment)
        again = await tx.create_payment(Payment(**{**payment.__dict__, "id": str(uuid.uuid4())}))
        assert again.id == first.id
        assert [p.id for p in await tx.list_pending_payments_older_than(cutoff=NOW)] == [first.id]
        from dataclasses import replace

        await tx.update_payment(replace(first, status=PaymentStatus.SUCCEEDED, provider_payment_id="pp-1",
                                        period_start=NOW, period_end=NOW + timedelta(days=31)))
        assert (await tx.get_payment(first.id)).status is PaymentStatus.SUCCEEDED
        assert (await tx.get_payment_by_provider_id("fake", "pp-1")).id == first.id
        assert (await tx.get_payment_by_idempotency_key(payment.idempotency_key)).provider_payment_id == "pp-1"
        assert await tx.list_pending_payments_older_than(cutoff=NOW) == []
        assert len(await tx.list_payments(sub.id)) == 1


@pytest.mark.asyncio
async def test_events_consents_audit_idempotency(store):
    async with store.transaction() as tx:
        _, account, _, sub = await _seed(tx)
        first = await tx.insert_event(provider="fake", provider_event_id="evt-1", signature_ok=True, payload_ciphertext=b"\x01x")
        assert isinstance(first, int)
        assert await tx.insert_event(provider="fake", provider_event_id="evt-1", signature_ok=True, payload_ciphertext=b"\x01x") is None
        await tx.mark_event_processed(first, processed_at=NOW, outcome="applied")

        consent = await tx.add_consent(Consent(
            id=0, account_id=account, subscription_id=sub.id, kind=ConsentKind.SUBSCRIPTION_OFFER, doc_version="ru/v1",
            doc_sha256="s" * 64, method="sms_code", created_at=NOW, shown_price_kopecks=27000,
            shown_plan_code=PlanCode.FAMILY3, ip_hmac="i" * 16,
        ))
        assert consent.id > 0
        listed = await tx.list_consents(account)
        assert listed[0].shown_plan_code is PlanCode.FAMILY3 and listed[0].doc_sha256 == "s" * 64

        row = await tx.add_audit(actor="system", action="subscription.activated", target=f"subscription:{sub.id}", meta={"k": 1})
        assert row.meta == {"k": 1}
        assert [a.action for a in await tx.list_audit(f"subscription:{sub.id}")] == ["subscription.activated"]

        stored = IdempotentResponse(scope="dev", key="k1", status_code=200, body={"ok": True}, created_at=NOW)
        await tx.put_idempotent_response(stored)
        await tx.put_idempotent_response(IdempotentResponse(scope="dev", key="k1", status_code=500, body={}, created_at=NOW))
        assert (await tx.get_idempotent_response("dev", "k1")).status_code == 200
        assert await tx.get_idempotent_response("dev", "k2") is None


@pytest.mark.asyncio
async def test_idempotency_key_reservation(store):
    stale_before = NOW - timedelta(minutes=5)
    async with store.transaction() as tx:
        # First caller reserves; a contender sees the in-progress row.
        assert await tx.reserve_idempotency_key("dev", "k", now=NOW, stale_before=stale_before) is None
        held = await tx.reserve_idempotency_key("dev", "k", now=NOW, stale_before=stale_before)
        assert held is not None and held.in_progress
        # Completing it stores the answer; a later reservation replays it.
        await tx.put_idempotent_response(IdempotentResponse(scope="dev", key="k", status_code=201, body={"ok": True},
                                                            created_at=NOW))
        done = await tx.reserve_idempotency_key("dev", "k", now=NOW + timedelta(hours=1), stale_before=NOW + timedelta(minutes=55))
        assert done is not None and not done.in_progress and done.status_code == 201 and dict(done.body) == {"ok": True}
        # A completed answer is never released.
        await tx.release_idempotency_key("dev", "k")
        assert (await tx.get_idempotent_response("dev", "k")).status_code == 201

        # A failed attempt releases its reservation; the key is free again.
        assert await tx.reserve_idempotency_key("dev", "k2", now=NOW, stale_before=stale_before) is None
        await tx.release_idempotency_key("dev", "k2")
        assert await tx.get_idempotent_response("dev", "k2") is None
        assert await tx.reserve_idempotency_key("dev", "k2", now=NOW, stale_before=stale_before) is None
        # An abandoned reservation (older than stale_before) is taken over.
        later = NOW + timedelta(minutes=10)
        assert await tx.reserve_idempotency_key("dev", "k2", now=later, stale_before=later - timedelta(minutes=5)) is None


@pytest.mark.asyncio
async def test_transaction_rolls_back_on_error(store):
    with pytest.raises(RuntimeError):
        async with store.transaction() as tx:
            await _seed(tx)
            raise RuntimeError("boom")
    async with store.transaction() as tx:
        assert await tx.list_plans(active_only=False) == []


@pytest.mark.asyncio
async def test_migrations_are_recorded_once():
    if not PG_URL:
        pytest.skip("BILLING_TEST_DATABASE_URL not set")
    import asyncpg

    from api.billing.migrate import apply_migrations, migration_files

    names = [p.name for p in migration_files()]
    assert names[0].startswith("001_")
    conn = await asyncpg.connect(PG_URL)
    try:
        await conn.execute("DROP SCHEMA public CASCADE; CREATE SCHEMA public;")
        assert list(await apply_migrations(conn)) == names
        assert list(await apply_migrations(conn)) == []
        purged = await conn.fetchval("SELECT billing_purge_msisdn()")
        assert purged == 0
    finally:
        await conn.close()

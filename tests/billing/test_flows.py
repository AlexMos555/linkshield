"""End-to-end flows through the service layer on the in-memory store:
trial → checkout → webhook → pass; no money → grace → retries → lapsed → basic;
cancel → the scheduler never charges; codes and the race for the last seat;
webhook redelivery = one effect; cancel-by-phone; promo; legacy; reconciliation.
"""
from __future__ import annotations

import asyncio
from datetime import timedelta

import pytest

from api.billing import scheduler
from api.billing.entitlement import Keyring
from api.billing.models import (
    ConsentKind,
    EntitlementSource,
    FailureReason,
    PaymentStatus,
    ProtectionMode,
    SubscriptionStatus as S,
)
from api.billing.providers.fake import PENDING_FOREVER
from api.billing.service import cancel as cancel_service
from api.billing.service import checkout as checkout_service
from api.billing.service import seats as seat_service
from api.billing.service import trial as trial_service
from api.billing.service.devices import authenticate, register_device
from api.billing.service.errors import Conflict, Forbidden, Invalid, NotFound, Unauthorized
from api.billing.service.passes import compute_entitlement
from api.billing.service.webhooks import ingest_webhook
from api.billing.state_machine import add_months
from tests.billing.conftest import NO_MONEY_NUMBER, SUCCESS_NUMBER, T0, make_settings

CONSENT = "ru/v1"


async def _device(ctx, *, legacy=False):
    device, secret = await register_device(ctx, platform="android", app_version="1.1.0", legacy_claim=legacy)
    return device, secret


async def _subscribe(ctx, fake, device, *, plan="family3", number=SUCCESS_NUMBER):
    """Checkout + the provider's success webhook → an active subscription."""
    result = await checkout_service.start_checkout(ctx, device, plan_code=plan, provider_code="fake", msisdn=number,
                                                   consent_doc_version=CONSENT, ip="10.0.0.1")
    ref = await _provider_ref(ctx, result["checkout_id"])
    await _deliver(ctx, fake, fake.event_payload(ref, payment_id=f"pay_{ref}"))
    return result["checkout_id"]


async def _provider_ref(ctx, sub_id):
    async with ctx.store.transaction() as tx:
        return (await tx.get_subscription(sub_id)).provider_subscription_id


async def _deliver(ctx, fake, payload):
    headers, body = fake.sign(payload)
    return await ingest_webhook(ctx, provider_code="fake", headers=headers, body=body)


async def _sub(ctx, sub_id):
    async with ctx.store.transaction() as tx:
        return await tx.get_subscription(sub_id)


async def _audit_actions(ctx, sub_id):
    async with ctx.store.transaction() as tx:
        return [a.action for a in await tx.list_audit(f"subscription:{sub_id}")]


# ── Devices and trial ──


@pytest.mark.asyncio
async def test_register_and_authenticate(ctx):
    device, secret = await _device(ctx)
    assert (await authenticate(ctx, secret, app_version="1.1.1")).id == device.id
    with pytest.raises(Unauthorized):
        await authenticate(ctx, "wrong")
    with pytest.raises(Unauthorized):
        await authenticate(ctx, None)
    with pytest.raises(Invalid):
        await register_device(ctx, platform="windows", app_version=None, legacy_claim=False)


@pytest.mark.asyncio
async def test_trial_gives_full_protection_then_the_lapse_policy(ctx, clock):
    device, _ = await _device(ctx)
    before = await compute_entitlement(ctx, device)
    assert before.claims.mode is ProtectionMode.BASIC and before.claims.src is EntitlementSource.NONE
    assert "basic_mode" in before.status["notices"]
    trial = await trial_service.start_trial(ctx, device, fingerprint_input="android-id-1")
    assert trial.ends_at == T0 + timedelta(days=14)
    ent = await compute_entitlement(ctx, device)
    assert ent.claims.mode is ProtectionMode.FULL and ent.claims.src is EntitlementSource.TRIAL
    assert ent.claims.until == int(trial.ends_at.timestamp()) and ent.claims.grace_until is None
    assert ent.claims.exp == ent.claims.iat + 7 * 86400
    assert Keyring({ctx.signer.kid: ctx.signer.public_key_b64}).verify(ent.token, ent.claims.iat) == ent.claims
    clock.advance(days=11)
    assert "trial_ending" in (await compute_entitlement(ctx, device)).status["notices"]
    clock.advance(days=3)
    after = await compute_entitlement(ctx, device)
    assert after.claims.mode is ProtectionMode.BASIC and after.status["trial_used"] is True


@pytest.mark.asyncio
async def test_trial_is_one_per_phone_and_survives_reinstall(ctx):
    device, _ = await _device(ctx)
    first = await trial_service.start_trial(ctx, device, fingerprint_input="android-id-1")
    assert await trial_service.start_trial(ctx, device, fingerprint_input="android-id-1") == first
    reinstalled, _ = await _device(ctx)
    # Reinstall: the same trial (same dates) follows the phone, never a second one (docs/BILLING.md).
    again = await trial_service.start_trial(ctx, reinstalled, fingerprint_input="android-id-1")
    assert (again.started_at, again.ends_at, again.device_id) == (first.started_at, first.ends_at, reinstalled.id)
    with pytest.raises(Invalid):
        await trial_service.start_trial(ctx, device, fingerprint_input="")


@pytest.mark.asyncio
async def test_lapse_policy_off_turns_protection_off(clock, fake):
    from api.billing.context import build_context, ensure_plans
    from api.billing.providers.promo import PromoProvider
    from api.billing.store.memory import MemoryStore

    ctx = build_context(make_settings(billing_lapse_policy="off"), MemoryStore(), {"fake": fake, "promo": PromoProvider()}, clock=clock)
    await ensure_plans(ctx)
    device, _ = await _device(ctx)
    ent = await compute_entitlement(ctx, device)
    assert ent.claims.mode is ProtectionMode.OFF and "protection_off" in ent.status["notices"]


@pytest.mark.asyncio
async def test_legacy_install_stays_full_forever(ctx, clock):
    device, _ = await _device(ctx, legacy=True)
    clock.advance(days=400)
    ent = await compute_entitlement(ctx, device)
    assert ent.claims.mode is ProtectionMode.FULL and ent.claims.src is EntitlementSource.LEGACY
    assert ent.claims.until is None


# ── Checkout → webhook → pass ──


@pytest.mark.asyncio
async def test_checkout_then_success_webhook_gives_a_full_pass(ctx, fake):
    device, _ = await _device(ctx)
    result = await checkout_service.start_checkout(ctx, device, plan_code="family3", provider_code="fake",
                                                   msisdn="8 915 000-00-00", consent_doc_version=CONSENT, ip="10.0.0.1")
    assert result["kind"] == "await_sms" and result["status"] == "pending"
    sub_id = result["checkout_id"]
    poll = await checkout_service.get_checkout(ctx, device, sub_id)
    assert poll["status"] == "pending" and poll["failure_reason"] is None
    # Before the SMS, the pass is unchanged (trial-less device → basic).
    assert (await compute_entitlement(ctx, device)).claims.mode is ProtectionMode.BASIC

    ref = await _provider_ref(ctx, sub_id)
    status, ack = await _deliver(ctx, fake, fake.event_payload(ref, payment_id="pay-1"))
    assert (status, ack) == (200, {"success": True})
    sub = await _sub(ctx, sub_id)
    assert sub.status is S.ACTIVE and sub.current_period_end == add_months(T0, 1)
    assert sub.msisdn_ciphertext is not None and ctx.cipher.decrypt(sub.msisdn_ciphertext) == SUCCESS_NUMBER
    assert sub.msisdn_hmac == ctx.hasher.msisdn(SUCCESS_NUMBER)

    ent = await compute_entitlement(ctx, device)
    assert ent.claims.mode is ProtectionMode.FULL and ent.claims.src is EntitlementSource.SUBSCRIPTION
    assert ent.claims.plan == "family3" and ent.claims.until == int(sub.current_period_end.timestamp())
    assert ent.claims.grace_until == int((sub.current_period_end + timedelta(days=7)).timestamp())
    assert ent.status["subscription"]["seats_used"] == 1 and ent.status["subscription"]["seats_total"] == 3
    assert ent.status["subscription"]["is_payer"] is True
    assert "+7915" not in ent.token and "9150000000" not in str(ent.status)

    async with ctx.store.transaction() as tx:
        consents = await tx.list_consents(device.account_id)
        payments = await tx.list_payments(sub_id)
    assert len(consents) == 1 and consents[0].kind is ConsentKind.SUBSCRIPTION_OFFER
    assert consents[0].shown_price_kopecks == 27000 and consents[0].doc_version == "ru/v1"
    assert len(consents[0].doc_sha256) == 64 and consents[0].ip_hmac == ctx.hasher.ip("10.0.0.1")
    assert payments[0].status is PaymentStatus.SUCCEEDED and payments[0].provider_payment_id == "pay-1"
    assert (await checkout_service.get_checkout(ctx, device, sub_id))["status"] == "active"


@pytest.mark.asyncio
async def test_checkout_validation(ctx, fake):
    device, _ = await _device(ctx)
    kw = dict(plan_code="solo", provider_code="fake", msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    with pytest.raises(Invalid, match="consent"):
        await checkout_service.start_checkout(ctx, device, **{**kw, "consent_doc_version": "ru/v0"})
    with pytest.raises(Invalid, match="phone"):
        await checkout_service.start_checkout(ctx, device, **{**kw, "msisdn": None})
    with pytest.raises(Invalid, match="Russian"):
        await checkout_service.start_checkout(ctx, device, **{**kw, "msisdn": "+1 415 555 0100"})
    with pytest.raises(Invalid, match="provider"):
        await checkout_service.start_checkout(ctx, device, **{**kw, "provider_code": "promo"})
    with pytest.raises(Invalid, match="provider"):
        await checkout_service.start_checkout(ctx, device, **{**kw, "provider_code": "t2_direct"})
    with pytest.raises(Invalid, match="plan"):
        await checkout_service.start_checkout(ctx, device, **{**kw, "plan_code": "gold"})
    await _subscribe(ctx, fake, device, plan="solo")
    with pytest.raises(Conflict, match="already"):
        await checkout_service.start_checkout(ctx, device, **kw)
    with pytest.raises(NotFound):
        await checkout_service.get_checkout(ctx, device, "not-a-uuid")


@pytest.mark.asyncio
async def test_no_money_at_checkout_deletes_the_subscription_and_keeps_the_reason(ctx, fake):
    device, _ = await _device(ctx)
    result = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                                   msisdn=NO_MONEY_NUMBER, consent_doc_version=CONSENT)
    ref = await _provider_ref(ctx, result["checkout_id"])
    status, _ = await _deliver(ctx, fake, fake.event_payload(ref, outcome=FailureReason.NO_MONEY))
    assert status == 200
    assert await _sub(ctx, result["checkout_id"]) is None
    poll = await checkout_service.get_checkout(ctx, device, result["checkout_id"])
    assert poll["status"] == "failed" and poll["failure_reason"] == "no_money"
    other, _ = await _device(ctx)
    with pytest.raises(NotFound):
        await checkout_service.get_checkout(ctx, other, result["checkout_id"])
    # The phone is free to try again (its owner seat was released with the row).
    again = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                                  msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    assert again["status"] == "pending"


@pytest.mark.asyncio
async def test_webhook_redelivery_has_one_effect(ctx, fake):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device)
    ref = await _provider_ref(ctx, sub_id)
    before = await _sub(ctx, sub_id)
    actions_before = await _audit_actions(ctx, sub_id)
    status, _ = await _deliver(ctx, fake, fake.event_payload(ref, payment_id=f"pay_{ref}"))
    assert status == 200
    assert await _sub(ctx, sub_id) == before
    assert await _audit_actions(ctx, sub_id) == actions_before
    # A NEW event id for the same payment does not extend the period either (no charge pending).
    status, _ = await _deliver(ctx, fake, fake.event_payload(ref, payment_id=f"pay_{ref}", event_id="evt-dup-2"))
    assert (await _sub(ctx, sub_id)).current_period_end == before.current_period_end
    assert "payment.unexpected_success" in await _audit_actions(ctx, sub_id)


@pytest.mark.asyncio
async def test_webhook_bad_signature_is_recorded_not_applied(ctx, fake):
    device, _ = await _device(ctx)
    result = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                                   msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    ref = await _provider_ref(ctx, result["checkout_id"])
    _, body = fake.sign(fake.event_payload(ref))
    status, payload = await ingest_webhook(ctx, provider_code="fake", headers={"x-fake-signature": "0" * 64}, body=body)
    assert status == 400 and payload["error"]["code"] == "invalid_signature"
    assert (await _sub(ctx, result["checkout_id"])).status is S.PENDING
    assert any(not row["signature_ok"] for row in ctx.store.tables.events.values())
    assert (await ingest_webhook(ctx, provider_code="nobody", headers={}, body=b"{}"))[0] == 404
    assert (await ingest_webhook(ctx, provider_code="t2_direct", headers={}, body=b"{}"))[0] == 503
    assert (await ingest_webhook(ctx, provider_code="fake", headers={}, body=b"x" * 70000))[0] == 413
    # An event for a subscription we do not know is answered 200 and recorded as unmatched.
    status, _ = await _deliver(ctx, fake, fake.event_payload("fake_unknown", payment_id="ghost"))
    assert status == 200


# ── Renewals, grace, lapse ──


@pytest.mark.asyncio
async def test_no_money_at_renewal_grace_retries_then_basic_mode(ctx, fake, clock):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")
    period_end = (await _sub(ctx, sub_id)).current_period_end
    assert await scheduler.run_renewals(ctx, clock.now) == 0          # not due yet
    clock.now = period_end
    assert await scheduler.run_renewals(ctx, clock.now) == 1
    assert len(fake.renewals) == 1 and fake.renewals[0]["amount_kopecks"] == 9900
    assert await scheduler.run_renewals(ctx, clock.now) == 0          # charge pending: never twice
    charged = await _sub(ctx, sub_id)
    assert charged.charge_pending is True
    async with ctx.store.transaction() as tx:
        payments = await tx.list_payments(sub_id)
    assert payments[-1].idempotency_key.endswith(":0") and payments[-1].provider_payment_id == fake.renewals[0]["payment_id"]

    await _deliver(ctx, fake, fake.event_payload(charged.provider_subscription_id, outcome=FailureReason.NO_MONEY,
                                                 payment_id=fake.renewals[0]["payment_id"], event_id="evt-fail-1"))
    grace = await _sub(ctx, sub_id)
    assert grace.status is S.GRACE and grace.grace_until == period_end + timedelta(days=7)
    assert grace.next_charge_at == period_end + timedelta(days=1)
    ent = await compute_entitlement(ctx, device)
    assert ent.claims.mode is ProtectionMode.FULL and "payment_failed_grace" in ent.status["notices"]
    assert ent.claims.grace_until == int(grace.grace_until.timestamp())

    # Retries on days 1, 3, 5, 7 — each one charge, each one failure.
    for n, day in enumerate((1, 3, 5, 7), start=1):
        clock.now = period_end + timedelta(days=day)
        assert await scheduler.run_renewals(ctx, clock.now) == 1
        current = await _sub(ctx, sub_id)
        await _deliver(ctx, fake, fake.event_payload(current.provider_subscription_id, outcome=FailureReason.NO_MONEY,
                                                     payment_id=fake.renewals[-1]["payment_id"], event_id=f"evt-fail-{n + 1}"))
    assert len(fake.renewals) == 5
    assert (await _sub(ctx, sub_id)).next_charge_at is None
    assert await scheduler.run_expiries(ctx, period_end + timedelta(days=6, hours=23)) == 0
    clock.now = period_end + timedelta(days=7)
    assert await scheduler.run_expiries(ctx, clock.now) == 1
    lapsed = await _sub(ctx, sub_id)
    assert lapsed.status is S.LAPSED
    ent = await compute_entitlement(ctx, device)
    assert ent.claims.mode is ProtectionMode.BASIC and ent.claims.src is EntitlementSource.NONE
    assert "device_mode.basic" in await _audit_actions(ctx, sub_id)
    # Lapsed → a new checkout is allowed.
    again = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                                  msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    assert again["status"] == "pending" and again["checkout_id"] != sub_id


@pytest.mark.asyncio
async def test_renewal_success_extends_the_period(ctx, fake, clock):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")
    period_end = (await _sub(ctx, sub_id)).current_period_end
    clock.now = period_end
    await scheduler.run_renewals(ctx, clock.now)
    sub = await _sub(ctx, sub_id)
    await _deliver(ctx, fake, fake.event_payload(sub.provider_subscription_id, payment_id=fake.renewals[0]["payment_id"],
                                                 event_id="evt-renew-1"))
    renewed = await _sub(ctx, sub_id)
    assert renewed.status is S.ACTIVE and renewed.current_period_start == period_end
    assert renewed.current_period_end == add_months(period_end, 1) and renewed.charge_pending is False


@pytest.mark.asyncio
async def test_cancel_stops_charges_and_lapses_at_period_end(ctx, fake, clock):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")
    result = await cancel_service.cancel_subscription(ctx, device)
    sub = await _sub(ctx, sub_id)
    assert result["status"] == "cancel_at_period_end" and sub.next_charge_at is None
    assert fake.cancelled == [sub.provider_subscription_id]
    # Idempotent second cancel.
    assert (await cancel_service.cancel_subscription(ctx, device))["status"] == "cancel_at_period_end"
    ent = await compute_entitlement(ctx, device)
    assert ent.claims.mode is ProtectionMode.FULL and "cancelled_until_period_end" in ent.status["notices"]
    async with ctx.store.transaction() as tx:
        consents = await tx.list_consents(device.account_id)
    assert [c.kind for c in consents] == [ConsentKind.SUBSCRIPTION_OFFER, ConsentKind.CANCEL]
    clock.now = sub.current_period_end + timedelta(days=30)
    assert await scheduler.run_renewals(ctx, clock.now) == 0 and fake.renewals == []
    assert await scheduler.run_expiries(ctx, clock.now) == 1
    assert (await _sub(ctx, sub_id)).status is S.LAPSED
    assert (await compute_entitlement(ctx, device)).claims.mode is ProtectionMode.BASIC


@pytest.mark.asyncio
async def test_cancel_requires_a_subscription_and_the_payer(ctx, fake):
    device, _ = await _device(ctx)
    with pytest.raises(NotFound):
        await cancel_service.cancel_subscription(ctx, device)
    await _subscribe(ctx, fake, device)
    code = (await seat_service.create_claim_code(ctx, device))["code"]
    member, _ = await _device(ctx)
    await seat_service.redeem_claim_code(ctx, member, code=code)
    with pytest.raises(Forbidden):
        await cancel_service.cancel_subscription(ctx, member)


@pytest.mark.asyncio
async def test_cancel_by_phone_is_the_same_answer_for_everyone(ctx, fake):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, number="+79161234567")
    assert await cancel_service.cancel_by_phone(ctx, msisdn="+79990000000", ip="1.2.3.4") is None
    assert (await _sub(ctx, sub_id)).status is S.ACTIVE
    assert await cancel_service.cancel_by_phone(ctx, msisdn="8 (916) 123-45-67", ip="1.2.3.4") is None
    assert (await _sub(ctx, sub_id)).status is S.CANCEL_AT_PERIOD_END
    with pytest.raises(Invalid):
        await cancel_service.cancel_by_phone(ctx, msisdn="+1 415 555 0100", ip=None)


# ── Seats and codes ──


@pytest.mark.asyncio
async def test_claim_codes_fill_seats_and_stop_at_the_plan_limit(ctx, fake, clock):
    owner, _ = await _device(ctx)
    await _subscribe(ctx, fake, owner, plan="family3")
    issued = await seat_service.create_claim_code(ctx, owner)
    assert issued["qr_payload"] == "cleanway://claim?code=" + issued["code"] and issued["seats_used"] == 1
    assert issued["expires_at"] == int((T0 + timedelta(hours=24)).timestamp())
    assert issued["code"] not in str(ctx.store.tables.claim_codes)

    mom, _ = await _device(ctx)
    joined = await seat_service.redeem_claim_code(ctx, mom, code=issued["code"])
    assert joined["seats_used"] == 2 and joined["plan"] == "family3"
    ent = await compute_entitlement(ctx, mom)
    assert ent.claims.mode is ProtectionMode.FULL and ent.status["subscription"]["is_payer"] is False
    with pytest.raises(Conflict, match="covered by a subscription"):
        await trial_service.start_trial(ctx, mom, fingerprint_input="mom-phone")
    # A code is single-use: a second redemption is refused for everyone, the same phone included.
    stranger, _ = await _device(ctx)
    for phone in (stranger, mom):
        with pytest.raises(NotFound, match="not valid"):
            await seat_service.redeem_claim_code(ctx, phone, code=issued["code"])
    # A phone already in the subscription presenting a fresh code takes no seat and burns no code.
    fresh = (await seat_service.create_claim_code(ctx, owner))["code"]
    assert (await seat_service.redeem_claim_code(ctx, mom, code=fresh))["seats_used"] == 2
    assert all(c.redeemed_at is None for c in ctx.store.tables.claim_codes.values() if c.code_hmac == ctx.hasher.claim_code(fresh))
    with pytest.raises(NotFound, match="not valid"):
        await seat_service.redeem_claim_code(ctx, stranger, code="000000")
    with pytest.raises(Invalid):
        await seat_service.redeem_claim_code(ctx, stranger, code="12a456")
    with pytest.raises(Forbidden):
        await seat_service.create_claim_code(ctx, mom)

    listing = await seat_service.list_devices(ctx, owner)
    assert listing["seats_used"] == 2 and {d["role"] for d in listing["devices"]} == {"owner", "member"}
    dad, _ = await _device(ctx)
    await seat_service.redeem_claim_code(ctx, dad, code=(await seat_service.create_claim_code(ctx, owner))["code"])
    with pytest.raises(Conflict, match="no free seats"):
        await seat_service.create_claim_code(ctx, owner)
    await seat_service.remove_seat(ctx, owner, device_id=dad.id)
    assert (await compute_entitlement(ctx, dad)).claims.mode is ProtectionMode.BASIC
    with pytest.raises(NotFound):
        await seat_service.remove_seat(ctx, owner, device_id=dad.id)
    with pytest.raises(Forbidden):
        await seat_service.remove_seat(ctx, mom, device_id=owner.id)
    with pytest.raises(NotFound):
        await seat_service.list_devices(ctx, dad)
    # Expired code.
    late = await seat_service.create_claim_code(ctx, owner)
    clock.advance(hours=24)
    with pytest.raises(NotFound, match="not valid"):
        await seat_service.redeem_claim_code(ctx, dad, code=late["code"])


@pytest.mark.asyncio
async def test_race_for_the_last_seat_admits_exactly_one(ctx, fake):
    owner, _ = await _device(ctx)
    await _subscribe(ctx, fake, owner, plan="family3")
    codes = [(await seat_service.create_claim_code(ctx, owner))["code"] for _ in range(3)]
    phones = [(await _device(ctx))[0] for _ in range(3)]
    await seat_service.redeem_claim_code(ctx, phones[0], code=codes[0])
    results = await asyncio.gather(
        seat_service.redeem_claim_code(ctx, phones[1], code=codes[1]),
        seat_service.redeem_claim_code(ctx, phones[2], code=codes[2]),
        return_exceptions=True,
    )
    winners = [r for r in results if isinstance(r, dict)]
    losers = [r for r in results if isinstance(r, Conflict)]
    assert len(winners) == 1 and len(losers) == 1 and losers[0].code == "no_free_seats"
    assert (await seat_service.list_devices(ctx, owner))["seats_used"] == 3


@pytest.mark.asyncio
async def test_member_of_a_lapsed_subscription_can_start_their_own(ctx, fake, clock):
    owner, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, owner, plan="family3")
    mom, _ = await _device(ctx)
    await seat_service.redeem_claim_code(ctx, mom, code=(await seat_service.create_claim_code(ctx, owner))["code"])
    await cancel_service.cancel_subscription(ctx, owner)
    clock.now = (await _sub(ctx, sub_id)).current_period_end
    await scheduler.run_expiries(ctx, clock.now)
    assert (await compute_entitlement(ctx, mom)).claims.mode is ProtectionMode.BASIC
    own = await checkout_service.start_checkout(ctx, mom, plan_code="solo", provider_code="fake", msisdn=SUCCESS_NUMBER,
                                                consent_doc_version=CONSENT)
    assert own["status"] == "pending"


# ── Promo, reconciliation, timeouts ──


@pytest.mark.asyncio
async def test_promo_grant_activates_immediately(ctx):
    device, _ = await _device(ctx)
    result = await checkout_service.start_checkout(ctx, device, plan_code="family5", provider_code="promo", msisdn=None,
                                                   consent_doc_version=CONSENT, consent_method="support", allow_grant=True)
    assert result["kind"] == "granted" and result["status"] == "active"
    ent = await compute_entitlement(ctx, device)
    assert ent.claims.mode is ProtectionMode.FULL and ent.claims.src is EntitlementSource.PROMO and ent.claims.plan == "family5"
    async with ctx.store.transaction() as tx:
        payments = await tx.list_payments(result["checkout_id"])
    assert payments[0].amount_kopecks == 0 and payments[0].status is PaymentStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_reconciliation_settles_a_checkout_whose_webhook_was_lost(ctx, fake, clock):
    device, _ = await _device(ctx)
    result = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                                   msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    assert await scheduler.run_reconciliation(ctx, clock.now) == 0          # too early
    clock.advance(minutes=31)
    assert await scheduler.run_reconciliation(ctx, clock.now) == 1
    assert (await _sub(ctx, result["checkout_id"])).status is S.ACTIVE
    assert await scheduler.run_reconciliation(ctx, clock.now) == 0          # nothing pending any more


@pytest.mark.asyncio
async def test_pending_checkout_times_out_and_run_once_reports_counts(ctx, fake, clock):
    device, _ = await _device(ctx)
    result = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                                   msisdn=PENDING_FOREVER, consent_doc_version=CONSENT)
    clock.advance(minutes=29)
    assert await scheduler.run_pending_timeouts(ctx, clock.now) == 0
    clock.advance(minutes=1)
    counts = await scheduler.run_once(ctx, clock.now)
    assert counts == {"pending_timeouts": 1, "renewals": 0, "expiries": 0, "reconciled": 0, "unmatched_applied": 0}
    assert await _sub(ctx, result["checkout_id"]) is None
    assert (await checkout_service.get_checkout(ctx, device, result["checkout_id"]))["failure_reason"] == "timeout"


@pytest.mark.asyncio
async def test_renewal_provider_unreachable_leaves_the_charge_pending_for_reconciliation(ctx, fake, clock):
    from api.billing.providers.base import ProviderUnavailable

    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")
    clock.now = (await _sub(ctx, sub_id)).current_period_end

    async def boom(**kwargs):
        raise ProviderUnavailable("down")

    fake.charge_renewal = boom
    assert await scheduler.run_renewals(ctx, clock.now) == 0
    sub = await _sub(ctx, sub_id)
    # The request may have reached the aggregator: no second call, the reconciler asks by our payment id.
    assert sub.charge_pending is True and sub.status is S.ACTIVE
    assert "charge.provider_error" in await _audit_actions(ctx, sub_id)
    assert await scheduler.run_renewals(ctx, clock.now) == 0


@pytest.mark.asyncio
async def test_provider_initiated_renewals_are_left_to_the_provider(ctx, clock):
    device, _ = await _device(ctx)
    result = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="promo", msisdn=None,
                                                   consent_doc_version=CONSENT, allow_grant=True)
    clock.now = (await _sub(ctx, result["checkout_id"])).current_period_end + timedelta(days=1)
    assert await scheduler.run_renewals(ctx, clock.now) == 0


# ── Review fixes (PR #65) ──


@pytest.mark.asyncio
async def test_lost_webhook_checkout_is_reconciled_not_timed_out(ctx, fake, clock):
    """The provider took the money but the webhook never came: the pass must reconcile, not delete."""
    device, _ = await _device(ctx)
    result = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                                   msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    clock.advance(minutes=31)
    counts = await scheduler.run_once(ctx, clock.now)
    assert counts["pending_timeouts"] == 0 and counts["reconciled"] == 1
    sub = await _sub(ctx, result["checkout_id"])
    assert sub is not None and sub.status is S.ACTIVE
    async with ctx.store.transaction() as tx:
        payments = await tx.list_payments(sub.id)
    assert [p.status for p in payments] == [PaymentStatus.SUCCEEDED]


@pytest.mark.asyncio
async def test_pending_timeout_asks_the_provider_before_closing(ctx, fake, clock):
    """Even on its own (a timeout shorter than the reconciliation delay), the timeout pass reconciles first."""
    device, _ = await _device(ctx)
    result = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                                   msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    clock.advance(minutes=30)
    assert await scheduler.run_pending_timeouts(ctx, clock.now) == 0
    assert (await _sub(ctx, result["checkout_id"])).status is S.ACTIVE


@pytest.mark.asyncio
async def test_pending_timeout_keeps_the_checkout_while_the_provider_is_unreachable(ctx, fake, clock):
    from api.billing.providers.base import ProviderUnavailable

    device, _ = await _device(ctx)
    result = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                                   msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)

    async def down(**kwargs):
        raise ProviderUnavailable("down")

    fake.fetch_status = down
    clock.advance(minutes=31)
    assert await scheduler.run_pending_timeouts(ctx, clock.now) == 0
    assert (await _sub(ctx, result["checkout_id"])).status is S.PENDING


@pytest.mark.asyncio
async def test_renewal_charges_the_subscribed_plan_version_not_the_new_price(ctx, fake, clock):
    from dataclasses import replace

    from api.billing.context import ensure_plans
    from api.billing.models import PlanCode

    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")              # 99 ₽, plan version 1
    repriced = replace(ctx, settings=ctx.settings.model_copy(
        update={"billing_price_solo_rub": 149, "billing_plan_version": 2}))
    await ensure_plans(repriced)
    assert repriced.plan(PlanCode.SOLO).version == 2 and repriced.plan(PlanCode.SOLO).price_kopecks == 14900
    assert (await compute_entitlement(repriced, device)).status["subscription"]["price_kopecks"] == 9900
    clock.now = (await _sub(ctx, sub_id)).current_period_end
    assert await scheduler.run_renewals(repriced, clock.now) == 1
    assert fake.renewals[-1]["amount_kopecks"] == 9900
    async with ctx.store.transaction() as tx:
        renewal = [p for p in await tx.list_payments(sub_id) if p.period_start is not None][-1]
    assert renewal.amount_kopecks == 9900


@pytest.mark.asyncio
async def test_a_price_change_without_a_new_plan_version_is_refused(ctx):
    from dataclasses import replace

    from api.billing.context import ensure_plans
    from api.config import ConfigError

    repriced = replace(ctx, settings=ctx.settings.model_copy(update={"billing_price_solo_rub": 149}))
    with pytest.raises(ConfigError, match="BILLING_PLAN_VERSION"):
        await ensure_plans(repriced)


@pytest.mark.asyncio
async def test_checkout_passes_the_configured_return_url(ctx, fake):
    seen = {}
    original = fake.start_checkout

    async def recording(**kwargs):
        seen.update(kwargs)
        return await original(**kwargs)

    fake.start_checkout = recording
    device, _ = await _device(ctx)
    await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake", msisdn=SUCCESS_NUMBER,
                                          consent_doc_version=CONSENT)
    assert seen["return_url"] == ctx.settings.billing_mixplat_return_url != ""


@pytest.mark.asyncio
async def test_a_claim_code_read_before_a_concurrent_redemption_cannot_be_used_twice(ctx, fake, monkeypatch):
    """Postgres READ COMMITTED: the second redeemer may hold a stale, still-unredeemed copy of the code."""
    from dataclasses import replace

    from api.billing.store.memory import MemoryTx

    owner, _ = await _device(ctx)
    await _subscribe(ctx, fake, owner, plan="family5")
    code = (await seat_service.create_claim_code(ctx, owner))["code"]
    first, second = (await _device(ctx))[0], (await _device(ctx))[0]
    await seat_service.redeem_claim_code(ctx, first, code=code)

    real_get = MemoryTx.get_claim_code

    async def stale_get(self, code_hmac, **kwargs):
        claim = await real_get(self, code_hmac, **kwargs)
        return replace(claim, redeemed_at=None, redeemed_by_device=None) if claim else None

    monkeypatch.setattr(MemoryTx, "get_claim_code", stale_get)
    with pytest.raises(NotFound, match="not valid"):
        await seat_service.redeem_claim_code(ctx, second, code=code)
    monkeypatch.setattr(MemoryTx, "get_claim_code", real_get)
    assert (await seat_service.list_devices(ctx, owner))["seats_used"] == 2

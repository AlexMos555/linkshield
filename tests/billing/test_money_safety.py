"""Money-safety fixes (2026-10): a provider call never runs inside a database
transaction, an ambiguous charge is reconciled by our own payment id, an
unmatched webhook is retried and alerted, a success is confirmed with the
provider before it extends anything, grants end, a number cannot be sold
twice, a reinstall gets its trial back.
"""
from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import replace

import pytest

from api.billing import scheduler
from api.billing.models import EntitlementSource, PaymentStatus, ProtectionMode, SubscriptionStatus as S
from api.billing.providers.base import ProviderError, ProviderUnavailable
from api.billing.providers.mixplat import MixplatProvider, md5_signature
from api.billing.service import checkout as checkout_service
from api.billing.service import trial as trial_service
from api.billing.service.errors import Conflict, NotConfigured
from api.billing.service.passes import compute_entitlement
from api.billing.service.webhooks import ingest_webhook
from api.billing.state_machine import add_months
from tests.billing.conftest import SUCCESS_NUMBER
from tests.billing.test_flows import CONSENT, _audit_actions, _deliver, _device, _sub, _subscribe

OTHER_NUMBER = "+79161112233"


async def _payments(ctx, sub_id):
    async with ctx.store.transaction() as tx:
        return list(await tx.list_payments(sub_id))


async def _store_is_free(ctx) -> bool:
    """True when no transaction is open (the memory store serialises them with one lock)."""
    async def peek():
        async with ctx.store.transaction():
            return True

    try:
        return await asyncio.wait_for(peek(), timeout=0.5)
    except asyncio.TimeoutError:
        return False


# ── 1. Renewals: one unit per subscription, the row committed before the provider is called ──


@pytest.mark.asyncio
async def test_renewal_payment_row_is_committed_before_the_provider_is_called(ctx, fake, clock):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")
    clock.now = (await _sub(ctx, sub_id)).current_period_end
    seen = {}
    original = fake.charge_renewal

    async def checking(**kwargs):
        seen["free"] = await _store_is_free(ctx)
        if seen["free"]:
            async with ctx.store.transaction() as tx:
                row = await tx.get_payment_by_idempotency_key(kwargs["idempotency_key"])
                seen["row"] = row
                seen["sub"] = await tx.get_subscription(sub_id)
        return await original(**kwargs)

    fake.charge_renewal = checking
    assert await scheduler.run_renewals(ctx, clock.now) == 1
    assert seen["free"] is True, "the provider was called inside a database transaction"
    assert seen["row"] is not None and seen["row"].status is PaymentStatus.PENDING
    assert seen["sub"].charge_pending is True


@pytest.mark.asyncio
async def test_a_failed_write_after_a_charge_never_leads_to_a_second_charge(ctx, fake, clock, monkeypatch):
    """Two subscriptions due; recording the second charge fails. The first stays charged
    exactly once, and the next pass charges neither again."""
    from api.billing.store.memory import MemoryTx

    first, _ = await _device(ctx)
    second, _ = await _device(ctx)
    a = await _subscribe(ctx, fake, first, plan="solo")
    b = await _subscribe(ctx, fake, second, plan="solo", number=OTHER_NUMBER)
    clock.now = max((await _sub(ctx, a)).current_period_end, (await _sub(ctx, b)).current_period_end)
    original_update = MemoryTx.update_payment
    calls = {"n": 0}

    async def flaky(self, payment):
        calls["n"] += 1
        if calls["n"] == 2:
            raise RuntimeError("database went away")
        return await original_update(self, payment)

    monkeypatch.setattr(MemoryTx, "update_payment", flaky)
    try:
        await scheduler.run_renewals(ctx, clock.now)
    except RuntimeError:
        pass
    monkeypatch.setattr(MemoryTx, "update_payment", original_update)
    await scheduler.run_renewals(ctx, clock.now)
    keys = [r["idempotency_key"] for r in fake.renewals]
    assert len(keys) == 2 and len(set(keys)) == 2, keys
    for sub_id in (a, b):
        assert (await _sub(ctx, sub_id)).charge_pending is True


@pytest.mark.asyncio
async def test_a_refused_renewal_is_a_failed_payment_not_a_stuck_one(ctx, fake, clock):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")
    period_end = (await _sub(ctx, sub_id)).current_period_end
    clock.now = period_end

    async def refused(**kwargs):
        raise ProviderError("MIXPLAT create_recurrent_payment: recurrent_not_found")

    fake.charge_renewal = refused
    assert await scheduler.run_renewals(ctx, clock.now) == 0
    sub = await _sub(ctx, sub_id)
    assert sub.status is S.GRACE and sub.charge_pending is False and sub.attempt == 1
    renewal = [p for p in await _payments(ctx, sub_id) if p.period_start is not None]
    assert [p.status for p in renewal] == [PaymentStatus.FAILED]


# ── 2. An ambiguous charge is reconciled by our merchant payment id; a late success is applied ──


async def _charge_then_time_out(fake):
    original = fake.charge_renewal

    async def timed_out(**kwargs):
        await original(**kwargs)          # the aggregator took the request (and the money)…
        raise ProviderUnavailable("MIXPLAT create_recurrent_payment: ReadTimeout")   # …we never saw the answer

    fake.charge_renewal = timed_out
    return original


@pytest.mark.asyncio
async def test_renewal_timeout_is_reconciled_by_merchant_payment_id(ctx, fake, clock):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")
    period_end = (await _sub(ctx, sub_id)).current_period_end
    clock.now = period_end
    await _charge_then_time_out(fake)
    assert await scheduler.run_renewals(ctx, clock.now) == 0
    pending = await _sub(ctx, sub_id)
    assert pending.charge_pending is True
    renewal = [p for p in await _payments(ctx, sub_id) if p.period_start is not None][0]
    assert renewal.status is PaymentStatus.PENDING and renewal.provider_payment_id is None
    assert await scheduler.run_renewals(ctx, clock.now) == 0 and len(fake.renewals) == 1   # never charged twice
    clock.advance(minutes=31)
    assert await scheduler.run_reconciliation(ctx, clock.now) == 1
    renewed = await _sub(ctx, sub_id)
    assert renewed.status is S.ACTIVE and renewed.current_period_end == add_months(period_end, 1)
    renewal = [p for p in await _payments(ctx, sub_id) if p.period_start is not None][0]
    assert renewal.status is PaymentStatus.SUCCEEDED and renewal.provider_payment_id == fake.renewals[0]["payment_id"]


@pytest.mark.asyncio
async def test_success_webhook_for_a_timed_out_renewal_extends_the_period(ctx, fake, clock):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")
    period_end = (await _sub(ctx, sub_id)).current_period_end
    clock.now = period_end
    original = await _charge_then_time_out(fake)
    await scheduler.run_renewals(ctx, clock.now)
    fake.charge_renewal = original
    key = fake.renewals[0]["idempotency_key"]
    sub = await _sub(ctx, sub_id)
    await _deliver(ctx, fake, fake.event_payload(sub.provider_subscription_id, payment_id=fake.renewals[0]["payment_id"],
                                                 merchant_payment_id=key, event_id="evt-late-success"))
    renewed = await _sub(ctx, sub_id)
    assert renewed.status is S.ACTIVE and renewed.current_period_end == add_months(period_end, 1)
    assert "payment.unexpected_success" not in await _audit_actions(ctx, sub_id)
    # The next period is charged normally, under a new key — nothing is blocked as "already settled".
    clock.now = renewed.current_period_end
    assert await scheduler.run_renewals(ctx, clock.now) == 1
    assert fake.renewals[-1]["idempotency_key"] != key
    assert "charge.already_settled" not in await _audit_actions(ctx, sub_id)


@pytest.mark.asyncio
async def test_success_for_a_charge_we_marked_failed_is_still_honoured(ctx, fake, clock):
    """The provider refused the call, we opened grace, then it reports the money was taken after all."""
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")
    period_end = (await _sub(ctx, sub_id)).current_period_end
    clock.now = period_end
    original = fake.charge_renewal

    async def charged_but_refused(**kwargs):
        await original(**kwargs)
        raise ProviderError("MIXPLAT create_recurrent_payment: internal_error")

    fake.charge_renewal = charged_but_refused
    await scheduler.run_renewals(ctx, clock.now)
    assert (await _sub(ctx, sub_id)).status is S.GRACE
    sub = await _sub(ctx, sub_id)
    await _deliver(ctx, fake, fake.event_payload(sub.provider_subscription_id, payment_id=fake.renewals[0]["payment_id"],
                                                 merchant_payment_id=fake.renewals[0]["idempotency_key"],
                                                 event_id="evt-after-refusal"))
    recovered = await _sub(ctx, sub_id)
    assert recovered.status is S.ACTIVE and recovered.grace_until is None
    assert "payment.unexpected_success" not in await _audit_actions(ctx, sub_id)


# ── 1b. Checkout: the intent is committed first, the provider is called after ──


@pytest.mark.asyncio
async def test_checkout_intent_is_committed_before_the_provider_is_called(ctx, fake):
    device, _ = await _device(ctx)
    seen = {}
    original = fake.start_checkout

    async def checking(**kwargs):
        seen["free"] = await _store_is_free(ctx)
        if seen["free"]:
            async with ctx.store.transaction() as tx:
                seen["payment"] = await tx.get_payment_by_idempotency_key(kwargs["idempotency_key"])
        return await original(**kwargs)

    fake.start_checkout = checking
    result = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                                   msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    assert seen["free"] is True, "start_checkout was called inside a database transaction"
    assert seen["payment"] is not None and seen["payment"].status is PaymentStatus.PENDING
    assert (await _sub(ctx, result["checkout_id"])).provider_subscription_id is not None


@pytest.mark.asyncio
async def test_checkout_refused_by_the_provider_closes_the_intent(ctx, fake):
    device, _ = await _device(ctx)

    async def refused(**kwargs):
        raise ProviderError("MIXPLAT create_payment_form: invalid_phone")

    fake.start_checkout = refused
    with pytest.raises(NotConfigured) as err:
        await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                              msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    assert err.value.code == "provider_error"
    assert [s for s in ctx.store.tables.subscriptions.values() if s.payer_account_id == device.account_id] == []
    assert any(a.action == "checkout.closed" for a in ctx.store.tables.audit)


@pytest.mark.asyncio
async def test_checkout_provider_timeout_keeps_the_intent_and_reconciles_it(ctx, fake, clock):
    device, _ = await _device(ctx)
    original = fake.start_checkout

    async def timed_out(**kwargs):
        await original(**kwargs)
        raise ProviderUnavailable("MIXPLAT create_payment_form: ReadTimeout")

    fake.start_checkout = timed_out
    with pytest.raises(NotConfigured):
        await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                              msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    (sub,) = [s for s in ctx.store.tables.subscriptions.values() if s.payer_account_id == device.account_id]
    assert sub.status is S.PENDING and sub.provider_subscription_id is None
    clock.advance(minutes=31)
    assert (await scheduler.run_once(ctx, clock.now))["reconciled"] == 1
    assert (await _sub(ctx, sub.id)).status is S.ACTIVE


# ── 3. An unmatched webhook is kept, retried and reported ──


@pytest.mark.asyncio
async def test_unmatched_webhook_is_logged_as_an_error_and_retried(ctx, fake, clock, caplog):
    device, _ = await _device(ctx)
    result = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="fake",
                                                   msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    sub = await _sub(ctx, result["checkout_id"])
    payload = fake.event_payload("fake_not_yet_known", payment_id="pay-early", amount_kopecks=9900)
    with caplog.at_level(logging.ERROR, logger="cleanway.billing.webhooks"):
        status, _ = await _deliver(ctx, fake, payload)
    assert status == 200
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR and r.getMessage() == "billing.webhook.unmatched"]
    assert len(errors) == 1
    (row,) = [r for r in ctx.store.tables.events.values() if r["outcome"] == "unmatched"]

    # The reference becomes known (e.g. the provider's answer was recorded after its webhook).
    async with ctx.store.transaction() as tx:
        await tx.update_subscription(replace(sub, provider_subscription_id="fake_not_yet_known"),
                                     expected_version=sub.row_version)
    counts = await scheduler.run_once(ctx, clock.now)
    assert counts["unmatched_applied"] == 1
    assert (await _sub(ctx, sub.id)).status is S.ACTIVE
    assert row["outcome"] == "applied"
    assert (await scheduler.run_once(ctx, clock.now))["unmatched_applied"] == 0


@pytest.mark.asyncio
async def test_unmatched_webhook_is_given_up_loudly_after_the_retry_budget(ctx, fake, clock, caplog, monkeypatch):
    monkeypatch.setattr(scheduler, "UNMATCHED_MAX_ATTEMPTS", 2)
    await _deliver(ctx, fake, fake.event_payload("fake_nobody", payment_id="pay-orphan", amount_kopecks=9900))
    assert await scheduler.run_unmatched_events(ctx, clock.now) == 0
    with caplog.at_level(logging.ERROR, logger="cleanway.billing.scheduler"):
        assert await scheduler.run_unmatched_events(ctx, clock.now) == 0
    (row,) = list(ctx.store.tables.events.values())
    assert row["outcome"] == "unmatched_abandoned"
    assert any(r.getMessage() == "billing.webhook.unmatched_abandoned" for r in caplog.records)
    assert await scheduler.run_unmatched_events(ctx, clock.now) == 0


# ── 4. A MIXPLAT success is confirmed with get_payment_status and checked against our row ──


class MixplatTransport:
    """The aggregator's HTTP API, scripted per payment."""

    def __init__(self) -> None:
        self.calls = []
        self.status = {}

    async def __call__(self, url, body):
        method = url.rsplit("/", 1)[1]
        self.calls.append((method, dict(body)))
        if method == "create_payment_form":
            return {"result": "ok", "payment_id": "P1", "redirect_url": "https://pay.mixplat.com/p/P1"}
        if method == "get_payment_status":
            key = body.get("payment_id") or body.get("merchant_payment_id")
            return {"result": "ok", **self.status.get(key, {"status": "pending"})}
        raise AssertionError(method)


KEY = "mixplat-test-key"


@pytest.fixture
def mixplat_ctx(ctx):
    transport = MixplatTransport()
    provider = MixplatProvider(project_id=100057, api_key=KEY, test=True, http_post=transport)
    return replace(ctx, providers={**ctx.providers, "mixplat": provider}), transport


def _mixplat_webhook(payment_id: str, merchant_payment_id: str, *, amount=9900, status="success", **extra):
    body = {"request": "payment_status", "payment_id": payment_id, "merchant_payment_id": merchant_payment_id,
            "status": status, "amount": amount, "currency": "RUB", "test": 1, "recurrent_id": "R1",
            "signature": md5_signature(payment_id, api_key=KEY), **extra}
    return json.dumps(body).encode()


async def _mixplat_checkout(mctx):
    device, _ = await _device(mctx)
    result = await checkout_service.start_checkout(mctx, device, plan_code="solo", provider_code="mixplat",
                                                   msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    return device, result["checkout_id"], checkout_service.checkout_key(result["checkout_id"])


@pytest.mark.asyncio
async def test_mixplat_success_is_confirmed_by_status_before_it_is_applied(mixplat_ctx):
    mctx, transport = mixplat_ctx
    device, sub_id, key = await _mixplat_checkout(mctx)
    transport.status["P1"] = {"status": "success", "amount": 9900, "currency": "RUB", "merchant_payment_id": key,
                              "recurrent_id": "R1"}
    status, _ = await ingest_webhook(mctx, provider_code="mixplat", headers={}, body=_mixplat_webhook("P1", key))
    assert status == 200
    assert ("get_payment_status", {"api_version": 3, "payment_id": "P1",
                                   "signature": md5_signature("P1", "", api_key=KEY)}) in transport.calls
    sub = await _sub(mctx, sub_id)
    assert sub.status is S.ACTIVE and sub.provider_subscription_id == "R1"
    assert (await compute_entitlement(mctx, device)).claims.mode is ProtectionMode.FULL


@pytest.mark.asyncio
@pytest.mark.parametrize("reported", [
    {"status": "pending", "amount": 9900, "currency": "RUB"},          # the webhook claims more than the provider says
    {"status": "success", "amount": 100, "currency": "RUB"},           # paid 1 ₽ for a 99 ₽ plan
    {"status": "success", "amount": 9900, "currency": "USD"},          # not roubles
    {"status": "success", "currency": "RUB"},                          # no amount at all
], ids=["status-pending", "amount", "currency", "no-amount"])
async def test_mixplat_success_that_does_not_match_is_rejected(mixplat_ctx, reported, caplog):
    mctx, transport = mixplat_ctx
    _, sub_id, key = await _mixplat_checkout(mctx)
    transport.status["P1"] = {**reported, "merchant_payment_id": key}
    with caplog.at_level(logging.ERROR):
        status, _ = await ingest_webhook(mctx, provider_code="mixplat", headers={}, body=_mixplat_webhook("P1", key))
    assert status == 200
    sub = await _sub(mctx, sub_id)
    assert sub.status is S.PENDING
    assert [p.status for p in await _payments(mctx, sub_id)] == [PaymentStatus.PENDING]
    assert any(r.levelno >= logging.ERROR for r in caplog.records)


@pytest.mark.asyncio
async def test_mixplat_webhook_fields_are_not_trusted_over_the_status(mixplat_ctx):
    """The md5 covers only payment_id: a replayed body with an edited amount changes nothing."""
    mctx, transport = mixplat_ctx
    _, sub_id, key = await _mixplat_checkout(mctx)
    transport.status["P1"] = {"status": "success", "amount": 9900, "currency": "RUB", "merchant_payment_id": key}
    await ingest_webhook(mctx, provider_code="mixplat", headers={}, body=_mixplat_webhook("P1", key, amount=1))
    assert (await _sub(mctx, sub_id)).status is S.ACTIVE


@pytest.mark.asyncio
async def test_mixplat_status_unreachable_answers_503_and_applies_nothing(mixplat_ctx):
    mctx, transport = mixplat_ctx
    _, sub_id, key = await _mixplat_checkout(mctx)

    async def down(url, body):
        if url.endswith("get_payment_status"):
            raise ConnectionError("down")
        return await MixplatTransport.__call__(transport, url, body)

    mctx.providers["mixplat"]._post = down
    status, payload = await ingest_webhook(mctx, provider_code="mixplat", headers={}, body=_mixplat_webhook("P1", key))
    assert status == 503 and payload["error"]["code"] == "provider_unreachable"
    assert (await _sub(mctx, sub_id)).status is S.PENDING
    assert not [r for r in mctx.store.tables.events.values() if r["signature_ok"]]   # a redelivery is processed


@pytest.mark.asyncio
async def test_webhook_ip_allowlist(mixplat_ctx):
    mctx, transport = mixplat_ctx
    _, sub_id, key = await _mixplat_checkout(mctx)
    transport.status["P1"] = {"status": "success", "amount": 9900, "currency": "RUB", "merchant_payment_id": key}
    locked = replace(mctx, settings=mctx.settings.model_copy(update={"billing_mixplat_webhook_ips": "185.77.232.0/24, 10.0.0.7"}))
    body = _mixplat_webhook("P1", key)
    status, payload = await ingest_webhook(locked, provider_code="mixplat", headers={}, body=body, ip="203.0.113.9")
    assert status == 403 and payload["error"]["code"] == "ip_not_allowed"
    status, _ = await ingest_webhook(locked, provider_code="mixplat", headers={}, body=body, ip=None)
    assert status == 403
    status, _ = await ingest_webhook(locked, provider_code="mixplat", headers={}, body=body, ip="185.77.232.15")
    assert status == 200 and (await _sub(mctx, sub_id)).status is S.ACTIVE
    # Empty list = off (the default).
    assert mctx.settings.billing_mixplat_webhook_ips == ""


# ── 5. Promo and partner grants end ──


@pytest.mark.asyncio
async def test_promo_grant_lapses_when_its_term_ends(ctx, clock):
    device, _ = await _device(ctx)
    result = await checkout_service.start_checkout(ctx, device, plan_code="solo", provider_code="promo", msisdn=None,
                                                   consent_doc_version=CONSENT, allow_grant=True)
    end = (await _sub(ctx, result["checkout_id"])).current_period_end
    assert await scheduler.run_expiries(ctx, end - (end - clock.now) / 2) == 0
    clock.now = end
    assert await scheduler.run_expiries(ctx, clock.now) == 1
    assert (await _sub(ctx, result["checkout_id"])).status is S.LAPSED
    ent = await compute_entitlement(ctx, device)
    assert ent.claims.mode is ProtectionMode.BASIC and ent.claims.src is EntitlementSource.NONE
    assert "device_mode.basic" in await _audit_actions(ctx, result["checkout_id"])


@pytest.mark.asyncio
async def test_partner_licence_lapses_when_its_term_ends(ctx, clock):
    from api.billing.partner import create_partner_license
    from api.billing.service import seats as seat_service

    licence = await create_partner_license(ctx, partner="t2", license_ref="L-1", seats=1, months=1)
    device, _ = await _device(ctx)
    await seat_service.redeem_claim_code(ctx, device, code=licence["activation_code"])
    assert (await compute_entitlement(ctx, device)).claims.mode is ProtectionMode.FULL
    clock.now = (await _sub(ctx, licence["subscription_id"])).current_period_end
    assert await scheduler.run_expiries(ctx, clock.now) == 1
    assert (await _sub(ctx, licence["subscription_id"])).status is S.LAPSED
    assert (await compute_entitlement(ctx, device)).claims.mode is ProtectionMode.BASIC


@pytest.mark.asyncio
async def test_paid_subscriptions_are_not_lapsed_by_the_grant_expiry(ctx, fake, clock):
    device, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, device, plan="solo")
    clock.now = (await _sub(ctx, sub_id)).current_period_end
    assert await scheduler.run_expiries(ctx, clock.now) == 0
    assert (await _sub(ctx, sub_id)).status is S.ACTIVE


# ── 7. One live subscription per phone number ──


@pytest.mark.asyncio
async def test_checkout_refuses_a_number_that_already_pays(ctx, fake):
    old_install, _ = await _device(ctx)
    await _subscribe(ctx, fake, old_install, plan="solo")
    reinstalled, _ = await _device(ctx)
    started = len(fake.checkouts)
    with pytest.raises(Conflict) as err:
        await checkout_service.start_checkout(ctx, reinstalled, plan_code="solo", provider_code="fake",
                                              msisdn="8 (915) 000-00-00", consent_doc_version=CONSENT)
    assert err.value.code == "subscription_exists_for_number"
    assert err.value.details == {"msisdn_masked": "+7 9•• •••-00-00"}
    assert len(fake.checkouts) == started
    assert [s for s in ctx.store.tables.subscriptions.values() if s.payer_account_id == reinstalled.account_id] == []


@pytest.mark.asyncio
async def test_checkout_refuses_a_number_with_another_install_checkout_in_flight(ctx, fake):
    first, _ = await _device(ctx)
    await checkout_service.start_checkout(ctx, first, plan_code="solo", provider_code="fake",
                                          msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    second, _ = await _device(ctx)
    with pytest.raises(Conflict) as err:
        await checkout_service.start_checkout(ctx, second, plan_code="solo", provider_code="fake",
                                              msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    assert err.value.code == "checkout_in_progress_for_number"


@pytest.mark.asyncio
async def test_a_number_whose_subscription_ended_can_buy_again(ctx, fake, clock):
    from api.billing.service import cancel as cancel_service

    old_install, _ = await _device(ctx)
    sub_id = await _subscribe(ctx, fake, old_install, plan="solo")
    await cancel_service.cancel_subscription(ctx, old_install)
    clock.now = (await _sub(ctx, sub_id)).current_period_end
    await scheduler.run_expiries(ctx, clock.now)
    reinstalled, _ = await _device(ctx)
    again = await checkout_service.start_checkout(ctx, reinstalled, plan_code="solo", provider_code="fake",
                                                  msisdn=SUCCESS_NUMBER, consent_doc_version=CONSENT)
    assert again["status"] == "pending"


# ── 8. A reinstall gets the same trial back ──


@pytest.mark.asyncio
async def test_reinstall_gets_the_same_trial_never_a_new_one(ctx, clock):
    device, _ = await _device(ctx)
    first = await trial_service.start_trial(ctx, device, fingerprint_input="android-id-1")
    clock.advance(days=5)
    reinstalled, _ = await _device(ctx)
    again = await trial_service.start_trial(ctx, reinstalled, fingerprint_input="android-id-1")
    assert (again.started_at, again.ends_at) == (first.started_at, first.ends_at)
    assert again.device_id == reinstalled.id
    ent = await compute_entitlement(ctx, reinstalled)
    assert ent.claims.src is EntitlementSource.TRIAL and ent.claims.until == int(first.ends_at.timestamp())
    clock.advance(days=10)
    assert (await compute_entitlement(ctx, reinstalled)).claims.mode is ProtectionMode.BASIC

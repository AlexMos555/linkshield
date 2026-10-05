"""Provider adapters: the interface contract, Fake, Promo, MIXPLAT (against the
documentation's own signature examples) and the T2 stub."""
from __future__ import annotations

import inspect
import json

import pytest

from api.billing.models import FailureReason
from api.billing.providers.base import (
    PROVIDER_METHODS,
    BillingProvider,
    EventKind,
    InvalidSignature,
    NotConfiguredError,
    ProviderError,
    ProviderUnavailable,
)
from api.billing.providers.fake import PENDING_FOREVER, FakeProvider, scripted_outcome
from api.billing.providers.mixplat import (
    MixplatProvider,
    failure_reason,
    md5_signature,
    parse_payment_status,
)
from api.billing.providers.promo import PromoProvider, granted_event
from api.billing.providers.registry import build_providers, checkout_providers
from api.billing.providers.t2 import T2DirectProvider
from api.billing.settings import BillingSettings

# The key and values from docs.mixplat.ru/methods — verified 2026-09-29.
DOC_KEY = "c23a4398db8ef7b3ae1f4b07aeeb7c54f8e3c7c9"


@pytest.mark.parametrize("provider", [
    FakeProvider(), PromoProvider(), T2DirectProvider(),
    MixplatProvider(project_id=1, api_key="k"),
], ids=lambda p: p.code)
def test_every_adapter_satisfies_the_contract(provider):
    assert isinstance(provider, BillingProvider)
    assert isinstance(provider.initiates_renewals, bool)
    for name in PROVIDER_METHODS:
        assert callable(getattr(provider, name)), name
    for name in ("start_checkout", "charge_renewal", "cancel", "refund", "fetch_status"):
        assert inspect.iscoroutinefunction(getattr(provider, name)), name
    assert not inspect.iscoroutinefunction(provider.parse_webhook)


# ── Fake ──


@pytest.mark.asyncio
async def test_fake_scripts_every_error_screen_by_number():
    fake = FakeProvider()
    assert scripted_outcome("+79030000000") is FailureReason.NO_MONEY
    assert scripted_outcome("+79030000001") is FailureReason.PAYMENTS_BANNED
    assert scripted_outcome("+79030000002") is FailureReason.PASSPORT
    assert scripted_outcome("+79030000003") is FailureReason.CORPORATE
    assert scripted_outcome("+79030000004") is FailureReason.USER_DECLINED
    assert scripted_outcome("+79161234567") is None
    start = await fake.start_checkout(plan_product_id="solo", amount_kopecks=9900, msisdn="+79030000000",
                                      idempotency_key="sub:checkout", return_url="https://x")
    assert start.kind == "await_sms" and start.provider_ref.startswith("fake_")
    status = await fake.fetch_status(provider_ref=start.provider_ref)
    assert status.kind is EventKind.PAYMENT_FAILED and status.failure is FailureReason.NO_MONEY
    assert status.amount_kopecks == 9900
    pending = await fake.start_checkout(plan_product_id="solo", amount_kopecks=9900, msisdn=PENDING_FOREVER,
                                        idempotency_key="sub2:checkout", return_url="https://x")
    assert await fake.fetch_status(provider_ref=pending.provider_ref) is None
    assert await fake.fetch_status(provider_ref="unknown") is None


@pytest.mark.asyncio
async def test_fake_webhook_signature_and_shape():
    fake = FakeProvider(secret="s")
    payload = fake.event_payload("fake_abc", payment_id="pay-1", amount_kopecks=27000)
    headers, body = fake.sign(payload)
    (event,) = fake.parse_webhook(headers, body)
    assert event.kind is EventKind.PAYMENT_SUCCEEDED and event.provider_payment_id == "pay-1"
    assert event.provider_event_id == "evt_fake_abc_payment_succeeded" and event.amount_kopecks == 27000
    with pytest.raises(InvalidSignature):
        fake.parse_webhook({"x-fake-signature": "nope"}, body)
    with pytest.raises(InvalidSignature):
        fake.parse_webhook({}, body)
    with pytest.raises(InvalidSignature):
        fake.parse_webhook({"x-fake-signature": fake.signature(b"[]")}, b"[]")
    with pytest.raises(InvalidSignature):
        fake.parse_webhook({"x-fake-signature": fake.signature(b"{bad")}, b"{bad")
    bad = dict(payload, kind="teleport")
    with pytest.raises(InvalidSignature):
        fake.parse_webhook(*fake.sign(bad))
    failed = fake.event_payload("fake_abc", outcome=FailureReason.PASSPORT)
    (event,) = fake.parse_webhook(*fake.sign(failed))
    assert event.kind is EventKind.PAYMENT_FAILED and event.failure is FailureReason.PASSPORT
    assert fake.ack_body() == {"success": True}


@pytest.mark.asyncio
async def test_fake_records_renewals_cancels_refunds():
    fake = FakeProvider()
    pid = await fake.charge_renewal(provider_subscription_id="fake_x", amount_kopecks=9900, idempotency_key="k")
    assert pid.startswith("fakepay_") and fake.renewals[0]["idempotency_key"] == "k"
    await fake.cancel(provider_subscription_id="fake_x")
    await fake.refund(provider_payment_id=pid, amount_kopecks=100, idempotency_key="r")
    assert fake.cancelled == ["fake_x"] and fake.refunds[0]["amount_kopecks"] == 100


# ── Promo ──


@pytest.mark.asyncio
async def test_promo_grants_without_money_and_has_no_webhooks():
    promo = PromoProvider()
    start = await promo.start_checkout(plan_product_id="family3", amount_kopecks=0, msisdn=None,
                                       idempotency_key="k", return_url="")
    assert start.kind == "granted" and start.provider_ref.startswith("promo_")
    event = await promo.fetch_status(provider_ref=start.provider_ref)
    expected = granted_event(start.provider_ref)
    assert (event.provider_event_id, event.provider_subscription_id, event.provider_payment_id) == (
        expected.provider_event_id, expected.provider_subscription_id, expected.provider_payment_id)
    assert event.kind is EventKind.PAYMENT_SUCCEEDED and event.amount_kopecks == 0
    with pytest.raises(InvalidSignature):
        promo.parse_webhook({}, b"{}")
    with pytest.raises(NotImplementedError):
        await promo.charge_renewal(provider_subscription_id="x", amount_kopecks=1, idempotency_key="k")
    assert await promo.cancel(provider_subscription_id="x") is None
    assert await promo.refund(provider_payment_id="x", amount_kopecks=1, idempotency_key="k") is None
    assert promo.initiates_renewals is False


# ── MIXPLAT ──


def test_mixplat_signatures_match_the_documentation_examples():
    assert md5_signature("324223", 100057, "payment123", api_key=DOC_KEY) == "510c464ec7337858f6f662cbdeda9ac5"
    assert md5_signature("1449272", api_key=DOC_KEY) == "f05b57071a180a05bb161231896bee43"
    assert md5_signature("707607041", "571", api_key=DOC_KEY) == "7e99a4988888d5c14b9faf2e14a95d43"
    assert md5_signature("707607041", api_key=DOC_KEY) == "047780e4f51dc6664d333536a6b4aab8"
    assert md5_signature("707607041", None, api_key=DOC_KEY) == "047780e4f51dc6664d333536a6b4aab8"


def test_mixplat_requests_carry_the_documented_fields():
    mp = MixplatProvider(project_id=100057, api_key=DOC_KEY, test=True)
    body = mp.checkout_request(amount_kopecks=9900, msisdn="+79031234567", merchant_payment_id="payment123",
                               return_url="https://cleanway.ai/r", description="Cleanway solo")
    assert body["api_version"] == 3 and body["project_id"] == 100057
    assert body["payment_method"] == "mobile" and body["recurrent_payment"] == 1 and body["test"] == 1
    assert body["user_phone"] == "79031234567" and body["amount"] == 9900
    assert body["signature"] == md5_signature("payment123", 100057, "payment123", api_key=DOC_KEY)
    assert "user_phone" not in mp.checkout_request(amount_kopecks=1, msisdn=None, merchant_payment_id="m",
                                                   return_url="", description="")
    rec = mp.recurrent_request(recurrent_id="1449272", amount_kopecks=9900, merchant_payment_id="m2")
    assert rec["signature"] == "f05b57071a180a05bb161231896bee43"
    st = mp.status_request(payment_id="707607041", merchant_payment_id="571")
    assert st["signature"] == "7e99a4988888d5c14b9faf2e14a95d43" and st["payment_id"] == "707607041"
    rf = mp.refund_request(payment_id="707607041", amount_kopecks=None)
    assert rf["signature"] == "047780e4f51dc6664d333536a6b4aab8" and "amount" not in rf
    assert mp.refund_request(payment_id="p", amount_kopecks=50)["amount"] == 50


def test_mixplat_payment_status_notification():
    payload = {
        "api_version": 3, "request": "payment_status", "payment_id": "707607041", "merchant_payment_id": "571",
        "status": "success", "status_extended": "success_success", "amount_merchant": 9900, "test": 1,
        "recurrent_id": "1449272", "date_processed": "2026-09-29 12:00:00", "user_phone": "79031234567",
        "signature": "047780e4f51dc6664d333536a6b4aab8",
    }
    event = parse_payment_status(payload, api_key=DOC_KEY)
    assert event.kind is EventKind.PAYMENT_SUCCEEDED and event.provider_payment_id == "707607041"
    assert event.provider_subscription_id == "1449272" and event.merchant_payment_id == "571"
    assert event.amount_kopecks == 9900 and event.test is True
    assert event.provider_event_id == "707607041:success"
    assert int(event.occurred_at) == 1790672400  # 2026-09-29 12:00 Moscow = 09:00 UTC
    with pytest.raises(InvalidSignature):
        parse_payment_status(dict(payload, signature="0" * 32), api_key=DOC_KEY)
    with pytest.raises(InvalidSignature):
        parse_payment_status(dict(payload, request="sms_status"), api_key=DOC_KEY)
    with pytest.raises(InvalidSignature):
        parse_payment_status(dict(payload, status="weird"), api_key=DOC_KEY)
    failed = parse_payment_status(dict(payload, status="failure", status_extended="failure_no_money"), api_key=DOC_KEY)
    assert failed.kind is EventKind.PAYMENT_FAILED and failed.failure is FailureReason.NO_MONEY
    pending = parse_payment_status(dict(payload, status="pending", date_processed=None, date_created=1700000000),
                                   api_key=DOC_KEY)
    assert pending.kind is EventKind.PAYMENT_PENDING and pending.occurred_at == 1700000000.0
    assert failure_reason("failure_canceled_by_user") is FailureReason.USER_DECLINED
    assert failure_reason("failure_timeout") is FailureReason.TIMEOUT
    assert failure_reason("failure_something_new") is FailureReason.OTHER


@pytest.mark.asyncio
async def test_mixplat_is_disabled_without_credentials():
    mp = MixplatProvider(project_id=0, api_key="")
    assert mp.configured is False
    with pytest.raises(NotConfiguredError):
        await mp.start_checkout(plan_product_id="solo", amount_kopecks=1, msisdn=None, idempotency_key="k", return_url="")
    with pytest.raises(NotConfiguredError):
        mp.parse_webhook({}, b"{}")
    with pytest.raises(NotConfiguredError):
        await mp.fetch_status(provider_ref="x")


@pytest.mark.asyncio
async def test_mixplat_calls_over_a_fake_transport():
    calls = []

    async def post(url, body):
        calls.append((url, body))
        method = url.rsplit("/", 1)[1]
        if method == "create_payment_form":
            return {"result": "ok", "payment_id": "XXehOf", "redirect_url": "https://pay.mixplat.com/p/XXehOf"}
        if method == "create_recurrent_payment":
            return {"result": "ok", "payment_id": "REC1"}
        if method == "get_payment_status":
            return {"result": "ok", "status": "failure", "status_extended": "failure_no_money", "amount": 9900}
        if method == "refund_payment":
            return {"result": "ok", "refund_id": 7}
        raise AssertionError(method)

    mp = MixplatProvider(project_id=100057, api_key=DOC_KEY, http_post=post)
    start = await mp.start_checkout(plan_product_id="solo", amount_kopecks=9900, msisdn="+79150000000",
                                    idempotency_key="sub:checkout", return_url="https://cleanway.ai/r")
    assert start.kind == "redirect" and start.provider_ref == "XXehOf" and start.url.endswith("/p/XXehOf")
    assert calls[0][0] == "https://api.mixplat.com/create_payment_form"
    assert await mp.charge_renewal(provider_subscription_id="1449272", amount_kopecks=9900, idempotency_key="k2") == "REC1"
    status = await mp.fetch_status(provider_ref="XXehOf")
    assert status.kind is EventKind.PAYMENT_FAILED and status.failure is FailureReason.NO_MONEY
    await mp.refund(provider_payment_id="XXehOf", amount_kopecks=9900, idempotency_key="r")
    assert calls[-1][1]["payment_id"] == "XXehOf"
    assert await mp.cancel(provider_subscription_id="1449272") is None
    assert mp.ack_body() == {"result": "ok"}
    (event,) = mp.parse_webhook({}, json.dumps({
        "request": "payment_status", "payment_id": "707607041", "status": "success",
        "signature": "047780e4f51dc6664d333536a6b4aab8",
    }).encode())
    assert event.kind is EventKind.PAYMENT_SUCCEEDED
    with pytest.raises(InvalidSignature):
        mp.parse_webhook({}, b"not json")
    with pytest.raises(InvalidSignature):
        mp.parse_webhook({}, b"[1]")


@pytest.mark.asyncio
async def test_mixplat_error_replies_and_transport_failures():
    async def error_post(url, body):
        return {"result": "invalid_signature", "error_description": "bad sign"}

    mp = MixplatProvider(project_id=1, api_key="k", http_post=error_post)
    with pytest.raises(ProviderError, match="invalid_signature"):
        await mp.start_checkout(plan_product_id="solo", amount_kopecks=1, msisdn=None, idempotency_key="k", return_url="")

    async def down(url, body):
        raise ConnectionError("down")

    with pytest.raises(ProviderUnavailable):
        await MixplatProvider(project_id=1, api_key="k", http_post=down).charge_renewal(
            provider_subscription_id="r", amount_kopecks=1, idempotency_key="k")

    async def no_id(url, body):
        return {"result": "ok"}

    with pytest.raises(ProviderError, match="no payment_id"):
        await MixplatProvider(project_id=1, api_key="k", http_post=no_id).start_checkout(
            plan_product_id="solo", amount_kopecks=1, msisdn=None, idempotency_key="k", return_url="")

    async def unknown_status(url, body):
        return {"result": "ok", "status": "???"}

    assert await MixplatProvider(project_id=1, api_key="k", http_post=unknown_status).fetch_status(provider_ref="x") is None

    async def not_object(url, body):
        return [1]

    with pytest.raises(ProviderError, match="non-object"):
        await MixplatProvider(project_id=1, api_key="k", http_post=not_object).fetch_status(provider_ref="x")


# ── T2 stub ──


@pytest.mark.asyncio
async def test_t2_stub_raises_not_configured_everywhere():
    t2 = T2DirectProvider()
    with pytest.raises(NotConfiguredError):
        await t2.start_checkout(plan_product_id="solo", amount_kopecks=1, msisdn=None, idempotency_key="k", return_url="")
    with pytest.raises(NotConfiguredError):
        await t2.charge_renewal(provider_subscription_id="x", amount_kopecks=1, idempotency_key="k")
    with pytest.raises(NotConfiguredError):
        await t2.cancel(provider_subscription_id="x")
    with pytest.raises(NotConfiguredError):
        await t2.refund(provider_payment_id="x", amount_kopecks=1, idempotency_key="k")
    with pytest.raises(NotConfiguredError):
        t2.parse_webhook({}, b"")
    with pytest.raises(NotConfiguredError):
        await t2.fetch_status(provider_ref="x")
    assert t2.ack_body() == {"result": "ok"}


# ── Registry ──


def test_registry_follows_settings():
    base = BillingSettings(_env_file=None)
    assert set(build_providers(base)) == {"promo", "t2_direct"}
    assert checkout_providers(build_providers(base)) == ()
    with_fake = BillingSettings(_env_file=None, billing_fake_provider_enabled=True)
    assert "fake" in build_providers(with_fake) and checkout_providers(build_providers(with_fake)) == ("fake",)
    with_mixplat = BillingSettings(_env_file=None, billing_mixplat_project_id=1, billing_mixplat_api_key="k")
    assert "mixplat" in build_providers(with_mixplat)

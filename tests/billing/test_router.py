"""/billing/v1 over HTTP: the flag gate, auth, envelope, idempotency, limits, webhooks, partner."""
from __future__ import annotations

import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.billing import deps
from api.billing.mount import is_billing_mounted, mount_billing
from api.billing.partner import partner_signature
from api.billing.settings import BillingSettings
from tests.billing.conftest import SUCCESS_NUMBER

CONSENT = "ru/v1"


@pytest.fixture
def client(ctx):
    app = FastAPI()
    assert mount_billing(app, ctx.settings) is True
    deps.install_context(ctx)
    try:
        with TestClient(app) as c:
            yield c
    finally:
        deps.install_context(None)


def _register(client, **body):
    r = client.post("/billing/v1/devices", json={"platform": "android", "app_version": "1.1.0", **body})
    assert r.status_code == 201, r.text
    data = r.json()["data"]
    return data["device_id"], {"Authorization": f"Bearer {data['device_secret']}"}


def _subscribe(client, ctx, fake, auth, *, plan="family3"):
    r = client.post("/billing/v1/checkout", headers=auth, json={
        "plan_code": plan, "provider": "fake", "msisdn": SUCCESS_NUMBER, "consent_doc_version": CONSENT,
    })
    assert r.status_code == 201, r.text
    checkout = r.json()["data"]
    ref = ctx.store.tables.subscriptions[checkout["checkout_id"]].provider_subscription_id
    headers, body = fake.sign(fake.event_payload(ref, payment_id="pay-1"))
    r = client.post("/billing/v1/webhooks/fake", headers=headers, content=body)
    assert r.status_code == 200 and r.json() == {"success": True}
    return checkout["checkout_id"]


# ── The gate ──


def test_default_app_mounts_nothing():
    from api.main import app

    assert not is_billing_mounted(app)
    assert all(not getattr(r, "path", "").startswith("/billing") for r in app.routes)


@pytest.mark.parametrize("enabled, role, mounted", [
    (False, "api", False), (True, "api", False), (False, "billing", False), (True, "billing", True),
])
def test_routes_need_flag_and_role(enabled, role, mounted):
    app = FastAPI()
    assert mount_billing(app, BillingSettings(_env_file=None, billing_enabled=enabled, role=role)) is mounted
    assert is_billing_mounted(app) is mounted


def test_context_is_not_built_when_unmounted(monkeypatch):
    """The api role must never reach for the billing database."""
    called = []

    async def _boom(*a, **k):
        called.append(1)
        raise AssertionError("must not build")

    monkeypatch.setattr("api.billing.bootstrap.build_runtime_context", _boom)
    app = FastAPI()
    mount_billing(app, BillingSettings(_env_file=None))
    with TestClient(app) as c:
        assert c.get("/billing/v1/plans").status_code == 404
    assert called == []


# ── Devices, trial, plans, entitlement ──


def test_register_trial_entitlement(client, ctx):
    device_id, auth = _register(client)
    assert client.get("/billing/v1/entitlement").status_code == 401
    assert client.get("/billing/v1/entitlement", headers={"Authorization": "Bearer nope"}).json()["error"]["code"] == "unauthorized"
    r = client.post("/billing/v1/trial", headers=auth, json={"fingerprint": "android-id"})
    assert r.status_code == 200
    data = r.json()["data"]
    assert data["claims"]["mode"] == "full" and data["claims"]["src"] == "trial" and data["claims"]["dev"] == device_id
    assert data["trial"]["ends_at"] - data["trial"]["started_at"] == 14 * 86400
    r = client.get("/billing/v1/entitlement", headers={**auth, "X-Cleanway-App-Version": "1.1.2"})
    assert r.json()["data"]["status"]["source"] == "trial"
    assert ctx.store.tables.devices[device_id].app_version == "1.1.2"
    assert client.post("/billing/v1/devices", json={"platform": "windows"}).status_code == 422


def test_plans_is_public_and_carries_the_settings(client):
    r = client.get("/billing/v1/plans")
    assert r.status_code == 200
    data = r.json()["data"]
    assert [(p["code"], p["seats"], p["price_rub"]) for p in data["plans"]] == [("solo", 1, 99), ("family3", 3, 270), ("family5", 5, 399)]
    assert data["trial_days"] == 14 and data["grace_days"] == 7 and data["lapse_policy"] == "basic"
    assert data["providers"] == ["fake"] and data["consent_doc_version"] == "ru/v1" and data["currency"] == "RUB"


# ── Checkout, webhook, envelope, idempotency ──


def test_checkout_webhook_and_status(client, ctx, fake):
    device_id, auth = _register(client)
    sub_id = _subscribe(client, ctx, fake, auth)
    r = client.get(f"/billing/v1/checkout/{sub_id}", headers=auth)
    assert r.json()["data"]["status"] == "active"
    ent = client.get("/billing/v1/entitlement", headers=auth).json()["data"]
    assert ent["claims"]["mode"] == "full" and ent["status"]["subscription"]["plan"] == "family3"
    assert SUCCESS_NUMBER not in json.dumps(ent)
    other_id, other = _register(client)
    r = client.get(f"/billing/v1/checkout/{sub_id}", headers=other)
    assert r.status_code == 404 and r.json() == {"success": False, "data": None, "error": {"code": "not_found", "message": "checkout not found"}}
    r = client.post("/billing/v1/checkout", headers=auth, json={
        "plan_code": "solo", "provider": "fake", "msisdn": SUCCESS_NUMBER, "consent_doc_version": CONSENT})
    assert r.status_code == 409 and r.json()["error"]["code"] == "already_subscribed"


def test_idempotency_key_replays_the_same_answer(client, ctx, fake):
    _, auth = _register(client)
    body = {"plan_code": "solo", "provider": "fake", "msisdn": SUCCESS_NUMBER, "consent_doc_version": CONSENT}
    first = client.post("/billing/v1/checkout", headers={**auth, "Idempotency-Key": "k-1"}, json=body)
    second = client.post("/billing/v1/checkout", headers={**auth, "Idempotency-Key": "k-1"}, json=body)
    assert first.status_code == 201 and second.status_code == 201 and first.json() == second.json()
    assert len(ctx.store.tables.subscriptions) == 1
    # A real second attempt (new key) restarts the checkout: the unconfirmed one is closed.
    third = client.post("/billing/v1/checkout", headers={**auth, "Idempotency-Key": "k-2"}, json=body)
    assert third.status_code == 201 and third.json()["data"]["checkout_id"] != first.json()["data"]["checkout_id"]
    assert len(ctx.store.tables.subscriptions) == 1
    gone = client.get(f"/billing/v1/checkout/{first.json()['data']['checkout_id']}", headers=auth).json()["data"]
    assert gone["status"] == "failed" and gone["failure_reason"] == "user_declined"
    bad = client.post("/billing/v1/checkout", headers={**auth, "Idempotency-Key": "x" * 129}, json=body)
    assert bad.status_code == 400 and bad.json()["error"]["code"] == "idempotency_key_invalid"


def test_codes_claim_devices_cancel(client, ctx, fake):
    owner_id, owner = _register(client)
    _subscribe(client, ctx, fake, owner)
    r = client.post("/billing/v1/subscription/codes", headers={**owner, "Idempotency-Key": "c1"})
    assert r.status_code == 201
    code = r.json()["data"]["code"]
    assert client.post("/billing/v1/subscription/codes", headers={**owner, "Idempotency-Key": "c1"}).json()["data"]["code"] == code
    mom_id, mom = _register(client)
    assert client.post("/billing/v1/claim", headers=mom, json={"code": "12"}).status_code == 422
    r = client.post("/billing/v1/claim", headers=mom, json={"code": code})
    assert r.status_code == 200 and r.json()["data"]["seats_used"] == 2
    r = client.get("/billing/v1/subscription/devices", headers=mom)
    assert r.json()["data"]["is_payer"] is False and len(r.json()["data"]["devices"]) == 2
    assert client.delete(f"/billing/v1/subscription/seats/{owner_id}", headers=mom).status_code == 403
    assert client.delete(f"/billing/v1/subscription/seats/{mom_id}", headers=owner).json()["data"] == {"removed": mom_id}
    assert client.get("/billing/v1/entitlement", headers=mom).json()["data"]["claims"]["mode"] == "basic"
    r = client.post("/billing/v1/subscription/cancel", headers=owner)
    assert r.status_code == 200 and r.json()["data"]["status"] == "cancel_at_period_end"
    assert client.post("/billing/v1/subscription/cancel", headers=mom).status_code == 404


def test_cancel_by_phone_same_answer(client, ctx, fake):
    _, auth = _register(client)
    sub_id = _subscribe(client, ctx, fake, auth)
    unknown = client.post("/billing/v1/cancel-by-phone", json={"msisdn": "+79990000000"})
    known = client.post("/billing/v1/cancel-by-phone", json={"msisdn": SUCCESS_NUMBER})
    assert unknown.status_code == known.status_code == 200 and unknown.json() == known.json()
    assert ctx.store.tables.subscriptions[sub_id].status.value == "cancel_at_period_end"
    assert client.post("/billing/v1/cancel-by-phone", json={"msisdn": "+1 415 555 0100"}).status_code == 400


def test_number_in_use_is_a_clear_error_with_the_masked_number(client, ctx, fake):
    _, old_install = _register(client)
    _subscribe(client, ctx, fake, old_install)
    _, reinstalled = _register(client)
    r = client.post("/billing/v1/checkout", headers=reinstalled, json={
        "plan_code": "solo", "provider": "fake", "msisdn": SUCCESS_NUMBER, "consent_doc_version": CONSENT,
    })
    assert r.status_code == 409
    error = r.json()["error"]
    assert error["code"] == "subscription_exists_for_number"
    assert error["details"] == {"msisdn_masked": "+7 9•• •••-00-00"}
    assert SUCCESS_NUMBER not in r.text


def test_cancel_by_phone_is_limited_per_number(client, ctx, fake, monkeypatch):
    """No proof of owning the number is possible yet (no SMS API at the aggregator): a strict per-number limit."""
    from tests.conftest import FakeRedis

    redis = FakeRedis()

    async def _get():
        return redis

    monkeypatch.setattr("api.services.rate_limiter.get_redis", _get)
    assert ctx.settings.billing_cancel_by_phone_per_phone_per_day == 3
    ctx.settings.billing_cancel_by_phone_per_phone_per_day = 1
    assert client.post("/billing/v1/cancel-by-phone", json={"msisdn": SUCCESS_NUMBER}).status_code == 200
    r = client.post("/billing/v1/cancel-by-phone", json={"msisdn": "8 915 000-00-00"})
    assert r.status_code == 429 and r.json()["detail"]["category"] == "billing:cancel_by_phone:phone"
    assert client.post("/billing/v1/cancel-by-phone", json={"msisdn": "+79990000000"}).status_code == 200


def test_webhook_errors(client, ctx, fake):
    assert client.post("/billing/v1/webhooks/nobody", content=b"{}").status_code == 404
    r = client.post("/billing/v1/webhooks/fake", headers={"X-Fake-Signature": "bad"}, content=b"{}")
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_signature"
    assert client.post("/billing/v1/webhooks/fake", content=b"x" * 70000).status_code == 413


def test_partner_license_end_to_end(client, ctx):
    body = json.dumps({"partner": "t2", "license_ref": "L-1", "seats": 3, "months": 2}).encode()
    assert client.post("/billing/v1/partner/licenses", content=body).status_code == 401
    good = {"X-Partner-Signature": partner_signature("partner-secret", body)}
    r = client.post("/billing/v1/partner/licenses", headers=good, content=body)
    assert r.status_code == 201, r.text
    lic = r.json()["data"]
    assert lic["plan"] == "family3" and lic["activation_link"] == "cleanway://activate?code=" + lic["activation_code"]
    assert client.post("/billing/v1/partner/licenses", headers=good, content=body).status_code == 409
    bad = json.dumps({"partner": "t2", "license_ref": "L-2", "seats": 9}).encode()
    r = client.post("/billing/v1/partner/licenses", headers={"X-Partner-Signature": partner_signature("partner-secret", bad)}, content=bad)
    assert r.status_code == 400 and r.json()["error"]["code"] == "too_many_seats"
    # The first phone to activate becomes the owner and can add relatives.
    _, phone = _register(client)
    r = client.post("/billing/v1/claim", headers=phone, json={"code": lic["activation_code"]})
    assert r.status_code == 200
    ent = client.get("/billing/v1/entitlement", headers=phone).json()["data"]
    assert ent["claims"]["src"] == "promo" and ent["status"]["subscription"]["is_payer"] is True
    assert client.post("/billing/v1/subscription/codes", headers=phone).status_code == 201


def test_partner_not_configured(ctx, fake):
    from api.billing.context import build_context
    from tests.billing.conftest import make_settings

    unconfigured = build_context(make_settings(billing_partner_hmac_key=""), ctx.store, ctx.providers, clock=ctx.clock)
    app = FastAPI()
    mount_billing(app, unconfigured.settings)
    deps.install_context(unconfigured)
    try:
        with TestClient(app) as c:
            r = c.post("/billing/v1/partner/licenses", content=b"{}")
            assert r.status_code == 503 and r.json()["error"]["code"] == "not_configured"
    finally:
        deps.install_context(None)


# ── Rate limits ──


def test_rate_limits_answer_429(client, ctx, monkeypatch):
    from tests.conftest import FakeRedis

    redis = FakeRedis()

    async def _get():
        return redis

    monkeypatch.setattr("api.services.rate_limiter.get_redis", _get)
    _, auth = _register(client)
    # Per device: claim attempts (brute force on 6-digit codes).
    ctx.settings.billing_claim_attempts_per_device_per_hour = 1
    assert client.post("/billing/v1/claim", headers=auth, json={"code": "123456"}).status_code == 404
    r = client.post("/billing/v1/claim", headers=auth, json={"code": "123456"})
    assert r.status_code == 429 and r.json()["detail"]["category"] == "billing:claim:device"
    # Per IP: registrations.
    ctx.settings.billing_register_per_ip_per_hour = 2
    assert client.post("/billing/v1/devices", json={"platform": "android"}).status_code == 201
    assert client.post("/billing/v1/devices", json={"platform": "android"}).status_code == 429
    # Per phone: checkouts naming the same number.
    ctx.settings.billing_checkout_per_phone_per_hour = 1
    body = {"plan_code": "solo", "provider": "fake", "msisdn": "8 915 000 00 00", "consent_doc_version": CONSENT}
    assert client.post("/billing/v1/checkout", headers=auth, json=body).status_code == 201
    assert client.post("/billing/v1/checkout", headers=auth, json={**body, "msisdn": SUCCESS_NUMBER}).status_code == 429


def test_rate_limits_fail_open_without_redis(client, monkeypatch, redis_down):
    """Dev posture: a Redis outage never blocks a registration (prod sets RATE_LIMIT_FAIL_CLOSED)."""
    monkeypatch.setattr("api.services.rate_limiter.get_redis", __import__("api.services.cache", fromlist=["get_redis"]).get_redis)
    assert client.post("/billing/v1/devices", json={"platform": "android"}).status_code == 201

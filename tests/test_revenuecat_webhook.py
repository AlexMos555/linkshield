"""RevenueCat webhook: POST /api/v1/webhooks/revenuecat.

Bodies are the sample payloads in tests/data/revenuecat/ — RevenueCat's
documented shape (api_version + event; fields per
https://www.revenuecat.com/docs/integrations/webhooks/event-types-and-fields)
with Google Play / App Store values. Their *_ms timestamps are shifted so the
purchase happened "just now", keeping the gaps between events.
"""
from __future__ import annotations

import asyncio
import copy
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.services import entitlements as ent

DATA = Path(__file__).parent / "data" / "revenuecat"
SECRET = "rc-webhook-secret-for-tests-0123456789abcdef"
ACCOUNT = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
GPA = "GPA.3372-4150-8203-17209"
RECORDED_PURCHASE_MS = 1759917600000


def load(name: str, **overrides) -> dict:
    body = json.loads((DATA / f"{name}.json").read_text())
    shift = int(time.time() * 1000) - RECORDED_PURCHASE_MS
    ev = body["event"]
    for key, value in list(ev.items()):
        if key.endswith("_ms") and isinstance(value, int):
            ev[key] = value + shift
    ev.update(overrides)
    return body


@pytest.fixture
def settings(monkeypatch):
    from api.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "revenuecat_webhook_auth", SECRET)
    monkeypatch.setattr(s, "revenuecat_secret_api_key", "")
    monkeypatch.setattr(s, "revenuecat_accept_sandbox", False)
    monkeypatch.setattr(s, "revenuecat_products", "")
    return s


@pytest.fixture
def audits(monkeypatch):
    rows: list[dict] = []

    async def _write(**kw):
        rows.append(kw)

    monkeypatch.setattr("api.services.audit_log.write", _write)
    return rows


@pytest.fixture
def client(settings, fake_redis, account_store, audits):
    from api.main import app

    return TestClient(app)


def post(client, body, auth: str | None = SECRET):
    headers = {"Authorization": auth} if auth is not None else {}
    return client.post("/api/v1/webhooks/revenuecat", content=json.dumps(body), headers=headers)


def row(store, external_id=GPA, source="google_play"):
    return next(r for r in store.entitlements if (r["source"], r["external_id"]) == (source, external_id))


def effective(account=ACCOUNT):
    return asyncio.run(ent.get_effective_entitlement(account, legacy_row=None))


# ─── authorization ────────────────────────────────────────────────


@pytest.mark.parametrize("auth", [None, "", "wrong", SECRET[:-1], f"Basic {SECRET}"])
def test_wrong_or_missing_authorization_is_401_and_writes_nothing(client, account_store, auth):
    resp = post(client, load("initial_purchase"), auth=auth)
    assert resp.status_code == 401
    assert account_store.entitlements == [] and account_store.processed_events == {}


def test_bearer_prefix_is_accepted_too(client, account_store):
    assert post(client, load("initial_purchase"), auth=f"Bearer {SECRET}").status_code == 200
    assert row(account_store)["status"] == "active"


def test_unconfigured_secret_is_503_and_grants_nothing(client, settings, account_store, monkeypatch):
    monkeypatch.setattr(settings, "revenuecat_webhook_auth", "")
    assert post(client, load("initial_purchase"), auth="").status_code == 503
    assert account_store.entitlements == []


def test_malformed_bodies_are_400(client):
    assert client.post("/api/v1/webhooks/revenuecat", content=b"not json",
                       headers={"Authorization": SECRET}).status_code == 400
    assert post(client, {"api_version": "1.0"}).status_code == 400
    assert post(client, {"event": {"type": "RENEWAL"}}).status_code == 400


def test_unconfigured_database_is_503(settings, fake_redis):
    from api.main import app

    resp = post(TestClient(app), load("initial_purchase"))
    assert resp.status_code == 503


# ─── purchase lifecycle ───────────────────────────────────────────


def test_initial_purchase_writes_a_google_play_entitlement(client, account_store, fake_redis, audits):
    fake_redis._kv[f"tier:{ACCOUNT}"] = "free"
    body = load("initial_purchase")
    resp = post(client, body)
    assert resp.status_code == 200, resp.text
    assert resp.json()["result"] == "applied"

    r = row(account_store)
    assert r["account_id"] == ACCOUNT and r["plan"] == "personal"
    assert r["status"] == "active" and r["device_limit"] == 3
    assert r["product_id"] == "cleanway.devices:monthly"
    expected_end = ent._parse_ts(r["period_end"]).timestamp() * 1000
    assert abs(expected_end - body["event"]["expiration_at_ms"]) < 1
    assert r["source_event_at"]
    # Marked only after the write; tier cache dropped so limits follow at once.
    assert account_store.processed_events == {body["event"]["id"]: "INITIAL_PURCHASE"}
    assert f"tier:{ACCOUNT}" not in fake_redis._kv
    assert any(a["action"] == "subscription.store_event" for a in audits)

    e = effective()
    assert e.is_paid and e.source == "google_play" and e.device_limit == 3


def test_entitlement_endpoint_says_where_to_manage_a_play_plan(client, account_store):
    import jwt

    from api.config import get_settings

    post(client, load("initial_purchase"))
    token = jwt.encode({"sub": ACCOUNT, "email": "p@example.com", "aud": "authenticated",
                        "exp": int(time.time()) + 3600}, get_settings().supabase_jwt_secret, algorithm="HS256")
    body = client.get("/api/v1/me/entitlement", headers={"Authorization": f"Bearer {token}"}).json()
    assert body["source"] == "google_play" and body["plan"] == "personal"
    assert body["manage_url"] == (
        "https://play.google.com/store/account/subscriptions?sku=cleanway.devices&package=ai.cleanway.app"
    )


def test_duplicate_event_id_is_acknowledged_without_rewriting(client, account_store):
    body = load("initial_purchase")
    assert post(client, body).status_code == 200
    row(account_store)["status"] = "expired"  # would be rewritten if processed again
    resp = post(client, body)
    assert resp.status_code == 200 and resp.json() == {"status": "ok", "duplicate": True}
    assert row(account_store)["status"] == "expired"


def test_failed_write_is_500_unmarked_and_the_retry_applies_it(client, account_store):
    body = load("initial_purchase")
    account_store.fail = True
    assert post(client, body).status_code == 503  # dedupe lookup already fails
    account_store.fail = False

    real_upsert = account_store.upsert_entitlement

    async def failing_upsert(r):
        from api.services.account_store import AccountStoreError

        raise AccountStoreError("simulated write failure")

    account_store.upsert_entitlement = failing_upsert
    assert post(client, body).status_code == 500
    assert account_store.processed_events == {} and account_store.entitlements == []

    account_store.upsert_entitlement = real_upsert
    assert post(client, body).status_code == 200
    assert row(account_store)["status"] == "active"
    assert body["event"]["id"] in account_store.processed_events


def test_failed_mark_still_answers_200(client, account_store):
    account_store.fail_mark = True
    assert post(client, load("initial_purchase")).status_code == 200
    assert row(account_store)["status"] == "active"


def test_renewal_extends_the_same_row(client, account_store):
    post(client, load("initial_purchase"))
    renewal = load("renewal")
    assert post(client, renewal).status_code == 200
    rows = [r for r in account_store.entitlements if r["source"] == "google_play"]
    assert len(rows) == 1 and rows[0]["external_id"] == GPA
    end = ent._parse_ts(rows[0]["period_end"]).timestamp() * 1000
    assert abs(end - renewal["event"]["expiration_at_ms"]) < 1


def test_play_renewal_order_id_without_original_maps_to_the_original(client, account_store):
    body = load("renewal", original_transaction_id=None)
    assert post(client, body).status_code == 200
    assert row(account_store)["external_id"] == GPA


def test_cancellation_keeps_access_until_expiration(client, account_store):
    post(client, load("initial_purchase"))
    post(client, load("cancellation_unsubscribe"))
    assert row(account_store)["status"] == "active"
    assert effective().is_paid

    post(client, load("expiration"))
    assert row(account_store)["status"] == "expired"
    assert not effective().is_paid


def test_refund_cancellation_ends_access_now(client, account_store):
    post(client, load("initial_purchase"))
    resp = post(client, load("cancellation_refund"))
    assert resp.json()["reason"] == "refunded"
    assert row(account_store)["status"] == "refunded"
    assert not effective().is_paid


def test_billing_error_cancellation_is_past_due(client, account_store):
    post(client, load("initial_purchase"))
    post(client, load("cancellation_unsubscribe", cancel_reason="BILLING_ERROR",
                      id="cancel-billing-error"))
    assert row(account_store)["status"] == "past_due" and effective().is_paid


def test_billing_issue_keeps_access_through_the_grace_period(client, account_store):
    post(client, load("initial_purchase"))
    issue = load("billing_issue")
    post(client, issue)
    r = row(account_store)
    assert r["status"] == "past_due"
    end = ent._parse_ts(r["period_end"]).timestamp() * 1000
    assert abs(end - issue["event"]["grace_period_expiration_at_ms"]) < 1
    assert effective().is_paid


def test_uncancellation_reactivates(client, account_store):
    post(client, load("initial_purchase"))
    post(client, load("cancellation_unsubscribe", cancel_reason="BILLING_ERROR"))
    post(client, load("uncancellation"))
    assert row(account_store)["status"] == "active"


def test_pause_is_noted_and_revoked_only_on_expiration(client, account_store):
    post(client, load("initial_purchase"))
    resp = post(client, load("subscription_paused"))
    assert resp.json()["result"] == "noted"
    assert row(account_store)["status"] == "active"

    post(client, load("expiration", expiration_reason="SUBSCRIPTION_PAUSED",
                      event_timestamp_ms=int(time.time() * 1000) + 10 * 86400000))
    assert row(account_store)["status"] == "paused" and not effective().is_paid


def test_product_change_is_noted_without_a_write(client, account_store):
    post(client, load("initial_purchase"))
    before = dict(row(account_store))
    resp = post(client, load("product_change"))
    assert resp.status_code == 200 and resp.json()["result"] == "noted"
    assert row(account_store) == before


def test_out_of_order_retry_does_not_resurrect_an_expired_row(client, account_store):
    post(client, load("initial_purchase"))
    post(client, load("expiration"))
    # The RENEWAL delivery that failed earlier is retried after the EXPIRATION.
    stale = load("expiration", type="RENEWAL", id="late-renewal",
                 event_timestamp_ms=load("initial_purchase")["event"]["event_timestamp_ms"] + 1000)
    resp = post(client, stale)
    assert resp.status_code == 200 and resp.json()["result"] == "stale"
    assert row(account_store)["status"] == "expired"


def test_refund_reversed_restores_access(client, account_store):
    post(client, load("initial_purchase"))
    post(client, load("cancellation_refund"))
    post(client, load("uncancellation", type="REFUND_REVERSED", id="refund-reversed",
                      event_timestamp_ms=int(time.time() * 1000) + 5 * 86400000))
    assert row(account_store)["status"] == "active"


# ─── who bought it ────────────────────────────────────────────────


def test_anonymous_purchase_is_acknowledged_and_alerted(client, account_store, caplog):
    anon = "$RCAnonymousID:2f6e0b9d4c8a4e1f9b3a7c5d1e0f2a4b"
    resp = post(client, load("initial_purchase", app_user_id=anon, aliases=[anon], original_app_user_id=anon))
    assert resp.status_code == 200 and resp.json()["reason"] == "anonymous"
    assert account_store.entitlements == []
    assert any(r.message == "revenuecat_purchase_without_account" for r in caplog.records)


def test_account_found_through_aliases(client, account_store):
    anon = "$RCAnonymousID:abc"
    post(client, load("initial_purchase", app_user_id=anon, original_app_user_id=anon, aliases=[anon, ACCOUNT]))
    assert row(account_store)["account_id"] == ACCOUNT


def test_foreign_ids_are_not_accounts(client, account_store):
    resp = post(client, load("initial_purchase", app_user_id="user@example.com",
                             original_app_user_id="user@example.com", aliases=[]))
    assert resp.json()["reason"] == "anonymous" and account_store.entitlements == []


# ─── products, stores, environments ───────────────────────────────


def test_unknown_product_grants_nothing_and_is_audited(client, account_store, audits):
    resp = post(client, load("initial_purchase", product_id="com.other.app.pro:monthly"))
    assert resp.json()["reason"] == "unknown_product"
    assert account_store.entitlements == []
    assert any(a["action"] == "subscription.store_unknown_product" for a in audits)


def test_unknown_product_event_is_applied_by_a_retry_once_the_map_knows_it(
    client, settings, account_store, monkeypatch
):
    body = load("initial_purchase", product_id="cleanway.devices.family:monthly")
    assert post(client, body).json()["reason"] == "unknown_product"
    assert account_store.processed_events == {}  # not marked: a Retry must run it again

    monkeypatch.setattr(settings, "revenuecat_products",
                        '{"cleanway.devices.family": {"plan": "personal", "extra_devices": 2}}')
    assert post(client, body).json()["result"] == "applied"
    assert row(account_store)["device_limit"] == 5


def test_product_map_override_from_env(client, settings, account_store, monkeypatch):
    monkeypatch.setattr(settings, "revenuecat_products",
                        '{"cleanway.devices.five": {"plan": "personal", "extra_devices": 2}}')
    post(client, load("initial_purchase", product_id="cleanway.devices.five:monthly"))
    assert row(account_store)["device_limit"] == 5


def test_extra_device_addon_adds_a_device_to_the_plan(client, account_store):
    post(client, load("initial_purchase_extra_device"))
    addon = row(account_store, "GPA.3301-1122-3344-55667")
    assert addon["plan"] == ent.ADDON_PLAN and addon["device_limit"] == 1
    assert not effective().is_paid  # an add-on alone is no plan

    post(client, load("initial_purchase"))
    e = effective()
    assert e.is_paid and e.device_limit == 4


def test_app_store_trial(client, account_store):
    post(client, load("initial_purchase_app_store"))
    r = row(account_store, "2000000912345678", source="app_store")
    assert r["status"] == "trialing" and r["product_id"] == "cleanway.devices.yearly"
    assert ent.manage_url(effective()) == "https://apps.apple.com/account/subscriptions"


@pytest.mark.parametrize("store", ["STRIPE", "RC_BILLING", "PADDLE", "PROMOTIONAL", "AMAZON"])
def test_other_stores_are_not_written(client, account_store, store):
    resp = post(client, load("initial_purchase", store=store))
    assert resp.status_code == 200 and resp.json()["reason"] == "store"
    assert account_store.entitlements == []


def test_sandbox_is_ignored_unless_accepted(client, settings, account_store, monkeypatch):
    resp = post(client, load("initial_purchase", environment="SANDBOX"))
    assert resp.json()["reason"] == "sandbox" and account_store.entitlements == []

    monkeypatch.setattr(settings, "revenuecat_accept_sandbox", True)
    post(client, load("initial_purchase", environment="SANDBOX", id="sandbox-2"))
    assert row(account_store)["status"] == "active"


def test_test_event_is_acknowledged(client, account_store):
    resp = post(client, load("test"))
    assert resp.status_code == 200 and resp.json()["result"] == "ignored"
    assert account_store.entitlements == []


# ─── double payment, transfer ─────────────────────────────────────


def test_store_purchase_on_an_account_paying_by_stripe_is_flagged(client, account_store, audits):
    account_store.add_entitlement(ACCOUNT, source="stripe", external_id="sub_web")
    post(client, load("initial_purchase"))
    flagged = [a for a in audits if a["action"] == "subscription.duplicate_detected"]
    assert flagged and flagged[0]["meta"]["existing_source"] == "stripe"


def test_the_double_payment_guard_sees_the_play_plan(client, account_store):
    """Stripe checkout asks has_active_entitlement before taking money (the
    409 itself: tests/test_payments_checkout.py, source=google_play)."""
    post(client, load("initial_purchase"))
    active = asyncio.run(ent.has_active_entitlement(ACCOUNT, legacy_row=None))
    assert active is not None and active.source == "google_play"


def test_transfer_moves_store_rows_to_the_new_account(client, account_store, settings, monkeypatch):
    account_store.add_entitlement(OTHER, source="google_play", external_id=GPA, product_id="cleanway.devices:monthly")
    account_store.add_entitlement(OTHER, source="stripe", external_id="sub_other")
    synced: list[str] = []

    async def fake_sync(account_id):
        synced.append(account_id)
        return {"applied": 0, "ended": 0}

    monkeypatch.setattr("api.services.revenuecat_sync.sync_account", fake_sync)
    resp = post(client, load("transfer"))
    assert resp.status_code == 200 and resp.json()["reason"] == "transfer"
    assert row(account_store)["account_id"] == ACCOUNT
    assert row(account_store, "sub_other", source="stripe")["account_id"] == OTHER  # Stripe stays
    assert synced == []  # no secret API key → no sync

    # With the secret API key both sides are re-read from RevenueCat instead.
    monkeypatch.setattr(settings, "revenuecat_secret_api_key", "sk_test")
    body = load("transfer")
    body["event"]["id"] = "transfer-2"
    assert post(client, body).status_code == 200
    assert synced == [ACCOUNT, OTHER]


def test_transfer_sync_failure_is_500_so_revenuecat_retries(client, account_store, settings, monkeypatch):
    from api.services.revenuecat import RevenueCatError

    async def failing_sync(account_id):
        raise RevenueCatError("RevenueCat answered 503")

    monkeypatch.setattr("api.services.revenuecat_sync.sync_account", failing_sync)
    monkeypatch.setattr(settings, "revenuecat_secret_api_key", "sk_test")
    body = load("transfer")
    assert post(client, body).status_code == 500
    assert body["event"]["id"] not in account_store.processed_events


def test_transfer_to_an_anonymous_id_is_ignored(client, account_store):
    body = load("transfer")
    body["event"]["transferred_to"] = ["$RCAnonymousID:abc"]
    account_store.add_entitlement(OTHER, source="google_play", external_id=GPA)
    assert post(client, body).json()["reason"] == "anonymous"
    assert row(account_store)["account_id"] == OTHER


def test_sample_payloads_are_unchanged_by_load():
    raw = json.loads((DATA / "initial_purchase.json").read_text())
    shifted = load("initial_purchase")
    assert set(raw["event"]) == set(shifted["event"])
    assert copy.deepcopy(raw)["event"]["original_transaction_id"] == GPA

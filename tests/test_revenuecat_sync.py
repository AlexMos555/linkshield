""""Restore purchases": POST /api/v1/me/entitlement/refresh and
api/services/revenuecat_sync.py.

RevenueCat's GET /v1/subscribers/{app_user_id} is served from
tests/data/revenuecat/subscriber.json (the documented response shape,
https://www.revenuecat.com/docs/api-v1/customers) through a real httpx
client on a mock transport.
"""
from __future__ import annotations

import asyncio
import copy
import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import jwt
import pytest
from fastapi.testclient import TestClient

from api.services import entitlements as ent
from api.services import store_products

DATA = Path(__file__).parent / "data" / "revenuecat"
ACCOUNT = "11111111-1111-4111-8111-111111111111"
GPA = "GPA.3372-4150-8203-17209"


def _iso(**delta) -> str:
    return (datetime.now(timezone.utc) + timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


def subscriber(**sub_overrides) -> dict:
    body = json.loads((DATA / "subscriber.json").read_text())
    body["subscriber"]["subscriptions"]["cleanway.devices"].update(sub_overrides)
    return body


@pytest.fixture
def revenuecat_api(monkeypatch):
    """configure(body, status=200) → list of requests made to RevenueCat."""
    from api.config import get_settings

    monkeypatch.setattr(get_settings(), "revenuecat_secret_api_key", "sk_test_revenuecat_secret")
    monkeypatch.setattr(get_settings(), "revenuecat_accept_sandbox", False)
    monkeypatch.setattr(get_settings(), "revenuecat_products", "")
    real_client = httpx.AsyncClient
    state = {"body": subscriber(), "status": 200}
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(state["status"], json=state["body"])

    def client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client)

    def configure(body=None, status=200):
        state["body"] = body if body is not None else subscriber()
        state["status"] = status
        return requests

    return configure


@pytest.fixture
def client(fake_redis, account_store, monkeypatch):
    from api.main import app
    from api.services import rate_limiter

    async def _fake():
        return fake_redis

    monkeypatch.setattr(rate_limiter, "get_redis", _fake)
    return TestClient(app)


def _headers() -> dict:
    from api.config import get_settings

    token = jwt.encode(
        {"sub": ACCOUNT, "email": "p@example.com", "aud": "authenticated",
         "exp": int(time.time()) + 3600, "session_id": str(uuid.uuid4())},
        get_settings().supabase_jwt_secret, algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


def refresh(client):
    return client.post("/api/v1/me/entitlement/refresh", headers=_headers())


def store_rows(account_store, source="google_play"):
    return [r for r in account_store.entitlements if r["source"] == source]


# ─── endpoint ─────────────────────────────────────────────────────


def test_refresh_restores_a_play_purchase(client, account_store, revenuecat_api):
    requests = revenuecat_api()
    resp = refresh(client)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["source"] == "google_play" and body["plan"] == "personal"
    assert body["device_limit"] == 3 and body["manage_url"].endswith("sku=cleanway.devices&package=ai.cleanway.app")

    [row] = store_rows(account_store)
    # The REST API gives the latest order id ("..1"); the row is keyed by
    # the original, the same id the webhook uses.
    assert row["external_id"] == GPA and row["account_id"] == ACCOUNT
    assert row["product_id"] == "cleanway.devices:monthly" and row["status"] == "active"

    [req] = requests
    assert str(req.url) == f"https://api.revenuecat.com/v1/subscribers/{ACCOUNT}"
    assert req.headers["Authorization"] == "Bearer sk_test_revenuecat_secret"


def test_refresh_updates_the_webhook_row_instead_of_adding_one(client, account_store, revenuecat_api):
    account_store.add_entitlement(ACCOUNT, source="google_play", external_id=GPA, status="expired",
                                  product_id="cleanway.devices:monthly")
    revenuecat_api()
    refresh(client)
    [row] = store_rows(account_store)
    assert row["status"] == "active"


def test_refresh_without_the_secret_key_is_503(client, revenuecat_api, monkeypatch):
    from api.config import get_settings

    monkeypatch.setattr(get_settings(), "revenuecat_secret_api_key", "")
    resp = refresh(client)
    assert resp.status_code == 503 and resp.json()["detail"]["code"] == "store_sync_unavailable"


@pytest.mark.parametrize("status", [401, 500, 503])
def test_revenuecat_failure_is_502_and_writes_nothing(client, account_store, revenuecat_api, status):
    revenuecat_api(body={"code": 7000, "message": "error"}, status=status)
    resp = refresh(client)
    assert resp.status_code == 502 and resp.json()["detail"]["code"] == "store_sync_failed"
    assert account_store.entitlements == []


def test_refresh_requires_sign_in(client, revenuecat_api):
    assert client.post("/api/v1/me/entitlement/refresh").status_code in (401, 403)


def test_refresh_is_rate_limited(client, account_store, revenuecat_api):
    revenuecat_api()
    codes = [refresh(client).status_code for _ in range(12)]
    assert codes[:10] == [200] * 10 and codes[-1] == 429


# ─── what the sync writes ─────────────────────────────────────────


def _sync():
    from api.services.revenuecat_sync import sync_account

    return asyncio.run(sync_account(ACCOUNT))


@pytest.mark.parametrize(
    "overrides, status",
    [
        ({"refunded_at": _iso(days=-1)}, "refunded"),
        ({"expires_date": _iso(days=-2)}, "expired"),
        ({"expires_date": _iso(days=-2), "auto_resume_date": _iso(days=20)}, "paused"),
        ({"expires_date": _iso(hours=-1), "grace_period_expires_date": _iso(days=5),
          "billing_issues_detected_at": _iso(hours=-1)}, "past_due"),
        ({"period_type": "trial"}, "trialing"),
        ({"unsubscribe_detected_at": _iso(days=-1)}, "active"),  # paid until expires_date
    ],
)
def test_subscription_states(account_store, revenuecat_api, overrides, status):
    revenuecat_api(subscriber(**overrides))
    _sync()
    [row] = store_rows(account_store)
    assert row["status"] == status


def test_sandbox_purchases_are_skipped_unless_accepted(account_store, revenuecat_api, monkeypatch):
    from api.config import get_settings

    revenuecat_api(subscriber(is_sandbox=True))
    _sync()
    assert store_rows(account_store) == []
    monkeypatch.setattr(get_settings(), "revenuecat_accept_sandbox", True)
    _sync()
    assert store_rows(account_store)[0]["status"] == "active"


def test_rows_revenuecat_no_longer_lists_end(account_store, revenuecat_api):
    # Transferred to another App User ID: RevenueCat lists nothing for us.
    account_store.add_entitlement(ACCOUNT, source="google_play", external_id="GPA.9999-0000-1111-22222",
                                  product_id="cleanway.extra_device:monthly", plan=ent.ADDON_PLAN, device_limit=1)
    account_store.add_entitlement(ACCOUNT, source="stripe", external_id="sub_web")
    body = subscriber()
    body["subscriber"]["subscriptions"] = {}
    revenuecat_api(body)
    assert _sync() == {"applied": 0, "ended": 1}
    assert store_rows(account_store)[0]["status"] == "expired"
    assert store_rows(account_store, "stripe")[0]["status"] == "active"  # not RevenueCat's


def test_other_stores_and_unknown_products_are_skipped(account_store, revenuecat_api):
    body = subscriber()
    subs = body["subscriber"]["subscriptions"]
    subs["web_monthly"] = dict(subs["cleanway.devices"], store="stripe")
    subs["com.other.pro"] = copy.deepcopy(subs.pop("cleanway.devices"))
    revenuecat_api(body)
    assert _sync() == {"applied": 0, "ended": 0}
    assert account_store.entitlements == []


def test_app_store_row_is_found_by_product(account_store, revenuecat_api):
    """The REST API carries the LATEST App Store transaction id, not the
    original the webhook keyed the row by — match on the product instead."""
    account_store.add_entitlement(ACCOUNT, source="app_store", external_id="2000000912345678",
                                  product_id="cleanway.devices.yearly", status="past_due")
    body = subscriber()
    subs = body["subscriber"]["subscriptions"]
    subs["cleanway.devices.yearly"] = dict(subs.pop("cleanway.devices"), store="app_store",
                                           store_transaction_id="2000000998765432")
    subs["cleanway.devices.yearly"].pop("product_plan_identifier")
    revenuecat_api(body)
    _sync()
    [row] = store_rows(account_store, "app_store")
    assert row["external_id"] == "2000000912345678" and row["status"] == "active"


# ─── product map ──────────────────────────────────────────────────


def test_product_lookup_defaults_and_base_plans(monkeypatch):
    from api.config import get_settings

    monkeypatch.setattr(get_settings(), "revenuecat_products", "")
    assert store_products.lookup("cleanway.devices:yearly").plan == "personal"
    assert store_products.lookup("cleanway.devices.monthly").extra_devices == 0
    addon = store_products.lookup("cleanway.extra_device:monthly")
    assert addon.is_addon and addon.extra_devices == 1
    assert store_products.lookup("com.other:monthly") is None
    assert store_products.lookup(None) is None


def test_product_override_merges_and_bad_json_keeps_defaults(monkeypatch, caplog):
    from api.config import get_settings

    monkeypatch.setattr(get_settings(), "revenuecat_products",
                        '{"cleanway.extra_devices_3": {"extra_devices": 3}}')
    assert store_products.lookup("cleanway.extra_devices_3").extra_devices == 3
    assert store_products.lookup("cleanway.devices:monthly") is not None

    monkeypatch.setattr(get_settings(), "revenuecat_products", "{not json")
    assert store_products.lookup("cleanway.devices:monthly") is not None
    assert any(r.message == "revenuecat_products_invalid" for r in caplog.records)


@pytest.mark.parametrize(
    "raw",
    [
        '{"x": {"plan": "gold"}}',
        '{"x": {"extra_devices": 0}}',
        '{"x": {"plan": "personal", "extra_devices": 99}}',
        '{"x": {"plan": "personal", "extra_devices": true}}',
        '{"x": 1}',
        "[]",
    ],
)
def test_product_override_validation(raw):
    with pytest.raises(ValueError):
        store_products.parse_products(raw)

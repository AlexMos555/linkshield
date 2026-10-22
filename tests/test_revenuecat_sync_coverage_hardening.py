"""RevenueCat REST sync hardening: failure paths of
api/services/revenuecat_sync.py (fetch_subscriber / sync_account).

The happy paths and the "Restore purchases" endpoint live in
tests/test_revenuecat_sync.py. RevenueCat is served through a real httpx
client on a mock transport; nothing leaves the process.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

from api.services import revenuecat_sync as sync
from api.services.account_store import AccountStoreError
from api.services.revenuecat import RevenueCatError, RevenueCatNotConfigured

DATA = Path(__file__).parent / "data" / "revenuecat"
ACCOUNT = "11111111-1111-4111-8111-111111111111"
GPA = "GPA.3372-4150-8203-17209"


def subscriber(**sub_overrides) -> dict:
    body = json.loads((DATA / "subscriber.json").read_text())
    body["subscriber"]["subscriptions"]["cleanway.devices"].update(sub_overrides)
    return body


@pytest.fixture
def settings(monkeypatch):
    from api.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "revenuecat_secret_api_key", "sk_test_revenuecat_secret")
    monkeypatch.setattr(s, "revenuecat_accept_sandbox", False)
    monkeypatch.setattr(s, "revenuecat_products", "")
    return s


@pytest.fixture
def revenuecat_api(monkeypatch, settings, fake_redis):
    """answer(fn) installs fn(request) -> httpx.Response | raises; returns the
    list of requests RevenueCat received."""
    real_client = httpx.AsyncClient
    requests: list[httpx.Request] = []
    state = {"fn": lambda request: httpx.Response(200, json=subscriber())}

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return state["fn"](request)

    def client(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client)

    def answer(fn=None):
        if fn is not None:
            state["fn"] = fn
        return requests

    return answer


def run_sync(account_id: str = ACCOUNT) -> dict:
    return asyncio.run(sync.sync_account(account_id))


def store_rows(account_store, source="google_play"):
    return [r for r in account_store.entitlements if r["source"] == source]


def _iso(**delta) -> str:
    return (datetime.now(timezone.utc) + timedelta(**delta)).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─── talking to RevenueCat ────────────────────────────────────────


def test_missing_secret_key_raises_not_configured_without_a_request(revenuecat_api, settings, account_store):
    requests = revenuecat_api()
    settings.revenuecat_secret_api_key = ""
    with pytest.raises(RevenueCatNotConfigured):
        run_sync()
    assert requests == [] and account_store.entitlements == []


@pytest.mark.parametrize("exc", [httpx.ConnectError("refused"), httpx.ReadTimeout("slow"), RuntimeError("tls")])
def test_network_failure_is_a_revenuecat_error_and_writes_nothing(revenuecat_api, account_store, exc):
    def boom(request):
        raise exc

    revenuecat_api(boom)
    account_store.add_entitlement(ACCOUNT, source="google_play", external_id=GPA, product_id="cleanway.devices:monthly")
    with pytest.raises(RevenueCatError, match="request failed"):
        run_sync()
    assert store_rows(account_store)[0]["status"] == "active"  # not ended by a failed read


def test_invalid_json_from_revenuecat_is_an_error(revenuecat_api, account_store):
    revenuecat_api(lambda request: httpx.Response(200, content=b"<html>gateway</html>"))
    with pytest.raises(RevenueCatError, match="invalid JSON"):
        run_sync()
    assert account_store.entitlements == []


@pytest.mark.parametrize("payload", [{}, {"subscriber": None}, {"subscriber": []}, {"subscriber": "x"}, []])
def test_answer_without_a_subscriber_object_is_an_error(revenuecat_api, account_store, payload):
    """An empty/odd answer must not be read as "no purchases" (which would
    end every store row of the account)."""
    account_store.add_entitlement(ACCOUNT, source="google_play", external_id=GPA, product_id="cleanway.devices:monthly")
    revenuecat_api(lambda request: httpx.Response(200, json=payload))
    with pytest.raises(RevenueCatError):
        run_sync()
    assert store_rows(account_store)[0]["status"] == "active"


def test_201_new_customer_is_accepted(revenuecat_api, account_store):
    body = subscriber()
    body["subscriber"]["subscriptions"] = {}
    revenuecat_api(lambda request: httpx.Response(201, json=body))
    assert run_sync() == {"applied": 0, "ended": 0}


def test_app_user_id_is_escaped_into_one_path_segment(revenuecat_api):
    requests = revenuecat_api()
    asyncio.run(sync.fetch_subscriber("../../projects/x?y=1#z"))
    [req] = requests
    assert req.url.raw_path.decode() == "/v1/subscribers/..%2F..%2Fprojects%2Fx%3Fy%3D1%23z"
    assert req.url.host == "api.revenuecat.com"


# ─── database failures ────────────────────────────────────────────


def test_without_a_database_sync_raises(revenuecat_api):
    from api.services import account_store as store_module

    store_module.set_account_store(None)
    with pytest.raises(RevenueCatError, match="not configured"):
        run_sync()


def test_listing_rows_failing_is_an_error(revenuecat_api, account_store):
    account_store.fail = True
    with pytest.raises(RevenueCatError, match="outage"):
        run_sync()
    account_store.fail = False
    assert account_store.entitlements == []


def test_write_failure_while_applying_is_an_error(revenuecat_api, account_store, monkeypatch):
    async def down(row):
        raise AccountStoreError("simulated write failure")

    monkeypatch.setattr(account_store, "upsert_entitlement", down)
    with pytest.raises(RevenueCatError, match="write failure"):
        run_sync()


def test_write_failure_while_ending_a_transferred_row_is_an_error(revenuecat_api, account_store, monkeypatch):
    account_store.add_entitlement(ACCOUNT, source="google_play", external_id="GPA.0000-0000-0000-00001",
                                  product_id="cleanway.extra_device:monthly")
    body = subscriber()
    body["subscriber"]["subscriptions"] = {}
    revenuecat_api(lambda request: httpx.Response(200, json=body))

    async def down(row):
        raise AccountStoreError("simulated write failure")

    monkeypatch.setattr(account_store, "upsert_entitlement", down)
    with pytest.raises(RevenueCatError):
        run_sync()
    assert store_rows(account_store)[0]["status"] == "active"


# ─── odd subscription entries ─────────────────────────────────────


def test_non_object_subscription_entries_are_skipped(revenuecat_api, account_store):
    body = subscriber()
    body["subscriber"]["subscriptions"]["cleanway.broken"] = "not-an-object"
    body["subscriber"]["subscriptions"]["cleanway.null"] = None
    revenuecat_api(lambda request: httpx.Response(200, json=body))
    assert run_sync() == {"applied": 1, "ended": 0}
    assert [r["external_id"] for r in store_rows(account_store)] == [GPA]


@pytest.mark.parametrize("txn", [None, ""])
def test_subscription_without_a_transaction_id_is_skipped(revenuecat_api, account_store, txn):
    revenuecat_api(lambda request: httpx.Response(200, json=subscriber(store_transaction_id=txn)))
    assert run_sync() == {"applied": 0, "ended": 0}
    assert account_store.entitlements == []


def test_play_subscription_without_transaction_id_updates_nothing_it_cannot_identify(revenuecat_api, account_store):
    # On Play an unmatched id is never guessed by product (that's App Store only).
    account_store.add_entitlement(ACCOUNT, source="google_play", external_id=GPA, status="past_due",
                                  product_id="cleanway.devices:monthly")
    revenuecat_api(lambda request: httpx.Response(200, json=subscriber(store_transaction_id=None)))
    assert run_sync() == {"applied": 0, "ended": 0}
    assert store_rows(account_store)[0]["status"] == "past_due"


def test_active_row_listed_but_skipped_as_sandbox_is_left_alone(revenuecat_api, account_store):
    account_store.add_entitlement(ACCOUNT, source="google_play", external_id=GPA, status="active",
                                  product_id="cleanway.devices:monthly")
    revenuecat_api(lambda request: httpx.Response(200, json=subscriber(is_sandbox=True)))
    assert run_sync() == {"applied": 0, "ended": 0}
    assert store_rows(account_store)[0]["status"] == "active"


def test_already_ended_and_non_store_rows_are_not_rewritten(revenuecat_api, account_store):
    account_store.add_entitlement(ACCOUNT, source="google_play", external_id="GPA.old", status="refunded",
                                  product_id="cleanway.extra_device:monthly")
    account_store.add_entitlement(ACCOUNT, source="stripe", external_id="sub_web", status="active")
    body = subscriber()
    body["subscriber"]["subscriptions"] = {}
    revenuecat_api(lambda request: httpx.Response(200, json=body))
    assert run_sync() == {"applied": 0, "ended": 0}
    assert store_rows(account_store)[0]["status"] == "refunded"
    assert store_rows(account_store, "stripe")[0]["status"] == "active"


def test_refund_wins_over_a_future_expiry(revenuecat_api, account_store):
    revenuecat_api(lambda request: httpx.Response(200, json=subscriber(refunded_at=_iso(hours=-1),
                                                                       expires_date=_iso(days=30))))
    run_sync()
    assert store_rows(account_store)[0]["status"] == "refunded"


def test_billing_issue_past_the_grace_period_is_expired(revenuecat_api, account_store):
    revenuecat_api(lambda request: httpx.Response(200, json=subscriber(
        expires_date=_iso(days=-10), grace_period_expires_date=_iso(days=-3),
        billing_issues_detected_at=_iso(days=-10))))
    run_sync()
    [row] = store_rows(account_store)
    assert row["status"] == "expired"
    assert sync.parse_ts(row["period_end"]) < datetime.now(timezone.utc)


def test_tier_cache_is_dropped_after_a_sync(revenuecat_api, account_store, fake_redis):
    fake_redis._kv[f"tier:{ACCOUNT}"] = "free"
    run_sync()
    assert f"tier:{ACCOUNT}" not in fake_redis._kv


# ─── delete_subscriber (the GDPR purge) ───────────────────────────


@pytest.mark.parametrize("status", [200, 202, 204, 404])
def test_delete_subscriber_accepts_deleted_and_already_gone(revenuecat_api, status):
    requests = revenuecat_api(lambda request: httpx.Response(status, json={"app_user_id": ACCOUNT}))
    asyncio.run(sync.delete_subscriber(ACCOUNT))
    [req] = requests
    assert req.method == "DELETE"
    assert str(req.url) == f"https://api.revenuecat.com/v1/subscribers/{ACCOUNT}"
    assert req.headers["Authorization"] == "Bearer sk_test_revenuecat_secret"


@pytest.mark.parametrize("status", [400, 401, 429, 500, 503])
def test_delete_subscriber_failure_is_an_error(revenuecat_api, status):
    revenuecat_api(lambda request: httpx.Response(status, json={}))
    with pytest.raises(RevenueCatError, match=str(status)):
        asyncio.run(sync.delete_subscriber(ACCOUNT))


def test_delete_subscriber_network_failure_is_an_error(revenuecat_api):
    def boom(request):
        raise httpx.ConnectError("refused")

    revenuecat_api(boom)
    with pytest.raises(RevenueCatError, match="request failed"):
        asyncio.run(sync.delete_subscriber(ACCOUNT))


def test_delete_subscriber_without_a_key_sends_nothing(revenuecat_api, settings):
    requests = revenuecat_api()
    settings.revenuecat_secret_api_key = ""
    with pytest.raises(RevenueCatNotConfigured):
        asyncio.run(sync.delete_subscriber(ACCOUNT))
    assert requests == []


def test_delete_subscriber_escapes_the_id_into_one_path_segment(revenuecat_api):
    requests = revenuecat_api(lambda request: httpx.Response(200, json={}))
    asyncio.run(sync.delete_subscriber("../x?y=1"))
    [req] = requests
    assert req.url.raw_path.decode() == "/v1/subscribers/..%2Fx%3Fy%3D1"

"""RevenueCat webhook hardening: failure paths of POST /api/v1/webhooks/revenuecat
(api/routers/revenuecat.py) and of the event handler behind it
(api/services/revenuecat.py).

The happy paths and the purchase lifecycle live in tests/test_revenuecat_webhook.py.

Here the router is mounted on a bare FastAPI app. Besides isolating the
handler from unrelated middleware, this makes it measurable: behind the
full app's two stacked BaseHTTPMiddleware layers (SecurityHeaders +
request logging), coverage.py stops recording the endpoint's frame after
`await request.body()`, so lines that DO run were reported as missed.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.routers import revenuecat as rc_router
from api.services import revenuecat as rc
from api.services.account_store import AccountStoreError
from api.services.entitlements import EntitlementError
from tests.test_revenuecat_webhook import ACCOUNT, GPA, OTHER, SECRET, load

URL = "/api/v1/webhooks/revenuecat"


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
def app():
    a = FastAPI()
    a.include_router(rc_router.router)
    return a


@pytest.fixture
def client(app, settings, fake_redis, account_store, audits, security_events):
    return TestClient(app)


def post_raw(client, content: bytes, auth: str | None = SECRET):
    headers = {"Authorization": auth} if auth is not None else {}
    return client.post(URL, content=content, headers=headers)


def post(client, body, auth: str | None = SECRET):
    return post_raw(client, json.dumps(body).encode(), auth)


def rows(store, source="google_play"):
    return [r for r in store.entitlements if r["source"] == source]


def row(store, external_id=GPA, source="google_play"):
    return next(r for r in rows(store, source) if r["external_id"] == external_id)


def padded(target_len: int) -> bytes:
    """A valid INITIAL_PURCHASE body exactly `target_len` bytes long."""
    body = load("initial_purchase")
    body["event"]["subscriber_attributes"] = {"pad": {"value": ""}}
    base = len(json.dumps(body).encode())
    body["event"]["subscriber_attributes"]["pad"]["value"] = "x" * (target_len - base)
    raw = json.dumps(body).encode()
    assert len(raw) == target_len
    return raw


# ─── authorization ────────────────────────────────────────────────


def test_non_ascii_authorization_header_is_401_not_a_crash(client, account_store, security_events):
    # Header bytes arrive latin-1 decoded; re-encoding must not raise.
    resp = client.post(URL, content=json.dumps(load("initial_purchase")).encode(),
                       headers=[(b"authorization", "Bearer éÿ".encode("latin-1"))])
    assert resp.status_code == 401
    assert account_store.entitlements == [] and account_store.processed_events == {}
    assert security_events == [("webhook_signature_invalid", "revenuecat")]


@pytest.mark.parametrize("auth", [f"{SECRET} ", f"Bearer  {SECRET}", f"Bearer {SECRET}x", SECRET.upper(), "Bearer "])
def test_near_miss_secrets_are_refused(client, account_store, auth):
    assert post(client, load("initial_purchase"), auth=auth).status_code == 401
    assert account_store.entitlements == []


def test_unauthorized_request_is_refused_before_the_body_is_parsed(client):
    # A forged request with garbage never reaches JSON parsing (no 400 oracle).
    assert post_raw(client, b"{not json", auth="wrong").status_code == 401


def test_both_accepted_forms_are_compared_in_constant_time(client, monkeypatch):
    """The secret is checked with hmac.compare_digest against BOTH accepted
    forms on every request, so timing doesn't reveal which form matched."""
    import hmac

    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a, b):
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(rc_router.hmac, "compare_digest", spy)
    assert post(client, load("initial_purchase")).status_code == 200
    assert [b for _, b in calls] == [SECRET.encode(), f"Bearer {SECRET}".encode()]
    assert all(isinstance(a, bytes) for a, _ in calls)


def test_unconfigured_secret_refuses_even_an_empty_authorization(client, settings, account_store, security_events):
    settings.revenuecat_webhook_auth = ""
    resp = post(client, load("initial_purchase"), auth=None)
    assert resp.status_code == 503 and account_store.entitlements == []
    assert security_events == []  # misconfiguration, not an attack


# ─── body shape ───────────────────────────────────────────────────


def test_body_at_the_size_limit_is_processed(client, account_store):
    resp = post_raw(client, padded(rc_router.MAX_BODY_BYTES))
    assert resp.status_code == 200 and resp.json()["result"] == "applied"
    assert row(account_store)["status"] == "active"


def test_body_one_byte_over_the_limit_is_413_and_writes_nothing(client, account_store):
    # Under the global 1 MiB request cap: this is the router's own, tighter check.
    resp = post_raw(client, padded(rc_router.MAX_BODY_BYTES + 1))
    assert resp.status_code == 413
    assert account_store.entitlements == [] and account_store.processed_events == {}


@pytest.mark.parametrize("raw", [
    b"", b"\xff\xfe\x00garbage", b'{"event": ', b"NaN-ish",
    # Nested past the interpreter's recursion limit: json raises
    # RecursionError, which must still be a 400, not a 500.
    b"[" * 100_000,
])
def test_unparseable_bodies_are_400(client, account_store, raw):
    assert post_raw(client, raw).status_code == 400
    assert account_store.processed_events == {}


@pytest.mark.parametrize(
    "body",
    [
        [],
        "event",
        None,
        42,
        {"event": None},
        {"event": ["INITIAL_PURCHASE"]},
        {"event": "INITIAL_PURCHASE"},
        {"event": {"id": "", "type": "RENEWAL"}},
        {"event": {"id": "abc", "type": ""}},
        {"event": {"id": 0, "type": "RENEWAL"}},
        {"event": {"id": "abc"}},
    ],
)
def test_bodies_without_a_usable_event_are_400(client, account_store, body):
    resp = post(client, body)
    assert resp.status_code == 400 and resp.json()["detail"] == "Missing event"
    assert account_store.processed_events == {}


def test_long_event_id_and_type_are_truncated_for_the_dedupe_table(client, account_store):
    body = load("test", id="E" * 1000, type="T" * 200)
    assert post(client, body).status_code == 200
    assert account_store.processed_events == {"E" * 255: "T" * 64}
    # A retry with the same id is recognised through the truncated key.
    assert post(client, body).json() == {"status": "ok", "duplicate": True}


def test_numeric_event_id_is_accepted_as_a_string(client, account_store):
    assert post(client, load("test", id=12345)).status_code == 200
    assert account_store.processed_events == {"12345": "TEST"}


# ─── database and idempotency ─────────────────────────────────────


def test_no_database_is_503_and_nothing_is_applied(app, settings, fake_redis, monkeypatch):
    called = []

    async def spy(event):
        called.append(event)

    monkeypatch.setattr(rc_router, "apply_event", spy)
    resp = post(TestClient(app), load("initial_purchase"))
    assert resp.status_code == 503 and called == []


def test_dedupe_lookup_failure_is_503_and_nothing_is_applied(client, account_store, monkeypatch):
    async def down(event_id):
        raise AccountStoreError("simulated Supabase outage")

    monkeypatch.setattr(account_store, "is_event_processed", down)
    resp = post(client, load("initial_purchase"))
    assert resp.status_code == 503
    assert account_store.entitlements == [] and account_store.processed_events == {}


def test_replayed_event_is_not_reapplied(client, account_store, monkeypatch):
    body = load("initial_purchase")
    assert post(client, body).json()["result"] == "applied"

    async def must_not_run(event):
        raise AssertionError("a replayed event id was processed again")

    monkeypatch.setattr(rc_router, "apply_event", must_not_run)
    assert post(client, body).json() == {"status": "ok", "duplicate": True}
    assert len(rows(account_store)) == 1


def test_replay_with_a_new_id_but_older_timestamp_is_stale(client, account_store):
    """A forged-looking replay of an old RENEWAL under a fresh id can't undo
    a later EXPIRATION: the row's source_event_at orders events."""
    post(client, load("initial_purchase"))
    post(client, load("expiration"))
    replay = load("renewal", id="fresh-id-old-event",
                  event_timestamp_ms=load("initial_purchase")["event"]["event_timestamp_ms"])
    assert post(client, replay).json()["result"] == "stale"
    assert row(account_store)["status"] == "expired"


def test_lookup_of_the_existing_row_failing_is_500_and_unmarked(client, account_store, monkeypatch):
    async def down(**kw):
        raise AccountStoreError("simulated read failure")

    monkeypatch.setattr(account_store, "get_entitlement", down)
    body = load("initial_purchase")
    assert post(client, body).status_code == 500
    assert account_store.processed_events == {} and account_store.entitlements == []


def test_failed_mark_is_logged_and_the_retry_rewrites_the_same_row(client, account_store, caplog):
    body = load("initial_purchase")
    account_store.fail_mark = True
    with caplog.at_level(logging.WARNING, logger="cleanway.revenuecat"):
        assert post(client, body).status_code == 200
    assert any(r.message == "revenuecat_mark_failed" for r in caplog.records)
    assert account_store.processed_events == {}

    account_store.fail_mark = False
    assert post(client, body).json()["result"] == "applied"
    assert len(rows(account_store)) == 1 and body["event"]["id"] in account_store.processed_events


def test_redis_down_does_not_block_a_purchase(app, settings, redis_down, account_store, audits):
    """Redis only holds the tier cache; dedupe is in the database. With
    Redis down the purchase is still applied and marked."""
    body = load("initial_purchase")
    resp = post(TestClient(app), body)
    assert resp.status_code == 200 and resp.json()["result"] == "applied"
    assert row(account_store)["status"] == "active"
    assert body["event"]["id"] in account_store.processed_events


@pytest.mark.parametrize(
    "overrides, reason, marked",
    [
        ({"environment": "SANDBOX"}, "sandbox", False),
        ({"product_id": "com.other.app:monthly"}, "unknown_product", False),
        ({"store": "STRIPE"}, "store", True),
        ({"type": "SOME_FUTURE_EVENT"}, "event_type", True),
        ({"type": "SUBSCRIPTION_PAUSED"}, "subscription_paused", True),
        ({"app_user_id": "$RCAnonymousID:x", "original_app_user_id": None, "aliases": None}, "anonymous", True),
        ({"original_transaction_id": None, "transaction_id": None}, "no_transaction_id", True),
    ],
)
def test_only_config_dependent_skips_stay_retryable(client, account_store, overrides, reason, marked):
    body = load("initial_purchase", **overrides)
    resp = post(client, body)
    assert resp.status_code == 200 and resp.json()["reason"] == reason
    assert account_store.entitlements == []
    assert (body["event"]["id"] in account_store.processed_events) is marked


# ─── what an event writes ─────────────────────────────────────────


def test_sandbox_event_is_written_when_accepted_and_production_always(client, settings, account_store):
    assert post(client, load("initial_purchase", environment="PRODUCTION", id="prod")).json()["result"] == "applied"
    account_store.entitlements.clear()
    settings.revenuecat_accept_sandbox = True
    assert post(client, load("initial_purchase", environment="SANDBOX", id="sbx")).json()["result"] == "applied"


def test_refund_reversed_after_the_period_ended_does_not_restore_access(client, account_store):
    post(client, load("initial_purchase"))
    refund = load("cancellation_refund")
    post(client, refund)
    reversed_late = load("uncancellation", type="REFUND_REVERSED", id="refund-reversed-late",
                         expiration_at_ms=int(time.time() * 1000) - 86400000,
                         event_timestamp_ms=refund["event"]["event_timestamp_ms"] + 1000)
    assert post(client, reversed_late).json()["reason"] == "expired"
    assert row(account_store)["status"] == "expired"


def test_garbage_timestamps_neither_crash_nor_wipe_the_paid_period(client, account_store):
    paid_until = "2099-01-01T00:00:00+00:00"
    an_hour_ago = datetime.fromtimestamp(time.time() - 3600, tz=timezone.utc).isoformat()
    account_store.add_entitlement(ACCOUNT, source="google_play", external_id=GPA, period_end=paid_until,
                                  source_event_at=an_hour_ago, product_id="cleanway.devices:monthly")
    renewal = load("renewal", expiration_at_ms="soon", event_timestamp_ms=10 ** 30)
    resp = post(client, renewal)
    assert resp.status_code == 200 and resp.json()["result"] == "applied"
    r = row(account_store)
    assert r["status"] == "active" and r["period_end"] == paid_until
    # An unusable event time falls back to "now", so ordering still works.
    assert rc.parse_ts(r["source_event_at"]).timestamp() == pytest.approx(time.time(), abs=60)


def test_unparseable_stored_event_time_does_not_block_new_events(client, account_store):
    account_store.add_entitlement(ACCOUNT, source="google_play", external_id=GPA, status="expired",
                                  source_event_at="not-a-timestamp")
    assert post(client, load("renewal")).json()["result"] == "applied"
    assert row(account_store)["status"] == "active"


def test_purchase_seen_on_another_account_moves_to_the_event_account(client, account_store, caplog):
    account_store.add_entitlement(OTHER, source="google_play", external_id=GPA, status="active")
    with caplog.at_level(logging.WARNING, logger="cleanway.revenuecat"):
        assert post(client, load("renewal")).json()["result"] == "applied"
    assert row(account_store)["account_id"] == ACCOUNT
    assert any(r.message == "revenuecat_purchase_moved_account" for r in caplog.records)


def test_double_payment_check_failing_still_grants_the_paid_purchase(client, account_store, audits, monkeypatch, caplog):
    async def down(account_id, **kw):
        raise EntitlementError("simulated read failure")

    monkeypatch.setattr(rc, "get_effective_entitlement", down)
    with caplog.at_level(logging.WARNING, logger="cleanway.revenuecat"):
        assert post(client, load("initial_purchase")).json()["result"] == "applied"
    assert row(account_store)["status"] == "active"
    assert any(r.message == "revenuecat_double_payment_check_failed" for r in caplog.records)
    assert not any(a["action"] == "subscription.duplicate_detected" for a in audits)


def test_renewing_the_same_store_purchase_is_not_flagged_as_double_payment(client, account_store, audits):
    post(client, load("initial_purchase"))
    post(client, load("initial_purchase", id="redelivered-initial"))
    assert not any(a["action"] == "subscription.duplicate_detected" for a in audits)


def test_record_failure_is_500_and_unmarked(client, account_store, monkeypatch):
    async def down(r):
        raise AccountStoreError("simulated write failure")

    monkeypatch.setattr(account_store, "upsert_entitlement", down)
    body = load("cancellation_refund")
    assert post(client, body).status_code == 500
    assert body["event"]["id"] not in account_store.processed_events


# ─── transfer ─────────────────────────────────────────────────────


def test_transfer_move_failure_is_500_and_moves_nothing(client, account_store, monkeypatch):
    account_store.add_entitlement(OTHER, source="google_play", external_id=GPA)

    async def down(**kw):
        raise AccountStoreError("simulated write failure")

    monkeypatch.setattr(account_store, "reassign_entitlements", down)
    body = load("transfer")
    assert post(client, body).status_code == 500
    assert row(account_store)["account_id"] == OTHER
    assert body["event"]["id"] not in account_store.processed_events


def test_transfer_ignores_the_destination_listed_as_a_source(client, account_store, audits):
    account_store.add_entitlement(ACCOUNT, source="google_play", external_id=GPA)
    body = load("transfer")
    body["event"]["transferred_from"] = [ACCOUNT, "$RCAnonymousID:abc", "not-a-uuid"]
    body["event"]["transferred_to"] = ["$RCAnonymousID:zzz", ACCOUNT]
    assert post(client, body).json()["reason"] == "transfer"
    assert row(account_store)["account_id"] == ACCOUNT
    [audit] = [a for a in audits if a["action"] == "subscription.store_transferred"]
    assert audit["meta"] == {"from_accounts": [], "synced": False}


# ─── service without a database ───────────────────────────────────


def test_apply_event_without_a_database_raises_instead_of_granting(settings):
    from api.services import account_store as store_module

    store_module.set_account_store(None)
    with pytest.raises(rc.RevenueCatError):
        asyncio.run(rc.apply_event(load("initial_purchase")["event"]))

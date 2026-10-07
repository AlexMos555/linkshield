"""
Stripe webhook integration tests.

Covers POST /api/v1/payments/webhook end-to-end:
  - Signature verification (good / bad / missing)
  - Routing to the four handler types
  - Subscription persistence shape (tier, status, provider_id)
  - Edge cases: missing user_id metadata, unknown event types

Strategy: build minimal Stripe-shaped JSON payloads + sign them with
a known webhook secret using stripe.WebhookSignature._compute_signature.
Mock httpx.AsyncClient to capture what would be POSTed to Supabase
without touching the network. Mock Redis with a fake to verify the
tier cache invalidation step.
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

import pytest
import stripe
from fastapi.testclient import TestClient


WEBHOOK_SECRET = "whsec_test_cleanway_unit_test_secret_value"


# ─── Stripe signature helper ───────────────────────────────────────


def _sign(payload: bytes, secret: str = WEBHOOK_SECRET, t: Optional[int] = None) -> str:
    """Build a stripe-signature header that construct_event will accept."""
    timestamp = int(t if t is not None else time.time())
    signed_payload = f"{timestamp}.{payload.decode('utf-8')}"
    signature = stripe.WebhookSignature._compute_signature(signed_payload, secret)
    return f"t={timestamp},v1={signature}"


def _event(event_type: str, data: Dict[str, Any]) -> bytes:
    """Wrap a data object in the Stripe Event envelope expected by webhooks."""
    envelope = {
        "id": f"evt_test_{event_type.replace('.', '_')}",
        "type": event_type,
        "object": "event",
        "data": {"object": data},
    }
    return json.dumps(envelope).encode("utf-8")


# ─── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def supabase_ok(monkeypatch):
    """Pretend Supabase env is configured so _update_subscription proceeds."""
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "fake_service_key", raising=False)
    monkeypatch.setattr(settings, "stripe_webhook_secret", WEBHOOK_SECRET, raising=False)
    monkeypatch.setattr(settings, "stripe_secret_key", "sk_test_dummy", raising=False)
    return settings


class FakeSubscriptionsTable:
    """Captures POSTs to /rest/v1/subscriptions so we can assert on the
    body AND the URL (the latter pins the `on_conflict=user_id` upsert
    semantics introduced after migration 013).

    Also serves GET lookups from `rows` (the webhook resolves the user
    behind a refund / dispute / metadata-less subscription event via
    provider_subscription_id or stripe_customer_id), and can simulate a
    failing write via `post_status` / `post_error`.
    """

    def __init__(self) -> None:
        self.posts: List[Dict[str, Any]] = []
        self.urls: List[str] = []
        # Separate list for /rest/v1/audit_log writes — keeps the
        # existing subscriptions assertions undisturbed when audit
        # rows fire alongside the main write.
        self.audit_posts: List[Dict[str, Any]] = []
        self.rows: List[Dict[str, Any]] = []
        self.gets: List[Dict[str, Any]] = []
        self.post_status = 201
        self.post_error: Optional[Exception] = None

    def build(self):
        recorder = self

        class _Resp:
            def __init__(self, status: int, body: Any = None):
                self.status_code = status
                self.text = "" if status < 400 else "upstream error"
                self._body = body

            def json(self):
                return self._body if self._body is not None else [{"ok": True}]

        class _Client:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def post(self, url, headers=None, json=None, params=None):
                if "/rest/v1/subscriptions" in url:
                    if recorder.post_error is not None:
                        raise recorder.post_error
                    if recorder.post_status >= 300:
                        return _Resp(recorder.post_status)
                    recorder.posts.append(json or {})
                    recorder.urls.append(url)
                elif "/rest/v1/audit_log" in url:
                    recorder.audit_posts.append(json or {})
                return _Resp(201)

            async def get(self, url, params=None, headers=None, **_kw):
                params = dict(params or {})
                recorder.gets.append({"url": url, "params": params})
                matches = list(recorder.rows)
                for col, cond in params.items():
                    if col in ("select", "limit", "order"):
                        continue
                    want = cond.split(".", 1)[1] if "." in cond else cond
                    matches = [r for r in matches if str(r.get(col)) == want]
                return _Resp(200, matches[:1])

            async def patch(self, url, params=None, json=None, headers=None, **_kw):
                return _Resp(204)

        return _Client


@pytest.fixture
def fake_subscriptions(monkeypatch):
    import httpx as _httpx

    fake = FakeSubscriptionsTable()
    monkeypatch.setattr(_httpx, "AsyncClient", fake.build())
    return fake


class FakeRedis:
    """Just enough surface for _update_subscription's invalidation step
    and the webhook idempotency gate (SET NX lease → SET done marker →
    DELETE on failure)."""

    def __init__(self) -> None:
        self.deleted: List[str] = []
        self.kv: Dict[str, Any] = {}

    async def delete(self, key: str):
        self.deleted.append(key)
        self.kv.pop(key, None)
        return 1

    async def get(self, key: str):
        return self.kv.get(key)

    async def set(self, key: str, value, nx: bool = False, ex: int | None = None):
        """Mirror redis-py's set(..., nx=True): returns truthy when the
        key was NOT previously set; falsy on re-set."""
        if nx and key in self.kv:
            return None  # already taken — duplicate
        self.kv[key] = value
        return True


@pytest.fixture
def fake_redis(monkeypatch):
    fake = FakeRedis()

    async def _get():
        return fake

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    return fake


@pytest.fixture
def client():
    from api.main import app
    return TestClient(app)


# ─── Signature verification ────────────────────────────────────────


def test_webhook_rejects_bad_signature(client, supabase_ok):
    payload = _event("checkout.session.completed", {"metadata": {"user_id": "u1"}})
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": "t=1,v1=deadbeef"},
    )
    assert resp.status_code == 400


def test_webhook_rejects_missing_signature(client, supabase_ok):
    payload = _event("checkout.session.completed", {"metadata": {"user_id": "u1"}})
    resp = client.post("/api/v1/payments/webhook", content=payload)
    assert resp.status_code == 400


def test_webhook_rejects_signature_with_wrong_secret(client, supabase_ok):
    payload = _event("checkout.session.completed", {"metadata": {"user_id": "u1"}})
    sig = _sign(payload, secret="whsec_attacker_guessed_wrong")
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": sig},
    )
    assert resp.status_code == 400


# ─── checkout.session.completed → upsert ──────────────────────────


def test_checkout_completed_personal_monthly_upserts_personal_active(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    payload = _event(
        "checkout.session.completed",
        {
            "metadata": {"user_id": "user-A", "plan": "personal_monthly"},
            "subscription": "sub_test_123",
        },
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200, resp.text
    assert len(fake_subscriptions.posts) == 1
    sent = fake_subscriptions.posts[0]
    assert sent["user_id"] == "user-A"
    assert sent["tier"] == "personal"
    assert sent["status"] == "active"
    assert sent["provider"] == "stripe"
    assert sent["provider_subscription_id"] == "sub_test_123"
    assert "tier:user-A" in fake_redis.deleted


def test_checkout_completed_family_yearly_upserts_family_active(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    payload = _event(
        "checkout.session.completed",
        {
            "metadata": {"user_id": "user-B", "plan": "family_yearly"},
            "subscription": "sub_test_fam",
        },
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    assert fake_subscriptions.posts[0]["tier"] == "family"


def test_checkout_completed_no_user_id_skips_persistence(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    payload = _event(
        "checkout.session.completed",
        {"metadata": {"plan": "personal_monthly"}},  # no user_id
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    assert fake_subscriptions.posts == []


# ─── customer.subscription.updated → status mapping ──────────────


def test_subscription_updated_active_maps_to_active(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    payload = _event(
        "customer.subscription.updated",
        {
            "id": "sub_test",
            "status": "active",
            "metadata": {"user_id": "user-C"},
        },
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    assert fake_subscriptions.posts[0]["status"] == "active"
    assert fake_subscriptions.posts[0]["user_id"] == "user-C"


def test_subscription_updated_trialing_maps_to_active(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    payload = _event(
        "customer.subscription.updated",
        {"id": "sub_t", "status": "trialing", "metadata": {"user_id": "user-D"}},
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    assert fake_subscriptions.posts[0]["status"] == "active"


def test_subscription_updated_past_due_maps_to_past_due(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    payload = _event(
        "customer.subscription.updated",
        {"id": "sub_pd", "status": "past_due", "metadata": {"user_id": "user-E"}},
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    assert fake_subscriptions.posts[0]["status"] == "past_due"


def test_subscription_updated_canceled_maps_to_cancelled(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    payload = _event(
        "customer.subscription.updated",
        {"id": "sub_x", "status": "canceled", "metadata": {"user_id": "user-F"}},
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    assert fake_subscriptions.posts[0]["status"] == "cancelled"


# ─── customer.subscription.deleted → free + cancelled ─────────────


def test_subscription_deleted_drops_to_free(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    payload = _event(
        "customer.subscription.deleted",
        {"id": "sub_del", "metadata": {"user_id": "user-G"}},
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    sent = fake_subscriptions.posts[0]
    assert sent["tier"] == "free"
    assert sent["status"] == "cancelled"
    assert "tier:user-G" in fake_redis.deleted


def test_subscription_deleted_no_user_id_skips(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    payload = _event(
        "customer.subscription.deleted",
        {"id": "sub_del", "metadata": {}},
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    assert fake_subscriptions.posts == []


# ─── invoice.payment_failed → log only ────────────────────────────


def test_payment_failed_logged_no_persistence(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    payload = _event(
        "invoice.payment_failed",
        {"id": "in_test", "subscription": "sub_xyz"},
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    # Payment-failed handler doesn't write to DB — only logs warn
    assert fake_subscriptions.posts == []


# ─── Unknown event types are accepted (forward-compat) ───────────


def test_unknown_event_type_returns_200_no_op(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    payload = _event("customer.created", {"id": "cus_new", "email": "test@test.com"})
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    # Stripe sends events we don't handle (customer.created, charge.succeeded, etc.).
    # We must accept them so Stripe doesn't retry; just don't act on them.
    assert resp.status_code == 200
    assert fake_subscriptions.posts == []


# ─── Idempotency (Stripe replay) ──────────────────────────────


def test_duplicate_event_id_processes_once_then_skips(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """Stripe explicitly documents at-least-once delivery. Replaying
    the same event.id must result in ONE Supabase upsert, not two."""
    payload = _event(
        "checkout.session.completed",
        {
            "metadata": {"user_id": "user-idem", "plan": "personal_monthly"},
            "subscription": "sub_test_idem",
        },
    )
    sig = _sign(payload)
    # First delivery — processed.
    r1 = client.post("/api/v1/payments/webhook", content=payload, headers={"stripe-signature": sig})
    assert r1.status_code == 200
    assert r1.json().get("duplicate") is not True
    assert len(fake_subscriptions.posts) == 1

    # Second delivery (Stripe retry) — same event.id, must be skipped.
    r2 = client.post("/api/v1/payments/webhook", content=payload, headers={"stripe-signature": sig})
    assert r2.status_code == 200
    assert r2.json().get("duplicate") is True
    # No additional Supabase write. Still one row from the first delivery.
    assert len(fake_subscriptions.posts) == 1


def test_concurrent_duplicate_delivery_processes_once(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """Stripe documents at-least-once delivery; under load they
    sometimes fire the SAME event.id in two near-simultaneous deliveries.
    The SET NX idempotency gate must be atomic enough to handle the race
    even with concurrent callers.

    Test strategy: 8 parallel POSTs of the same payload via a thread
    pool. At-most-one POST should produce a subscription upsert; all
    others should return {"duplicate": true}. The fake_redis already
    serialises via _claimed (since it's a single set guarded by the
    Python GIL on dict-style ops, which mirrors Redis's atomic SET NX
    semantic). Audit MEDIUM "Stripe webhook idempotency test uses
    sequential fake Redis — does not cover concurrent duplicate delivery
    race".
    """
    from concurrent.futures import ThreadPoolExecutor

    payload = _event(
        "checkout.session.completed",
        {
            "metadata": {"user_id": "user-race", "plan": "personal_monthly"},
            "subscription": "sub_test_race",
        },
    )
    sig = _sign(payload)
    headers = {"stripe-signature": sig}

    def _post():
        return client.post("/api/v1/payments/webhook", content=payload, headers=headers)

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(lambda _: _post(), range(8)))

    # Exactly ONE delivery processed the event. Every other delivery is
    # either a completed duplicate (200 + duplicate:true) or arrived
    # while the first was still in flight (409 — Stripe retries it
    # later and then sees the done marker). Nothing else is acceptable.
    processed = [
        r for r in responses
        if r.status_code == 200 and r.json().get("duplicate") is not True
    ]
    dupes = [r for r in responses if r.status_code == 200 and r.json().get("duplicate") is True]
    in_flight = [r for r in responses if r.status_code == 409]
    assert len(processed) == 1, [(r.status_code, r.text) for r in responses]
    assert len(dupes) + len(in_flight) == 7, [(r.status_code, r.text) for r in responses]

    # And exactly one Supabase subscription upsert happened.
    assert len(fake_subscriptions.posts) == 1


def test_distinct_event_ids_each_process(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """Idempotency keys on event.id, NOT event.type. Two legitimate
    distinct events of the same type must both process."""
    # Build two events with different ids by varying the event_type
    # suffix in our helper — _event() uses type to build the id.
    p1 = _event(
        "checkout.session.completed",
        {"metadata": {"user_id": "user-A", "plan": "personal_monthly"}, "subscription": "sub_1"},
    )
    # Force a unique id by injecting "id" override
    import json

    body2 = json.loads(p1.decode())
    body2["id"] = "evt_distinct_second"
    body2["data"]["object"]["subscription"] = "sub_2"
    body2["data"]["object"]["metadata"] = {"user_id": "user-B", "plan": "personal_monthly"}
    p2 = json.dumps(body2).encode()

    client.post("/api/v1/payments/webhook", content=p1, headers={"stripe-signature": _sign(p1)})
    client.post("/api/v1/payments/webhook", content=p2, headers={"stripe-signature": _sign(p2)})
    # Both distinct events were processed.
    assert len(fake_subscriptions.posts) == 2


def test_redis_down_fails_open_processes_anyway(
    client, supabase_ok, fake_subscriptions, monkeypatch
):
    """If Redis is unreachable, we must NOT drop the event — Stripe's
    retry budget is finite and a real billing event going to the floor
    is far worse than a possible duplicate write."""
    async def _boom():
        raise ConnectionError("redis is down")

    monkeypatch.setattr("api.services.cache.get_redis", _boom)

    payload = _event(
        "checkout.session.completed",
        {"metadata": {"user_id": "user-Z", "plan": "family_yearly"}, "subscription": "sub_z"},
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    # Event still processed despite Redis being down.
    assert len(fake_subscriptions.posts) == 1


# ─── Upsert semantics (single-row per user) ─────────────────────


def test_upsert_url_uses_on_conflict_user_id(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """Migration 013 added UNIQUE(user_id). Webhook MUST pass
    `on_conflict=user_id` so PostgREST merges the existing row instead
    of inserting a new one. Without this header the cancel path would
    leave the original active row in place and the user would keep
    paid access forever."""
    payload = _event(
        "checkout.session.completed",
        {
            "metadata": {"user_id": "user-upsert", "plan": "personal_monthly"},
            "subscription": "sub_upsert",
        },
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    assert len(fake_subscriptions.urls) == 1
    assert "on_conflict=user_id" in fake_subscriptions.urls[0], (
        f"upsert URL missing on_conflict=user_id: {fake_subscriptions.urls[0]}"
    )


def test_subscribe_then_cancel_then_resubscribe_each_step_persists(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """End-to-end sequence: a real customer who subscribes, cancels,
    then re-subscribes. Each event must persist a body that reflects
    the new state — not pile up alongside the old one. We can't fake
    the Supabase UPSERT in this test harness, but we CAN verify the
    payload sequence is what we'd want PostgREST to merge."""
    # 1. Subscribe → active personal
    p1 = _event(
        "checkout.session.completed",
        {"metadata": {"user_id": "user-loop", "plan": "personal_monthly"}, "subscription": "sub_1"},
    )
    client.post("/api/v1/payments/webhook", content=p1, headers={"stripe-signature": _sign(p1)})

    # 2. Cancel → free + cancelled
    import json as _json
    p2_body = _json.loads(p1.decode())
    p2_body["id"] = "evt_cancel_loop"
    p2_body["type"] = "customer.subscription.deleted"
    p2_body["data"]["object"] = {
        "id": "sub_1",
        "metadata": {"user_id": "user-loop"},
    }
    p2 = _json.dumps(p2_body).encode()
    client.post("/api/v1/payments/webhook", content=p2, headers={"stripe-signature": _sign(p2)})

    # 3. Re-subscribe → active family
    p3_body = _json.loads(p1.decode())
    p3_body["id"] = "evt_resub"
    p3_body["data"]["object"]["metadata"]["plan"] = "family_yearly"
    p3_body["data"]["object"]["subscription"] = "sub_2"
    p3 = _json.dumps(p3_body).encode()
    client.post("/api/v1/payments/webhook", content=p3, headers={"stripe-signature": _sign(p3)})

    assert len(fake_subscriptions.posts) == 3
    # Each upsert is for the same user_id (merge target on prod)
    for p in fake_subscriptions.posts:
        assert p["user_id"] == "user-loop"
    # And all three URLs carry the conflict resolver
    for url in fake_subscriptions.urls:
        assert "on_conflict=user_id" in url
    # The final state is what survives a real merge: family + active
    final = fake_subscriptions.posts[-1]
    assert final["tier"] == "family"
    assert final["status"] == "active"


# ─── Lifecycle events beyond the core 4 (trial / renewal / customer) ──


def test_trial_will_end_returns_200_no_persistence(
    client, supabase_ok, fake_subscriptions, fake_redis, caplog
):
    """customer.subscription.trial_will_end fires 3 days before trial
    conversion. We log + accept so Stripe doesn't retry; persistence
    is intentionally untouched (the actual DB write happens when the
    trial converts and customer.subscription.updated fires)."""
    import logging

    payload = _event(
        "customer.subscription.trial_will_end",
        {
            "id": "sub_trial",
            "status": "trialing",
            "trial_end": 1715965200,
            "metadata": {"user_id": "user-trial"},
        },
    )
    with caplog.at_level(logging.INFO):
        resp = client.post(
            "/api/v1/payments/webhook",
            content=payload,
            headers={"stripe-signature": _sign(payload)},
        )
    assert resp.status_code == 200
    # No persistence on this event — Stripe will fire .updated when the
    # trial actually converts.
    assert fake_subscriptions.posts == []
    # And the structured log breadcrumb is in place for Sentry.
    assert any("trial_will_end" in r.message for r in caplog.records)


def test_invoice_paid_returns_200_no_persistence(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """invoice.paid is the authoritative recovery signal after a
    past_due cycle. customer.subscription.updated does the actual DB
    write; this handler just structured-logs for analytics."""
    payload = _event(
        "invoice.paid",
        {
            "id": "in_paid_test",
            "subscription": "sub_recovered",
            "amount_paid": 999,
            "metadata": {"user_id": "user-recovered"},
        },
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    assert fake_subscriptions.posts == []


def test_customer_deleted_with_user_id_drops_to_free(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """If Stripe deletes the customer entirely (operator cleanup),
    we must drop their tier to free so our resolver doesn't keep
    surfacing paid access for a customer that no longer exists in
    Stripe. Requires the customer object to carry user_id in metadata
    — Stripe lets us set it at customer-create time; we currently set
    it on subscriptions, so this path only fires for callers who set
    it on the customer too. Logged either way."""
    payload = _event(
        "customer.deleted",
        {
            "id": "cus_test_deleted",
            "metadata": {"user_id": "user-stripe-deleted"},
        },
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    # Drops to free + cancelled in subscriptions
    assert len(fake_subscriptions.posts) == 1
    final = fake_subscriptions.posts[0]
    assert final["user_id"] == "user-stripe-deleted"
    assert final["tier"] == "free"
    assert final["status"] == "cancelled"


def test_customer_deleted_without_user_id_logs_skips(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """Without metadata.user_id we can't attribute the deletion safely.
    Log + return 200 so Stripe doesn't retry, but DON'T mis-cancel some
    random user."""
    payload = _event(
        "customer.deleted",
        {"id": "cus_no_meta"},
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    assert fake_subscriptions.posts == []


# ─── Business plan tier mapping (regression) ───────────────────


def test_checkout_business_plan_maps_to_business_tier(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """The inline tier-from-plan logic before this fix checked only
    'personal' / 'family' substrings, so 'business_monthly' silently
    fell through to 'personal'. A B2B customer paying for Business
    would have ended up with Personal-tier limits in our DB."""
    payload = _event(
        "checkout.session.completed",
        {
            "metadata": {"user_id": "user-biz", "plan": "business_yearly"},
            "subscription": "sub_biz",
        },
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    # The first POST (recorded by FakeSubscriptionsTable) is the
    # subscription upsert. audit_log writes come AFTER and go through
    # the same recorder. We just need the subscription row to carry
    # tier='business'.
    sub_writes = [p for p in fake_subscriptions.posts if "tier" in p]
    assert sub_writes, "no subscription upsert recorded"
    assert sub_writes[0]["tier"] == "business"


def test_tier_from_plan_helper():
    """Pure-function test of the tier mapping used by the webhook."""
    from api.routers.payments import _tier_from_plan_key

    assert _tier_from_plan_key("personal_monthly") == "personal"
    assert _tier_from_plan_key("personal_yearly") == "personal"
    assert _tier_from_plan_key("family_monthly") == "family"
    assert _tier_from_plan_key("family_yearly") == "family"
    assert _tier_from_plan_key("business_monthly") == "business"
    assert _tier_from_plan_key("business_yearly") == "business"
    # Unknown plan → personal (safer than crashing the webhook).
    assert _tier_from_plan_key("garbage") == "personal"


# ─── Audit-log rows on each event (regression for compliance) ──


def test_subscription_created_writes_audit_row(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """checkout.session.completed → audit row with action
    'subscription.created' so compliance teams can answer 'when did
    this customer subscribe?' without joining Stripe history."""
    payload = _event(
        "checkout.session.completed",
        {
            "metadata": {"user_id": "user-aud", "plan": "personal_monthly"},
            "subscription": "sub_aud",
        },
    )
    client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    audit_rows = [
        p for p in fake_subscriptions.audit_posts
        if p.get("action") == "subscription.created"
    ]
    assert len(audit_rows) == 1
    assert audit_rows[0]["target_id"] == "sub_aud"
    assert audit_rows[0]["actor_user_id"] == "user-aud"


def test_subscription_cancelled_writes_audit_row(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    payload = _event(
        "customer.subscription.deleted",
        {"id": "sub_cancel_aud", "metadata": {"user_id": "user-cancel"}},
    )
    client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    audit_rows = [
        p for p in fake_subscriptions.audit_posts
        if p.get("action") == "subscription.cancelled"
    ]
    assert len(audit_rows) == 1
    assert audit_rows[0]["target_id"] == "sub_cancel_aud"


# ─── Current-period sync (renewal-date awareness) ──────────────


def test_subscription_updated_persists_current_period(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """customer.subscription.updated carries current_period_start and
    current_period_end as Unix epoch seconds. We must convert + persist
    those so the UI can render 'renews on Aug 14' and support can
    answer expiration questions from our DB without a Stripe round
    trip."""
    # Stripe sends epoch seconds; our handler converts to ISO-8601 UTC.
    # Pick two specific epochs and assert the exact ISO round-trip.
    from datetime import datetime, timezone

    start_epoch = 1786723200  # 2026-08-14T16:00:00+00:00
    end_epoch = 1789315200    # 2026-09-13T16:00:00+00:00
    expected_start = datetime.fromtimestamp(start_epoch, tz=timezone.utc).isoformat()
    expected_end = datetime.fromtimestamp(end_epoch, tz=timezone.utc).isoformat()

    payload = _event(
        "customer.subscription.updated",
        {
            "id": "sub_periods",
            "status": "active",
            "metadata": {"user_id": "user-periods"},
            "current_period_start": start_epoch,
            "current_period_end": end_epoch,
        },
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    sub_writes = fake_subscriptions.posts
    assert len(sub_writes) == 1
    body = sub_writes[0]
    assert body["current_period_start"] == expected_start
    assert body["current_period_end"] == expected_end


def test_subscription_updated_handles_missing_period(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """When Stripe omits the period fields (older API versions, weird
    edge cases) we must NOT crash and NOT write null garbage — just
    skip those fields entirely so the existing row's period stays
    untouched."""
    payload = _event(
        "customer.subscription.updated",
        {
            "id": "sub_no_period",
            "status": "active",
            "metadata": {"user_id": "user-no-period"},
            # current_period_start / _end absent
        },
    )
    resp = client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )
    assert resp.status_code == 200
    body = fake_subscriptions.posts[0]
    assert "current_period_start" not in body
    assert "current_period_end" not in body


def test_epoch_to_iso_helper():
    """The conversion helper must be defensive — None, 0, junk should
    all return None rather than raise."""
    from datetime import datetime, timezone

    from api.routers.payments import _epoch_to_iso

    assert _epoch_to_iso(None) is None
    assert _epoch_to_iso(0) is None
    assert _epoch_to_iso("garbage") is None
    # A known good value round-trips deterministically.
    iso = _epoch_to_iso(1786723200)
    assert iso == datetime.fromtimestamp(1786723200, tz=timezone.utc).isoformat()




# ─── charge.refunded ────────────────────────────────────────────────
#
# Invoice charges (every renewal, and the first payment after a trial)
# carry NO metadata.user_id — Stripe only copies subscription metadata
# onto the subscription. The handler finds the user via the customer.
# The subscriptions CHECK only allows active / cancelled / expired /
# past_due, so 'refunded' can never be written.

_ALLOWED_STATUSES = {"active", "cancelled", "expired", "past_due"}


def _paid_row(user_id: str, sub_id: str, customer: Optional[str]) -> Dict[str, Any]:
    return {
        "user_id": user_id,
        "tier": "personal",
        "status": "active",
        "provider": "stripe",
        "provider_subscription_id": sub_id,
        "stripe_customer_id": customer,
        "trial_used_at": None,
    }


def _invoice_charge(**overrides) -> Dict[str, Any]:
    charge = {
        "id": "ch_invoice_1",
        "object": "charge",
        "customer": "cus_refund",
        "invoice": "in_latest",
        "metadata": {},  # invoice charges never carry our user_id
        "amount": 499,
        "amount_refunded": 499,
        "currency": "usd",
        "refunds": {"data": [{"reason": "requested_by_customer"}]},
    }
    charge.update(overrides)
    return charge


def _post_event(client, event_type: str, data: Dict[str, Any], event_id: Optional[str] = None):
    body = json.loads(_event(event_type, data).decode())
    if event_id:
        body["id"] = event_id
    payload = json.dumps(body).encode()
    return client.post(
        "/api/v1/payments/webhook",
        content=payload,
        headers={"stripe-signature": _sign(payload)},
    )


def test_full_refund_of_latest_invoice_cancels_and_drops_to_free(
    client, supabase_ok, fake_subscriptions, fake_redis, fake_stripe
):
    """Full refund of the current period: access ends now, with a status
    the CHECK constraint accepts, and the Stripe subscription is
    cancelled immediately so it can't renew and re-grant access."""
    fake_subscriptions.rows = [_paid_row("user-refunded", "sub_r", "cus_refund")]
    fake_stripe.add_subscription("sub_r", "cus_refund", latest_invoice="in_latest")

    resp = _post_event(client, "charge.refunded", _invoice_charge())

    assert resp.status_code == 200, resp.text
    assert len(fake_subscriptions.posts) == 1
    sent = fake_subscriptions.posts[0]
    assert sent["user_id"] == "user-refunded"
    assert sent["tier"] == "free"
    assert sent["status"] == "cancelled"
    assert sent["status"] in _ALLOWED_STATUSES
    assert [c[0] for c in fake_stripe.cancel_calls] == ["sub_r"]
    assert fake_stripe.cancel_calls[0][1] == {"prorate": False, "invoice_now": False}
    refund_rows = [
        r for r in fake_subscriptions.audit_posts
        if r.get("action") == "subscription.refunded"
    ]
    assert len(refund_rows) == 1
    assert refund_rows[0]["actor_user_id"] == "user-refunded"
    assert refund_rows[0]["meta"]["amount_refunded_cents"] == 499
    assert refund_rows[0]["meta"]["reason"] == "requested_by_customer"
    assert refund_rows[0]["meta"]["access_revoked"] is True


def test_refund_never_writes_a_status_outside_the_check_constraint(
    client, supabase_ok, fake_subscriptions, fake_redis, fake_stripe
):
    """Regression: the old handler wrote status='refunded', which the
    subscriptions CHECK rejects — PostgREST answered 400, the error was
    swallowed, and the user kept paid access."""
    fake_subscriptions.rows = [_paid_row("user-x", "sub_x", "cus_refund")]
    fake_stripe.add_subscription("sub_x", "cus_refund", latest_invoice="in_latest")

    _post_event(client, "charge.refunded", _invoice_charge())

    assert fake_subscriptions.posts
    assert all(p["status"] in _ALLOWED_STATUSES for p in fake_subscriptions.posts)


def test_partial_refund_keeps_access(
    client, supabase_ok, fake_subscriptions, fake_redis, fake_stripe
):
    """A partial refund is a goodwill credit — the period is still
    mostly paid. Audit it; don't touch access or the subscription."""
    fake_subscriptions.rows = [_paid_row("user-partial", "sub_p", "cus_refund")]
    fake_stripe.add_subscription("sub_p", "cus_refund", latest_invoice="in_latest")

    resp = _post_event(client, "charge.refunded", _invoice_charge(amount_refunded=200))

    assert resp.status_code == 200
    assert fake_subscriptions.posts == []
    assert fake_stripe.cancel_calls == []
    rows = [r for r in fake_subscriptions.audit_posts if r.get("action") == "subscription.refunded"]
    assert len(rows) == 1
    assert rows[0]["meta"]["access_revoked"] is False


def test_full_refund_of_an_older_invoice_keeps_current_access(
    client, supabase_ok, fake_subscriptions, fake_redis, fake_stripe
):
    """Refunding last month's charge doesn't void the period the user
    has already paid for now."""
    fake_subscriptions.rows = [_paid_row("user-old", "sub_o", "cus_refund")]
    fake_stripe.add_subscription("sub_o", "cus_refund", latest_invoice="in_newer")

    resp = _post_event(client, "charge.refunded", _invoice_charge(invoice="in_older"))

    assert resp.status_code == 200
    assert fake_subscriptions.posts == []
    assert fake_stripe.cancel_calls == []


def test_refund_resolves_legacy_user_via_stripe_subscription_metadata(
    client, supabase_ok, fake_subscriptions, fake_redis, fake_stripe
):
    """Rows written before stripe_customer_id existed can't be found by
    customer in our DB. The customer's Stripe subscription carries our
    user_id in metadata (set at checkout) — use that."""
    fake_subscriptions.rows = [_paid_row("user-legacy", "sub_l", None)]
    sub = fake_stripe.add_subscription("sub_l", "cus_legacy", latest_invoice="in_latest")
    sub["metadata"] = {"user_id": "user-legacy"}

    resp = _post_event(client, "charge.refunded", _invoice_charge(customer="cus_legacy"))

    assert resp.status_code == 200
    assert fake_subscriptions.posts[0]["user_id"] == "user-legacy"
    assert fake_subscriptions.posts[0]["status"] == "cancelled"


def test_refund_for_unknown_customer_skips_persistence(
    client, supabase_ok, fake_subscriptions, fake_redis, fake_stripe
):
    """Nobody to attribute the refund to (one-off charge, foreign
    customer): log and acknowledge — never downgrade a random user."""
    resp = _post_event(client, "charge.refunded", _invoice_charge(customer="cus_nobody"))

    assert resp.status_code == 200
    assert fake_subscriptions.posts == []
    assert fake_stripe.cancel_calls == []


# ─── charge.dispute.created ─────────────────────────────────────────


def test_charge_dispute_audit_logged_no_tier_change(
    client, supabase_ok, fake_subscriptions, fake_redis, fake_stripe
):
    """Disputes get an audit-log row but DO NOT change tier — Stripe
    gives merchants ~20 days to respond and revoking access mid-dispute
    is bad UX if the dispute turns out to be card-not-present fraud
    where Cleanway is the victim too.

    The dispute object has no customer and no user metadata; the user
    is found through the disputed charge's customer."""
    fake_subscriptions.rows = [_paid_row("user-dispute", "sub_d", "cus_disp")]
    fake_stripe.charges["ch_test_disputed"] = _invoice_charge(id="ch_test_disputed", customer="cus_disp")

    resp = _post_event(
        client,
        "charge.dispute.created",
        {
            "id": "dp_test_dispute",
            "object": "dispute",
            "charge": "ch_test_disputed",
            "metadata": {},
            "amount": 499,
            "currency": "usd",
            "reason": "fraudulent",
        },
    )
    assert resp.status_code == 200
    # No tier change — subscriptions table untouched
    assert fake_subscriptions.posts == []
    dispute_rows = [
        r for r in fake_subscriptions.audit_posts
        if r.get("action") == "subscription.dispute_opened"
    ]
    assert len(dispute_rows) == 1
    assert dispute_rows[0]["actor_user_id"] == "user-dispute"
    assert dispute_rows[0]["meta"]["reason"] == "fraudulent"
    assert dispute_rows[0]["meta"]["charge_id"] == "ch_test_disputed"


# ─── Idempotency must never lose an event ──────────────────────────


def test_failed_supabase_write_returns_5xx_and_retry_processes(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """The bug: the event was marked seen BEFORE processing and the
    write error was swallowed, so the endpoint said 200, Stripe stopped
    retrying, and the paid subscription never reached our DB. Now a
    failed write is a 5xx, the event stays unclaimed, and Stripe's retry
    of the SAME event id is processed."""
    data = {
        "metadata": {"user_id": "user-retry", "plan": "personal_monthly"},
        "subscription": "sub_retry",
        "customer": "cus_retry",
    }
    fake_subscriptions.post_status = 503
    r1 = _post_event(client, "checkout.session.completed", data, event_id="evt_retry")
    assert r1.status_code >= 500
    assert fake_subscriptions.posts == []

    fake_subscriptions.post_status = 201
    r2 = _post_event(client, "checkout.session.completed", data, event_id="evt_retry")
    assert r2.status_code == 200, r2.text
    assert r2.json().get("duplicate") is not True
    assert len(fake_subscriptions.posts) == 1

    # Only now is it a duplicate.
    r3 = _post_event(client, "checkout.session.completed", data, event_id="evt_retry")
    assert r3.status_code == 200
    assert r3.json().get("duplicate") is True
    assert len(fake_subscriptions.posts) == 1


def test_supabase_exception_returns_5xx(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    import httpx as _httpx

    fake_subscriptions.post_error = _httpx.ConnectTimeout("supabase timed out")
    resp = _post_event(
        client,
        "customer.subscription.deleted",
        {"id": "sub_gone", "metadata": {"user_id": "user-timeout"}},
        event_id="evt_timeout",
    )
    assert resp.status_code >= 500
    # The lease was released so the retry isn't mistaken for a duplicate.
    assert "stripe:event:evt_timeout" not in fake_redis.kv


def test_supabase_not_configured_is_a_5xx_not_a_silent_200(
    client, supabase_ok, fake_subscriptions, fake_redis, monkeypatch
):
    monkeypatch.setattr(supabase_ok, "supabase_url", "", raising=False)
    resp = _post_event(
        client,
        "checkout.session.completed",
        {"metadata": {"user_id": "u-nodb", "plan": "personal_monthly"}, "subscription": "sub_n"},
        event_id="evt_nodb",
    )
    assert resp.status_code >= 500


def test_event_in_flight_elsewhere_is_not_acknowledged(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """Another worker holds the processing lease. Answering 200 would
    let Stripe drop the event if that worker then fails — answer 409 so
    Stripe retries and sees the outcome."""
    fake_redis.kv["stripe:event:evt_busy"] = "processing"
    resp = _post_event(
        client,
        "checkout.session.completed",
        {"metadata": {"user_id": "user-busy", "plan": "personal_monthly"}, "subscription": "sub_b"},
        event_id="evt_busy",
    )
    assert resp.status_code == 409
    assert fake_subscriptions.posts == []


def test_processed_event_is_marked_done(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    _post_event(
        client,
        "checkout.session.completed",
        {"metadata": {"user_id": "user-done", "plan": "personal_monthly"}, "subscription": "sub_dn"},
        event_id="evt_done",
    )
    assert fake_redis.kv.get("stripe:event:evt_done") == "done"


# ─── Customer id + one-time trial are recorded at checkout ─────────


def test_checkout_completed_stores_customer_and_trial_use(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    resp = _post_event(
        client,
        "checkout.session.completed",
        {
            "metadata": {"user_id": "user-cus", "plan": "personal_monthly", "trial": "1"},
            "subscription": "sub_cus",
            "customer": "cus_123",
        },
    )
    assert resp.status_code == 200
    sent = fake_subscriptions.posts[0]
    assert sent["stripe_customer_id"] == "cus_123"
    assert sent.get("trial_used_at")


def test_checkout_completed_without_trial_leaves_trial_marker_alone(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    _post_event(
        client,
        "checkout.session.completed",
        {
            "metadata": {"user_id": "user-nt", "plan": "personal_monthly", "trial": "0"},
            "subscription": "sub_nt",
            "customer": "cus_nt",
        },
    )
    assert "trial_used_at" not in fake_subscriptions.posts[0]


def test_checkout_completed_flags_a_second_live_subscription(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    """Two Checkout tabs completed → two Stripe subscriptions, one row.
    The row follows the newest, and the overlap is audit-logged so the
    operator can refund the other one."""
    fake_subscriptions.rows = [_paid_row("user-dup", "sub_first", "cus_dup")]
    _post_event(
        client,
        "checkout.session.completed",
        {
            "metadata": {"user_id": "user-dup", "plan": "family_monthly"},
            "subscription": "sub_second",
            "customer": "cus_dup",
        },
    )
    dup_rows = [
        r for r in fake_subscriptions.audit_posts
        if r.get("action") == "subscription.duplicate_detected"
    ]
    assert len(dup_rows) == 1
    assert dup_rows[0]["meta"]["previous_subscription_id"] == "sub_first"
    assert fake_subscriptions.posts[0]["provider_subscription_id"] == "sub_second"


# ─── subscription.updated maps the price back to the plan ──────────


def _sub_with_price(price_id: str, **extra) -> Dict[str, Any]:
    sub = {
        "id": "sub_plan_change",
        "object": "subscription",
        "status": "active",
        "customer": "cus_pc",
        "metadata": {"user_id": "user-plan"},
        "items": {"data": [{"id": "si_1", "price": {"id": price_id}}]},
    }
    sub.update(extra)
    return sub


@pytest.mark.parametrize(
    "plan,tier,interval",
    [("family", 2, "monthly"), ("business", 4, "yearly"), ("personal", 1, "monthly")],
)
def test_subscription_updated_maps_price_to_tier(
    client, supabase_ok, fake_subscriptions, fake_redis, plan, tier, interval
):
    """Upgrade personal → family in the portal fires subscription.updated
    with the new price. The old handler passed tier=None, so the DB kept
    'personal' forever."""
    from api.services.pricing import STRIPE_PRICE_IDS

    price_id = STRIPE_PRICE_IDS[plan][tier][interval]
    resp = _post_event(client, "customer.subscription.updated", _sub_with_price(price_id))

    assert resp.status_code == 200
    sent = fake_subscriptions.posts[0]
    assert sent["tier"] == plan
    assert sent["stripe_customer_id"] == "cus_pc"


def test_subscription_updated_unknown_price_leaves_tier_untouched(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    resp = _post_event(client, "customer.subscription.updated", _sub_with_price("price_unknown"))
    assert resp.status_code == 200
    assert "tier" not in fake_subscriptions.posts[0]


def test_subscription_deleted_without_metadata_resolves_by_subscription_id(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    fake_subscriptions.rows = [_paid_row("user-by-sub", "sub_lookup", "cus_l")]
    resp = _post_event(
        client,
        "customer.subscription.deleted",
        {"id": "sub_lookup", "customer": "cus_l", "metadata": {}},
    )
    assert resp.status_code == 200
    assert fake_subscriptions.posts[0]["user_id"] == "user-by-sub"
    assert fake_subscriptions.posts[0]["status"] == "cancelled"


def test_customer_deleted_resolves_by_stored_customer_id(
    client, supabase_ok, fake_subscriptions, fake_redis
):
    fake_subscriptions.rows = [_paid_row("user-cus-del", "sub_cd", "cus_gone")]
    resp = _post_event(client, "customer.deleted", {"id": "cus_gone"})
    assert resp.status_code == 200
    sent = fake_subscriptions.posts[0]
    assert sent["user_id"] == "user-cus-del"
    assert sent["tier"] == "free"
    assert sent["status"] == "cancelled"
    # The customer no longer exists in Stripe — checkout must not reuse
    # it, nor re-derive it from the (now dead) subscription.
    assert sent["stripe_customer_id"] is None
    assert sent["provider_subscription_id"] is None

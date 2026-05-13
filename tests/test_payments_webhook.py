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
    """

    def __init__(self) -> None:
        self.posts: List[Dict[str, Any]] = []
        self.urls: List[str] = []
        # Separate list for /rest/v1/audit_log writes — keeps the
        # existing subscriptions assertions undisturbed when audit
        # rows fire alongside the main write.
        self.audit_posts: List[Dict[str, Any]] = []

    def build(self):
        recorder = self

        class _Resp:
            def __init__(self, status: int):
                self.status_code = status
                self.text = ""

            def json(self):
                return [{"ok": True}]

        class _Client:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def post(self, url, headers=None, json=None, params=None):
                if "/rest/v1/subscriptions" in url:
                    recorder.posts.append(json or {})
                    recorder.urls.append(url)
                elif "/rest/v1/audit_log" in url:
                    recorder.audit_posts.append(json or {})
                return _Resp(201)

        return _Client


@pytest.fixture
def fake_subscriptions(monkeypatch):
    import httpx as _httpx

    fake = FakeSubscriptionsTable()
    monkeypatch.setattr(_httpx, "AsyncClient", fake.build())
    return fake


class FakeRedis:
    """Just enough surface for _update_subscription's invalidation step
    and the webhook idempotency gate."""

    def __init__(self) -> None:
        self.deleted: List[str] = []
        # Tracks keys claimed via SET NX so the idempotency gate sees
        # the second call to the same event.id as a duplicate.
        self._claimed: set[str] = set()

    async def delete(self, key: str):
        self.deleted.append(key)
        self._claimed.discard(key)
        return 1

    async def set(self, key: str, value, nx: bool = False, ex: int | None = None):
        """Mirror redis-py's set(..., nx=True): returns truthy when the
        key was NOT previously set; falsy on re-set."""
        if nx:
            if key in self._claimed:
                return None  # already taken — duplicate
            self._claimed.add(key)
            return True
        # Non-NX path isn't used by the webhook, but be permissive.
        self._claimed.add(key)
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

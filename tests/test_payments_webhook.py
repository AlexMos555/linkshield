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
    """Captures POSTs to /rest/v1/subscriptions so we can assert on the body."""

    def __init__(self) -> None:
        self.posts: List[Dict[str, Any]] = []

    def build(self):
        recorder = self

        class _Resp:
            def __init__(self, status: int):
                self.status_code = status

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
                return _Resp(201)

        return _Client


@pytest.fixture
def fake_subscriptions(monkeypatch):
    import httpx as _httpx

    fake = FakeSubscriptionsTable()
    monkeypatch.setattr(_httpx, "AsyncClient", fake.build())
    return fake


class FakeRedis:
    """Just enough surface for _update_subscription's invalidation step."""

    def __init__(self) -> None:
        self.deleted: List[str] = []

    async def delete(self, key: str):
        self.deleted.append(key)
        return 1


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

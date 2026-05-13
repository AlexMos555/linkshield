"""Tier resolver — past_due users must keep paid access during dunning.

Stripe's payment-retry cycle (dunning) sends `customer.subscription.updated`
with status='past_due' immediately on a failed charge. We persist that as
subscriptions.status='past_due'. The dunning window typically runs 1-2
weeks before Stripe gives up and fires `customer.subscription.deleted`.

If the tier resolver only matches status='active', a user whose card
declined yesterday loses paid features today — punitive UX during a
period that Stripe explicitly designed for retry. This file pins the
contract: past_due rows still resolve to their paid tier.
"""
from __future__ import annotations

import pytest

from api.models.schemas import UserTier


class _SupabaseStub:
    def __init__(self, rows):
        self.rows = rows
        self.urls: list[str] = []

    def build(self):
        stub = self

        class _Resp:
            def __init__(self, body):
                self.status_code = 200
                self._body = body

            def json(self):
                return self._body

        class _Client:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def get(self, url, headers=None, **_kw):
                stub.urls.append(url)
                return _Resp(stub.rows)

        return _Client


@pytest.fixture
def supabase_ok(monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    return s


@pytest.fixture
def no_redis(monkeypatch):
    """Force tier resolver to skip Redis cache so we hit Supabase path."""
    async def _boom():
        raise ConnectionError("no redis in test")

    monkeypatch.setattr("api.services.cache.get_redis", _boom)


@pytest.mark.asyncio
async def test_past_due_user_keeps_paid_tier(supabase_ok, no_redis, monkeypatch):
    """past_due subscription must still resolve to its paid tier — the
    user paid; Stripe is retrying; we don't yank access on the first
    declined charge."""
    import httpx as _httpx
    from api.services import auth

    stub = _SupabaseStub(rows=[{"tier": "personal"}])
    monkeypatch.setattr(_httpx, "AsyncClient", stub.build())

    tier = await auth._fetch_tier_from_supabase("user-past-due")
    assert tier == UserTier.personal
    # Query must explicitly include both statuses, not just `active`
    assert stub.urls, "no Supabase query issued"
    q = stub.urls[0]
    assert "status=in.%28active%2Cpast_due%29" in q or "status=in.(active,past_due)" in q, q


@pytest.mark.asyncio
async def test_active_user_resolves_normally(supabase_ok, no_redis, monkeypatch):
    """Regression: an `active` row still resolves to its paid tier
    (the past_due change must not break the active path)."""
    import httpx as _httpx
    from api.services import auth

    stub = _SupabaseStub(rows=[{"tier": "family"}])
    monkeypatch.setattr(_httpx, "AsyncClient", stub.build())

    tier = await auth._fetch_tier_from_supabase("user-active")
    assert tier == UserTier.family


@pytest.mark.asyncio
async def test_cancelled_user_falls_to_free(supabase_ok, no_redis, monkeypatch):
    """When the only row is cancelled, the in.() filter excludes it →
    Supabase returns empty → resolver falls back to free."""
    import httpx as _httpx
    from api.services import auth

    stub = _SupabaseStub(rows=[])  # Empty result mimics filter excluding cancelled
    monkeypatch.setattr(_httpx, "AsyncClient", stub.build())

    tier = await auth._fetch_tier_from_supabase("user-cancelled")
    assert tier == UserTier.free


@pytest.mark.asyncio
async def test_query_orders_by_created_at_desc(supabase_ok, no_redis, monkeypatch):
    """When a user has multiple subscription rows (e.g. historical
    cancelled alongside fresh active), we MUST pick the newest one.
    Without explicit ordering, a stale cancelled row could win."""
    import httpx as _httpx
    from api.services import auth

    stub = _SupabaseStub(rows=[{"tier": "business"}])
    monkeypatch.setattr(_httpx, "AsyncClient", stub.build())

    await auth._fetch_tier_from_supabase("user-multi")
    q = stub.urls[0]
    assert "order=created_at.desc" in q, q
    assert "limit=1" in q, q

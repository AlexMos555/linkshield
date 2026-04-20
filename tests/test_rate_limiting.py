"""
Rate limiting tests across all routers.

Verifies the three-tier rate limiting introduced for Phase "#3 — rate limiting
on all routers":

1. Per-user daily + burst limits (authenticated endpoints)
2. Per-IP window limits (public endpoints)
3. Per-user sensitive-action limits (payments, org_create, referral_redeem)

All tests stub out Redis with an in-memory fake so they are deterministic and
isolated from a real Redis instance.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict

import pytest
from fastapi.testclient import TestClient


# ─── Fake Redis ───────────────────────────────────────────────────────────────


class FakeRedis:
    """Minimal async Redis stub used only by the rate limiter."""

    def __init__(self) -> None:
        self._data: Dict[str, int] = {}
        self._ttls: Dict[str, int] = {}

    async def incr(self, key: str) -> int:
        self._data[key] = int(self._data.get(key, 0)) + 1
        return self._data[key]

    async def incrby(self, key: str, amount: int) -> int:
        self._data[key] = int(self._data.get(key, 0)) + amount
        return self._data[key]

    async def expire(self, key: str, seconds: int) -> bool:
        self._ttls[key] = seconds
        return True

    async def ttl(self, key: str) -> int:
        return self._ttls.get(key, -1)

    async def get(self, key: str):  # pragma: no cover — unused in rate limiter
        return None

    async def setex(self, key: str, ttl: int, value):  # pragma: no cover
        return True

    async def close(self):  # pragma: no cover
        return None

    def reset(self) -> None:
        self._data.clear()
        self._ttls.clear()


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def fake_redis(monkeypatch):
    """Patch get_redis everywhere it is consumed from rate_limiter paths."""
    from api.services import rate_limiter, cache

    fake = FakeRedis()

    async def _get_fake():
        return fake

    monkeypatch.setattr(rate_limiter, "get_redis", _get_fake)
    monkeypatch.setattr(cache, "get_redis", _get_fake)
    return fake


@pytest.fixture
def tight_limits(monkeypatch):
    """
    Shrink rate-limit settings so we can exercise the limits without having
    to issue thousands of requests in a unit test.
    """
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "free_tier_daily_limit", 3, raising=False)
    monkeypatch.setattr(settings, "paid_tier_daily_limit", 5, raising=False)
    monkeypatch.setattr(settings, "burst_limit", 5, raising=False)
    monkeypatch.setattr(settings, "burst_window_seconds", 10, raising=False)
    monkeypatch.setattr(settings, "public_rate_limit_per_window", 4, raising=False)
    monkeypatch.setattr(settings, "public_rate_limit_window_seconds", 60, raising=False)
    monkeypatch.setattr(settings, "sensitive_action_limit", 2, raising=False)
    monkeypatch.setattr(settings, "sensitive_action_window_seconds", 60, raising=False)
    monkeypatch.setattr(settings, "unsubscribe_limit_per_window", 3, raising=False)
    monkeypatch.setattr(settings, "unsubscribe_window_seconds", 60, raising=False)
    return settings


@pytest.fixture
def authed_user():
    from api.models.schemas import AuthUser, UserTier

    return AuthUser(id="test-user-123", email="t@test.com", tier=UserTier.free)


@pytest.fixture
def app(authed_user):
    """App instance with auth dependencies stubbed to `authed_user`."""
    from api.main import app as fastapi_app
    from api.services.auth import get_current_user, get_optional_user

    fastapi_app.dependency_overrides[get_current_user] = lambda: authed_user
    fastapi_app.dependency_overrides[get_optional_user] = lambda: authed_user
    yield fastapi_app
    fastapi_app.dependency_overrides.clear()


@pytest.fixture
def client(app):
    return TestClient(app)


# ─── Unit tests: rate_limiter internals ───────────────────────────────────────


@pytest.mark.asyncio
async def test_check_rate_limit_under_cap(fake_redis, tight_limits, authed_user):
    """Free user can call up to daily limit without 429."""
    from api.services.rate_limiter import check_rate_limit

    # Free tier daily limit is 3 per fixture
    remaining = await check_rate_limit(authed_user, num_domains=1)
    assert remaining == 2
    remaining = await check_rate_limit(authed_user, num_domains=1)
    assert remaining == 1
    remaining = await check_rate_limit(authed_user, num_domains=1)
    assert remaining == 0


@pytest.mark.asyncio
async def test_check_rate_limit_over_cap_raises_429(
    fake_redis, tight_limits, authed_user
):
    """Exceeding the daily limit raises HTTPException 429."""
    from fastapi import HTTPException
    from api.services.rate_limiter import check_rate_limit

    for _ in range(3):
        await check_rate_limit(authed_user, num_domains=1)

    with pytest.raises(HTTPException) as exc_info:
        await check_rate_limit(authed_user, num_domains=1)
    assert exc_info.value.status_code == 429
    assert "daily_limit" in exc_info.value.detail


@pytest.mark.asyncio
async def test_burst_limit_triggers(fake_redis, monkeypatch, authed_user):
    """Burst limit bites even before the daily limit is reached."""
    from fastapi import HTTPException
    from api import config
    from api.services.rate_limiter import check_rate_limit

    settings = config.get_settings()
    monkeypatch.setattr(settings, "free_tier_daily_limit", 1000, raising=False)
    monkeypatch.setattr(settings, "burst_limit", 2, raising=False)
    monkeypatch.setattr(settings, "burst_window_seconds", 10, raising=False)

    await check_rate_limit(authed_user, num_domains=1)
    await check_rate_limit(authed_user, num_domains=1)
    with pytest.raises(HTTPException) as exc_info:
        await check_rate_limit(authed_user, num_domains=1)
    assert exc_info.value.status_code == 429
    assert "slow down" in str(exc_info.value.detail).lower()


@pytest.mark.asyncio
async def test_ip_rate_limit_fires_429(fake_redis, tight_limits):
    """check_ip_rate_limit enforces per-IP cap and raises 429 over the limit."""
    from fastapi import HTTPException
    from api.services.rate_limiter import check_ip_rate_limit

    for _ in range(4):
        await check_ip_rate_limit("1.2.3.4", "unit", 4, 60)

    with pytest.raises(HTTPException) as exc_info:
        await check_ip_rate_limit("1.2.3.4", "unit", 4, 60)
    assert exc_info.value.status_code == 429


@pytest.mark.asyncio
async def test_ip_rate_limit_isolates_per_ip(fake_redis):
    """Different IPs use independent counters."""
    from api.services.rate_limiter import check_ip_rate_limit

    for _ in range(3):
        await check_ip_rate_limit("1.1.1.1", "unit", 3, 60)

    # Different IP — should not carry state from the first
    remaining = await check_ip_rate_limit("2.2.2.2", "unit", 3, 60)
    assert remaining == 2


@pytest.mark.asyncio
async def test_sensitive_action_limit(fake_redis, tight_limits, authed_user):
    """Sensitive actions use a separate (stricter) per-user quota."""
    from fastapi import HTTPException
    from api.services.rate_limiter import check_sensitive_action_limit

    await check_sensitive_action_limit(authed_user, "checkout")
    await check_sensitive_action_limit(authed_user, "checkout")

    with pytest.raises(HTTPException) as exc_info:
        await check_sensitive_action_limit(authed_user, "checkout")
    assert exc_info.value.status_code == 429


@pytest.mark.asyncio
async def test_sensitive_limit_isolates_per_category(
    fake_redis, tight_limits, authed_user
):
    """Different sensitive categories do not share counters."""
    from api.services.rate_limiter import check_sensitive_action_limit

    # Burn through checkout quota
    for _ in range(2):
        await check_sensitive_action_limit(authed_user, "checkout")

    # Different category should still have full quota
    remaining = await check_sensitive_action_limit(authed_user, "portal")
    assert remaining == 1  # limit=2, used 1


@pytest.mark.asyncio
async def test_redis_failure_fails_open(monkeypatch, authed_user):
    """If Redis is unreachable, rate limiter must not block requests."""
    from api.services import rate_limiter

    async def _boom():
        raise ConnectionError("redis unreachable")

    monkeypatch.setattr(rate_limiter, "get_redis", _boom)

    # Should NOT raise — returns quota estimate instead
    remaining = await rate_limiter.check_rate_limit(authed_user, num_domains=1)
    assert remaining >= 0


def test_extract_client_ip_prefers_xff():
    """X-Forwarded-For takes precedence over request.client for proxied setups."""
    from unittest.mock import MagicMock
    from api.services.rate_limiter import _extract_client_ip

    req = MagicMock()
    req.headers = {"x-forwarded-for": "203.0.113.5, 10.0.0.1"}
    req.client = MagicMock(host="10.0.0.1")
    assert _extract_client_ip(req) == "203.0.113.5"


def test_extract_client_ip_falls_back_to_client():
    from unittest.mock import MagicMock
    from api.services.rate_limiter import _extract_client_ip

    req = MagicMock()
    req.headers = {}
    req.client = MagicMock(host="198.51.100.9")
    assert _extract_client_ip(req) == "198.51.100.9"


# ─── Integration tests: routers enforce limits via Depends ────────────────────


def test_public_check_enforces_ip_rate_limit(client, fake_redis, tight_limits):
    """Public /public/check endpoint — IP limit of 4/window."""
    headers = {"x-forwarded-for": "10.20.30.40"}

    # Requests within limit should not be 429 (may still be 200/400 etc)
    for _ in range(4):
        resp = client.get("/api/v1/public/check/example.com", headers=headers)
        assert resp.status_code != 429, (
            f"Got 429 before limit exhausted: {resp.status_code}"
        )

    # The 5th request should hit the rate limit
    resp = client.get("/api/v1/public/check/example.com", headers=headers)
    assert resp.status_code == 429
    body = resp.json()
    assert body["detail"]["category"] == "public_check"


def test_public_stats_enforces_ip_rate_limit(client, fake_redis, tight_limits):
    headers = {"x-forwarded-for": "10.20.30.41"}

    for _ in range(4):
        resp = client.get("/api/v1/public/stats", headers=headers)
        assert resp.status_code != 429

    resp = client.get("/api/v1/public/stats", headers=headers)
    assert resp.status_code == 429


def test_pricing_endpoint_rate_limited(client, fake_redis, tight_limits):
    headers = {"x-forwarded-for": "10.20.30.42"}
    # `/pricing/tiers` and `/pricing/for-country` share the "pricing" category.
    for _ in range(4):
        resp = client.get("/api/v1/pricing/tiers", headers=headers)
        assert resp.status_code != 429

    resp = client.get("/api/v1/pricing/tiers", headers=headers)
    assert resp.status_code == 429


def test_unsubscribe_rate_limited(client, fake_redis, tight_limits):
    """Unsubscribe endpoints use their own (very strict) limit."""
    headers = {"x-forwarded-for": "10.20.30.43"}

    # limit is 3 per fixture
    for _ in range(3):
        resp = client.get("/api/v1/email/unsubscribe/invalid-token", headers=headers)
        # token is invalid — expect 200 HTML saying "invalid or expired"
        # but NOT 429 yet
        assert resp.status_code != 429

    resp = client.get("/api/v1/email/unsubscribe/invalid-token", headers=headers)
    assert resp.status_code == 429


def test_unsubscribe_and_public_limits_are_independent(
    client, fake_redis, tight_limits
):
    """Burning through unsubscribe quota must not affect public-check quota."""
    headers = {"x-forwarded-for": "10.20.30.44"}

    # Exhaust unsubscribe quota (3)
    for _ in range(4):
        client.get("/api/v1/email/unsubscribe/invalid-token", headers=headers)

    # Public check still works up to its own limit
    resp = client.get("/api/v1/public/stats", headers=headers)
    assert resp.status_code != 429


# ─── Meta-tests: enforce that rate_limit is wired across the codebase ─────────


ROUTERS_DIR = (
    Path(__file__).resolve().parent.parent / "api" / "routers"
)

# Endpoints that intentionally have NO rate limit and why
EXEMPT_ENDPOINTS = {
    # Stripe signs webhook payloads; rate limiting would hurt webhook delivery
    # retries. Stripe itself manages retries / IP allow-listing.
    ("payments.py", "stripe_webhook"),
    # Internal module-private helpers (not @router.*) — listed for clarity
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_every_router_imports_rate_limit_helper():
    """Each router file must import at least one rate-limit helper."""
    rate_limit_import_re = re.compile(
        r"from api\.services\.rate_limiter import .*(rate_limit|unsubscribe_rate_limit)",
    )

    router_files = [
        p for p in ROUTERS_DIR.glob("*.py") if p.name != "__init__.py"
    ]
    missing: list[str] = []
    for path in router_files:
        text = _read(path)
        if not rate_limit_import_re.search(text):
            # check.py is allowed — it uses check_rate_limit directly
            # (embedded conditional logic inside the handler body)
            if path.name == "check.py" and "check_rate_limit" in text:
                continue
            missing.append(path.name)
    assert missing == [], f"Routers without rate limit import: {missing}"


def test_every_public_endpoint_has_ip_rate_limit():
    """public.py, pricing.py, email_unsubscribe.py all declare IP-based limits."""
    for fname in ("public.py", "pricing.py"):
        text = _read(ROUTERS_DIR / fname)
        assert 'mode="ip"' in text, f"{fname} missing mode='ip' rate_limit"
    unsub_text = _read(ROUTERS_DIR / "email_unsubscribe.py")
    assert "unsubscribe_rate_limit()" in unsub_text


def test_sensitive_payment_endpoints_use_sensitive_mode():
    """Payments checkout/portal and org/create go through sensitive limits."""
    text = _read(ROUTERS_DIR / "payments.py")
    assert text.count('mode="sensitive"') >= 2, (
        "payments.py should have sensitive-mode rate limit on checkout and portal"
    )
    org_text = _read(ROUTERS_DIR / "org.py")
    assert 'mode="sensitive"' in org_text


def test_stripe_webhook_has_no_rate_limit():
    """Webhook endpoint must not be rate-limited (Stripe retries)."""
    text = _read(ROUTERS_DIR / "payments.py")

    # Find the stripe_webhook decorator region and ensure no dependencies kwarg
    match = re.search(
        r"@router\.post\(\s*\"/webhook\"[^)]*\)\s*\n\s*async def stripe_webhook",
        text,
    )
    assert match is not None, "stripe_webhook decorator not found in expected form"
    decorator_block = match.group(0)
    assert "dependencies=" not in decorator_block, (
        "stripe_webhook must NOT have a rate-limit dependency"
    )


def test_all_router_modules_declare_rate_limit_at_decoration():
    """
    All @router.post / @router.get decorators in protected routers must
    declare a `dependencies=[Depends(rate_limit(...))]`, a
    `dependencies=[Depends(unsubscribe_rate_limit())]`, or be on the
    `stripe_webhook` exemption list.
    """
    # Routers that use the new pattern
    must_have = [
        "user.py",
        "feedback.py",
        "referral.py",
        "payments.py",
        "org.py",
        "breach.py",
        "pricing.py",
        "public.py",
        "email_unsubscribe.py",
    ]

    decorator_re = re.compile(
        r"@router\.(get|post|put|delete|patch)\(\s*\"([^\"]+)\"(.*?)\)\s*\n\s*async def (\w+)",
        re.DOTALL,
    )

    violations: list[str] = []
    for fname in must_have:
        text = _read(ROUTERS_DIR / fname)
        for match in decorator_re.finditer(text):
            _verb, _path, kwargs, func_name = match.groups()
            if (fname, func_name) in EXEMPT_ENDPOINTS:
                continue
            has_dep = "dependencies=" in kwargs and (
                "rate_limit(" in kwargs or "unsubscribe_rate_limit()" in kwargs
            )
            if not has_dep:
                violations.append(f"{fname}::{func_name}")

    assert violations == [], (
        f"Endpoints without a rate-limit dependency: {violations}"
    )

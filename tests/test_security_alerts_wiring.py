"""Rate limiting and the paid-source budget report to security_alerts.

(The endpoint wiring — JWT, export, delete, webhooks, SSRF, extension
session — is pinned next to each endpoint's own tests.)"""
from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException

from api.models.schemas import AuthUser, UserTier
from api.services import paid_budget, rate_limiter

USER = AuthUser(id="user-1", email="a@example.com", tier=UserTier.free)


@pytest.fixture
def limiter_redis(fake_redis, monkeypatch):
    async def _get():
        return fake_redis

    monkeypatch.setattr(rate_limiter, "get_redis", _get)
    return fake_redis


def _refused(coro) -> int:
    with pytest.raises(HTTPException) as exc:
        asyncio.run(coro)
    return exc.value.status_code


def test_ip_limit_429_is_reported_per_category(limiter_redis, security_events):
    asyncio.run(rate_limiter.check_ip_rate_limit("203.0.113.9", "public_check", 1, 60))
    assert security_events == []
    assert _refused(rate_limiter.check_ip_rate_limit("203.0.113.9", "public_check", 1, 60)) == 429
    assert security_events == [("rate_limited", "public_check")]


def test_install_limit_429_is_reported(limiter_redis, security_events):
    asyncio.run(rate_limiter.check_install_rate_limit("install-abcdef12", "check", 1, 60))
    assert _refused(rate_limiter.check_install_rate_limit("install-abcdef12", "check", 1, 60)) == 429
    assert security_events == [("rate_limited", "check")]


def test_sensitive_limit_429_is_reported(limiter_redis, security_events):
    asyncio.run(rate_limiter.check_sensitive_action_limit(USER, "user_export", limit=1))
    assert _refused(rate_limiter.check_sensitive_action_limit(USER, "user_export", limit=1)) == 429
    assert security_events == [("rate_limited", "sensitive:user_export")]


def test_burst_and_daily_429_are_reported(limiter_redis, security_events, monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "burst_limit", 1, raising=False)
    asyncio.run(rate_limiter.check_burst_only(USER))
    assert _refused(rate_limiter.check_burst_only(USER)) == 429

    monkeypatch.setattr(s, "burst_limit", 100, raising=False)
    monkeypatch.setattr(s, "free_tier_daily_limit", 1, raising=False)
    asyncio.run(rate_limiter.check_rate_limit(USER))
    assert _refused(rate_limiter.check_rate_limit(USER)) == 429
    assert security_events == [("rate_limited", "burst"), ("rate_limited", "daily_quota")]


def test_paid_budget_exhaustion_is_reported_once(fake_redis, security_events):
    async def _run():
        return [await paid_budget.take("ipqs", 2) for _ in range(5)]

    assert asyncio.run(_run()) == [True, True, False, False, False]
    assert security_events == [("paid_budget_exhausted", "ipqs")]

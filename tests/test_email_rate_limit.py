"""
Tests for per-user-per-template email rate limiting.

The rate limiter protects domain reputation: a bug or abuse vector that
fires the same template in a loop would tank our Gmail/Yahoo sender
score within hours. This catches that locally before infra catches it
operationally.

Covers:
- Allowed when count is below budget
- Blocked when count exceeds budget
- TTL set only on first increment (window anchored to first send)
- Different templates have independent budgets
- Different users have independent budgets
- Fails OPEN on Redis errors (transactional emails must still go out)
- send_template surfaces skipped=True, skip_reason="rate_limited"
- send_template without user_id never even checks the rate limit
"""
from __future__ import annotations

from typing import Dict

import pytest


class FakeRedis:
    """Minimal in-memory Redis stand-in for INCR + EXPIRE."""

    def __init__(self) -> None:
        self.counts: Dict[str, int] = {}
        self.ttls: Dict[str, int] = {}
        self.fail_mode = False

    async def incr(self, key: str) -> int:
        if self.fail_mode:
            raise RuntimeError("redis offline")
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def expire(self, key: str, seconds: int) -> bool:
        if self.fail_mode:
            raise RuntimeError("redis offline")
        self.ttls[key] = seconds
        return True


@pytest.fixture
def fake_redis(monkeypatch):
    fake = FakeRedis()

    async def _get_redis():
        return fake

    monkeypatch.setattr("api.services.cache.get_redis", _get_redis)
    return fake


# ─── _check_email_rate_limit ───────────────────────────────────────


@pytest.mark.asyncio
async def test_allowed_below_budget(fake_redis):
    from api.services.email import _check_email_rate_limit

    # weekly_report budget = (1, 8 * 86400). First call passes.
    assert await _check_email_rate_limit("u1", "weekly_report") is True


@pytest.mark.asyncio
async def test_blocked_when_budget_exhausted(fake_redis):
    from api.services.email import _check_email_rate_limit

    # weekly_report = 1 per 8 days. Second call must be blocked.
    assert await _check_email_rate_limit("u1", "weekly_report") is True
    assert await _check_email_rate_limit("u1", "weekly_report") is False


@pytest.mark.asyncio
async def test_breach_alert_higher_budget(fake_redis):
    """breach_alert = 20 per 24h. First several calls all pass."""
    from api.services.email import _check_email_rate_limit

    for i in range(20):
        assert await _check_email_rate_limit("u1", "breach_alert") is True, f"call {i+1}"
    # 21st must fail
    assert await _check_email_rate_limit("u1", "breach_alert") is False


@pytest.mark.asyncio
async def test_ttl_set_only_on_first_increment(fake_redis):
    """Window must be anchored to first send, not refreshed every call."""
    from api.services.email import _check_email_rate_limit

    await _check_email_rate_limit("u1", "breach_alert")
    first_ttl = fake_redis.ttls.get("email_rl:breach_alert:u1")
    assert first_ttl == 86400  # configured window

    # Tamper with TTL to detect a re-set on next call
    fake_redis.ttls["email_rl:breach_alert:u1"] = 999

    await _check_email_rate_limit("u1", "breach_alert")
    assert fake_redis.ttls["email_rl:breach_alert:u1"] == 999


@pytest.mark.asyncio
async def test_different_templates_independent(fake_redis):
    from api.services.email import _check_email_rate_limit

    # Exhaust weekly_report (budget 1)
    assert await _check_email_rate_limit("u1", "weekly_report") is True
    assert await _check_email_rate_limit("u1", "weekly_report") is False
    # welcome should still work
    assert await _check_email_rate_limit("u1", "welcome") is True


@pytest.mark.asyncio
async def test_different_users_independent(fake_redis):
    from api.services.email import _check_email_rate_limit

    assert await _check_email_rate_limit("u1", "weekly_report") is True
    assert await _check_email_rate_limit("u1", "weekly_report") is False  # u1 done
    assert await _check_email_rate_limit("u2", "weekly_report") is True  # u2 fresh


@pytest.mark.asyncio
async def test_fails_open_on_redis_error(fake_redis):
    """Redis outage MUST NOT block transactional emails."""
    from api.services.email import _check_email_rate_limit

    fake_redis.fail_mode = True
    assert await _check_email_rate_limit("u1", "welcome") is True


# ─── send_template integration ─────────────────────────────────────


@pytest.mark.asyncio
async def test_send_template_skips_when_rate_limited(monkeypatch, fake_redis):
    from api.services import email as email_svc

    async def _not_unsub(uid, tpl):
        return False

    monkeypatch.setattr(
        "api.routers.email_unsubscribe.is_unsubscribed", _not_unsub, raising=False
    )

    # Exhaust the weekly_report budget
    fake_redis.counts["email_rl:weekly_report:u1"] = 5  # already over

    sent = {"v": False}

    class _Provider:
        async def send(self, **_kw):
            sent["v"] = True
            return email_svc.SendResult(ok=True, provider_message_id="m", error=None, send_id="s")

    monkeypatch.setattr(email_svc, "get_provider", lambda: _Provider())

    result = await email_svc.send_template(
        to="user@test.com",
        user_id="u1",
        template="weekly_report",
        locale="en",
        fixture_overrides={"unsubscribe_url": "https://cleanway.ai/u/x"},
        unsubscribe_url="https://cleanway.ai/u/x",
    )

    assert result.skipped is True
    assert result.skip_reason == "rate_limited"
    assert result.ok is True
    assert sent["v"] is False  # provider was never called


@pytest.mark.asyncio
async def test_send_template_no_user_id_skips_rate_check(monkeypatch, fake_redis):
    """No user_id means transactional path: never check the rate limit."""
    from api.services import email as email_svc

    # If the rate-check ran, this would block (counter pre-bumped past budget).
    # We're verifying the no-user_id path doesn't even consult Redis.
    fake_redis.counts["email_rl:receipt:any"] = 9999

    monkeypatch.setattr(
        email_svc,
        "render_template",
        lambda *a, **k: email_svc.RenderedEmail(
            subject="s", html="<p>h</p>", text="t", template_key="receipt", locale="en"
        ),
    )

    sent = {"v": False}

    class _Provider:
        async def send(self, **_kw):
            sent["v"] = True
            return email_svc.SendResult(ok=True, provider_message_id="m", error=None, send_id="s")

    monkeypatch.setattr(email_svc, "get_provider", lambda: _Provider())

    result = await email_svc.send_template(
        to="user@test.com",
        # no user_id
        template="receipt",
        locale="en",
        fixture_overrides={"unsubscribe_url": "https://cleanway.ai/u/x"},
        unsubscribe_url="https://cleanway.ai/u/x",
    )

    assert result.skipped is False
    assert sent["v"] is True

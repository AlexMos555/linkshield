"""Security anomaly alerts: count security events in Redis, email once.

`security_alerts.record(event, key=...)` is called from the request path on
every security-relevant event (bad JWT, data export, forged webhook, SSRF
block, ...). Pinned here:

  - one alert when a rule's threshold is reached inside its window, none
    below it and none for the rest of the window;
  - a cooldown lock (SET NX) so the next window does not alert again, and
    two replicas never both send;
  - per-key rules count each key (user, category) on its own, and a user id
    never reaches Redis or the alert in the clear;
  - thresholds come from the environment, 0 turns a rule off;
  - Redis down, slow or failing: record() returns quietly (it never raises
    into the request path);
  - delivery: an email to SECURITY_ALERT_EMAIL through Resend, from
    alerts@cleanway.ai, Russian body with the runbook link; with no address
    configured only a CRITICAL log line.
"""
from __future__ import annotations

import asyncio
import logging
import os

import pytest

from api.services import security_alerts as sa


@pytest.fixture
def alerts(monkeypatch) -> list:
    """Capture delivered alerts instead of emailing them."""
    sent: list = []

    async def _deliver(alert):
        sent.append(alert)

    monkeypatch.setattr(sa, "_deliver", _deliver)
    monkeypatch.setattr(sa, "_last_unavailable_log", float("-inf"))
    monkeypatch.delenv("SECURITY_ALERTS_ENABLED", raising=False)
    for name in list(os.environ):
        if name.startswith("SECURITY_ALERT_THRESHOLD_"):
            monkeypatch.delenv(name, raising=False)
    return sent


async def _record_n(event: str, n: int, key=None) -> None:
    for _ in range(n):
        await sa.record(event, key=key)
    await sa.drain()


def _rule(event: str, per_key: bool = False):
    return next(r for r in sa.rules_for(event) if r.per_key is per_key)


# ─── threshold + window ─────────────────────────────────────────


def test_below_threshold_sends_nothing(fake_redis, alerts):
    threshold = _rule("webhook_signature_invalid", per_key=True).threshold
    asyncio.run(_record_n("webhook_signature_invalid", threshold - 1, key="stripe"))
    assert alerts == []


def test_reaching_the_threshold_sends_exactly_one_alert(fake_redis, alerts):
    rule = _rule("auth_invalid_token")
    asyncio.run(_record_n("auth_invalid_token", rule.threshold * 3))
    assert len(alerts) == 1
    a = alerts[0]
    assert a.event == "auth_invalid_token"
    assert a.count == rule.threshold
    assert a.window_s == rule.window_s


def test_counter_keys_expire_with_the_window(fake_redis, alerts):
    asyncio.run(_record_n("ssrf_blocked", 1))
    counters = [k for k in fake_redis._kv if k.startswith("secalert:n:ssrf_blocked")]
    assert counters, fake_redis._kv
    assert fake_redis._ttls[counters[0]] == _rule("ssrf_blocked").window_s


# ─── cooldown + dual replica ────────────────────────────────────


def _clear_counters(fake_redis) -> None:
    for k in [k for k in fake_redis._kv if k.startswith("secalert:n:")]:
        fake_redis._kv.pop(k)


def _clear_locks(fake_redis) -> None:
    for k in [k for k in fake_redis._kv if k.startswith("secalert:lock:")]:
        fake_redis._kv.pop(k)


def test_cooldown_suppresses_the_next_window_then_lets_it_through(fake_redis, alerts):
    n = _rule("ssrf_blocked").threshold
    asyncio.run(_record_n("ssrf_blocked", n))
    assert len(alerts) == 1

    _clear_counters(fake_redis)  # the 5-minute window rolled over
    asyncio.run(_record_n("ssrf_blocked", n))
    assert len(alerts) == 1, "still inside the cooldown"

    _clear_counters(fake_redis)
    _clear_locks(fake_redis)  # the cooldown expired
    asyncio.run(_record_n("ssrf_blocked", n))
    assert len(alerts) == 2


def test_cooldown_lock_has_a_ttl(fake_redis, alerts):
    asyncio.run(_record_n("ssrf_blocked", _rule("ssrf_blocked").threshold))
    locks = [k for k in fake_redis._kv if k.startswith("secalert:lock:")]
    assert len(locks) == 1
    assert fake_redis._ttls[locks[0]] == _rule("ssrf_blocked").cooldown_s


def test_lock_held_by_the_other_replica_means_no_second_email(fake_redis, alerts):
    """The other replica crossed the threshold first and holds the lock."""
    rule = _rule("ssrf_blocked")
    fake_redis._kv[sa.lock_key("ssrf_blocked", rule, None)] = "1"
    asyncio.run(_record_n("ssrf_blocked", rule.threshold))
    assert alerts == []


def test_concurrent_callers_send_one_alert(fake_redis, alerts):
    n = _rule("auth_invalid_token").threshold

    async def _run():
        await asyncio.gather(*(sa.record("auth_invalid_token") for _ in range(n + 20)))
        await sa.drain()

    asyncio.run(_run())
    assert len(alerts) == 1


# ─── per-key rules ──────────────────────────────────────────────


def test_per_user_export_rule_counts_each_user_separately(fake_redis, alerts):
    per_user = _rule("user_export", per_key=True)
    assert per_user.threshold == 4 and per_user.window_s == 3600  # "> 3 an hour"

    async def _run():
        for _ in range(per_user.threshold - 1):
            await sa.record("user_export", key="user-a")
            await sa.record("user_export", key="user-b")
        await sa.drain()

    asyncio.run(_run())
    assert alerts == []

    asyncio.run(_record_n("user_export", 1, key="user-a"))
    assert len(alerts) == 1
    assert alerts[0].per_key is True
    assert alerts[0].count == per_user.threshold


def test_user_ids_never_reach_redis_or_the_alert(fake_redis, alerts):
    uid = "6f1c2d3e-aaaa-bbbb-cccc-123456789abc"
    asyncio.run(_record_n("user_export", 10, key=uid))
    assert all(uid not in k for k in fake_redis._kv)
    assert alerts
    subject, body = sa.build_message(alerts[0])
    assert uid not in subject and uid not in body
    assert alerts[0].key_label and alerts[0].key_label != uid


def test_global_export_rule_sums_all_users(fake_redis, alerts):
    total = _rule("user_export").threshold

    async def _run():
        for i in range(total):
            await sa.record("user_export", key=f"user-{i}")
        await sa.drain()

    asyncio.run(_run())
    assert [a.per_key for a in alerts] == [False]


def test_public_keys_are_shown_as_is(fake_redis, alerts):
    """Rate-limit categories and webhook providers are not personal data."""
    rule = _rule("rate_limited", per_key=True)
    asyncio.run(_record_n("rate_limited", rule.threshold, key="public_check"))
    assert len(alerts) == 1
    assert alerts[0].key_label == "public_check"


def test_per_key_rule_without_a_key_is_skipped(fake_redis, alerts):
    asyncio.run(_record_n("rate_limited", _rule("rate_limited", per_key=True).threshold))
    assert alerts == []


def test_paid_budget_exhaustion_alerts_once_per_day_per_budget(fake_redis, alerts):
    rule = _rule("paid_budget_exhausted", per_key=True)
    assert rule.threshold == 1 and rule.cooldown_s >= 86400
    asyncio.run(_record_n("paid_budget_exhausted", 1, key="ipqs"))
    asyncio.run(_record_n("paid_budget_exhausted", 1, key="llm_judge"))
    _clear_counters(fake_redis)
    asyncio.run(_record_n("paid_budget_exhausted", 1, key="ipqs"))
    assert [a.key_label for a in alerts] == ["ipqs", "llm_judge"]


# ─── configuration ──────────────────────────────────────────────


def test_threshold_comes_from_the_environment(fake_redis, alerts, monkeypatch):
    monkeypatch.setenv("SECURITY_ALERT_THRESHOLD_AUTH_INVALID_TOKEN", "3")
    asyncio.run(_record_n("auth_invalid_token", 3))
    assert len(alerts) == 1 and alerts[0].count == 3


def test_per_key_threshold_comes_from_the_environment(fake_redis, alerts, monkeypatch):
    monkeypatch.setenv("SECURITY_ALERT_THRESHOLD_USER_EXPORT_PER_KEY", "2")
    asyncio.run(_record_n("user_export", 2, key="user-a"))
    assert [a.per_key for a in alerts] == [True]


def test_zero_threshold_turns_a_rule_off(fake_redis, alerts, monkeypatch):
    monkeypatch.setenv("SECURITY_ALERT_THRESHOLD_SSRF_BLOCKED", "0")
    asyncio.run(_record_n("ssrf_blocked", 500))
    assert alerts == []


def test_garbage_threshold_falls_back_to_the_default(monkeypatch):
    default = _rule("ssrf_blocked").threshold
    monkeypatch.setenv("SECURITY_ALERT_THRESHOLD_SSRF_BLOCKED", "lots")
    assert _rule("ssrf_blocked").threshold == default


def test_alerts_can_be_switched_off(fake_redis, alerts, monkeypatch):
    monkeypatch.setenv("SECURITY_ALERTS_ENABLED", "false")
    asyncio.run(_record_n("ssrf_blocked", 500))
    assert alerts == [] and not fake_redis._kv


def test_unknown_event_is_ignored(fake_redis, alerts):
    asyncio.run(_record_n("no_such_event", 5))
    assert alerts == [] and not fake_redis._kv


def test_every_wired_event_has_rules_and_an_explanation():
    for event in (
        "auth_invalid_token", "reauth_required", "user_export", "account_delete",
        "webhook_signature_invalid", "ssrf_blocked", "paid_budget_exhausted",
        "rate_limited", "admin_or_service_key_use",
    ):
        assert sa.rules_for(event), event
        assert event in sa.EVENT_INFO, event


# ─── Redis trouble never reaches the request ────────────────────


def test_redis_down_is_quiet(redis_down, alerts, caplog):
    caplog.set_level(logging.WARNING, logger="cleanway.security_alerts")
    asyncio.run(_record_n("auth_invalid_token", 300))
    assert alerts == []
    assert "security_alert_counter_unavailable" in caplog.text


def test_redis_error_mid_command_is_quiet(fake_redis, alerts, monkeypatch):
    async def _boom(*_a, **_k):
        raise RuntimeError("READONLY You can't write against a read only replica")

    monkeypatch.setattr(fake_redis, "eval", _boom)
    asyncio.run(_record_n("auth_invalid_token", 5))
    assert alerts == []


def test_slow_redis_times_out(fake_redis, alerts, monkeypatch):
    async def _hang(*_a, **_k):
        await asyncio.sleep(5)

    monkeypatch.setattr(fake_redis, "eval", _hang)
    monkeypatch.setattr(sa, "REDIS_TIMEOUT_S", 0.05)

    async def _run():
        loop = asyncio.get_running_loop()
        start = loop.time()
        await sa.record("auth_invalid_token")
        return loop.time() - start

    assert asyncio.run(_run()) < 1.0
    assert alerts == []


def test_delivery_failure_is_quiet(fake_redis, monkeypatch, caplog):
    async def _boom(_alert):
        raise RuntimeError("resend down")

    monkeypatch.setattr(sa, "_deliver", _boom)
    caplog.set_level(logging.ERROR, logger="cleanway.security_alerts")
    asyncio.run(_record_n("ssrf_blocked", _rule("ssrf_blocked").threshold))
    assert "security_alert_delivery_failed" in caplog.text


# ─── message + delivery ─────────────────────────────────────────


def _alert(**kw):
    base = dict(event="user_export", count=20, threshold=20, window_s=300, per_key=False, key_label=None)
    base.update(kw)
    return sa.Alert(**base)


def test_subject_names_the_event_count_and_window():
    subject, _ = sa.build_message(_alert())
    assert subject == "Cleanway security: user_export (20 in 5 min)"
    subject, _ = sa.build_message(_alert(count=4, threshold=4, window_s=3600, per_key=True, key_label="ab12"))
    assert subject == "Cleanway security: user_export (4 in 60 min)"


def test_body_is_russian_and_points_at_the_runbook():
    _, body = sa.build_message(_alert())
    assert "docs/runbooks/security-incident.md" in body
    assert "Что проверить" in body
    assert sa.EVENT_INFO["user_export"][0] in body


def test_no_address_configured_logs_critical_and_sends_nothing(monkeypatch, caplog):
    monkeypatch.delenv("SECURITY_ALERT_EMAIL", raising=False)
    sent = []

    class _Provider:
        async def send(self, **kw):  # pragma: no cover — must not be called
            sent.append(kw)

    monkeypatch.setattr(sa, "_email_provider", lambda: _Provider())
    caplog.set_level(logging.CRITICAL, logger="cleanway.security_alerts")
    asyncio.run(sa._deliver(_alert()))
    assert sent == []
    assert any(r.levelno == logging.CRITICAL and "SECURITY_ALERT_EMAIL" in r.getMessage() for r in caplog.records)


def test_dispatch_always_logs_a_critical_line(fake_redis, alerts, caplog):
    caplog.set_level(logging.CRITICAL, logger="cleanway.security_alerts")
    asyncio.run(_record_n("ssrf_blocked", _rule("ssrf_blocked").threshold))
    lines = [r.getMessage() for r in caplog.records if r.levelno == logging.CRITICAL]
    assert any("security_alert" in m and "ssrf_blocked" in m for m in lines)


def test_email_goes_through_resend_from_the_alerts_address(monkeypatch):
    from api.services import email as email_service

    monkeypatch.setenv("SECURITY_ALERT_EMAIL", "founder@example.com")
    monkeypatch.setenv("RESEND_API_KEY", "re_test_not_real")
    monkeypatch.delenv("SECURITY_ALERT_FROM", raising=False)
    captured = {}

    async def _send(self, **kw):
        captured.update(kw)
        return email_service.SendResult(ok=True, provider_message_id="m1", error=None, send_id="s1")

    monkeypatch.setattr(email_service.ResendProvider, "send", _send)
    asyncio.run(sa._deliver(_alert()))
    assert captured["to"] == "founder@example.com"
    assert captured["from_addr"] == "alerts@cleanway.ai"
    assert captured["subject"] == "Cleanway security: user_export (20 in 5 min)"
    assert "docs/runbooks/security-incident.md" in captured["text"]
    assert captured["headers"].get("Auto-Submitted") == "auto-generated"


def test_failed_send_is_logged_not_raised(monkeypatch, caplog):
    from api.services import email as email_service

    monkeypatch.setenv("SECURITY_ALERT_EMAIL", "founder@example.com")
    monkeypatch.setenv("RESEND_API_KEY", "re_test_not_real")

    async def _send(self, **kw):
        return email_service.SendResult(ok=False, provider_message_id=None, error="Resend 500", send_id="s1")

    monkeypatch.setattr(email_service.ResendProvider, "send", _send)
    caplog.set_level(logging.ERROR, logger="cleanway.security_alerts")
    asyncio.run(sa._deliver(_alert()))
    assert "security_alert_email_failed" in caplog.text

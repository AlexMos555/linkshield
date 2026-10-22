"""Server-side retention promised by the privacy policy (docs/PRIVACY.md,
landing.privacy_policy section 16) — enforced by api/services/retention.py.

Pinned here:
  - each table rule deletes exactly what the policy says is expired
    (audit_log 2 years, weekly_aggregates 1 year, family_alerts past
    expires_at / legacy rows past 30 days, family_invites past expiry or
    redeemed more than a day ago, feedback_reports 1 year) and nothing
    without a filter;
  - dry-run counts and never deletes;
  - "off" (the default) does nothing at all;
  - one failing table doesn't stop the others and is reported;
  - the account purge runs only in "on" mode; dry-run counts candidates;
  - the background loop is not started unless RETENTION_PURGE is set;
  - the docs that point a reader at the policy's retention list name the
    section it has today.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

from api.services import retention

ROOT = Path(__file__).resolve().parent.parent

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)


class _Resp:
    def __init__(self, status: int, body: Any = None, headers: Dict[str, str] | None = None):
        self.status_code = status
        self._body = body if body is not None else []
        self.headers = headers or {}

    def json(self):
        return self._body


class _Stub:
    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.fail_tables: set[str] = set()
        self.count = 3

    def client(self):
        stub = self

        class _Client:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def request(self, method, url, params=None, headers=None, **_kw):
                table = url.rsplit("/", 1)[-1]
                stub.calls.append(
                    {"method": method, "table": table, "params": dict(params or {}), "headers": dict(headers or {})}
                )
                if table in stub.fail_tables:
                    return _Resp(500)
                return _Resp(200 if method == "GET" else 204, [], {"Content-Range": f"*/{stub.count}"})

        return _Client


@pytest.fixture
def stub(monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://proj.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_secret_key", "sb_secret_test_value_123", raising=False)
    st = _Stub()
    monkeypatch.setattr("httpx.AsyncClient", st.client())
    return st


def _by_table(calls, table):
    return [c for c in calls if c["table"] == table]


def test_rules_match_the_policy():
    rules = {r.name: r.params(NOW) for r in retention.TABLE_RULES}
    assert rules == {
        "audit_log_2y": {"created_at": f"lt.{(NOW - timedelta(days=730)).isoformat()}"},
        "weekly_aggregates_1y": {"week_start": f"lt.{(NOW - timedelta(days=365)).date().isoformat()}"},
        "family_alerts_expired": {"expires_at": f"lt.{NOW.isoformat()}"},
        "family_alerts_legacy_30d": {
            "expires_at": "is.null",
            "created_at": f"lt.{(NOW - timedelta(days=30)).isoformat()}",
        },
        "family_invites_expired": {"expires_at": f"lt.{NOW.isoformat()}"},
        "family_invites_redeemed": {"redeemed_at": f"lt.{(NOW - timedelta(days=1)).isoformat()}"},
        # Wrong-result and phishing reports (the app, the extension, the
        # Outlook add-in) had no end date at all; the policy now says 1 year.
        "feedback_reports_1y": {"created_at": f"lt.{(NOW - timedelta(days=365)).isoformat()}"},
    }
    tables = {r.name: r.table for r in retention.TABLE_RULES}
    assert tables["feedback_reports_1y"] == "feedback_reports"
    assert tables["audit_log_2y"] == "audit_log"
    assert tables["weekly_aggregates_1y"] == "weekly_aggregates"
    assert tables["family_alerts_expired"] == tables["family_alerts_legacy_30d"] == "family_alerts"
    assert tables["family_invites_expired"] == tables["family_invites_redeemed"] == "family_invites"


def test_windows_agree_with_the_code_that_sets_them():
    from api.routers import family, user
    from api.services import account_purge

    assert retention.FAMILY_ALERT_LEGACY_DAYS == family.ALERT_DEFAULT_TTL_DAYS
    assert account_purge.GRACE_DAYS == user._DELETION_GRACE_DAYS == 30
    assert retention.AUDIT_LOG_DAYS == 730
    assert retention.WEEKLY_AGGREGATES_DAYS == 365
    assert retention.FEEDBACK_REPORTS_DAYS == 365


def _policy_section_number(title: str) -> int:
    """Number of the English policy section titled ``title`` ("16. How long…")."""
    source = json.loads((ROOT / "packages" / "i18n-strings" / "src" / "en.json").read_text(encoding="utf-8"))
    for section in source["landing"]["privacy_policy"]["sections"]:
        number, _, name = section["title"].partition(". ")
        if name == title:
            return int(number)
    raise AssertionError(f"no policy section titled {title!r}")


def test_docs_name_the_policy_section_that_lists_retention():
    # #274 inserted "15. Why we may use your data", so the retention list moved
    # to 16 and every "section 15" pointer started naming the legal bases.
    n = _policy_section_number("How long we keep data")
    assert f"public policy section {n}," in (retention.__doc__ or "")
    runbook = (ROOT / "docs" / "runbooks" / "data-retention.md").read_text(encoding="utf-8")
    assert f"раздел {n} `landing.privacy_policy`" in runbook
    readme = (ROOT / "email-plugin-outlook" / "README.md").read_text(encoding="utf-8")
    assert f"policy section {n})" in readme


@pytest.mark.asyncio
async def test_on_mode_deletes_with_filters(stub, monkeypatch):
    purged: list = []

    async def _fake_purge():
        purged.append(True)
        return {"deleted": 1, "ids": ["u1"]}

    monkeypatch.setattr("api.services.account_purge.purge_expired_accounts", _fake_purge)

    out = await retention.run_retention("on", now=NOW)

    assert purged == [True]
    assert out["mode"] == "on"
    assert out["accounts"] == {"deleted": 1, "ids": ["u1"]}
    deletes = [c for c in stub.calls if c["method"] == "DELETE"]
    assert len(deletes) == len(retention.TABLE_RULES)
    for call, rule in zip(deletes, retention.TABLE_RULES):
        assert call["table"] == rule.table
        assert call["params"] == rule.params(NOW)
        assert call["params"], "never a DELETE without a filter"
        assert call["headers"]["apikey"] == "sb_secret_test_value_123"
        assert "count=exact" in call["headers"]["Prefer"]
    assert out["tables"]["audit_log_2y"] == {"deleted": 3}


@pytest.mark.asyncio
async def test_dry_run_counts_and_never_deletes(stub, monkeypatch):
    async def _boom():
        raise AssertionError("dry run must not purge accounts")

    monkeypatch.setattr("api.services.account_purge.purge_expired_accounts", _boom)

    out = await retention.run_retention("dry_run", now=NOW)

    assert all(c["method"] == "GET" for c in stub.calls)
    users = _by_table(stub.calls, "users")
    assert users[0]["params"]["deletion_requested_at"] == f"lte.{(NOW - timedelta(days=30)).isoformat()}"
    assert out["accounts"] == {"would_delete": 3}
    assert out["tables"]["family_alerts_expired"] == {"would_delete": 3}
    for c in stub.calls:
        assert c["params"]["limit"] == "1"
        assert c["headers"]["Prefer"] == "count=exact"


@pytest.mark.asyncio
async def test_off_mode_does_nothing(stub):
    out = await retention.run_retention("off", now=NOW)
    assert out == {"mode": "off"}
    assert stub.calls == []


@pytest.mark.asyncio
async def test_one_failing_table_does_not_stop_the_rest(stub, monkeypatch):
    async def _fake_purge():
        return {"deleted": 0}

    monkeypatch.setattr("api.services.account_purge.purge_expired_accounts", _fake_purge)
    stub.fail_tables = {"audit_log"}

    out = await retention.run_retention("on", now=NOW)

    assert out["tables"]["audit_log_2y"] == {"error": "status_500"}
    assert out["tables"]["weekly_aggregates_1y"] == {"deleted": 3}
    assert len([c for c in stub.calls if c["method"] == "DELETE"]) == len(retention.TABLE_RULES)


@pytest.mark.asyncio
async def test_unconfigured_supabase_is_a_noop(monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "", raising=False)
    out = await retention.run_retention("on", now=NOW)
    assert out == {"mode": "on", "skipped": "supabase_not_configured"}


def test_count_from_content_range():
    assert retention._count(_Resp(200, headers={"Content-Range": "0-0/42"})) == 42
    assert retention._count(_Resp(204, headers={"Content-Range": "*/7"})) == 7
    assert retention._count(_Resp(204, headers={"content-range": "*/0"})) == 0
    assert retention._count(_Resp(204)) is None
    assert retention._count(_Resp(204, headers={"Content-Range": "*/*"})) is None


def test_mode_parsing():
    assert retention.parse_mode("") == "off"
    assert retention.parse_mode("OFF") == "off"
    assert retention.parse_mode("dry-run") == "dry_run"
    assert retention.parse_mode("dry_run") == "dry_run"
    assert retention.parse_mode("on") == "on"
    assert retention.parse_mode("true") == "on"
    # Anything unrecognised is OFF — a typo must never start deleting.
    assert retention.parse_mode("yes please") == "off"


@pytest.mark.asyncio
async def test_loop_not_started_when_off(monkeypatch):
    from api import config

    monkeypatch.setattr(config.get_settings(), "retention_purge", "off", raising=False)
    assert retention.start_background() is None


@pytest.mark.asyncio
async def test_loop_runs_after_delay_then_every_interval(monkeypatch):
    import asyncio

    from api import config

    monkeypatch.setattr(config.get_settings(), "retention_purge", "dry-run", raising=False)
    monkeypatch.setattr(retention, "FIRST_RUN_DELAY_S", 0.01)
    monkeypatch.setattr(retention, "INTERVAL_S", 0.01)
    runs: list = []

    async def _fake_run(mode, now=None):
        runs.append(mode)
        return {"mode": mode}

    async def _no_lock():
        return True

    monkeypatch.setattr(retention, "run_retention", _fake_run)
    monkeypatch.setattr(retention, "_acquire_lock", _no_lock)

    task = retention.start_background()
    assert task is not None
    await asyncio.sleep(0.1)
    await retention.stop_background()
    assert len(runs) >= 2
    assert set(runs) == {"dry_run"}


@pytest.mark.asyncio
async def test_loop_skips_a_tick_another_replica_holds(monkeypatch):
    import asyncio

    from api import config

    monkeypatch.setattr(config.get_settings(), "retention_purge", "on", raising=False)
    monkeypatch.setattr(retention, "FIRST_RUN_DELAY_S", 0.01)
    monkeypatch.setattr(retention, "INTERVAL_S", 0.01)
    runs: list = []

    async def _fake_run(mode, now=None):
        runs.append(mode)
        return {}

    async def _held():
        return False

    monkeypatch.setattr(retention, "run_retention", _fake_run)
    monkeypatch.setattr(retention, "_acquire_lock", _held)

    retention.start_background()
    await asyncio.sleep(0.05)
    await retention.stop_background()
    assert runs == []


# ── What /health/deep shows (founder console, 2026-10-22) ──
#
# The production value of RETENTION_PURGE was unknowable from outside: the
# JSON log dropped the pass counts and /health/deep said nothing. Every pass
# now leaves its time in Redis (shared by the replicas), and the component
# reports the mode and the last pass that succeeded.

NOW_TS = int(NOW.timestamp())


async def _purge_ok():
    return {"deleted": 0}


@pytest.mark.asyncio
async def test_a_clean_pass_is_remembered(stub, fake_redis, monkeypatch):
    monkeypatch.setattr("api.services.account_purge.purge_expired_accounts", _purge_ok)
    monkeypatch.setattr(retention, "_settings_mode", lambda: "on")
    await retention.run_retention("on", now=NOW)

    st = await retention.health_status(now=NOW_TS + 60)
    assert st["mode"] == "on"
    assert st["last_ok_at"] == NOW.isoformat()
    assert st["last_pass_at"] == NOW.isoformat()
    assert st["last_pass_failed"] == []
    assert st["ok"] is True


@pytest.mark.asyncio
async def test_a_failed_pass_is_shown_but_is_not_a_success(stub, fake_redis, monkeypatch):
    monkeypatch.setattr("api.services.account_purge.purge_expired_accounts", _purge_ok)
    monkeypatch.setattr(retention, "_settings_mode", lambda: "on")
    stub.fail_tables = {"audit_log"}
    await retention.run_retention("on", now=NOW)

    st = await retention.health_status(now=NOW_TS + 60)
    assert st["last_pass_failed"] == ["audit_log_2y"]
    assert st["last_ok_at"] is None
    assert (st["ok"], st["error"]) == (False, "no_recent_pass")


@pytest.mark.asyncio
async def test_a_failed_account_purge_counts_as_a_failed_pass(stub, fake_redis, monkeypatch):
    async def _boom():
        raise RuntimeError("purge down")

    monkeypatch.setattr("api.services.account_purge.purge_expired_accounts", _boom)
    await retention.run_retention("on", now=NOW)
    st = await retention.health_status(now=NOW_TS + 60)
    assert st["last_pass_failed"] == ["accounts"]
    assert st["last_ok_at"] is None


@pytest.mark.asyncio
async def test_an_old_success_is_stale(stub, fake_redis, monkeypatch):
    monkeypatch.setattr("api.services.account_purge.purge_expired_accounts", _purge_ok)
    monkeypatch.setattr(retention, "_settings_mode", lambda: "on")
    await retention.run_retention("on", now=NOW)
    st = await retention.health_status(now=NOW_TS + retention.STALE_AFTER_S + 1)
    assert (st["ok"], st["error"]) == (False, "no_recent_pass")
    assert st["last_ok_at"] == NOW.isoformat()


@pytest.mark.asyncio
async def test_a_dry_run_is_shown_as_not_deleting(stub, fake_redis, monkeypatch):
    monkeypatch.setattr(retention, "_settings_mode", lambda: "dry_run")
    await retention.run_retention("dry_run", now=NOW)
    st = await retention.health_status(now=NOW_TS + 60)
    assert st["mode"] == "dry_run"
    assert st["last_ok_mode"] == "dry_run"
    assert (st["ok"], st["error"]) == (False, "dry_run")


@pytest.mark.asyncio
async def test_a_dry_run_success_does_not_count_once_switched_on(stub, fake_redis, monkeypatch):
    await retention.run_retention("dry_run", now=NOW)
    monkeypatch.setattr(retention, "_settings_mode", lambda: "on")
    st = await retention.health_status(now=NOW_TS + 60)
    assert (st["ok"], st["error"]) == (False, "no_recent_pass")
    assert st["last_ok_mode"] == "dry_run"


@pytest.mark.asyncio
@pytest.mark.parametrize("garbage", ["not json", "[1, 2]", '{"at": "yesterday"}'])
async def test_garbage_in_redis_reads_as_no_pass(fake_redis, monkeypatch, garbage):
    monkeypatch.setattr(retention, "_settings_mode", lambda: "on")
    await fake_redis.set("retention:last_pass", garbage)
    await fake_redis.set("retention:last_ok", garbage)
    st = await retention.health_status()
    assert (st["last_pass_at"], st["last_ok_at"], st["error"]) == (None, None, "no_recent_pass")


@pytest.mark.asyncio
async def test_off_says_so(fake_redis, monkeypatch):
    monkeypatch.setattr(retention, "_settings_mode", lambda: "off")
    st = await retention.health_status()
    assert st == {"mode": "off", "last_ok_at": None, "last_ok_mode": None, "last_pass_at": None,
                  "last_pass_failed": None, "ok": False, "error": "off"}


@pytest.mark.asyncio
async def test_the_mode_comes_from_the_setting(fake_redis, monkeypatch):
    from api import config

    monkeypatch.setattr(config.get_settings(), "retention_purge", "dry-run", raising=False)
    assert (await retention.health_status())["mode"] == "dry_run"


@pytest.mark.asyncio
async def test_redis_down_still_reports_the_mode(redis_down, monkeypatch):
    monkeypatch.setattr(retention, "_settings_mode", lambda: "on")
    st = await retention.health_status()
    assert st["mode"] == "on"
    assert (st["ok"], st["error"]) == (False, "redis_unavailable")


@pytest.mark.asyncio
async def test_redis_down_never_breaks_a_pass(stub, redis_down, monkeypatch):
    monkeypatch.setattr("api.services.account_purge.purge_expired_accounts", _purge_ok)
    out = await retention.run_retention("on", now=NOW)
    assert out["tables"]["audit_log_2y"] == {"deleted": 3}

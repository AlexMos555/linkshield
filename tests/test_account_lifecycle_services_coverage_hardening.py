"""Account lifecycle services — failure paths of retention, purge, devices.

  api/services/retention.py        sweep never deletes without a filter; one
                                   broken table / Redis / the account purge
                                   never stops the others; the loop survives
                                   a crashing pass; the CLI exit code tells
                                   an operator something failed.
  api/services/account_purge.py    timeouts at each step keep the user for
                                   the next run instead of half-purging; a
                                   failed final DELETE writes no
                                   "hard_deleted" audit rows.
  api/services/account_devices.py  store outages surface as StoreUnavailable
                                   (→ 503), never as "linked" / "not found";
                                   malformed ids never reach the store.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx
import pytest

from api.services import account_devices, retention
from api.services.account_store import AccountStoreError
from tests.supabase_rest_stub import FakeSupabase

NOW = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
ACCOUNT = "55555555-5555-4555-8555-555555555555"


@pytest.fixture
def sb(monkeypatch) -> FakeSupabase:
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    stub = FakeSupabase()
    # Migration 027's functions (Supabase Auth's sign-in log) answer with
    # their bigint, as PostgREST does.
    stub.on("GET", "/rest/v1/rpc/", body=0).on("POST", "/rest/v1/rpc/", body=0)
    monkeypatch.setattr(httpx, "AsyncClient", stub.client())
    return stub


# ─── retention: one pass ─────────────────────────────────────────


@pytest.fixture
def no_account_purge(monkeypatch):
    async def _purge():
        return {"deleted": 0}

    monkeypatch.setattr("api.services.account_purge.purge_expired_accounts", _purge)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["on", "dry_run"])
async def test_a_rule_without_a_filter_is_refused_not_run(sb, monkeypatch, no_account_purge, mode):
    bad = retention.TableRule("everything", "audit_log", lambda now: {})
    monkeypatch.setattr(retention, "TABLE_RULES", (bad,) + retention.TABLE_RULES)

    out = await retention.run_retention(mode, now=NOW)

    assert out["tables"]["everything"] == {"error": "no_filter"}
    # No request went out for it: every table call carries a real filter …
    # (the auth sign-in log's rule is a function call, not a table rule)
    calls = [c for c in sb.calls if "/rest/v1/rpc/" not in c["url"]]
    for call in calls:
        assert set(call["params"]) - {"select", "limit"}, call
    # … and the genuine rules still ran.
    table_calls = [c for c in calls if "/rest/v1/users" not in c["url"]]
    assert len(table_calls) == len(retention.TABLE_RULES) - 1
    assert out["tables"]["audit_log_2y"].keys() & {"deleted", "would_delete"}


@pytest.mark.asyncio
async def test_on_mode_table_timeouts_are_reported_and_the_rest_still_run(sb, no_account_purge):
    sb.on("DELETE", "/rest/v1/family_alerts", exc=httpx.ReadTimeout("slow"))
    sb.on("DELETE", "/rest/v1/weekly_aggregates", status=200, headers={"Content-Range": "*/4"})

    out = await retention.run_retention("on", now=NOW)

    assert out["tables"]["family_alerts_expired"] == {"error": "ReadTimeout"}
    assert out["tables"]["family_alerts_legacy_30d"] == {"error": "ReadTimeout"}
    assert out["tables"]["weekly_aggregates_1y"] == {"deleted": 4}
    assert len(sb.to("DELETE", "/rest/v1/")) == len(retention.TABLE_RULES)


@pytest.mark.asyncio
async def test_dry_run_upstream_errors_are_reported_and_nothing_is_deleted(sb):
    sb.on("GET", "/rest/v1/users", exc=httpx.ConnectError("down"))
    sb.on("GET", "/rest/v1/audit_log", status=401, body={"message": "bad key"})
    sb.on("GET", "/rest/v1/family_invites", exc=httpx.ReadTimeout("slow"))

    out = await retention.run_retention("dry_run", now=NOW)

    assert out["accounts"] == {"error": "ConnectError"}
    assert out["tables"]["audit_log_2y"] == {"error": "status_401"}
    assert out["tables"]["family_invites_expired"] == {"error": "ReadTimeout"}
    assert out["tables"]["weekly_aggregates_1y"] == {"would_delete": None}  # no Content-Range
    assert sb.writes() == []


@pytest.mark.asyncio
async def test_dry_run_account_count_rejected(sb):
    sb.on("GET", "/rest/v1/users", status=500, body={"message": "boom"})
    out = await retention.run_retention("dry_run", now=NOW)
    assert out["accounts"] == {"error": "status_500"}


@pytest.mark.asyncio
async def test_a_crashing_account_purge_does_not_stop_the_table_sweep(sb, monkeypatch):
    async def _boom():
        raise RuntimeError("purge exploded")

    monkeypatch.setattr("api.services.account_purge.purge_expired_accounts", _boom)
    out = await retention.run_retention("on", now=NOW)
    assert out["accounts"] == {"error": "RuntimeError"}
    assert len(sb.to("DELETE", "/rest/v1/")) == len(retention.TABLE_RULES)


# ─── retention: lock, loop, CLI ──────────────────────────────────


@pytest.mark.asyncio
async def test_lock_lets_one_replica_run_a_tick(fake_redis):
    assert await retention._acquire_lock() is True
    assert await retention._acquire_lock() is False  # the other replica
    assert fake_redis._ttls["retention:lock"] == 30 * 60


@pytest.mark.asyncio
async def test_lock_with_redis_down_runs_anyway(redis_down):
    # Every rule is idempotent: a double run only repeats a no-op.
    assert await retention._acquire_lock() is True


@pytest.mark.asyncio
async def test_loop_survives_a_crashing_pass(monkeypatch):
    monkeypatch.setattr(retention, "FIRST_RUN_DELAY_S", 0)
    monkeypatch.setattr(retention, "INTERVAL_S", 0.001)
    runs: list[str] = []
    second = asyncio.Event()

    async def _run(mode, now=None):
        runs.append(mode)
        if len(runs) == 1:
            raise RuntimeError("bad pass")
        second.set()
        return {}

    async def _lock():
        return True

    monkeypatch.setattr(retention, "run_retention", _run)
    monkeypatch.setattr(retention, "_acquire_lock", _lock)
    task = asyncio.ensure_future(retention.retention_loop("on"))
    try:
        await asyncio.wait_for(second.wait(), timeout=2)
    finally:
        task.cancel()
        await asyncio.wait({task}, timeout=1)
    assert runs[:2] == ["on", "on"]


@pytest.mark.asyncio
async def test_loop_stops_when_cancelled_mid_pass(monkeypatch):
    monkeypatch.setattr(retention, "FIRST_RUN_DELAY_S", 0)

    async def _run(mode, now=None):
        raise asyncio.CancelledError()

    async def _lock():
        return True

    monkeypatch.setattr(retention, "run_retention", _run)
    monkeypatch.setattr(retention, "_acquire_lock", _lock)
    task = asyncio.ensure_future(retention.retention_loop("on"))
    await asyncio.wait({task}, timeout=2)
    assert task.cancelled()


@pytest.mark.asyncio
async def test_starting_the_loop_twice_keeps_one_task(monkeypatch):
    from api import config

    monkeypatch.setattr(config.get_settings(), "retention_purge", "dry_run", raising=False)
    monkeypatch.setattr(retention, "FIRST_RUN_DELAY_S", 3600)
    try:
        first = retention.start_background()
        assert retention.start_background() is first
    finally:
        await retention.stop_background()
    assert first.cancelled() or first.done()
    # Shutdown when the loop was never started (mode off) is a no-op.
    await retention.stop_background()


@pytest.mark.parametrize("argv, result, code, mode", [
    (["--dry-run"], {"mode": "dry_run", "tables": {"a": {"would_delete": 1}}}, 0, "dry_run"),
    ([], {"mode": "on", "tables": {"a": {"deleted": 1}}, "accounts": {"deleted": 0}}, 0, "on"),
    ([], {"mode": "on", "tables": {"a": {"error": "status_500"}}}, 1, "on"),
    ([], {"mode": "on", "tables": {}, "accounts": {"error": "list_exception"}}, 1, "on"),
    # Accounts erased, but their Supabase Auth sign-in log entries stayed.
    ([], {"mode": "on", "tables": {}, "accounts": {"deleted": 1, "auth_audit_log_error": "not_installed"}}, 1, "on"),
])
def test_cli_exit_code_reports_failures(monkeypatch, capsys, argv, result, code, mode):
    seen: list = []

    async def _run(m, now=None):
        seen.append(m)
        return result

    monkeypatch.setattr(retention, "run_retention", _run)
    assert retention.main(argv) == code
    assert seen == [mode]
    assert '"mode"' in capsys.readouterr().out


# ─── account purge ───────────────────────────────────────────────


def _purge_candidates(sb: FakeSupabase, *ids: str) -> None:
    # The listing and each per-user re-read; the DELETE returns the rows it removed.
    sb.on("GET", "/rest/v1/users", body=[{"id": i} for i in ids])
    sb.on("DELETE", "/rest/v1/users", status=200, body=[{"id": i} for i in ids])


def _hard_deleted_audits(sb: FakeSupabase) -> list[dict]:
    return [c["json"] for c in sb.to("POST", "/rest/v1/audit_log") if c["json"]["action"] == "account.hard_deleted"]


@pytest.mark.asyncio
async def test_purge_listing_timeout_deletes_nothing(sb):
    from api.services.account_purge import purge_expired_accounts

    sb.on("GET", "/rest/v1/users", exc=httpx.ReadTimeout("slow"))
    assert await purge_expired_accounts() == {"deleted": 0, "error": "list_exception"}
    assert sb.writes() == []


@pytest.mark.asyncio
async def test_purge_audit_anonymise_timeout_is_best_effort(sb, fake_redis):
    from api.services.account_purge import purge_expired_accounts

    _purge_candidates(sb, "u-1")
    sb.on("PATCH", "/rest/v1/audit_log", exc=httpx.ReadTimeout("slow"))
    assert await purge_expired_accounts() == {"deleted": 1, "ids": ["u-1"]}


@pytest.mark.asyncio
async def test_purge_auth_delete_timeout_keeps_that_user_for_the_next_run(sb, fake_redis):
    from api.services.account_purge import purge_expired_accounts

    _purge_candidates(sb, "u-slow", "u-ok")
    sb.on("DELETE", "/auth/v1/admin/users/u-slow", exc=httpx.ReadTimeout("slow"))

    result = await purge_expired_accounts()

    assert result == {"deleted": 1, "ids": ["u-ok"], "skipped": ["u-slow"]}
    (delete,) = sb.to("DELETE", "/rest/v1/users")
    assert delete["params"]["id"] == "in.(u-ok)"
    assert [a["target_id"] for a in _hard_deleted_audits(sb)] == ["u-ok"]


@pytest.mark.asyncio
async def test_purge_final_delete_timeout_claims_nothing_and_next_run_finishes(sb, fake_redis):
    from api.services.account_purge import purge_expired_accounts

    _purge_candidates(sb, "u-1")
    sb.on("DELETE", "/rest/v1/users", exc=httpx.ReadTimeout("slow"))
    assert await purge_expired_accounts() == {"deleted": 0, "error": "delete_exception"}
    assert _hard_deleted_audits(sb) == []

    # Next run: the public row is still a candidate; its auth identity is
    # already gone (404 counts as done) and the purge completes.
    sb.on("DELETE", "/rest/v1/users", status=200, body=[{"id": "u-1"}])
    sb.on("DELETE", "/auth/v1/admin/users/u-1", status=404, body={"msg": "User not found"})
    assert await purge_expired_accounts() == {"deleted": 1, "ids": ["u-1"]}
    assert [a["target_id"] for a in _hard_deleted_audits(sb)] == ["u-1"]


@pytest.mark.asyncio
async def test_purge_recheck_timeout_keeps_the_user_and_touches_nothing(sb, fake_redis):
    from api.services.account_purge import purge_expired_accounts

    _purge_candidates(sb, "u-1")
    calls = {"n": 0}
    real = sb._handle

    def _second_users_get_times_out(method, url, params=None, json=None, headers=None):
        if method == "GET" and url.endswith("/rest/v1/users"):
            calls["n"] += 1
            if calls["n"] == 2:
                sb.calls.append({"method": method, "url": url, "params": dict(params or {})})
                raise httpx.ReadTimeout("slow")
        return real(method, url, params, json, headers)

    sb._handle = _second_users_get_times_out
    assert await purge_expired_accounts() == {"deleted": 0, "ids": [], "skipped": ["u-1"]}
    assert sb.writes() == []


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [b"<html>gateway</html>", {"id": "u-1"}])
async def test_purge_delete_answer_that_is_not_a_row_list_claims_nothing(sb, fake_redis, body):
    from api.services.account_purge import purge_expired_accounts

    _purge_candidates(sb, "u-1")
    sb.on("DELETE", "/rest/v1/users", status=200, body=body)
    result = await purge_expired_accounts()
    assert result == {"deleted": 0, "error": "delete_failed_200", "candidates": ["u-1"]}
    assert _hard_deleted_audits(sb) == []


@pytest.mark.asyncio
async def test_purge_where_every_row_was_restored_during_the_delete(sb, fake_redis):
    from api.services.account_purge import purge_expired_accounts

    _purge_candidates(sb, "u-1")
    sb.on("DELETE", "/rest/v1/users", status=200, body=[])
    assert await purge_expired_accounts() == {"deleted": 0, "ids": [], "restored": ["u-1"]}
    assert _hard_deleted_audits(sb) == []


@pytest.mark.asyncio
async def test_purge_audit_anonymise_rejection_is_best_effort(sb, fake_redis):
    from api.services.account_purge import purge_expired_accounts

    _purge_candidates(sb, "u-1")
    sb.on("PATCH", "/rest/v1/audit_log", status=500, body={"message": "boom"})
    assert await purge_expired_accounts() == {"deleted": 1, "ids": ["u-1"]}


@pytest.mark.parametrize("result, code", [({"deleted": 2, "ids": ["a", "b"]}, 0), ({"deleted": 0, "error": "x"}, 1)])
def test_purge_cli_exit_code(monkeypatch, capsys, result, code):
    from api.services import account_purge

    async def _purge():
        return result

    monkeypatch.setattr(account_purge, "purge_expired_accounts", _purge)
    assert account_purge.main() == code
    assert str(result["deleted"]) in capsys.readouterr().out


# ─── account devices ─────────────────────────────────────────────

INSTALL = "phone-install-hardening-01"


@pytest.mark.parametrize("raw, platform", [
    ("android", "android"), (" IOS ", "ios"), ("chrome", "extension"), ("safari_ext", "extension"),
    ("smart-fridge", "web"), ("", "web"), (None, "web"),
])
def test_legacy_platform_mapping(raw, platform):
    assert account_devices.legacy_platform(raw) == platform


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", [None, "", "short", "has space in it 1234", "x" * 129, "ünïcode-install-id-01"])
async def test_malformed_device_id_never_reaches_redis_or_the_store(account_store, redis_down, bad):
    account_store.fail = True  # would 503 if consulted
    assert await account_devices.is_revoked(ACCOUNT, bad, strict=True) is False


@pytest.mark.asyncio
async def test_unlink_with_redis_down_still_revokes_the_row(account_store, redis_down):
    row = account_store.add_device(ACCOUNT, INSTALL)
    device = await account_devices.revoke(account_id=ACCOUNT, device_row_id=row["id"])
    assert device["revoked_at"] is not None
    # Without the marker the row decides at the next request.
    assert await account_devices.is_revoked(ACCOUNT, INSTALL) is True


@pytest.mark.asyncio
async def test_unlink_of_a_row_without_install_id_writes_no_marker(account_store, fake_redis):
    row = account_store.add_device(ACCOUNT, None)
    await account_devices.revoke(account_id=ACCOUNT, device_row_id=row["id"])
    assert not [k for k in fake_redis._kv if k.startswith("revoked_device:")]


@pytest.mark.asyncio
async def test_store_errors_surface_as_unavailable(account_store, sb, monkeypatch):
    row = account_store.add_device(ACCOUNT, INSTALL)
    for name in ("list_devices", "register_device", "revoke_device", "rename_device"):
        async def _fail(*_a, **_k):
            raise AccountStoreError("simulated timeout")

        monkeypatch.setattr(account_store, name, _fail)

    with pytest.raises(account_devices.StoreUnavailable):
        await account_devices.list_devices(ACCOUNT)
    with pytest.raises(account_devices.StoreUnavailable):
        await account_devices.register(account_id=ACCOUNT, device_id=INSTALL, platform="ios", name=None,
                                       app_version=None, session_id=None)
    with pytest.raises(account_devices.StoreUnavailable):
        await account_devices.revoke(account_id=ACCOUNT, device_row_id=row["id"])
    with pytest.raises(account_devices.StoreUnavailable):
        await account_devices.rename(account_id=ACCOUNT, device_row_id=row["id"], name="Phone")


@pytest.mark.asyncio
async def test_unexpected_register_answer_is_unavailable_not_linked(account_store, sb, monkeypatch):
    async def _weird(**_kw):
        return {"status": "maybe"}

    monkeypatch.setattr(account_store, "register_device", _weird)
    with pytest.raises(account_devices.StoreUnavailable):
        await account_devices.register(account_id=ACCOUNT, device_id=INSTALL, platform="ios", name=None,
                                       app_version=None, session_id=None)


@pytest.mark.asyncio
async def test_register_drops_a_non_uuid_session_id(account_store, sb):
    status, _device, _ent = await account_devices.register(
        account_id=ACCOUNT, device_id=INSTALL, platform="ios", name="  Phone​ ",
        app_version="", session_id="not-a-uuid",
    )
    assert status == "created"
    assert account_store.register_calls[-1]["session_id"] is None
    assert account_store.devices[0]["app_version"] is None


@pytest.mark.asyncio
async def test_rename_validates_before_touching_the_store(account_store):
    account_store.fail = True
    with pytest.raises(ValueError):
        await account_devices.rename(account_id=ACCOUNT, device_row_id="00000000-0000-4000-8000-000000000001",
                                     name=" \t\n ")
    with pytest.raises(account_devices.DeviceNotFound):
        await account_devices.rename(account_id=ACCOUNT, device_row_id="../other-account", name="Phone")

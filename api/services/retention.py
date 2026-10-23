"""Server-side retention: delete what the privacy policy says we no longer keep.

What the policy promises (docs/PRIVACY.md "What we store, and for how long";
public policy section 16, landing.privacy_policy in packages/i18n-strings)
and what enforces it here:

  accounts            erased 30 days after a deletion request
                      → api/services/account_purge.purge_expired_accounts
  audit_log           2 years (730 days)          → audit_log_2y
  weekly_aggregates   1 year                      → weekly_aggregates_1y
  family_alerts       up to 30 days (expires_at)  → family_alerts_expired,
                      rows from before expires_at existed: 30 days after
                      created_at                  → family_alerts_legacy_30d
  family_invites      until redeemed or 7-day expiry
                      → family_invites_expired, family_invites_redeemed
                        (a day after redemption: the accept flow may roll
                        a redemption back within the same request)
  feedback_reports    1 year — a reported site's or sender's domain, the
                      kind of report, and the account ID if signed in
                      → feedback_reports_1y
  Supabase Auth's     2 years, like audit_log: the policy names no period
  sign-in log         for it (section 9: Supabase "may also record the IP
  (auth.audit_log_    address a sign-in came from in its own security
  entries)            log") → auth_audit_log_2y

Redis data carries its own TTLs and the nightly backups age out by the R2
lifecycle rule (35 days) — nothing to do here for those.

Every table rule is a filtered PostgREST DELETE with the server key —
idempotent, never without a filter. The auth schema is not exposed through
PostgREST, so auth_audit_log_2y calls migration 027's service-role-only
function instead (``purge_auth_audit_log``: POST deletes, the dry run's GET
only counts — PostgREST runs a GET READ ONLY). Until 027 is applied the rule
reports ``not_installed`` and the pass counts as failed. Modes (env
RETENTION_PURGE):

  off (default)  nothing runs;
  dry_run        counts what would be deleted and logs it, deletes nothing;
  on             deletes.

Scheduler: the API process itself (no pg_cron in the project, and the
GitHub workflows can't reach a job without an admin endpoint). When the mode
is not "off", api.main's lifespan starts ``retention_loop``: first pass
FIRST_RUN_DELAY_S after boot, then every INTERVAL_S; a Redis lock keeps two
replicas from running the same tick. Manual run:
``python -m api.services.retention [--dry-run]``.

Visible from outside: every pass leaves its time, mode and failures in Redis,
and /health/deep's `retention` component (``health_status``) shows the
configured mode and when a pass last succeeded — informational, never in
`warnings`.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal, Optional

from api.config import get_settings
from api.services import supabase_keys

logger = logging.getLogger("cleanway.retention")

Mode = Literal["off", "dry_run", "on"]

AUDIT_LOG_DAYS = 730
AUTH_AUDIT_LOG_DAYS = AUDIT_LOG_DAYS  # no period of its own in the policy
WEEKLY_AGGREGATES_DAYS = 365
FEEDBACK_REPORTS_DAYS = 365
FAMILY_ALERT_LEGACY_DAYS = 30  # == family.ALERT_DEFAULT_TTL_DAYS
REDEEMED_INVITE_KEEP_DAYS = 1

FIRST_RUN_DELAY_S: float = 15 * 60
INTERVAL_S: float = 6 * 3600
_LOCK_KEY = "retention:lock"
_LOCK_TTL_S = 30 * 60
_TIMEOUT_S = 30.0

_LAST_PASS_KEY = "retention:last_pass"
_LAST_OK_KEY = "retention:last_ok"
_STATUS_TTL_S = 30 * 86400
_REDIS_TIMEOUT_S = 1.0
# A pass that succeeded longer ago than this means the loop stopped: two
# missed intervals, plus the boot delay and a lock another replica held.
STALE_AFTER_S: float = FIRST_RUN_DELAY_S + 2 * INTERVAL_S + _LOCK_TTL_S


@dataclass(frozen=True)
class TableRule:
    name: str
    table: str
    params: Callable[[datetime], dict[str, str]]


def _iso(dt: datetime) -> str:
    return dt.isoformat()


TABLE_RULES: tuple[TableRule, ...] = (
    TableRule(
        "audit_log_2y",
        "audit_log",
        lambda now: {"created_at": f"lt.{_iso(now - timedelta(days=AUDIT_LOG_DAYS))}"},
    ),
    TableRule(
        "weekly_aggregates_1y",
        "weekly_aggregates",
        lambda now: {"week_start": f"lt.{(now - timedelta(days=WEEKLY_AGGREGATES_DAYS)).date().isoformat()}"},
    ),
    TableRule(
        "family_alerts_expired",
        "family_alerts",
        lambda now: {"expires_at": f"lt.{_iso(now)}"},
    ),
    TableRule(
        "family_alerts_legacy_30d",
        "family_alerts",
        lambda now: {
            "expires_at": "is.null",
            "created_at": f"lt.{_iso(now - timedelta(days=FAMILY_ALERT_LEGACY_DAYS))}",
        },
    ),
    TableRule(
        "family_invites_expired",
        "family_invites",
        lambda now: {"expires_at": f"lt.{_iso(now)}"},
    ),
    TableRule(
        "family_invites_redeemed",
        "family_invites",
        lambda now: {"redeemed_at": f"lt.{_iso(now - timedelta(days=REDEEMED_INVITE_KEEP_DAYS))}"},
    ),
    TableRule(
        "feedback_reports_1y",
        "feedback_reports",
        lambda now: {"created_at": f"lt.{_iso(now - timedelta(days=FEEDBACK_REPORTS_DAYS))}"},
    ),
)


def parse_mode(value: Any) -> Mode:
    """RETENTION_PURGE → mode. Anything unrecognised is "off": a typo must
    never start deleting."""
    v = (value if isinstance(value, str) else "").strip().lower().replace("-", "_")
    if v in ("on", "true", "1", "enabled"):
        return "on"
    if v in ("dry_run", "dryrun"):
        return "dry_run"
    return "off"


def _count(resp: Any) -> Optional[int]:
    """Total from PostgREST's Content-Range ("0-0/42", "*/7"); None if absent."""
    headers = getattr(resp, "headers", None) or {}
    raw = headers.get("Content-Range") or headers.get("content-range") or ""
    total = raw.rsplit("/", 1)[-1] if "/" in raw else ""
    return int(total) if total.isdigit() else None


async def _apply_rule(client: Any, base: str, rule: TableRule, mode: Mode, now: datetime) -> dict:
    params = rule.params(now)
    if not params:  # never a DELETE without a filter
        return {"error": "no_filter"}
    url = f"{base}/rest/v1/{rule.table}"
    try:
        if mode == "dry_run":
            resp = await client.request(
                "GET",
                url,
                params={**params, "select": "*", "limit": "1"},
                headers=supabase_keys.server_headers(None, Prefer="count=exact"),
            )
            if resp.status_code not in (200, 206):
                return {"error": f"status_{resp.status_code}"}
            return {"would_delete": _count(resp)}
        resp = await client.request(
            "DELETE",
            url,
            params=params,
            headers=supabase_keys.server_headers(None, Prefer="return=minimal,count=exact"),
        )
        if resp.status_code not in (200, 204):
            return {"error": f"status_{resp.status_code}"}
        return {"deleted": _count(resp)}
    except Exception as e:  # noqa: BLE001 — one table never stops the others
        return {"error": type(e).__name__}


AUTH_AUDIT_RULE = "auth_audit_log_2y"
AUTH_AUDIT_PURGE_FN = "purge_auth_audit_log"  # migration 027


def auth_audit_args(mode: Mode) -> dict[str, Any]:
    """purge_auth_audit_log's arguments: anything but "on" only counts."""
    return {"p_retention_days": AUTH_AUDIT_LOG_DAYS, "p_dry_run": mode != "on"}


def _rpc_count(resp: Any) -> Optional[int]:
    """The bigint a function answered with, or None."""
    try:
        value = resp.json()
    except Exception:  # noqa: BLE001 — a non-JSON answer proves nothing
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


async def _purge_auth_audit_log(client: Any, base: str, mode: Mode) -> dict:
    url = f"{base}/rest/v1/rpc/{AUTH_AUDIT_PURGE_FN}"
    args = auth_audit_args(mode)
    headers = supabase_keys.server_headers(None)
    try:
        if mode == "dry_run":
            resp = await client.request("GET", url, params=args, headers=headers)
        else:
            resp = await client.request("POST", url, json=args, headers=headers)
    except Exception as e:  # noqa: BLE001 — reported like a table
        return {"error": type(e).__name__}
    if resp.status_code == 404:  # PostgREST doesn't know the function
        return {"error": "not_installed"}
    if resp.status_code != 200:
        return {"error": f"status_{resp.status_code}"}
    n = _rpc_count(resp)
    if n is None:
        return {"error": "bad_response"}
    return {"would_delete" if mode == "dry_run" else "deleted": n}


def _accounts_failed(accounts: dict) -> bool:
    """The purge failed, or purged accounts kept their auth log entries."""
    return "error" in accounts or "auth_audit_log_error" in accounts


async def _count_account_candidates(client: Any, base: str, now: datetime) -> dict:
    from api.services.account_purge import GRACE_DAYS

    cutoff = _iso(now - timedelta(days=GRACE_DAYS))
    try:
        resp = await client.request(
            "GET",
            f"{base}/rest/v1/users",
            params={"deletion_requested_at": f"lte.{cutoff}", "select": "id", "limit": "1"},
            headers=supabase_keys.server_headers(None, Prefer="count=exact"),
        )
    except Exception as e:  # noqa: BLE001
        return {"error": type(e).__name__}
    if resp.status_code not in (200, 206):
        return {"error": f"status_{resp.status_code}"}
    return {"would_delete": _count(resp)}


async def run_retention(mode: Any, now: Optional[datetime] = None) -> dict:
    """One pass over every retention rule. Returns a summary (no personal
    data besides purged account ids, which account_purge already logs)."""
    m = parse_mode(mode)
    if m == "off":
        return {"mode": "off"}
    settings = get_settings()
    base = (settings.supabase_url or "").rstrip("/")
    if not base or not supabase_keys.server_key(settings):
        logger.warning("retention.supabase_not_configured")
        return {"mode": m, "skipped": "supabase_not_configured"}

    now = now or datetime.now(timezone.utc)
    import httpx

    from api.services import account_purge

    summary: dict = {"mode": m, "tables": {}}
    if m == "on":
        try:
            summary["accounts"] = await account_purge.purge_expired_accounts()
        except Exception as e:  # noqa: BLE001
            logger.error("retention.account_purge_failed", extra={"error": type(e).__name__})
            summary["accounts"] = {"error": type(e).__name__}

    async with httpx.AsyncClient(timeout=_TIMEOUT_S) as client:
        if m == "dry_run":
            summary["accounts"] = await _count_account_candidates(client, base, now)
        for rule in TABLE_RULES:
            summary["tables"][rule.name] = await _apply_rule(client, base, rule, m, now)
        summary["tables"][AUTH_AUDIT_RULE] = await _purge_auth_audit_log(client, base, m)

    failed = [name for name, r in summary["tables"].items() if "error" in r]
    accounts_failed = _accounts_failed(summary.get("accounts") or {})
    await _remember_pass(m, now, failed + (["accounts"] if accounts_failed else []))
    log = logger.error if failed else logger.info
    log(
        "retention.pass_complete",
        extra={
            "mode": m,
            "tables": summary["tables"],
            "accounts_deleted": (summary.get("accounts") or {}).get("deleted"),
            "accounts_would_delete": (summary.get("accounts") or {}).get("would_delete"),
            "failed": failed,
        },
    )
    return summary


# ── what /health/deep shows ───────────────────────────────────────────


async def _redis():
    from api.services.cache import get_redis

    return await get_redis()


async def _remember_pass(mode: Mode, now: datetime, failed: list[str]) -> None:
    """Store this pass for health_status (every replica reads the same keys).
    Never raises: Redis down must not fail a retention pass."""
    entry = json.dumps({"at": int(now.timestamp()), "mode": mode, "failed": failed})
    try:
        r = await _redis()
        await asyncio.wait_for(r.set(_LAST_PASS_KEY, entry, ex=_STATUS_TTL_S), _REDIS_TIMEOUT_S)
        if not failed:
            await asyncio.wait_for(r.set(_LAST_OK_KEY, entry, ex=_STATUS_TTL_S), _REDIS_TIMEOUT_S)
    except Exception as e:  # noqa: BLE001
        logger.warning("retention.status_not_recorded", extra={"error": type(e).__name__})


def _settings_mode() -> Mode:
    return parse_mode(getattr(get_settings(), "retention_purge", "off"))


def _load(raw: Any) -> Optional[dict]:
    try:
        value = json.loads(raw) if raw else None
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) and isinstance(value.get("at"), int) else None


def _iso_at(entry: Optional[dict]) -> Optional[str]:
    return datetime.fromtimestamp(entry["at"], tz=timezone.utc).isoformat() if entry else None


async def health_status(now: Optional[float] = None) -> dict:
    """The configured mode and the last passes. `ok` means "deleting on
    schedule": false while off (the published periods are not enforced), in
    dry_run (nothing is deleted), or when no pass succeeded within
    STALE_AFTER_S. No counts — /health/deep is public."""
    mode = _settings_mode()
    out: dict = {"mode": mode, "last_ok_at": None, "last_ok_mode": None,
                 "last_pass_at": None, "last_pass_failed": None}
    try:
        r = await _redis()
        last_pass = _load(await asyncio.wait_for(r.get(_LAST_PASS_KEY), _REDIS_TIMEOUT_S))
        last_ok = _load(await asyncio.wait_for(r.get(_LAST_OK_KEY), _REDIS_TIMEOUT_S))
    except Exception:  # noqa: BLE001 — reported, never raised
        return {**out, "ok": False, "error": "redis_unavailable"}
    out.update(
        last_ok_at=_iso_at(last_ok),
        last_ok_mode=last_ok.get("mode") if last_ok else None,
        last_pass_at=_iso_at(last_pass),
        last_pass_failed=last_pass.get("failed") if last_pass else None,
    )
    if mode != "on":
        return {**out, "ok": False, "error": mode}
    current = time.time() if now is None else now
    if last_ok and last_ok.get("mode") == "on" and current - last_ok["at"] <= STALE_AFTER_S:
        return {**out, "ok": True}
    return {**out, "ok": False, "error": "no_recent_pass"}


# ── background loop (started from api.main lifespan) ──────────────────

_task: Optional[asyncio.Task] = None


async def _acquire_lock() -> bool:
    """One replica per tick. Redis down → run anyway (every rule is
    idempotent, a double run only repeats a no-op)."""
    try:
        from api.services.cache import get_redis

        r = await get_redis()
        return bool(await r.set(_LOCK_KEY, "1", nx=True, ex=_LOCK_TTL_S))
    except Exception as e:  # noqa: BLE001
        logger.warning("retention.lock_unavailable", extra={"error": type(e).__name__})
        return True


async def retention_loop(mode: Mode) -> None:
    await asyncio.sleep(FIRST_RUN_DELAY_S)
    while True:
        try:
            if await _acquire_lock():
                await run_retention(mode)
        except asyncio.CancelledError:
            raise
        except Exception as e:  # noqa: BLE001 — the loop must survive a bad pass
            logger.error("retention.pass_crashed", extra={"error": type(e).__name__})
        await asyncio.sleep(INTERVAL_S)


def start_background() -> Optional[asyncio.Task]:
    """Start the loop if RETENTION_PURGE is dry_run / on. Returns the task."""
    global _task
    mode = _settings_mode()
    if mode == "off":
        return None
    if _task is None or _task.done():
        _task = asyncio.get_running_loop().create_task(retention_loop(mode))
        logger.info("retention.loop_started", extra={"mode": mode, "interval_s": INTERVAL_S})
    return _task


async def stop_background() -> None:
    global _task
    task, _task = _task, None
    if task is not None:
        task.cancel()
        await asyncio.wait({task}, timeout=1.0)


def main(argv: Optional[list[str]] = None) -> int:
    """CLI: ``python -m api.services.retention [--dry-run]``."""
    import json
    import sys

    args = sys.argv[1:] if argv is None else argv
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    mode: Mode = "dry_run" if "--dry-run" in args else "on"
    result = asyncio.run(run_retention(mode))
    print(json.dumps(result, default=str, indent=2))
    failed = any("error" in r for r in result.get("tables", {}).values())
    return 1 if failed or _accounts_failed(result.get("accounts") or {}) else 0


if __name__ == "__main__":
    import sys

    sys.exit(main())

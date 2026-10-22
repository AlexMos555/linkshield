"""Everything the server holds about one account — GDPR Art. 15 / 152-FZ
art. 14 (right of access).

Two ways in:
  * the person, signed in: GET /api/v1/user/export (api/routers/user.py),
    behind "Download my data" on cleanway.ai/account and in the app's
    Account screen;
  * the operator, for a request that arrives by email (the person can't
    sign in, or asks us to do it): ``python -m api.services.export --user
    <uuid|email> [--out file.json]`` in the API service's shell —
    docs/runbooks/data-requests.md.

Every table that holds the account id is read, filtered on that id and
nothing else. Left out on purpose: ciphertext of family alerts (useless
without the device's private key), the hashes of family invite codes and
PINs (secrets, not data about the person), an org's SSO configuration
(credentials of the organisation). Payment records held by Stripe are the
Stripe Customer Portal's (linked from the account page); the RevenueCat and
Supabase Auth records hold only the account id, email and the purchase
status already in `entitlements` / `users`.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from datetime import datetime, timezone
from typing import Any, Optional

from api.config import get_settings
from api.services import supabase_keys

logger = logging.getLogger("cleanway.export")

SCHEMA_VERSION = 2

# (key in the export, table, column holding the account id, columns).
EXPORT_TABLES: tuple[tuple[str, str, str, str], ...] = (
    ("users", "users", "id", "*"),
    ("subscriptions", "subscriptions", "user_id", "*"),
    ("entitlements", "entitlements", "account_id", "*"),
    ("user_settings", "user_settings", "user_id", "*"),
    ("devices", "devices", "user_id", "*"),
    ("weekly_aggregates", "weekly_aggregates", "user_id", "*"),
    ("rate_limits", "rate_limits", "user_id", "*"),
    # Verdicts of message checks (never the message itself).
    ("scam_analyses", "scam_analyses", "user_id", "*"),
    ("families", "families", "owner_id", "*"),
    ("family_members", "family_members", "user_id", "*"),
    ("family_member_keys", "family_member_keys", "user_id", "*"),
    ("family_invites", "family_invites", "inviter_id",
     "id,family_id,expires_at,redeemed_at,redeemed_by_user_id,created_at"),
    ("family_alerts", "family_alerts", "recipient_user_id",
     "id,family_id,sender_user_id,created_at,alert_type"),
    ("family_alerts_sent", "family_alerts", "sender_user_id",
     "id,family_id,recipient_user_id,created_at,alert_type"),
    ("orgs", "orgs", "admin_user_id", "id,name,admin_user_id,created_at"),
    ("org_members", "org_members", "user_id", "*"),
    ("brand_watchlist", "brand_watchlist", "user_id", "*"),
    ("sms_reports", "sms_reports", "reporter_user_id", "*"),
    ("feedback_reports", "feedback_reports", "user_id", "*"),
    # Rows where this account was the actor: a timeline of its privileged
    # actions (deletion requests, family invites, …). actor_ip_hash is
    # already a hash, not the IP.
    ("audit_log", "audit_log", "actor_user_id", "*"),
)

# Per-table row cap: five years of weekly rows or thousands of audit rows
# must not become a 100 MB download that times out, and a future filter bug
# must not read a whole table into memory.
EXPORT_ROW_CAP = 5000

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


class ExportUnavailable(Exception):
    """Supabase isn't configured, or the account couldn't be looked up."""


def _base() -> tuple[str, dict]:
    settings = get_settings()
    if not settings.supabase_url or not supabase_keys.server_key(settings):
        raise ExportUnavailable("Database not configured")
    return settings.supabase_url.rstrip("/"), supabase_keys.server_headers(settings)


async def build_export(user_id: str, email: Optional[str]) -> dict[str, Any]:
    """Read every table for `user_id`. A table that fails is marked with its
    error instead of failing the whole export (never shown as empty).
    Raises ExportUnavailable when Supabase isn't configured."""
    import httpx

    base, headers = _base()
    export: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "user_id": user_id,
        "email": email,
        "schema_version": SCHEMA_VERSION,
        "tables": {},
    }
    async with httpx.AsyncClient(timeout=10.0) as client:
        for key, table, column, select in EXPORT_TABLES:
            try:
                resp = await client.get(
                    f"{base}/rest/v1/{table}",
                    # No `order`: tables have different keys, and for an
                    # access request order carries no meaning.
                    params={column: f"eq.{user_id}", "select": select, "limit": str(EXPORT_ROW_CAP)},
                    headers=headers,
                )
                if resp.status_code == 200:
                    export["tables"][key] = resp.json()
                else:
                    export["tables"][key] = {"error": f"upstream returned {resp.status_code}"}
                    logger.warning(
                        "export_table_failed",
                        extra={"user_id": user_id, "table": key, "status": resp.status_code},
                    )
            except Exception as e:  # noqa: BLE001 — flagged per table
                export["tables"][key] = {"error": type(e).__name__}
                logger.warning(
                    "export_table_exception",
                    extra={"user_id": user_id, "table": key, "error": str(e)},
                )
    return export


async def find_account(identifier: str) -> Optional[dict]:
    """The users row ({id, email}) for an account id or an email address,
    or None. Raises ExportUnavailable when the lookup itself fails."""
    import httpx

    base, headers = _base()
    ident = identifier.strip()
    if _UUID.match(ident):
        params = {"id": f"eq.{ident.lower()}"}
    elif "@" in ident:
        # Supabase Auth stores emails lower-cased; users.email is copied
        # from it (migration 010).
        params = {"email": f"eq.{ident.lower()}"}
    else:
        raise ValueError("expected an account id (uuid) or an email address")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{base}/rest/v1/users",
                params={**params, "select": "id,email", "limit": "2"},
                headers=headers,
            )
    except Exception as e:  # noqa: BLE001
        raise ExportUnavailable(f"account lookup failed: {type(e).__name__}") from e
    if resp.status_code != 200:
        raise ExportUnavailable(f"account lookup returned {resp.status_code}")
    rows = resp.json()
    if not isinstance(rows, list) or len(rows) != 1:
        # id and email are both unique (001): anything but one row is "none".
        return None
    return rows[0]


def main(argv: Optional[list[str]] = None) -> int:
    """CLI: `python -m api.services.export --user <uuid|email> [--out f.json]`.
    Exit 0 written, 1 no such account, 2 database unavailable or bad input."""
    import asyncio

    parser = argparse.ArgumentParser(
        prog="python -m api.services.export",
        description="Print (or write) everything the server holds about one account, as JSON — "
        "the answer to an access request (docs/runbooks/data-requests.md).",
    )
    parser.add_argument("--user", required=True, help="account id (uuid) or email address")
    parser.add_argument("--out", help="write the JSON here instead of stdout")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, stream=sys.stderr)

    async def _run() -> int:
        try:
            account = await find_account(args.user)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if account is None:
            print("error: no account with that id or email", file=sys.stderr)
            return 1
        export = await build_export(str(account["id"]), account.get("email"))
        text = json.dumps(export, ensure_ascii=False, indent=2, default=str)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
            failed = [k for k, v in export["tables"].items() if isinstance(v, dict) and "error" in v]
            print(f"wrote {args.out} ({len(export['tables'])} tables; failed: {failed or 'none'})", file=sys.stderr)
        else:
            print(text)
        return 0

    try:
        return asyncio.run(_run())
    except ExportUnavailable as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

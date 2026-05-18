"""Hard-delete accounts whose 30-day grace window expired.

Privacy Policy §9 promises "All server-side data is permanently removed
within 30 days." The DELETE /api/v1/user/account endpoint sets
`users.deletion_requested_at = now()`. This module owns the second half
of the loop — periodically hard-deleting users whose timestamp is older
than the grace window.

The `users.id` foreign key cascades (declared since migration 001)
mean a single DELETE wipes every dependent row across:
  subscriptions, devices, user_settings, weekly_aggregates,
  family_members, family_alerts (where the user is a recipient), orgs,
  org_members, feedback_reports (user_id set to NULL by ON DELETE
  SET NULL), referrals.

This script is invokable two ways:
  1. CLI:   `python -m api.services.account_purge`
  2. HTTP:  the admin-token-gated endpoint defined in api/routers/admin.py
     (set ADMIN_PURGE_TOKEN env to use it; otherwise the endpoint 503s)

Cron'd hourly is plenty — grace is 30 DAYS, so the exact tick time of
the purge doesn't matter. A nightly run would also be fine.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from api.config import get_settings

logger = logging.getLogger("cleanway.account_purge")

# Must match _DELETION_GRACE_DAYS in api/routers/user.py.
GRACE_DAYS = 30


async def purge_expired_accounts() -> dict:
    """Find users whose deletion_requested_at <= now() - GRACE_DAYS and
    hard-delete them. Returns a summary dict for logging/observability.

    Idempotent — calling it twice on the same dataset is safe (second
    call finds zero candidates because the first DELETE wiped the rows).
    """
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        logger.warning("account_purge.supabase_not_configured")
        return {"deleted": 0, "skipped": "supabase_not_configured"}

    import httpx

    cutoff = (datetime.now(timezone.utc) - timedelta(days=GRACE_DAYS)).isoformat()
    headers = {
        "apikey": settings.supabase_service_key,
        "Authorization": f"Bearer {settings.supabase_service_key}",
    }

    # Step 1: list candidates for logging. We need to know WHO got
    # purged for the audit trail before they're gone.
    deleted_ids: list[str] = []
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            list_resp = await client.get(
                f"{settings.supabase_url}/rest/v1/users",
                params={
                    "deletion_requested_at": f"lte.{cutoff}",
                    "select": "id",
                },
                headers=headers,
            )
            if list_resp.status_code != 200:
                logger.error(
                    "account_purge.list_failed",
                    extra={"status": list_resp.status_code},
                )
                return {"deleted": 0, "error": f"list_failed_{list_resp.status_code}"}
            deleted_ids = [row["id"] for row in list_resp.json()]
        except Exception as e:
            logger.error("account_purge.list_exception", extra={"error": str(e)})
            return {"deleted": 0, "error": "list_exception"}

        if not deleted_ids:
            logger.info("account_purge.no_candidates", extra={"cutoff": cutoff})
            return {"deleted": 0}

        # Step 2: hard-delete. We rely on the cascading foreign keys
        # established in migration 001 — a single DELETE on users.id
        # wipes every dependent row across 8+ tables.
        try:
            del_resp = await client.request(
                "DELETE",
                f"{settings.supabase_url}/rest/v1/users",
                params={"deletion_requested_at": f"lte.{cutoff}"},
                headers=headers,
            )
            if del_resp.status_code not in (200, 204):
                logger.error(
                    "account_purge.delete_failed",
                    extra={
                        "status": del_resp.status_code,
                        "candidates": len(deleted_ids),
                    },
                )
                return {
                    "deleted": 0,
                    "error": f"delete_failed_{del_resp.status_code}",
                    "candidates": deleted_ids,
                }
        except Exception as e:
            logger.error("account_purge.delete_exception", extra={"error": str(e)})
            return {"deleted": 0, "error": "delete_exception"}

    logger.info(
        "account_purge.complete",
        extra={"deleted": len(deleted_ids), "ids": deleted_ids, "cutoff": cutoff},
    )

    # Write one audit row per deleted user. audit_log.actor_user_id is
    # NULL (system event — the cron, not a human, fired this). The
    # row's target_id pins which user got purged + when, which is
    # exactly what a compliance review needs after the fact (the
    # users.id row itself is gone forever now). audit_log rows do NOT
    # cascade on users.id — see migration 014.
    from api.services import audit_log
    for uid in deleted_ids:
        await audit_log.write(
            action="account.hard_deleted",
            target_kind="user",
            target_id=uid,
            actor_user_id=None,  # system / cron
            meta={"grace_days": GRACE_DAYS, "cutoff": cutoff},
        )

    return {"deleted": len(deleted_ids), "ids": deleted_ids}


def main() -> int:
    """CLI entry: `python -m api.services.account_purge`."""
    import asyncio

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    result = asyncio.run(purge_expired_accounts())
    print(result)
    return 0 if "error" not in result else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())

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

public.users has NO foreign key to auth.users, so that cascade never
touched the Supabase Auth identity (email, provider identities,
sessions). Each user's auth record is deleted explicitly through the
Auth Admin API (DELETE /auth/v1/admin/users/{id}), which also cascades
the tables keyed on auth.users (brand_watchlist, …). Before anything is
deleted, any still-live Stripe subscription is cancelled; a user whose
billing can't be stopped, or whose auth record can't be deleted, is
skipped and retried on the next run.

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
from api.services.stripe_billing import BillingError, cancel_user_subscriptions

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

        candidate_ids = deleted_ids
        deleted_ids = []
        skipped_ids: list[str] = []
        for uid in candidate_ids:
            # Step 1.4: stop Stripe billing. The subscriptions row (with
            # the Stripe customer id) is wiped by the cascade below; after
            # that nothing links the user to a still-live subscription and
            # it would bill forever. DELETE /user/account already cancels
            # at request time — this is the safety net. Can't confirm →
            # keep the user and retry next run.
            try:
                await cancel_user_subscriptions(uid)
            except BillingError as e:
                logger.error(
                    "account_purge.stripe_cancel_failed",
                    extra={"user_id": uid, "error": str(e)},
                )
                skipped_ids.append(uid)
                continue

            # Step 1.5: GDPR Art. 17 — anonymise audit_log rows BEFORE the
            # cascade DELETE.
            #
            # audit_log.actor_user_id has no FK cascade (see migration 014),
            # so historical rows would otherwise persist with the deleted
            # user's UUID forever. The compliance-friendly answer: keep the
            # event timeline (the action verb + timestamp + meta), null the
            # actor so the row is no longer personal data tied to the user.
            # (Audit backend MEDIUM "audit_log table has no retention
            # policy or row cap, and the GDPR purge cron is not wired to
            # clean it".)
            try:
                anon_resp = await client.request(
                    "PATCH",
                    f"{settings.supabase_url}/rest/v1/audit_log",
                    params={"actor_user_id": f"eq.{uid}"},
                    json={"actor_user_id": None},
                    headers={**headers, "Prefer": "return=minimal"},
                )
                if anon_resp.status_code not in (200, 204):
                    logger.warning(
                        "account_purge.audit_anonymise_failed",
                        extra={
                            "user_id": uid,
                            "status": anon_resp.status_code,
                        },
                    )
            except Exception as e:
                logger.warning(
                    "account_purge.audit_anonymise_exception",
                    extra={"user_id": uid, "error": str(e)},
                )

            # Step 1.6: delete the Supabase Auth identity (auth.users —
            # email, provider identities, sessions, refresh tokens).
            # public.users.id has no FK to auth.users, so the cascade
            # below never reached it: the identity outlived the purge and
            # the person could still sign in. Done BEFORE the public row:
            # if this fails the public row keeps the user a candidate for
            # the next run; 404 means a previous run already did it.
            try:
                auth_resp = await client.request(
                    "DELETE",
                    f"{settings.supabase_url}/auth/v1/admin/users/{uid}",
                    headers=headers,
                )
                auth_ok = auth_resp.status_code in (200, 204, 404)
            except Exception as e:
                logger.error(
                    "account_purge.auth_delete_exception",
                    extra={"user_id": uid, "error": str(e)},
                )
                auth_ok = False
            if not auth_ok:
                logger.error("account_purge.auth_delete_failed", extra={"user_id": uid})
                skipped_ids.append(uid)
                continue

            deleted_ids.append(uid)

        if not deleted_ids:
            return {"deleted": 0, "ids": [], "skipped": skipped_ids}

        # Step 2: hard-delete. We rely on the cascading foreign keys
        # established in migration 001 — a single DELETE on users.id
        # wipes every dependent row across 8+ tables. Restricted to the
        # users that cleared every step above, AND still to the grace
        # cutoff so a bad id list can never reach a user inside grace.
        try:
            del_resp = await client.request(
                "DELETE",
                f"{settings.supabase_url}/rest/v1/users",
                params={
                    "id": f"in.({','.join(deleted_ids)})",
                    "deletion_requested_at": f"lte.{cutoff}",
                },
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
        extra={
            "deleted": len(deleted_ids),
            "ids": deleted_ids,
            "skipped": skipped_ids,
            "cutoff": cutoff,
        },
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

    result: dict = {"deleted": len(deleted_ids), "ids": deleted_ids}
    if skipped_ids:
        result["skipped"] = skipped_ids
    return result


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

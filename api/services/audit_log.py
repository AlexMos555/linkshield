"""Append-only audit log writes for compliance.

Use this whenever a privileged or money-relevant action happens:

  - Account: delete request, restore, hard-purge
  - Subscription: tier change, status change
  - Family Hub: invite created, accepted, member removed
  - Org: member added, role changed, simulation triggered
  - Admin / support tooling (when we add it)

Calling code is intentionally fire-and-forget — audit writes must
NEVER block or fail the user-facing operation. Each call wraps the
HTTP request in a try/except and silently absorbs network errors;
the worst-case outcome is a missing audit row, which is recoverable
(Stripe / Supabase data is still authoritative for state).

The audit_log table is RLS-locked to service_role only — see
supabase/migrations/014_audit_log.sql. The /api/v1/user/export
endpoint queries it server-side filtered by actor_user_id.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any, Optional

from api.config import get_settings

logger = logging.getLogger("cleanway.audit_log")


def _hash_ip(ip: Optional[str]) -> Optional[str]:
    """SHA-256 the raw IP so a leaked audit table can't be used to
    deanonymise users. Truncated to 16 hex chars (64 bits) — enough
    for correlating events from the same source IP within a small
    user base, not enough to brute-force back to the address."""
    if not ip:
        return None
    return hashlib.sha256(ip.encode("utf-8")).hexdigest()[:16]


async def write(
    *,
    action: str,
    target_kind: str,
    target_id: str,
    actor_user_id: Optional[str] = None,
    meta: Optional[dict[str, Any]] = None,
    actor_ip: Optional[str] = None,
) -> None:
    """Insert one audit row. Silent on failure (best-effort).

    `action` is a dotted-verb string like `"account.delete_requested"`.
    `target_kind` is the entity class: `"user"`, `"subscription"`,
    `"family"`, `"org"`, etc. `target_id` is the entity's primary key
    serialised as a string.

    Examples:
        await audit_log.write(
            action="account.delete_requested",
            target_kind="user",
            target_id=user.id,
            actor_user_id=user.id,
            actor_ip=client_ip,
        )

        await audit_log.write(
            action="subscription.tier_changed",
            target_kind="subscription",
            target_id=stripe_subscription_id,
            actor_user_id=None,  # system event from Stripe
            meta={"from_tier": "personal", "to_tier": "family"},
        )
    """
    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        # Without Supabase wired we can't write the row. Log so a
        # developer running locally sees the trace, but never raise.
        logger.debug(
            "audit_log.skipped_unconfigured",
            extra={"action": action, "target_kind": target_kind, "target_id": target_id},
        )
        return

    import httpx

    body = {
        "actor_user_id": actor_user_id,
        "target_kind": target_kind,
        "target_id": target_id,
        "action": action,
        "meta": meta or {},
        "actor_ip_hash": _hash_ip(actor_ip),
    }

    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.post(
                f"{settings.supabase_url}/rest/v1/audit_log",
                headers={
                    "apikey": settings.supabase_service_key,
                    "Authorization": f"Bearer {settings.supabase_service_key}",
                    "Content-Type": "application/json",
                    "Prefer": "return=minimal",
                },
                json=body,
            )
            if resp.status_code not in (200, 201, 204):
                logger.warning(
                    "audit_log.write_failed",
                    extra={
                        "status": resp.status_code,
                        "action": action,
                        "target_kind": target_kind,
                    },
                )
    except Exception as e:
        # Fire-and-forget — audit writes must never block. Worst case
        # is a missing row, which the operator can backfill from the
        # structured logs (Sentry breadcrumb / Railway log stream).
        logger.warning(
            "audit_log.write_exception",
            extra={"error": str(e), "action": action},
        )

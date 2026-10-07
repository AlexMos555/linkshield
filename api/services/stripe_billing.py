"""Stripe billing helpers shared by the payments router, account deletion
and the GDPR purge job.

Everything here is about ONE question: "which Stripe customer / which
Stripe subscription belongs to this Cleanway user, and what do we do
with it?" The answers live in our `subscriptions` row (one per user,
migration 013) — `provider_subscription_id` since migration 001 and
`stripe_customer_id` + `trial_used_at` since migration 021.

Error policy: every helper RAISES `BillingError` when Supabase or
Stripe can't be reached / answers non-2xx. Callers decide what that
means (webhook → 5xx so Stripe retries; checkout → 503; account
deletion → 503 without deleting). Nothing on the billing path may
swallow a failure and carry on as if it succeeded — that is how a
paid event got lost forever before (see the webhook docstring).
"""
from __future__ import annotations

import logging
from typing import Any, Optional

from api.config import get_settings

logger = logging.getLogger("cleanway.stripe_billing")

# Our subscriptions.status values that still grant the paid tier
# (mirrors the resolver in api/services/auth.py::_fetch_tier_from_supabase).
PAID_STATUSES = frozenset({"active", "past_due"})

# Stripe subscription statuses that can still produce a charge (or
# already grant access). Cancelling one of these stops all future
# invoices; `canceled` and `incomplete_expired` are terminal.
LIVE_STRIPE_STATUSES = frozenset(
    {"active", "trialing", "past_due", "unpaid", "incomplete", "paused"}
)

_ROW_COLUMNS = (
    "user_id,tier,status,provider,provider_subscription_id,"
    "stripe_customer_id,trial_used_at"
)


class BillingError(Exception):
    """Supabase or Stripe failed on the billing path. Never swallow."""


def field(obj: Any, key: str) -> Any:
    """Read `key` from a Stripe object or a plain dict (tests) alike.

    StripeObject subclasses dict in stripe-python, so `.get` works on
    both; anything else (None, a bare id string) yields None."""
    if isinstance(obj, dict):
        return obj.get(key)
    return None


def object_id(value: Any) -> Optional[str]:
    """Stripe fields like `customer` / `latest_invoice` are either an id
    string or (when expanded) an object carrying `id`."""
    if isinstance(value, str):
        return value or None
    return field(value, "id")


def _supabase_headers() -> dict[str, str]:
    settings = get_settings()
    return {
        "apikey": settings.supabase_service_key,
        "Authorization": f"Bearer {settings.supabase_service_key}",
    }


def supabase_configured() -> bool:
    settings = get_settings()
    return bool(settings.supabase_url and settings.supabase_service_key)


async def fetch_subscription_row(
    *,
    user_id: Optional[str] = None,
    subscription_id: Optional[str] = None,
    customer_id: Optional[str] = None,
) -> Optional[dict]:
    """Return the subscriptions row matching exactly one filter, or None.

    Returns None (no row) when Supabase isn't configured — local dev
    without a database behaves like "nobody has a subscription", the
    same default the tier resolver uses. Raises BillingError on any
    upstream failure so the caller can't mistake "DB down" for "free".
    """
    filters = {
        "user_id": user_id,
        "provider_subscription_id": subscription_id,
        "stripe_customer_id": customer_id,
    }
    chosen = {k: v for k, v in filters.items() if v}
    if len(chosen) != 1:
        raise ValueError("fetch_subscription_row needs exactly one filter")
    if not supabase_configured():
        return None

    import httpx

    column, value = next(iter(chosen.items()))
    settings = get_settings()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{settings.supabase_url}/rest/v1/subscriptions",
                params={column: f"eq.{value}", "select": _ROW_COLUMNS, "limit": "1"},
                headers=_supabase_headers(),
            )
    except Exception as e:
        raise BillingError(f"subscription lookup failed: {e}") from e
    if resp.status_code != 200:
        raise BillingError(f"subscription lookup returned {resp.status_code}")
    rows = resp.json() or []
    return rows[0] if rows else None


def has_paid_subscription(row: Optional[dict]) -> bool:
    """True when the row grants a paid tier right now. Every user has a
    row (migration 010 seeds tier='free', status='active'), so status
    alone means nothing — the tier must be paid too."""
    if not row:
        return False
    return row.get("tier") not in (None, "", "free") and row.get("status") in PAID_STATUSES


def trial_available(row: Optional[dict]) -> bool:
    """The 14-day trial is offered once per user. `trial_used_at` is the
    record; a row that ever carried a provider subscription predates the
    column (migration 021 backfills it, this is belt and braces)."""
    if not row:
        return True
    return not row.get("trial_used_at") and not row.get("provider_subscription_id")


def stripe_client():
    """Configured `stripe` module, or BillingError when there's no key."""
    settings = get_settings()
    key = getattr(settings, "stripe_secret_key", "")
    if not key:
        raise BillingError("stripe_not_configured")
    import stripe

    stripe.api_key = key
    return stripe


async def resolve_customer_id(row: Optional[dict]) -> Optional[str]:
    """Stripe customer for this row: the stored id, else (rows written
    before migration 021) the customer of the stored subscription.
    Never searches by email — emails are not unique in Stripe and the
    first match may be someone else's customer."""
    if not row:
        return None
    if row.get("stripe_customer_id"):
        return row["stripe_customer_id"]
    sub_id = row.get("provider_subscription_id")
    if row.get("provider", "stripe") != "stripe" or not sub_id:
        return None
    stripe = stripe_client()
    try:
        sub = await stripe.Subscription.retrieve_async(sub_id)
    except Exception as e:
        raise BillingError(f"subscription retrieve failed: {e}") from e
    return object_id(field(sub, "customer"))


async def store_customer_id(user_id: str, customer_id: str) -> None:
    """Persist a customer id we had to derive (legacy rows). Best-effort:
    the next call derives it again if this write is lost."""
    if not supabase_configured():
        return
    import httpx

    settings = get_settings()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            await client.patch(
                f"{settings.supabase_url}/rest/v1/subscriptions",
                params={"user_id": f"eq.{user_id}"},
                json={"stripe_customer_id": customer_id},
                headers={**_supabase_headers(), "Content-Type": "application/json",
                         "Prefer": "return=minimal"},
            )
    except Exception as e:
        logger.warning("stripe_customer_id_store_failed", extra={"user_id": user_id, "error": str(e)})


async def cancel_subscription_now(subscription_id: str, *, known_live: bool = False) -> bool:
    """Cancel one Stripe subscription immediately — no proration credit,
    no final invoice, so nothing further is ever charged. Returns False
    when it was already in a terminal state (idempotent for retries)."""
    stripe = stripe_client()
    try:
        if not known_live:
            sub = await stripe.Subscription.retrieve_async(subscription_id)
            if field(sub, "status") not in LIVE_STRIPE_STATUSES:
                return False
        await stripe.Subscription.cancel_async(
            subscription_id, prorate=False, invoice_now=False
        )
    except Exception as e:
        raise BillingError(f"subscription cancel failed: {e}") from e
    return True


async def cancel_user_subscriptions(user_id: str) -> list[str]:
    """Immediately cancel every live Stripe subscription of this user.

    Looks at the customer's whole subscription list, not just the id on
    our row: a user who completed two Checkout sessions has two live
    subscriptions and only the last one is on the row. Returns the ids
    that were cancelled ([] when the user never paid through Stripe).
    """
    row = await fetch_subscription_row(user_id=user_id)
    if not row:
        return []
    sub_id = row.get("provider_subscription_id") if row.get("provider", "stripe") == "stripe" else None
    if not row.get("stripe_customer_id") and not sub_id:
        return []

    customer_id = await resolve_customer_id(row)
    stripe = stripe_client()
    live: list[str] = []
    known_live = False
    if customer_id:
        try:
            listing = await stripe.Subscription.list_async(
                customer=customer_id, status="all", limit=100
            )
        except Exception as e:
            raise BillingError(f"subscription list failed: {e}") from e
        live = [
            s["id"] for s in (field(listing, "data") or [])
            if field(s, "status") in LIVE_STRIPE_STATUSES
        ]
        known_live = True
    elif sub_id:
        live = [sub_id]

    cancelled: list[str] = []
    for sid in live:
        if await cancel_subscription_now(sid, known_live=known_live):
            cancelled.append(sid)
    if cancelled:
        logger.info(
            "stripe_subscriptions_cancelled",
            extra={"user_id": user_id, "subscription_ids": cancelled},
        )
    return cancelled

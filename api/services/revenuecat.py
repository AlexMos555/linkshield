"""Google Play / App Store purchases (through RevenueCat) → `entitlements`.

docs/ACCOUNTS_BILLING_PLAN.md §11, docs/runbooks/revenuecat.md. The app
logs in to RevenueCat with our Supabase account id, so a webhook event's
`app_user_id` IS the account. Event names and fields follow RevenueCat's
reference (checked 2026-10-08):
https://www.revenuecat.com/docs/integrations/webhooks/event-types-and-fields

One row per purchase: source google_play / app_store (from `store`),
external_id = `original_transaction_id` (stable across renewals), plan and
device_limit from the product (api/services/store_products.py), period_end
= `expiration_at_ms`. What each event does:

  INITIAL_PURCHASE, RENEWAL, UNCANCELLATION, SUBSCRIPTION_EXTENDED,
  REFUND_REVERSED       → active (trialing while period_type = TRIAL)
  CANCELLATION          → cancel_reason CUSTOMER_SUPPORT is a refund:
                          refunded, access ends now. BILLING_ERROR: past_due.
                          Anything else (UNSUBSCRIBE…): stays active until
                          expiration_at_ms — the period is paid.
  BILLING_ISSUE         → past_due until the store's grace period ends
  EXPIRATION            → expired (paused when the reason is SUBSCRIPTION_PAUSED)
  SUBSCRIPTION_PAUSED   → nothing yet: the pause starts at the period end and
                          RevenueCat says to revoke only on EXPIRATION
  PRODUCT_CHANGE        → noted; the new product applies with the RENEWAL /
                          INITIAL_PURCHASE that carries it ("may not take
                          effect immediately")
  TRANSFER              → the store rows of `transferred_from` accounts move
                          to the `transferred_to` account, then it is synced
  TEST and everything else → acknowledged, nothing written

Events are applied in time order per row: an event older than the row's
`source_event_at` (a retried delivery overtaken by a newer event) is skipped.
"""
from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional

from api.config import get_settings
from api.services import account_store, store_products
from api.services.account_store import AccountStoreError
from api.services.entitlements import (
    ADDON_PLAN,
    EntitlementError,
    get_effective_entitlement,
    included_devices,
    record_entitlement,
)

logger = logging.getLogger("cleanway.revenuecat")

ANONYMOUS_PREFIX = "$RCAnonymousID:"

# Webhook `store` → entitlements.source. STRIPE / RC_BILLING / PADDLE are
# NOT taken from RevenueCat: Stripe writes its own rows (payments.py), and a
# second writer would double-count the same purchase.
WEBHOOK_STORES = {"PLAY_STORE": "google_play", "APP_STORE": "app_store", "MAC_APP_STORE": "app_store"}
STORE_SOURCES = ("google_play", "app_store")

ACTIVATING = frozenset(
    {"INITIAL_PURCHASE", "RENEWAL", "UNCANCELLATION", "SUBSCRIPTION_EXTENDED", "REFUND_REVERSED"}
)
WRITING = ACTIVATING | {"CANCELLATION", "BILLING_ISSUE", "EXPIRATION"}
NOTED = frozenset({"PRODUCT_CHANGE", "SUBSCRIPTION_PAUSED"})

# A Play renewal's order id is the original's plus "..N".
_PLAY_RENEWAL_SUFFIX = re.compile(r"\.\.\d+$")


class RevenueCatError(Exception):
    """A write or a RevenueCat API call failed — the caller answers 5xx."""


class RevenueCatNotConfigured(RevenueCatError):
    """REVENUECAT_SECRET_API_KEY is not set."""


@dataclass(frozen=True)
class Outcome:
    # applied | noted | ignored | stale
    result: str
    reason: str = ""
    account_id: Optional[str] = None


# ── helpers ──


def _ms_to_iso(ms: Any) -> Optional[str]:
    try:
        return datetime.fromtimestamp(int(ms) / 1000, tz=timezone.utc).isoformat() if ms else None
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def parse_ts(value: Any) -> Optional[datetime]:
    if not value or not isinstance(value, str):
        return None
    try:
        ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)


def account_id_from(value: Any) -> Optional[str]:
    """Our account id (a UUID) from a RevenueCat App User ID, or None for
    an anonymous ($RCAnonymousID:…) or foreign id."""
    if not isinstance(value, str) or not value or value.startswith(ANONYMOUS_PREFIX):
        return None
    try:
        return str(uuid.UUID(value))
    except ValueError:
        return None


def resolve_account(event: dict) -> Optional[str]:
    """app_user_id first, then original_app_user_id and the aliases
    (RevenueCat: "search both")."""
    candidates = [event.get("app_user_id"), event.get("original_app_user_id")]
    candidates += list(event.get("aliases") or [])
    for value in candidates:
        account = account_id_from(value)
        if account:
            return account
    return None


def original_purchase_id(source: str, transaction_id: Optional[str]) -> Optional[str]:
    if not transaction_id:
        return None
    if source == "google_play":
        return _PLAY_RENEWAL_SUFFIX.sub("", transaction_id)
    return transaction_id


def plan_fields(product: store_products.StoreProduct) -> tuple[str, int]:
    if product.is_addon:
        return ADDON_PLAN, product.extra_devices
    return str(product.plan), included_devices() + product.extra_devices


def sandbox_accepted() -> bool:
    return bool(get_settings().revenuecat_accept_sandbox)


async def invalidate_tier_cache(account_id: str) -> None:
    try:
        from api.services.cache import get_redis

        r = await get_redis()
        await r.delete(f"tier:{account_id}")
    except Exception:
        pass  # the cache expires on its own in 5 minutes


async def _audit(action: str, account_id: Optional[str], target_id: str, meta: dict) -> None:
    from api.services import audit_log

    await audit_log.write(
        action=action, target_kind="subscription", target_id=target_id,
        actor_user_id=account_id, meta=meta,
    )


def require_store():
    store = account_store.get_account_store()
    if store is None:
        raise RevenueCatError("account store not configured")
    return store


# ── webhook events ──


def _event_status(event_type: str, event: dict) -> tuple[str, Optional[str]]:
    """(entitlement status, period_end) for a writing event."""
    period_end = _ms_to_iso(event.get("expiration_at_ms"))
    trial = event.get("period_type") == "TRIAL"
    if event_type in ACTIVATING:
        end = parse_ts(period_end)
        if event_type == "REFUND_REVERSED" and end and end <= datetime.now(timezone.utc):
            return "expired", period_end
        return ("trialing" if trial else "active"), period_end
    if event_type == "CANCELLATION":
        reason = event.get("cancel_reason")
        if reason == "CUSTOMER_SUPPORT":
            return "refunded", period_end
        if reason == "BILLING_ERROR":
            return "past_due", period_end
        return ("trialing" if trial else "active"), period_end
    if event_type == "BILLING_ISSUE":
        grace = _ms_to_iso(event.get("grace_period_expiration_at_ms"))
        ends = [t for t in (period_end, grace) if t]
        return "past_due", max(ends, key=lambda t: parse_ts(t)) if ends else None
    # EXPIRATION
    return ("paused" if event.get("expiration_reason") == "SUBSCRIPTION_PAUSED" else "expired"), period_end


async def _flag_double_payment(account_id: str, source: str, external_id: str) -> None:
    """A store purchase on an account that already pays another way. The
    store sold it and we can't refuse it — flag it for a refund."""
    try:
        current = await get_effective_entitlement(account_id)
    except EntitlementError as e:
        logger.warning("revenuecat_double_payment_check_failed", extra={"error": str(e)})
        return
    if current.is_paid and (current.source, current.external_id) != (source, external_id):
        logger.error(
            "subscription_duplicate_detected",
            extra={"account_id": account_id, "existing_source": current.source, "new_source": source},
        )
        await _audit(
            "subscription.duplicate_detected", account_id, external_id,
            {"existing_source": current.source, "existing_id": current.external_id,
             "new_source": source, "new_id": external_id},
        )


async def apply_event(event: dict) -> Outcome:
    """Apply one webhook event. Raises RevenueCatError when a write fails."""
    event_type = str(event.get("type") or "")
    if event_type == "TRANSFER":
        return await _apply_transfer(event)
    if event_type in NOTED:
        logger.info("revenuecat_event_noted", extra={"type": event_type, "product_id": event.get("product_id"),
                                                     "new_product_id": event.get("new_product_id")})
        return Outcome("noted", event_type.lower())
    if event_type not in WRITING:
        return Outcome("ignored", "event_type")

    source = WEBHOOK_STORES.get(str(event.get("store") or ""))
    if source is None:
        logger.info("revenuecat_store_ignored", extra={"store": event.get("store"), "type": event_type})
        return Outcome("ignored", "store")
    if event.get("environment") == "SANDBOX" and not sandbox_accepted():
        return Outcome("ignored", "sandbox")

    account_id = resolve_account(event)
    if account_id is None:
        # A purchase made before the app logged in to RevenueCat with our
        # account id. Nobody to give it to: alert, and let the app's
        # "Restore purchases" (after sign-in) move it with a TRANSFER.
        logger.error("revenuecat_purchase_without_account",
                     extra={"type": event_type, "store": event.get("store"), "event_id": event.get("id")})
        return Outcome("ignored", "anonymous")

    product_id = event.get("product_id")
    product = store_products.lookup(product_id)
    if product is None:
        logger.error("revenuecat_unknown_product", extra={"product_id": product_id, "account_id": account_id})
        await _audit("subscription.store_unknown_product", account_id, str(event.get("id") or ""),
                     {"product_id": product_id, "store": event.get("store"), "type": event_type})
        return Outcome("ignored", "unknown_product", account_id)

    external_id = original_purchase_id(
        source, event.get("original_transaction_id") or event.get("transaction_id")
    )
    if not external_id:
        logger.error("revenuecat_event_without_transaction", extra={"event_id": event.get("id")})
        return Outcome("ignored", "no_transaction_id", account_id)

    store = require_store()
    event_at = _ms_to_iso(event.get("event_timestamp_ms")) or datetime.now(timezone.utc).isoformat()
    try:
        existing = await store.get_entitlement(source=source, external_id=external_id)
    except AccountStoreError as e:
        raise RevenueCatError(str(e)) from e
    seen_at = parse_ts((existing or {}).get("source_event_at"))
    if seen_at and parse_ts(event_at) and parse_ts(event_at) < seen_at:
        logger.info("revenuecat_event_stale", extra={"type": event_type, "external_id": external_id})
        return Outcome("stale", "older_than_row", account_id)
    if existing and existing.get("account_id") not in (None, account_id):
        logger.warning("revenuecat_purchase_moved_account", extra={"external_id": external_id})

    status, period_end = _event_status(event_type, event)
    plan, device_limit = plan_fields(product)
    if event_type == "INITIAL_PURCHASE" and not product.is_addon:
        await _flag_double_payment(account_id, source, external_id)
    try:
        await record_entitlement(
            account_id=account_id, source=source, external_id=external_id, status=status,
            plan=plan, period_end=period_end, device_limit=device_limit,
            product_id=str(product_id), source_event_at=event_at,
        )
    except EntitlementError as e:
        raise RevenueCatError(str(e)) from e
    await invalidate_tier_cache(account_id)
    await _audit(
        "subscription.store_event", account_id, external_id,
        {"type": event_type, "source": source, "status": status, "product_id": product_id,
         "cancel_reason": event.get("cancel_reason"), "expiration_reason": event.get("expiration_reason"),
         "environment": event.get("environment")},
    )
    return Outcome("applied", status, account_id)


async def _apply_transfer(event: dict) -> Outcome:
    """Purchases moved between App User IDs (e.g. "Restore purchases" on a
    phone signed in to another account). The event names the accounts but
    not the purchases, so:

      * with REVENUECAT_SECRET_API_KEY: sync the destination, then every
        source account, from RevenueCat — exact, and it also picks up
        purchases made anonymously (they had no row anywhere);
      * without it: move every google_play / app_store row of the source
        accounts to the destination (a store account usually belongs to one
        person) and log that a sync is needed.
    """
    destinations = [a for a in (account_id_from(v) for v in event.get("transferred_to") or []) if a]
    if not destinations:
        logger.error("revenuecat_transfer_without_account", extra={"event_id": event.get("id")})
        return Outcome("ignored", "anonymous")
    to_account = destinations[0]
    from_accounts = [
        a for a in (account_id_from(v) for v in event.get("transferred_from") or []) if a and a != to_account
    ]

    if get_settings().revenuecat_secret_api_key:
        from api.services.revenuecat_sync import sync_account

        await sync_account(to_account)
        for from_account in from_accounts:
            await sync_account(from_account)
    else:
        store = require_store()
        for from_account in from_accounts:
            try:
                moved = await store.reassign_entitlements(
                    from_account=from_account, to_account=to_account, sources=STORE_SOURCES
                )
            except AccountStoreError as e:
                raise RevenueCatError(str(e)) from e
            await invalidate_tier_cache(from_account)
            logger.info("revenuecat_rows_moved", extra={"rows": moved, "to": to_account})
        logger.warning("revenuecat_transfer_not_synced", extra={"account_id": to_account})
    await invalidate_tier_cache(to_account)
    await _audit("subscription.store_transferred", to_account, to_account,
                 {"from_accounts": from_accounts, "synced": bool(get_settings().revenuecat_secret_api_key)})
    return Outcome("applied", "transfer", to_account)

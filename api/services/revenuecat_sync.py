"""Reconcile an account's store purchases with RevenueCat's REST API.

"Restore purchases" in the app (POST /api/v1/me/entitlement/refresh) and the
webhook's TRANSFER handling call `sync_account`: GET /v1/subscribers/{id}
(https://www.revenuecat.com/docs/api-v1/customers) is RevenueCat's current
view of the customer, so the google_play / app_store rows are rewritten from
it — whatever webhooks were missed or arrived out of order. Row semantics
are those of api/services/revenuecat.py.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

from api.config import get_settings
from api.services import store_products
from api.services.account_store import AccountStoreError
from api.services.entitlements import ACTIVE_STATUSES, EntitlementError, record_entitlement
from api.services.revenuecat import (
    STORE_SOURCES,
    RevenueCatError,
    RevenueCatNotConfigured,
    invalidate_tier_cache,
    original_purchase_id,
    parse_ts,
    plan_fields,
    require_store,
    sandbox_accepted,
)

logger = logging.getLogger("cleanway.revenuecat")

API_BASE = "https://api.revenuecat.com/v1"
# The REST API spells stores in lower case.
REST_STORES = {"play_store": "google_play", "app_store": "app_store", "mac_app_store": "app_store"}


async def fetch_subscriber(app_user_id: str) -> dict:
    """GET /v1/subscribers/{app_user_id} (creates an empty customer when
    there is none — harmless). Raises RevenueCatError."""
    import httpx

    key = get_settings().revenuecat_secret_api_key
    if not key:
        raise RevenueCatNotConfigured("REVENUECAT_SECRET_API_KEY is not set")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                f"{API_BASE}/subscribers/{quote(app_user_id, safe='')}",
                headers={"Authorization": f"Bearer {key}", "Accept": "application/json"},
            )
    except Exception as e:
        raise RevenueCatError(f"RevenueCat request failed: {e}") from e
    if resp.status_code not in (200, 201):
        raise RevenueCatError(f"RevenueCat answered {resp.status_code}")
    try:
        subscriber = resp.json().get("subscriber")
    except Exception as e:
        raise RevenueCatError("RevenueCat answered invalid JSON") from e
    if not isinstance(subscriber, dict):
        raise RevenueCatError("RevenueCat answered without a subscriber")
    return subscriber


def _rest_status(sub: dict, now: datetime) -> tuple[str, Optional[str]]:
    expires = sub.get("expires_date")
    grace = sub.get("grace_period_expires_date")
    ends = [t for t in (expires, grace) if parse_ts(t)]
    period_end = max(ends, key=lambda t: parse_ts(t)) if ends else None
    if sub.get("refunded_at"):
        return "refunded", period_end
    end = parse_ts(period_end)
    if end is not None and end <= now:
        return ("paused" if sub.get("auto_resume_date") else "expired"), period_end
    expires_at = parse_ts(expires)
    if sub.get("billing_issues_detected_at") and expires_at is not None and expires_at <= now:
        return "past_due", period_end  # inside the store's grace period
    return ("trialing" if sub.get("period_type") == "trial" else "active"), period_end


def _match_row(rows: list[dict], source: str, external_id: Optional[str], product_id: str) -> Optional[dict]:
    """Our row for a RevenueCat subscription. The REST API gives the LATEST
    transaction id: on Play the original is derivable (an unmatched Play id
    is a new purchase), on the App Store it is not, so there fall back to
    this account's row of the same product."""
    for r in rows:
        if r.get("source") == source and external_id and r.get("external_id") == external_id:
            return r
    if source != "app_store":
        return None
    same = [r for r in rows if r.get("source") == source and r.get("product_id") == product_id]
    return max(same, key=lambda r: r.get("period_end") or "") if same else None


async def sync_account(account_id: str) -> dict:
    """Reconcile the account's store rows with RevenueCat. Returns counts.
    Raises RevenueCatError (incl. RevenueCatNotConfigured)."""
    subscriber = await fetch_subscriber(account_id)
    store = require_store()
    try:
        rows = await store.list_entitlements(account_id)
    except AccountStoreError as e:
        raise RevenueCatError(str(e)) from e

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    subscriptions = subscriber.get("subscriptions") or {}
    seen: set[tuple[str, str]] = set()
    applied = 0
    for key, sub in subscriptions.items():
        if not isinstance(sub, dict):
            continue
        source = REST_STORES.get(str(sub.get("store") or ""))
        if source is None or (sub.get("is_sandbox") and not sandbox_accepted()):
            continue
        product_id = str(key)
        if ":" not in product_id and sub.get("product_plan_identifier"):
            product_id = f"{product_id}:{sub['product_plan_identifier']}"
        product = store_products.lookup(product_id)
        if product is None:
            logger.error("revenuecat_unknown_product", extra={"product_id": product_id, "account_id": account_id})
            continue
        external_id = original_purchase_id(source, sub.get("store_transaction_id"))
        row = _match_row(rows, source, external_id, product_id)
        if row is not None:
            external_id = row["external_id"]
        if not external_id:
            continue
        status, period_end = _rest_status(sub, now)
        plan, device_limit = plan_fields(product)
        try:
            await record_entitlement(
                account_id=account_id, source=source, external_id=external_id, status=status,
                plan=plan, period_end=period_end, device_limit=device_limit,
                product_id=product_id, source_event_at=now_iso,
            )
        except EntitlementError as e:
            raise RevenueCatError(str(e)) from e
        seen.add((source, external_id))
        applied += 1

    # Active store rows RevenueCat no longer lists for this account were
    # transferred to another App User ID: they end here.
    ended = 0
    listed = {str(k).split(":", 1)[0] for k in subscriptions}
    for r in rows:
        key = (r.get("source"), r.get("external_id"))
        product_root = str(r.get("product_id") or "").split(":", 1)[0]
        if r.get("source") not in STORE_SOURCES or key in seen or r.get("status") not in ACTIVE_STATUSES:
            continue
        if product_root and product_root in listed:
            continue  # listed but skipped above (sandbox / unknown) — leave it
        try:
            await record_entitlement(account_id=account_id, source=r["source"], external_id=r["external_id"],
                                     status="expired", source_event_at=now_iso)
        except EntitlementError as e:
            raise RevenueCatError(str(e)) from e
        ended += 1

    await invalidate_tier_cache(account_id)
    logger.info("revenuecat_synced", extra={"account_id": account_id, "applied": applied, "ended": ended})
    return {"applied": applied, "ended": ended}

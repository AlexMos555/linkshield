"""RevenueCat webhook: Google Play / App Store purchases → entitlements.

  POST /api/v1/webhooks/revenuecat

docs/runbooks/revenuecat.md (setup), api/services/revenuecat.py (what each
event does). RevenueCat's delivery contract
(https://www.revenuecat.com/docs/integrations/webhooks, checked 2026-10-08):
it sends the Authorization header value set in its dashboard; anything but
a 200 is a failure and is retried up to 5 times (after 5, 10, 20, 40 and 80
minutes); retries reuse the event `id`. So:

  * the header is compared in constant time with REVENUECAT_WEBHOOK_AUTH;
    wrong or missing → 401. Not configured → 503 (and nothing is granted);
  * an event id already applied answers 200 duplicate:true
    (`revenuecat_events`, migration 024);
  * process-then-mark: the id is stored only after every write succeeded.
    A failed write answers 500, RevenueCat retries, the retry is processed
    again (the writes are upserts). A failed mark is logged and answered
    200 — a repeat would only rewrite the same rows.
"""
from __future__ import annotations

import hmac
import json
import logging

from fastapi import APIRouter, HTTPException, Request

from api.config import get_settings
from api.services import account_store
from api.services.account_store import AccountStoreError
from api.services.revenuecat import RevenueCatError, apply_event

logger = logging.getLogger("cleanway.revenuecat")

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

# RevenueCat events are a few KB; anything far larger isn't one.
MAX_BODY_BYTES = 256 * 1024
CONFIG_DEPENDENT_SKIPS = frozenset({"unknown_product", "sandbox"})


def _authorized(header: str, secret: str) -> bool:
    """The dashboard value is sent as-is. Accept it either verbatim or with a
    "Bearer " prefix the founder may have typed in only one of the two places."""
    got = header.encode("utf-8")
    ok = hmac.compare_digest(got, secret.encode("utf-8"))
    ok |= hmac.compare_digest(got, f"Bearer {secret}".encode("utf-8"))
    return ok


@router.post("/revenuecat", include_in_schema=False)
async def revenuecat_webhook(request: Request):
    secret = get_settings().revenuecat_webhook_auth
    if not secret:
        logger.error("revenuecat_webhook_not_configured")
        raise HTTPException(503, "RevenueCat webhook is not configured")
    if not _authorized(request.headers.get("authorization", ""), secret):
        logger.warning("revenuecat_webhook_unauthorized")
        raise HTTPException(401, "Unauthorized")

    payload = await request.body()
    if len(payload) > MAX_BODY_BYTES:
        raise HTTPException(413, "Payload too large")
    try:
        body = json.loads(payload)
    except ValueError:
        raise HTTPException(400, "Invalid JSON")
    event = body.get("event") if isinstance(body, dict) else None
    if not isinstance(event, dict) or not event.get("id") or not event.get("type"):
        raise HTTPException(400, "Missing event")
    event_id = str(event["id"])[:255]
    event_type = str(event["type"])[:64]

    store = account_store.get_account_store()
    if store is None:
        logger.error("revenuecat_webhook_no_database", extra={"event_id": event_id})
        raise HTTPException(503, "Database not configured; RevenueCat will retry")
    try:
        if await store.is_event_processed(event_id):
            logger.info("revenuecat_duplicate_skipped", extra={"event_id": event_id, "type": event_type})
            return {"status": "ok", "duplicate": True}
    except AccountStoreError as e:
        logger.error("revenuecat_dedupe_lookup_failed", extra={"event_id": event_id, "error": str(e)})
        raise HTTPException(503, "Database unavailable; RevenueCat will retry")

    logger.info("revenuecat_webhook_received", extra={"event_id": event_id, "type": event_type,
                                                       "environment": event.get("environment")})
    try:
        outcome = await apply_event(event)
    except RevenueCatError as e:
        logger.error("revenuecat_webhook_failed", extra={"event_id": event_id, "type": event_type, "error": str(e)})
        raise HTTPException(500, "Webhook processing failed; RevenueCat will retry")

    # An event skipped because of OUR configuration (a product missing from
    # the map, sandbox off) stays unmarked: once the config is fixed, a Retry
    # from the RevenueCat dashboard applies it.
    if outcome.reason not in CONFIG_DEPENDENT_SKIPS:
        try:
            await store.mark_event_processed(event_id, event_type)
        except AccountStoreError as e:
            logger.warning("revenuecat_mark_failed", extra={"event_id": event_id, "error": str(e)})
    return {"status": "ok", "result": outcome.result, "reason": outcome.reason}

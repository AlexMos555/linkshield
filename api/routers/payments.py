"""
Stripe Payments Router.

Handles:
  1. POST /api/v1/payments/checkout — create Stripe Checkout session
     (alias /create-checkout kept for legacy callers)
  2. POST /api/v1/payments/webhook — Stripe webhook handler (idempotent
     on event.id: Redis lease while processing, "done" marker only after
     a successful write; failures answer 5xx so Stripe retries)
  3. POST /api/v1/payments/portal — Stripe Customer Portal link

Real Stripe price IDs are resolved at request time from
api.services.pricing.STRIPE_PRICE_IDS, which reads
STRIPE_PRICE_{PLAN}_T{TIER}_{INTERVAL} env vars populated by
scripts/create_stripe_prices.py.

Tier updates are written to Supabase subscriptions table
and cached in Redis for fast tier lookups.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator

from api.config import get_settings
from api.services.auth import get_current_user
from api.services.rate_limiter import rate_limit
from api.services.stripe_billing import (
    BillingError,
    cancel_subscription_now,
    fetch_subscription_row,
    field,
    has_paid_subscription,
    object_id,
    resolve_customer_id,
    store_customer_id,
    stripe_client,
    trial_available,
)
from api.models.schemas import AuthUser

logger = logging.getLogger("cleanway.payments")

router = APIRouter(prefix="/api/v1/payments", tags=["payments"])

# Free trial length for a user's FIRST paid subscription. Offered once
# per user (subscriptions.trial_used_at, migration 021).
TRIAL_DAYS = 14


def _resolve_price(plan_interval: str, country: Optional[str]) -> tuple[str, int] | None:
    """Translate 'personal_monthly' / 'family_yearly' / 'business_monthly'
    + the visitor's country into (Stripe price ID, PPP tier).

    Uses pricing.price_id_for_checkout → country_to_tier, the same
    function /api/v1/pricing/for-country uses to pick the price it SHOWS
    — so for the same `cc` the price charged is the price displayed.
    (Before, checkout always charged tier 1 while the page showed the
    regional tier.) Returns None on a malformed key."""
    from api.services.pricing import STRIPE_PRICE_IDS, country_to_tier, price_id_for_checkout

    if "_" not in plan_interval:
        return None
    plan, interval = plan_interval.rsplit("_", 1)
    if plan not in STRIPE_PRICE_IDS:
        return None
    if interval not in ("monthly", "yearly"):
        return None
    return price_id_for_checkout(plan, country, interval), country_to_tier(country)  # type: ignore[arg-type]


_ALLOWED_REDIRECT_PREFIXES = ("https://cleanway.ai/", "https://www.cleanway.ai/")


class CheckoutRequest(BaseModel):
    plan: str  # "personal_monthly", "personal_yearly", "family_monthly", "family_yearly"
    success_url: str = "https://cleanway.ai/success"
    cancel_url: str = "https://cleanway.ai/pricing"
    # The same `cc` the client passed to /api/v1/pricing/for-country, so
    # checkout charges the regional price the visitor was shown. Omitted
    # → tier 2 (base), exactly what /pricing shows without a cc.
    country: Optional[str] = Field(
        default=None,
        max_length=2,
        description="ISO 3166-1 alpha-2 country code — the `cc` used for /api/v1/pricing/for-country.",
    )

    @field_validator("success_url", "cancel_url")
    @classmethod
    def _must_be_cleanway_domain(cls, v: str) -> str:
        # Defense layer 1: reject control characters anywhere. CR/LF would
        # let an attacker craft a Stripe success_url that smuggles a
        # `Location:` header into the redirect (HTTP response splitting),
        # null bytes truncate string parsers in legacy stacks, etc.
        # tests/test_payments_validators.py covers each variant explicitly.
        if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in v):
            raise ValueError("URL must not contain control characters")
        # Defense layer 2: cap absolute length so an attacker can't push
        # a 10 MB URL through the validator and stress Stripe's API.
        if len(v) > 2048:
            raise ValueError("URL too long")
        # Defense layer 3: must be on a known Cleanway origin.
        if not any(v.startswith(p) for p in _ALLOWED_REDIRECT_PREFIXES):
            raise ValueError("URL must be on cleanway.ai domain")
        return v


class CheckoutResponse(BaseModel):
    checkout_url: str


_BILLING_UNAVAILABLE = "Billing is temporarily unavailable. Please try again in a moment."


@router.post(
    "/checkout",
    response_model=CheckoutResponse,
    dependencies=[Depends(rate_limit(mode="sensitive", category="checkout"))],
)
async def create_checkout(
    request: CheckoutRequest,
    user: AuthUser = Depends(get_current_user),
):
    """Create a Stripe Checkout session for subscription.

    Endpoint path is /checkout (matches the landing PricingClient).
    /create-checkout is preserved as an alias below for any code that
    might still reference the legacy name.

    Refuses (409 `subscription_already_active`) when the user already
    pays: subscriptions has one row per user, so a second Stripe
    subscription would overwrite the first on our side while Stripe kept
    billing both. Plan changes go through the Customer Portal."""
    try:
        import stripe
    except ImportError:
        raise HTTPException(500, "Stripe not configured")

    settings = get_settings()
    stripe_key = getattr(settings, "stripe_secret_key", "")
    if not stripe_key:
        raise HTTPException(500, "Stripe not configured")

    stripe.api_key = stripe_key

    resolved = _resolve_price(request.plan, request.country)
    if not resolved:
        raise HTTPException(400, f"Invalid plan: {request.plan}")
    price_id, pricing_tier = resolved

    try:
        row = await fetch_subscription_row(user_id=user.id)
        if has_paid_subscription(row):
            raise HTTPException(
                409,
                detail={
                    "code": "subscription_already_active",
                    "error": (
                        "You already have an active subscription. Change or "
                        "cancel it in the billing portal."
                    ),
                    "portal_endpoint": "/api/v1/payments/portal",
                },
            )
        # Reuse the user's Stripe customer (stored id, or the customer of
        # a pre-migration-021 subscription) instead of letting Checkout
        # mint a new customer from customer_email on every purchase.
        customer_id = await resolve_customer_id(row)
    except BillingError as e:
        logger.error("checkout_billing_lookup_failed", extra={"user_id": user.id, "error": str(e)})
        raise HTTPException(503, _BILLING_UNAVAILABLE)
    if customer_id and row and not row.get("stripe_customer_id"):
        await store_customer_id(user.id, customer_id)

    trial = trial_available(row)
    subscription_data: dict = {"metadata": {"user_id": user.id}}
    if trial:
        subscription_data["trial_period_days"] = TRIAL_DAYS
    params: dict = {
        "mode": "subscription",
        "line_items": [{"price": price_id, "quantity": 1}],
        "success_url": request.success_url + "?session_id={CHECKOUT_SESSION_ID}",
        "cancel_url": request.cancel_url,
        "metadata": {
            "user_id": user.id,
            "plan": request.plan,
            # The webhook records trial use from this flag (trial_used_at)
            # once the session actually completes.
            "trial": "1" if trial else "0",
            "pricing_tier": str(pricing_tier),
        },
        "subscription_data": subscription_data,
    }
    if customer_id:
        params["customer"] = customer_id
    else:
        params["customer_email"] = user.email

    try:
        # Stripe idempotency: identical (user, plan, params) calls within
        # the same 5-minute bucket return the SAME Checkout session, so a
        # double-click on Subscribe doesn't create two pending sessions.
        # The params digest is part of the key because Stripe rejects a
        # reused key whose parameters differ (e.g. the trial or the
        # customer changed between two clicks).
        import time as _time

        bucket = int(_time.time() // 300)  # 5-minute slot
        digest = hashlib.sha256(json.dumps(params, sort_keys=True).encode()).hexdigest()[:16]
        idem_key = f"checkout:{user.id}:{request.plan}:{bucket}:{digest}"

        # stripe v11 ships native async variants for every resource.
        # Using sync create() inside an async handler pins the event loop
        # for the full Stripe RTT (300–800ms US-East) and starves every
        # other concurrent request on this worker. (Audit backend-async-2.)
        session = await stripe.checkout.Session.create_async(**params, idempotency_key=idem_key)

        logger.info(
            "checkout_created",
            extra={"user_id": user.id, "plan": request.plan, "pricing_tier": pricing_tier, "trial": trial},
        )
        return CheckoutResponse(checkout_url=session.url)

    except Exception as e:
        logger.error("checkout_error", extra={"error": str(e)})
        raise HTTPException(500, "Failed to create checkout session")


# Alias for any caller still on the legacy path. Kept thin so the
# bulk of the logic lives in one place. Drop this after a release cycle
# once we're confident no production caller hits the old URL.
@router.post(
    "/create-checkout",
    response_model=CheckoutResponse,
    dependencies=[Depends(rate_limit(mode="sensitive", category="checkout"))],
)
async def create_checkout_legacy(
    request: CheckoutRequest,
    user: AuthUser = Depends(get_current_user),
):
    return await create_checkout(request, user)


# ── Webhook idempotency ──
#
# Key stripe:event:{id} has two states:
#   "processing" — a worker holds a short lease (SET NX EX) and is
#                  handling the event right now;
#   "done"       — the event was fully processed (written only AFTER
#                  every handler write succeeded), kept 7 days to cover
#                  Stripe's 3-day retry window with headroom.
# On failure the lease is deleted and the endpoint answers 5xx, so
# Stripe's retry processes the event again. A crashed worker's lease
# simply expires. (The old gate set the key BEFORE processing and the
# write swallowed errors — a failed Supabase write was acknowledged with
# 200 and lost forever.)
_EVENT_KEY = "stripe:event:{}"
_EVENT_LEASE_SECONDS = 120
_EVENT_DONE_TTL_SECONDS = 7 * 24 * 3600


async def _claim_event(event_id: str) -> str:
    """Returns "claimed", "done", "in_flight" or "unavailable" (Redis down)."""
    try:
        from api.services.cache import get_redis

        r = await get_redis()
        key = _EVENT_KEY.format(event_id)
        for _ in range(2):
            if await r.set(key, "processing", nx=True, ex=_EVENT_LEASE_SECONDS):
                return "claimed"
            state = await r.get(key)
            if state is None:
                continue  # lease expired between SET and GET — try again
            # "1" is the marker the previous gate wrote; it means the
            # event was already taken, which is how it was treated then.
            return "done" if state in ("done", "1") else "in_flight"
        return "in_flight"
    except Exception as e:
        logger.warning(
            "webhook_idempotency_redis_unavailable",
            extra={"event_id": event_id, "error": str(e)},
        )
        return "unavailable"


async def _finish_event(event_id: str) -> None:
    try:
        from api.services.cache import get_redis

        r = await get_redis()
        await r.set(_EVENT_KEY.format(event_id), "done", ex=_EVENT_DONE_TTL_SECONDS)
    except Exception as e:
        # Processed but not marked: a Stripe retry re-runs the handlers,
        # which are idempotent upserts. Acceptable.
        logger.warning("webhook_done_marker_failed", extra={"event_id": event_id, "error": str(e)})


async def _release_event(event_id: str) -> None:
    try:
        from api.services.cache import get_redis

        r = await get_redis()
        await r.delete(_EVENT_KEY.format(event_id))
    except Exception as e:
        # The lease expires on its own after _EVENT_LEASE_SECONDS.
        logger.warning("webhook_lease_release_failed", extra={"event_id": event_id, "error": str(e)})


@router.post("/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events.

    Stripe documents "events may be delivered more than once" — they
    retry on any non-2xx / timeout for up to 72 hours with exponential
    backoff. So:
      - an event is acknowledged (2xx) only once every write it implies
        has succeeded; any failure → 500 → Stripe retries;
      - an already-processed event id answers 200 duplicate:true;
      - an event another worker is processing right now answers 409 —
        Stripe retries later and then sees the outcome (a 200 here could
        drop the event if that other worker fails).
    Redis unreachable → process anyway (risking one duplicate write is
    better than dropping a billing event; every handler is an upsert).
    """
    try:
        import stripe
    except ImportError:
        raise HTTPException(500, "Stripe not configured")

    settings = get_settings()
    stripe.api_key = getattr(settings, "stripe_secret_key", "")
    webhook_secret = getattr(settings, "stripe_webhook_secret", "")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = stripe.Webhook.construct_event(payload, sig_header, webhook_secret)
    except Exception as e:
        logger.warning("webhook_signature_invalid", extra={"error": str(e)})
        raise HTTPException(400, "Invalid signature")

    event_id = event.get("id", "")
    event_type = event["type"]
    data = event["data"]["object"]

    claim = await _claim_event(event_id) if event_id else "unavailable"
    if claim == "done":
        logger.info(
            "webhook_duplicate_skipped",
            extra={"event_id": event_id, "type": event_type},
        )
        return {"status": "ok", "duplicate": True}
    if claim == "in_flight":
        logger.info("webhook_in_flight_elsewhere", extra={"event_id": event_id, "type": event_type})
        raise HTTPException(409, "Event is being processed; retry later")

    logger.info("webhook_received", extra={"type": event_type, "event_id": event_id})

    try:
        await _dispatch_event(event_type, data)
    except Exception as e:
        logger.error(
            "webhook_processing_failed",
            extra={"event_id": event_id, "type": event_type, "error": str(e)},
        )
        if claim == "claimed":
            await _release_event(event_id)
        raise HTTPException(500, "Webhook processing failed; Stripe will retry")

    if claim == "claimed":
        await _finish_event(event_id)
    return {"status": "ok"}


async def _dispatch_event(event_type: str, data: dict) -> None:
    if event_type == "checkout.session.completed":
        await _handle_checkout_completed(data)
    elif event_type == "customer.subscription.updated":
        await _handle_subscription_updated(data)
    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_deleted(data)
    elif event_type == "customer.subscription.trial_will_end":
        # Stripe fires this 3 days before a trial ends. Used for the
        # "your trial ends Friday, click here to keep your plan or
        # cancel" email — without it, every user gets a surprise
        # charge at trial end and we eat the chargeback. Persistence
        # untouched; downstream email job reads logs / a future
        # trial_ending_at column.
        await _handle_trial_will_end(data)
    elif event_type == "invoice.paid":
        # Successful renewal payment. After a past_due cycle this is
        # how we know the customer is back to good standing — Stripe
        # also sends subscription.updated, but invoice.paid is the
        # authoritative signal for "money actually changed hands."
        await _handle_invoice_paid(data)
    elif event_type == "customer.deleted":
        # Stripe-side customer deletion (operator-initiated cleanup,
        # support tool, etc.). Cancel any subscriptions we have on
        # file for that customer to keep our DB consistent.
        await _handle_customer_deleted(data)
    elif event_type == "invoice.payment_failed":
        await _handle_payment_failed(data)
    elif event_type == "charge.refunded":
        # Operator / customer issued a refund. A full refund of the
        # current period ends access now (and the Stripe subscription,
        # so it can't renew); see _handle_charge_refunded.
        await _handle_charge_refunded(data)
    elif event_type == "charge.dispute.created":
        # Customer (or their bank) filed a chargeback. Account stays
        # functional during the dispute (Stripe gives us ~20 days to
        # respond), but we audit-log it for fraud review and tag the
        # user so support can de-prioritise their tickets if needed.
        await _handle_charge_dispute(data)


@router.post(
    "/portal",
    dependencies=[Depends(rate_limit(mode="sensitive", category="portal"))],
)
async def customer_portal(user: AuthUser = Depends(get_current_user)):
    """Create Stripe Customer Portal link for managing subscription.

    Uses the Stripe customer stored on the user's subscriptions row (or
    the customer of their pre-migration-021 subscription). It used to
    search customers by email with limit=1 — emails aren't unique in
    Stripe, so that could open someone else's billing portal or a stale
    duplicate customer without the live subscription."""
    try:
        stripe = stripe_client()
    except BillingError:
        raise HTTPException(500, "Stripe not configured")

    try:
        row = await fetch_subscription_row(user_id=user.id)
        customer_id = await resolve_customer_id(row)
    except BillingError as e:
        logger.error("portal_billing_lookup_failed", extra={"user_id": user.id, "error": str(e)})
        raise HTTPException(503, _BILLING_UNAVAILABLE)
    if not customer_id:
        raise HTTPException(404, "No subscription found")
    if row and not row.get("stripe_customer_id"):
        await store_customer_id(user.id, customer_id)

    try:
        # return_url is where Stripe sends the user after they close the
        # portal (or after they cancel / upgrade). /settings on landing
        # doesn't exist yet (web settings UI lives inside the extension
        # popup + mobile app, not on the marketing site). Redirecting to
        # /pricing makes the most sense — it shows their tier options
        # again and reflects the change they just made via the portal.
        session = await stripe.billing_portal.Session.create_async(
            customer=customer_id,
            return_url="https://cleanway.ai/pricing",
        )
        return {"portal_url": session.url}
    except Exception as e:
        logger.error("portal_error", extra={"error": str(e)})
        raise HTTPException(500, "Failed to create portal session")


# ── Webhook handlers ──
#
# Every handler raises on a failed read/write (BillingError) — the
# webhook turns that into a 5xx so Stripe retries. A handler returns
# normally only when there is nothing (more) to do.

def _tier_from_plan_key(plan: str) -> str:
    """Map 'personal_monthly' / 'family_yearly' / 'business_monthly' → tier.

    Used by webhook handlers to translate the metadata.plan we set during
    checkout into the subscriptions.tier value our DB stores. Before
    this helper, the inline logic only checked personal/family —
    business plans silently fell through to 'personal', giving B2B
    customers Personal-tier limits despite paying for Business."""
    if "business" in plan:
        return "business"
    if "family" in plan:
        return "family"
    return "personal"


def _tier_from_subscription(subscription: dict) -> Optional[str]:
    """The plan (subscriptions.tier) behind a Stripe subscription's price.

    A plan change in the Customer Portal swaps the item's price and
    fires customer.subscription.updated — this is the only place the
    new plan is visible. None when no item carries a price we created."""
    from api.services.pricing import plan_for_price_id

    items = field(field(subscription, "items"), "data") or []
    for item in items:
        price = field(item, "price") or field(item, "plan")
        plan = plan_for_price_id(object_id(price))
        if plan:
            return plan
    return None


async def _resolve_user_id(
    metadata_user_id: Optional[str],
    *,
    subscription_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    stripe_fallback: bool = True,
) -> Optional[str]:
    """Find the Cleanway user behind a Stripe object.

    Order: our metadata.user_id (set on Checkout sessions and on the
    subscription) → our subscriptions row by subscription id → by
    stored customer id → (rows from before migration 021 have no
    customer id) the user_id in the metadata of the customer's Stripe
    subscriptions. Invoice charges, refunds and disputes never carry
    our metadata, which is why charge.metadata.user_id was always empty
    for them."""
    if metadata_user_id:
        return metadata_user_id
    if subscription_id:
        row = await fetch_subscription_row(subscription_id=subscription_id)
        if row:
            return row["user_id"]
    if customer_id:
        row = await fetch_subscription_row(customer_id=customer_id)
        if row:
            return row["user_id"]
        if stripe_fallback:
            stripe = stripe_client()
            try:
                listing = await stripe.Subscription.list_async(
                    customer=customer_id, status="all", limit=10
                )
            except Exception as e:
                if getattr(e, "code", None) == "resource_missing":
                    return None  # customer gone in Stripe — nobody to attribute
                raise BillingError(f"subscription list failed: {e}") from e
            for sub in field(listing, "data") or []:
                uid = field(field(sub, "metadata"), "user_id")
                if uid:
                    return uid
    return None


async def _handle_checkout_completed(session: dict):
    """New subscription created."""
    metadata = session.get("metadata") or {}
    user_id = metadata.get("user_id")
    plan = metadata.get("plan", "personal_monthly")
    subscription_id = object_id(session.get("subscription"))
    customer_id = object_id(session.get("customer"))

    if not user_id:
        logger.warning("checkout_no_user_id")
        return

    tier = _tier_from_plan_key(plan)

    from api.services import audit_log

    # Checkout refuses users who already pay, but two Checkout sessions
    # opened before either completed can both go through. Our row can
    # only hold one subscription: it follows the newest, and the overlap
    # is flagged loudly so the operator can cancel + refund the other.
    existing = await fetch_subscription_row(user_id=user_id)
    previous = existing.get("provider_subscription_id") if has_paid_subscription(existing) else None
    if previous and subscription_id and previous != subscription_id:
        logger.error(
            "subscription_duplicate_detected",
            extra={"user_id": user_id, "previous": previous, "new": subscription_id},
        )
        await audit_log.write(
            action="subscription.duplicate_detected",
            target_kind="subscription",
            target_id=subscription_id,
            actor_user_id=user_id,
            meta={"previous_subscription_id": previous, "new_subscription_id": subscription_id},
        )

    trial_used_at = (
        datetime.now(timezone.utc).isoformat() if metadata.get("trial") == "1" else None
    )
    await _update_subscription(
        user_id, tier, "active", "stripe", subscription_id,
        stripe_customer_id=customer_id,
        trial_used_at=trial_used_at,
    )
    logger.info("subscription_created", extra={"user_id": user_id, "tier": tier})

    await audit_log.write(
        action="subscription.created",
        target_kind="subscription",
        target_id=subscription_id or user_id,
        actor_user_id=user_id,
        meta={"tier": tier, "plan": plan, "provider": "stripe"},
    )


async def _handle_subscription_updated(subscription: dict):
    """Subscription changed (upgrade/downgrade/renewal)."""
    status = subscription.get("status")  # active, past_due, canceled, etc.
    subscription_id = subscription.get("id")
    customer_id = object_id(subscription.get("customer"))
    user_id = await _resolve_user_id(
        (subscription.get("metadata") or {}).get("user_id"),
        subscription_id=subscription_id,
        customer_id=customer_id,
    )

    if not user_id:
        logger.warning("subscription_updated_unattributed", extra={"subscription_id": subscription_id})
        return

    mapped_status = "active" if status in ("active", "trialing") else "past_due" if status == "past_due" else "cancelled"
    # Plan changes (personal ↔ family ↔ business) arrive here as a new
    # price; map it back so the tier follows. Unknown price → leave the
    # stored tier alone rather than guess.
    tier = _tier_from_subscription(subscription)
    if tier is None and field(field(subscription, "items"), "data"):
        logger.warning("subscription_price_unmapped", extra={"subscription_id": subscription_id})
    # Persist the current billing period so the UI can show "renews
    # Aug 14" and support can answer "when does this expire" from our
    # DB without a Stripe round trip. Stripe sends epoch seconds.
    period_start = _epoch_to_iso(subscription.get("current_period_start"))
    period_end = _epoch_to_iso(subscription.get("current_period_end"))
    await _update_subscription(
        user_id, tier, mapped_status, "stripe", subscription_id,
        current_period_start=period_start,
        current_period_end=period_end,
        stripe_customer_id=customer_id,
    )

    from api.services import audit_log
    await audit_log.write(
        action="subscription.status_changed",
        target_kind="subscription",
        target_id=subscription_id or user_id,
        actor_user_id=user_id,
        meta={
            "stripe_status": status,
            "mapped_status": mapped_status,
            "tier": tier,
            "stripe_event": "subscription.updated",
        },
    )


async def _handle_subscription_deleted(subscription: dict):
    """Subscription cancelled."""
    user_id = await _resolve_user_id(
        (subscription.get("metadata") or {}).get("user_id"),
        subscription_id=subscription.get("id"),
        customer_id=object_id(subscription.get("customer")),
    )
    if user_id:
        await _update_subscription(user_id, "free", "cancelled", "stripe", subscription.get("id"))
        logger.info("subscription_cancelled", extra={"user_id": user_id})

        from api.services import audit_log
        await audit_log.write(
            action="subscription.cancelled",
            target_kind="subscription",
            target_id=subscription.get("id") or user_id,
            actor_user_id=user_id,
            meta={"stripe_event": "subscription.deleted"},
        )


async def _handle_payment_failed(invoice: dict):
    """Payment failed."""
    subscription_id = invoice.get("subscription")
    logger.warning("payment_failed", extra={"subscription_id": subscription_id})


async def _handle_trial_will_end(subscription: dict):
    """Stripe fires this exactly 3 days before a trialing subscription
    converts to paid. Currently we just log + structured-log it for
    Sentry breadcrumb context; the email-template `trial_ending` exists
    in packages/email-templates/ and will be wired to fire from this
    handler once the email provider is activated."""
    user_id = subscription.get("metadata", {}).get("user_id")
    trial_end = subscription.get("trial_end")  # epoch seconds
    logger.info(
        "trial_will_end",
        extra={
            "user_id": user_id,
            "subscription_id": subscription.get("id"),
            "trial_end_epoch": trial_end,
        },
    )


async def _handle_invoice_paid(invoice: dict):
    """Successful renewal. After a past_due cycle this is the
    authoritative recovery signal — money changed hands, the customer
    is good. Stripe also fires customer.subscription.updated when status
    flips back to 'active'; that's where the actual DB write happens.
    Here we just emit a structured log so analytics / Sentry can pin
    the recovery moment to the actual payment."""
    user_id = (invoice.get("metadata") or {}).get("user_id")
    subscription_id = invoice.get("subscription")
    amount_paid = invoice.get("amount_paid")  # cents
    logger.info(
        "invoice_paid",
        extra={
            "user_id": user_id,
            "subscription_id": subscription_id,
            "amount_paid_cents": amount_paid,
        },
    )


async def _refund_covers_current_period(charge: dict, subscription_id: Optional[str]) -> bool:
    """Is the refunded charge the payment for the period the user is in
    now (the subscription's latest invoice)? When we can't tell — no
    invoice on the charge, no subscription on file — assume yes: the
    customer has their money back."""
    invoice_id = object_id(charge.get("invoice"))
    if not invoice_id or not subscription_id:
        return True
    stripe = stripe_client()
    try:
        sub = await stripe.Subscription.retrieve_async(subscription_id)
    except Exception as e:
        raise BillingError(f"subscription retrieve failed: {e}") from e
    latest = object_id(field(sub, "latest_invoice"))
    return latest is None or latest == invoice_id


async def _handle_charge_refunded(charge: dict):
    """A charge was refunded (full or partial).

    Mapping (subscriptions.status only allows active / cancelled /
    expired / past_due — the old 'refunded' was rejected by the CHECK
    constraint and the error swallowed, so refunds never revoked
    anything):
      - FULL refund of the current period's invoice → the customer has
        this period's money back: cancel the Stripe subscription now
        (no proration, no final invoice — it can't renew and re-grant
        access) and set tier='free', status='cancelled'. Stripe's own
        customer.subscription.deleted that follows writes the same row.
      - full refund of an OLDER invoice, or a PARTIAL refund (goodwill
        credit) → access unchanged; audit only.
    The user is found via the customer: invoice charges never carry our
    metadata.user_id.
    """
    customer_id = object_id(charge.get("customer"))
    metadata_user_id = (charge.get("metadata") or {}).get("user_id")
    amount = charge.get("amount") or 0
    amount_refunded = charge.get("amount_refunded") or 0
    full_refund = amount > 0 and amount_refunded >= amount
    currency = charge.get("currency")
    reason = (charge.get("refunds") or {}).get("data", [{}])
    reason = reason[0].get("reason") if reason else None

    user_id = await _resolve_user_id(metadata_user_id, customer_id=customer_id)

    logger.info(
        "charge_refunded",
        extra={
            "customer_id": customer_id,
            "user_id": user_id,
            "amount_cents": amount,
            "amount_refunded_cents": amount_refunded,
            "currency": currency,
            "reason": reason,
        },
    )

    if not user_id:
        logger.warning("charge_refunded_unattributed", extra={"charge_id": charge.get("id")})
        return

    access_revoked = False
    if full_refund:
        row = await fetch_subscription_row(user_id=user_id)
        sub_id = row.get("provider_subscription_id") if row and row.get("provider", "stripe") == "stripe" else None
        if has_paid_subscription(row) and await _refund_covers_current_period(charge, sub_id):
            if sub_id:
                await cancel_subscription_now(sub_id)
            await _update_subscription(user_id, "free", "cancelled", "stripe", None)
            access_revoked = True

    from api.services import audit_log
    await audit_log.write(
        action="subscription.refunded",
        target_kind="subscription",
        target_id=charge.get("id") or user_id,
        actor_user_id=user_id,
        meta={
            "stripe_event": "charge.refunded",
            "amount_refunded_cents": amount_refunded,
            "currency": currency,
            "reason": reason,
            "full_refund": full_refund,
            "access_revoked": access_revoked,
        },
    )


async def _handle_charge_dispute(charge_or_dispute: dict):
    """Customer (or their bank) filed a chargeback. Stripe's
    charge.dispute.created event payload contains the dispute object
    directly, with `.charge` pointing at the original charge id.

    We DON'T downgrade the user here — Stripe gives merchants ~20 days
    to respond with evidence, and revoking access mid-dispute is bad
    UX if the dispute turns out to be fraud-against-us (stolen card
    used to buy a subscription, real cardholder disputes). Instead we:
      - audit-log the event so support / finance can pull a report
      - log structured so Sentry breadcrumb context shows it
      - flag the user in a future fraud_review_required column once
        we add one

    The dispute carries neither a customer nor our metadata, so the
    user is found via the disputed charge's customer.

    If the dispute is LOST (charge.dispute.closed with status=lost),
    that's when we drop tier — covered in a future handler when we
    wire that event.
    """
    dispute_id = charge_or_dispute.get("id")
    charge_ref = charge_or_dispute.get("charge")
    charge_id = object_id(charge_ref)
    amount = charge_or_dispute.get("amount") or 0
    currency = charge_or_dispute.get("currency")
    reason = charge_or_dispute.get("reason")
    user_id = (charge_or_dispute.get("metadata") or {}).get("user_id")

    if not user_id and charge_id:
        charge = charge_ref if isinstance(charge_ref, dict) else None
        if charge is None:
            stripe = stripe_client()
            try:
                charge = await stripe.Charge.retrieve_async(charge_id)
            except Exception as e:
                raise BillingError(f"charge retrieve failed: {e}") from e
        customer_id = object_id(field(charge, "customer"))
        if customer_id:
            user_id = await _resolve_user_id(None, customer_id=customer_id)

    logger.warning(
        "charge_dispute_created",
        extra={
            "dispute_id": dispute_id,
            "charge_id": charge_id,
            "amount_cents": amount,
            "currency": currency,
            "reason": reason,
            "user_id": user_id,
        },
    )

    from api.services import audit_log
    await audit_log.write(
        action="subscription.dispute_opened",
        target_kind="subscription",
        target_id=dispute_id or charge_id or "unknown",
        actor_user_id=user_id,
        meta={
            "stripe_event": "charge.dispute.created",
            "amount_cents": amount,
            "currency": currency,
            "reason": reason,
            "charge_id": charge_id,
        },
    )


async def _handle_customer_deleted(customer: dict):
    """Stripe customer was deleted (support tool / operator-initiated
    cleanup). Drop the user to free in our DB so the tier resolver
    doesn't show paid access for a customer Stripe no longer knows, and
    forget the customer id so checkout doesn't try to reuse it.

    Found by the stored stripe_customer_id, else by metadata.user_id if
    the operator set one on the customer. Nobody found → log + skip
    (never mis-attribute the cancellation)."""
    customer_id = customer.get("id")
    row = await fetch_subscription_row(customer_id=customer_id) if customer_id else None
    user_id = row["user_id"] if row else (customer.get("metadata") or {}).get("user_id")
    logger.warning(
        "stripe_customer_deleted",
        extra={"customer_id": customer_id, "user_id": user_id},
    )
    if user_id:
        await _update_subscription(
            user_id, "free", "cancelled", "stripe", None, clear_customer=row is not None
        )


def _epoch_to_iso(epoch: Optional[int]) -> Optional[str]:
    """Stripe sends timestamps as Unix epoch seconds; our DB column is
    TIMESTAMPTZ. Convert defensively (returns None for None / 0 / weird
    inputs rather than raising)."""
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(int(epoch), tz=timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError):
        return None


async def _update_subscription(
    user_id: str,
    tier: Optional[str],
    status: str,
    provider: str,
    provider_id: Optional[str],
    *,
    current_period_start: Optional[str] = None,
    current_period_end: Optional[str] = None,
    stripe_customer_id: Optional[str] = None,
    trial_used_at: Optional[str] = None,
    clear_customer: bool = False,
):
    """Upsert the user's subscription row in Supabase + invalidate the
    Redis tier cache.

    RAISES BillingError when Supabase isn't configured, times out or
    answers non-2xx — the webhook must not acknowledge an event whose
    write didn't land (that was the lost-event bug).

    `current_period_*` are ISO-8601 strings. The Stripe payload carries
    them as epoch seconds — callers should run them through
    `_epoch_to_iso()`. Persisting them gives us:
      - 'expires on Sep 13' UI string without an extra Stripe round trip
      - graceful expiry awareness (resolver can prune stale tier even if
        we somehow miss the deleted webhook)
      - support team can answer 'when does this user's subscription
        renew/expire?' from our own DB
    Only the columns present in the body are updated on conflict, so
    omitted fields (tier, trial_used_at, …) keep their stored value.
    """
    import httpx
    from api.services.cache import get_redis

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        raise BillingError("supabase_not_configured_for_subscription_update")

    # Update Supabase — one row per user_id, mutated in place. Migration
    # 013 added UNIQUE(user_id), so the `on_conflict=user_id` query param
    # tells PostgREST to actually merge instead of inserting a new row.
    headers = {
        "apikey": settings.supabase_service_key,
        "Authorization": f"Bearer {settings.supabase_service_key}",
        "Content-Type": "application/json",
        "Prefer": "resolution=merge-duplicates,return=minimal",
    }

    body: dict = {
        "user_id": user_id,
        "status": status,
        "provider": provider,
    }
    if tier:
        body["tier"] = tier
    if provider_id:
        body["provider_subscription_id"] = provider_id
    if current_period_start is not None:
        body["current_period_start"] = current_period_start
    if current_period_end is not None:
        body["current_period_end"] = current_period_end
    if stripe_customer_id:
        body["stripe_customer_id"] = stripe_customer_id
    elif clear_customer:
        # The customer is gone in Stripe: forget it AND its subscription,
        # or resolve_customer_id would re-derive the dead customer from
        # the old subscription and checkout would fail on it.
        body["stripe_customer_id"] = None
        body["provider_subscription_id"] = None
    if trial_used_at:
        body["trial_used_at"] = trial_used_at

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{settings.supabase_url}/rest/v1/subscriptions"
                f"?on_conflict=user_id",
                headers=headers,
                json=body,
            )
    except Exception as e:
        raise BillingError(f"subscription upsert failed: {e}") from e
    if resp.status_code not in (200, 201, 204):
        logger.error(
            "subscription_upsert_unexpected_status",
            extra={
                "user_id": user_id,
                "status_code": resp.status_code,
                "body": resp.text[:200],
            },
        )
        raise BillingError(f"subscription upsert returned {resp.status_code}")

    # Invalidate Redis tier cache
    try:
        r = await get_redis()
        await r.delete(f"tier:{user_id}")
    except Exception:
        pass

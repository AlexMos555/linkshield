"""
Stripe Payments Router.

Handles:
  1. POST /api/v1/payments/checkout — create Stripe Checkout session
     (alias /create-checkout kept for legacy callers)
  2. POST /api/v1/payments/webhook — Stripe webhook handler (idempotent
     on event.id via Redis SETNX, 7-day TTL)
  3. POST /api/v1/payments/portal — Stripe Customer Portal link

Real Stripe price IDs are resolved at request time from
api.services.pricing.STRIPE_PRICE_IDS, which reads
STRIPE_PRICE_{PLAN}_T{TIER}_{INTERVAL} env vars populated by
scripts/create_stripe_prices.py.

Tier updates are written to Supabase subscriptions table
and cached in Redis for fast tier lookups.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, field_validator

from api.config import get_settings
from api.services.auth import get_current_user
from api.services.rate_limiter import rate_limit
from api.models.schemas import AuthUser

logger = logging.getLogger("cleanway.payments")

router = APIRouter(prefix="/api/v1/payments", tags=["payments"])

# Map the legacy client-side "plan_interval" string (e.g. "personal_monthly")
# to a real Stripe price ID, fetched from STRIPE_PRICE_IDS in pricing.py
# (which itself reads STRIPE_PRICE_{PLAN}_T{TIER}_{INTERVAL} env vars
# populated by scripts/create_stripe_prices.py).
#
# Tier defaults to 1 (US/EU/UK pricing). When we wire country-based tier
# resolution end-to-end (the data is already in pricing.py's
# infer_tier_from_country, just not threaded through the checkout call
# yet), this becomes the user's resolved tier.
_DEFAULT_TIER = 1


def _resolve_price_id(plan_interval: str) -> str | None:
    """Translate 'personal_monthly' / 'family_yearly' / 'business_monthly'
    into a real Stripe price ID. Returns None on a malformed key."""
    from api.services.pricing import STRIPE_PRICE_IDS

    if "_" not in plan_interval:
        return None
    plan, interval = plan_interval.rsplit("_", 1)
    if plan not in STRIPE_PRICE_IDS:
        return None
    if interval not in ("monthly", "yearly"):
        return None
    return STRIPE_PRICE_IDS[plan][_DEFAULT_TIER][interval]


_ALLOWED_REDIRECT_PREFIXES = ("https://cleanway.ai/", "https://www.cleanway.ai/")


class CheckoutRequest(BaseModel):
    plan: str  # "personal_monthly", "personal_yearly", "family_monthly", "family_yearly"
    success_url: str = "https://cleanway.ai/success"
    cancel_url: str = "https://cleanway.ai/pricing"

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
    might still reference the legacy name."""
    try:
        import stripe
    except ImportError:
        raise HTTPException(500, "Stripe not configured")

    settings = get_settings()
    stripe_key = getattr(settings, "stripe_secret_key", "")
    if not stripe_key:
        raise HTTPException(500, "Stripe not configured")

    stripe.api_key = stripe_key

    price_id = _resolve_price_id(request.plan)
    if not price_id:
        raise HTTPException(400, f"Invalid plan: {request.plan}")

    try:
        session = stripe.checkout.Session.create(
            mode="subscription",
            customer_email=user.email,
            line_items=[{"price": price_id, "quantity": 1}],
            success_url=request.success_url + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=request.cancel_url,
            metadata={
                "user_id": user.id,
                "plan": request.plan,
            },
            subscription_data={
                "metadata": {"user_id": user.id},
                "trial_period_days": 14,
            },
        )

        logger.info("checkout_created", extra={"user_id": user.id, "plan": request.plan})
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


@router.post("/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events.

    Stripe documents "events may be delivered more than once" — they
    retry on any 5xx / timeout for up to 72 hours with exponential
    backoff. Without dedup, a retried checkout.session.completed
    upserts the subscription twice; a retried subscription.updated
    can race with newer events and flip status backward.

    We dedup by event.id with a Redis SETNX + 7-day TTL. Already-seen
    events return 200 OK (so Stripe stops retrying) but skip processing.
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

    # ── Idempotency gate ───────────────────────────────────────
    # SETNX returns 1 if we just claimed the key, 0 if it was already
    # taken (= duplicate delivery). 7-day TTL covers Stripe's 72-hour
    # retry window with headroom. Failure mode: Redis unreachable →
    # log + process anyway. Better to risk one duplicate write than to
    # silently drop a legitimate billing event because Redis blipped.
    if event_id:
        try:
            from api.services.cache import get_redis

            r = await get_redis()
            claimed = await r.set(
                f"stripe:event:{event_id}",
                "1",
                nx=True,
                ex=7 * 24 * 3600,
            )
            if not claimed:
                logger.info(
                    "webhook_duplicate_skipped",
                    extra={"event_id": event_id, "type": event_type},
                )
                return {"status": "ok", "duplicate": True}
        except Exception as e:
            logger.warning(
                "webhook_idempotency_redis_unavailable",
                extra={"event_id": event_id, "error": str(e)},
            )
            # Fall through and process — accept the risk of duplicate
            # processing over the risk of dropping a real event.

    logger.info("webhook_received", extra={"type": event_type, "event_id": event_id})

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

    return {"status": "ok"}


@router.post(
    "/portal",
    dependencies=[Depends(rate_limit(mode="sensitive", category="portal"))],
)
async def customer_portal(user: AuthUser = Depends(get_current_user)):
    """Create Stripe Customer Portal link for managing subscription."""
    try:
        import stripe
    except ImportError:
        raise HTTPException(500, "Stripe not configured")

    settings = get_settings()
    stripe.api_key = getattr(settings, "stripe_secret_key", "")

    try:
        # Find Stripe customer by email
        customers = stripe.Customer.list(email=user.email, limit=1)
        if not customers.data:
            raise HTTPException(404, "No subscription found")

        # return_url is where Stripe sends the user after they close the
        # portal (or after they cancel / upgrade). /settings on landing
        # doesn't exist yet (web settings UI lives inside the extension
        # popup + mobile app, not on the marketing site). Redirecting to
        # /pricing makes the most sense — it shows their tier options
        # again and reflects the change they just made via the portal.
        session = stripe.billing_portal.Session.create(
            customer=customers.data[0].id,
            return_url="https://cleanway.ai/pricing",
        )
        return {"portal_url": session.url}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("portal_error", extra={"error": str(e)})
        raise HTTPException(500, "Failed to create portal session")


# ── Webhook handlers ──

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


async def _handle_checkout_completed(session: dict):
    """New subscription created."""
    user_id = session.get("metadata", {}).get("user_id")
    plan = session.get("metadata", {}).get("plan", "personal_monthly")
    subscription_id = session.get("subscription")

    if not user_id:
        logger.warning("checkout_no_user_id")
        return

    tier = _tier_from_plan_key(plan)

    await _update_subscription(user_id, tier, "active", "stripe", subscription_id)
    logger.info("subscription_created", extra={"user_id": user_id, "tier": tier})

    from api.services import audit_log
    await audit_log.write(
        action="subscription.created",
        target_kind="subscription",
        target_id=subscription_id or user_id,
        actor_user_id=user_id,
        meta={"tier": tier, "plan": plan, "provider": "stripe"},
    )


async def _handle_subscription_updated(subscription: dict):
    """Subscription changed (upgrade/downgrade/renewal)."""
    user_id = subscription.get("metadata", {}).get("user_id")
    status = subscription.get("status")  # active, past_due, canceled, etc.

    if not user_id:
        return

    mapped_status = "active" if status in ("active", "trialing") else "past_due" if status == "past_due" else "cancelled"
    await _update_subscription(user_id, None, mapped_status, "stripe", subscription.get("id"))

    from api.services import audit_log
    await audit_log.write(
        action="subscription.status_changed",
        target_kind="subscription",
        target_id=subscription.get("id") or user_id,
        actor_user_id=user_id,
        meta={
            "stripe_status": status,
            "mapped_status": mapped_status,
            "stripe_event": "subscription.updated",
        },
    )


async def _handle_subscription_deleted(subscription: dict):
    """Subscription cancelled."""
    user_id = subscription.get("metadata", {}).get("user_id")
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


async def _handle_customer_deleted(customer: dict):
    """Stripe customer was deleted (support tool / operator-initiated
    cleanup). Drop the user to free in our DB so the tier resolver
    doesn't show paid access for a customer Stripe no longer knows.

    The Stripe customer doesn't always carry our user_id in metadata,
    so we have to look up by stripe_customer_id. Until we add that
    column on subscriptions, we log + skip the persistence update —
    safer than mis-attributing the cancellation. (Migration to add
    stripe_customer_id is a future hardening, not blocking ship.)"""
    customer_id = customer.get("id")
    user_id = (customer.get("metadata") or {}).get("user_id")
    logger.warning(
        "stripe_customer_deleted",
        extra={"customer_id": customer_id, "user_id": user_id},
    )
    if user_id:
        await _update_subscription(user_id, "free", "cancelled", "stripe", None)


async def _update_subscription(
    user_id: str, tier: Optional[str], status: str,
    provider: str, provider_id: Optional[str]
):
    """Update subscription in Supabase + invalidate Redis tier cache."""
    import httpx
    from api.services.cache import get_redis

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        logger.warning("supabase_not_configured_for_subscription_update")
        return

    # Update Supabase — one row per user_id, mutated in place. Migration
    # 013 added UNIQUE(user_id), so the `on_conflict=user_id` query param
    # tells PostgREST to actually merge instead of inserting a new row.
    # Without this, the previous flow inserted a row on every event:
    # cancel → status='cancelled' row alongside an existing status='active'
    # row → tier resolver still found the active one → user kept paid
    # access after cancellation. That's a revenue / fairness bug we'd
    # have shipped to prod without this fix.
    try:
        headers = {
            "apikey": settings.supabase_service_key,
            "Authorization": f"Bearer {settings.supabase_service_key}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates,return=minimal",
        }

        body = {
            "user_id": user_id,
            "status": status,
            "provider": provider,
        }
        if tier:
            body["tier"] = tier
        if provider_id:
            body["provider_subscription_id"] = provider_id

        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{settings.supabase_url}/rest/v1/subscriptions"
                f"?on_conflict=user_id",
                headers=headers,
                json=body,
            )
            if resp.status_code not in (200, 201, 204):
                logger.warning(
                    "subscription_upsert_unexpected_status",
                    extra={
                        "user_id": user_id,
                        "status_code": resp.status_code,
                        "body": resp.text[:200],
                    },
                )
    except Exception as e:
        logger.error("subscription_update_error", extra={"error": str(e)})

    # Invalidate Redis tier cache
    try:
        r = await get_redis()
        await r.delete(f"tier:{user_id}")
    except Exception:
        pass

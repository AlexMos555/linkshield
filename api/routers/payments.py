"""
Stripe Payments Router.

Handles:
  1. POST /api/v1/payments/create-checkout — create Stripe Checkout session
  2. POST /api/v1/payments/webhook — Stripe webhook handler
  3. POST /api/v1/payments/portal — Stripe Customer Portal link

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

# Stripe price IDs (set in env or hardcode after creating in Stripe Dashboard)
PRICE_IDS = {
    "personal_monthly": "price_PERSONAL_MONTHLY",  # $4.99/mo
    "personal_yearly": "price_PERSONAL_YEARLY",     # $49.99/yr
    "family_monthly": "price_FAMILY_MONTHLY",       # $9.99/mo
    "family_yearly": "price_FAMILY_YEARLY",         # $99.99/yr
}


_ALLOWED_REDIRECT_PREFIXES = ("https://cleanway.ai/", "https://www.cleanway.ai/")


class CheckoutRequest(BaseModel):
    plan: str  # "personal_monthly", "personal_yearly", "family_monthly", "family_yearly"
    success_url: str = "https://cleanway.ai/success"
    cancel_url: str = "https://cleanway.ai/pricing"

    @field_validator("success_url", "cancel_url")
    @classmethod
    def _must_be_cleanway_domain(cls, v: str) -> str:
        if not any(v.startswith(p) for p in _ALLOWED_REDIRECT_PREFIXES):
            raise ValueError("URL must be on cleanway.ai domain")
        return v


class CheckoutResponse(BaseModel):
    checkout_url: str


@router.post(
    "/create-checkout",
    response_model=CheckoutResponse,
    dependencies=[Depends(rate_limit(mode="sensitive", category="checkout"))],
)
async def create_checkout(
    request: CheckoutRequest,
    user: AuthUser = Depends(get_current_user),
):
    """Create a Stripe Checkout session for subscription."""
    try:
        import stripe
    except ImportError:
        raise HTTPException(500, "Stripe not configured")

    settings = get_settings()
    stripe_key = getattr(settings, "stripe_secret_key", "")
    if not stripe_key:
        raise HTTPException(500, "Stripe not configured")

    stripe.api_key = stripe_key

    price_id = PRICE_IDS.get(request.plan)
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


@router.post("/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events."""
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

    event_type = event["type"]
    data = event["data"]["object"]

    logger.info("webhook_received", extra={"type": event_type})

    if event_type == "checkout.session.completed":
        await _handle_checkout_completed(data)
    elif event_type == "customer.subscription.updated":
        await _handle_subscription_updated(data)
    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_deleted(data)
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

        session = stripe.billing_portal.Session.create(
            customer=customers.data[0].id,
            return_url="https://cleanway.ai/settings",
        )
        return {"portal_url": session.url}

    except HTTPException:
        raise
    except Exception as e:
        logger.error("portal_error", extra={"error": str(e)})
        raise HTTPException(500, "Failed to create portal session")


# ── Webhook handlers ──

async def _handle_checkout_completed(session: dict):
    """New subscription created."""
    user_id = session.get("metadata", {}).get("user_id")
    plan = session.get("metadata", {}).get("plan", "personal_monthly")
    subscription_id = session.get("subscription")

    if not user_id:
        logger.warning("checkout_no_user_id")
        return

    # Determine tier from plan
    tier = "personal" if "personal" in plan else "family" if "family" in plan else "personal"

    await _update_subscription(user_id, tier, "active", "stripe", subscription_id)
    logger.info("subscription_created", extra={"user_id": user_id, "tier": tier})


async def _handle_subscription_updated(subscription: dict):
    """Subscription changed (upgrade/downgrade/renewal)."""
    user_id = subscription.get("metadata", {}).get("user_id")
    status = subscription.get("status")  # active, past_due, canceled, etc.

    if not user_id:
        return

    mapped_status = "active" if status in ("active", "trialing") else "past_due" if status == "past_due" else "cancelled"
    await _update_subscription(user_id, None, mapped_status, "stripe", subscription.get("id"))


async def _handle_subscription_deleted(subscription: dict):
    """Subscription cancelled."""
    user_id = subscription.get("metadata", {}).get("user_id")
    if user_id:
        await _update_subscription(user_id, "free", "cancelled", "stripe", subscription.get("id"))
        logger.info("subscription_cancelled", extra={"user_id": user_id})


async def _handle_payment_failed(invoice: dict):
    """Payment failed."""
    subscription_id = invoice.get("subscription")
    logger.warning("payment_failed", extra={"subscription_id": subscription_id})


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

    # Update Supabase
    try:
        headers = {
            "apikey": settings.supabase_service_key,
            "Authorization": f"Bearer {settings.supabase_service_key}",
            "Content-Type": "application/json",
            "Prefer": "resolution=merge-duplicates",
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
            await client.post(
                f"{settings.supabase_url}/rest/v1/subscriptions",
                headers=headers,
                json=body,
            )
    except Exception as e:
        logger.error("subscription_update_error", extra={"error": str(e)})

    # Invalidate Redis tier cache
    try:
        r = await get_redis()
        await r.delete(f"tier:{user_id}")
    except Exception:
        pass

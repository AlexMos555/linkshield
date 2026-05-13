"""
Authentication service.

Validates Supabase JWTs and resolves user tier from database.
Tier is cached in Redis for 5 minutes to avoid per-request DB calls.
"""

import logging
from typing import Optional

import jwt
from fastapi import HTTPException, Header

from api.config import get_settings
from api.models.schemas import AuthUser, UserTier

logger = logging.getLogger("cleanway.auth")

# Cache tier in Redis for 5 minutes
_TIER_CACHE_TTL = 300


async def get_current_user(
    authorization: Optional[str] = Header(None),
) -> AuthUser:
    """
    Validate Supabase JWT and return authenticated user.
    Tier is resolved from Supabase DB (cached in Redis).
    """
    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required")

    token = authorization.replace("Bearer ", "").strip()
    if not token:
        raise HTTPException(status_code=401, detail="Token required")

    settings = get_settings()

    try:
        payload = jwt.decode(
            token,
            settings.supabase_jwt_secret,
            algorithms=["HS256"],
            audience="authenticated",
        )

        user_id = payload.get("sub")
        email = payload.get("email")

        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid or expired token")

        # Resolve tier from DB (cached in Redis)
        tier = await _resolve_user_tier(user_id)

        return AuthUser(
            id=user_id,
            email=email,
            tier=tier,
        )

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError as e:
        # Log the real error server-side, return generic message to client
        logger.warning("jwt_invalid", extra={"error": str(e)})
        raise HTTPException(status_code=401, detail="Invalid or expired token")


async def get_optional_user(
    authorization: Optional[str] = Header(None),
) -> Optional[AuthUser]:
    """Same as get_current_user but returns None for unauthenticated requests."""
    if not authorization:
        return None
    try:
        return await get_current_user(authorization)
    except HTTPException:
        return None


async def get_current_user_no_disposable(
    authorization: Optional[str] = Header(None),
) -> AuthUser:
    """`get_current_user` plus a domain check against the disposable
    blocklist (mailinator, 10minutemail, …).

    The /signup landing form already pre-flights via /auth/check-email,
    but anyone with our public Supabase anon key can call signInWithOtp
    directly and bypass that. This dependency is the second layer:
    even with a forged session, calls to expensive endpoints (think
    /check, which fans out to Google Safe Browsing + IPQS + half a
    dozen other paid providers) get refused before they burn quota.

    Paid users with disposable addresses are vanishingly rare (you don't
    pay $9/mo from a mailinator inbox), so we don't bother carving an
    exception for tier > free. If a real customer ever hits this,
    support email path stays open via /unsubscribe / /settings which
    use plain `get_current_user` so they can still update their address.
    """
    user = await get_current_user(authorization)
    # Lazy import — keeps the module-level import graph small for
    # tests that stub auth without loading the 5400-domain blocklist.
    from api.services.email_validator import is_disposable_email

    if user.email and is_disposable_email(user.email):
        logger.warning(
            "disposable_email_blocked_at_endpoint",
            extra={"user_id": user.id, "domain": user.email.rsplit("@", 1)[-1]},
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": (
                    "Free-tier checks aren't available for disposable / "
                    "throwaway email addresses. Update your account to a "
                    "real email or contact support."
                ),
                "support_url": "https://cleanway.ai/support",
            },
        )
    return user


async def _resolve_user_tier(user_id: str) -> UserTier:
    """
    Look up user's subscription tier.
    1. Check Redis cache (tier:{user_id})
    2. If miss, query Supabase subscriptions table
    3. Cache result for 5 minutes
    4. Fallback to free tier if DB unavailable
    """
    from api.services.cache import get_redis

    # 1. Check Redis cache
    try:
        r = await get_redis()
        cached_tier = await r.get(f"tier:{user_id}")
        if cached_tier:
            return UserTier(cached_tier)
    except Exception:
        pass

    # 2. Query Supabase
    tier = await _fetch_tier_from_supabase(user_id)

    # 3. Cache the result
    try:
        r = await get_redis()
        await r.setex(f"tier:{user_id}", _TIER_CACHE_TTL, tier.value)
    except Exception:
        pass

    return tier


async def _fetch_tier_from_supabase(user_id: str) -> UserTier:
    """
    Query Supabase for user's active subscription tier.
    Returns free tier if no active subscription or on error.
    """
    import httpx

    settings = get_settings()

    if not settings.supabase_url or not settings.supabase_service_key:
        logger.debug("Supabase not configured — defaulting to free tier")
        return UserTier.free

    try:
        # We grant paid tier on BOTH `active` AND `past_due`. Stripe sends
        # `past_due` while it's retrying a failed payment (typical dunning
        # window is 1-2 weeks); revoking the user's tier instantly on the
        # first declined card is hostile UX. If the retry cycle fails,
        # Stripe eventually sends `customer.subscription.deleted` which our
        # webhook maps to status='cancelled' — the user falls to free
        # naturally at that point.
        #
        # order=created_at.desc + limit=1: when a user has historical
        # cancelled rows alongside a current row, pick the most recent.
        # Otherwise the unordered query could return any row and a stale
        # cancelled row would override a fresh active subscription.
        url = (
            f"{settings.supabase_url}/rest/v1/subscriptions"
            f"?user_id=eq.{user_id}"
            f"&status=in.(active,past_due)"
            f"&select=tier"
            f"&order=created_at.desc"
            f"&limit=1"
        )
        headers = {
            "apikey": settings.supabase_service_key,
            "Authorization": f"Bearer {settings.supabase_service_key}",
        }

        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                if data and len(data) > 0:
                    tier_str = data[0].get("tier", "free")
                    try:
                        return UserTier(tier_str)
                    except ValueError:
                        logger.warning("Unknown tier value: %s", tier_str)
                        return UserTier.free

        return UserTier.free

    except Exception as e:
        logger.warning("supabase_tier_lookup_failed", extra={"error": str(e)})
        return UserTier.free  # Safe fallback

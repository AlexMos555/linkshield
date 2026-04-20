"""
Rate limiting service.

Three layers:
1. Per-user daily limit — sliding 24-hour window (free: 10, paid: 10,000)
2. Per-user burst limit — max N requests per M-second window (prevents API hammering)
3. Per-IP window limit — for public endpoints and unauthenticated access

All timestamps use UTC to avoid timezone inconsistencies.

Public API:
- `check_rate_limit(user, num_domains)` — authenticated per-user (legacy, used by /check)
- `check_ip_rate_limit(ip, category, limit, window_seconds)` — per-IP generic
- `rate_limit(cost=1, category="default", mode="user")` — FastAPI dependency factory

The dependency factory is the preferred surface for routers. Attach with
`Depends(rate_limit(...))` on any endpoint to enforce a limit at the framework
boundary, uniformly across the codebase.
"""

import logging
from datetime import datetime, timezone
from typing import Callable, Literal

from fastapi import Depends, HTTPException, Request

from api.config import get_settings
from api.models.schemas import AuthUser, UserTier
from api.services.auth import get_current_user
from api.services.cache import get_redis

logger = logging.getLogger("linkshield.rate_limiter")

RateLimitMode = Literal["user", "ip", "sensitive", "public"]


# ──────────────────────────────────────────────────────────────────────────────
# Per-user limits (daily + burst)
# ──────────────────────────────────────────────────────────────────────────────


async def check_rate_limit(user: AuthUser, num_domains: int = 1) -> int:
    """
    Check and increment daily + burst rate limit for authenticated user.

    Returns remaining API calls for today.
    Raises HTTPException(429) if limit exceeded.
    Fails open (returns full quota) if Redis is unreachable.
    """
    settings = get_settings()

    # Determine daily limit based on tier
    if user.tier in (UserTier.personal, UserTier.family, UserTier.business):
        daily_limit = settings.paid_tier_daily_limit
    else:
        daily_limit = settings.free_tier_daily_limit

    try:
        r = await get_redis()

        # ── Check burst limit first ──
        await _check_burst_limit(
            r, user.id, settings.burst_limit, settings.burst_window_seconds
        )

        # ── Check daily limit (UTC-based) ──
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        daily_key = f"rate:daily:{user.id}:{today}"

        # Atomic increment
        current = await r.incrby(daily_key, num_domains)

        # Set expiry on first call (25 hours to cover timezone edge cases)
        if current == num_domains:
            await r.expire(daily_key, 90000)  # 25 hours

        if current > daily_limit:
            logger.warning(
                "rate_limit_exceeded",
                extra={"user_id": user.id, "tier": user.tier.value, "used": current},
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Rate limit exceeded",
                    "daily_limit": daily_limit,
                    "used": current,
                    "tier": user.tier.value,
                    "upgrade_url": "https://linkshield.io/pricing",
                },
            )

        return daily_limit - current

    except HTTPException:
        raise  # Re-raise 429
    except Exception as e:
        # Redis unavailable — allow request but log warning
        logger.warning("rate_limiter_redis_unavailable", extra={"error": str(e)})
        return daily_limit  # Assume full quota available


async def _check_burst_limit(
    r, user_id: str, max_burst: int, window_seconds: int
) -> None:
    """
    Sliding window burst limiter.
    Prevents rapid-fire requests even from paid users.
    """
    burst_key = f"rate:burst:{user_id}"

    current = await r.incr(burst_key)

    # Set TTL on first increment
    if current == 1:
        await r.expire(burst_key, window_seconds)

    if current > max_burst:
        ttl = await r.ttl(burst_key)
        logger.warning(
            "burst_limit_exceeded",
            extra={"user_id": user_id, "count": current, "window": window_seconds},
        )
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Too many requests. Please slow down.",
                "retry_after_seconds": max(ttl, 1),
            },
        )


# ──────────────────────────────────────────────────────────────────────────────
# Per-IP / per-category limits
# ──────────────────────────────────────────────────────────────────────────────


async def check_ip_rate_limit(
    ip: str,
    category: str,
    limit: int,
    window_seconds: int,
) -> int:
    """
    Fixed-window counter per IP address per endpoint category.

    Used for public/unauthenticated endpoints where no user_id is available.
    Returns remaining quota in the current window.
    Raises HTTPException(429) if limit exceeded.
    Fails open if Redis unreachable.
    """
    # Normalize ip (IPv6 brackets, IPv4-mapped, empty strings)
    safe_ip = (ip or "unknown").strip().lower().lstrip("[").rstrip("]")
    key = f"rate:ip:{category}:{safe_ip}"

    try:
        r = await get_redis()
        current = await r.incr(key)

        if current == 1:
            await r.expire(key, window_seconds)

        if current > limit:
            ttl = await r.ttl(key)
            logger.warning(
                "ip_rate_limit_exceeded",
                extra={
                    "ip": safe_ip,
                    "category": category,
                    "count": current,
                    "limit": limit,
                },
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Too many requests from this IP. Please slow down.",
                    "category": category,
                    "retry_after_seconds": max(ttl, 1),
                },
            )

        return limit - current

    except HTTPException:
        raise
    except Exception as e:
        logger.warning("ip_rate_limiter_redis_unavailable", extra={"error": str(e)})
        return limit


async def check_sensitive_action_limit(user: AuthUser, category: str) -> int:
    """
    Stricter per-user limit for sensitive actions (payments, org creation).

    Uses a separate key space from daily quota so it doesn't consume user's
    normal quota.
    """
    settings = get_settings()
    key = f"rate:sensitive:{category}:{user.id}"
    try:
        r = await get_redis()
        current = await r.incr(key)
        if current == 1:
            await r.expire(key, settings.sensitive_action_window_seconds)

        if current > settings.sensitive_action_limit:
            ttl = await r.ttl(key)
            logger.warning(
                "sensitive_action_limit_exceeded",
                extra={
                    "user_id": user.id,
                    "category": category,
                    "count": current,
                },
            )
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Too many attempts for this action. Please wait.",
                    "category": category,
                    "retry_after_seconds": max(ttl, 1),
                },
            )
        return settings.sensitive_action_limit - current
    except HTTPException:
        raise
    except Exception as e:
        logger.warning(
            "sensitive_action_limiter_redis_unavailable", extra={"error": str(e)}
        )
        return settings.sensitive_action_limit


# ──────────────────────────────────────────────────────────────────────────────
# FastAPI dependency factories
# ──────────────────────────────────────────────────────────────────────────────


def _extract_client_ip(request: Request) -> str:
    """
    Resolve real client IP, honoring X-Forwarded-For from the proxy.

    Railway/Vercel terminate TLS and forward via headers — we take the first
    entry in XFF which is the original client.
    """
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def rate_limit(
    cost: int = 1,
    category: str = "default",
    mode: RateLimitMode = "user",
) -> Callable:
    """
    FastAPI dependency factory.

    Usage:
        @router.post("/some")
        async def handler(user: AuthUser = Depends(get_current_user),
                          _rate = Depends(rate_limit(cost=1, category="feedback"))):
            ...

    Modes:
    - "user"      — authenticated per-user daily+burst (requires Authorization)
    - "sensitive" — stricter per-user limit (payments, org/create)
    - "ip"        — per-IP public endpoint limit
    - "public"    — alias of "ip" (clearer at call sites)

    The dependency resolves the current user/IP itself — call sites only need to
    declare `Depends(rate_limit(...))` without passing the user.
    """

    if mode == "user":

        async def user_dep(
            user: AuthUser = Depends(get_current_user),
        ) -> None:
            await check_rate_limit(user, num_domains=cost)

        return user_dep

    if mode == "sensitive":

        async def sensitive_dep(
            user: AuthUser = Depends(get_current_user),
        ) -> None:
            await check_sensitive_action_limit(user, category)

        return sensitive_dep

    # "ip" / "public"
    async def ip_dep(request: Request) -> None:
        settings = get_settings()
        ip = _extract_client_ip(request)
        await check_ip_rate_limit(
            ip,
            category,
            settings.public_rate_limit_per_window,
            settings.public_rate_limit_window_seconds,
        )

    return ip_dep


def unsubscribe_rate_limit() -> Callable:
    """
    Dedicated dependency for unsubscribe endpoints.
    Uses its own (stricter) limit than generic public endpoints.
    """

    async def dep(request: Request) -> None:
        settings = get_settings()
        ip = _extract_client_ip(request)
        await check_ip_rate_limit(
            ip,
            "unsubscribe",
            settings.unsubscribe_limit_per_window,
            settings.unsubscribe_window_seconds,
        )

    return dep

"""
Rate limiting service.

Two layers:
1. Daily limit — sliding 24-hour window per user (free: 10, paid: 10,000)
2. Burst limit — max N requests per M-second window (prevents API hammering)

All timestamps use UTC to avoid timezone inconsistencies.
"""

import logging
import time
from datetime import datetime, timezone

from fastapi import HTTPException

from api.config import get_settings
from api.models.schemas import AuthUser, UserTier
from api.services.cache import get_redis

logger = logging.getLogger("linkshield.rate_limiter")


async def check_rate_limit(user: AuthUser, num_domains: int = 1) -> int:
    """
    Check and increment rate limit for user.
    Returns remaining API calls for today.
    Raises 429 if limit exceeded.
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
        await _check_burst_limit(r, user.id, settings.burst_limit, settings.burst_window_seconds)

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

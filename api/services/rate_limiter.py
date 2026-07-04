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

import hmac
import logging
from datetime import datetime, timezone
from typing import Callable, Literal

from fastapi import Depends, HTTPException, Request

from api.config import get_settings
from api.models.schemas import AuthUser, UserTier
from api.services.auth import get_current_user_including_deleted
from api.services.cache import get_redis

logger = logging.getLogger("cleanway.rate_limiter")

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
                    "upgrade_url": "https://cleanway.ai/pricing",
                },
            )

        return daily_limit - current

    except HTTPException:
        raise  # Re-raise 429
    except Exception as e:
        # Redis unavailable. Two failure modes, governed by config:
        #   fail-OPEN (default, dev/staging): log + allow the request.
        #   fail-CLOSED (RATE_LIMIT_FAIL_CLOSED=true, prod): refuse.
        # Without the latter, an attacker who realises Redis is down can
        # bypass per-user quotas entirely and burn our paid API budget.
        logger.warning("rate_limiter_redis_unavailable", extra={"error": str(e)})
        if get_settings().rate_limit_fail_closed:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "Rate limit service unavailable. Please retry shortly.",
                    "retry_after_seconds": 30,
                },
            )
        return daily_limit  # fail-open: assume full quota available


#
# Atomic INCR + first-write TTL.
#
# Naïve `INCR key; if current == 1: EXPIRE key seconds` has a crash
# window: if the process dies between the two commands, the key is
# left with value=1 and NO TTL — it persists forever, and the rate
# limiter treats the user as if they've already burned one slot and
# never refreshes. Three call sites had this bug (burst + IP + sensitive,
# audit finding backend-async / rate_limit).
#
# The Lua script runs atomically inside Redis: either both operations
# happen or neither does. Returns the post-increment count to the
# caller so the existing limit-check logic is unchanged.
_INCR_WITH_TTL_LUA = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""


async def _incr_with_ttl_on_first(r, key: str, window_seconds: int) -> int:
    """Atomic equivalent of `INCR + (EXPIRE if first)`. Returns the new value."""
    return int(await r.eval(_INCR_WITH_TTL_LUA, 1, key, window_seconds))


async def _check_burst_limit(
    r, user_id: str, max_burst: int, window_seconds: int
) -> None:
    """
    Sliding window burst limiter.
    Prevents rapid-fire requests even from paid users.
    """
    burst_key = f"rate:burst:{user_id}"

    current = await _incr_with_ttl_on_first(r, burst_key, window_seconds)

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


async def check_burst_only(user: AuthUser) -> None:
    """
    Burst rate limit without touching the daily quota.

    Used as a route-level dependency on endpoints whose work is partly
    cached (so a request that "uses 0 API calls" still consumes our
    /check endpoint's CPU + DB lookups). Without this, a paid user
    can hammer cached lookups at any rate they like — audit finding
    backend-security HIGH "/check has no route-level rate limit".

    Fails open on Redis outages unless `rate_limit_fail_closed=true`
    (matching the rest of the limiter's contract).
    """
    settings = get_settings()
    try:
        r = await get_redis()
        await _check_burst_limit(
            r, user.id, settings.burst_limit, settings.burst_window_seconds
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("burst_limiter_redis_unavailable", extra={"error": str(e)})
        if settings.rate_limit_fail_closed:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "Rate limit service unavailable. Please retry shortly.",
                    "retry_after_seconds": 30,
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
        current = await _incr_with_ttl_on_first(r, key, window_seconds)

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
        if get_settings().rate_limit_fail_closed:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "Rate limit service unavailable. Please retry shortly.",
                    "retry_after_seconds": 30,
                },
            )
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
        current = await _incr_with_ttl_on_first(
            r, key, settings.sensitive_action_window_seconds
        )

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
        if settings.rate_limit_fail_closed:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "Rate limit service unavailable. Please retry shortly.",
                    "retry_after_seconds": 30,
                },
            )
        return settings.sensitive_action_limit


# ──────────────────────────────────────────────────────────────────────────────
# FastAPI dependency factories
# ──────────────────────────────────────────────────────────────────────────────


def _extract_client_ip(request: Request) -> str:
    """
    Resolve real client IP, honoring X-Forwarded-For only when the
    immediate upstream is a trusted proxy.

    Threat model (audit backend-security HIGH): a request that arrives
    direct (no proxy in front) carries whatever X-Forwarded-For the
    attacker sent. Blindly taking `xff.split(',')[0]` let any caller
    pick their own rate-limit key — send a different XFF on every
    request and effectively bypass per-IP quotas entirely.

    The fix:
      - When the immediate caller (request.client.host) IS in our
        trust list, the proxy is responsible for replacing/appending
        the client's real IP — we honor the leftmost XFF entry.
      - When it is NOT, ignore XFF and use the TCP peer address.
        That's still a rate-limit signal (it caps the offending box),
        just one the caller can't forge.

    `trusted_proxy_cidrs` is empty by default — locally everything
    runs unproxied, so we keep the legacy "leftmost XFF" behavior.
    Production sets it to Railway's egress range (also covers Vercel
    when it sits in front of the API).
    """
    settings = get_settings()
    peer = request.client.host if request.client else None

    raw_trusted = (settings.trusted_proxy_cidrs or "").strip()
    trusted_cidrs = [c.strip() for c in raw_trusted.split(",") if c.strip()]

    xff_trusted: bool
    if not trusted_cidrs:
        # No trust list configured → behave the same as before
        # (dev/local where there's no proxy in front anyway). Safe
        # because validate_settings will require this to be set
        # before flipping rate_limit_fail_closed on in prod.
        xff_trusted = True
    elif peer is None:
        xff_trusted = False
    else:
        xff_trusted = _ip_in_any_cidr(peer, trusted_cidrs)

    xff = request.headers.get("x-forwarded-for") if xff_trusted else None
    if xff:
        return xff.split(",")[0].strip()
    if peer:
        return peer
    return "unknown"


def _ip_in_any_cidr(ip_str: str, cidrs: list[str]) -> bool:
    """True if `ip_str` matches any CIDR. Tolerant of bad input —
    a malformed setting value silently denies trust rather than
    crashing the rate limit dependency."""
    import ipaddress

    try:
        ip = ipaddress.ip_address(ip_str.strip().lstrip("[").rstrip("]"))
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


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

    # Both auth-flavoured rate-limit modes depend on the
    # soft-delete-bypassing user resolver (`get_current_user_including_deleted`).
    # Reason: a rate limit is a quota concept, NOT a soft-delete gate.
    # The route's own `Depends(get_current_user)` is what enforces the
    # 410 lock on regular endpoints; rate_limit just needs a user_id
    # to key off. If we left rate_limit depending on the strict
    # variant, then any route that uses BOTH `Depends(rate_limit(...))`
    # AND `Depends(get_current_user_including_deleted)` (like /restore
    # and /export) would still hit the 410 via the rate-limit dep's
    # transitive resolution.

    if mode == "user":

        async def user_dep(
            user: AuthUser = Depends(get_current_user_including_deleted),
        ) -> None:
            await check_rate_limit(user, num_domains=cost)

        return user_dep

    if mode == "sensitive":

        async def sensitive_dep(
            user: AuthUser = Depends(get_current_user_including_deleted),
        ) -> None:
            await check_sensitive_action_limit(user, category)

        return sensitive_dep

    # "ip" / "public"
    async def ip_dep(request: Request) -> None:
        settings = get_settings()
        # Benchmark bypass: a request carrying the correct X-Cleanway-Benchmark
        # header skips the IP limit. Only active when the token is configured
        # (non-empty) — production requests without the header are unaffected.
        # Constant-time compare so the token can't be recovered by timing.
        bypass = settings.benchmark_bypass_token
        if bypass:
            presented = request.headers.get("X-Cleanway-Benchmark", "")
            if presented and hmac.compare_digest(presented, bypass):
                return
        ip = _extract_client_ip(request)
        # DoH is a DNS resolver: a single page load fires dozens of queries,
        # so the 60/hour public limit would break real resolution. Give it a
        # realistic device-level budget instead. Other public categories keep
        # the standard public limit.
        if category == "doh":
            limit = settings.doh_rate_limit_per_window
            window = settings.doh_rate_limit_window_seconds
        else:
            limit = settings.public_rate_limit_per_window
            window = settings.public_rate_limit_window_seconds
        await check_ip_rate_limit(ip, category, limit, window)

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

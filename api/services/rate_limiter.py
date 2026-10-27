"""
Rate limiting service.

Three layers:
1. Per-user daily limit — sliding 24-hour window (free: 10, paid: 10,000)
2. Per-user burst limit — max N requests per M-second window (prevents API hammering)
3. Per-IP window limit — for public endpoints and unauthenticated access
4. Per-install window limit — public checks from a client that identifies its
   install (`X-Cleanway-Install`), under a higher per-IP ceiling (CGNAT)

All timestamps use UTC to avoid timezone inconsistencies.

Public API:
- `check_rate_limit(user, num_domains)` — authenticated per-user (legacy, used by /check)
- `refund_daily_quota(user, num_domains)` — give back what /check charged but did not analyse
- `check_ip_rate_limit(ip, category, limit, window_seconds)` — per-IP generic
- `rate_limit(cost=1, category="default", mode="user")` — FastAPI dependency factory

The dependency factory is the preferred surface for routers. Attach with
`Depends(rate_limit(...))` on any endpoint to enforce a limit at the framework
boundary, uniformly across the codebase.
"""

import hashlib
import hmac
import logging
import re
from datetime import datetime, timezone
from typing import Callable, Literal, Optional

from fastapi import Depends, HTTPException, Request

from api.config import get_settings
from api.models.schemas import AuthUser, UserTier
from api.services.audit_log import hash_ip
from api.services.auth import get_current_user_including_deleted
from api.services import security_alerts
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
        daily_key = _daily_key(user)

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
            await security_alerts.record("rate_limited", key="daily_quota")
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


def _daily_key(user: AuthUser) -> str:
    return f"rate:daily:{user.id}:{datetime.now(timezone.utc).strftime('%Y-%m-%d')}"


async def refund_daily_quota(user: AuthUser, num_domains: int) -> None:
    """Give back `num_domains` that check_rate_limit charged but that were
    not analysed after all (/check: its batch window ran out — routers/check.py).
    Best effort: on a Redis error the charge stands."""
    if num_domains <= 0:
        return
    try:
        r = await get_redis()
        await r.decrby(_daily_key(user), num_domains)
    except Exception as e:  # noqa: BLE001 — a refund must never fail the response
        logger.warning("rate_limit_refund_failed", extra={"error": str(e)})


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
        await security_alerts.record("rate_limited", key="burst")
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


# Categories whose availability outranks limiter strictness (see below).
FAIL_OPEN_CATEGORIES: frozenset[str] = frozenset({"doh", "blocklist"})


def ip_rate_key(ip: Optional[str]) -> str:
    """The per-IP rate-limit bucket for an address.

    IPv4 is the address itself. IPv6 is its /64: an ISP gives each
    subscriber at least a /64 and devices rotate addresses inside it
    (privacy extensions), so keying the full address let a client pick a
    fresh limit on every request. An IPv4-mapped IPv6 address
    (::ffff:198.51.100.7, what a dual-stack socket reports for an IPv4
    peer) is the IPv4 client it wraps. Anything unparsable keeps its
    trimmed, lower-cased spelling, so it can still be limited.
    """
    import ipaddress

    raw = (ip or "").strip().lower().lstrip("[").rstrip("]")
    if not raw:
        return "unknown"
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    if isinstance(addr, ipaddress.IPv6Address):
        if addr.ipv4_mapped is not None:
            return str(addr.ipv4_mapped)
        # Built from the integer so a zone id (fe80::1%eth0) is dropped too.
        return str(ipaddress.IPv6Network((int(addr) >> 64 << 64, 64)))
    return str(addr)


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
    # One bucket per client: IPv6 by /64, IPv4-mapped as IPv4 (ip_rate_key).
    safe_ip = ip_rate_key(ip)
    return await _check_window_limit(
        f"rate:ip:{category}:{safe_ip}", category, limit, window_seconds,
        # Logs keep only the keyed hash: the privacy policy promises the raw
        # address lives only in the Redis counter, for up to an hour.
        who={"ip_hash": hash_ip(safe_ip)}, error="Too many requests from this IP. Please slow down.",
    )


async def check_install_rate_limit(
    install_key: str,
    category: str,
    limit: int,
    window_seconds: int,
) -> int:
    """Fixed-window counter per app install (see `install_key`). Same
    contract as `check_ip_rate_limit`."""
    return await _check_window_limit(
        f"rate:install:{category}:{install_key}", category, limit, window_seconds,
        who={"install": install_key[:8]}, error="Too many checks from this app. Please slow down.",
    )


async def _check_window_limit(
    key: str,
    category: str,
    limit: int,
    window_seconds: int,
    who: dict,
    error: str,
    fallback: Optional[Callable[[], Optional[int]]] = None,
) -> int:
    """The fixed window both limiters share, with the fail-open/closed policy.

    `fallback`, when given, decides instead of that policy while Redis is
    unavailable: None admits the request, a number of seconds is a 429.
    """
    try:
        r = await get_redis()
        current = await _incr_with_ttl_on_first(r, key, window_seconds)

        if current > limit:
            ttl = await r.ttl(key)
            logger.warning(
                "ip_rate_limit_exceeded",
                extra={
                    **who,
                    "category": category,
                    "count": current,
                    "limit": limit,
                },
            )
            await security_alerts.record("rate_limited", key=category)
            raise _limited(category, error, max(ttl, 1))

        return limit - current

    except HTTPException:
        raise
    except Exception as e:
        logger.warning("ip_rate_limiter_redis_unavailable", extra={"error": str(e), "category": category})
        if fallback is not None:
            retry = fallback()
            if retry is None:
                return limit
            logger.warning("ip_rate_limit_exceeded", extra={**who, "category": category, "fallback": True})
            raise _limited(category, error, retry)
        # DNS is the one path that must never 503: for anyone whose phone
        # points at /dns-query, "rate limiter unavailable" would mean "no
        # site on the internet resolves" for the length of a Redis blip.
        # Everything else keeps the production fail-closed posture.
        if category in FAIL_OPEN_CATEGORIES:
            return limit
        if get_settings().rate_limit_fail_closed:
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "Rate limit service unavailable. Please retry shortly.",
                    "retry_after_seconds": 30,
                },
            )
        return limit


def _limited(category: str, error: str, retry: int) -> HTTPException:
    return HTTPException(
        status_code=429,
        detail={
            "error": error,
            "category": category,
            "retry_after_seconds": retry,
        },
        # The standard header too: the extension pauses its link
        # lookups until then instead of retrying into the limit.
        headers={"Retry-After": str(retry)},
    )


async def check_sensitive_action_limit(
    user: AuthUser, category: str, limit: Optional[int] = None
) -> int:
    """
    Stricter per-user limit for sensitive actions (payments, org creation).

    Uses a separate key space from daily quota so it doesn't consume user's
    normal quota. `limit` overrides SENSITIVE_ACTION_LIMIT for one category
    (per hour window) — account screens and device heartbeats need more than
    10 an hour, but must not eat the free user's daily check quota either.
    """
    settings = get_settings()
    allowed = limit if limit is not None else settings.sensitive_action_limit
    key = f"rate:sensitive:{category}:{user.id}"
    try:
        r = await get_redis()
        current = await _incr_with_ttl_on_first(
            r, key, settings.sensitive_action_window_seconds
        )

        if current > allowed:
            ttl = await r.ttl(key)
            logger.warning(
                "sensitive_action_limit_exceeded",
                extra={
                    "user_id": user.id,
                    "category": category,
                    "count": current,
                },
            )
            await security_alerts.record("rate_limited", key=f"sensitive:{category}")
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Too many attempts for this action. Please wait.",
                    "category": category,
                    "retry_after_seconds": max(ttl, 1),
                },
            )
        return allowed - current
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
        return allowed


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
        trust list, walk X-Forwarded-For from the RIGHT and take the
        first address that is not itself one of our proxies. Railway's
        edge APPENDS the address it saw to whatever header the client
        sent, so the leftmost entry is attacker-chosen (a client that
        prepends a fake IP would otherwise pick its own rate-limit key).
      - When it is NOT, ignore XFF and use the TCP peer address.
        That's still a rate-limit signal (it caps the offending box),
        just one the caller can't forge.

    `trusted_proxy_cidrs` is empty by default — locally everything
    runs unproxied, so we keep the legacy "leftmost XFF" behavior there
    (no proxy list → no way to tell our hops from the client's).
    Production sets it to Railway's egress range (also covers Vercel
    when it sits in front of the API).

    Cloudflare in front (orange cloud, docs/runbooks/cloudflare-proxy.md):
    the chain is client → Cloudflare edge → Railway edge → app, so the
    walk's first untrusted hop is a Cloudflare edge address — keying on it
    would put every user behind that edge into one bucket. When (and only
    when) that hop is inside Cloudflare's published ranges, the client is
    CF-Connecting-IP (Cloudflare overwrites it), else the address
    Cloudflare appended just left of its own hop. The header is never read
    otherwise: anyone can send it straight to the Railway origin.
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

    raw_xff = request.headers.get("x-forwarded-for")
    from api.services import proxy_trust
    proxy_trust.observe(peer, bool(raw_xff), bool(trusted_cidrs), xff_trusted)

    cf_header = request.headers.get("cf-connecting-ip")
    xff = raw_xff if xff_trusted else None
    if xff:
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        if hops:
            if not trusted_cidrs:
                return hops[0]
            return _client_from_hops(hops, trusted_cidrs, cf_header)
    if cf_header and trusted_cidrs:
        proxy_trust.observe_cloudflare("cloudflare_header_ignored")
    if peer:
        return peer
    return "unknown"


def _client_from_hops(hops: list[str], trusted_cidrs: list[str], cf_header: Optional[str]) -> str:
    """The standard right-to-left X-Forwarded-For walk, aware of Cloudflare.

    Every hop to the right of the client was appended by a proxy we trust,
    so skip those; the first address that is not one of our proxies is the
    client as our edge saw it. Anything further left was written by the
    client and is never used. A malformed entry is not a trusted proxy, so it
    stops the walk too (our edge never writes one). If every hop is a
    trusted proxy, the leftmost is all we have.

    If that first hop is a Cloudflare edge, the client is CF-Connecting-IP,
    or (header missing/garbled) the one address Cloudflare appended left of it.
    """
    from api.services import proxy_trust

    for i in range(len(hops) - 1, -1, -1):
        hop = hops[i]
        # Checked before the trust list, so adding Cloudflare's ranges to
        # TRUSTED_PROXY_CIDRS (older runbook advice) changes nothing.
        if proxy_trust.is_cloudflare(hop):
            cf_ip = proxy_trust.parse_ip(cf_header)
            if cf_ip is not None:
                proxy_trust.observe_cloudflare("cloudflare|client=header")
                return str(cf_ip)
            proxy_trust.observe_cloudflare("cloudflare|client=xff")
            # Exactly one step left: what Cloudflare saw. Further left is
            # client-written, even when it looks like a Cloudflare address.
            return hops[i - 1] if i > 0 else hop
        if _ip_in_any_cidr(hop, trusted_cidrs):
            continue
        if cf_header:
            proxy_trust.observe_cloudflare("cloudflare_header_ignored")
        return hop
    return hops[0]


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


# ── Per-install identity for CGNAT ──
#
# Tele2 puts hundreds to thousands of phones behind one public IPv4, so a
# per-IP limit meant one busy gateway 429'd everyone behind it — and the
# phone's background link check then failed silently. A client may send a
# random per-install UUID; the server keeps only a SHA-256 of it, as a
# rate-limit key that expires with its window. It is never logged in full,
# stored anywhere else, or joined to anything. Anything that is not a
# canonical UUID is ignored (the request is limited per IP, as before), so a
# malformed header can never loosen a limit.
INSTALL_HEADER = "X-Cleanway-Install"
_INSTALL_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)


def install_key(request: Request) -> Optional[str]:
    """Hashed rate-limit key for a valid `X-Cleanway-Install`, else None."""
    raw = (request.headers.get(INSTALL_HEADER) or "").strip().lower()
    if not raw:
        return None
    if not _INSTALL_ID_RE.fullmatch(raw):
        logger.info("install_header_rejected", extra={"length": len(raw)})
        return None
    return hashlib.sha256(raw.encode("ascii")).hexdigest()[:32]


def benchmark_bypass(request: Request) -> bool:
    """A request carrying the configured X-Cleanway-Benchmark token.

    Only active when the token is configured (non-empty) — production
    requests without the header are unaffected. Constant-time compare so the
    token can't be recovered by timing.
    """
    bypass = get_settings().benchmark_bypass_token
    if not bypass:
        return False
    presented = request.headers.get("X-Cleanway-Benchmark", "")
    return bool(presented) and hmac.compare_digest(presented, bypass)


async def _install_limits(request: Request, category: str, ikey: str) -> None:
    """Per-install quota under a per-IP ceiling. The install is checked first
    so an install already over its own quota does not also eat into the
    ceiling everyone behind the same address shares."""
    settings = get_settings()
    window = settings.public_rate_limit_window_seconds
    await check_install_rate_limit(
        ikey, category, settings.public_install_rate_limit_per_window, window,
    )
    await check_ip_rate_limit(
        _extract_client_ip(request), f"{category}:ip_ceiling",
        settings.public_install_ip_ceiling_per_window, window,
    )


def rate_limit(
    cost: int = 1,
    category: str = "default",
    mode: RateLimitMode = "user",
    install_aware: bool = False,
    limit: Optional[int] = None,
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

    `install_aware=True` (ip modes only): a request with a valid
    `X-Cleanway-Install` header is limited per install under a per-IP
    ceiling instead of per IP (see `install_key`).

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
            await check_sensitive_action_limit(user, category, limit)

        return sensitive_dep

    # "ip" / "public"
    async def ip_dep(request: Request) -> None:
        settings = get_settings()
        # Benchmark bypass: a request carrying the correct X-Cleanway-Benchmark
        # header skips the IP limit.
        if benchmark_bypass(request):
            return
        ikey = install_key(request) if install_aware else None
        if ikey:
            await _install_limits(request, category, ikey)
            return
        ip = _extract_client_ip(request)
        # DoH is a DNS resolver: a single page load fires dozens of queries,
        # so the 60/hour public limit would break real resolution. Give it a
        # realistic device-level budget instead. Other public categories keep
        # the standard public limit.
        if category == "doh":
            limit = settings.doh_rate_limit_per_window
            window = settings.doh_rate_limit_window_seconds
        elif category == "blocklist":
            # Phones sync every ~2h with If-None-Match; CGNAT shares an IP
            # across hundreds of them. Cheap bytes — be generous.
            limit = settings.blocklist_rate_limit_per_window
            window = settings.blocklist_rate_limit_window_seconds
        else:
            limit = settings.public_rate_limit_per_window
            window = settings.public_rate_limit_window_seconds
        await check_ip_rate_limit(ip, category, limit, window)

    return ip_dep


def doh_rate_check(request: Request) -> Optional[int]:
    """None when this DNS query is within budget, else seconds to wait."""
    from api.services import doh_metrics
    if benchmark_bypass(request):
        return None
    retry = doh_metrics.limiter().check(ip_rate_key(_extract_client_ip(request)))
    if retry is not None:
        doh_metrics.METRICS.inc("rate_limited")
    return retry


async def doh_rate_limit(request: Request) -> None:
    """Per-IP DNS budget for /dns-query, kept IN PROCESS
    (api/services/doh_metrics.WindowLimiter) instead of a Redis INCR per DNS
    query: no round trip on the hot path and nothing to fail when Redis is
    down. Same settings (doh_rate_limit_per_window / _window_seconds) and the
    same benchmark bypass as the "ip" mode's doh category. The fast path
    (api/services/doh_fastpath.py) applies the same check itself."""
    retry = doh_rate_check(request)
    if retry is not None:
        raise HTTPException(
            status_code=429,
            detail={"error": "Too many DNS queries from this IP.", "retry_after_seconds": retry},
            headers={"Retry-After": str(retry)},
        )


def unsubscribe_rate_limit(verify: Callable[[str], Optional[dict]]) -> Callable:
    """
    Dependency for the unsubscribe endpoints; `verify` is the router's token
    check (api/routers/email_unsubscribe.verify_token).

    A link that verifies is limited per subscription (user + template), GET
    and POST counted apart, and never per IP. RFC 8058 one-click POSTs come
    from Gmail's and Yahoo's shared egress addresses, and link scanners
    (Safe Links, Proofpoint) GET from small pools of their own: one per-IP
    budget let other people's one-clicks and scanner GETs spend it, and a
    real one-click got 429 and was lost. The signed link is the only
    credential, so the subscription is what bounds its holder (each POST is
    a Supabase read and write). The key is a hash of the verified payload,
    not the link as sent: lenient base64 gives one link many spellings.

    While Redis is down the same budget is counted in this worker process
    (_unsubscribe_fallback): an unsubscribe must not be lost to a Redis blip,
    and one link must not become unlimited Supabase traffic either. Plain
    fail-open (#313) let 50 one-clicks of one link through as 50 reads and
    writes with rate_limit_fail_closed on (measured 2026-10-27).

    A link that does not verify (forged, tampered, expired) is limited per
    IP, both methods together, under the usual fail-open/closed policy.
    """

    async def dep(request: Request, token: str) -> None:
        settings = get_settings()
        window = settings.unsubscribe_window_seconds
        payload = verify(token)
        if payload is None:
            await check_ip_rate_limit(
                _extract_client_ip(request),
                "unsubscribe",
                settings.unsubscribe_limit_per_window,
                window,
            )
            return
        subscription = f"{payload['uid']}\0{payload['template']}".encode("utf-8")
        key = hashlib.sha256(subscription).hexdigest()[:32]
        method = request.method.lower()
        limit = settings.unsubscribe_link_limit_per_window
        await _check_window_limit(
            f"rate:unsubscribe:{method}:{key}",
            f"unsubscribe_{method}",
            limit,
            window,
            who={}, error="Too many requests for this unsubscribe link. Please wait.",
            fallback=lambda: _unsubscribe_fallback(method, limit, window).check(key),
        )

    return dep


# Per-process windows for verified unsubscribe links while Redis is down, one
# per method. With N workers in all, one link gets at most N times its budget.
_unsubscribe_windows: dict = {}


def _unsubscribe_fallback(method: str, limit: int, window: int):
    from api.services.doh_metrics import WindowLimiter

    lim = _unsubscribe_windows.get(method)
    if lim is None or lim.limit != limit or lim.window_s != window:
        lim = _unsubscribe_windows[method] = WindowLimiter(limit, window)
    return lim


def reset_for_tests() -> None:
    _unsubscribe_windows.clear()

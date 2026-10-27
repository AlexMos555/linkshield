"""
Domain check endpoint.

Architecture for speed:
  1. Cache check (<1ms)
  2. Allowlist check (<1ms) — top 100K popular domains, instant safe
  3. Full analysis (~3-5s) — only for unknown domains

This means 95%+ of requests return in <10ms.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from api.models.schemas import (
    AuthUser,
    CheckRequest,
    CheckResponse,
    DomainResult,
    DomainReason,
    RiskLevel,
    ConfidenceLevel,
)
from api.config import get_settings
from api.services.analysis_budget import Deadline
from api.services.analyzer import analyze_domain, rule_only_result
from api.services import load_shedding
from api.services import verdict_basis as vb
from api.services.cleanway_blocklist import listed_as
# /check is the most expensive auth-required endpoint — fans out to
# Google Safe Browsing + IPQS + a half dozen other paid providers per
# domain. Use the disposable-email-blocking variant so a sophisticated
# bypass of the /signup pre-flight (calling Supabase Auth directly with
# our public anon key) still doesn't burn API budget.
from api.services.auth import get_current_user_no_disposable as get_current_user
from api.services.cache import get_cached_result, cache_result
from api.services.rate_limiter import check_burst_only, check_rate_limit, refund_daily_quota
from api.services.domain_validator import validate_domain, normalize_domain, DomainValidationError

router = APIRouter(prefix="/api/v1", tags=["check"])

# A batch may start analyses for this many analysis budgets (6 s at the
# default 3 s), each while at least half a budget is left.
_BATCH_WINDOW_BUDGETS = 2


async def _analyse_batch(domains: list[str], slots: int) -> list:
    """Analyse `domains` at most `slots` at a time — the request's share of
    the worker's fresh-analysis budget (load_shedding.fresh_share), so one
    big batch cannot take every slot; the rest wait their turn. Each gets
    what is left of the batch's window, at most one analysis budget. One that
    could not start in time is None: the caller answers it on the address
    alone, marked partial. Exceptions are returned, not raised."""
    budget = get_settings().analysis_budget_seconds
    window = Deadline(budget * _BATCH_WINDOW_BUDGETS)
    turn = asyncio.Semaphore(slots)

    async def one(domain: str):
        async with turn:
            left = window.remaining()
            if left < budget / 2:
                return None
            return await analyze_domain(domain, budget_s=min(budget, left))

    return await asyncio.gather(*[one(d) for d in domains], return_exceptions=True)


def _quick_allowlist_check(domain: str) -> DomainResult | None:
    """
    Fast path: a popular domain gets an instant safe result, no API calls.

    Uses the ONE allowlist rule the public check and the scorer share,
    is_trusted_top_domain(): this path used to keep its own shorter hosting
    list, so a tenant on a shared platform the public check already refused
    (gwcu.us.org, a tw1.ru page) was still "known legitimate" here.
    """
    from api.services.scoring import TOP_10K_RANKS, is_trusted_top_domain, top_domain_key

    if not is_trusted_top_domain(domain):
        return None  # Unknown or shared platform — needs full analysis

    # The entry the allowlist matched: amazon.co.uk for www.amazon.co.uk,
    # where the last two labels named 'co.uk' and found no rank.
    base = top_domain_key(domain)
    rank = TOP_10K_RANKS.get(base)
    detail = f"Ranked #{rank} globally" if rank else "In global top 100K"
    return DomainResult(
        domain=domain,
        score=0,
        level=RiskLevel.safe,
        confidence=ConfidenceLevel.high,
        reasons=[DomainReason(
            signal="known_legitimate",
            detail=f"Known legitimate domain: {base}. {detail}",
            weight=-50,
        )],
        verdict_basis=vb.BASIS_ALLOWLIST,
    )


@router.post("/check", response_model=CheckResponse)
async def check_domains(
    request: CheckRequest,
    user: AuthUser = Depends(get_current_user),
):
    """
    Check one or more domains for phishing/safety.

    Speed tiers:
      - Cached: <1ms (Redis)
      - Allowlisted: <1ms (top 100K popular domains, no API calls)
      - Full analysis: 2-5s (14 parallel checks)

    Privacy: only domain names processed. Full URLs never logged.
    """
    # Burst rate limit BEFORE we touch the cache, so a user firing
    # 1000 requests/sec at known-cached domains still gets throttled.
    # Daily quota is still keyed off `needs_analysis` further down —
    # cached lookups are free in API-spend terms (correctly), they
    # just can't be a free DDoS path. (Audit backend-security HIGH
    # "/check has no route-level rate limit".)
    #
    # NOTE: this MUST come after the docstring, otherwise the docstring
    # is no longer the first statement of the function and FastAPI can't
    # pick it up for OpenAPI generation (causing the openapi-drift CI
    # job to fail with a stale committed schema).
    await check_burst_only(user)
    # Rate limit (counts only domains that need full analysis)
    # Pre-count how many will actually hit the API
    unique_domains = list(set(normalize_domain(d) for d in request.domains if d.strip()))

    # ── Step 1: Cache check ──
    results: dict[str, DomainResult] = {}
    uncached: list[str] = []

    for domain in unique_domains:
        # Validate domain format
        try:
            domain = validate_domain(domain)
        except DomainValidationError:
            results[domain] = DomainResult(
                domain=domain, score=0, level=RiskLevel.caution,
                reasons=[DomainReason(signal="invalid", detail="Invalid domain format", weight=0)],
                verdict_basis=vb.BASIS_HEURISTICS,
            )
            continue

        # Our own published blocklist first — the list the phone blocks — so
        # a verdict cached before the host was listed cannot outlive it.
        listed = await listed_as(domain)
        if listed:
            results[domain] = vb.blocklist_result(domain, listed)
            continue

        cached = await get_cached_result(domain)
        if cached:
            # Results cached before verdict_basis existed get one derived
            # from their reasons, so every result in the response has one.
            results[domain] = cached.model_copy(update={"verdict_basis": vb.basis_of(cached)})
        else:
            uncached.append(domain)

    # ── Step 1.5: Check user's personal whitelist ──
    # Fail-open on Redis blip — the whitelist is an opt-in convenience,
    # not a security primitive. Log so a real outage is visible in
    # Sentry breadcrumb context instead of silently treating every
    # request as "no whitelist". (Audit backend MEDIUM "Silent bare
    # except on user whitelist Redis lookup swallows errors with no
    # logging".)
    user_whitelist: set[str] = set()
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        wl = await r.smembers(f"whitelist:{user.id}")
        user_whitelist = set(wl) if wl else set()
    except Exception as e:
        import logging
        logging.getLogger("cleanway.check").debug(
            "user_whitelist_lookup_failed", extra={"error": str(e)}
        )

    for domain in list(uncached):
        if domain in user_whitelist:
            result = DomainResult(
                domain=domain, score=0, level=RiskLevel.safe,
                confidence=ConfidenceLevel.high,
                reasons=[DomainReason(signal="user_whitelist", detail="In your personal whitelist", weight=-50)],
                verdict_basis=vb.BASIS_ALLOWLIST,
            )
            results[domain] = result
            uncached.remove(domain)

    # ── Step 2: Fast allowlist check (no API calls!) ──
    needs_analysis: list[str] = []
    for domain in uncached:
        quick = _quick_allowlist_check(domain)
        if quick:
            results[domain] = quick
            await cache_result(quick)  # Cache for future requests
        else:
            needs_analysis.append(domain)

    # ── Step 3: Full analysis for unknown domains (parallel) ──
    # Up to the request's share of the worker's fresh-analysis slots
    # (api/services/load_shedding.py), the rest of the batch waiting its
    # turn. None free: 503 before any quota is spent. What the batch's window
    # had no room for gets the verdict on the address alone, marked partial —
    # given back to the quota, not cached.
    remaining = None  # No API calls used
    if needs_analysis:
        granted = load_shedding.FRESH_ANALYSES.try_acquire(load_shedding.fresh_share(len(needs_analysis)))
        if not granted:
            raise load_shedding.Overloaded(load_shedding.FRESH_ANALYSES.name)
        try:
            # Rate limit only for domains that need full analysis
            remaining = await check_rate_limit(user, num_domains=len(needs_analysis))
            analyses = await _analyse_batch(needs_analysis, granted)
        finally:
            load_shedding.FRESH_ANALYSES.release(granted)
        deferred = [d for d, result in zip(needs_analysis, analyses) if result is None]
        if deferred:
            await refund_daily_quota(user, len(deferred))
            remaining += len(deferred)

        for domain, result in zip(needs_analysis, analyses):
            if result is None:
                results[domain] = rule_only_result(domain)
            elif isinstance(result, Exception):
                results[domain] = DomainResult(
                    domain=domain, score=25, level=RiskLevel.caution,
                    reasons=[DomainReason(signal="analysis_error", detail="Check failed, proceed with caution", weight=0)],
                    verdict_basis=vb.BASIS_HEURISTICS,
                )
            else:
                results[domain] = result
                await cache_result(result)

    # Return in original order
    ordered = []
    for d in request.domains:
        key = normalize_domain(d)
        try:
            key = validate_domain(key)
        except DomainValidationError:
            pass
        if key in results:
            ordered.append(results[key])

    return CheckResponse(
        results=ordered,
        checked_at=datetime.now(timezone.utc).isoformat(),
        api_calls_remaining=remaining,
    )

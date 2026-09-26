"""
Domain check endpoint.

Architecture for speed:
  1. Cache check (<1ms)
  2. Allowlist check (<1ms) — Tranco 100K, instant safe
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
from api.services.analyzer import analyze_domain
from api.services import verdict_basis as vb
from api.services.cleanway_blocklist import listed_as
# /check is the most expensive auth-required endpoint — fans out to
# Google Safe Browsing + IPQS + a half dozen other paid providers per
# domain. Use the disposable-email-blocking variant so a sophisticated
# bypass of the /signup pre-flight (calling Supabase Auth directly with
# our public anon key) still doesn't burn API budget.
from api.services.auth import get_current_user_no_disposable as get_current_user
from api.services.cache import get_cached_result, cache_result
from api.services.rate_limiter import check_burst_only, check_rate_limit
from api.services.domain_validator import validate_domain, normalize_domain, DomainValidationError

router = APIRouter(prefix="/api/v1", tags=["check"])


def _quick_allowlist_check(domain: str) -> DomainResult | None:
    """
    Fast path: a popular domain gets an instant safe result, no API calls.

    Uses the ONE allowlist rule the public check and the scorer share,
    is_trusted_top_domain(): this path used to keep its own shorter hosting
    list, so a tenant on a shared platform the public check already refused
    (gwcu.us.org, a tw1.ru page) was still "known legitimate" here.
    """
    from api.services.scoring import _extract_base_domain, _TRANCO_TOP_10K, is_trusted_top_domain

    if not is_trusted_top_domain(domain):
        return None  # Unknown or shared platform — needs full analysis

    base = _extract_base_domain(domain)
    rank = _TRANCO_TOP_10K.get(base)
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
      - Allowlisted: <1ms (Tranco 100K, no API calls)
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

    # ── Rate limit only for domains that need full analysis ──
    if needs_analysis:
        remaining = await check_rate_limit(user, num_domains=len(needs_analysis))
    else:
        remaining = None  # No API calls used

    # ── Step 3: Full analysis for unknown domains (parallel) ──
    if needs_analysis:
        analyses = await asyncio.gather(
            *[analyze_domain(d) for d in needs_analysis],
            return_exceptions=True,
        )

        for domain, result in zip(needs_analysis, analyses):
            if isinstance(result, Exception):
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

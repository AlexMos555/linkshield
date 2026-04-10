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
from typing import Optional

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
from api.services.auth import get_current_user
from api.services.cache import get_cached_result, cache_result
from api.services.rate_limiter import check_rate_limit
from api.services.domain_validator import validate_domain, normalize_domain, DomainValidationError

router = APIRouter(prefix="/api/v1", tags=["check"])


def _quick_allowlist_check(domain: str) -> DomainResult | None:
    """
    Fast path: check if domain is in Tranco Top 100K.
    Returns instant safe result without any API calls.
    Skips hosting platforms and URL shorteners (handled by full analysis).
    """
    from api.services.scoring import TOP_DOMAINS, _extract_base_domain, _is_url_shortener, _TRANCO_TOP_10K

    base = _extract_base_domain(domain)

    # Hosting platforms: subdomains can be anyone's — need full analysis
    _HOSTING = {
        "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app",
        "herokuapp.com", "github.io", "gitlab.io", "web.app", "firebaseapp.com",
        "appspot.com", "azurewebsites.net", "cloudfront.net", "onrender.com",
        "fly.dev", "railway.app", "blogspot.com", "wordpress.com", "wixsite.com",
        "wixstudio.com", "weebly.com", "webflow.io", "framer.app", "framer.website",
        "carrd.co", "notion.site", "myshopify.com", "lovable.app", "replit.app",
        "webcindario.com", "contaboserver.net", "s3.amazonaws.com",
    }

    is_hosting = base in _HOSTING and domain != base
    is_shortener = _is_url_shortener(base)

    if is_hosting or is_shortener:
        return None  # Need full analysis

    if base in TOP_DOMAINS:
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
        )

    return None  # Unknown — needs full analysis


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
            )
            continue

        cached = await get_cached_result(domain)
        if cached:
            results[domain] = cached
        else:
            uncached.append(domain)

    # ── Step 1.5: Check user's personal whitelist ──
    user_whitelist = set()
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        wl = await r.smembers(f"whitelist:{user.id}")
        user_whitelist = set(wl) if wl else set()
    except Exception:
        pass

    for domain in list(uncached):
        if domain in user_whitelist:
            result = DomainResult(
                domain=domain, score=0, level=RiskLevel.safe,
                confidence=ConfidenceLevel.high,
                reasons=[DomainReason(signal="user_whitelist", detail="In your personal whitelist", weight=-50)],
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

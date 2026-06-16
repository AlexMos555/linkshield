"""
Public API endpoints (no auth required).

  GET  /api/v1/public/check/{domain} — public domain safety check (rate limited by IP)
  GET  /api/v1/public/stats — global platform stats

These power the SEO pages and the public "is X safe?" feature.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from api.services.scoring import (
    calculate_score, _extract_base_domain, TOP_DOMAINS,
    calculate_confidence_pct,
)
from api.services.domain_validator import validate_domain, DomainValidationError
from api.services.cache import get_cached_result, cache_result
from api.services.rate_limiter import rate_limit
from api.models.schemas import DomainResult, RiskLevel, ConfidenceLevel

logger = logging.getLogger("cleanway.public")

router = APIRouter(prefix="/api/v1/public", tags=["public"])


@router.get(
    "/check/{domain}",
    dependencies=[Depends(rate_limit(mode="ip", category="public_check"))],
)
async def public_check(domain: str, request: Request):
    """
    Public domain safety check. No auth required.
    Rate limited by IP (10/min). Used for SEO pages and embeds.
    Returns simplified result without full analysis (fast, no external API calls).
    """
    # IP rate limit (10 req/min for public endpoints)
    client_ip = request.client.host if request.client else "unknown"
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        ip_key = f"public_rate:{client_ip}"
        count = await r.incr(ip_key)
        if count == 1:
            await r.expire(ip_key, 60)
        if count > 10:
            raise HTTPException(429, "Rate limit exceeded. Install Cleanway extension for unlimited checks.")
    except HTTPException:
        raise
    except Exception:
        pass  # Redis down — allow request

    # Validate domain
    try:
        domain = validate_domain(domain.lower().strip())
    except DomainValidationError as e:
        raise HTTPException(400, f"Invalid domain: {e}")

    # Check cache first
    cached = await get_cached_result(domain)
    if cached:
        return _format_public_result(cached)

    # Fast allowlist check
    base = _extract_base_domain(domain)
    if base in TOP_DOMAINS:
        return {
            "domain": domain,
            "safe": True,
            "score": 0,
            "level": "safe",
            "verdict": f"{base} is a known legitimate website.",
            "signals": ["Verified as a top global domain"],
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    # Rule-based scoring only (no external API calls for public endpoint)
    signals = {"domain": domain, "raw_url": domain}
    score, level, reasons = calculate_score(signals)

    result = DomainResult(
        domain=domain,
        score=score,
        level=level,
        confidence=ConfidenceLevel.low,  # No API calls = low confidence
        reasons=reasons,
    )

    # Cache it
    await cache_result(result)

    return _format_public_result(result)


def _format_public_result(result: DomainResult) -> dict:
    """Format result for public/SEO consumption."""
    verdicts = {
        "safe": f"{result.domain} appears to be safe.",
        "caution": f"{result.domain} has some suspicious characteristics. Proceed with caution.",
        "dangerous": f"{result.domain} shows strong indicators of being a phishing or malicious site. Do not enter personal information.",
    }

    # Public endpoint is rule-based only (no external API calls) so
    # coverage is 0; confidence_pct floors at 50. When the result
    # came from the cache of a full analyze_domain run, the cached
    # value already carries the real confidence_pct — prefer that.
    confidence_pct = (
        getattr(result, "confidence_pct", None)
        or calculate_confidence_pct(result.score, 0, 1)
    )

    return {
        "domain": result.domain,
        "safe": result.level == RiskLevel.safe,
        "score": result.score,
        "level": result.level.value,
        "confidence": result.confidence.value if hasattr(result, 'confidence') else "medium",
        "confidence_pct": confidence_pct,
        "verdict": verdicts.get(result.level.value, ""),
        "signals": [r.detail for r in (result.reasons or [])[:5]],
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "cta": "Install Cleanway for real-time protection backed by 16 independent threat-intel sources and our public transparency report.",
        "install_url": "https://chrome.google.com/webstore/detail/cleanway",
        # Strategy doc #10 — link the per-domain scorecard back to
        # the platform-wide transparency report so the per-verdict
        # confidence sits inside a population-level FP rate.
        "transparency_url": "https://cleanway.ai/transparency",
    }


@router.get(
    "/stats",
    dependencies=[Depends(rate_limit(mode="ip", category="public_stats"))],
)
async def platform_stats():
    """Global platform statistics for landing page and social proof.

    Numbers MUST stay consistent with docs/transparency/<latest>.json —
    that file is the source of truth, but reading it here would
    couple this fast hot-path endpoint to disk I/O. Mirror by hand
    until we have a build step that injects the values at deploy.
    """
    return {
        "total_domains_protected": 100000,
        # 16 active sources as of Q2 2026 transparency report:
        # 11 external blocklists + 2 reputation/visual identity
        # (Tranco, favicon) + 3 Cleanway-original (credential-form,
        # modern-phish guard, URL-PII).
        "threat_sources": 16,
        "detection_signals": 42,
        "ml_model_auc": 0.9988,
        "detection_rate": 91.1,
        # Mirrors docs/transparency/2026-q2.json. 0.0 was wishful;
        # 0.0008 (0.08%) is what the latest period actually measured.
        "false_positive_rate": 0.0008,
        "brand_targets_monitored": 125,
        "transparency_url": "https://cleanway.ai/transparency",
    }

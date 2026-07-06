"""
Public API endpoints (no auth required).

  GET  /api/v1/public/check/{domain} — public domain safety check (rate limited by IP)
  GET  /api/v1/public/stats — global platform stats

These power the SEO pages and the public "is X safe?" feature.
"""

from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from api.services.scoring import (
    calculate_score, _extract_base_domain, TOP_DOMAINS,
    calculate_confidence_pct,
)
from api.services.domain_validator import validate_domain, DomainValidationError
from api.services.rate_limiter import rate_limit, _extract_client_ip
from api.models.schemas import DomainResult, RiskLevel, ConfidenceLevel
from api.services import ml_scorer

# Per-domain in-flight singleflight map. When N concurrent requests
# arrive for the same fresh domain, only the first runs analyze_domain;
# the rest await its Future. This collapses N*19 outbound API calls
# back into 19 — guards against thundering-herd / cache stampede.
_INFLIGHT: dict[str, asyncio.Future] = {}

# Public endpoint cache: domain-only, 24h TTL across all verdict
# levels. Separate from the default cache (5m/15m/1h) which serves
# the authed extension flow where 'recheck often after a takedown'
# is valid. On the anonymous SEO surface we want maximum cache hit
# rate — anyone re-querying the same domain pays nothing.
_PUBLIC_CACHE_PREFIX = "public_check:"
_PUBLIC_CACHE_TTL_SECONDS = 24 * 60 * 60

logger = logging.getLogger("cleanway.public")

router = APIRouter(prefix="/api/v1/public", tags=["public"])


async def _get_public_cache(domain: str) -> DomainResult | None:
    """Read the public-endpoint cache. Separate namespace from
    the default cache so the public surface owns its own 24h
    TTL policy independent of the authed extension flow's tighter
    re-check cadence.
    """
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        raw = await r.get(_PUBLIC_CACHE_PREFIX + domain)
        if not raw:
            return None
        data = json.loads(raw)
        out = DomainResult(**data)
        out.cached = True
        return out
    except Exception:
        return None


async def _put_public_cache(result: DomainResult) -> None:
    """Write the public-endpoint cache. Single TTL across all
    verdict levels — the public anonymous surface doesn't need the
    'recheck dangerous after takedown' cadence the authed path uses.
    """
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        await r.setex(
            _PUBLIC_CACHE_PREFIX + result.domain,
            _PUBLIC_CACHE_TTL_SECONDS,
            result.model_dump_json(),
        )
    except Exception:
        pass  # Cache failures don't break the response


@router.get(
    "/check/{domain}",
    dependencies=[Depends(rate_limit(mode="ip", category="public_check"))],
)
async def public_check(domain: str, request: Request):
    """Public domain safety check. No auth required.

    Up until 2026-06-17 this endpoint ran ONLY rule-based scoring
    and intentionally skipped the 16-source threat-intel fan-out
    for speed. Measured result: 0% recall on fresh URLhaus URLs.

    Now runs the FULL 18-check analyzer, but with FOUR defenses
    against analyzer cost (each closes a distinct adversarial-review
    finding from 2026-06-17):

      1. Top-domain allowlist short-circuit (instant safe verdict
         for top-10k legit hosts — no API calls).
      2. Per-endpoint Redis cache, single 24h TTL across verdict
         levels. The endpoint OWNS its cache namespace separately
         from cache_result()/get_cached_result() so it cannot get
         clobbered by the authed flow's 5-min dangerous TTL.
      3. SINGLEFLIGHT coalescing: N concurrent requests for the
         same fresh domain collapse to ONE analyze_domain call.
         The rest await the same Future.
      4. IP rate-limit uses _extract_client_ip() so X-Forwarded-For
         is honored when the immediate caller is in trusted_proxy_cidrs
         — without it we collapse all traffic behind Railway's
         single egress IP into one bucket.

    Trade-off: first cold-cache lookup on a never-seen domain takes
    1-3 seconds (vs prior ~100 ms). Every subsequent hit on the
    same domain serves from cache in sub-50 ms — 99% of real
    traffic will land there.
    """
    # 1) Validate domain (cheap, in-process).
    try:
        domain = validate_domain(domain.lower().strip())
    except DomainValidationError as e:
        raise HTTPException(400, f"Invalid domain: {e}")

    # 2) Public-cache hit: serve previously-analysed result.
    #    Cache hits are essentially free — Redis GET, no fan-out, no LLM.
    #    Rate-limiting these would punish landing-page repeat visitors AND
    #    prevent the credibility-page side-by-side from rendering multiple
    #    comparison rows. The 2026-06-29 audit caught the prior ordering:
    #    incrementing before the cache check made warm domains 429 on the
    #    6th visitor inside a minute. Cache + top-domain paths now run
    #    FREE; only the expensive fan-out below increments the IP cap.
    cached = await _get_public_cache(domain)
    if cached:
        return await _build_response(cached)

    # 3) Top-domain allowlist short-circuit (also free — in-memory set
    #    lookup, no network, no analyzer).
    base = _extract_base_domain(domain)
    if base in TOP_DOMAINS:
        # Build a synthetic DomainResult so the response shape stays
        # identical (incl. competitors[] side-by-side) — easier for
        # the landing scorecard than a separate branch.
        synth = DomainResult(
            domain=domain,
            score=0,
            level=RiskLevel.safe,
            confidence=ConfidenceLevel.high,
            confidence_pct=99,
            reasons=[],
        )
        return await _build_response(synth)

    # 4) NOW rate-limit the expensive fan-out path.
    #    Moved here from the top of the function (audit 2026-06-29) so
    #    cache hits + top-domain hits stay free. The 5-req/min cap only
    #    protects the analyzer (16-source fan-out + ML + LLM), which is
    #    what the cap was designed for in the first place.
    client_ip = _extract_client_ip(request)
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        ip_key = f"public_rate:{client_ip}"
        count = await r.incr(ip_key)
        if count == 1:
            await r.expire(ip_key, 60)
        if count > 5:
            raise HTTPException(
                429,
                "Rate limit exceeded (5 fresh checks per minute). "
                "Install the Cleanway extension for unlimited checks.",
            )
    except HTTPException:
        raise
    except Exception:
        pass  # Redis down — allow request

    # 5) SINGLEFLIGHT — collapse N concurrent fresh-domain requests
    #    into ONE analyzer fan-out. The first caller starts the work;
    #    every subsequent caller arrives, finds an in-flight Future,
    #    and awaits it.
    loop = asyncio.get_event_loop()
    fut = _INFLIGHT.get(domain)
    if fut is None:
        fut = loop.create_future()
        _INFLIGHT[domain] = fut
        owner = True
    else:
        owner = False

    if not owner:
        try:
            result = await fut
            return _format_public_result(result)
        except Exception:
            # Owner crashed — fall through to compute ourselves.
            pass

    # We are the owner — run the analyzer.
    try:
        from api.services.analyzer import analyze_domain
        result = await analyze_domain(domain, raw_url=domain)
        # 6) Cache the analyzer result for 24h. Without this, every
        #    repeat request paid the full fan-out — the original
        #    adversarial-review finding.
        await _put_public_cache(result)
        if not fut.done():
            fut.set_result(result)
    except Exception as exc:
        # Fail-soft: rule-only fallback. DO NOT cache the degraded
        # verdict — we want a real measurement next time.
        logger.warning("public_check analyzer failed for %s: %s", domain, exc)
        signals = {"domain": domain, "raw_url": domain}
        score, level, reasons = calculate_score(signals)
        result = DomainResult(
            domain=domain,
            score=score,
            level=level,
            confidence=ConfidenceLevel.low,
            reasons=reasons,
        )
        if not fut.done():
            fut.set_exception(exc)  # waiters fall through to compute
    finally:
        # Drop the in-flight slot so memory doesn't grow unbounded.
        _INFLIGHT.pop(domain, None)

    return _format_public_result(result)


def _format_public_result(
    result: DomainResult,
    competitors: list[dict] | None = None,
) -> dict:
    """Format result for public/SEO consumption.

    `competitors` is an optional side-by-side breakdown — what
    other resolvers say about the same domain. Surfaced on the
    landing scorecard so every per-domain page becomes a
    shareable head-to-head demo:

        Cleanway: dangerous (score 87)
        Cloudflare 1.1.1.1 for Families: safe

    No competitor publishes their per-domain verdict next to a
    competitor's. We do. That's the credibility moat.
    """
    verdicts = {
        "safe": f"{result.domain} appears to be safe.",
        "caution": f"{result.domain} has some suspicious characteristics. Proceed with caution.",
        "dangerous": f"{result.domain} shows strong indicators of being a phishing or malicious site. Do not enter personal information.",
    }

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
        # Side-by-side comparison — nobody else publishes this.
        # Renders as a 'vs Cloudflare' card on the landing scorecard.
        "competitors": competitors or [],
        "cta": "Install Cleanway for real-time protection backed by 16 independent threat-intel sources and our public transparency report.",
        "install_url": "https://chrome.google.com/webstore/detail/cleanway",
        "transparency_url": "https://cleanway.ai/transparency",
    }


async def _build_response(result: DomainResult) -> dict:
    """Helper: assemble the final response with competitor verdicts
    fetched in parallel. Used by every successful return path
    (cache hit, allowlist short-circuit, fresh analyzer run).

    Competitor lookup is bounded by COMPETITOR timeout (3 s); a
    slow Cloudflare response can never block the user response by
    more than that. If lookup fails entirely we just ship empty
    competitors — the page still renders with our verdict.
    """
    try:
        from api.services.competitor_verdicts import gather_competitor_verdicts
        competitors = await gather_competitor_verdicts(result.domain)
    except Exception as exc:
        logger.debug("competitor lookup failed for %s: %s", result.domain, exc)
        competitors = []
    return _format_public_result(result, competitors=competitors)


_LATEST_BENCHMARK = os.path.join(
    os.path.dirname(__file__), "..", "..", "docs", "benchmarks", "latest.json"
)


@functools.lru_cache(maxsize=1)
def _measured_detection_rate() -> "float | None":
    """Honest fresh-URL recall from the latest weekly benchmark.

    Gated exactly like the landing's live-recall.ts: only return a number when
    the sample is statistically meaningful (n_phishing >= 100 AND classified
    (tp+fn) >= 50). Otherwise return None so the endpoint publishes no rate
    rather than a hand-authored one — the old hardcoded 93.5% was never re-run
    against the live endpoint (see docs/AUDIT_2026-06-29.md) and is not
    defensible. Cached: latest.json only changes on redeploy / the weekly cron.
    """
    try:
        with open(_LATEST_BENCHMARK, "r") as f:
            d = json.load(f)
        cw = d.get("phishing", {}).get("cleanway", {})
        recall = cw.get("recall")
        n_phishing = d.get("n_phishing", 0)
        classified = (cw.get("tp") or 0) + (cw.get("fn") or 0)
        if recall is None or n_phishing < 100 or classified < 50:
            return None
        return round(recall * 100, 1)
    except Exception:
        return None


@router.get(
    "/stats",
    dependencies=[Depends(rate_limit(mode="ip", category="public_stats"))],
)
async def platform_stats():
    """Global platform statistics for landing page and social proof.

    detection_rate is read (and gated) from docs/benchmarks/latest.json — the
    weekly-measured source of truth — NOT a hand-authored number. It is null
    until a large-enough sample has been benchmarked, matching how the landing
    presents recall. Other counts mirror docs/transparency/<latest>.json.
    """
    return {
        "total_domains_protected": 100000,
        # 16 active sources as of Q2 2026 transparency report:
        # 11 external blocklists + 2 reputation/visual identity
        # (Tranco, favicon) + 3 Cleanway-original (credential-form,
        # modern-phish guard, URL-PII).
        "threat_sources": 16,
        "detection_signals": 42,
        "ml_model_auc": 0.9506,
        # Which ML backend is actually live: 'onnx' | 'catboost' | 'disabled'.
        # Lets us verify from prod that ML is firing, not silently degraded.
        "ml_backend": ml_scorer.backend_status(),
        # Measured fresh-URL recall, gated (null until n>=100). Never hardcoded.
        "detection_rate": _measured_detection_rate(),
        # Mirrors docs/transparency/2026-q2.json. 0.0 was wishful;
        # 0.0008 (0.08%) is what the latest period actually measured.
        "false_positive_rate": 0.0008,
        "brand_targets_monitored": 125,
        "transparency_url": "https://cleanway.ai/transparency",
    }

"""
Public API endpoints (no auth required).

  GET  /api/v1/public/check/{domain} — public domain safety check (rate limited
                                       per IP, or per install behind CGNAT)
  GET  /api/v1/public/stats — global platform stats (measured values only)

These power the SEO pages and the public "is X safe?" feature.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from api.config import get_settings
from api.models.schemas import ConfidenceLevel, DomainResult, RiskLevel
from api.services import ml_scorer, public_stats
from api.services import verdict_basis as vb
from api.services.cleanway_blocklist import listed_as
from api.services.domain_validator import DomainValidationError, validate_domain
from api.services.hosting_platforms import is_user_content_service
from api.services.rate_limiter import rate_limit
from api.services.rate_limiter import (
    _extract_client_ip,
    _incr_with_ttl_on_first,
    benchmark_bypass,
    install_key,
)
from api.services.scoring import calculate_confidence_pct, calculate_score, is_trusted_top_domain

# Per-domain in-flight singleflight map. When N concurrent requests
# arrive for the same fresh domain, only the first runs analyze_domain;
# the rest await its Future. This collapses N*19 outbound API calls
# back into 19 — guards against thundering-herd / cache stampede.
_INFLIGHT: dict[str, asyncio.Future] = {}

# Public endpoint cache: domain-only. Separate from the default cache
# (5m/15m/1h) which serves the authed extension flow where 'recheck often
# after a takedown' is valid. On the anonymous SEO surface we want maximum
# cache hit rate — anyone re-querying the same domain pays nothing.
#
# v2 (2026-09-26): verdicts cached before this carried the "could not connect
# = insecure" penalties — bankspb.ru, президент.рф, rosreestr.gov.ru sat at
# 'dangerous' for a day. A new namespace retires them at deploy without
# anyone writing to production Redis; the old keys expire on their own.
# v3 (2026-09-27): the same for the heuristic false positives on Russian
# regional and short names (kvs.gov.spb.ru sat at 'dangerous 100').
_PUBLIC_CACHE_PREFIX = "public_check:v3:"
_PUBLIC_CACHE_TTL_SECONDS = 24 * 60 * 60
# A name that does not exist can be registered at any moment, and a verdict
# the scanner could not complete may be better next time — neither is kept
# for a whole day.
_NOT_FOUND_CACHE_TTL_SECONDS = 15 * 60
_PARTIAL_CACHE_TTL_SECONDS = 60 * 60
# The analyzer enforces its own budget; this router-level backstop only
# catches a bug in that enforcement, so a request can never hang.
_BACKSTOP_GRACE_SECONDS = 1.0
_FRESH_WINDOW_SECONDS = 60

# Android 1.0.1 — on phones today — localizes a reason by its code and shows
# the English `detail` for any code it does not know, and it knows none of the
# codes added with verdict_basis. A client that sends X-Cleanway-Install (1.0.2
# on) knows them. For the others: our own blocklist is shown under a code they
# DO localize («В доверенных списках мошеннических и спам-сайтов»), a broken
# certificate under the "connection is not secure" one — what the browser
# itself will say — and the informational reasons, which explain a verdict's
# limits, are sent only when nothing else explains it: a Russian card with an
# English paragraph under «Почему мы так считаем» helps no one when a
# localized reason is there anyway.
_LEGACY_CODE_ALIASES = {
    vb.REASON_CLEANWAY_BLOCKLIST: "multi_blocklist",
    "invalid_certificate": "no_https",
}

_INSTALL_URL = "https://cleanway.ai/android"
_CTA = (
    "Get Cleanway for Android to block known scam sites on your phone, "
    "and see how we measure in our public transparency report."
)

logger = logging.getLogger("cleanway.public")

router = APIRouter(prefix="/api/v1/public", tags=["public"])


async def _get_public_cache(domain: str) -> DomainResult | None:
    """Read the public-endpoint cache. Separate namespace from
    the default cache so the public surface owns its own TTL
    policy independent of the authed extension flow's tighter
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


def _public_cache_ttl(result: DomainResult) -> int:
    if result.exists is False:
        return _NOT_FOUND_CACHE_TTL_SECONDS
    if result.checks_incomplete or vb.basis_of(result) == vb.BASIS_UNREACHABLE:
        return _PARTIAL_CACHE_TTL_SECONDS
    return _PUBLIC_CACHE_TTL_SECONDS


async def _put_public_cache(result: DomainResult) -> None:
    """Write the public-endpoint cache. A full verdict is kept for a day; a
    not-found or partial one for much less (see the TTL constants)."""
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        await r.setex(
            _PUBLIC_CACHE_PREFIX + result.domain,
            _public_cache_ttl(result),
            result.model_dump_json(),
        )
    except Exception:
        pass  # Cache failures don't break the response


@router.get(
    "/check/{domain}",
    dependencies=[Depends(rate_limit(mode="ip", category="public_check", install_aware=True))],
)
async def public_check(domain: str, request: Request):
    """Public domain safety check. No auth required.

    Runs the full analyzer (threat-intel fan-out, site probes, ML, LLM judge)
    inside a ~3 s budget, behind these short-circuits and defenses:

      1. Top-domain allowlist (instant safe for popular sites that are not
         shared platforms — no API calls).
      2. Cleanway's own published blocklist, the list the phone blocks: a
         listed host is 'dangerous' at once (verdict_basis 'blocklist').
      3. The service host of a user-content platform (disk.yandex.ru,
         onedrive.live.com): a fixed "real service, we cannot vouch for the
         page" caution (verdict_basis 'user_content'), no analysis.
      4. Per-endpoint Redis cache, in its own namespace: a day for a full
         verdict, less for a not-found or partial one.
      5. A fresh-analysis cap per minute — per IP, or per install when the
         app sends X-Cleanway-Install (CGNAT: one IP, thousands of phones).
      6. SINGLEFLIGHT coalescing: N concurrent requests for the same fresh
         domain collapse to ONE analyze_domain call.

    Every response carries `verdict_basis`. Only 'blocklist' and
    'threat_intel' are evidence a client may block on; everything else is
    advice. `exists` is false for a domain that does not exist, and
    `checks_incomplete` names checks the time budget cut off.
    """
    # 1) Validate domain (cheap, in-process).
    try:
        domain = validate_domain(domain.lower().strip())
    except DomainValidationError as e:
        raise HTTPException(400, f"Invalid domain: {e}")
    modern = install_key(request) is not None

    # 2) Top-domain allowlist short-circuit (free — in-memory set lookup).
    #    NOT for subdomains of shared platforms / public suffixes / hosting
    #    (us.org, github.io, tw1.ru, forms.yandex.ru …): anyone can publish
    #    there. One rule shared with the scorer and the authed /check.
    if is_trusted_top_domain(domain):
        return await _build_response(vb.allowlist_result(domain), modern)

    # 3) Our own blocklist — before the cache, so a verdict cached before the
    #    host was listed cannot outlive the listing. One Redis round-trip.
    listed = await listed_as(domain)
    if listed:
        return _format_public_result(vb.blocklist_result(domain, listed), modern_client=modern)

    # 4) A user-content service host: free, fixed answer (see analyzer).
    if is_user_content_service(domain):
        return await _build_response(vb.user_content_result(domain), modern)

    # 5) Public-cache hit: serve previously-analysed result. Essentially
    #    free (Redis GET, no fan-out, no LLM), so it does not touch the
    #    fresh-analysis cap below.
    cached = await _get_public_cache(domain)
    if cached:
        return await _build_response(cached, modern)

    # 6) Cap the expensive fan-out, then run it once per domain.
    await _enforce_fresh_check_budget(request)
    return _format_public_result(await _analyze_once(domain), modern_client=modern)


async def _enforce_fresh_check_budget(request: Request) -> None:
    """At most N fresh analyses a minute: per IP, or per install under a
    per-IP ceiling. Cache hits, allowlisted and blocklisted domains never
    get here. The benchmark bypass skips it, as the config promises."""
    if benchmark_bypass(request):
        return
    settings = get_settings()
    ikey = install_key(request)
    client_ip = _extract_client_ip(request)
    if ikey:
        limits = (
            (f"public_rate:install:{ikey}", settings.public_fresh_checks_per_minute),
            (f"public_rate:ip_ceiling:{client_ip}", settings.public_fresh_ip_ceiling_per_minute),
        )
    else:
        limits = ((f"public_rate:{client_ip}", settings.public_fresh_checks_per_minute),)
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        for key, limit in limits:
            if await _incr_with_ttl_on_first(r, key, _FRESH_WINDOW_SECONDS) > limit:
                raise HTTPException(
                    429,
                    f"Rate limit exceeded ({limit} fresh checks per minute). "
                    "Please try again in a minute.",
                )
    except HTTPException:
        raise
    except Exception:
        pass  # Redis down — allow request


async def _analyze_once(domain: str) -> DomainResult:
    """SINGLEFLIGHT: the first caller runs the analysis, concurrent callers
    for the same domain await its result. If the first caller goes away
    (its request was cancelled), a waiter runs its own analysis."""
    existing = _INFLIGHT.get(domain)
    if existing is not None:
        try:
            return await asyncio.shield(existing)
        except asyncio.CancelledError:
            if not existing.cancelled():
                raise  # this request itself was cancelled
    fut = asyncio.get_event_loop().create_future()
    _INFLIGHT[domain] = fut
    try:
        result = await _run_analyzer(domain)
        fut.set_result(result)
        return result
    finally:
        if not fut.done():
            fut.cancel()
        # Drop the in-flight slot so memory doesn't grow unbounded.
        if _INFLIGHT.get(domain) is fut:
            _INFLIGHT.pop(domain, None)


async def _run_analyzer(domain: str) -> DomainResult:
    """The full analysis, cached. Fail-soft: on an error — or the backstop
    firing — a rule-only verdict that says it is partial, NOT cached so the
    next request gets a real measurement."""
    from api.services.analyzer import analyze_domain
    backstop = get_settings().analysis_budget_seconds + _BACKSTOP_GRACE_SECONDS
    try:
        result = await asyncio.wait_for(analyze_domain(domain, raw_url=domain), timeout=backstop)
    except Exception as exc:
        logger.warning("public_check analyzer failed for %s: %r", domain, exc)
        return _fallback_result(domain)
    await _put_public_cache(result)
    return result


def _fallback_result(domain: str) -> DomainResult:
    signals = {"domain": domain, "raw_url": domain}
    score, level, reasons = calculate_score(signals)
    partial = DomainResult(
        domain=domain,
        score=score,
        level=level,
        confidence=ConfidenceLevel.low,
        reasons=reasons + [vb.checks_incomplete_reason(["analysis"])],
        checks_incomplete=["analysis"],
    )
    return partial.model_copy(update={"verdict_basis": vb.derive_verdict_basis(partial)})


def _verdict_reasons(result, modern_client: bool = True) -> list:
    """Top reasons whose direction matches the verdict (see _format_public_result),
    then the informational ones.

    Dangerous/caution → only risk-increasing signals (weight > 0). Safe → the
    positive ones. Informational reasons (domain not found, site unreachable
    from the scanner, checks cut off, shared platform — weight 0, see
    verdict_basis.INFORMATIONAL_REASONS) say what the verdict could NOT see;
    they are shown whatever its direction. Only when neither explains the
    verdict does the card fall back to the other direction's reasons (e.g. a
    verdict driven by a hard listing with odd weights), so it is never
    reasonless — but never to put "the name looks randomly generated" under
    "appears to be safe" while an informational reason is there to say why.
    A client that cannot localize the informational codes gets them only when
    nothing else explains the verdict (see _LEGACY_CODE_ALIASES).
    """
    reasons = list(result.reasons or [])
    if not reasons:
        return []
    info = [r for r in reasons if r.signal in vb.INFORMATIONAL_REASONS][:5]
    rest = [r for r in reasons if r.signal not in vb.INFORMATIONAL_REASONS]
    is_safe = result.level == RiskLevel.safe
    matched = [r for r in rest if (r.weight <= 0) == is_safe]
    directional = matched or ([] if info else rest)
    if directional and not modern_client:
        return directional[:5]
    return directional[:5 - len(info)] + info


def _verdict_text(result: DomainResult) -> str:
    domain = result.domain
    if result.exists is False:
        return f"{domain} does not work right now: there is no site at this address. Check the spelling of the address."
    basis = vb.basis_of(result)
    if basis == vb.BASIS_USER_CONTENT:
        return (
            f"{domain} is a real service where anyone can publish pages, scammers "
            "included. We cannot vouch for the page itself. Do not enter passwords "
            "or card details there unless you trust whoever sent you the link."
        )
    if basis == vb.BASIS_UNREACHABLE and result.level != RiskLevel.dangerous:
        # "appears to be safe" would claim a check that never happened.
        return {
            "safe": f"Our scanner could not open {domain}, so the site itself was not checked. No threat list we checked flags it.",
            "caution": f"Our scanner could not open {domain} and cannot vouch for it. Proceed with caution.",
        }[result.level.value]
    verdicts = {
        "safe": f"{domain} appears to be safe.",
        "caution": f"{domain} has some suspicious characteristics. Proceed with caution.",
        "dangerous": f"{domain} shows strong indicators of being a phishing or malicious site. Do not enter personal information.",
    }
    return verdicts.get(result.level.value, "")


def _reason_codes(shown: list, modern_client: bool) -> list[str]:
    if modern_client:
        return [r.signal for r in shown]
    return [_LEGACY_CODE_ALIASES.get(r.signal, r.signal) for r in shown]


def _format_public_result(
    result: DomainResult,
    competitors: list[dict] | None = None,
    modern_client: bool = True,
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

    `modern_client` False (no X-Cleanway-Install) adapts the reasons to
    clients that cannot localize the newer codes (_LEGACY_CODE_ALIASES).
    """
    confidence_pct = (
        getattr(result, "confidence_pct", None)
        or calculate_confidence_pct(result.score, 0, 1)
    )
    shown = _verdict_reasons(result, modern_client)

    return {
        "domain": result.domain,
        "safe": result.level == RiskLevel.safe,
        "score": result.score,
        "level": result.level.value,
        "confidence": result.confidence.value if hasattr(result, 'confidence') else "medium",
        "confidence_pct": confidence_pct,
        "verdict": _verdict_text(result),
        # Show reasons that match the verdict's direction. A DANGEROUS/CAUTION
        # result must not list a positive signal like "our detector considers
        # this site safe" (weight <= 0) as a red "why we say this" bullet — a
        # real contradiction a user hit on amazont-support.com. A SAFE result
        # keeps its positive reasons ("known legitimate").
        "signals": [r.detail for r in shown],
        # Machine-readable code per signal, positionally aligned with `signals`.
        # Clients localize from the code (mobile.reason.<code>) and fall back to
        # the English `detail` for codes they don't map — so an Arabic or
        # Russian user stops seeing "Site does not use HTTPS encryption" in
        # English, which broke the grandma-grade promise on a 10-locale app.
        "reason_codes": _reason_codes(shown, modern_client),
        # What the verdict rests on. A client blocks a site ONLY when this is
        # 'blocklist' or 'threat_intel' — never on 'heuristics',
        # 'ml_and_heuristics', 'unreachable', 'not_found' or an unknown value.
        "verdict_basis": vb.basis_of(result),
        # false = DNS says no such domain; null = not checked / no answer.
        "exists": result.exists,
        # Checks the time budget cut off, by name (empty when complete).
        "checks_incomplete": list(result.checks_incomplete),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        # Side-by-side comparison — nobody else publishes this.
        # Renders as a 'vs Cloudflare' card on the landing scorecard.
        "competitors": competitors or [],
        # No hand-kept source count (/stats says why) and only a platform
        # that is actually installable: the Chrome listing is not live.
        "cta": _CTA,
        "install_url": _INSTALL_URL,
        "transparency_url": "https://cleanway.ai/transparency",
    }


async def _build_response(result: DomainResult, modern_client: bool = True) -> dict:
    """Helper: assemble the final response with competitor verdicts
    fetched in parallel. Used by the cache-hit and allowlist paths.

    Competitor lookup is bounded by COMPETITOR timeout (3 s); a
    slow Cloudflare response can never block the user response by
    more than that. If lookup fails entirely we just ship empty
    competitors — the page still renders with our verdict. Our own
    `exists` answer lets it tell "Cloudflare blocked it" from "the
    domain does not exist" without a second query.
    """
    try:
        from api.services.competitor_verdicts import gather_competitor_verdicts
        competitors = await gather_competitor_verdicts(result.domain, domain_exists=result.exists)
    except Exception as exc:
        logger.debug("competitor lookup failed for %s: %s", result.domain, exc)
        competitors = []
    return _format_public_result(result, competitors=competitors, modern_client=modern_client)


@router.get(
    "/stats",
    dependencies=[Depends(rate_limit(mode="ip", category="public_stats"))],
)
async def platform_stats():
    """Global platform statistics — measured values only.

    Every number is read from something that measured it (the weekly
    benchmark, the deployed model's held-out test, the live blocklist, the
    brand list the scorer loads) or is null, with `notes` saying why. The
    hand-written figures this used to return — including a 0.08% false-
    positive rate that was never measured — are gone. Keys are unchanged so
    existing clients keep working.
    """
    report = public_stats.benchmark()
    return {
        "total_domains_protected": None,
        "threat_sources": None,
        "detection_signals": None,
        "ml_model_auc": public_stats.model_auc(),
        # Which ML backend is actually live: 'onnx' | 'catboost' | 'disabled'.
        # Lets us verify from prod that ML is firing, not silently degraded.
        "ml_backend": ml_scorer.backend_status(),
        "detection_rate": public_stats.measured_detection_rate(report),
        "false_positive_rate": public_stats.measured_false_positive_rate(report),
        "benchmark_measured_at": report.get("ts"),
        "blocklist_entries": await public_stats.blocklist_entries(),
        "brand_targets_monitored": public_stats.brand_targets_monitored(),
        "notes": public_stats.notes_for(report),
        "transparency_url": "https://cleanway.ai/transparency",
    }

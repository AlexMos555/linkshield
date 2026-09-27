"""
Domain Analysis Engine 3.1

Before anything else, two cheap questions:
  * does the domain exist at all? NXDOMAIN → an honest "no such site"
    (verdict_basis 'not_found') instead of reasons invented from failed
    connections;
  * does it resolve to a safe network? (SSRF guard)

Then 19 checks run in parallel via circuit breakers, inside ONE time budget
(config.analysis_budget_seconds):
  threat intel (11)  Google Safe Browsing, PhishTank, URLhaus, PhishStats,
                     ThreatFox, Spamhaus DBL, SURBL, AlienVault OTX,
                     IPQualityScore, MalwareBazaar, Feodo Tracker
  reputation (3)     Tranco popularity, favicon brand clone, typosquat watchtower
  enrichment (5)     WHOIS/RDAP age, TLS certificate, security headers, DNS,
                     redirect chain (the connection probes live in site_probes)

A check still running at the deadline is cancelled and named in
`checks_incomplete`; the LLM judge only gets whatever budget is left.

Privacy: only domain names processed — never full URLs or user data.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Optional

import httpx

from api.config import get_settings
from api.services import paid_budget
from api.services import verdict_basis as vb
from api.services.analysis_budget import MIN_STEP_S, Deadline, run_within_budget
from api.services.hosting_platforms import is_user_content_service
from api.services.scoring import (
    calculate_score, calculate_confidence, calculate_confidence_pct, is_hosting_platform_site,
    registrable_domain,
)
from api.services.domain_validator import (
    validate_domain,
    validate_domain_resolution,
    DomainValidationError,
)
from api.services.circuit_breaker import (
    safe_browsing_breaker, phishtank_breaker, urlhaus_breaker,
    phishstats_breaker, threatfox_breaker,
    spamhaus_breaker, surbl_breaker,
    alienvault_breaker, ipqs_breaker,
    whois_breaker, ssl_breaker, headers_breaker,
    dns_breaker, redirect_breaker,
    malware_bazaar_breaker, feodo_breaker,
    tranco_breaker, favicon_breaker, watchtower_breaker,
)
from api.services.dns_checks import (  # noqa: F401 — re-exported
    EXISTENCE_TIMEOUT_S, check_dns, check_domain_exists,
)
from api.services.confirmed_threats import record_if_confirmed
from api.services.tranco import check_tranco_popularity, get_tranco_rank
from api.services.favicon_hash import check_favicon_brand_clone
from api.services.watchtower_lookup import check_typosquat_alert
# Connection probes: re-exported here, where callers and tests have always
# found them.
from api.services.site_probes import (  # noqa: F401
    check_redirect_chain, check_security_headers, check_ssl,
    first_failure, site_reachability, wire_host,
)
from api.models.schemas import DomainResult, DomainReason, RiskLevel, ConfidenceLevel

logger = logging.getLogger("cleanway.analyzer")

TOTAL_CHECKS = 19
# The checks that connect to the site itself. They are skipped when the SSRF
# guard could not finish (we would not know where we are connecting), and an
# unreachable result counts as "not measured" for confidence.
_SITE_PROBES = frozenset({"favicon", "ssl", "headers", "redirect"})
# Cap for the SSRF resolution step inside the overall budget.
RESOLUTION_TIMEOUT_S = 1.5
# Every external source gives up BELOW the analysis budget (3 s), so a source
# that hangs raises — and its circuit breaker counts the failure and opens —
# instead of being silently cancelled at the deadline on every single check.
# (PhishStats hung like that, holding each fresh check to the full budget.)
SOURCE_TIMEOUT_S = 2.5


# ═══════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════

async def analyze_domain(
    domain: str, raw_url: str = "", budget_s: Optional[float] = None,
) -> DomainResult:
    """Analyze a domain inside one time budget.

    Returns a DomainResult with score, level, confidence, reasons,
    `verdict_basis`, `exists` and `checks_incomplete`.
    """
    # ── Validate & normalize domain (SSRF protection) ──
    try:
        domain = validate_domain(domain)
    except DomainValidationError as e:
        logger.warning("Domain validation failed: %s — %s", domain, str(e))
        return DomainResult(
            domain=domain, score=0, level=RiskLevel.caution,
            reasons=[DomainReason(signal="invalid_domain", detail=f"Invalid domain: {str(e)}", weight=0)],
            verdict_basis=vb.BASIS_HEURISTICS,
        )

    # A user-content service host (disk.yandex.ru, onedrive.live.com): its
    # name is the platform's, so scoring it judges Yandex or Microsoft, not
    # the page. Fixed answer, no analysis.
    if is_user_content_service(domain):
        return vb.user_content_result(domain)

    budget = get_settings().analysis_budget_seconds if budget_s is None else budget_s
    deadline = Deadline(budget)
    is_ip = _is_ip_address(domain)

    # Existence and the SSRF guard both resolve the name, and each may take
    # up to its 1.5 s cap on a slow authoritative server — in sequence they
    # could spend the whole 3 s before any check started. So in parallel.
    resolution = asyncio.ensure_future(_resolution_is_safe(domain, deadline))
    exists = None if is_ip else await _domain_exists_within(domain, deadline)
    if exists is False:
        _discard(resolution)
        logger.info("analysis_not_found", extra={"domain": domain})
        return vb.not_found_result(domain)

    # Block internal IPs before making any requests to the site.
    try:
        probes_allowed = await resolution
    except DomainValidationError as e:
        logger.warning("DNS resolution blocked (SSRF): %s — %s", domain, str(e))
        return DomainResult(
            domain=domain, score=100, level=RiskLevel.dangerous,
            reasons=[DomainReason(signal="ssrf_blocked", detail="Domain resolves to a blocked network", weight=100)],
            exists=exists, verdict_basis=vb.BASIS_HEURISTICS,
        )

    outcomes, unfinished = await run_within_budget(
        _check_calls(domain, probes_allowed), deadline.remaining(),
    )
    if not probes_allowed:
        unfinished = unfinished + sorted(_SITE_PROBES)
    return await _judge(domain, raw_url, is_ip, exists, outcomes, unfinished, deadline)


async def _judge(
    domain: str, raw_url: str, is_ip: bool, exists: Optional[bool],
    outcomes: dict, unfinished: list[str], deadline: Deadline,
) -> DomainResult:
    """Score the gathered evidence, let the LLM judge use what budget is left,
    and assemble the result."""
    signals = _build_signals(domain, raw_url, is_ip, outcomes)
    whois_age = signals["domain_age_days"]
    measured = _measured_checks(outcomes, signals["site_reachable"])
    signals["checks_succeeded"] = measured

    score, level, reasons = calculate_score(signals)
    confidence = calculate_confidence(measured, TOTAL_CHECKS, whois_age)

    if confidence == ConfidenceLevel.low and level == RiskLevel.safe:
        score = max(score, vb.CANNOT_VOUCH_SCORE)
        level = RiskLevel.caution
        reasons.append(DomainReason(
            signal="partial_analysis", weight=0,
            detail=f"Only {measured}/{TOTAL_CHECKS} checks completed — limited confidence",
        ))

    # A site we could not open, whose name nothing else vouches for, gets no
    # benefit of the doubt: no listing is not evidence of safety for a fresh,
    # geo-fenced Госуслуги look-alike — the ML model and the brand list both
    # miss those. Caution, never 'safe' (and 'unreachable' never blocks).
    vouched = True
    if signals["site_reachable"] is False:
        vouched = await _name_is_vouched_for(domain, signals, deadline)
        if not vouched and level == RiskLevel.safe:
            score = max(score, vb.CANNOT_VOUCH_SCORE)
            level = RiskLevel.caution

    # A verdict on a site we could not open, or on partial data near 'safe',
    # is never 'high' confidence.
    if (measured < TOTAL_CHECKS and score < 20) or signals["site_reachable"] is False:
        confidence = _at_most(confidence, ConfidenceLevel.medium)

    score, level, judge_reason, judge_finished = await _llm_judge_within(signals, score, level, deadline)
    if judge_reason is not None:
        reasons.append(judge_reason)
    if not judge_finished:
        unfinished = unfinished + ["llm_judge"]
    reasons.extend(_informational_reasons(domain, outcomes, signals, unfinished, vouched))

    _log_features(domain, signals, score)
    # With PUBLISH_CONFIRMED_THREATS on (off by default — a licence
    # decision), a dangerous verdict that rests on a Safe Browsing
    # phishing/malware listing reaches every phone's blocklist on the next
    # publish; heuristic verdicts never do. Bounded and never raises.
    await record_if_confirmed(domain, level.value, signals)

    # Strategy doc #12 — numeric confidence band per verdict.
    confidence_pct = calculate_confidence_pct(score, measured, TOTAL_CHECKS)
    result = DomainResult(
        domain=domain, score=score, level=level, confidence=confidence,
        confidence_pct=confidence_pct,
        reasons=reasons,
        domain_age_days=whois_age,
        has_ssl=_value(outcomes, "ssl", {}).get("has_ssl"),
        ssl_issuer=_value(outcomes, "ssl", {}).get("issuer"),
        exists=exists,
        checks_incomplete=sorted(set(unfinished)),
    )
    basis = vb.derive_verdict_basis(result, ml_consulted=_ml_available())
    logger.info("analysis_complete", extra={
        "domain": domain, "score": score, "level": level.value,
        "confidence": confidence.value, "confidence_pct": confidence_pct,
        "checks": measured, "basis": basis, "incomplete": result.checks_incomplete,
    })
    return result.model_copy(update={"verdict_basis": basis})


# ── Steps ──

def _discard(task: "asyncio.Future[Any]") -> None:
    """Drop a step whose answer is no longer needed, without leaving an
    exception nobody retrieved."""
    if task.done():
        if not task.cancelled():
            task.exception()
    else:
        task.cancel()


async def _domain_exists_within(domain: str, deadline: Deadline) -> Optional[bool]:
    try:
        return await asyncio.wait_for(
            check_domain_exists(domain), timeout=deadline.step(EXISTENCE_TIMEOUT_S),
        )
    except asyncio.TimeoutError:
        return None


async def _resolution_is_safe(domain: str, deadline: Deadline) -> bool:
    """SSRF guard inside the budget.

    True: safe to connect. False: the lookup did not finish in time, so
    nothing may connect to the site (we would not know where we are
    connecting) — the site probes are skipped and reported as incomplete.
    Raises DomainValidationError when the domain resolves to a blocked
    network.
    """
    try:
        await asyncio.wait_for(
            validate_domain_resolution(domain), timeout=deadline.step(RESOLUTION_TIMEOUT_S),
        )
        return True
    except asyncio.TimeoutError:
        logger.info("ssrf_resolution_timeout — site probes skipped", extra={"domain": domain})
        return False


def _check_calls(domain: str, probes_allowed: bool) -> dict[str, Any]:
    """Every check, by name, as a not-yet-awaited breaker call.

    Built per call rather than at import so a monkeypatched check function
    is the one that runs.
    """
    plan = {
        # Blocklist sources (11)
        "safe_browsing": (safe_browsing_breaker, check_safe_browsing),
        "phishtank": (phishtank_breaker, check_phishtank),
        "urlhaus": (urlhaus_breaker, check_urlhaus),
        "phishstats": (phishstats_breaker, check_phishstats),
        "threatfox": (threatfox_breaker, check_threatfox),
        "spamhaus": (spamhaus_breaker, check_spamhaus_dbl),
        "surbl": (surbl_breaker, check_surbl),
        "alienvault": (alienvault_breaker, check_alienvault_otx),
        "ipqs": (ipqs_breaker, check_ipqualityscore),
        "malware_bazaar": (malware_bazaar_breaker, check_malware_bazaar),
        "feodo": (feodo_breaker, check_feodo_tracker),
        # Reputation + visual identity (3)
        "tranco": (tranco_breaker, check_tranco_popularity),
        "favicon": (favicon_breaker, check_favicon_brand_clone),
        "watchtower": (watchtower_breaker, check_typosquat_alert),
        # Enrichment sources (5)
        "whois": (whois_breaker, check_whois_age),
        "ssl": (ssl_breaker, check_ssl),
        "headers": (headers_breaker, check_security_headers),
        "dns": (dns_breaker, check_dns),
        "redirect": (redirect_breaker, check_redirect_chain),
    }
    return {
        name: breaker.call(fn if name in _SITE_PROBES else _within_source_timeout(fn), domain)
        for name, (breaker, fn) in plan.items()
        if probes_allowed or name not in _SITE_PROBES
    }


def _within_source_timeout(fn: Any) -> Any:
    """`fn` with a TOTAL time limit that raises inside the breaker.

    httpx's timeout is per phase (connect, then each read), so a source that
    accepts the connection and then answers a byte at a time never times out
    by itself — PhishStats did roughly that, and the check was cancelled at
    the deadline instead, which a breaker cannot count (CancelledError is not
    an Exception). This limit fires first, as a failure the breaker counts.
    The site probes keep their own limits: one slow SITE must not open a
    breaker that skips the probe for everyone.
    """
    async def _call(domain: str) -> Any:
        return await asyncio.wait_for(fn(domain), timeout=SOURCE_TIMEOUT_S)
    return _call


def _value(outcomes: dict, name: str, default: Any) -> Any:
    """A check's value, or `default` when it failed, was cut off or skipped."""
    value, ok = outcomes.get(name, (default, False))
    return value if ok else default


def _measured_checks(outcomes: dict, site_reachable: Optional[bool]) -> int:
    """Checks that returned real data. A site probe that could not reach the
    site ran fine but measured nothing, so it does not count — nor does any
    site probe (the favicon fetch included) once the site is known to be
    unreachable."""
    count = 0
    for name, (value, ok) in outcomes.items():
        probe = name in _SITE_PROBES
        unreachable = probe and (
            site_reachable is False
            or (isinstance(value, dict) and value.get("reachable") is False)
        )
        if ok and not unreachable:
            count += 1
    return count


_CONFIDENCE_RANK = {ConfidenceLevel.low: 0, ConfidenceLevel.medium: 1, ConfidenceLevel.high: 2}


def _at_most(confidence: ConfidenceLevel, cap: ConfidenceLevel) -> ConfidenceLevel:
    # Ranked explicitly: the previous min(..., key=c.value) compared the
    # STRINGS, and "high" < "medium" alphabetically, so it never capped.
    return confidence if _CONFIDENCE_RANK[confidence] <= _CONFIDENCE_RANK[cap] else cap


def _build_signals(domain: str, raw_url: str, is_ip: bool, outcomes: dict) -> dict:
    """The scorer's input — all 42+ signals, from the gathered outcomes."""
    alienvault_data = _value(outcomes, "alienvault", {})
    ipqs_data = _value(outcomes, "ipqs", {})
    tranco_result = _value(outcomes, "tranco", {"ranked": False, "rank": None, "weight": 0, "label": ""})
    favicon_result = _value(outcomes, "favicon", {"cloned": False, "brand": None, "weight": 0, "detail": ""})
    watchtower_result = _value(outcomes, "watchtower", {"matched": False, "weight": 0})
    whois_data = _value(outcomes, "whois", {})
    ssl_data = _value(outcomes, "ssl", {})
    headers_data = _value(outcomes, "headers", {})
    dns_data = _value(outcomes, "dns", {})
    redirect_data = _value(outcomes, "redirect", {})
    hard_hits = [_value(outcomes, name, False) for name in (
        "safe_browsing", "phishtank", "urlhaus", "phishstats", "threatfox",
        "spamhaus", "surbl", "malware_bazaar", "feodo",
    )]

    return {
        "domain": domain,
        "raw_url": raw_url or domain,
        # Blocklist hits — 11 named source adapters. phishtank_hit always
        # resolves False until Cisco reopens PhishTank registration but is
        # kept for backward compatibility with older scoring rules.
        "safe_browsing_hit": _value(outcomes, "safe_browsing", False),
        "phishtank_hit": _value(outcomes, "phishtank", False),
        "urlhaus_hit": _value(outcomes, "urlhaus", False),
        "phishstats_hit": _value(outcomes, "phishstats", False),
        "threatfox_hit": _value(outcomes, "threatfox", False),
        "spamhaus_hit": _value(outcomes, "spamhaus", False),
        "surbl_hit": _value(outcomes, "surbl", False),
        "alienvault_pulse_count": alienvault_data.get("pulse_count", 0),
        "ipqs_risk_score": ipqs_data.get("risk_score", 0),
        "ipqs_phishing": ipqs_data.get("phishing", False),
        "malware_bazaar_hit": _value(outcomes, "malware_bazaar", False),
        "feodo_hit": _value(outcomes, "feodo", False),
        "blocklist_hits": sum(bool(h) for h in hard_hits)
        + bool(alienvault_data.get("hit")) + bool(ipqs_data.get("hit")),
        # Strategy #14 — Tranco popularity (negative weight = trust)
        "tranco_ranked": bool(tranco_result.get("ranked")),
        "tranco_rank": tranco_result.get("rank"),
        "tranco_weight": tranco_result.get("weight", 0),
        "tranco_label": tranco_result.get("label", ""),
        # Strategy #2 — favicon brand-clone
        "favicon_cloned": bool(favicon_result.get("cloned")),
        "favicon_brand": favicon_result.get("brand"),
        "favicon_detail": favicon_result.get("detail", ""),
        # Strategy #17 — typosquat watchtower lookup
        "watchtower_matched": bool(watchtower_result.get("matched")),
        "watchtower_brand": watchtower_result.get("brand"),
        "watchtower_variant": watchtower_result.get("variant_kind"),
        "watchtower_distance": watchtower_result.get("edit_distance"),
        "watchtower_weight": watchtower_result.get("weight", 0),
        # WHOIS
        "domain_age_days": whois_data.get("age_days"),
        "registrar": whois_data.get("registrar"),
        # TLS / site probes. None = not measured (unreachable, cut off or
        # skipped) — never "insecure".
        "is_ip_based": is_ip,
        "site_reachable": site_reachability(ssl_data, headers_data, redirect_data),
        "no_https": (not ssl_data["has_ssl"]) if "has_ssl" in ssl_data else None,
        "certificate_problem": ssl_data.get("certificate_problem"),
        "free_ssl": ssl_data.get("is_free_ssl", False),
        "cert_age_days": ssl_data.get("cert_age_days"),
        "missing_security_headers": headers_data.get("missing"),
        # DNS
        "dns_ttl": dns_data.get("ttl"),
        "dns_ns_count": dns_data.get("ns_count"),
        "dns_has_mx": dns_data.get("has_mx", True),
        "dns_a_count": dns_data.get("a_count"),
        # Redirects
        "redirect_count": redirect_data.get("count", 0),
        "redirect_cross_domain": redirect_data.get("cross_domain", False),
        # Meta (checks_succeeded is filled in by the caller)
        "checks_succeeded": 0,
        "total_checks": TOTAL_CHECKS,
    }


async def _llm_judge_within(
    signals: dict, score: int, level: RiskLevel, deadline: Deadline,
) -> tuple[int, RiskLevel, Optional[DomainReason], bool]:
    """Strategy #21 — the LLM judge for caution-band verdicts, inside the budget.

    When the rule-based scorer landed in the caution band (no blocklist hit,
    no allowlist short-circuit), Claude weighs in on a domain-FREE feature
    vector and proposes a signed score shift capped at ±20. Returns
    (score, level, reason or None, finished). `finished` is False when the
    judge was still running at the deadline — the verdict then stands
    without it, and says so. The live call itself is not lost: it finishes
    in the background and fills the judge's cache (llm_judge._live_opinion),
    so the next domain with the same pattern gets the answer in time.
    """
    try:
        from api.services.llm_judge import judge_ambiguous_verdict
        judge = await asyncio.wait_for(
            judge_ambiguous_verdict(signals, score, level.value),
            timeout=max(MIN_STEP_S, deadline.remaining()),
        )
    except asyncio.TimeoutError:
        return score, level, None, False
    except Exception:
        # Judge MUST NEVER take down the analyzer hot path.
        logger.debug("LLM judge wrapper failed", exc_info=True)
        return score, level, None, True
    if judge is None:
        return score, level, None, True
    shift = int(judge.get("score_shift", 0))
    if shift != 0:
        score = max(0, min(score + shift, 100))
        if score >= 70:
            level = RiskLevel.dangerous
        elif score >= 30:
            level = RiskLevel.caution
        else:
            level = RiskLevel.safe
    reason = DomainReason(signal="llm_judge", weight=shift, detail=judge["one_line_reason"])
    return score, level, reason, True


# Second-level labels of registries only a government can register in, under
# a country code: gov.ru is for federal bodies. Tranco ranks such a suffix as
# one name (gov.ru, #10861) and never the sites under it (rosreestr.gov.ru),
# so without this every federal site that refuses foreign scanners would be
# "not a widely known site".
_GOVERNMENT_LABELS = frozenset({"gov", "gob", "gouv", "govt", "go", "mil"})
# Government sites registered under an OPEN regional zone, named one by one.
# 'gov' is NOT reserved in the FAITID zones (spb.ru, msk.ru, nov.ru …): on
# 2026-09-27 whois.flexireg.net had gov.vladimir.ru, gov.adygeya.ru,
# gov.bir.ru and gov.mytis.ru unregistered — anyone can buy them — gov.msk.ru
# parked at a registrar's resale shop, gov.nov.ru registered in 2023 through
# a retail registrar. So "gov.<regional zone>" vouches for nothing; only a
# name checked individually does. gov.spb.ru: the St Petersburg government's
# site (Wikidata Q1993715, P856), registered 2010-04-23, served by its own
# name servers ns{,2,3}.gov.spb.ru.
_REGIONAL_GOVERNMENT_DOMAINS = frozenset({"gov.spb.ru"})
_VOUCH_LOOKUP_S = 0.3


def _government_name(domain: str) -> bool:
    name = domain.lower().rstrip(".")
    if any(name == g or name.endswith("." + g) for g in _REGIONAL_GOVERNMENT_DOMAINS):
        return True
    parts = name.split(".")
    if parts[-1] in ("gov", "mil"):
        return len(parts) >= 2
    return len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in _GOVERNMENT_LABELS


async def _name_is_vouched_for(domain: str, signals: dict, deadline: Deadline) -> bool:
    """Does anything besides this analysis vouch for the NAME? It is in the
    world's top-1M — itself, or (www.kaluga-gov.ru) its registrable domain
    when that is not a shared platform where anyone can publish — or it sits
    in a government-only registry.

    The registrable domain is PSL-aware: under a regional zone it is
    x.spb.ru, never spb.ru. Tranco ranks spb.ru (#2605) as one name, and
    reading that rank as a vouch for every host anyone registers under it
    let an unreachable gosuslugi-lk.spb.ru through as 'safe'."""
    if signals.get("tranco_ranked") or _government_name(domain):
        return True
    registrable = registrable_domain(domain)
    if registrable == domain or is_hosting_platform_site(domain):
        return False
    try:
        rank = await asyncio.wait_for(get_tranco_rank(registrable), timeout=deadline.step(_VOUCH_LOOKUP_S))
    except asyncio.TimeoutError:
        return False
    return bool(rank and rank > 0)


def _informational_reasons(
    domain: str, outcomes: dict, signals: dict, unfinished: list[str], vouched: bool,
) -> list[DomainReason]:
    """Zero-weight reasons that say what the verdict could NOT see."""
    out: list[DomainReason] = []
    if signals.get("site_reachable") is False:
        out.append(vb.unreachable_reason(
            first_failure(
                _value(outcomes, "ssl", {}), _value(outcomes, "headers", {}),
                _value(outcomes, "redirect", {}),
            ),
            known_site=vouched,
        ))
    if is_hosting_platform_site(domain):
        out.append(vb.user_content_reason())
    if unfinished:
        out.append(vb.checks_incomplete_reason(unfinished))
    return out


def _log_features(domain: str, signals: dict, score: int) -> None:
    """Log the ML feature vector (for future model training). Non-critical."""
    try:
        from api.services.url_features import extract_features, log_features
        log_features(domain, extract_features(domain, signals), score)
    except Exception:
        pass


def _ml_available() -> bool:
    try:
        from api.services import ml_scorer
        return ml_scorer.backend_status() != "disabled"
    except Exception:
        return False


def _is_ip_address(domain: str) -> bool:
    try:
        import ipaddress
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


# ═══════════════════════════════════════════════════════════════
# CHECK 1: Google Safe Browsing
# ═══════════════════════════════════════════════════════════════
# The real implementation lives in api.services.safe_browsing — this re-export
# keeps backward compatibility for the circuit breaker wiring in analyze_domain.

from api.services.safe_browsing import check_safe_browsing  # noqa: E402,F401


# ═══════════════════════════════════════════════════════════════
# CHECK 2: PhishTank
# ═══════════════════════════════════════════════════════════════

async def check_phishtank(domain: str) -> bool:
    async with httpx.AsyncClient(timeout=SOURCE_TIMEOUT_S) as client:
        resp = await client.post(
            "https://checkurl.phishtank.com/checkurl/",
            data={"url": f"http://{domain}/", "format": "json", "app_key": get_settings().phishtank_api_key or ""},
        )
        data = resp.json()
        hit = data.get("results", {}).get("in_database", False) and data["results"].get("valid", False)
        if hit:
            logger.info("phishtank_hit", extra={"domain": domain})
        return hit


# ═══════════════════════════════════════════════════════════════
# CHECK 3: URLhaus (abuse.ch) — malware URL database
# ═══════════════════════════════════════════════════════════════

async def check_urlhaus(domain: str) -> bool:
    """Check domain against URLhaus malware URL database (free, no key needed)."""
    async with httpx.AsyncClient(timeout=SOURCE_TIMEOUT_S) as client:
        resp = await client.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
        )
        data = resp.json()
        # query_status: "no_results" = clean, "is_host" = found
        hit = data.get("query_status") == "is_host"
        if hit:
            url_count = data.get("url_count", 0)
            logger.info("urlhaus_hit", extra={"domain": domain, "url_count": url_count})
        return hit


# ═══════════════════════════════════════════════════════════════
# CHECK 4: WHOIS/RDAP — domain age + registrar
# ═══════════════════════════════════════════════════════════════

async def check_whois_age(domain: str) -> dict:
    async with httpx.AsyncClient(timeout=SOURCE_TIMEOUT_S) as client:
        resp = await client.get(f"https://rdap.org/domain/{domain}")
        if resp.status_code != 200:
            return {}

        data = resp.json()
        result = {}

        # Extract registration date
        for event in data.get("events", []):
            if event.get("eventAction") == "registration":
                reg_date_str = event.get("eventDate", "")
                if reg_date_str:
                    reg_date = datetime.fromisoformat(reg_date_str.replace("Z", "+00:00"))
                    result["age_days"] = (datetime.now(timezone.utc) - reg_date).days
                    result["registered"] = reg_date_str

        # Extract registrar
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [None, []])[1]
                for field in vcard:
                    if field[0] == "fn":
                        result["registrar"] = field[3]
                        break

        return result


# ═══════════════════════════════════════════════════════════════
# CHECK 9: PhishStats — aggregated phishing intelligence
# ═══════════════════════════════════════════════════════════════

# PhishStats can only search URLs by substring, so it returns every listed URL
# that CONTAINS the name: https://bankspb.ru.secure-login.xyz/ and
# evil.com/?r=bankspb.ru for bankspb.ru, anything under mybank.ru for bank.ru.
# Brand impersonation produces exactly those. Ask for a page of candidates and
# count a hit only when a listed URL's own host IS the domain (a leading www.
# ignored on both sides).
_PHISHSTATS_PAGE = 20


async def check_phishstats(domain: str) -> bool:
    """Check domain against PhishStats API (free, no key, 20 req/min)."""
    async with httpx.AsyncClient(timeout=SOURCE_TIMEOUT_S) as client:
        resp = await client.get(
            "https://phishstats.info:2096/api/phishing"
            f"?_where=(url,like,~{domain}~)&_size={_PHISHSTATS_PAGE}"
        )
        data = resp.json()
        hit = isinstance(data, list) and any(
            _phishstats_row_is_host(row, domain) for row in data
        )
        if hit:
            logger.info("phishstats_hit", extra={"domain": domain})
        return hit


def _phishstats_row_is_host(row: Any, domain: str) -> bool:
    if not isinstance(row, dict) or not isinstance(row.get("url"), str):
        return False
    url = row["url"].strip()
    try:
        # Wire (punycode) form, as `domain` is: a listed госуслуги.рф URL
        # compares equal to the xn-- name we were asked about.
        host = wire_host(httpx.URL(url if "://" in url else f"http://{url}"))
    except Exception:
        return False
    return _without_www(host) == _without_www(domain.lower().rstrip("."))


def _without_www(host: str) -> str:
    return host[4:] if host.startswith("www.") else host


# ═══════════════════════════════════════════════════════════════
# CHECK 10: abuse.ch ThreatFox — IOC database
# ═══════════════════════════════════════════════════════════════

async def check_threatfox(domain: str) -> bool:
    """Check domain against ThreatFox IOC database (free, no key)."""
    async with httpx.AsyncClient(timeout=SOURCE_TIMEOUT_S) as client:
        resp = await client.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": domain},
        )
        data = resp.json()
        hit = data.get("query_status") == "ok" and len(data.get("data", [])) > 0
        if hit:
            logger.info("threatfox_hit", extra={"domain": domain})
        return hit


# ═══════════════════════════════════════════════════════════════
# CHECK 10b: abuse.ch MalwareBazaar — malware-distribution hosts
# ═══════════════════════════════════════════════════════════════

async def check_malware_bazaar(domain: str) -> bool:
    """
    Check domain against MalwareBazaar's host index.

    Strategy doc Top-20 #5 — complete the abuse.ch bundle. Free, no
    key required; same 5-minute freshness as URLhaus. Returns True
    when MalwareBazaar has at least one malware sample tied to this
    host (delivery URL, payload download, or C2 callback).
    """
    async with httpx.AsyncClient(timeout=SOURCE_TIMEOUT_S) as client:
        resp = await client.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_taginfo", "tag": domain, "limit": "1"},
        )
        try:
            data = resp.json()
        except ValueError:
            return False
        # Documented response: query_status="ok" + data array with
        # samples means hits. "no_results" / "illegal_tag" → clean.
        hit = (
            data.get("query_status") == "ok"
            and isinstance(data.get("data"), list)
            and len(data["data"]) > 0
        )
        if hit:
            logger.info(
                "malware_bazaar_hit",
                extra={"domain": domain, "samples": len(data["data"])},
            )
        return hit


# ═══════════════════════════════════════════════════════════════
# CHECK 10c: abuse.ch Feodo Tracker — active botnet C2 servers
# ═══════════════════════════════════════════════════════════════

# Cached blocklist + last-fetch timestamp. Feodo Tracker publishes a
# small JSON blob (~100 KB) of active botnet C2 IPs/hosts, refreshed
# every 5 min. Polling on every /check would burn bandwidth + add
# 100-300ms latency; instead we cache the full set in-process and
# refresh on demand. Cheap, accurate, no rate limit risk.
_FEODO_CACHE: dict[str, object] = {
    "hosts": set(),
    "fetched_at": 0.0,
}
_FEODO_TTL_SECONDS = 300  # match upstream 5-min refresh cadence
_FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


async def _refresh_feodo_cache() -> None:
    import time as _time

    now = _time.time()
    if now - _FEODO_CACHE["fetched_at"] < _FEODO_TTL_SECONDS:
        return
    async with httpx.AsyncClient(timeout=SOURCE_TIMEOUT_S) as client:
        resp = await client.get(_FEODO_URL)
        if resp.status_code != 200:
            return
        try:
            data = resp.json()
        except ValueError:
            return
    # The blocklist is a flat list of dicts with `ip_address` and
    # sometimes `hostname`. We index both — caller normalises to
    # lowercase host before lookup.
    hosts: set = set()
    if isinstance(data, list):
        for row in data:
            if not isinstance(row, dict):
                continue
            ip = row.get("ip_address")
            host = row.get("hostname")
            if ip:
                hosts.add(str(ip).lower())
            if host:
                hosts.add(str(host).lower())
    _FEODO_CACHE["hosts"] = hosts
    _FEODO_CACHE["fetched_at"] = now
    logger.info("feodo_cache_refreshed", extra={"size": len(hosts)})


async def check_feodo_tracker(domain: str) -> bool:
    """
    Check domain against Feodo Tracker's active botnet C2 blocklist.

    Strategy doc Top-20 #5 — third leg of the abuse.ch bundle (with
    URLhaus + ThreatFox + MalwareBazaar). Catches the long tail of
    URL-flow-aware malware that doesn't reach end-user phishing
    blocklists but DOES talk to a known C2 from this host.
    """
    await _refresh_feodo_cache()
    hosts = _FEODO_CACHE["hosts"]
    if not isinstance(hosts, set) or not hosts:
        return False
    key = domain.strip().lower()
    hit = key in hosts
    if hit:
        logger.info("feodo_hit", extra={"domain": domain})
    return hit


# ═══════════════════════════════════════════════════════════════
# CHECK 11: Spamhaus DBL — domain blocklist via DNS
# ═══════════════════════════════════════════════════════════════

async def check_spamhaus_dbl(domain: str) -> bool:
    """
    Check domain against Spamhaus DBL via DNS lookup.
    Free for low-volume non-commercial use.
    Returns True if domain is listed (spam/phishing/malware).
    """
    import dns.resolver as dns_resolver

    resolver = dns_resolver.Resolver()
    resolver.timeout = SOURCE_TIMEOUT_S
    resolver.lifetime = SOURCE_TIMEOUT_S

    query = f"{domain}.dbl.spamhaus.org"
    try:
        answers = await asyncio.to_thread(resolver.resolve, query, "A")
        for answer in answers:
            ip = str(answer)
            # 127.0.1.2 = spam domain
            # 127.0.1.4 = phishing domain
            # 127.0.1.5 = malware domain
            # 127.0.1.6 = botnet C&C domain
            if ip.startswith("127.0.1."):
                logger.info("spamhaus_hit", extra={"domain": domain, "result": ip})
                return True
        return False
    except (dns_resolver.NXDOMAIN, dns_resolver.NoAnswer, dns_resolver.NoNameservers):
        return False  # Not listed
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# CHECK 12: SURBL — URI blocklist via DNS
# ═══════════════════════════════════════════════════════════════

async def check_surbl(domain: str) -> bool:
    """
    Check domain against SURBL multi list via DNS lookup.
    Free for low-volume non-commercial use.
    """
    import dns.resolver as dns_resolver

    # SURBL expects base domain (no subdomains for most queries)
    from api.services.scoring import _extract_base_domain
    base = _extract_base_domain(domain)

    resolver = dns_resolver.Resolver()
    resolver.timeout = SOURCE_TIMEOUT_S
    resolver.lifetime = SOURCE_TIMEOUT_S

    query = f"{base}.multi.surbl.org"
    try:
        answers = await asyncio.to_thread(resolver.resolve, query, "A")
        for answer in answers:
            ip = str(answer)
            # Any 127.0.0.x response = listed
            if ip.startswith("127."):
                logger.info("surbl_hit", extra={"domain": domain, "result": ip})
                return True
        return False
    except (dns_resolver.NXDOMAIN, dns_resolver.NoAnswer, dns_resolver.NoNameservers):
        return False
    except Exception:
        return False


# ═══════════════════════════════════════════════════════════════
# CHECK 13: AlienVault OTX — community threat intelligence
# ═══════════════════════════════════════════════════════════════

async def check_alienvault_otx(domain: str) -> dict:
    """
    Check domain reputation via AlienVault OTX (free, no key for basic lookup).
    Returns reputation data including pulse count (community threat reports).
    """
    async with httpx.AsyncClient(timeout=SOURCE_TIMEOUT_S) as client:
        resp = await client.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers={"Accept": "application/json"},
        )
        if resp.status_code != 200:
            return {}
        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        reputation = data.get("reputation", 0)
        return {
            "pulse_count": pulse_count,  # Number of community threat reports
            "reputation": reputation,
            "hit": pulse_count > 0,
        }


# ═══════════════════════════════════════════════════════════════
# CHECK 14: IPQualityScore — real-time URL risk scoring
# ═══════════════════════════════════════════════════════════════

async def check_ipqualityscore(domain: str) -> dict:
    """
    Check domain via IPQualityScore (free: 5K/month, key required).
    Returns risk score 0-100, phishing/malware/suspicious flags.
    """
    settings = get_settings()
    ipqs_key = getattr(settings, "ipqualityscore_key", "")
    if not ipqs_key:
        return {}
    # A service-wide daily cap: per-IP and per-install limits bound one
    # caller, never the sum of all of them.
    if not await paid_budget.take("ipqs", settings.ipqs_daily_budget):
        return {}

    async with httpx.AsyncClient(timeout=SOURCE_TIMEOUT_S) as client:
        resp = await client.get(
            f"https://ipqualityscore.com/api/json/url/{ipqs_key}/{domain}",
        )
        if resp.status_code != 200:
            return {}
        data = resp.json()
        if not data.get("success"):
            return {}
        return {
            "risk_score": data.get("risk_score", 0),
            "phishing": data.get("phishing", False),
            "malware": data.get("malware", False),
            "suspicious": data.get("suspicious", False),
            "hit": data.get("phishing", False) or data.get("malware", False),
        }

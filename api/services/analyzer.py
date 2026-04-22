"""
Domain Analysis Engine 3.0

Runs 8 parallel checks via circuit breakers:
  1. Google Safe Browsing (blocklist)
  2. PhishTank (blocklist)
  3. URLhaus / abuse.ch (blocklist)
  4. WHOIS/RDAP (domain age, registrar)
  5. SSL certificate (issuer, age, free cert detection)
  6. Security headers (HSTS, CSP, etc.)
  7. DNS analysis (TTL, NS count, MX existence)
  8. Redirect chain (depth, cross-domain redirects)

Privacy: only domain names processed — never full URLs or user data.
"""

from __future__ import annotations

import asyncio
import dns.resolver  # dnspython
import logging
import ssl
import socket
from datetime import datetime, timezone

import httpx

from api.config import get_settings
from api.services.scoring import calculate_score, calculate_confidence
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
)
from api.models.schemas import DomainResult, DomainReason, RiskLevel, ConfidenceLevel

logger = logging.getLogger("cleanway.analyzer")


# ═══════════════════════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════

async def analyze_domain(domain: str, raw_url: str = "") -> DomainResult:
    """
    Analyze a domain by running 8 checks in parallel.
    Returns a DomainResult with score, level, confidence, and reasons.
    """
    # ── Validate & normalize domain (SSRF protection) ──
    try:
        domain = validate_domain(domain)
    except DomainValidationError as e:
        logger.warning("Domain validation failed: %s — %s", domain, str(e))
        return DomainResult(
            domain=domain, score=0, level=RiskLevel.caution,
            reasons=[DomainReason(signal="invalid_domain", detail=f"Invalid domain: {str(e)}", weight=0)],
        )

    is_ip = _is_ip_address(domain)

    # Resolve DNS and block internal IPs before making any requests
    try:
        await validate_domain_resolution(domain)
    except DomainValidationError as e:
        logger.warning("DNS resolution blocked (SSRF): %s — %s", domain, str(e))
        return DomainResult(
            domain=domain, score=100, level=RiskLevel.dangerous,
            reasons=[DomainReason(signal="ssrf_blocked", detail="Domain resolves to a blocked network", weight=100)],
        )

    # ── Run ALL 14 checks in parallel via circuit breakers ──
    results = await asyncio.gather(
        # Blocklist sources (9)
        safe_browsing_breaker.call(check_safe_browsing, domain),   # 0
        phishtank_breaker.call(check_phishtank, domain),           # 1
        urlhaus_breaker.call(check_urlhaus, domain),               # 2
        phishstats_breaker.call(check_phishstats, domain),         # 3
        threatfox_breaker.call(check_threatfox, domain),           # 4
        spamhaus_breaker.call(check_spamhaus_dbl, domain),         # 5
        surbl_breaker.call(check_surbl, domain),                   # 6
        alienvault_breaker.call(check_alienvault_otx, domain),     # 7
        ipqs_breaker.call(check_ipqualityscore, domain),           # 8
        # Enrichment sources (5)
        whois_breaker.call(check_whois_age, domain),               # 9
        ssl_breaker.call(check_ssl, domain),                       # 10
        headers_breaker.call(check_security_headers, domain),      # 11
        dns_breaker.call(check_dns, domain),                       # 12
        redirect_breaker.call(check_redirect_chain, domain),       # 13
    )

    total_checks = 14
    checks_succeeded = sum(1 for _, ok in results if ok)

    # ── Unpack blocklist results ──
    def _val(idx, default=False):
        return results[idx][0] if results[idx][1] else default

    safe_browsing_hit = _val(0)
    phishtank_hit = _val(1)
    urlhaus_hit = _val(2)
    phishstats_hit = _val(3)
    threatfox_hit = _val(4)
    spamhaus_hit = _val(5)
    surbl_hit = _val(6)
    alienvault_data = _val(7, default={})
    ipqs_data = _val(8, default={})

    # ── Unpack enrichment results ──
    whois_data = _val(9, default={})
    ssl_data = _val(10, default={})
    headers_data = _val(11, default={})
    dns_data = _val(12, default={})
    redirect_data = _val(13, default={})

    # Aggregate blocklist hits
    blocklist_hits = sum([
        safe_browsing_hit, phishtank_hit, urlhaus_hit,
        phishstats_hit, threatfox_hit, spamhaus_hit, surbl_hit,
        bool(alienvault_data.get("hit")),
        bool(ipqs_data.get("hit")),
    ])

    # Build signals dict — all 42+ signals for scoring engine
    signals = {
        "domain": domain,
        "raw_url": raw_url or domain,
        # Blocklist hits (9 sources)
        "safe_browsing_hit": safe_browsing_hit,
        "phishtank_hit": phishtank_hit,
        "urlhaus_hit": urlhaus_hit,
        "phishstats_hit": phishstats_hit,
        "threatfox_hit": threatfox_hit,
        "spamhaus_hit": spamhaus_hit,
        "surbl_hit": surbl_hit,
        "alienvault_pulse_count": alienvault_data.get("pulse_count", 0),
        "ipqs_risk_score": ipqs_data.get("risk_score", 0),
        "ipqs_phishing": ipqs_data.get("phishing", False),
        "blocklist_hits": blocklist_hits,
        # WHOIS
        "domain_age_days": whois_data.get("age_days"),
        "registrar": whois_data.get("registrar"),
        # SSL
        "is_ip_based": is_ip,
        "no_https": not ssl_data.get("has_ssl", True),
        "free_ssl": ssl_data.get("is_free_ssl", False),
        "cert_age_days": ssl_data.get("cert_age_days"),
        # Headers
        "missing_security_headers": headers_data.get("missing", []),
        # DNS
        "dns_ttl": dns_data.get("ttl"),
        "dns_ns_count": dns_data.get("ns_count"),
        "dns_has_mx": dns_data.get("has_mx", True),
        "dns_a_count": dns_data.get("a_count"),
        # Redirects
        "redirect_count": redirect_data.get("count", 0),
        "redirect_cross_domain": redirect_data.get("cross_domain", False),
        # Meta
        "checks_succeeded": checks_succeeded,
        "total_checks": total_checks,
    }

    score, level, reasons = calculate_score(signals)

    confidence = calculate_confidence(
        checks_succeeded, total_checks, whois_data.get("age_days")
    )

    if confidence == ConfidenceLevel.low and level == RiskLevel.safe:
        score = max(score, 25)
        level = RiskLevel.caution
        reasons.append(DomainReason(
            signal="partial_analysis", weight=0,
            detail=f"Only {checks_succeeded}/{total_checks} checks completed — limited confidence",
        ))

    if checks_succeeded < total_checks and score < 20:
        confidence = min(confidence, ConfidenceLevel.medium, key=lambda c: c.value)

    # ── Log ML feature vector (for future model training) ──
    try:
        from api.services.url_features import extract_features, log_features
        features = extract_features(domain, signals)
        log_features(domain, features, score)
    except Exception:
        pass  # Feature logging is non-critical

    logger.info("analysis_complete", extra={
        "domain": domain, "score": score, "level": level.value,
        "confidence": confidence.value, "checks": checks_succeeded,
    })

    return DomainResult(
        domain=domain, score=score, level=level, confidence=confidence,
        reasons=reasons,
        domain_age_days=whois_data.get("age_days"),
        has_ssl=ssl_data.get("has_ssl"),
        ssl_issuer=ssl_data.get("issuer"),
    )


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
    async with httpx.AsyncClient(timeout=3.0) as client:
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
    async with httpx.AsyncClient(timeout=3.0) as client:
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
    async with httpx.AsyncClient(timeout=3.0) as client:
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
# CHECK 5: SSL Certificate — issuer, age, free detection
# ═══════════════════════════════════════════════════════════════

async def check_ssl(domain: str) -> dict:
    try:
        result = await asyncio.get_event_loop().run_in_executor(None, _check_ssl_sync, domain)
        return result
    except Exception:
        return {"has_ssl": False}


def _check_ssl_sync(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Issuer info
                issuer_parts = dict(x[0] for x in cert.get("issuer", []))
                issuer_org = issuer_parts.get("organizationName", "Unknown")
                issuer_cn = issuer_parts.get("commonName", "")

                # Free SSL detection
                free_issuers = ["let's encrypt", "zerossl", "buypass", "ssl.com"]
                is_free = any(fi in issuer_org.lower() or fi in issuer_cn.lower() for fi in free_issuers)

                # Certificate age (notBefore → now)
                cert_age_days = None
                not_before = cert.get("notBefore")
                if not_before:
                    try:
                        # Format: "Mon DD HH:MM:SS YYYY GMT"
                        nb_date = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z")
                        nb_date = nb_date.replace(tzinfo=timezone.utc)
                        cert_age_days = (datetime.now(timezone.utc) - nb_date).days
                    except (ValueError, TypeError):
                        pass

                return {
                    "has_ssl": True,
                    "issuer": issuer_org,
                    "is_free_ssl": is_free,
                    "cert_age_days": cert_age_days,
                }
    except Exception:
        return {"has_ssl": False}


# ═══════════════════════════════════════════════════════════════
# CHECK 6: Security Headers
# ═══════════════════════════════════════════════════════════════

async def check_security_headers(domain: str) -> dict:
    important_headers = [
        "strict-transport-security", "content-security-policy",
        "x-frame-options", "x-content-type-options", "referrer-policy",
    ]
    try:
        async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, max_redirects=3) as client:
            resp = await client.head(f"https://{domain}/")
            present = [h for h in important_headers if h in resp.headers]
            missing = [h for h in important_headers if h not in resp.headers]
            return {"present": present, "missing": missing}
    except Exception:
        try:
            async with httpx.AsyncClient(timeout=5.0, follow_redirects=True, max_redirects=3) as client:
                resp = await client.head(f"http://{domain}/")
                missing = [h for h in important_headers if h not in resp.headers]
                return {"present": [], "missing": missing}
        except Exception:
            return {"missing": important_headers}


# ═══════════════════════════════════════════════════════════════
# CHECK 7: DNS Analysis — TTL, NS count, MX, A record count
# ═══════════════════════════════════════════════════════════════

async def check_dns(domain: str) -> dict:
    """
    Analyze DNS records for phishing indicators:
    - Low TTL = fast-flux (bulletproof hosting)
    - No MX = not a real business domain
    - Many A records = CDN or fast-flux
    - Few/suspicious NS = cheap/disposable hosting
    """
    result = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 3

    # A records + TTL
    try:
        answers = await asyncio.get_event_loop().run_in_executor(
            None, lambda: resolver.resolve(domain, "A")
        )
        result["a_count"] = len(answers)
        result["ttl"] = answers.rrset.ttl if answers.rrset else None
    except Exception:
        result["a_count"] = 0
        result["ttl"] = None

    # NS records
    try:
        ns_answers = await asyncio.get_event_loop().run_in_executor(
            None, lambda: resolver.resolve(domain, "NS")
        )
        result["ns_count"] = len(ns_answers)
        result["nameservers"] = [str(ns) for ns in ns_answers]
    except Exception:
        result["ns_count"] = 0

    # MX records
    try:
        mx_answers = await asyncio.get_event_loop().run_in_executor(
            None, lambda: resolver.resolve(domain, "MX")
        )
        result["has_mx"] = len(mx_answers) > 0
    except Exception:
        result["has_mx"] = False

    return result


# ═══════════════════════════════════════════════════════════════
# CHECK 8: Redirect Chain Analysis
# ═══════════════════════════════════════════════════════════════

async def check_redirect_chain(domain: str) -> dict:
    """
    Follow redirects and analyze the chain:
    - Many redirects = obfuscation
    - Cross-domain redirects = suspicious (landing on different domain)
    """
    try:
        async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, max_redirects=5) as client:
            resp = await client.get(f"https://{domain}/")
            history = resp.history

            count = len(history)
            cross_domain = False
            domains_seen = set()

            for r in history:
                redirect_host = r.headers.get("location", "")
                if "://" in redirect_host:
                    from urllib.parse import urlparse
                    parsed = urlparse(redirect_host)
                    if parsed.hostname:
                        domains_seen.add(parsed.hostname.lower())

            # Check if we ended up on a different domain
            final_host = resp.url.host
            if final_host and final_host.lower() != domain.lower():
                cross_domain = True
                domains_seen.add(final_host.lower())

            return {
                "count": count,
                "cross_domain": cross_domain,
                "domains_visited": list(domains_seen),
                "final_url": str(resp.url),
            }
    except Exception:
        # Try HTTP fallback
        try:
            async with httpx.AsyncClient(timeout=4.0, follow_redirects=True, max_redirects=5) as client:
                resp = await client.get(f"http://{domain}/")
                return {
                    "count": len(resp.history),
                    "cross_domain": resp.url.host and resp.url.host.lower() != domain.lower(),
                }
        except Exception:
            return {"count": 0, "cross_domain": False}


# ═══════════════════════════════════════════════════════════════
# CHECK 9: PhishStats — aggregated phishing intelligence
# ═══════════════════════════════════════════════════════════════

async def check_phishstats(domain: str) -> bool:
    """Check domain against PhishStats API (free, no key, 20 req/min)."""
    async with httpx.AsyncClient(timeout=3.0) as client:
        resp = await client.get(
            f"https://phishstats.info:2096/api/phishing?_where=(url,like,~{domain}~)&_size=1"
        )
        data = resp.json()
        hit = isinstance(data, list) and len(data) > 0
        if hit:
            logger.info("phishstats_hit", extra={"domain": domain})
        return hit


# ═══════════════════════════════════════════════════════════════
# CHECK 10: abuse.ch ThreatFox — IOC database
# ═══════════════════════════════════════════════════════════════

async def check_threatfox(domain: str) -> bool:
    """Check domain against ThreatFox IOC database (free, no key)."""
    async with httpx.AsyncClient(timeout=3.0) as client:
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
    resolver.timeout = 3
    resolver.lifetime = 3

    query = f"{domain}.dbl.spamhaus.org"
    try:
        answers = await asyncio.get_event_loop().run_in_executor(
            None, lambda: resolver.resolve(query, "A")
        )
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
    resolver.timeout = 3
    resolver.lifetime = 3

    query = f"{base}.multi.surbl.org"
    try:
        answers = await asyncio.get_event_loop().run_in_executor(
            None, lambda: resolver.resolve(query, "A")
        )
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
    async with httpx.AsyncClient(timeout=3.0) as client:
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

    async with httpx.AsyncClient(timeout=3.0) as client:
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

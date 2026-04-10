"""
Scoring Engine 3.0 — Production-grade phishing detection.

30+ signals across 6 categories:
  1. Blocklist hits (Safe Browsing, PhishTank, URLhaus)
  2. Allowlist checks (Tranco Top 100K)
  3. URL lexical analysis (length, entropy, special chars, encoding)
  4. Brand impersonation (typosquatting, homograph, subdomain abuse, combosquatting)
  5. DNS/WHOIS enrichment (domain age, SSL, security headers)
  6. TLD & structural analysis (risky TLDs, depth, keywords)

Score 0-100. Thresholds: 0-20 safe / 21-50 caution / 51-100 dangerous.

Architecture: Layered pipeline.
  Layer 1: Blocklist check → instant block
  Layer 2: Allowlist check → instant safe
  Layer 3: Feature extraction + rule scoring → 0-100
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
from collections import Counter
from difflib import SequenceMatcher
from typing import Optional

from api.models.schemas import RiskLevel, DomainReason, ConfidenceLevel

logger = logging.getLogger("linkshield.scoring")

# ═══════════════════════════════════════════════════════════════
# DATA LOADING
# ═══════════════════════════════════════════════════════════════

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")


def _load_json_set(filename: str) -> set[str]:
    """Load a JSON list/dict file as a set of domain strings."""
    path = os.path.join(_DATA_DIR, filename)
    try:
        with open(path, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                return set(d.lower() for d in data)
            elif isinstance(data, dict):
                return set(d.lower() for d in data.keys())
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("Failed to load %s: %s — using built-in fallback", filename, e)
    return set()


def _load_json_dict(filename: str) -> dict:
    path = os.path.join(_DATA_DIR, filename)
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


# ── Load Tranco top domains (100K from file, 50 builtin fallback) ──

_TRANCO_TOP_100K: set[str] = _load_json_set("top_100k.json")
_TRANCO_TOP_10K: dict = _load_json_dict("top_10k.json")

_BUILTIN_TOP_DOMAINS = {
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "x.com", "instagram.com", "linkedin.com", "reddit.com",
    "apple.com", "microsoft.com", "github.com", "netflix.com", "whatsapp.com",
    "tiktok.com", "yahoo.com", "bing.com", "zoom.us", "paypal.com",
    "stripe.com", "shopify.com", "wordpress.com", "medium.com", "notion.so",
    "slack.com", "discord.com", "telegram.org", "spotify.com", "twitch.tv",
    "stackoverflow.com", "cloudflare.com", "dropbox.com", "adobe.com",
    "salesforce.com", "oracle.com", "samsung.com", "ebay.com", "walmart.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "usps.com",
    "ups.com", "fedex.com", "dhl.com", "citi.com",
}

TOP_DOMAINS: set[str] = _TRANCO_TOP_100K if _TRANCO_TOP_100K else _BUILTIN_TOP_DOMAINS

_domains_source = "tranco_100k" if _TRANCO_TOP_100K else "builtin_50"
logger.info("Loaded %d top domains from %s", len(TOP_DOMAINS), _domains_source)


# ═══════════════════════════════════════════════════════════════
# BRAND TARGETS — loaded from external JSON (100+ brands)
# ═══════════════════════════════════════════════════════════════

def _load_typosquat_targets() -> dict[str, str]:
    """Load typosquat targets from data/typosquat_targets.json or fall back to built-in."""
    path = os.path.join(_DATA_DIR, "typosquat_targets.json")
    try:
        with open(path, "r") as f:
            data = json.load(f)
            brands = data.get("brands", data)
            if isinstance(brands, dict):
                return {k.lower(): v.lower() for k, v in brands.items() if k != "_meta"}
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.warning("Failed to load typosquat_targets.json: %s — using built-in", e)

    # Minimal fallback
    return {
        "paypal": "paypal.com", "apple": "apple.com", "google": "google.com",
        "amazon": "amazon.com", "microsoft": "microsoft.com", "netflix": "netflix.com",
        "facebook": "facebook.com", "instagram": "instagram.com",
    }


TYPOSQUAT_TARGETS: dict[str, str] = _load_typosquat_targets()
logger.info("Loaded %d typosquat brand targets", len(TYPOSQUAT_TARGETS))


# ═══════════════════════════════════════════════════════════════
# ABUSED REGISTRAR LIST
# ═══════════════════════════════════════════════════════════════

def _load_abused_registrars() -> tuple[set[str], set[str]]:
    path = os.path.join(_DATA_DIR, "abused_registrars.json")
    try:
        with open(path, "r") as f:
            data = json.load(f)
            high = set(r.lower() for r in data.get("high_risk", []))
            medium = set(r.lower() for r in data.get("medium_risk", []))
            return high, medium
    except (FileNotFoundError, json.JSONDecodeError):
        return set(), set()


_ABUSED_REGISTRARS_HIGH, _ABUSED_REGISTRARS_MEDIUM = _load_abused_registrars()


# ═══════════════════════════════════════════════════════════════
# TLD RISK SCORING
# ═══════════════════════════════════════════════════════════════

HIGH_RISK_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",       # Free TLDs — 80%+ abuse rate
    ".xyz", ".top", ".work", ".click",        # Cheap gTLDs — heavily abused
    ".buzz", ".rest", ".surf", ".icu",        # New gTLDs — high abuse
    ".cam", ".live", ".online", ".site",      # Common phishing
    ".loan", ".racing", ".win", ".download",  # Almost exclusively spam
}

MEDIUM_RISK_TLDS = {
    ".info", ".biz", ".cc", ".pw", ".ws",
    ".club", ".space", ".fun", ".monster",
    ".store", ".stream", ".gdn", ".bid",
}


# ═══════════════════════════════════════════════════════════════
# HOMOGRAPH DETECTION — confusable Unicode characters
# ═══════════════════════════════════════════════════════════════

_CONFUSABLES: dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0458": "j", "\u04bb": "h", "\u0501": "d", "\u051b": "q",
    # Greek → Latin
    "\u03b1": "a", "\u03bf": "o", "\u0391": "A", "\u0392": "B",
    "\u0395": "E", "\u0397": "H", "\u0399": "I", "\u039a": "K",
    "\u039c": "M", "\u039d": "N", "\u039f": "O", "\u03a1": "P",
    "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
    # Latin extended
    "\u0261": "g", "\u026a": "i", "\u0299": "b",
    "\u1d0f": "o", "\u1d1c": "u",
}

_CHAR_SUBS: dict[str, str] = {
    "1": "l", "0": "o", "3": "e", "@": "a", "5": "s", "!": "i",
}

_SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "update", "confirm", "secure", "account", "banking", "password",
    "reset", "suspend", "locked", "unlock", "validate", "authenticate",
    "wallet", "payment", "invoice", "billing", "refund", "recovery",
    "alert", "notification", "urgent", "expired", "reactivate",
}

# URL shorteners to detect
_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bl.ink", "lnkd.in", "rb.gy", "cutt.ly",
    "short.io", "rebrand.ly", "tiny.cc", "surl.li", "shorturl.at",
    "v.gd", "qr.ae", "dub.sh", "link.infini.fr", "t.ly",
    "u.to", "clck.ru", "shrtco.de", "1url.cz",
}


# ═══════════════════════════════════════════════════════════════
# URL LEXICAL FEATURE EXTRACTION
# ═══════════════════════════════════════════════════════════════

def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string. Higher = more random (DGA indicator)."""
    if not s:
        return 0.0
    counter = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counter.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 3)


def _digit_ratio(s: str) -> float:
    """Ratio of digits to total characters."""
    if not s:
        return 0.0
    digits = sum(1 for c in s if c.isdigit())
    return round(digits / len(s), 3)


def _special_char_count(domain: str) -> int:
    """Count hyphens and dots beyond the minimum."""
    hyphens = domain.count("-")
    # Dots beyond TLD separator are suspicious
    extra_dots = max(0, domain.count(".") - 1)
    return hyphens + extra_dots


def _has_at_symbol(url_or_domain: str) -> bool:
    """@ in URL causes browser to ignore everything before it — classic phishing trick."""
    return "@" in url_or_domain


def _has_double_slash_redirect(url_or_domain: str) -> bool:
    """Double slash in path indicates redirect attempt."""
    # Find // after the protocol
    stripped = url_or_domain
    for prefix in ("http://", "https://"):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]
    return "//" in stripped


def _has_hex_encoding(url_or_domain: str) -> bool:
    """Percent-encoded characters in domain part (obfuscation)."""
    return bool(re.search(r"%[0-9a-fA-F]{2}", url_or_domain))


def _has_non_standard_port(url_or_domain: str) -> bool:
    """Non-standard port number in URL."""
    match = re.search(r":(\d+)", url_or_domain)
    if match:
        port = int(match.group(1))
        if port not in (80, 443, 8080, 8443):
            return True
    return False


def _url_path_depth(url_or_domain: str) -> int:
    """Count path depth: example.com/a/b/c → depth 3."""
    if "/" in url_or_domain:
        path = url_or_domain.split("/", 1)[1] if "/" in url_or_domain else ""
        return path.count("/")
    return 0


def _has_fake_tld_in_subdomain(domain: str) -> bool:
    """Detect paypal.com.evil.xyz pattern — real TLD used as subdomain."""
    parts = domain.split(".")
    if len(parts) <= 2:
        return False
    # Check if any subdomain part looks like a known TLD
    real_tlds = {"com", "org", "net", "gov", "edu", "co", "io", "me"}
    subdomain_parts = parts[:-2]  # Everything except actual base domain
    for part in subdomain_parts:
        if part in real_tlds:
            return True
    return False


def _is_url_shortener(domain: str) -> bool:
    """Check if domain is a known URL shortener."""
    base = _extract_base_domain(domain)
    return base in _URL_SHORTENERS


# ═══════════════════════════════════════════════════════════════
# MAIN SCORING FUNCTION — 30+ SIGNALS
# ═══════════════════════════════════════════════════════════════

def calculate_score(signals: dict) -> tuple[int, RiskLevel, list[DomainReason]]:
    """
    Layered scoring pipeline with 30+ signals.

    Layer 1: Blocklist → instant dangerous
    Layer 2: Allowlist (Tranco 100K) → instant safe
    Layer 3: Feature extraction → weighted scoring
    """
    score = 0
    reasons: list[DomainReason] = []
    domain: str = signals.get("domain", "")
    base_domain = _extract_base_domain(domain)
    domain_name = base_domain.split(".")[0] if "." in base_domain else base_domain

    # ════════════════════════════════════════════
    # LAYER 1: BLOCKLIST CHECK (instant block)
    # ════════════════════════════════════════════

    if signals.get("safe_browsing_hit"):
        score += 80
        reasons.append(DomainReason(
            signal="safe_browsing", weight=80,
            detail="Flagged by Google Safe Browsing as dangerous",
        ))

    if signals.get("phishtank_hit"):
        score += 70
        reasons.append(DomainReason(
            signal="phishtank", weight=70,
            detail="Listed in PhishTank phishing database",
        ))

    if signals.get("urlhaus_hit"):
        score += 75
        reasons.append(DomainReason(
            signal="urlhaus", weight=75,
            detail="Listed in URLhaus malware URL database",
        ))

    if signals.get("phishstats_hit"):
        score += 65
        reasons.append(DomainReason(
            signal="phishstats", weight=65,
            detail="Found in PhishStats aggregated phishing database",
        ))

    if signals.get("threatfox_hit"):
        score += 70
        reasons.append(DomainReason(
            signal="threatfox", weight=70,
            detail="Listed in ThreatFox IOC database (abuse.ch)",
        ))

    if signals.get("spamhaus_hit"):
        score += 75
        reasons.append(DomainReason(
            signal="spamhaus_dbl", weight=75,
            detail="Listed in Spamhaus Domain Block List",
        ))

    if signals.get("surbl_hit"):
        score += 65
        reasons.append(DomainReason(
            signal="surbl", weight=65,
            detail="Listed in SURBL URI blocklist",
        ))

    # AlienVault OTX community reports
    alienvault_pulses = signals.get("alienvault_pulse_count", 0)
    if alienvault_pulses > 5:
        score += 60
        reasons.append(DomainReason(
            signal="alienvault_otx_high", weight=60,
            detail=f"Flagged in {alienvault_pulses} AlienVault OTX threat reports",
        ))
    elif alienvault_pulses > 0:
        score += 30
        reasons.append(DomainReason(
            signal="alienvault_otx", weight=30,
            detail=f"Found in {alienvault_pulses} AlienVault OTX threat report(s)",
        ))

    # IPQualityScore
    if signals.get("ipqs_phishing"):
        score += 70
        reasons.append(DomainReason(
            signal="ipqs_phishing", weight=70,
            detail="Identified as phishing by IPQualityScore",
        ))
    elif signals.get("ipqs_risk_score", 0) > 75:
        score += 40
        reasons.append(DomainReason(
            signal="ipqs_high_risk", weight=40,
            detail=f"High risk score ({signals['ipqs_risk_score']}) from IPQualityScore",
        ))

    # Multi-source confirmation boost
    blocklist_count = signals.get("blocklist_hits", 0)
    if blocklist_count >= 3:
        score += 20
        reasons.append(DomainReason(
            signal="multi_blocklist", weight=20,
            detail=f"Flagged by {blocklist_count} independent blocklist sources — high confidence threat",
        ))

    # If any blocklist hit, skip allowlist and return high score
    if score >= 70:
        score = min(score, 100)
        return score, RiskLevel.dangerous, reasons

    # ════════════════════════════════════════════
    # LAYER 2: ALLOWLIST CHECK (instant safe)
    # ════════════════════════════════════════════

    # ── Hosting platforms: subdomains can be anyone's ──
    _HOSTING_PLATFORMS = {
        # CDN / Cloud hosting
        "pages.dev", "workers.dev", "r2.dev",                   # Cloudflare
        "netlify.app", "vercel.app", "onrender.com",             # Jamstack
        "herokuapp.com", "fly.dev", "railway.app", "deno.dev",   # PaaS
        "github.io", "gitlab.io", "bitbucket.io",                # Git hosting
        "web.app", "firebaseapp.com", "appspot.com",             # Google/Firebase
        "azurewebsites.net", "blob.core.windows.net",            # Azure
        "cloudfront.net", "s3.amazonaws.com", "amplifyapp.com",  # AWS
        # Website builders
        "blogspot.com", "wordpress.com", "wixsite.com", "wixstudio.com",
        "weebly.com", "squarespace.com", "webflow.io",
        "framer.app", "framer.website",                          # Framer
        "carrd.co", "notion.site", "super.site",
        "myshopify.com", "square.site", "bigcartel.com",
        "lovable.app", "replit.app", "glitch.me",
        # Free hosting
        "000webhostapp.com", "infinityfreeapp.com",
        "webcindario.com", "bravenet.com", "tripod.com",
        "atwebpages.com", "epizy.com", "rf.gd",
        "contaboserver.net", "hostinger.com",
        # URL shorteners already handled separately
        # Google Docs (special case)
        "docs.google.com", "forms.google.com", "sites.google.com",
    }

    # Also treat Google subdomains used for phishing specially
    _GOOGLE_ABUSED_SUBDOMAINS = {
        "docs.google.com", "forms.google.com", "sites.google.com",
        "drive.google.com", "translate.google.com",
    }

    # Subdomains on hosting platforms = NOT safe (anyone can register)
    is_hosting_sub = base_domain in _HOSTING_PLATFORMS and domain != base_domain

    # Full domain match for Google abused services
    is_google_abused = domain in _GOOGLE_ABUSED_SUBDOMAINS or any(
        domain.startswith(g) for g in _GOOGLE_ABUSED_SUBDOMAINS
    )

    # URL shorteners hide the real destination
    if _is_url_shortener(base_domain) or is_hosting_sub or is_google_abused:
        pass  # Don't auto-safe — continue to scoring
    elif base_domain in TOP_DOMAINS:
        rank = _TRANCO_TOP_10K.get(base_domain)
        detail = f"Ranked #{rank} globally" if rank else "In global top 100K domains"
        return 0, RiskLevel.safe, [DomainReason(
            signal="known_legitimate", weight=-50,
            detail=f"Known legitimate domain: {base_domain}. {detail}",
        )]

    # ════════════════════════════════════════════
    # LAYER 3: FEATURE SCORING (30+ signals)
    # ════════════════════════════════════════════

    # ── 3.1 Homograph / IDN attack ──
    homograph_target = _check_homograph(domain)
    if homograph_target:
        score += 60
        reasons.append(DomainReason(
            signal="homograph_attack", weight=60,
            detail=f"Uses look-alike Unicode characters to impersonate {homograph_target}",
        ))

    # ── 3.2 Domain age ──
    domain_age = signals.get("domain_age_days")
    if domain_age is not None:
        if domain_age < 7:
            score += 50
            reasons.append(DomainReason(
                signal="domain_very_new", weight=50,
                detail=f"Domain registered {domain_age} days ago — very suspicious",
            ))
        elif domain_age < 30:
            score += 30
            reasons.append(DomainReason(
                signal="domain_new", weight=30,
                detail=f"Domain registered {domain_age} days ago",
            ))

    # ── 3.3 IP-based URL ──
    if signals.get("is_ip_based"):
        score += 35
        reasons.append(DomainReason(
            signal="ip_based", weight=35,
            detail="Uses IP address instead of domain name",
        ))

    # ── 3.4 Typosquatting (6 methods) ──
    typosquat_result = _check_typosquatting_v2(domain)
    if typosquat_result:
        legit_domain, method = typosquat_result
        score += 25
        reasons.append(DomainReason(
            signal="typosquatting", weight=25,
            detail=f"Impersonates {legit_domain} ({method})",
        ))

    # ── 3.5 Brand in subdomain: "paypal.evil.com" ──
    brand_sub = _check_brand_in_subdomain(domain)
    if brand_sub:
        score += 30
        reasons.append(DomainReason(
            signal="brand_subdomain_abuse", weight=30,
            detail=f"Uses '{brand_sub}' brand name in subdomain to deceive",
        ))

    # ── 3.6 Fake TLD in subdomain: "paypal.com.evil.xyz" ──
    if _has_fake_tld_in_subdomain(domain):
        score += 35
        reasons.append(DomainReason(
            signal="fake_tld_subdomain", weight=35,
            detail="Contains a real TLD in subdomain (e.g., example.com.evil.xyz)",
        ))

    # ── 3.7 No HTTPS ──
    if signals.get("no_https"):
        score += 40
        reasons.append(DomainReason(
            signal="no_https", weight=40,
            detail="Site does not use HTTPS encryption",
        ))

    # ── 3.8 Free SSL + new domain combo ──
    if signals.get("free_ssl") and domain_age is not None and domain_age < 30:
        score += 20
        reasons.append(DomainReason(
            signal="free_ssl_new_domain", weight=20,
            detail="Free SSL certificate on a new domain — common phishing pattern",
        ))

    # ── 3.9 Missing security headers ──
    missing_headers = signals.get("missing_security_headers", [])
    if len(missing_headers) >= 3:
        score += 15
        reasons.append(DomainReason(
            signal="missing_headers", weight=15,
            detail=f"Missing security headers: {', '.join(missing_headers[:3])}",
        ))

    # ── 3.10 Risky TLD ──
    tld = _extract_tld(domain)
    if tld in HIGH_RISK_TLDS:
        score += 20
        reasons.append(DomainReason(
            signal="risky_tld_high", weight=20,
            detail=f"Uses high-risk TLD '{tld}' — commonly abused in phishing",
        ))
    elif tld in MEDIUM_RISK_TLDS:
        score += 10
        reasons.append(DomainReason(
            signal="risky_tld_medium", weight=10,
            detail=f"Uses suspicious TLD '{tld}'",
        ))

    # ── 3.11 Excessive subdomains (>3 levels) ──
    dot_count = domain.count(".")
    if dot_count >= 3:
        score += 15
        reasons.append(DomainReason(
            signal="excessive_subdomains", weight=15,
            detail=f"Unusually deep subdomain nesting ({dot_count + 1} levels)",
        ))

    # ── 3.12 Suspicious keywords in domain ──
    keyword = _check_suspicious_keywords(domain)
    if keyword:
        score += 10
        reasons.append(DomainReason(
            signal="suspicious_keyword", weight=10,
            detail=f"Contains suspicious keyword: '{keyword}'",
        ))

    # ── 3.13 Shannon entropy (DGA detection) ──
    entropy = _shannon_entropy(domain_name)
    if entropy > 4.0 and len(domain_name) > 8:
        score += 20
        reasons.append(DomainReason(
            signal="high_entropy", weight=20,
            detail=f"Domain name has unusually high randomness (entropy={entropy}) — possible auto-generated domain",
        ))
    elif entropy > 3.5 and len(domain_name) > 10:
        score += 10
        reasons.append(DomainReason(
            signal="medium_entropy", weight=10,
            detail=f"Domain name appears somewhat random (entropy={entropy})",
        ))

    # ── 3.14 High digit ratio ──
    d_ratio = _digit_ratio(domain_name)
    if d_ratio > 0.4 and len(domain_name) > 5:
        score += 15
        reasons.append(DomainReason(
            signal="high_digit_ratio", weight=15,
            detail=f"Domain name is {round(d_ratio*100)}% digits — suspicious",
        ))

    # ── 3.15 Excessive special characters ──
    special = _special_char_count(domain)
    if special >= 4:
        score += 15
        reasons.append(DomainReason(
            signal="excessive_special_chars", weight=15,
            detail=f"Excessive hyphens/dots ({special}) in domain",
        ))
    elif special >= 3:
        score += 8
        reasons.append(DomainReason(
            signal="many_special_chars", weight=8,
            detail=f"Multiple hyphens/dots ({special}) in domain",
        ))

    # ── 3.16 @ symbol in URL (browser ignores everything before @) ──
    raw_input = signals.get("raw_url", domain)
    if _has_at_symbol(raw_input):
        score += 40
        reasons.append(DomainReason(
            signal="at_symbol", weight=40,
            detail="Contains @ symbol — browser ignores everything before it (phishing trick)",
        ))

    # ── 3.17 Double-slash redirect ──
    if _has_double_slash_redirect(raw_input):
        score += 20
        reasons.append(DomainReason(
            signal="double_slash_redirect", weight=20,
            detail="Contains suspicious double-slash redirect in URL path",
        ))

    # ── 3.18 Hex/percent encoding in domain ──
    if _has_hex_encoding(domain):
        score += 20
        reasons.append(DomainReason(
            signal="hex_encoding", weight=20,
            detail="Domain contains percent-encoded characters (obfuscation)",
        ))

    # ── 3.19 Non-standard port ──
    if _has_non_standard_port(raw_input):
        score += 15
        reasons.append(DomainReason(
            signal="non_standard_port", weight=15,
            detail="Uses non-standard port number",
        ))

    # ── 3.20 URL length (long URLs are suspicious) ──
    url_len = len(raw_input)
    if url_len > 100:
        score += 15
        reasons.append(DomainReason(
            signal="very_long_url", weight=15,
            detail=f"Unusually long URL ({url_len} characters)",
        ))
    elif url_len > 75:
        score += 8
        reasons.append(DomainReason(
            signal="long_url", weight=8,
            detail=f"Long URL ({url_len} characters)",
        ))

    # ── 3.21 Deep path ──
    path_depth = _url_path_depth(raw_input)
    if path_depth > 5:
        score += 10
        reasons.append(DomainReason(
            signal="deep_path", weight=10,
            detail=f"Unusually deep URL path ({path_depth} levels)",
        ))

    # ── 3.22 URL shortener ──
    if _is_url_shortener(domain):
        score += 15
        reasons.append(DomainReason(
            signal="url_shortener", weight=15,
            detail="URL shortener detected — real destination is hidden",
        ))

    # ── 3.23 Domain length ──
    if len(domain_name) > 25:
        score += 10
        reasons.append(DomainReason(
            signal="long_domain_name", weight=10,
            detail=f"Unusually long domain name ({len(domain_name)} characters)",
        ))

    # ── 3.24 DNS: Low TTL (fast-flux indicator) ──
    dns_ttl = signals.get("dns_ttl")
    if dns_ttl is not None and dns_ttl < 300:
        score += 15
        reasons.append(DomainReason(
            signal="low_dns_ttl", weight=15,
            detail=f"Very low DNS TTL ({dns_ttl}s) — possible fast-flux infrastructure",
        ))

    # ── 3.25 DNS: No MX record (not a real business) ──
    if signals.get("dns_has_mx") is False:
        score += 8
        reasons.append(DomainReason(
            signal="no_mx_record", weight=8,
            detail="No MX (email) record — unlikely to be a legitimate business",
        ))

    # ── 3.26 DNS: Many A records (fast-flux or CDN) ──
    a_count = signals.get("dns_a_count")
    if a_count is not None and a_count > 10:
        score += 10
        reasons.append(DomainReason(
            signal="many_a_records", weight=10,
            detail=f"Unusually many A records ({a_count}) — possible fast-flux network",
        ))

    # ── 3.27 SSL: New certificate (issued < 7 days ago) ──
    cert_age = signals.get("cert_age_days")
    if cert_age is not None and cert_age < 7:
        score += 15
        reasons.append(DomainReason(
            signal="new_certificate", weight=15,
            detail=f"SSL certificate issued {cert_age} days ago — very new",
        ))

    # ── 3.28 Redirect chain: Too many redirects ──
    redirect_count = signals.get("redirect_count", 0)
    if redirect_count > 3:
        score += 15
        reasons.append(DomainReason(
            signal="excessive_redirects", weight=15,
            detail=f"Suspicious redirect chain ({redirect_count} hops)",
        ))
    elif redirect_count > 1:
        score += 5
        reasons.append(DomainReason(
            signal="multiple_redirects", weight=5,
            detail=f"Multiple redirects ({redirect_count} hops)",
        ))

    # ── 3.29 Redirect: Cross-domain (landing on different domain) ──
    if signals.get("redirect_cross_domain"):
        score += 20
        reasons.append(DomainReason(
            signal="cross_domain_redirect", weight=20,
            detail="Redirects to a different domain — possible phishing redirect",
        ))

    # ── 3.30 N-gram analysis: domain name "naturalness" ──
    from api.services.url_features import bigram_score, vowel_consonant_ratio, consecutive_consonants_max

    bg_score = bigram_score(domain_name)
    if bg_score < 0.15 and len(domain_name) > 7:
        score += 18
        reasons.append(DomainReason(
            signal="unnatural_ngram", weight=18,
            detail=f"Domain name has unnatural character patterns (bigram score={bg_score})",
        ))
    elif bg_score < 0.25 and len(domain_name) > 10:
        score += 8
        reasons.append(DomainReason(
            signal="suspicious_ngram", weight=8,
            detail=f"Domain name has unusual character patterns (bigram score={bg_score})",
        ))

    # ── 3.31 Vowel/consonant ratio anomaly ──
    vc_ratio = vowel_consonant_ratio(domain_name)
    if len(domain_name) > 6 and (vc_ratio < 0.2 or vc_ratio > 1.5):
        score += 12
        reasons.append(DomainReason(
            signal="abnormal_vowel_ratio", weight=12,
            detail=f"Abnormal vowel/consonant ratio ({vc_ratio}) — likely auto-generated",
        ))

    # ── 3.32 Consecutive consonants (>5 = very unnatural) ──
    max_cons = consecutive_consonants_max(domain_name)
    if max_cons >= 5 and len(domain_name) > 6:
        score += 12
        reasons.append(DomainReason(
            signal="consonant_cluster", weight=12,
            detail=f"Unnatural consonant cluster ({max_cons} consecutive) — possible DGA",
        ))

    # ── 3.33 Registrar reputation ──
    registrar = signals.get("registrar", "")
    if registrar:
        registrar_lower = registrar.lower()
        if any(ar in registrar_lower for ar in _ABUSED_REGISTRARS_HIGH):
            score += 12
            reasons.append(DomainReason(
                signal="abused_registrar", weight=12,
                detail=f"Registered through high-abuse registrar: {registrar[:40]}",
            ))
        elif any(ar in registrar_lower for ar in _ABUSED_REGISTRARS_MEDIUM):
            score += 5
            reasons.append(DomainReason(
                signal="risky_registrar", weight=5,
                detail=f"Registered through frequently-abused registrar: {registrar[:40]}",
            ))

    # ── 3.34 ML Model prediction ──
    try:
        from api.services.ml_scorer import ml_predict
        ml_result = ml_predict(domain)
        if ml_result:
            ml_prob = ml_result["phishing_probability"]
            ml_confidence = ml_result["confidence"]

            if ml_prob > 0.85 and ml_confidence > 0.7:
                score += 35
                reasons.append(DomainReason(
                    signal="ml_high_risk", weight=35,
                    detail=f"ML model: {ml_prob*100:.0f}% phishing probability (confidence: {ml_confidence*100:.0f}%)",
                ))
            elif ml_prob > 0.6:
                score += 20
                reasons.append(DomainReason(
                    signal="ml_suspicious", weight=20,
                    detail=f"ML model: {ml_prob*100:.0f}% phishing probability",
                ))
            elif ml_prob < 0.1 and score > 30:
                # ML says safe but rules say risky — reduce score slightly
                score -= 10
                reasons.append(DomainReason(
                    signal="ml_safe_override", weight=-10,
                    detail=f"ML model: only {ml_prob*100:.0f}% phishing probability — reducing risk score",
                ))
    except Exception:
        pass  # ML is optional — don't break scoring if unavailable

    # ── Clamp ──
    score = max(0, min(100, score))

    # ── Determine level ──
    if score <= 20:
        level = RiskLevel.safe
    elif score <= 50:
        level = RiskLevel.caution
    else:
        level = RiskLevel.dangerous

    return score, level, reasons


def calculate_confidence(
    checks_succeeded: int, total_checks: int, domain_age: Optional[int]
) -> ConfidenceLevel:
    if checks_succeeded >= 4 and domain_age is not None:
        return ConfidenceLevel.high
    elif checks_succeeded >= 3:
        return ConfidenceLevel.medium
    else:
        return ConfidenceLevel.low


# ═══════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def _extract_base_domain(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower()


def _extract_tld(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    return "." + parts[-1] if parts else ""


# ── Homograph detection ──

def _check_homograph(domain: str) -> Optional[str]:
    try:
        domain.encode("ascii")
        return None
    except UnicodeEncodeError:
        pass

    ascii_version = ""
    has_confusable = False
    for char in domain:
        if char in _CONFUSABLES:
            ascii_version += _CONFUSABLES[char]
            has_confusable = True
        else:
            ascii_version += char

    if not has_confusable:
        return None

    ascii_base = _extract_base_domain(ascii_version)
    if ascii_base in TOP_DOMAINS:
        return ascii_base

    ascii_name = ascii_base.split(".")[0]
    if ascii_name in TYPOSQUAT_TARGETS:
        return TYPOSQUAT_TARGETS[ascii_name]

    return None


# ── Typosquatting v2 ──

def _check_typosquatting_v2(domain: str) -> Optional[tuple[str, str]]:
    base = _extract_base_domain(domain)
    name = base.split(".")[0].lower()
    tld = _extract_tld(domain)

    for brand, legit_domain in TYPOSQUAT_TARGETS.items():
        if domain == legit_domain or base == legit_domain:
            continue

        # TLD confusion (paypal.co vs paypal.com)
        legit_tld = _extract_tld(legit_domain)
        if name == brand and tld != legit_tld:
            return (legit_domain, "TLD confusion")

        if brand == name:
            continue

        # Character substitution
        if _check_char_substitution(name, brand):
            return (legit_domain, "character substitution")

        # Transposition
        if _check_transposition(name, brand):
            return (legit_domain, "character swap")

        # Hyphen injection
        if name.replace("-", "") == brand and "-" in name:
            return (legit_domain, "hyphen injection")

        # Combosquatting
        if _check_combosquat(name, brand):
            return (legit_domain, "combosquatting")

        # SequenceMatcher fallback
        ratio = SequenceMatcher(None, name, brand).ratio()
        if ratio >= 0.82 and len(name) >= 4:
            return (legit_domain, "high similarity")

    return None


def _check_char_substitution(s1: str, s2: str) -> bool:
    if len(s1) != len(s2):
        return False
    normalized = ""
    for ch in s1:
        normalized += _CHAR_SUBS.get(ch, ch)
    if normalized == s2:
        return True
    diffs = sum(1 for a, b in zip(s1, s2) if a != b)
    return diffs <= 2


def _check_transposition(s1: str, s2: str) -> bool:
    if len(s1) != len(s2):
        return False
    for i in range(len(s2) - 1):
        swapped = s2[:i] + s2[i + 1] + s2[i] + s2[i + 2:]
        if s1 == swapped:
            return True
    return False


def _check_combosquat(name: str, brand: str) -> bool:
    combo_suffixes = _SUSPICIOUS_KEYWORDS | {"com", "net", "org", "official", "support", "help", "app", "web", "mail", "team"}
    combo_prefixes = _SUSPICIOUS_KEYWORDS | {"my", "the", "get", "go", "try", "use", "new", "real", "true"}

    if name.startswith(brand) and len(name) > len(brand):
        suffix = name[len(brand):].lstrip("-")
        if suffix in combo_suffixes:
            return True

    if name.endswith(brand) and len(name) > len(brand):
        prefix = name[:len(name) - len(brand)].rstrip("-")
        if prefix in combo_prefixes:
            return True

    return False


# ── Brand subdomain abuse ──

def _check_brand_in_subdomain(domain: str) -> Optional[str]:
    parts = domain.lower().strip(".").split(".")
    if len(parts) <= 2:
        return None
    base = _extract_base_domain(domain)
    for part in parts[:-2]:
        part_clean = part.replace("-", "")
        if part_clean in TYPOSQUAT_TARGETS:
            if base != TYPOSQUAT_TARGETS[part_clean]:
                return part_clean
    return None


# ── Suspicious keywords ──

def _check_suspicious_keywords(domain: str) -> Optional[str]:
    base = _extract_base_domain(domain)
    name = base.split(".")[0].lower()
    for part in name.replace("_", "-").split("-"):
        if part in _SUSPICIOUS_KEYWORDS:
            return part
    return None

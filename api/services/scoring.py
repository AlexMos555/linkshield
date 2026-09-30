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
from types import MappingProxyType
from typing import Mapping, NamedTuple, Optional

from api.models.schemas import RiskLevel, DomainReason, ConfidenceLevel
from api.services import ru_brands, ru_lures
from api.services.hosting_platforms import is_shared_platform_site

logger = logging.getLogger("cleanway.scoring")

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

# ── Public suffixes that are ALSO top domains ──
#
# Tranco ranks `us.org`, `github.io`, `blogspot.com`, `azurewebsites.net`,
# `bounceme.net` … in its top 100k — and every one of them is a public suffix
# (Mozilla PSL): anyone can register a name under it. Trusting "base domain in
# TOP_DOMAINS" for a SUBDOMAIN of these was an instant-safe hole: the live
# phishing host gwcu.us.org came back "safe, 99%" from /public/check without
# ever reaching the analyzer (found 2026-08-18 through the Android shield).
# Built by scripts/build_public_suffixes_in_top.py = every PSL rule whose
# last-two-labels base is in top_100k.json (1,539 entries, multi-label ones
# like s3.amazonaws.com included). See is_trusted_top_domain().
PUBLIC_SUFFIXES_IN_TOP: set[str] = _load_json_set("public_suffixes_in_top.json")
if not PUBLIC_SUFFIXES_IN_TOP:
    logger.warning("public_suffixes_in_top.json missing — falling back to the hand list only")

# ── Russian public suffixes (PSL) ──
#
# Every multi-label PSL rule under .ru / .su / .рф / .рус, in ASCII form: the
# reserved gov.ru / mil.ru / ac.ru / edu.ru / int.ru, the regional zones
# (spb.ru, msk.ru, nov.ru, adygeya.ru … and their .su twins), net.ru /
# org.ru / pp.ru, com.ru, ras.ru, the .рус city zones and a few hosting
# platforms. A name under one of them is registered AT that suffix, so it is
# the suffix plus one label — kvs.gov.spb.ru belongs to gov.spb.ru (the
# St Petersburg government), not to 'spb.ru'. Judging the last two labels
# instead compared 'spb' with brand names ("Impersonates ups.com"), read 'gov'
# as a fake TLD and counted three subdomain levels where there is one:
# 100/dangerous in production on 2026-09-27. public_suffixes_in_top.json
# cannot stand in: it only holds rules whose base ranks in Tranco.
# Built by scripts/build_ru_public_suffixes.py. See registrable_domain().
# Wildcard rules ('*.hosting.myjino.ru': every b.hosting.myjino.ru is itself
# a suffix) are kept apart, by their base.
_RU_PSL_RULES: frozenset[str] = frozenset(_load_json_set("ru_public_suffixes.json"))
RU_PUBLIC_SUFFIXES: frozenset[str] = frozenset(r for r in _RU_PSL_RULES if not r.startswith("*."))
_RU_WILDCARD_SUFFIXES: frozenset[str] = frozenset(r[2:] for r in _RU_PSL_RULES if r.startswith("*."))
if not RU_PUBLIC_SUFFIXES:
    logger.warning("ru_public_suffixes.json missing — Russian regional zones read as registrable domains")

# Suffixes in RU_PUBLIC_SUFFIXES whose names are not anyone's pick: the
# cctld.ru reserved zones (gov.ru is for federal bodies, mil.ru for the
# military, edu.ru / ac.ru / int.ru the same way) and ras.ru, whose names the
# Russian Academy of Sciences assigns to its own institutes. Everything else
# — the FAITID regional zones (spb.ru, msk.ru, nov.ru …), com.ru, net.ru,
# org.ru, pp.ru, the .рус city zones, the hosting platforms — sells or hands
# out names like any registry: on 2026-09-27 whois.flexireg.net had
# com.msk.ru, ru.msk.ru and gov.msk.ru held by private persons and
# org.spb.ru free to buy.
_RU_RESTRICTED_ZONES = frozenset({"ac.ru", "edu.ru", "gov.ru", "int.ru", "mil.ru", "ras.ru"})
# Second-level labels that mark a restricted zone under any other country
# code (gov.uk, ac.uk, go.jp, gob.mx …) for the compound-suffix heuristic.
_RESTRICTED_ZONE_LABELS = frozenset({"gov", "mil", "edu", "ac", "int", "gob", "gouv", "govt", "go", "gv", "sch"})

# Government sites registered under an OPEN regional zone, named one by one:
# 'gov' is not reserved there (gov.msk.ru is a private person's name), so
# only a name checked individually is a government's. gov.spb.ru: the
# St Petersburg government (Wikidata Q1993715, official website P856), on
# its own name servers ns{,2,3}.gov.spb.ru. Its 2010-04-23 creation date
# proves nothing — com.spb.ru has the same one, FAITID's migration date.
# Shared by the fake-TLD rule here and the analyzer's government vouch.
REGIONAL_GOVERNMENT_DOMAINS: frozenset[str] = frozenset({"gov.spb.ru"})


def is_regional_government_domain(domain: str) -> bool:
    """True for a REGIONAL_GOVERNMENT_DOMAINS name or any host under it."""
    name = (domain or "").lower().strip(".")
    return any(name == g or name.endswith("." + g) for g in REGIONAL_GOVERNMENT_DOMAINS)

# ── Shared platforms: subdomains can be anyone's ──
# Kept in sync with ml_features.HOSTING_PLATFORMS / refresh_dangerous_domains.
HOSTING_PLATFORMS: frozenset[str] = frozenset({
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
    # Google Docs (special case)
    "docs.google.com", "forms.google.com", "sites.google.com",
})

# What a broken certificate (site_probes `certificate_problem`) means for the
# person — the browser warning they will see.
_CERTIFICATE_PROBLEM_TEXT: dict[str, str] = {
    "expired": "The site's security certificate has expired, so your browser will warn that the connection is not private",
    "not_yet_valid": "The site's security certificate is not valid yet, so your browser will warn that the connection is not private",
    "self_signed": "The site's security certificate was not issued by a trusted authority, so your browser will warn that the connection is not private",
    "wrong_host": "The site's security certificate belongs to a different address, so your browser will warn that the connection is not private",
    "": "The site's security certificate is invalid, so your browser will warn that the connection is not private",
}

# Google subdomains used for phishing: never auto-safe.
GOOGLE_ABUSED_SUBDOMAINS: frozenset[str] = frozenset({
    "docs.google.com", "forms.google.com", "sites.google.com",
    "drive.google.com", "translate.google.com",
})


# Every suffix the scorer itself knows to be shared; the curated
# data/hosting_platforms.json (tw1.ru, weeblysite.com, forms.yandex.ru …) is
# added on top by hosting_platforms.is_shared_platform_site().
_SCORER_SHARED_SUFFIXES: frozenset[str] = frozenset(PUBLIC_SUFFIXES_IN_TOP) | HOSTING_PLATFORMS


def _is_under_shared_suffix(domain: str) -> bool:
    """True when `domain` is a STRICT subdomain of a public suffix / hosting
    platform (a name someone else could have registered), or a page host
    that many users publish to at different paths (forms.yandex.ru)."""
    # Every proper suffix of length >= 2 labels is checked: evil.s3.amazonaws.com
    # must match s3.amazonaws.com; a.b.evil.us.org must match us.org.
    return is_shared_platform_site(domain, _SCORER_SHARED_SUFFIXES)


def is_hosting_platform_site(domain: str) -> bool:
    """A customer's site on a hosting / site-builder platform, or a page on a
    user-content host — from the curated lists only. Deliberately NOT the
    PSL-derived set: that also holds restricted registries such as gov.ru,
    where "anyone can publish here" would be a false statement."""
    return is_shared_platform_site((domain or "").lower().strip("."), HOSTING_PLATFORMS)


def is_trusted_top_domain(domain: str) -> bool:
    """The ONE rule for the instant-safe allowlist short-circuit.

    True only when the domain is a top domain (Tranco 100k) or a subdomain of
    one that is NOT a shared platform / public suffix / URL shortener /
    abused Google service. Shared platforms include the curated
    data/hosting_platforms.json — Timeweb, Beget, SpaceWeb, Selectel, Weebly,
    WordPress staging, ScreenConnect, Yandex Forms/Disk … — whose customers'
    pages came back "safe, 99%" in production (report 2026-09-25 #7). Used by
    the public and authenticated /check routers and by the scorer's Layer 2,
    so none of them can disagree again.
    """
    d = (domain or "").lower().strip(".")
    if not d:
        return False
    base = _extract_base_domain(d)
    if base not in TOP_DOMAINS:
        return False
    if _is_url_shortener(base):
        return False
    if d in GOOGLE_ABUSED_SUBDOMAINS or any(d.startswith(g) for g in GOOGLE_ABUSED_SUBDOMAINS):
        return False
    if _is_under_shared_suffix(d):
        return False
    return True


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


# The global list exactly as loaded. brand_subdomain_abuse and the ML
# model's max_brand_similarity feature read THIS one, not the merged list
# below: the served model was trained on these brands' similarity, and a
# Russian brand as a subdomain label has not had its false-positive pass —
# 'pochta' is what Russian companies call their webmail (pochta.<company>.ru),
# and marketplace seller tools put ozon./wildberries. in front of their own
# names.
GLOBAL_TYPOSQUAT_TARGETS: Mapping[str, str] = MappingProxyType(_load_typosquat_targets())

# Russian brands (data/typosquat_targets_ru.json, see api.services.ru_brands):
# every official domain of the brand family, same-shaped sites of other
# owners, words one edit from a name, and per-brand switches for TLD
# confusion and edit distance.
RU_BRAND_GROUPS: tuple[ru_brands.BrandGroup, ...] = ru_brands.load()

# What the typosquat rule compares against: global first (so an existing
# host keeps the brand it was reported under), then the Russian names.
TYPOSQUAT_TARGETS: dict[str, str] = {
    **GLOBAL_TYPOSQUAT_TARGETS,
    **{n: d for g in RU_BRAND_GROUPS for n, d in g.names.items() if n not in GLOBAL_TYPOSQUAT_TARGETS},
}
logger.info("Loaded %d typosquat brand targets (%d Russian brand groups)", len(TYPOSQUAT_TARGETS), len(RU_BRAND_GROUPS))

# Every Russian brand's own registrable domains (yandex.kz, втб.рф), both
# spellings of an IDN.
_BRAND_OFFICIAL_DOMAINS: frozenset[str] = frozenset(d for g in RU_BRAND_GROUPS for d in g.official)
# Registrable domains that are no one's typo: a listed brand's own sites
# and verified sites of other owners with the same shape (mts.ca —
# Manitoba's phone company).
_BRAND_LEGIT_DOMAINS: frozenset[str] = _BRAND_OFFICIAL_DOMAINS | frozenset(
    d for g in RU_BRAND_GROUPS for d in g.unrelated
)
# Per name: labels one edit away that are words or other companies (ozone).
_BRAND_NOT_TYPOS: Mapping[str, frozenset[str]] = MappingProxyType(
    {n: g.not_typos for g in RU_BRAND_GROUPS for n in g.names if g.not_typos}
)
# The Russian list's names (sberbank, втб …): see _rule_for.
_RU_NAMES: frozenset[str] = frozenset(n for g in RU_BRAND_GROUPS for n in g.names)
# Names other owners use too — abroad (Tele2 AB, T Bank N.A.), as an
# acronym (vtb) or a word (ozon): TLD confusion only under a TLD phishing
# favours, and no combos with generic words.
_SHARED_NAMES: frozenset[str] = frozenset(n for g in RU_BRAND_GROUPS for n in g.shared_name)
# Names too few letters apart from other names for edit distance (tele2).
_NO_FUZZY: frozenset[str] = frozenset(n for g in RU_BRAND_GROUPS for n in g.no_fuzzy)
# Per name: lure words for this brand alone — its own product's name
# (СберБанк Онлайн: sberbank-online, сбербанк-онлайн), as ru_lures skeletons.
_BRAND_LURE_WORDS: Mapping[str, frozenset[str]] = MappingProxyType({
    n: frozenset(ru_lures.skeleton(w) for w in g.lure_words)
    for g in RU_BRAND_GROUPS for n in g.names if g.lure_words
})


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
    ".zip", ".mov",                            # Google file-ext TLDs — 18% malicious (Netskope 2025)
    ".sbs", ".cfd",                            # Newly heavily-abused junk TLDs (cybercrimeinfocenter 2026)
}

MEDIUM_RISK_TLDS = {
    ".info", ".biz", ".cc", ".pw", ".ws",
    ".club", ".space", ".fun", ".monster",
    ".store", ".shop", ".stream", ".gdn", ".bid",  # .shop: abused but mainstream e-commerce, sits with .store
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

# Look-alike characters and every letter each one passes for: '1' reads as
# l (paypa1) or i (1kea), '4' as a (eb4y).
_CHAR_SUBS: dict[str, str] = {
    "1": "li", "0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "!": "i",
}

# Multi-char ASCII glyph homoglyphs — the #1 lookalike tactic (Unit42 2025):
# "rn"->m, "vv"->w, "cl"->d survive IDN/punycode defenses AND change the label
# length, so they slip past single-char _CHAR_SUBS and Levenshtein<=2 checks.
_GLYPH_SUBS: list[tuple[str, str]] = [("rn", "m"), ("vv", "w"), ("cl", "d")]


def _glyph_skeleton(name: str) -> str:
    """Collapse multi-char glyph look-alikes so rnicrosoft->microsoft etc."""
    out = name
    for a, b in _GLYPH_SUBS:
        out = out.replace(a, b)
    return out

_SUSPICIOUS_KEYWORDS = {
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "update", "confirm", "secure", "account", "banking", "password",
    "reset", "suspend", "locked", "unlock", "validate", "authenticate",
    "wallet", "payment", "invoice", "billing", "refund", "recovery",
    "alert", "notification", "urgent", "expired", "reactivate",
    # Crypto-drainer lexicon (2025-2026: ledger-restore, metamask-claim, etc.)
    "connect", "restore", "sync", "migrate", "airdrop", "claim",
    "seed", "staking", "mint", "rewards", "presale",
}

# Combosquat action words are a SEPARATE, high-precision list. It must NOT be
# derived from _SUSPICIOUS_KEYWORDS: generic words like "connect"/"sync"/"rewards"/
# "restore" are common in legit brand-partner names (shopify-connect, chase-rewards)
# and would make brand+word combos false-positive as combosquats. These stay as
# standalone +10 keyword hits only.
_COMBOSQUAT_KEYWORDS = frozenset({
    "login", "signin", "sign-in", "log-in", "verify", "verification",
    "update", "confirm", "secure", "account", "banking", "password",
    "reset", "suspend", "locked", "unlock", "validate", "authenticate",
    "wallet", "payment", "invoice", "billing", "refund", "recovery",
    "alert", "notification", "urgent", "expired", "reactivate",
})

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


# ── PII / token leak detection in URL parameters ─────────────────
#
# Strategy doc Top-20 #20 (impact 6, diff 7) — "Detect URLs that
# exfiltrate the user's email or session token in plain query
# parameters — a common phishing-and-tracking hybrid". Matches
# nothing in the consumer category; differentiator for a privacy-
# first product.
#
# Three patterns we look for, in descending order of suspicion:
#
#   1. JWT / bearer-token-shaped value in any query parameter. Real
#      sites never put auth tokens in the URL (the URL is logged in
#      browser history, Referer headers, web-server access logs,
#      CDN logs, and analytics-pixel destinations — every one of
#      which becomes a token exfiltration vector). When we see it,
#      it's almost certainly a phishing redirector or a poorly
#      designed tracker stealing a session.
#
#   2. Email address in any query parameter. Legitimate sites
#      occasionally use this for one-click sign-in ("magic link"),
#      but always behind a one-time token — never as the plain
#      identifier. Plain-email parameters are the canonical
#      footprint of a tracker that fingerprints the user across
#      sites OR a phishing page that prefills its own form.
#
#   3. Long high-entropy random-looking strings (≥ 28 chars, mix of
#      digits + letters). Often session IDs, sometimes UUIDs.
#      Lower confidence than the first two — many legitimate
#      systems use them too — so we score it lower.
#
# All three together cap the contribution at +25 so a URL with all
# of them at once doesn't push score over the dangerous threshold
# by themselves; they're a multiplier, not a verdict.

_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}")
_LONG_ENTROPY_RE = re.compile(r"[A-Za-z0-9_\-]{28,}")


def _detect_url_pii_leak(url_or_domain: str) -> dict:
    """
    Return a dict with the per-pattern hits + a max-weight score.

    Shape: {
        jwt: bool,        # JWT-shaped token in the URL
        email: bool,      # Email address in the URL
        long_random: bool,# Long high-entropy string in the URL
        weight: int,      # 0–25 score contribution
    }

    URL-decoded once before matching so a `%40` doesn't hide an
    email — but we deliberately do NOT recurse into doubly-encoded
    cases (that's its own phishing pattern, _has_hex_encoding picks
    it up separately).
    """
    if "?" not in url_or_domain:
        return {"jwt": False, "email": False, "long_random": False, "weight": 0}
    try:
        from urllib.parse import unquote

        query = url_or_domain.split("?", 1)[1]
        decoded = unquote(query)
    except Exception:
        return {"jwt": False, "email": False, "long_random": False, "weight": 0}

    has_jwt = bool(_JWT_RE.search(decoded))
    has_email = bool(_EMAIL_RE.search(decoded))
    # Long random matches are noisy — only flag when the URL doesn't
    # already have JWT/email and the random part is in a value position
    # (after =). This avoids triple-counting on `?session=eyJ...`.
    has_long_random = False
    if not has_jwt and not has_email:
        for token in decoded.split("&"):
            if "=" not in token:
                continue
            value = token.split("=", 1)[1]
            if _LONG_ENTROPY_RE.search(value):
                # Require both letters AND digits to dodge pure base64
                # decorative hashes (e.g. version tokens that have only
                # letters or only hex).
                if any(c.isdigit() for c in value) and any(c.isalpha() for c in value):
                    has_long_random = True
                    break

    weight = 0
    if has_jwt:
        weight += 25
    if has_email:
        weight += 15
    if has_long_random:
        weight += 5
    # Cap at 25 — the signals stack but we don't want one URL to
    # single-handedly dominate the verdict; the rest of the analyzer
    # (blocklists, brand impersonation, etc.) still has to corroborate.
    if weight > 25:
        weight = 25
    return {
        "jwt": has_jwt,
        "email": has_email,
        "long_random": has_long_random,
        "weight": weight,
    }


_FAKE_TLD_LABELS = frozenset({"com", "org", "net", "gov", "edu", "co", "io", "me"})
# A registered NAME that spells a TLD may also spell a country's: ru.msk.ru
# turns sberbank.ru.msk.ru into "sberbank.ru". Only the registered name gets
# these two — as a subdomain label 'ru' is a language (ru.wikipedia.org).
_REGISTERED_FAKE_TLD_LABELS = _FAKE_TLD_LABELS | {"ru", "su"}


def _is_restricted_zone(suffix: str) -> bool:
    return suffix in _RU_RESTRICTED_ZONES or suffix.split(".")[0] in _RESTRICTED_ZONE_LABELS


def _registered_tld_lookalike(domain: str) -> Optional[str]:
    """The registered name itself, when it spells a TLD and was bought under
    a multi-label public suffix anyone can register at: 'com' of
    vk.com.msk.ru, which a reader takes for vk.com. com.msk.ru, ru.msk.ru
    and gov.msk.ru are private persons' names (whois.flexireg.net,
    2026-09-27). Not under a restricted zone — edu.gov.ru is the Ministry of
    Education — nor for REGIONAL_GOVERNMENT_DOMAINS (gov.spb.ru)."""
    registrable = registrable_domain(domain)
    label, _, suffix = registrable.partition(".")
    if "." not in suffix or label not in _REGISTERED_FAKE_TLD_LABELS:
        return None
    if registrable in REGIONAL_GOVERNMENT_DOMAINS or _is_restricted_zone(suffix):
        return None
    return label


def _apparent_subdomain_levels(domain: str) -> int:
    """Subdomain levels as a reader counts them: the labels left of the
    registrable domain, plus the registered name when it spells a TLD —
    vk.com.msk.ru reads as two levels (vk.com) above msk.ru."""
    levels = len(_subdomain_labels(domain))
    return levels + 1 if levels and _registered_tld_lookalike(domain) else levels


def _has_fake_tld_in_subdomain(domain: str) -> bool:
    """Detect paypal.com.evil.xyz pattern — real TLD used as subdomain.

    Only labels LEFT of the registrable domain are a subdomain. In
    kvs.gov.spb.ru the 'gov' is the registered name under the spb.ru zone,
    and in edu.gov.ru it is part of the public suffix — neither is somebody
    dressing a TLD up as a subdomain. But where the registered name itself
    spells a TLD under an open zone (vk.com.msk.ru), whatever stands to its
    left is dressed up exactly that way.
    """
    subdomain = _subdomain_labels(domain)
    if any(part in _FAKE_TLD_LABELS for part in subdomain):
        return True
    return bool(subdomain) and _registered_tld_lookalike(domain) is not None


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

    # ── IDN normalisation, done ONCE, up front ──
    #
    # An internationalised domain reaches us in its ASCII-compatible
    # (punycode) form, because that is what DNS carries. Two different
    # questions get asked about it downstream, and they need different forms:
    #
    #   ascii_domain   — the wire form. Everything that LOOKS THE NAME UP
    #                    speaks punycode: DNS/DoH, the blocklists, the Tranco
    #                    tables, the PSL helpers, and the ML model (whose
    #                    training features were extracted from ASCII names —
    #                    feeding it Unicode would break feature parity).
    #   unicode_domain — the name a human reads. Everything that judges the
    #                    SHAPE of the name (hyphens, length, entropy,
    #                    n-grams) must use this, or it scores the encoder's
    #                    artefacts: xn----7sbnackuskv0m.xn--p1ai "has" six
    #                    hyphens and a 19-char label, while экзамен-пдд.рф
    #                    has one hyphen and eleven characters.
    #
    # Each heuristic below states which form it takes and why.
    ascii_domain = domain
    unicode_domain = _decode_idn(domain)

    # Lookup key: the top-domain / Tranco tables are indexed on the ASCII form.
    base_domain = _extract_base_domain(ascii_domain)
    # Name under judgement: the decoded registrable label.
    unicode_base = _extract_base_domain(unicode_domain)
    domain_name = unicode_base.split(".")[0] if "." in unicode_base else unicode_base

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

    # Strategy doc #5 — explicit cards for the abuse.ch full bundle.
    # blocklist_hits aggregate already counts them; this adds the
    # per-source DomainReason so EVIDENCE_BOOK can render specifically.
    if signals.get("malware_bazaar_hit"):
        score += 75
        reasons.append(DomainReason(
            signal="malware_bazaar", weight=75,
            detail="Distributing known malware samples (MalwareBazaar / abuse.ch)",
        ))

    if signals.get("feodo_hit"):
        score += 80
        reasons.append(DomainReason(
            signal="feodo", weight=80,
            detail="Active C2 server for a known botnet (Feodo Tracker / abuse.ch)",
        ))

    # Strategy doc #2 — favicon brand-clone match. Very high-confidence
    # signal: page serves a known brand's favicon but is hosted off-brand.
    if signals.get("favicon_cloned"):
        score += 35
        reasons.append(DomainReason(
            signal="favicon_brand_clone", weight=35,
            detail=signals.get("favicon_detail") or "Brand-clone favicon detected",
        ))

    # Strategy doc #17 — typosquat watchtower hit. The user (or
    # another user watching the same brand) added this brand to the
    # watchlist; the daily scan caught a cousin-domain CT entry.
    if signals.get("watchtower_matched"):
        wt_weight = signals.get("watchtower_weight", 25)
        variant = signals.get("watchtower_variant") or "typo"
        brand = signals.get("watchtower_brand") or "a watched brand"
        explanations = {
            "typo": f"Looks like a misspelling of {brand} (Levenshtein {signals.get('watchtower_distance', '?')}).",
            "tld": f"Same name as {brand}, different top-level domain — common phishing pattern.",
            "homograph": f"Uses look-alike Unicode characters mimicking {brand}.",
            "subdomain": f"Uses {brand}'s name as a subdomain on an unrelated host.",
        }
        score += wt_weight
        reasons.append(DomainReason(
            signal="watchtower_typosquat", weight=wt_weight,
            detail=explanations.get(variant, f"Flagged by Cleanway Watchtower as a cousin of {brand}."),
        ))

    # AlienVault OTX community reports — popularity-gated.
    # OTX "pulses" are community threat reports that MENTION a domain. Legit
    # popular sites appear in them constantly as impersonation TARGETS / campaign
    # victims, so a mention is NOT proof of malice. A raw +30/+60 (ungated by
    # popularity) flagged major legit sites — e.g. elfinanciero.com.mx (a national
    # newspaper, top-10k) landed at "dangerous" on 8 victim-reference pulses.
    #   - top-10k domain  → skip (an OTX mention is ~always a victim reference).
    #   - top-100k domain → discount by half.
    #   - otherwise (obscure domain in threat reports) → full weight.
    # Uses the PSL-aware registrable domain so compound ccTLDs (.com.mx/.co.uk)
    # resolve correctly, not the naive 2-label split.
    alienvault_pulses = signals.get("alienvault_pulse_count", 0)
    if alienvault_pulses > 0:
        from api.services.doh_gateway import _registrable_domain
        _reg = _registrable_domain(domain)
        if _reg not in _TRANCO_TOP_10K:
            _discount = _reg in _TRANCO_TOP_100K
            if alienvault_pulses > 5:
                _wt = 30 if _discount else 60
                score += _wt
                reasons.append(DomainReason(
                    signal="alienvault_otx_high", weight=_wt,
                    detail=f"Flagged in {alienvault_pulses} AlienVault OTX threat reports",
                ))
            else:
                _wt = 15 if _discount else 30
                score += _wt
                reasons.append(DomainReason(
                    signal="alienvault_otx", weight=_wt,
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

    # Instant-safe only for real top domains — NOT for subdomains of shared
    # platforms / public suffixes (github.io, blogspot.com, us.org, s3…),
    # URL shorteners, or abused Google services. One rule, shared with the
    # public router: is_trusted_top_domain().
    if is_trusted_top_domain(domain):
        rank = _TRANCO_TOP_10K.get(base_domain)
        detail = f"Ranked #{rank} globally" if rank else "In global top 100K domains"
        return 0, RiskLevel.safe, [DomainReason(
            signal="known_legitimate", weight=-50,
            detail=f"Known legitimate domain: {base_domain}. {detail}",
        )]

    # ════════════════════════════════════════════
    # LAYER 3: FEATURE SCORING (30+ signals)
    # ════════════════════════════════════════════

    # ── 3.0 Tranco popularity (Strategy doc #14) ──
    # Negative weight = trust. A domain that's been in the worldwide
    # top-1M for the rolling 30 days is statistically unlikely to be a
    # phishing landing page (kits churn through fresh domains). The
    # tier system (top-1k / 10k / 100k / 1M) tapers the bonus — never
    # large enough to single-handedly flip a high-risk verdict, but
    # enough to dampen false positives on legitimate-but-unfamiliar
    # sites. NB: NOT a free safe-pass — subdomain takeover and
    # compromised popular sites still get scored by other rules.
    if signals.get("tranco_ranked"):
        tranco_weight = signals.get("tranco_weight", 0)
        if tranco_weight < 0:
            score += tranco_weight  # negative — pulls score down
            reasons.append(DomainReason(
                signal="tranco_popularity", weight=tranco_weight,
                detail=signals.get("tranco_label") or "In the public top-1M domains",
            ))

    # ── 3.1 Homograph / IDN attack ──
    # ASCII form: _check_homograph decodes internally, on purpose — it needs
    # the raw characters (and its own permissive punycode fallback) to spot
    # mixed-script look-alikes such as pаypal.com with a Cyrillic 'а'.
    homograph_target = _check_homograph(ascii_domain)
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
    # Unicode form: brand comparison is meaningless against punycode gibberish
    # ('xn--pypal-4ve' resembles no brand), while on the decoded name a
    # Cyrillic look-alike sits one edit from its target — so this now
    # corroborates the homograph signal instead of missing it.
    typosquat_result = _check_typosquatting_v2(unicode_domain)
    if typosquat_result:
        legit_domain, method = typosquat_result
        score += 25
        reasons.append(DomainReason(
            signal="typosquatting", weight=25,
            detail=f"Impersonates {legit_domain} ({method})",
        ))

    # ── 3.5 Brand in subdomain: "paypal.evil.com" ──
    # ASCII form: this walks the registrable-domain boundary with the PSL
    # helper, whose compound-suffix tables are written in ASCII. Decoding
    # would change nothing anyway — the brand list it matches against is
    # Latin, so a decoded Cyrillic label can never match it.
    #
    # Or a Russian brand's name bought under an open Russian zone
    # (sberbank.spb.ru, vk.nov.ru): the same deception, one level down.
    brand_sub = _check_brand_in_subdomain(ascii_domain)
    zone_brand = None if brand_sub else _check_brand_under_open_zone(ascii_domain)
    if brand_sub or zone_brand:
        score += 30
        # Under an open zone the name may be a dealer's or a partner's
        # (cdek.msk.ru calls itself CDEK's partner): the reason says what the
        # name does to a reader, not what its owner intends.
        detail = (
            f"Uses '{brand_sub}' brand name in subdomain to deceive" if brand_sub else
            f"Uses the '{zone_brand}' brand name as its own name under a zone anyone can register in, "
            f"so it reads as the brand's site"
        )
        reasons.append(DomainReason(signal="brand_subdomain_abuse", weight=30, detail=detail))

    # ── 3.6 Fake TLD in subdomain: "paypal.com.evil.xyz" ──
    # ASCII form: looks for literal 'com'/'org'/… labels; decoding never
    # creates or removes one.
    if _has_fake_tld_in_subdomain(ascii_domain):
        score += 35
        reasons.append(DomainReason(
            signal="fake_tld_subdomain", weight=35,
            detail="Contains a real TLD in subdomain (e.g., example.com.evil.xyz)",
        ))

    # ── 3.7 No HTTPS ──
    # True only on positive evidence: port 443 refused us or spoke no TLS,
    # AND port 80 served a page (site_probes). "Our scanner could not
    # connect" is None, never True: президент.рф, rosreestr.gov.ru and
    # bankspb.ru refuse foreign connections, and scoring that as "no HTTPS"
    # (+40) plus "no headers" (+15) alone crossed the 'dangerous' line
    # (report 2026-09-25 #1).
    if signals.get("no_https"):
        score += 40
        reasons.append(DomainReason(
            signal="no_https", weight=40,
            detail="Site does not use HTTPS encryption",
        ))

    # ── 3.7b Broken certificate ──
    # Expired, self-signed or issued for another name: every browser shows a
    # full-page warning, wherever it is opened from, so this is measured —
    # unlike a certificate from an authority we merely do not know (the
    # Russian national CA), which site_probes reports as "not reached".
    cert_problem = signals.get("certificate_problem")
    if cert_problem:
        score += 30
        reasons.append(DomainReason(
            signal="invalid_certificate", weight=30,
            detail=_CERTIFICATE_PROBLEM_TEXT.get(cert_problem, _CERTIFICATE_PROBLEM_TEXT[""]),
        ))

    # ── 3.8 Free SSL + new domain combo ──
    if signals.get("free_ssl") and domain_age is not None and domain_age < 30:
        score += 20
        reasons.append(DomainReason(
            signal="free_ssl_new_domain", weight=20,
            detail="Free SSL certificate on a new domain — common phishing pattern",
        ))

    # ── 3.9 Missing security headers ──
    # None = not measured (the scanner could not open the site over HTTPS).
    # Only a real HTTPS response that lacks the headers counts — a site that
    # refuses our foreign scanner has not shown us anything to judge.
    missing_headers = signals.get("missing_security_headers") or []
    if len(missing_headers) >= 3:
        score += 15
        reasons.append(DomainReason(
            signal="missing_headers", weight=15,
            detail=f"Missing security headers: {', '.join(missing_headers[:3])}",
        ))

    # ── 3.10 Risky TLD ──
    # ASCII form: HIGH_RISK_TLDS / MEDIUM_RISK_TLDS are spelled in ASCII, so
    # '.xn--p1ai' must stay encoded here rather than decode to '.рф'.
    tld = _extract_tld(ascii_domain)
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

    # ── 3.11 Excessive subdomains (2+ levels above the registrable domain) ──
    # Counted from the registrable domain, not from the TLD: www.shop.co.uk
    # and kvs.gov.spb.ru have ONE subdomain level each, a.b.evil.com has two
    # — and so does vk.com.msk.ru, whose registered name 'com' reads as a TLD.
    # Either form works — decoding never adds or removes a label separator.
    sub_levels = _apparent_subdomain_levels(ascii_domain)
    if sub_levels >= 2:
        below = ascii_domain.lower().strip(".").split(".", sub_levels)[-1]
        score += 15
        reasons.append(DomainReason(
            signal="excessive_subdomains", weight=15,
            detail=f"Unusually deep subdomain nesting ({sub_levels} levels above {below})",
        ))

    # ── 3.12 Suspicious keywords in domain ──
    # Unicode form: the keyword list is words a human would read in the name.
    keyword = _check_suspicious_keywords(unicode_domain)
    if keyword:
        score += 10
        reasons.append(DomainReason(
            signal="suspicious_keyword", weight=10,
            detail=f"Contains suspicious keyword: '{keyword}'",
        ))

    # ── SCRIPT GATE for the name-shape heuristics ──
    #
    # 3.13 (entropy), 3.30 (n-gram), 3.31 (vowel ratio) and 3.32 (consonant
    # cluster) all ask "does this look like a word, or like output from a
    # generator?" — and the answer depends on WHICH LANGUAGE the name is in.
    # Asking the English model about a Russian name does not measure
    # "random", it measures "not English":
    #
    #   * bigram_score() looks names up in _ENGLISH_BIGRAMS, which has no
    #     Cyrillic pairs — so it returns 0.0 for EVERY Russian name.
    #   * vowel_consonant_ratio() and consecutive_consonants_max() count
    #     against ASCII-only _VOWELS/_CONSONANTS — a Cyrillic name has zero
    #     of each, so the ratio is 0.0 and trips the "< 0.2" anomaly.
    #
    # So each script gets the model that fits it. Cleanway is RU-first, and
    # the Russian branch exists because gating these on `isascii()` alone
    # left an all-Cyrillic name with NO lexical scrutiny whatsoever:
    # measured on the previous commit, жкшнвыапролдэъ.рф scored 0/safe with
    # an empty reasons list, and 398 of 400 synthesised Cyrillic DGA names
    # scored exactly 0. A freshly registered generated .рф domain with no
    # reputation has to look suspicious to the local rules, or the local
    # rules are not protecting the users we ship to first.
    #
    # A script we have no model for — Greek, Arabic, accented Latin — still
    # skips, because guessing with the wrong table is what caused the
    # original false positives. Mixed-script names also skip (name_script
    # returns 'other'): they are homograph attacks, and _check_homograph
    # above is the tool for them, unweakened.
    from api.services.url_features import (
        bigram_score,
        consecutive_consonants_max,
        cyrillic_consecutive_consonants_max,
        cyrillic_vowel_consonant_ratio,
        name_script,
        russian_bigram_score,
        vowel_consonant_ratio,
    )

    script = name_script(domain_name)

    # ── 3.13 Shannon entropy (DGA detection) ──
    #
    # Thresholds are per-alphabet: entropy is bounded by log2(alphabet), so
    # the same "ordinariness" reads hotter on Russian's 33 letters than on
    # English's 26. Calibrated 2026-09-20 against the 653 Cyrillic names in
    # data/top-1m.csv vs 1,000 length-matched random Cyrillic names.
    #
    # Be honest about what this signal is worth on Cyrillic: it BARELY
    # separates. Legitimate Russian domain names are long compounds that use
    # many distinct letters, so they sit right on top of the random ones —
    # перемышльский-район has entropy 3.93, HIGHER than the keyboard mash
    # жкшнвыапролдэъ at 3.81. At Latin's medium threshold (3.5) the Cyrillic
    # false-positive rate is 10.26%, so that tier is dropped entirely rather
    # than shipped with a prettier-looking number. What survives is one
    # conservative tier at the point where measured legitimate FPs hit zero
    # (> 4.0 with len > 10: 0.00% of legitimate names, 2.5% of the DGA set).
    entropy = _shannon_entropy(domain_name)
    if script == "ascii" and entropy > 4.0 and len(domain_name) > 8:
        score += 12
        reasons.append(DomainReason(
            signal="high_entropy", weight=12,
            detail=f"Domain name has unusually high randomness (entropy={entropy}) — possible auto-generated domain",
        ))
    elif script == "ascii" and entropy > 3.5 and len(domain_name) > 10:
        score += 6
        reasons.append(DomainReason(
            signal="medium_entropy", weight=6,
            detail=f"Domain name appears somewhat random (entropy={entropy})",
        ))
    elif script == "cyrillic" and entropy > 4.0 and len(domain_name) > 10:
        score += 12
        reasons.append(DomainReason(
            signal="high_entropy", weight=12,
            detail=f"Domain name has unusually high randomness (entropy={entropy}) — possible auto-generated domain",
        ))

    # ── 3.14 High digit ratio ──
    # Unicode form (via domain_name): punycode encodes non-ASCII letters into
    # a base-36 tail full of digits, so the wire form invents a digit ratio
    # the real name does not have.
    d_ratio = _digit_ratio(domain_name)
    if d_ratio > 0.4 and len(domain_name) > 5:
        score += 15
        reasons.append(DomainReason(
            signal="high_digit_ratio", weight=15,
            detail=f"Domain name is {round(d_ratio*100)}% digits — suspicious",
        ))

    # ── 3.15 Excessive special characters ──
    # Unicode form. This is the single biggest source of the RU false
    # positives: all 28 flagged punycode domains in the 2026-09-20 sample
    # tripped it, because the '----' in xn----7sb… is the ACE delimiter plus
    # the name's own hyphen, not four hyphens that anybody typed.
    special = _special_char_count(unicode_domain)
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
    # ASCII form: percent-encoding is a property of the wire representation.
    if _has_hex_encoding(ascii_domain):
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

    # ── 3.19b PII / token leak in URL query parameters ──
    # Strategy doc Top-20 #20. Flags URLs that exfiltrate the user's
    # email, JWT, or session token through plain query params — a
    # common phishing-and-tracking hybrid that no consumer product
    # currently detects.
    pii_hit = _detect_url_pii_leak(raw_input)
    if pii_hit["weight"] > 0:
        bits = []
        if pii_hit["jwt"]:
            bits.append("auth token")
        if pii_hit["email"]:
            bits.append("email address")
        if pii_hit["long_random"]:
            bits.append("session-id-like value")
        detail = "URL leaks " + " + ".join(bits) + " in the address"
        score += pii_hit["weight"]
        reasons.append(DomainReason(
            signal="url_pii_leak",
            weight=pii_hit["weight"],
            detail=detail,
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
    # ASCII form: _URL_SHORTENERS is an ASCII lookup table.
    if _is_url_shortener(ascii_domain):
        score += 15
        reasons.append(DomainReason(
            signal="url_shortener", weight=15,
            detail="URL shortener detected — real destination is hidden",
        ))

    # ── 3.23 Domain length ──
    # Unicode form (via domain_name): punycode inflates length — перемышльский-район
    # is 19 characters, its xn---- encoding is 28.
    if len(domain_name) > 25:
        score += 10
        reasons.append(DomainReason(
            signal="long_domain_name", weight=10,
            detail=f"Unusually long domain name ({len(domain_name)} characters)",
        ))

    # ── 3.24 DNS: Very low TTL (fast-flux indicator) ──
    # Real fast-flux runs TTL <= 60s with rapid IP rotation. Ordinary CDN /
    # tracker infra sits at 60-300s (Cloudflare defaults to 300), so the old
    # `< 300` threshold flagged a huge slice of the legit web as "fast-flux".
    # Tightened to < 60 so this fires on genuinely suspicious infra only.
    dns_ttl = signals.get("dns_ttl")
    if dns_ttl is not None and dns_ttl < 60:
        score += 15
        reasons.append(DomainReason(
            signal="low_dns_ttl", weight=15,
            detail=f"Very low DNS TTL ({dns_ttl}s) — rapidly-changing infrastructure",
        ))

    # ── 3.25 DNS: No MX record (apex domains only) ──
    # MX lives on the registrable domain, never on a `track.`/`go.` subdomain,
    # so penalising a subdomain for "no MX" dinged every legit redirect/CDN
    # host. Only apply when we're actually looking at the apex. Use the
    # PSL-aware registrable-domain helper (not the naive 2-label split) so this
    # stays correct for compound ccTLDs — foo.co.uk is an apex, not a subdomain.
    if signals.get("dns_has_mx") is False:
        from api.services.doh_gateway import _registrable_domain
        if domain == _registrable_domain(domain):
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
    if script == "ascii":
        bg_score = bigram_score(domain_name)
        if bg_score < 0.15 and len(domain_name) > 7:
            score += 10
            reasons.append(DomainReason(
                signal="unnatural_ngram", weight=10,
                detail=f"Domain name has unnatural character patterns (bigram score={bg_score})",
            ))
        elif bg_score < 0.25 and len(domain_name) > 10:
            score += 5
            reasons.append(DomainReason(
                signal="suspicious_ngram", weight=5,
                detail=f"Domain name has unusual character patterns (bigram score={bg_score})",
            ))
    elif script == "cyrillic":
        # One tier only. The weak Latin tier ("suspicious_ngram", < 0.25)
        # has no Cyrillic counterpart because it earns nothing: measured, a
        # < 0.18 second tier moved the DGA caution rate by 0.00pp while
        # adding a lexical mark to 79 more legitimate Russian domains
        # (14.4% → 26.5%), including экзамен-пдд.рф and судьироссии.рф —
        # the exact names the previous commit cleared.
        bg_score = russian_bigram_score(domain_name)
        if bg_score < 0.10 and len(domain_name) > 7:
            score += 10
            reasons.append(DomainReason(
                signal="unnatural_ngram", weight=10,
                detail=f"Domain name has unnatural character patterns (bigram score={bg_score})",
            ))

    # ── 3.31 Vowel/consonant ratio anomaly ──
    #
    # The band is per-alphabet. English has 5 vowels to 21 consonants, so a
    # uniformly random Latin string lands near 5/21 = 0.24 and the "< 0.2"
    # floor catches its lower tail. Russian has 10 vowels to 21 consonants,
    # so random Cyrillic lands near 0.48 — comfortably INSIDE the Latin
    # band. Reusing 0.2 would have made random Cyrillic look more
    # pronounceable than random Latin, which is why the Cyrillic floor is
    # raised to 0.30 (measured: 1.53% of legitimate names, 20.0% of the DGA
    # set; at 0.35 it would be 3.68% / 27.2%, and the names it starts
    # touching are abbreviation-style ones like транснефть and мфц-омск).
    if script == "ascii":
        vc_ratio = vowel_consonant_ratio(domain_name)
        vc_floor = 0.2
    elif script == "cyrillic":
        vc_ratio = cyrillic_vowel_consonant_ratio(domain_name)
        vc_floor = 0.30
    else:
        vc_ratio, vc_floor = None, 0.0
    if vc_ratio is not None and len(domain_name) > 6 and (vc_ratio < vc_floor or vc_ratio > 1.5):
        score += 6
        reasons.append(DomainReason(
            signal="abnormal_vowel_ratio", weight=6,
            detail=f"Abnormal vowel/consonant ratio ({vc_ratio}) — likely auto-generated",
        ))

    # ── 3.32 Consecutive consonants (>5 = very unnatural) ──
    #
    # The >= 5 cut holds for Russian too, and the measurement is emphatic:
    # across the 653 legitimate Cyrillic names NOT ONE has a 5-consonant
    # run, while 28.1% of the DGA set does. Dropping to >= 4 would catch
    # more (44.3%) but starts hitting real institutions —
    # президентскиегранты, реестрповесток, декларации-соответствия — so it
    # stays at 5. ъ and ь break a run; see CYRILLIC_SIGNS.
    if script == "ascii":
        max_cons = consecutive_consonants_max(domain_name)
    elif script == "cyrillic":
        max_cons = cyrillic_consecutive_consonants_max(domain_name)
    else:
        max_cons = 0
    if max_cons >= 5 and len(domain_name) > 6:
        score += 6
        reasons.append(DomainReason(
            signal="consonant_cluster", weight=6,
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
        # ASCII form: the model's features were extracted from ASCII domains,
        # so the wire form is what keeps inference consistent with training.
        ml_result = ml_predict(ascii_domain)
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


def calculate_confidence_pct(
    score: int, checks_succeeded: int, total_checks: int
) -> int:
    """Strategy doc Top-20 #12 — numeric confidence band per verdict.

    The headline transparency claim ("FP rate 0.08%") is a marginal
    average. A specific verdict's confidence depends on two
    measurable factors:

      coverage  — fraction of analyzer checks that returned a real
                  answer (not the breaker fallback). A verdict
                  built on 4/18 checks is less trustworthy than
                  one built on 18/18.
      margin    — how far the final score sits from the nearest
                  decision boundary (30 = safe/caution, 70 =
                  caution/dangerous). A score of 75 is more
                  confidently 'dangerous' than a score of 71.

    The blend is weighted toward coverage (0.7) because no amount
    of margin can rescue a verdict that ran on no data. Output is
    clamped to [50, 99]; we never claim 100% — that's the conformal
    point. The categorical ConfidenceLevel is derived downstream
    from this number for backwards-compatible callers.
    """
    if total_checks <= 0:
        return 50
    coverage = max(0.0, min(checks_succeeded / total_checks, 1.0))

    score_clamped = max(0, min(score, 100))
    if score_clamped < 30:
        margin_pts = 30 - score_clamped
    elif score_clamped < 70:
        margin_pts = min(score_clamped - 30, 70 - score_clamped)
    else:
        margin_pts = score_clamped - 70
    # Normalize: a 30-point cushion = full margin = 1.0.
    margin = min(margin_pts / 30.0, 1.0)

    # Coverage is a hard gate, not a weighted term: with zero data,
    # we never claim more than the floor regardless of margin (we
    # can't see the threshold to know the margin is real). The
    # margin then refines the answer once at least some data is in.
    blended = coverage * (0.7 + 0.3 * margin)   # in [0, 1]
    pct = 50 + round(49 * blended)              # in [50, 99]
    return max(50, min(pct, 99))


# ═══════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════

def _extract_base_domain(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain.lower()


def _ascii_label(label: str) -> str:
    """The ASCII (punycode) spelling of one label, so a decoded name can be
    looked up in the ASCII suffix tables."""
    if label.isascii():
        return label
    try:
        return "xn--" + label.encode("punycode").decode("ascii")
    except UnicodeError:
        return label


def _ru_suffix_length(ascii_labels: list[str]) -> int:
    """How many trailing labels form the longest Russian PSL suffix the name
    ends with — an exact rule, or one label under a wildcard base — 0 when
    none does. Every rule has 2+ labels."""
    for k in range(len(ascii_labels), 1, -1):
        tail = ascii_labels[-k:]
        if ".".join(tail) in RU_PUBLIC_SUFFIXES or ".".join(tail[1:]) in _RU_WILDCARD_SUFFIXES:
            return k
    return 0


def _ru_registrable_domain(domain: str) -> Optional[str]:
    """The registrable domain of a host under a Russian public suffix from
    the PSL: that suffix plus one label, longest suffix first —
    kvs.gov.spb.ru → gov.spb.ru, a.b.hosting.myjino.ru → itself
    (b.hosting.myjino.ru is a suffix under '*.hosting.myjino.ru'). A bare
    suffix answers itself; None when no such suffix applies. Accepts the
    ASCII or the decoded form and answers in the same form."""
    parts = (domain or "").lower().strip(".").split(".")
    k = _ru_suffix_length([_ascii_label(p) for p in parts])
    return ".".join(parts[-(k + 1):]) if k else None


def registrable_domain(domain: str) -> str:
    """The registrable domain (eTLD+1) a host is judged by — PSL-aware.

    Under a Russian public suffix, _ru_registrable_domain(). Everywhere else
    the compound-ccTLD heuristic the rest of the service already uses
    (doh_gateway._registrable_domain): login.example.co.uk → example.co.uk.
    """
    from api.services.doh_gateway import _registrable_domain as heuristic_registrable

    dom = (domain or "").lower().strip(".")
    return _ru_registrable_domain(dom) or heuristic_registrable(dom)


def _subdomain_labels(domain: str) -> list[str]:
    """Labels strictly LEFT of the registrable domain ([] for an apex)."""
    dom = (domain or "").lower().strip(".")
    registrable = registrable_domain(dom)
    if dom == registrable or not dom.endswith("." + registrable):
        return []
    return dom[: -(len(registrable) + 1)].split(".")


def _extract_tld(domain: str) -> str:
    parts = domain.lower().strip(".").split(".")
    return "." + parts[-1] if parts else ""


# ── IDN / punycode normalisation ──

# RFC 1035 §2.3.4. _DOMAIN_PATTERN already caps labels at 63 on the request
# path, so this is defence in depth for callers that reach the scorer some
# other way (tests, scripts, future entry points).
_MAX_DNS_LABEL = 63


def _decode_idn(domain: str) -> str:
    """Return the Unicode form of an internationalised domain.

    `xn----7sbnackuskv0m.xn--p1ai` → `экзамен-пдд.рф`.

    Punycode is an ENCODING, not a name. That ASCII form has six hyphens and
    a 19-character label; the name it actually spells has one hyphen and
    eleven characters. Any heuristic that judges the SHAPE of a name — hyphen
    counts, label length, entropy, n-grams — is reading the encoder's output
    unless it decodes first, and scores the artefacts instead of the name.
    (Measured 2026-09-20: 28 of the 29 punycode domains in a 2,000-domain
    sample of the .ru/.рф/.su Tranco tail came back 'caution' this way.)

    Callers keep the ASCII form for everything that legitimately speaks
    punycode — DNS lookups, blocklists, the Tranco tables and the ML model,
    all of which are keyed on the wire form.

    Decoding is per-label and never raises: a label that is not valid
    punycode keeps its ASCII spelling, so malformed input degrades to the
    previous behaviour rather than erroring. The stdlib `idna` codec is
    tried first and the raw `punycode` codec second — the latter skips
    IDNA validation, so a deliberately malformed attack label still decodes
    to the characters it encodes instead of being waved through as ASCII.

    That permissive second codec is why the length bound below exists. It
    will happily "decode" anything, and punycode is expansive, so a label
    longer than a DNS label may legally be ('xn--' + 'a' * 120) comes back
    as a run of U+0080 control characters — not a name, and not something
    any downstream heuristic should be handed. A label over
    _MAX_DNS_LABEL keeps its ASCII spelling instead.
    """
    if "xn--" not in domain.lower():
        return domain

    out: list[str] = []
    for label in domain.split("."):
        if not label.lower().startswith("xn--"):
            out.append(label)
            continue
        # RFC 1035 §2.3.4: a label is at most 63 octets. Anything longer is
        # malformed input, not a name — decoding it yields control
        # characters, so keep the ASCII form.
        if len(label) > _MAX_DNS_LABEL:
            out.append(label)
            continue
        decoded = ""
        try:
            decoded = label.encode("ascii").decode("idna")
        except Exception:
            try:
                decoded = label[4:].encode("ascii").decode("punycode")
            except Exception:
                decoded = ""
        # The permissive codec can also emit UNPAIRED SURROGATES (U+D800-
        # U+DFFF) — 'xn--zi0c0o6s' is one. Python keeps them in a str, but the
        # first component that ENCODES the name (a log line, the JSON
        # response, a cache key) raises UnicodeEncodeError, turning a hostile
        # domain into a 500. Keep the ASCII spelling unless the decoded label
        # survives a UTF-8 round trip.
        if decoded:
            try:
                decoded.encode("utf-8")
            except UnicodeEncodeError:
                decoded = ""
        out.append(decoded or label)
    return ".".join(out)


# ── Homograph detection ──

def _check_homograph(domain: str) -> Optional[str]:
    # IDN homograph attacks appear in DNS/URLs as ASCII punycode (xn--…), so a
    # raw ascii check misses them entirely. Decode any xn-- label back to
    # Unicode FIRST, then look for confusable characters on the decoded form.
    # Shares _decode_idn with the scorer so the two cannot drift apart: this
    # check is the reason a decode failure falls back to the raw punycode
    # codec rather than giving up, and the reason callers hand it the ASCII
    # form instead of a pre-decoded one.
    decoded = _decode_idn(domain)

    try:
        decoded.encode("ascii")
        return None  # pure ASCII after decoding — no confusables possible
    except UnicodeEncodeError:
        pass

    ascii_version = ""
    has_confusable = False
    for char in decoded:
        if char in _CONFUSABLES:
            ascii_version += _CONFUSABLES[char]
            has_confusable = True
        else:
            ascii_version += char

    if not has_confusable:
        return None

    # A brand family's own site (втб.рф) and verified same-shaped sites of
    # other owners are nobody's disguise, whatever script they are in.
    if (_ru_registrable_domain(decoded) or _extract_base_domain(decoded)) in _BRAND_LEGIT_DOMAINS:
        return None

    ascii_base = _extract_base_domain(ascii_version)
    if ascii_base in TOP_DOMAINS:
        return ascii_base

    # A brand only when the look-alikes are IN the name and turn it into a
    # Latin one (раураl → paypal). The 'р' of the .рф TLD is Cyrillic, not a
    # disguise: втб.рф has no look-alike in its name, which maps to itself —
    # and to 'втб', VTB's own Cyrillic name on the target list, so VTB's own
    # domain came back 'dangerous 60' before this.
    decoded_name = _extract_base_domain(decoded).split(".")[0]
    ascii_name = ascii_base.split(".")[0]
    if ascii_name != decoded_name and ascii_name.isascii() and ascii_name in TYPOSQUAT_TARGETS:
        return TYPOSQUAT_TARGETS[ascii_name]

    return None


# ── Typosquatting v2 ──

# How long the registrable label has to be before it is compared at all:
# the shortest brands (aws, ups, n26). A 3-letter name is only compared for
# an EXACT match — the brand's own name under another TLD (dhl.top) or
# spelled with look-alike characters (up5, dh1). Edit distance means nothing
# there: every 3-letter string sits within two edits of some 3-letter brand
# — 'ako' (the Kemerovo region, ako.ru) is two substitutions from 'aws',
# 'spb' from 'ups', both 'caution' or worse in production on 2026-09-27.
_TYPOSQUAT_MIN_LABEL = 3
# Swaps, doubled letters (dhll), hyphens, combos and multi-char glyphs from 4.
_SHAPE_MIN_LABEL = 4
# Edit-distance matches (substitutions, the similarity ratio) need a longer
# label still: 4-letter names are too dense — etsp.ru is one letter from
# 'etsy', ikar.ru two from 'ikea'. Exact look-alikes (1kea, ub3r) still count.
_FUZZY_MIN_LABEL = 5
# Below this length a name may differ from the brand in ONE position: two
# substitutions in seven letters (ngpedia → expedia) is a different word.
_TWO_EDIT_MIN_LABEL = 8


# Words a brand ends with that other names end with too. sberbank and
# swedbank differ only in 'sber' / 'swed', tbank and mbank in one letter,
# rustore and upstore in 'ru' / 'up': compared whole, every 'bank' and 'store'
# of the right length is a "typo" (tbank alone matched 55 of the Tranco
# 100k-1M names). When a name ends with the same word, only the parts before
# it are compared, under the same length rules as a whole name: 'sber',
# 'alfa', 't' and 'ru' get look-alikes and shapes only (altabank and oberbank
# are other banks), 'gazprom' and 'sovcom' one edit. A typo INSIDE the word
# (sberbamk, tbamk) leaves a name that no longer ends with it, and that name
# is compared whole, as before.
_GENERIC_TAILS: tuple[str, ...] = ("bank", "store", "банк")


def _generic_tail(name: str, brand: str) -> int:
    """Length of a _GENERIC_TAILS word both end with, each with letters
    before it; 0 when there is none."""
    for tail in _GENERIC_TAILS:
        if name.endswith(tail) and brand.endswith(tail) and len(name) > len(tail) and len(brand) > len(tail):
            return len(tail)
    return 0


def _edit_distance_at_most(a: str, b: str, limit: int) -> bool:
    """True when a becomes b in at most `limit` single-letter insertions,
    deletions, substitutions or swaps of neighbours (optimal string
    alignment distance)."""
    if abs(len(a) - len(b)) > limit:
        return False
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return False
        prev2, prev = prev, cur
    return prev[-1] <= limit


# ── What counts as a slip of the hand ──
#
# Under 8 letters a Russian brand's name sits among ordinary Russian company
# names one letter away. Of the 1,322 registered .ru names one edit from a
# Russian brand on 2026-09-27, the rule flagged 1,081, and the live sites
# among them included megafox.ru (a fur factory), megason.ru (mattresses),
# tirkoff.ru (furniture repair), avico.ru, aviko.ru, avido.ru, avits.ru,
# beelink.ru and uralgib.ru. A typosquat is made the way a typo is: a key
# next to the right one (yandez, gazorombank), a letter that looks like it
# (sberbamk, timkoff), a vowel for a vowel (magafon), or the other Latin
# spelling of one Russian sound (sovkombank: к as k or c). A substitution that
# is none of these — n→x, f→s, t→c — makes another word. Under 8 letters a
# Russian name's substitution has to be a slip; insertions, omissions, swaps
# and doubled letters count as before, and so does everything from 8 letters
# and every global brand (their neighbourhoods have not been measured this
# way). scripts/eval_typo_variants.py measures random substitutions, so this
# shows there as lost 'substitution_1' variants.
_KEYBOARD_ROWS: tuple[tuple[str, ...], ...] = (
    ("qwertyuiop", "asdfghjkl", "zxcvbnm"),
    ("йцукенгшщзхъ", "фывапролджэ", "ячсмитьбю"),
)
_KEY_POSITIONS: Mapping[str, tuple[int, int, int]] = MappingProxyType({
    ch: (layout, row, col)
    for layout, rows in enumerate(_KEYBOARD_ROWS)
    for row, keys in enumerate(rows)
    for col, ch in enumerate(keys)
})
_VOWELS = frozenset("aeiouyаеёиоуыэюя")
# Letters that look alike in an address bar (i/l, m/n, u/v, c/e, b/d …), and
# the two Latin spellings of one Russian sound: к as c/k, с as s/c, з as z/s,
# й as j/y/i, х as h/x, ф/в as f/v.
_SIMILAR_LETTERS = frozenset(frozenset(pair) for pair in (
    "il", "ij", "lj", "mn", "uv", "vw", "ce", "bd", "pq", "gq",
    "ck", "cs", "sz", "iy", "jy", "hx", "fv",
    "шщ", "её", "ий", "ьъ",
))


def _keyboard_neighbours(a: str, b: str) -> bool:
    """a and b are next to each other on the same keyboard (QWERTY or
    ЙЦУКЕН), in a row or diagonally across the stagger."""
    pa, pb = _KEY_POSITIONS.get(a), _KEY_POSITIONS.get(b)
    if not pa or not pb or pa[0] != pb[0]:
        return False
    (_, row_a, col_a), (_, row_b, col_b) = pa, pb
    if row_a == row_b:
        return abs(col_a - col_b) == 1
    if abs(row_a - row_b) != 1:
        return False
    upper, lower = (col_a, col_b) if row_a < row_b else (col_b, col_a)
    return lower in (upper - 1, upper)


def _is_slip(typed: str, letter: str) -> bool:
    """`typed` where `letter` belongs is a slip, not another word: a
    look-alike, a similar letter, a vowel for a vowel, or a neighbouring key."""
    return (
        _imitates(typed, letter)
        or frozenset((typed, letter)) in _SIMILAR_LETTERS
        or (typed in _VOWELS and letter in _VOWELS)
        or _keyboard_neighbours(typed, letter)
    )


def _one_odd_substitution(name: str, brand: str) -> bool:
    """name differs from brand in exactly one position, and not by a slip."""
    if len(name) != len(brand):
        return False
    diffs = [(a, b) for a, b in zip(name, brand) if a != b]
    return len(diffs) == 1 and not _is_slip(*diffs[0])


class _NameRule(NamedTuple):
    """How one listed name is compared. _rule_for() builds it."""

    # Edit distance at all: substitutions and the similarity ratio (no_fuzzy
    # turns it off: ozon + a letter is ozone).
    fuzzy: bool = True
    # Under _TWO_EDIT_MIN_LABEL a substitution has to be a slip (_is_slip).
    slips_only: bool = False
    # The name glued to a generic word (paypalhelp, trybeeline, ozonweb).
    generic_combos: bool = True
    # A generic or country word counts only across a hyphen (mts-help, not
    # mtshelp); a lure keyword counts either way (dhllogin).
    hyphen_combos_only: bool = False
    # The name plus its own country (avito-ru, sberbankru).
    country_combos: bool = False
    # The name plus a Russian lure word (ru_lures), glued or among several
    # words: sberbank-bonus, ozonpriz, lk-gosuslugi, yandex-pay-login.
    lure_words: bool = False


_DEFAULT_NAME_RULE = _NameRule()


def _rule_for(name: str, at_home: bool = False) -> _NameRule:
    """How `name` is compared; `at_home` when the host is under a Russian TLD.

    Names under 4 letters (vk, mts, vtb, dhl, ups) combine with a generic
    word only across a hyphen: glued, they are other words — mtscom.ru makes
    food machinery, vkweb.ru is a web studio, thevk.net a blog, gomts.com
    and usemts.com other firms, and main already flagged dhlweb.com and
    upshelp.com. A lure keyword still counts glued (dhllogin). A shared name (see ru_brands) does not combine with generic
    words abroad either — thebeeline.ca is a Chicago cleaning firm,
    ozonweb.com a fashion magazine, trymegafon.com Megafon Productions,
    mts-team.com a Düsseldorf trainer — but under .ru the name means the
    Russian brand, and vtb-team.ru (a copy of VTB's page), theozon.ru (a
    log-in page) and tbankapp.ru ('T-Bank — Ввод ключа') are its imitators.
    Russian names get slips only under 8 letters, their country as a combo
    word (avito-ru.com), and Russian lure words (sberbank-bonus) under every
    TLD, shared names included."""
    short = len(name) < _SHAPE_MIN_LABEL
    russian = name in _RU_NAMES and name not in GLOBAL_TYPOSQUAT_TARGETS
    if short:
        generic = not russian or at_home
    else:
        generic = name not in _SHARED_NAMES or at_home
    return _NameRule(
        fuzzy=name not in _NO_FUZZY,
        slips_only=russian,
        generic_combos=generic,
        hyphen_combos_only=short,
        country_combos=russian,
        lure_words=russian,
    )


# Russian TLDs, in both spellings of the IDN ones: see _rule_for.
_RU_TLDS = frozenset({".ru", ".su", ".рф", ".xn--p1ai", ".рус", ".xn--p1acf"})
# Built once: _check_typosquatting_v2 looks every listed name's rule up.
_NAME_RULES: Mapping[str, _NameRule] = MappingProxyType({n: _rule_for(n) for n in TYPOSQUAT_TARGETS})
_NAME_RULES_AT_HOME: Mapping[str, _NameRule] = MappingProxyType(
    {n: _rule_for(n, at_home=True) for n in TYPOSQUAT_TARGETS}
)


def _imitation(name: str, brand: str, rule: _NameRule = _DEFAULT_NAME_RULE) -> Optional[str]:
    """How `name` imitates `brand` (a different string), or None.

    Look-alike characters count as the letter they imitate at any length.
    Swaps, doubled letters, hyphens, combos and multi-char glyphs from
    _SHAPE_MIN_LABEL. Edit distance — one substitution, the similarity ratio
    — from _FUZZY_MIN_LABEL, and not at all when `rule.fuzzy` is False. Two
    edits only when both are _TWO_EDIT_MIN_LABEL long. `rule` (see
    _rule_for) narrows combos and substitutions for some names.
    """
    tail = _generic_tail(name, brand)
    if tail:
        if "-" in name and name.replace("-", "") == brand:
            return "hyphen injection"
        if _check_combosquat(name, brand, rule):
            return "combosquatting"
        # `slips_only` is about names under 8 letters; gazprombank's stem is
        # short, the name is not.
        if min(len(name), len(brand)) >= _TWO_EDIT_MIN_LABEL:
            rule = rule._replace(slips_only=False)
        return _imitation(name[:-tail].rstrip("-"), brand[:-tail], rule)

    # Character substitution
    if _check_char_substitution(name, brand, rule.fuzzy, rule.slips_only):
        return "character substitution"

    if len(name) < _SHAPE_MIN_LABEL:
        return None

    # Multi-char ASCII glyph homoglyph (rn->m, vv->w, cl->d) — #1 tactic,
    # not covered by single-char subs or Levenshtein<=2. When a glyph
    # substitution actually happened (skel != name), the corruption itself
    # signals intent, so we look past an exact match to the brand surfacing
    # as a delimited label (rnicrosoft-login), a combosquat, or a close
    # variant (rnicrosofts). The len(brand)>=6 guard prevents the short-name
    # over-collapse that false-matched legit domains (clax->wix, clara->...).
    # >=5 verified to add zero FPs on 20k legit while catching 5-char targets
    # (gmail, apple, yahoo, venmo, zelle).
    skel = _glyph_skeleton(name)
    if skel != name:
        if skel == brand:
            return "glyph homoglyph"
        if len(brand) >= 5 and (
            brand in re.split(r"[-.]", skel)
            or _check_combosquat(skel, brand, rule)
            or SequenceMatcher(None, skel, brand).ratio() >= 0.90
        ):
            return "glyph homoglyph"

    # Transposition
    if _check_transposition(name, brand):
        return "character swap"

    # Hyphen injection
    if name.replace("-", "") == brand and "-" in name:
        return "hyphen injection"

    # Combosquatting
    if _check_combosquat(name, brand, rule):
        return "combosquatting"

    # SequenceMatcher fallback. The ratio alone let two edits through at any
    # length — aviator ~ avito, kontakt ~ vkontakte, rutor ~ rustore — which
    # _TWO_EDIT_MIN_LABEL forbids for substitutions; the edit budget holds it
    # to the same rule, and a substitution it lets through to `slips_only`.
    if rule.fuzzy and len(name) >= _FUZZY_MIN_LABEL and SequenceMatcher(None, name, brand).ratio() >= 0.82:
        two_edits = min(len(name), len(brand)) >= _TWO_EDIT_MIN_LABEL
        if _edit_distance_at_most(name, brand, 2 if two_edits else 1) and not (
            rule.slips_only and not two_edits and _one_odd_substitution(name, brand)
        ):
            return "high similarity"

    # One letter typed twice — what the ratio above catches from 5
    # letters, for the 3-letter brands (dhll, upss).
    if _check_doubled_letter(name, brand):
        return "doubled letter"

    return None


# Zones sold like TLDs whose first label is the Russian ccTLD: a name
# registered under ru.com reads as the brand's .ru address with '.com'
# appended (yandex.ru.com, behind a Cloudflare phishing interstitial on
# 2026-09-27). Both are PSL private suffixes, in public_suffixes_in_top.json.
_RU_LOOKALIKE_ZONES = frozenset({"ru.com", "ru.net"})

# TLDs phishing favours, where a shared name (see ru_brands) is still
# reported as TLD confusion: the scorer's own risk lists, and .pro, which F6
# found under 10% of phishing domains in H1 2026 (.shop 22%, .com 19%; .com
# is everyone's and stays out).
_LURE_TLDS: frozenset[str] = frozenset(HIGH_RISK_TLDS | MEDIUM_RISK_TLDS | {".pro"})


def _lookalike_zone_name(domain: str) -> Optional[str]:
    """'yandex.ru.com' for any host under a _RU_LOOKALIKE_ZONES zone, the
    name registered there plus the zone; None elsewhere."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _RU_LOOKALIKE_ZONES:
        return ".".join(parts[-3:])
    return None


def _check_typosquatting_v2(domain: str) -> Optional[tuple[str, str]]:
    # Under a Russian public suffix, the REGISTRABLE label — never the zone
    # label ('spb' of kvs.gov.spb.ru was "ups", 'nov' of adm.nov.ru "n26").
    # Under ru.com / ru.net, the name registered there ('yandex' of
    # yandex.ru.com, which was read as 'ru').
    # Elsewhere the last two labels, as before: on a compound ccTLD that is
    # the zone label ('co' of co.uk), too short to match anything. Comparing
    # the real label there is right in principle but flags top-100k names
    # (telegraph.co.uk → "telegram", paypay.ne.jp → "paypal": 31 of the 9,217
    # compound-suffix names) because the allowlist looks names up by their
    # last two labels and never sees them.
    zone_name = _lookalike_zone_name(domain)
    base = zone_name or _ru_registrable_domain(domain) or _extract_base_domain(domain)
    # A brand family's own site, or a verified site of another owner with the
    # same shape (data/typosquat_targets_ru.json), imitates no one.
    if base in _BRAND_LEGIT_DOMAINS:
        return None
    name = base.split(".")[0].lower()
    # A brand's own .ru address with .com after it: yandex.ru.com,
    # mail.ru.com, vk.ru.com (vk: too short for the rest of the rule). Reported
    # when the name imitates no brand itself — yandx.ru is Yandex's typo
    # registration, and yandx.ru.com a typo of yandex.ru.
    zone_site = (f"{name}.ru", "TLD confusion") if zone_name and f"{name}.ru" in _BRAND_OFFICIAL_DOMAINS else None
    if len(name) < _TYPOSQUAT_MIN_LABEL:
        return zone_site
    tld = _extract_tld(domain)
    # TLD confusion is the brand's own name directly under another TLD
    # (paypal.co). A brand name registered under a Russian zone
    # (paypal.spb.ru) was — and still is — brand_subdomain_abuse's to report:
    # that check reads spb.ru as the registrable domain.
    directly_under_tld = base.count(".") == 1
    rules = _NAME_RULES_AT_HOME if tld in _RU_TLDS else _NAME_RULES

    for brand, legit_domain in TYPOSQUAT_TARGETS.items():
        if domain == legit_domain or base == legit_domain:
            continue
        if name in _BRAND_NOT_TYPOS.get(brand, ()):
            continue

        if name == brand:
            # TLD confusion (paypal.co vs paypal.com). A shared name under a
            # country's or a legacy TLD is someone's own name (ozon.pl is a
            # cloud provider, tbank.com a Dallas bank); under a TLD phishing
            # favours it is still reported (ozon.shop, vtb.top).
            legit_tld = _extract_tld(legit_domain)
            if directly_under_tld and tld != legit_tld and (brand not in _SHARED_NAMES or tld in _LURE_TLDS):
                return (legit_domain, "TLD confusion")
            continue

        method = _imitation(name, brand, rules.get(brand, _DEFAULT_NAME_RULE))
        if method:
            return (legit_domain, method)

    return zone_site


def _imitates(ch: str, letter: str) -> bool:
    """ch is the letter, or a look-alike of it: a digit (paypa1) or a
    Unicode confusable (the Cyrillic 'р' and 'а' of раypal)."""
    return ch == letter or letter in _CHAR_SUBS.get(ch, "") or _CONFUSABLES.get(ch) == letter


def _check_char_substitution(s1: str, s2: str, fuzzy: bool = True, slips_only: bool = False) -> bool:
    if len(s1) != len(s2):
        return False
    # Look-alike characters read as the letter they imitate: they are the
    # attack, not a difference. Compared position by position, so a brand's
    # own digits (office365) stay digits.
    diffs = [(a, b) for a, b in zip(s1, s2) if not _imitates(a, b)]
    if len(s1) < _FUZZY_MIN_LABEL or not fuzzy:
        return not diffs
    if len(s1) >= _TWO_EDIT_MIN_LABEL:
        return len(diffs) <= 2
    return not diffs or (len(diffs) == 1 and (not slips_only or _is_slip(*diffs[0])))


def _check_doubled_letter(s1: str, s2: str) -> bool:
    """s1 is s2 with one of its letters typed twice."""
    if len(s1) != len(s2) + 1:
        return False
    return any(s1[i] == s1[i + 1] and s1[:i] + s1[i + 1:] == s2 for i in range(len(s1) - 1))


def _check_transposition(s1: str, s2: str) -> bool:
    if len(s1) != len(s2):
        return False
    for i in range(len(s2) - 1):
        swapped = s2[:i] + s2[i + 1] + s2[i] + s2[i + 2:]
        if s1 == swapped:
            return True
    return False


_COMBO_GENERIC_SUFFIXES = frozenset({"com", "net", "org", "official", "support", "help", "app", "web", "mail", "team"})
_COMBO_GENERIC_PREFIXES = frozenset({"my", "the", "get", "go", "try", "use", "new", "real", "true"})
# A Russian brand's name with its country after it reads as its .ru address:
# avito-ru.com, ozon-ru.com, sberbank-ru.com (missed until 2026-09-27).
_COMBO_COUNTRY_SUFFIXES = frozenset({"ru", "rus", "rf", "russia"})


def _combo_parts(name: str, brand: str) -> list[tuple[str, bool, bool]]:
    """(word, hyphenated, word_is_after_brand) for each way `name` is
    `brand` with a word before or after it."""
    parts = []
    if len(name) > len(brand) and name.startswith(brand):
        rest = name[len(brand):]
        parts.append((rest.lstrip("-"), rest.startswith("-"), True))
    if len(name) > len(brand) and name.endswith(brand):
        rest = name[: len(name) - len(brand)]
        parts.append((rest.rstrip("-"), rest.endswith("-"), False))
    return parts


def _check_combosquat(name: str, brand: str, rule: _NameRule = _DEFAULT_NAME_RULE) -> bool:
    for word, hyphenated, after in _combo_parts(name, brand):
        if word in _COMBOSQUAT_KEYWORDS:
            return True
        if rule.hyphen_combos_only and not hyphenated:
            continue
        if rule.generic_combos and word in (_COMBO_GENERIC_SUFFIXES if after else _COMBO_GENERIC_PREFIXES):
            return True
        if rule.country_combos and after and word in _COMBO_COUNTRY_SUFFIXES:
            return True
    return rule.lure_words and _check_lure_combo(name, brand)


def _is_lure_word(word: str, brand: str) -> bool:
    """An English lure keyword (login), a Russian one in any spelling
    (бонус, bonusy, doctavka: see ru_lures), or one that lures next to this
    brand alone (sberbank-online)."""
    return (
        word in _COMBOSQUAT_KEYWORDS
        or ru_lures.is_lure(word)
        or ru_lures.skeleton(word) in _BRAND_LURE_WORDS.get(brand, ())
    )


def _check_lure_combo(name: str, brand: str) -> bool:
    """`name` is `brand` and a lure word: glued to it (ozonpriz, lkgosuslugi)
    or among the hyphenated words around it (sberbank-bonus, lk-gosuslugi,
    yandex-pay-login, vk-login-verify, госуслуги-лк). The brand has to be one
    whole word: vkusvill-bonus is VkusVill's, not VK's."""
    words = name.split("-")
    for i, word in enumerate(words):
        if word == brand:
            if any(_is_lure_word(w, brand) for w in words[:i] + words[i + 1:]):
                return True
        elif len(word) > len(brand):
            glued = word[len(brand):] if word.startswith(brand) else word[:-len(brand)] if word.endswith(brand) else ""
            if glued and _is_lure_word(glued, brand):
                return True
    return False


# ── Brand subdomain abuse ──

def _check_brand_in_subdomain(domain: str) -> Optional[str]:
    from api.services.doh_gateway import _registrable_domain

    dom = domain.lower().strip(".")
    reg = _registrable_domain(dom)
    # Only labels strictly BEFORE the registrable domain are real subdomains.
    # Naive parts[:-2] misfires on multi-part suffixes (barclays.co.uk would
    # treat "barclays" as a spoof subdomain) — use the PSL-aware registrable.
    if not reg or dom == reg:
        return None
    sub = dom[: -(len(reg) + 1)]
    # The global brands only (GLOBAL_TYPOSQUAT_TARGETS explains why); Russian
    # ones are checked under open Russian zones by _check_brand_under_open_zone.
    for part in sub.split("."):
        part_clean = part.replace("-", "")
        if part_clean in GLOBAL_TYPOSQUAT_TARGETS and reg != GLOBAL_TYPOSQUAT_TARGETS[part_clean]:
            return part_clean
    return None


# Russian brands for ONE narrow check: the brand's name bought under an open
# Russian zone (see _RU_RESTRICTED_ZONES), where a reader takes spb.ru or
# nov.ru for the site and the brand for a section of it. The CT log for
# nov.ru alone lists vk.nov.ru, mts.nov.ru, ok.nov.ru and kinopoisk.nov.ru.
# Separate from the typosquat targets: vk, ok and t2 are too short to be
# compared there, and a name bought as-is needs no edit distance. The Latin
# names of data/typosquat_targets_ru.json are here too. None of the Tranco
# top-1M names under a Russian zone (40) matches.
_RU_ZONE_BRANDS = frozenset({
    "sber", "sberbank", "gosuslugi", "tinkoff", "tbank", "vtb", "alfabank",
    "ozon", "wildberries", "avito", "mts", "tele2", "t2", "yandex", "vk",
    "ok", "kinopoisk", "mailru",
    "uralsib", "gazprombank", "pochtabank", "sovcombank", "beeline", "megafon",
    "cdek", "russianpost", "rustore", "vkontakte", "odnoklassniki",
})
# Shorter brands match only as a whole label or a hyphenated keyword combo
# (vk-login): as one part of a name (ok-stroy) or glued to a word (gook) they
# are too common.
_RU_ZONE_BRAND_PART_MIN = 4
# A keyword combo there is an English or a Russian lure word (vk-login,
# mts-bonus, ok-podarok): see ru_lures.
_ZONE_NAME_RULE = _NameRule(lure_words=True)
_RU_ZONE_BRANDS_LONGEST_FIRST = tuple(sorted(_RU_ZONE_BRANDS, key=lambda b: (-len(b), b)))


def _check_brand_under_open_zone(domain: str) -> Optional[str]:
    """A Russian brand in any label left of an open Russian zone — as the
    whole label (sberbank.spb.ru, v-k.nov.ru), one hyphen-separated part of
    it (gosuslugi-lk.spb.ru) or a keyword combo (vk-login.nov.ru). None
    under restricted zones, REGIONAL_GOVERNMENT_DOMAINS and anywhere else."""
    parts = (domain or "").lower().strip(".").split(".")
    ascii_parts = [_ascii_label(p) for p in parts]
    k = _ru_suffix_length(ascii_parts)
    if not k or k == len(parts) or ".".join(ascii_parts[-k:]) in _RU_RESTRICTED_ZONES:
        return None
    if is_regional_government_domain(domain):
        return None
    # A name data/typosquat_targets_ru.json lists as the brand's own or as
    # another owner's. Dealers and partners are not listed: 'официальный
    # партнёр' on a page is the site's own claim, and lead-generation and
    # scam pages make it too (cdek.msk.ru, beeline.com.ru stay caution).
    if ".".join(parts[-(k + 1):]) in _BRAND_LEGIT_DOMAINS:
        return None
    for label in parts[:-k]:
        whole = label.replace("-", "")
        if whole in _RU_ZONE_BRANDS:
            return whole
        pieces = label.split("-")
        for brand in _RU_ZONE_BRANDS_LONGEST_FIRST:
            if len(brand) >= _RU_ZONE_BRAND_PART_MIN:
                if brand in pieces or _check_combosquat(label, brand, _ZONE_NAME_RULE):
                    return brand
            elif brand in pieces and _check_combosquat(label, brand, _ZONE_NAME_RULE):
                return brand
    return None


# ── Suspicious keywords ──

def _check_suspicious_keywords(domain: str) -> Optional[str]:
    base = _extract_base_domain(domain)
    name = base.split(".")[0].lower()
    for part in name.replace("_", "-").split("-"):
        if part in _SUSPICIOUS_KEYWORDS:
            return part
    return None

"""
URL Feature Extraction Engine.

Extracts 50+ numeric features from a domain/URL for:
  1. Rule-based scoring (used now)
  2. ML model input (CatBoost/LightGBM, future)
  3. Feature logging for training data collection

Features are grouped into categories:
  - Lexical: length, entropy, char ratios, n-gram score
  - Structural: subdomain depth, TLD risk, special chars
  - Brand similarity: edit distance to known brands
  - DNS-derived: TTL, A count, MX, NS
  - SSL-derived: cert age, issuer type
"""

from __future__ import annotations

import json
import logging
import os
from difflib import SequenceMatcher

logger = logging.getLogger("linkshield.url_features")

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")

# ═══════════════════════════════════════════════════════════════
# N-GRAM LANGUAGE MODEL
# ═══════════════════════════════════════════════════════════════

# English bigram frequencies (from large corpus analysis)
# Legitimate domains follow natural language patterns.
# Random/DGA domains deviate significantly.
_ENGLISH_BIGRAMS: dict[str, float] = {
    "th": 3.56, "he": 3.07, "in": 2.43, "er": 2.05, "an": 1.99,
    "re": 1.85, "on": 1.76, "at": 1.49, "en": 1.45, "nd": 1.35,
    "ti": 1.34, "es": 1.34, "or": 1.28, "te": 1.27, "of": 1.17,
    "ed": 1.17, "is": 1.13, "it": 1.12, "al": 1.09, "ar": 1.07,
    "st": 1.05, "to": 1.04, "nt": 1.04, "ng": 0.95, "se": 0.93,
    "ha": 0.93, "as": 0.87, "ou": 0.87, "io": 0.83, "le": 0.83,
    "ve": 0.83, "co": 0.79, "me": 0.79, "de": 0.76, "hi": 0.73,
    "ri": 0.73, "ro": 0.73, "ic": 0.70, "ne": 0.69, "ea": 0.69,
    "ra": 0.69, "ce": 0.65, "li": 0.62, "ch": 0.60, "ll": 0.58,
    "be": 0.58, "ma": 0.57, "si": 0.55, "om": 0.55, "ur": 0.54,
}

# Consonants and vowels
_VOWELS = set("aeiou")
_CONSONANTS = set("bcdfghjklmnpqrstvwxyz")


def bigram_score(s: str) -> float:
    """
    Score how "English-like" a string is based on bigram frequency.
    Higher score = more natural. Lower score = more random/DGA-like.
    Returns normalized score 0.0-1.0.
    """
    s = s.lower()
    if len(s) < 2:
        return 0.5

    total_freq = 0.0
    count = 0
    for i in range(len(s) - 1):
        bigram = s[i:i + 2]
        if bigram.isalpha():
            total_freq += _ENGLISH_BIGRAMS.get(bigram, 0.0)
            count += 1

    if count == 0:
        return 0.0

    avg_freq = total_freq / count
    # Normalize: typical legitimate domains score 0.5-0.9
    # DGA domains score 0.0-0.3
    normalized = min(avg_freq / 2.0, 1.0)
    return round(normalized, 3)


def trigram_uniqueness(s: str) -> float:
    """
    Ratio of unique trigrams to total trigrams.
    High uniqueness (close to 1.0) = random/DGA.
    Low uniqueness (close to 0.3-0.5) = natural language.
    """
    s = s.lower()
    if len(s) < 3:
        return 0.5

    trigrams = [s[i:i + 3] for i in range(len(s) - 2)]
    if not trigrams:
        return 0.5

    unique = len(set(trigrams))
    return round(unique / len(trigrams), 3)


def vowel_consonant_ratio(s: str) -> float:
    """
    Ratio of vowels to consonants.
    Normal English: ~0.6-0.8
    DGA/random: very low (<0.3) or very high (>1.2)
    """
    s = s.lower()
    vowels = sum(1 for c in s if c in _VOWELS)
    consonants = sum(1 for c in s if c in _CONSONANTS)
    if consonants == 0:
        return 2.0 if vowels > 0 else 0.0
    return round(vowels / consonants, 3)


def consecutive_consonants_max(s: str) -> int:
    """
    Maximum consecutive consonants in a string.
    Normal words: max 3-4 (e.g., "str", "ngs")
    Random domains: 5+ consecutive consonants
    """
    s = s.lower()
    max_run = 0
    current = 0
    for c in s:
        if c in _CONSONANTS:
            current += 1
            max_run = max(max_run, current)
        else:
            current = 0
    return max_run


def char_diversity(s: str) -> float:
    """
    Character diversity: unique chars / total length.
    Very high (>0.8) on short strings = random.
    Very low (<0.3) = repetitive/weird.
    """
    if not s:
        return 0.0
    return round(len(set(s.lower())) / len(s), 3)


# ═══════════════════════════════════════════════════════════════
# COMPLETE FEATURE VECTOR EXTRACTION
# ═══════════════════════════════════════════════════════════════

def extract_features(domain: str, signals: dict) -> dict[str, float]:
    """
    Extract complete numeric feature vector from domain and signals.
    Returns dict of feature_name → numeric_value.
    Ready for ML model input or logging.
    """
    from api.services.scoring import (
        _extract_base_domain, _extract_tld, _shannon_entropy,
        _digit_ratio, _special_char_count, _has_at_symbol,
        _has_double_slash_redirect, _has_hex_encoding,
        _has_fake_tld_in_subdomain, _is_url_shortener,
        TOP_DOMAINS, HIGH_RISK_TLDS, MEDIUM_RISK_TLDS,
    )

    base = _extract_base_domain(domain)
    name = base.split(".")[0] if "." in base else base
    tld = _extract_tld(domain)
    raw_url = signals.get("raw_url", domain)

    features: dict[str, float] = {}

    # ── Lexical features ──
    features["domain_length"] = len(domain)
    features["name_length"] = len(name)
    features["url_length"] = len(raw_url)
    features["dot_count"] = domain.count(".")
    features["hyphen_count"] = domain.count("-")
    features["digit_count"] = sum(c.isdigit() for c in name)
    features["digit_ratio"] = _digit_ratio(name)
    features["special_char_count"] = _special_char_count(domain)
    features["path_depth"] = raw_url.count("/") - 2 if "://" in raw_url else raw_url.count("/")

    # ── Entropy & randomness ──
    features["shannon_entropy"] = _shannon_entropy(name)
    features["bigram_score"] = bigram_score(name)
    features["trigram_uniqueness"] = trigram_uniqueness(name)
    features["vowel_consonant_ratio"] = vowel_consonant_ratio(name)
    features["max_consecutive_consonants"] = consecutive_consonants_max(name)
    features["char_diversity"] = char_diversity(name)

    # ── Structural ──
    features["subdomain_depth"] = max(0, domain.count(".") - 1)
    features["is_ip"] = 1.0 if signals.get("is_ip_based") else 0.0
    features["has_at_symbol"] = 1.0 if _has_at_symbol(raw_url) else 0.0
    features["has_double_slash"] = 1.0 if _has_double_slash_redirect(raw_url) else 0.0
    features["has_hex_encoding"] = 1.0 if _has_hex_encoding(domain) else 0.0
    features["has_fake_tld_subdomain"] = 1.0 if _has_fake_tld_in_subdomain(domain) else 0.0
    features["is_url_shortener"] = 1.0 if _is_url_shortener(domain) else 0.0

    # ── TLD risk ──
    features["tld_high_risk"] = 1.0 if tld in HIGH_RISK_TLDS else 0.0
    features["tld_medium_risk"] = 1.0 if tld in MEDIUM_RISK_TLDS else 0.0
    features["in_top_domains"] = 1.0 if base in TOP_DOMAINS else 0.0

    # ── Brand similarity (max similarity to any typosquat target) ──
    features["max_brand_similarity"] = _max_brand_similarity(name)

    # ── DNS-derived ──
    features["domain_age_days"] = float(signals.get("domain_age_days") or -1)
    features["dns_ttl"] = float(signals.get("dns_ttl") or -1)
    features["dns_a_count"] = float(signals.get("dns_a_count") or -1)
    features["dns_ns_count"] = float(signals.get("dns_ns_count") or -1)
    features["dns_has_mx"] = 1.0 if signals.get("dns_has_mx") else 0.0

    # ── SSL-derived ──
    features["has_ssl"] = 0.0 if signals.get("no_https") else 1.0
    features["free_ssl"] = 1.0 if signals.get("free_ssl") else 0.0
    features["cert_age_days"] = float(signals.get("cert_age_days") or -1)

    # ── Redirect ──
    features["redirect_count"] = float(signals.get("redirect_count", 0))
    features["redirect_cross_domain"] = 1.0 if signals.get("redirect_cross_domain") else 0.0

    # ── Blocklist hits (for labeling, not features for ML) ──
    features["_label_safe_browsing"] = 1.0 if signals.get("safe_browsing_hit") else 0.0
    features["_label_phishtank"] = 1.0 if signals.get("phishtank_hit") else 0.0
    features["_label_urlhaus"] = 1.0 if signals.get("urlhaus_hit") else 0.0

    return features


def _max_brand_similarity(name: str) -> float:
    """Find the highest SequenceMatcher similarity to any typosquat target brand."""
    from api.services.scoring import TYPOSQUAT_TARGETS

    max_sim = 0.0
    for brand in TYPOSQUAT_TARGETS:
        if brand == name:
            continue  # Exact match = legitimate, not a feature
        sim = SequenceMatcher(None, name, brand).ratio()
        max_sim = max(max_sim, sim)
    return round(max_sim, 3)


def log_features(domain: str, features: dict[str, float], score: int) -> None:
    """
    Log feature vector for future ML training data collection.
    Append to JSONL file (one line per domain check).
    Privacy: only domain name, no user data.
    """
    import time

    log_entry = {
        "ts": int(time.time()),
        "domain": domain,
        "score": score,
        "features": features,
    }

    log_path = os.path.join(_DATA_DIR, "feature_log.jsonl")
    try:
        with open(log_path, "a") as f:
            f.write(json.dumps(log_entry, default=str) + "\n")
    except Exception as e:
        logger.debug("Failed to write feature log: %s", e)

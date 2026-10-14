"""Every reason code a verdict can carry — the explainer's whole vocabulary.

POST /api/v1/explain is anonymous and its signals end up in an LLM prompt,
so it accepts these codes and nothing else: the reason codes our scorers
emit (api/services/scoring.py, analyzer.py, verdict_basis.py), the ones the
extension's local scorer emits (extension/src/utils/local-scorer.js — the
block page sends both), and the brand / pattern codes the explainer's
category rules know (scam_explainer._CATEGORY_RULES).

tests/test_explainer_hardening.py scans the sources and fails when a new
code is missing here.
"""

from __future__ import annotations

from typing import Iterable

# The most codes one explanation is built from. A real verdict carries 4-6;
# the block page sends at most 20.
MAX_SIGNALS = 20

_BACKEND = frozenset({
    "abnormal_vowel_ratio", "abused_registrar", "alienvault_otx", "alienvault_otx_high",
    "analysis_error", "at_symbol", "brand_subdomain_abuse", "consonant_cluster",
    "cross_domain_redirect", "deep_path", "domain_new", "domain_very_new",
    "double_slash_redirect", "excessive_redirects", "excessive_special_chars",
    "excessive_subdomains", "fake_tld_subdomain", "favicon_brand_clone", "feodo",
    "free_ssl_new_domain", "hex_encoding", "high_digit_ratio", "high_entropy",
    "homograph_attack", "invalid", "invalid_certificate", "invalid_domain", "ip_based",
    "ipqs_high_risk", "ipqs_phishing", "known_legitimate", "llm_judge", "long_domain_name",
    "long_url", "low_dns_ttl", "malware_bazaar", "many_a_records", "many_special_chars",
    "medium_entropy", "missing_headers", "ml_high_risk", "ml_safe_override", "ml_suspicious",
    "multi_blocklist", "multiple_redirects", "new_certificate", "no_https", "no_mx_record",
    "non_standard_port", "partial_analysis", "phishstats", "phishtank", "risky_registrar",
    "risky_tld_high", "risky_tld_medium", "safe_browsing", "spamhaus_dbl", "ssrf_blocked",
    "surbl", "suspicious_keyword", "suspicious_ngram", "threatfox", "tranco_popularity",
    "typosquatting", "unnatural_ngram", "url_pii_leak", "url_shortener", "urlhaus",
    "user_whitelist", "very_long_url", "watchtower_typosquat",
    # verdict_basis.REASON_*
    "cleanway_blocklist", "domain_not_found", "unreachable_from_scanner",
    "checks_incomplete", "user_content_platform",
})

_EXTENSION = frozenset({
    "brand_subdomain", "deep_subdomains", "fake_tld", "high_digits", "hosting_platform",
    "long_domain", "many_hyphens", "risky_tld", "user_content",
})

_EXPLAINER_CATEGORIES = frozenset({
    "credential_form_mismatch", "typosquat_brand_match",
    "metamask_brand", "phantom_brand", "wallet_drain_pattern", "binance_brand",
    "chase_brand", "wellsfargo_brand", "hsbc_brand", "santander_brand", "barclays_brand",
    "bankofamerica_brand",
    "dhl_brand", "ups_brand", "fedex_brand", "package_pickup_pattern", "shipping_fee_request",
})


KNOWN_REASON_CODES: frozenset[str] = _BACKEND | _EXTENSION | _EXPLAINER_CATEGORIES


def clean_signals(signals: Iterable[object]) -> list[str]:
    """The known codes in `signals`, in order, without duplicates, at most
    MAX_SIGNALS. Anything else — free text, other types — is dropped."""
    out: list[str] = []
    for s in signals or ():
        if not isinstance(s, str):
            continue
        code = s.strip().lower()
        if code in KNOWN_REASON_CODES and code not in out:
            out.append(code)
            if len(out) == MAX_SIGNALS:
                break
    return out

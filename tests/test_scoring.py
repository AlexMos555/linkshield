"""Tests for LinkShield Scoring Engine 3.0 — 30+ signals."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api.services.scoring import (
    calculate_score,
    calculate_confidence,
    _check_typosquatting_v2,
    _check_homograph,
    _check_brand_in_subdomain,
    _shannon_entropy,
    _digit_ratio,
    _has_at_symbol,
    _has_double_slash_redirect,
    _has_hex_encoding,
    _has_fake_tld_in_subdomain,
    _is_url_shortener,
    _extract_base_domain,
    TOP_DOMAINS,
)
from api.models.schemas import RiskLevel, ConfidenceLevel


# ═══════════════════════════════════════════════════════════════
# LAYER 1: BLOCKLIST TESTS
# ═══════════════════════════════════════════════════════════════

def test_safe_browsing_instant_block():
    signals = {"domain": "evil.com", "safe_browsing_hit": True}
    score, level, _ = calculate_score(signals)
    assert score >= 80 and level == RiskLevel.dangerous
    print(f"  Safe Browsing hit → instant block: score={score}")


def test_phishtank_instant_block():
    signals = {"domain": "phish.com", "phishtank_hit": True}
    score, level, _ = calculate_score(signals)
    assert score >= 70 and level == RiskLevel.dangerous
    print(f"  PhishTank hit → instant block: score={score}")


def test_urlhaus_instant_block():
    signals = {"domain": "malware.com", "urlhaus_hit": True}
    score, level, _ = calculate_score(signals)
    assert score >= 75 and level == RiskLevel.dangerous
    print(f"  URLhaus hit → instant block: score={score}")


def test_phishstats_hit():
    signals = {"domain": "scam.xyz", "phishstats_hit": True}
    score, level, _ = calculate_score(signals)
    assert score >= 65 and level == RiskLevel.dangerous
    print(f"  PhishStats hit → score={score}")


def test_threatfox_hit():
    signals = {"domain": "ioc.xyz", "threatfox_hit": True}
    score, level, _ = calculate_score(signals)
    assert score >= 70 and level == RiskLevel.dangerous
    print(f"  ThreatFox hit → score={score}")


def test_spamhaus_hit():
    signals = {"domain": "spam.xyz", "spamhaus_hit": True}
    score, level, _ = calculate_score(signals)
    assert score >= 75 and level == RiskLevel.dangerous
    print(f"  Spamhaus DBL hit → score={score}")


def test_surbl_hit():
    signals = {"domain": "spam-uri.xyz", "surbl_hit": True}
    score, level, _ = calculate_score(signals)
    assert score >= 65 and level == RiskLevel.dangerous
    print(f"  SURBL hit → score={score}")


def test_alienvault_otx_high():
    signals = {"domain": "threat.xyz", "alienvault_pulse_count": 10}
    score, _, reasons = calculate_score(signals)
    sigs = [r.signal for r in reasons]
    assert "alienvault_otx_high" in sigs
    print(f"  AlienVault OTX (10 pulses) → score={score}")


def test_alienvault_otx_low():
    signals = {"domain": "suspect.xyz", "alienvault_pulse_count": 2}
    score, _, reasons = calculate_score(signals)
    sigs = [r.signal for r in reasons]
    assert "alienvault_otx" in sigs
    print(f"  AlienVault OTX (2 pulses) → score={score}")


def test_ipqs_phishing():
    signals = {"domain": "phish.xyz", "ipqs_phishing": True}
    score, level, _ = calculate_score(signals)
    assert score >= 70 and level == RiskLevel.dangerous
    print(f"  IPQS phishing → score={score}")


def test_multi_blocklist_boost():
    """Multiple blocklist hits → extra confidence boost."""
    signals = {
        "domain": "evil.xyz",
        "safe_browsing_hit": True,
        "phishtank_hit": True,
        "urlhaus_hit": True,
        "blocklist_hits": 3,
    }
    score, level, reasons = calculate_score(signals)
    sigs = [r.signal for r in reasons]
    assert "multi_blocklist" in sigs
    assert score == 100
    print(f"  Multi-blocklist (3 sources) → score={score}")


# ═══════════════════════════════════════════════════════════════
# LAYER 2: ALLOWLIST TESTS (Tranco 100K)
# ═══════════════════════════════════════════════════════════════

def test_top_domains_loaded():
    assert len(TOP_DOMAINS) > 1000, f"Only {len(TOP_DOMAINS)} domains loaded!"
    print(f"  Top domains loaded: {len(TOP_DOMAINS):,}")


def test_known_domain_safe():
    signals = {"domain": "google.com"}
    score, level, reasons = calculate_score(signals)
    assert score == 0 and level == RiskLevel.safe
    print("  google.com: score=0, safe")


def test_subdomain_of_known():
    signals = {"domain": "mail.google.com"}
    score, level, _ = calculate_score(signals)
    assert score == 0 and level == RiskLevel.safe
    print("  mail.google.com: score=0, safe")


def test_tranco_domain_safe():
    """Domain in Tranco top 100K but not in hardcoded list."""
    signals = {"domain": "stackoverflow.com"}
    score, level, _ = calculate_score(signals)
    assert score == 0 and level == RiskLevel.safe
    print("  stackoverflow.com (Tranco): score=0, safe")


# ═══════════════════════════════════════════════════════════════
# LAYER 3.1-3.5: CORE SIGNALS
# ═══════════════════════════════════════════════════════════════

def test_domain_age_very_new():
    signals = {"domain": "new-site.com", "domain_age_days": 3}
    score, level, _ = calculate_score(signals)
    assert score >= 50
    print(f"  3-day domain: score={score}")


def test_ip_based():
    signals = {"domain": "8.8.8.8", "is_ip_based": True}
    score, level, _ = calculate_score(signals)
    assert score >= 35
    print(f"  IP-based: score={score}")


def test_typosquat_char_sub():
    result = _check_typosquatting_v2("paypa1.com")
    assert result and result[0] == "paypal.com"
    print(f"  paypa1.com → {result[0]} ({result[1]})")


def test_typosquat_hyphen():
    result = _check_typosquatting_v2("pay-pal.com")
    assert result and result[0] == "paypal.com"
    print(f"  pay-pal.com → {result[0]} ({result[1]})")


def test_typosquat_combo():
    result = _check_typosquatting_v2("paypal-login.com")
    assert result and result[0] == "paypal.com"
    print(f"  paypal-login.com → {result[0]} ({result[1]})")


def test_typosquat_tld_confusion():
    result = _check_typosquatting_v2("paypal.co")
    assert result and result[0] == "paypal.com"
    print(f"  paypal.co → {result[0]} ({result[1]})")


def test_typosquat_exact_not_flagged():
    result = _check_typosquatting_v2("paypal.com")
    assert result is None
    print("  paypal.com → not flagged")


def test_brand_subdomain_abuse():
    result = _check_brand_in_subdomain("paypal.evil.com")
    assert result == "paypal"
    print("  paypal.evil.com → brand abuse detected")


def test_brand_subdomain_legit():
    assert _check_brand_in_subdomain("paypal.com") is None
    print("  paypal.com → not abuse")


# ═══════════════════════════════════════════════════════════════
# LAYER 3.6-3.12: STRUCTURAL SIGNALS
# ═══════════════════════════════════════════════════════════════

def test_fake_tld_in_subdomain():
    assert _has_fake_tld_in_subdomain("paypal.com.evil.xyz") is True
    assert _has_fake_tld_in_subdomain("evil.xyz") is False
    print("  paypal.com.evil.xyz → fake TLD detected")


def test_fake_tld_in_scoring():
    signals = {"domain": "paypal.com.evil.xyz"}
    score, _, reasons = calculate_score(signals)
    sigs = [r.signal for r in reasons]
    assert "fake_tld_subdomain" in sigs
    print(f"  fake TLD in scoring: score={score}")


def test_no_https():
    signals = {"domain": "unsafe.com", "no_https": True}
    score, _, _ = calculate_score(signals)
    assert score >= 40
    print(f"  no HTTPS: score={score}")


def test_risky_tld_high():
    signals = {"domain": "evil.tk"}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal.startswith("risky_tld") for r in reasons)
    print(f"  .tk: score={score}")


def test_risky_tld_medium():
    signals = {"domain": "shady.info"}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal.startswith("risky_tld") for r in reasons)
    print(f"  .info: score={score}")


def test_excessive_subdomains():
    signals = {"domain": "a.b.c.d.evil.com"}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "excessive_subdomains" for r in reasons)
    print(f"  deep subdomains: score={score}")


def test_suspicious_keyword():
    signals = {"domain": "secure-login-verify.fakesite.xyz"}
    score, _, reasons = calculate_score(signals)
    assert score > 0
    sigs = [r.signal for r in reasons]
    print(f"  suspicious keyword: score={score}, signals={sigs}")


# ═══════════════════════════════════════════════════════════════
# LAYER 3.13-3.17: URL LEXICAL ANALYSIS
# ═══════════════════════════════════════════════════════════════

def test_shannon_entropy():
    # Normal domain
    e_normal = _shannon_entropy("paypal")
    assert e_normal < 3.0
    # Random DGA domain
    e_random = _shannon_entropy("xk7qm2bz9w3j")
    assert e_random > 3.5
    print(f"  entropy: paypal={e_normal}, random={e_random}")


def test_entropy_in_scoring():
    signals = {"domain": "xk7qm2bz9w3jfp.xyz"}
    score, _, reasons = calculate_score(signals)
    sigs = [r.signal for r in reasons]
    assert "high_entropy" in sigs or "medium_entropy" in sigs
    print(f"  DGA domain scoring: score={score}")


def test_digit_ratio():
    assert _digit_ratio("abc") == 0.0
    assert _digit_ratio("a1b2c3") == 0.5
    assert _digit_ratio("12345") == 1.0
    print("  digit ratio: OK")


def test_high_digit_ratio_scoring():
    signals = {"domain": "abc123456def.com"}
    score, _, reasons = calculate_score(signals)
    sigs = [r.signal for r in reasons]
    assert "high_digit_ratio" in sigs
    print(f"  high digit ratio: score={score}")


def test_at_symbol():
    assert _has_at_symbol("user@evil.com/login") is True
    assert _has_at_symbol("example.com") is False
    print("  @ symbol detection: OK")


def test_at_symbol_scoring():
    signals = {"domain": "evil.com", "raw_url": "http://google.com@evil.com/login"}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "at_symbol" for r in reasons)
    print(f"  @ in URL scoring: score={score}")


def test_double_slash():
    assert _has_double_slash_redirect("http://evil.com//redirect") is True
    assert _has_double_slash_redirect("http://example.com/page") is False
    print("  double slash detection: OK")


def test_hex_encoding():
    assert _has_hex_encoding("evil%2Ecom") is True
    assert _has_hex_encoding("example.com") is False
    print("  hex encoding detection: OK")


def test_non_standard_port():
    signals = {"domain": "evil.com", "raw_url": "http://evil.com:4444/login"}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "non_standard_port" for r in reasons)
    print(f"  non-standard port: score={score}")


def test_long_url():
    long_path = "a" * 80
    signals = {"domain": "evil.com", "raw_url": f"http://evil.com/{long_path}"}
    score, _, reasons = calculate_score(signals)
    assert any("long" in r.signal for r in reasons)
    print(f"  long URL: score={score}")


# ═══════════════════════════════════════════════════════════════
# LAYER 3.18-3.23: EXTRA SIGNALS
# ═══════════════════════════════════════════════════════════════

def test_url_shortener():
    assert _is_url_shortener("bit.ly") is True
    assert _is_url_shortener("tinyurl.com") is True
    assert _is_url_shortener("google.com") is False
    print("  URL shortener detection: OK")


def test_url_shortener_scoring():
    signals = {"domain": "bit.ly"}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "url_shortener" for r in reasons)
    print(f"  URL shortener scoring: score={score}")


def test_long_domain_name():
    signals = {"domain": "this-is-a-very-long-suspicious-domain-name.com"}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "long_domain_name" for r in reasons)
    print(f"  long domain name: score={score}")


# ═══════════════════════════════════════════════════════════════
# HOMOGRAPH TESTS
# ═══════════════════════════════════════════════════════════════

def test_homograph_cyrillic():
    result = _check_homograph("p\u0430ypal.com")
    assert result is not None
    print(f"  Cyrillic а in paypal → impersonates {result}")


def test_homograph_pure_ascii():
    assert _check_homograph("paypal.com") is None
    print("  Pure ASCII → no homograph")


def test_homograph_scoring():
    signals = {"domain": "p\u0430ypal.com"}
    score, _, reasons = calculate_score(signals)
    assert score >= 60
    print(f"  homograph scoring: score={score}")


# ═══════════════════════════════════════════════════════════════
# CONFIDENCE LEVELS
# ═══════════════════════════════════════════════════════════════

def test_confidence_high():
    assert calculate_confidence(5, 5, 100) == ConfidenceLevel.high
    print("  5/5 + age → high")


def test_confidence_medium():
    assert calculate_confidence(3, 5, None) == ConfidenceLevel.medium
    print("  3/5 → medium")


def test_confidence_low():
    assert calculate_confidence(2, 5, None) == ConfidenceLevel.low
    print("  2/5 → low")


# ═══════════════════════════════════════════════════════════════
# CIRCUIT BREAKER
# ═══════════════════════════════════════════════════════════════

def test_circuit_breaker():
    import asyncio
    from api.services.circuit_breaker import CircuitBreaker, CircuitState

    breaker = CircuitBreaker(name="test", failure_threshold=2, cooldown_seconds=0.1)

    async def success(): return "ok"
    async def failure(): raise Exception("boom")

    async def run():
        assert breaker.state == CircuitState.CLOSED
        await breaker.call(success)
        await breaker.call(failure)
        await breaker.call(failure)
        assert breaker.state == CircuitState.OPEN
        result, ok = await breaker.call(success)
        assert ok is False
        import time; time.sleep(0.15)
        assert breaker.state == CircuitState.HALF_OPEN
        _, ok = await breaker.call(success)
        assert ok is True and breaker.state == CircuitState.CLOSED

    asyncio.get_event_loop().run_until_complete(run())
    print("  circuit breaker transitions: OK")


# ═══════════════════════════════════════════════════════════════
# SSRF PROTECTION
# ═══════════════════════════════════════════════════════════════

def test_ssrf_blocked_domains():
    from api.services.domain_validator import validate_domain, DomainValidationError
    for d in ["localhost", "", ".", "a" * 300]:
        try:
            validate_domain(d)
            assert False, f"Should reject: {d}"
        except DomainValidationError:
            pass
    print("  SSRF: blocked domains rejected")


def test_ssrf_blocked_ips():
    from api.services.domain_validator import validate_domain, DomainValidationError
    for ip in ["127.0.0.1", "10.0.0.1", "169.254.169.254"]:
        try:
            validate_domain(ip)
            assert False, f"Should reject: {ip}"
        except DomainValidationError:
            pass
    assert validate_domain("8.8.8.8") == "8.8.8.8"
    print("  SSRF: internal IPs blocked, public allowed")


# ═══════════════════════════════════════════════════════════════
# DNS & INFRASTRUCTURE SIGNALS
# ═══════════════════════════════════════════════════════════════

def test_low_dns_ttl():
    signals = {"domain": "suspicious.xyz", "dns_ttl": 60}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "low_dns_ttl" for r in reasons)
    print(f"  low TTL (60s): score={score}")


def test_normal_dns_ttl():
    signals = {"domain": "normal.com", "dns_ttl": 3600}
    score, _, reasons = calculate_score(signals)
    assert not any(r.signal == "low_dns_ttl" for r in reasons)
    print("  normal TTL (3600s): no flag")


def test_no_mx_record():
    signals = {"domain": "nomx.xyz", "dns_has_mx": False}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "no_mx_record" for r in reasons)
    print(f"  no MX record: score={score}")


def test_many_a_records():
    signals = {"domain": "fastflux.xyz", "dns_a_count": 15}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "many_a_records" for r in reasons)
    print(f"  many A records (15): score={score}")


def test_new_certificate():
    signals = {"domain": "newcert.xyz", "cert_age_days": 2}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "new_certificate" for r in reasons)
    print(f"  new cert (2 days): score={score}")


def test_old_certificate_no_flag():
    signals = {"domain": "oldcert.com", "cert_age_days": 365}
    score, _, reasons = calculate_score(signals)
    assert not any(r.signal == "new_certificate" for r in reasons)
    print("  old cert (365 days): no flag")


def test_excessive_redirects():
    signals = {"domain": "redir.xyz", "redirect_count": 5}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "excessive_redirects" for r in reasons)
    print(f"  5 redirects: score={score}")


def test_cross_domain_redirect():
    signals = {"domain": "trick.xyz", "redirect_cross_domain": True}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "cross_domain_redirect" for r in reasons)
    print(f"  cross-domain redirect: score={score}")


def test_dns_plus_cert_combo():
    """New domain + low TTL + new cert + no MX = very suspicious."""
    signals = {
        "domain": "scam-site.tk",
        "domain_age_days": 3,
        "dns_ttl": 60,
        "dns_has_mx": False,
        "cert_age_days": 1,
    }
    score, level, reasons = calculate_score(signals)
    assert score >= 80 and level == RiskLevel.dangerous
    sigs = [r.signal for r in reasons]
    print(f"  DNS+cert combo: score={score}, signals={sigs}")


# ═══════════════════════════════════════════════════════════════
# N-GRAM / LANGUAGE ANALYSIS
# ═══════════════════════════════════════════════════════════════

def test_bigram_score():
    from api.services.url_features import bigram_score
    # Natural word
    natural = bigram_score("internet")
    # Random DGA
    random_ = bigram_score("xkqzmwpbvj")
    assert natural > random_, f"natural={natural} should be > random={random_}"
    print(f"  bigram: internet={natural}, random={random_}")


def test_trigram_uniqueness():
    from api.services.url_features import trigram_uniqueness
    # Repetitive word has lower uniqueness
    repetitive = trigram_uniqueness("aaaaaaa")
    varied = trigram_uniqueness("xkqzmwpbvjrl")
    assert varied > repetitive, f"varied={varied} should be > repetitive={repetitive}"
    print(f"  trigram uniqueness: repetitive={repetitive}, varied={varied}")


def test_vowel_consonant_ratio():
    from api.services.url_features import vowel_consonant_ratio
    normal = vowel_consonant_ratio("paypal")
    extreme = vowel_consonant_ratio("bcdfgh")
    assert 0.3 < normal < 1.2
    assert extreme < 0.2
    print(f"  vowel ratio: paypal={normal}, bcdfgh={extreme}")


def test_consecutive_consonants():
    from api.services.url_features import consecutive_consonants_max
    assert consecutive_consonants_max("strengths") == 5
    assert consecutive_consonants_max("paypal") == 2
    print("  consecutive consonants: OK")


def test_ngram_in_scoring():
    """DGA-like domain triggers n-gram signal."""
    signals = {"domain": "xkqzmbwpvjnt.com"}
    score, _, reasons = calculate_score(signals)
    sigs = [r.signal for r in reasons]
    assert "unnatural_ngram" in sigs or "suspicious_ngram" in sigs
    print(f"  n-gram in scoring: score={score}")


def test_vowel_ratio_in_scoring():
    """Domain with extreme vowel ratio."""
    signals = {"domain": "bcdfghjklmnp.com"}
    score, _, reasons = calculate_score(signals)
    sigs = [r.signal for r in reasons]
    assert "abnormal_vowel_ratio" in sigs or "consonant_cluster" in sigs
    print(f"  vowel ratio in scoring: score={score}")


def test_registrar_reputation():
    """Abused registrar adds to score."""
    signals = {"domain": "suspicious.xyz", "registrar": "Namecheap, Inc."}
    score, _, reasons = calculate_score(signals)
    sigs = [r.signal for r in reasons]
    assert "abused_registrar" in sigs
    print(f"  abused registrar: score={score}")


def test_normal_registrar():
    signals = {"domain": "normal.com", "registrar": "Cloudflare, Inc."}
    score, _, reasons = calculate_score(signals)
    sigs = [r.signal for r in reasons]
    assert "abused_registrar" not in sigs
    print("  normal registrar: no flag")


# ═══════════════════════════════════════════════════════════════
# ML FEATURE EXTRACTION
# ═══════════════════════════════════════════════════════════════

def test_feature_extraction():
    """Extract full feature vector."""
    from api.services.url_features import extract_features
    signals = {
        "domain": "paypa1-verify.tk",
        "raw_url": "http://paypa1-verify.tk/login",
        "domain_age_days": 3,
        "is_ip_based": False,
        "no_https": True,
        "free_ssl": False,
        "dns_ttl": 60,
        "dns_a_count": 2,
        "dns_ns_count": 2,
        "dns_has_mx": False,
        "cert_age_days": 1,
        "redirect_count": 2,
        "redirect_cross_domain": False,
    }
    features = extract_features("paypa1-verify.tk", signals)
    assert len(features) >= 35, f"Only {len(features)} features extracted"
    assert "shannon_entropy" in features
    assert "bigram_score" in features
    assert "vowel_consonant_ratio" in features
    assert "max_brand_similarity" in features
    assert features["tld_high_risk"] == 1.0  # .tk is high risk
    print(f"  feature extraction: {len(features)} features")
    # Print a sample
    sample = {k: v for k, v in list(features.items())[:8]}
    print(f"    sample: {sample}")


def test_typosquat_targets_loaded():
    """Verify 100+ brands loaded from JSON."""
    from api.services.scoring import TYPOSQUAT_TARGETS
    assert len(TYPOSQUAT_TARGETS) >= 100, f"Only {len(TYPOSQUAT_TARGETS)} brands!"
    assert "paypal" in TYPOSQUAT_TARGETS
    assert "coinbase" in TYPOSQUAT_TARGETS
    assert "airbnb" in TYPOSQUAT_TARGETS
    print(f"  typosquat targets loaded: {len(TYPOSQUAT_TARGETS)} brands")


# ═══════════════════════════════════════════════════════════════
# COMBO — MAXIMUM DANGER SCORE
# ═══════════════════════════════════════════════════════════════

def test_combo_blocklist_instant():
    """Blocklist hit → instant dangerous (Layer 1)."""
    signals = {"domain": "evil.tk", "safe_browsing_hit": True, "phishtank_hit": True}
    score, level, reasons = calculate_score(signals)
    assert score == 100 and level == RiskLevel.dangerous
    print(f"  Double blocklist hit: score={score}, {len(reasons)} reasons")


def test_combo_no_blocklist_stacks():
    """Without blocklist, many signals stack to dangerous."""
    signals = {
        "domain": "paypa1-verify.tk",
        "raw_url": "http://google.com@paypa1-verify.tk:4444/a/b/c/d/e/login.php?x=" + "a" * 50,
        "safe_browsing_hit": False,
        "domain_age_days": 2,
        "no_https": True,
        "free_ssl": True,
    }
    score, level, reasons = calculate_score(signals)
    assert score == 100 and level == RiskLevel.dangerous
    sigs = [r.signal for r in reasons]
    print(f"  Maximum danger (no blocklist): score={score}, {len(reasons)} signals")
    print(f"    signals: {sigs}")
    assert len(reasons) >= 6  # Many signals stacking


def test_extract_base_domain():
    assert _extract_base_domain("www.example.com") == "example.com"
    assert _extract_base_domain("a.b.c.example.com") == "example.com"
    print("  base domain extraction: OK")


# ═══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("LinkShield Scoring Engine 3.0 — 30+ Signal Tests")
    print("=" * 55)

    sections = [
        ("\n[Layer 1: Blocklist — 9 sources]", [
            test_safe_browsing_instant_block, test_phishtank_instant_block, test_urlhaus_instant_block,
            test_phishstats_hit, test_threatfox_hit, test_spamhaus_hit, test_surbl_hit,
            test_alienvault_otx_high, test_alienvault_otx_low, test_ipqs_phishing,
            test_multi_blocklist_boost,
        ]),
        ("\n[Layer 2: Allowlist — Tranco 100K]", [
            test_top_domains_loaded, test_known_domain_safe, test_subdomain_of_known, test_tranco_domain_safe,
        ]),
        ("\n[Layer 3.1-3.5: Core Signals]", [
            test_domain_age_very_new, test_ip_based,
            test_typosquat_char_sub, test_typosquat_hyphen, test_typosquat_combo,
            test_typosquat_tld_confusion, test_typosquat_exact_not_flagged,
            test_brand_subdomain_abuse, test_brand_subdomain_legit,
        ]),
        ("\n[Layer 3.6-3.12: Structural]", [
            test_fake_tld_in_subdomain, test_fake_tld_in_scoring,
            test_no_https, test_risky_tld_high, test_risky_tld_medium,
            test_excessive_subdomains, test_suspicious_keyword,
        ]),
        ("\n[Layer 3.13-3.17: URL Lexical]", [
            test_shannon_entropy, test_entropy_in_scoring,
            test_digit_ratio, test_high_digit_ratio_scoring,
            test_at_symbol, test_at_symbol_scoring,
            test_double_slash, test_hex_encoding,
            test_non_standard_port, test_long_url,
        ]),
        ("\n[Layer 3.18-3.23: Extra Signals]", [
            test_url_shortener, test_url_shortener_scoring, test_long_domain_name,
        ]),
        ("\n[Homograph / IDN]", [
            test_homograph_cyrillic, test_homograph_pure_ascii, test_homograph_scoring,
        ]),
        ("\n[Confidence]", [
            test_confidence_high, test_confidence_medium, test_confidence_low,
        ]),
        ("\n[Circuit Breaker]", [test_circuit_breaker]),
        ("\n[DNS & Infrastructure]", [
            test_low_dns_ttl, test_normal_dns_ttl, test_no_mx_record,
            test_many_a_records, test_new_certificate, test_old_certificate_no_flag,
            test_excessive_redirects, test_cross_domain_redirect, test_dns_plus_cert_combo,
        ]),
        ("\n[N-gram / Language Analysis]", [
            test_bigram_score, test_trigram_uniqueness,
            test_vowel_consonant_ratio, test_consecutive_consonants,
            test_ngram_in_scoring, test_vowel_ratio_in_scoring,
            test_registrar_reputation, test_normal_registrar,
        ]),
        ("\n[ML Feature Extraction]", [
            test_feature_extraction, test_typosquat_targets_loaded,
        ]),
        ("\n[SSRF Protection]", [test_ssrf_blocked_domains, test_ssrf_blocked_ips]),
        ("\n[Combo Maximum Danger]", [test_combo_blocklist_instant, test_combo_no_blocklist_stacks, test_extract_base_domain]),
    ]

    total = 0
    for title, tests in sections:
        print(title)
        for t in tests:
            t()
            total += 1

    print("\n" + "=" * 55)
    print(f"All {total} tests passed!")

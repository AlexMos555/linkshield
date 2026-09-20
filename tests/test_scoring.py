"""Tests for Cleanway Scoring Engine 3.0 — 30+ signals."""
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
    _decode_idn,
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


def test_otx_popularity_gate():
    """OTX pulses MENTION a domain; legit popular sites appear as impersonation
    TARGETS, so gate by popularity. Regression guard for the 2026-07-06 FP where
    elfinanciero.com.mx (national newspaper, top-10k) landed 'dangerous' on 8
    victim-reference pulses. Top-10k → suppressed (incl. compound ccTLD); obscure
    domains keep full weight so recall on genuinely-flagged domains holds."""
    def otx_weight(domain, pulses):
        _, _, reasons = calculate_score({"domain": domain, "alienvault_pulse_count": pulses})
        return sum(r.weight for r in reasons if r.signal.startswith("alienvault"))

    # top-10k legit → suppressed regardless of pulse count (compound ccTLD works)
    assert otx_weight("elfinanciero.com.mx", 8) == 0
    assert otx_weight("mercadolibre.com.mx", 2) == 0
    # obscure domain → kept at full weight (recall preserved)
    assert otx_weight("solar-sanat.net", 50) == 60
    assert otx_weight("hdbkell.com", 1) == 30


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
    score, level, reasons = calculate_score(signals)
    # domain_very_new (+50) is the signal under test. The ML may apply
    # ml_safe_override (-10) when it reads the (benign-looking) domain as safe,
    # so assert the signal fires + a threshold that accounts for that nudge.
    assert any(r.signal == "domain_very_new" for r in reasons)
    assert score >= 40
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


def test_typosquat_glyph_homoglyph():
    # Multi-char ASCII glyph look-alikes (rn->m, vv->w) — a top real-world tactic,
    # missed by single-char substitution and Levenshtein<=2.
    for dom, brand in [("rnicrosoft.com", "microsoft.com"), ("vvhatsapp.com", "whatsapp.com")]:
        result = _check_typosquatting_v2(dom)
        assert result and result[0] == brand, f"{dom} not caught: {result}"
        print(f"  {dom} → {result[0]} ({result[1]})")


def test_brand_subdomain_cctld_apex_safe():
    # A brand's own apex on a multi-part suffix must NOT be flagged as a spoof
    # subdomain (regression: barclays.co.uk was caution before the PSL-aware fix).
    for apex in ["barclays.co.uk", "halifax.co.uk", "google.co.jp", "itau.com.br",
                 # out-of-hardcoded-list compound ccTLDs (PSL heuristic must cover):
                 "apple.com.cn", "barclays.co.nz", "hsbc.com.tr", "paypal.co.il",
                 "santander.com.ar", "hsbc.co.th"]:
        assert _check_brand_in_subdomain(apex) is None, f"{apex} wrongly flagged"
        score, level, _ = calculate_score({"domain": apex})
        assert level.value == "safe", f"{apex} → {level.value} ({score})"
    print("  ccTLD brand apexes → all safe (no brand_subdomain_abuse)")


def test_brand_subdomain_cctld_spoof_still_fires():
    # But a brand label as a real subdomain of an attacker domain must still fire.
    assert _check_brand_in_subdomain("barclays.account-verify.com") == "barclays"
    assert _check_brand_in_subdomain("paypal.com.attacker.xyz") == "paypal"
    print("  attacker brand-subdomain spoofs → still detected")


def test_combosquat_generic_word_not_dangerous():
    # Regression (workflow finding 1): crypto/generic keywords must NOT expand
    # combosquat. Legit brand-partner names (Shopify Connect, Chase Rewards) must
    # not flip to DANGEROUS the way they did when combosquat reused the full
    # keyword list.
    for dom in ["shopify-connect.com", "google-sync.com", "chase-rewards.com",
                "salesforce-connect.com", "microsoft-connect.com", "amex-rewards.com"]:
        score, level, _ = calculate_score({"domain": dom})
        assert level.value != "dangerous", f"{dom} → {level.value} ({score})"
    print("  brand+generic-word → not dangerous (combosquat decoupled)")


def test_combosquat_classic_word_still_fires():
    # The classic phishing-action words must still drive combosquat detection.
    for dom, brand in [("paypal-login.com", "paypal.com"), ("apple-account.com", "apple.com"),
                       ("amazon-billing.com", "amazon.com"), ("microsoft-verify.net", "microsoft.com")]:
        res = _check_typosquatting_v2(dom)
        assert res and res[0] == brand, f"{dom} not caught: {res}"
    print("  brand+classic-action-word → still combosquat-detected")


def test_glyph_homoglyph_with_keyword():
    # Regression (workflow findings 2/3): a glyph lookalike of a listed brand PLUS
    # an extra label / second typo must still flag — the glyph corruption itself is
    # the intent signal, so exact-match-only was too strict.
    for dom, brand in [("rnicrosoft-login.com", "microsoft.com"),
                       ("vvhatsapp-web.com", "whatsapp.com"),
                       ("vvellsfargo-secure.com", "wellsfargo.com"),
                       ("grnail-verify.com", "gmail.com"),
                       ("rnicrosofts.com", "microsoft.com")]:
        res = _check_typosquatting_v2(dom)
        assert res and res[0] == brand, f"{dom} not caught: {res}"
    print("  glyph homoglyph + keyword/typo → detected")


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
    score, _, reasons = calculate_score(signals)
    # no_https (+40) is the signal under test; ML may apply ml_safe_override (-10).
    assert any(r.signal == "no_https" for r in reasons)
    assert score >= 30
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


def test_risky_tld_zip_mov():
    # Google's 2023 file-extension gTLDs (.zip/.mov) + 2026 abused TLDs are high-risk.
    for tld_dom in ["invoice.zip", "brand.mov", "login.sbs", "promo.cfd"]:
        _, _, reasons = calculate_score({"domain": tld_dom})
        assert any(r.signal.startswith("risky_tld") for r in reasons), f"{tld_dom} not flagged"
    print("  .zip/.mov/.sbs/.cfd → risky_tld fires")


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


def test_suspicious_keyword_crypto_drainer():
    # Wallet-drainer lexicon (connect/claim/airdrop/restore/seed) is the 2025-2026
    # crypto-phishing signature.
    for kw_dom in ["ledger-restore.com", "metamask-claim.xyz", "wallet-airdrop.io"]:
        _, _, reasons = calculate_score({"domain": kw_dom})
        assert any(r.signal == "suspicious_keyword" for r in reasons), f"{kw_dom} missed"
    print("  crypto-drainer keywords → suspicious_keyword fires")


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


def test_homograph_punycode():
    # IDN homograph attacks appear in DNS/URLs as ASCII xn-- punycode; the
    # detector must decode them, not treat them as harmless ASCII (2026-07-06 gap:
    # punycode homographs were 70% missed until we decoded xn-- first).
    result = _check_homograph("xn--pypal-4ve.com")  # punycode of pаypal (Cyrillic а)
    assert result is not None, "punycode homograph must be decoded + flagged"
    # a legit internationalized domain (no confusables) must NOT false-positive
    assert _check_homograph("xn--caf-dma.com") is None  # café.com — legit é, not a lookalike


def test_homograph_scoring():
    signals = {"domain": "p\u0430ypal.com"}
    score, _, reasons = calculate_score(signals)
    assert score >= 60
    print(f"  homograph scoring: score={score}")


# ═══════════════════════════════════════════════════════════════
# IDN / PUNYCODE NORMALISATION
#
# DNS carries internationalised domains in their ASCII-compatible
# (punycode) form. That form is an ENCODING, not a name:
# `xn----7sbnackuskv0m.xn--p1ai` has six hyphens and a 19-character
# label, while the name it encodes — `экзамен-пдд.рф` — has one hyphen
# and eleven characters. Measured 2026-09-20 on a 2,000-domain random
# sample of the .ru/.рф/.su Tranco tail: 28 of the 29 punycode domains
# came back 'caution', every one of them on name-shape heuristics
# reading the encoding's artefacts (судьироссии.рф — the Russian
# judiciary — scored 31). Cleanway is RU-first, so this is a direct
# trust problem.
# ═══════════════════════════════════════════════════════════════

# Real .рф domains from the Tranco top-1M tail, with the names they encode.
_EKZAMEN_PDD = "xn----7sbnackuskv0m.xn--p1ai"         # экзамен-пдд.рф
_SUDI_ROSSII = "xn--d1aiaa2aleeao4h.xn--p1ai"         # судьироссии.рф
_PEREMYSHL = "xn----8sbnapgcdijslcphl1j5bv.xn--p1ai"  # перемышльский-район.рф

# Heuristics that judge the SHAPE of a name. Every one of them must read
# the decoded name, never the punycode.
_NAME_SHAPE_SIGNALS = {
    "high_entropy", "medium_entropy",
    "excessive_special_chars", "many_special_chars",
    "unnatural_ngram", "suspicious_ngram",
    "abnormal_vowel_ratio", "consonant_cluster",
    "long_domain_name", "high_digit_ratio",
}


def test_decode_idn_returns_the_real_name():
    assert _decode_idn(_EKZAMEN_PDD) == "экзамен-пдд.рф"
    assert _decode_idn(_SUDI_ROSSII) == "судьироссии.рф"
    # Only xn-- labels change; a mixed name keeps its ASCII labels verbatim.
    assert _decode_idn("shop.xn--p1ai") == "shop.рф"
    print("  _decode_idn: punycode → real name")


def test_decode_idn_is_a_noop_for_ascii():
    # The overwhelmingly common path must be byte-identical, not merely equal.
    for d in ("paypal.com", "my-shop.ru", "a.b.c.example.co.uk", ""):
        assert _decode_idn(d) == d
    print("  _decode_idn: ASCII untouched")


def test_decode_idn_never_raises_on_malformed_labels():
    # A decode failure must degrade to the ASCII form, never propagate.
    for bad in ("xn--.com", "xn--!!!!.com", "xn--" + "a" * 120 + ".com", "xn--xn--xn--.ru"):
        out = _decode_idn(bad)
        assert isinstance(out, str) and out          # no crash, no empty result
        assert out.count(".") == bad.count(".")      # label structure preserved
    # And the scorer as a whole survives them.
    for bad in ("xn--.com", "xn--!!!!.ru"):
        score, _level, _ = calculate_score({"domain": bad})
        assert 0 <= score <= 100
    print("  _decode_idn: malformed punycode falls back safely")


def test_idn_russian_domain_loses_encoding_artefact_penalties():
    # экзамен-пдд.рф — a driving-test site. Was: 37 / caution on
    # medium_entropy + excessive_special_chars + unnatural_ngram +
    # abnormal_vowel_ratio, all read off the punycode.
    score, level, reasons = calculate_score({"domain": _EKZAMEN_PDD})
    fired = {r.signal for r in reasons}
    assert not (fired & _NAME_SHAPE_SIGNALS), f"name-shape signals still firing on the encoding: {fired}"
    assert level == RiskLevel.safe, f"legit .рф domain scored {score}/{level}"
    print(f"  экзамен-пдд.рф: score={score} level={level.value}")


def test_idn_russian_government_domain_is_safe():
    # судьироссии.рф — the Russian judiciary. Was 31 / caution.
    score, level, reasons = calculate_score({"domain": _SUDI_ROSSII})
    assert level == RiskLevel.safe, f"судьироссии.рф scored {score}: {[r.signal for r in reasons]}"
    print(f"  судьироссии.рф: score={score} level={level.value}")


def test_idn_hyphen_count_uses_the_decoded_name():
    # The '----' in xn----7sb… is the ACE delimiter plus the hyphen of the
    # real name — an artefact of the encoding, not four hyphens in the name.
    _score, _level, reasons = calculate_score({"domain": _EKZAMEN_PDD})
    assert not any(r.signal in ("excessive_special_chars", "many_special_chars") for r in reasons)
    # An ASCII name with genuinely many hyphens must still be flagged.
    _, _, ascii_reasons = calculate_score({"domain": "a-b-c-d-e.ru"})
    assert any(r.signal == "excessive_special_chars" for r in ascii_reasons)
    print("  hyphen count read off the real name, ASCII behaviour intact")


def test_idn_english_heuristics_do_not_judge_cyrillic():
    # The ENGLISH-trained forms must never touch a Cyrillic name:
    # bigram_score() has no Cyrillic pairs (0.0 for EVERY Russian name) and
    # _VOWELS/_CONSONANTS are ASCII-only (vowel ratio always 0.0 →
    # "abnormal"). Applied to Cyrillic they measure "not English", not
    # "random". The Cyrillic name is judged by the Cyrillic forms instead
    # (see the SCRIPT-AWARE block below) — these three legitimate names
    # trip none of them.
    for d in (_EKZAMEN_PDD, _SUDI_ROSSII, _PEREMYSHL):
        _, _, reasons = calculate_score({"domain": d})
        fired = {r.signal for r in reasons}
        assert "unnatural_ngram" not in fired and "suspicious_ngram" not in fired
        assert "abnormal_vowel_ratio" not in fired
        assert "consonant_cluster" not in fired
    # An ASCII DGA-looking name must still trip them.
    _, _, dga = calculate_score({"domain": "qwrtpsdfgh.ru"})
    dga_fired = {r.signal for r in dga}
    assert "unnatural_ngram" in dga_fired and "abnormal_vowel_ratio" in dga_fired
    print("  English-trained heuristics skip Cyrillic, still fire on ASCII DGA")


def test_idn_legit_non_cyrillic_idn_is_safe():
    # café.com — a legitimate accented name, not a lookalike. Was 18 on
    # many_special_chars (punycode hyphens) + unnatural_ngram.
    score, level, reasons = calculate_score({"domain": "xn--caf-dma.com"})
    assert not ({r.signal for r in reasons} & _NAME_SHAPE_SIGNALS)
    assert level == RiskLevel.safe
    print(f"  café.com: score={score}")


# ═══════════════════════════════════════════════════════════════
# SCRIPT-AWARE NAME-SHAPE HEURISTICS (Cyrillic)
#
# Skipping the English heuristics on non-ASCII names fixed the punycode
# false positives but left a hole: an all-Cyrillic name got ZERO lexical
# scrutiny. Measured on the branch before this change,
# `xn--80adhfuilkik7f6ag8a.xn--p1ai` (жкшнвыапролдэъ.рф — a ЙЦУКЕН
# home-row mash) scored 0/safe with an EMPTY reasons list, and 398 of 400
# synthesised Cyrillic DGA names scored exactly 0.
#
# Cleanway is RU-first, so "we no longer judge Cyrillic names at all" is
# the wrong end state: a freshly registered, algorithmically generated
# Cyrillic domain with no reputation must still look suspicious locally.
# The heuristics are therefore re-run against CYRILLIC reference data.
#
# Calibration sets (see the commit message for the full trade-off curve):
#   negative — the 653 Cyrillic-name punycode domains in data/top-1m.csv
#   positive — 1,000 synthesised uniform-random Cyrillic names, length
#              distribution matched to the negative set, seed 1337
# ═══════════════════════════════════════════════════════════════

# The reviewer's reproduction case: a home-row keyboard mash under .рф.
_CYRILLIC_MASH = "xn--80adhfuilkik7f6ag8a.xn--p1ai"   # жкшнвыапролдэъ.рф


def test_cyrillic_dga_name_is_no_longer_invisible():
    # THE regression this block exists for. Was: 0 / safe / [] — a name
    # nobody could read got a clean bill of health with nothing to show
    # for it. It must now be looked at and the finding must be NAMED.
    score, _level, reasons = calculate_score({"domain": _CYRILLIC_MASH})
    assert score > 0, "all-Cyrillic DGA name still gets zero lexical scrutiny"
    assert reasons, "score with an empty reasons list — nothing to show a user"
    assert any(r.signal in _NAME_SHAPE_SIGNALS for r in reasons), \
        f"scored, but on no name-shape signal: {[r.signal for r in reasons]}"
    print(f"  жкшнвыапролдэъ.рф: score={score} reasons={[r.signal for r in reasons]}")


def test_cyrillic_stacked_anomalies_reach_caution():
    # A Cyrillic name that trips several independent anomalies at once must
    # clear the caution line. No single lexical signal can do this alone
    # (max weight 12 < the 21 needed) — that is deliberate: one anomaly is
    # an opinion, three are a pattern.
    #   ьъщчжшгкхцф — no vowels at all, an 11-consonant run.
    name = "xn--" + "ьъщчжшгкхцф".encode("punycode").decode() + ".xn--p1ai"
    score, level, reasons = calculate_score({"domain": name})
    fired = {r.signal for r in reasons}
    assert "abnormal_vowel_ratio" in fired, fired
    assert "consonant_cluster" in fired, fired
    assert level == RiskLevel.caution, f"stacked Cyrillic anomalies scored only {score}"
    print(f"  ьъщчжшгкхцф.рф: score={score} level={level.value} {sorted(fired)}")


def test_cyrillic_vowel_ratio_uses_the_cyrillic_alphabet():
    from api.services.url_features import cyrillic_vowel_consonant_ratio
    # а е ё и о у ы э ю я are the vowels; б…щ the consonants.
    assert cyrillic_vowel_consonant_ratio("оооо") == 2.0      # vowels, no consonants
    assert cyrillic_vowel_consonant_ratio("ктпр") == 0.0      # consonants, no vowels
    assert cyrillic_vowel_consonant_ratio("вода") == 1.0      # в-о-д-а → 2/2
    # ASCII letters are not Cyrillic and must not be counted either way.
    assert cyrillic_vowel_consonant_ratio("abcde") == 0.0
    print("  Cyrillic vowel ratio counts the right alphabet")


def test_cyrillic_soft_and_hard_signs_break_consonant_runs():
    from api.services.url_features import cyrillic_consecutive_consonants_max
    # ъ and ь are SIGNS, not consonants — they modify the consonant before
    # them and cannot be spoken alone, so they BREAK a run. This is not a
    # stylistic call: counting them as consonants turns three real domains
    # in the Tranco Cyrillic set into >= 5-runs, one of which is the
    # regional-government name this branch exists to protect.
    assert cyrillic_consecutive_consonants_max("перемышльский-район") == 2   # ...шльс... → 5 if ь counted
    assert cyrillic_consecutive_consonants_max("севастопольстрой") == 3      # ...льстр... → 5 if ь counted
    assert cyrillic_consecutive_consonants_max("объясняем") == 2
    assert cyrillic_consecutive_consonants_max("жкшнв") == 5
    # Measured on the 653 legitimate Cyrillic names: a run of >= 5 never
    # occurs, while >= 4 hits 17 of them — including президентскиегранты
    # and реестрповесток, both Russian government sites. Hence the >= 5 cut.
    assert cyrillic_consecutive_consonants_max("президентскиегранты") == 4
    print("  ъ/ь break consonant runs; >=5 stays clear of real Russian words")


def test_russian_bigram_score_separates_words_from_mash():
    from api.services.url_features import russian_bigram_score
    # Real Russian compounds score above the 0.10 line; uniform-random
    # Cyrillic scores at or near zero (it has no common Russian pairs).
    assert russian_bigram_score("всеостройке") > 0.10
    assert russian_bigram_score("смородина") > 0.10
    assert russian_bigram_score("щъэьжфхцщъ") < 0.10
    # An ASCII string has no Russian bigrams at all.
    assert russian_bigram_score("paypal") == 0.0
    print("  Russian bigram table separates words from random Cyrillic")


def test_legit_russian_domains_gain_nothing_from_the_cyrillic_rules():
    # The whole point of the RU-first product: turning the heuristics back
    # on must NOT re-flag the names the previous commit cleared.
    for d in (_EKZAMEN_PDD, _SUDI_ROSSII, _PEREMYSHL):
        score, level, reasons = calculate_score({"domain": d})
        assert level == RiskLevel.safe, f"{_decode_idn(d)} scored {score}: {[r.signal for r in reasons]}"
    print("  экзамен-пдд.рф / судьироссии.рф / перемышльский-район.рф still safe")


def test_non_cyrillic_non_ascii_names_are_still_skipped():
    # We have a language model for English and for Russian, and for nothing
    # else. A Greek, Arabic or accented-Latin name must keep skipping rather
    # than be judged by either table.
    for d in ("xn--caf-dma.com",           # café.com
              "xn--mgbh0fb.com",           # مثال.com
              "xn--hxajbheg2az3al.com"):   # παράδειγμα.com
        _score, _level, reasons = calculate_score({"domain": d})
        fired = {r.signal for r in reasons}
        assert not (fired & _NAME_SHAPE_SIGNALS), f"{d} judged by a table we do not have: {fired}"
    print("  scripts with no language model are still skipped")


def test_decode_idn_bounds_label_length():
    # A DNS label is capped at 63 characters (RFC 1035). Punycode decoding
    # is expansive, so an over-long label is not a name — it is malformed
    # input, and decoding it produced C1 control characters
    # ('xn--' + 'a' * 120 → U+0080 repeated). Keep the ASCII spelling.
    over_long = "xn--" + "a" * 120
    out = _decode_idn(over_long + ".com")
    assert out == over_long + ".com", f"over-long label was decoded: {out!r}"
    assert out.isascii(), "decoding an over-long label produced control characters"
    # A label at exactly the limit is still a legal label and still decodes.
    assert _decode_idn(_EKZAMEN_PDD) == "экзамен-пдд.рф"
    # And the scorer survives the malformed form.
    score, _level, _ = calculate_score({"domain": over_long + ".com"})
    assert 0 <= score <= 100
    print("  over-long punycode label keeps its ASCII form")


# ── The homograph defence must NOT be weakened by any of the above ──

def test_idn_punycode_homograph_still_dangerous():
    # xn--pypal-4ve.com = pаypal.com with a Cyrillic 'а'.
    score, level, reasons = calculate_score({"domain": "xn--pypal-4ve.com"})
    fired = {r.signal for r in reasons}
    assert "homograph_attack" in fired, f"homograph defence lost: {fired}"
    assert level == RiskLevel.dangerous, f"punycode homograph scored only {score}"
    print(f"  punycode homograph: score={score} level={level.value}")


def test_idn_unicode_homograph_still_dangerous():
    score, level, reasons = calculate_score({"domain": "pаypal.com"})
    assert any(r.signal == "homograph_attack" for r in reasons)
    assert level == RiskLevel.dangerous
    print(f"  unicode homograph: score={score}")


def test_idn_cyrillic_lookalike_of_top_domain_still_dangerous():
    # аpple.com with a leading Cyrillic 'а', in both wire forms.
    for d in ("аpple.com", "xn--pple-43d.com"):
        score, level, reasons = calculate_score({"domain": d})
        assert any(r.signal == "homograph_attack" for r in reasons), d
        assert level == RiskLevel.dangerous, f"{d} scored {score}"
    print("  Cyrillic lookalike of a top domain: dangerous in both forms")


def test_idn_multichar_glyph_homoglyphs_still_fire():
    # rn→m and vv→w are ASCII tricks; the IDN work must not touch them.
    for d in ("rnicrosoft-login.com", "vvhatsapp.com"):
        _, _, reasons = calculate_score({"domain": d})
        assert any(r.signal == "typosquatting" for r in reasons), d
    print("  rn→m / vv→w glyph homoglyphs intact")


# ── Regression guard: ASCII scoring is byte-identical ──
#
# Expected values captured from main @2b4f54c BEFORE the IDN change.
# These exercise every heuristic the change touches (entropy, special
# chars, n-gram, vowel ratio, consonant cluster, length, typosquatting)
# on purely ASCII names, where decoding is a no-op.

_ASCII_REGRESSION_BASELINE = {
    "paypal.com": 0,
    "google.com": 0,
    "sudden-random-xkcdvbn.ru": 17,
    "my-very-long-suspicious-domain-name-here.ru": 51,
    "this-is-a-very-long-suspicious-domain-name.com": 51,
    "qwrtpsdfgh.ru": 22,
    "ikar.ru": 25,
    "ngpedia.ru": 25,
    "etsp.ru": 25,
    "ugpr.ru": 25,
    "rnicrosoft-login.com": 40,
    "vvhatsapp.com": 25,
}


def test_ascii_domain_scores_unchanged():
    for domain, expected in _ASCII_REGRESSION_BASELINE.items():
        score, _, reasons = calculate_score({"domain": domain})
        assert score == expected, (
            f"ASCII regression on {domain}: {score} != {expected} "
            f"({[(r.signal, r.weight) for r in reasons]})"
        )
    print(f"  {len(_ASCII_REGRESSION_BASELINE)} ASCII domains unchanged")


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
        import time
        time.sleep(0.15)
        assert breaker.state == CircuitState.HALF_OPEN
        _, ok = await breaker.call(success)
        assert ok is True and breaker.state == CircuitState.CLOSED

    # Python ≥3.10: get_event_loop() raises when no running loop. asyncio.run()
    # creates+closes its own loop, which is what we want for a self-contained test.
    asyncio.run(run())
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
    # Threshold tightened to < 60s (2026-07-06): 60-300s is ordinary CDN/tracker
    # TTL (Cloudflare defaults to 300), so only genuinely low TTLs fire now.
    signals = {"domain": "suspicious.xyz", "dns_ttl": 30}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "low_dns_ttl" for r in reasons)
    print(f"  low TTL (30s): score={score}")


def test_moderate_dns_ttl_no_longer_fires():
    # 120s used to be flagged "fast-flux" (old < 300 threshold) — a false
    # positive on normal CDN infra. It must NOT fire the signal now.
    signals = {"domain": "cdn-hosted.com", "dns_ttl": 120}
    _, _, reasons = calculate_score(signals)
    assert not any(r.signal == "low_dns_ttl" for r in reasons)


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


def test_no_mx_apex_gate():
    """no_mx only fires on the registrable apex — never a subdomain (MX lives on
    the apex). Uses the PSL-aware helper so compound ccTLDs work: foo.co.uk is an
    apex and MUST fire; track.foo.com is a subdomain and MUST NOT."""
    def fires(domain):
        _, _, reasons = calculate_score({"domain": domain, "dns_has_mx": False})
        return any(r.signal == "no_mx_record" for r in reasons)

    # Apex — fire
    assert fires("nomx.com")
    assert fires("phishy-bank.co.uk"), "compound-ccTLD apex must fire (was silently dropped)"
    assert fires("loja-falsa.com.br")
    # Subdomain — suppress
    assert not fires("track.safeinflow.com")
    assert not fires("login.phishy-bank.co.uk")


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
    print("Cleanway Scoring Engine 3.0 — 30+ Signal Tests")
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
            test_typosquat_glyph_homoglyph, test_brand_subdomain_cctld_apex_safe,
            test_brand_subdomain_cctld_spoof_still_fires,
            test_combosquat_generic_word_not_dangerous, test_combosquat_classic_word_still_fires,
            test_glyph_homoglyph_with_keyword,
        ]),
        ("\n[Layer 3.6-3.12: Structural]", [
            test_fake_tld_in_subdomain, test_fake_tld_in_scoring,
            test_no_https, test_risky_tld_high, test_risky_tld_medium,
            test_risky_tld_zip_mov, test_excessive_subdomains,
            test_suspicious_keyword, test_suspicious_keyword_crypto_drainer,
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
        ("\n[IDN / punycode normalisation]", [
            test_decode_idn_returns_the_real_name, test_decode_idn_is_a_noop_for_ascii,
            test_decode_idn_never_raises_on_malformed_labels,
            test_idn_russian_domain_loses_encoding_artefact_penalties,
            test_idn_russian_government_domain_is_safe,
            test_idn_hyphen_count_uses_the_decoded_name,
            test_idn_english_heuristics_do_not_judge_cyrillic,
            test_idn_legit_non_cyrillic_idn_is_safe,
            test_idn_punycode_homograph_still_dangerous,
            test_idn_unicode_homograph_still_dangerous,
            test_idn_cyrillic_lookalike_of_top_domain_still_dangerous,
            test_idn_multichar_glyph_homoglyphs_still_fire,
            test_ascii_domain_scores_unchanged,
        ]),
        ("\n[Script-aware name shape (Cyrillic)]", [
            test_cyrillic_dga_name_is_no_longer_invisible,
            test_cyrillic_stacked_anomalies_reach_caution,
            test_cyrillic_vowel_ratio_uses_the_cyrillic_alphabet,
            test_cyrillic_soft_and_hard_signs_break_consonant_runs,
            test_russian_bigram_score_separates_words_from_mash,
            test_legit_russian_domains_gain_nothing_from_the_cyrillic_rules,
            test_non_cyrillic_non_ascii_names_are_still_skipped,
            test_decode_idn_bounds_label_length,
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

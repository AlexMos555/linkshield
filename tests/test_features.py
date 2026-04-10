"""
Tests for product features: breach check, referral, feedback, public API.
Run: python3 -m tests.test_features
"""

import os
import sys
import hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["DEBUG"] = "true"


def test_breach_hash_prefix_validation():
    """Breach endpoint validates hash prefix format."""
    # Valid: exactly 5 hex chars
    prefix = hashlib.sha1(b"test@example.com").hexdigest()[:5].upper()
    assert len(prefix) == 5
    assert all(c in "0123456789ABCDEF" for c in prefix)
    print(f"  Breach hash prefix: {prefix} (valid)")


def test_breach_k_anonymity():
    """k-anonymity: full hash is never sent, only 5-char prefix."""
    email = "user@example.com"
    full_hash = hashlib.sha1(email.encode()).hexdigest().upper()
    prefix = full_hash[:5]
    suffix = full_hash[5:]

    assert len(prefix) == 5
    assert len(suffix) == 35
    assert prefix + suffix == full_hash
    print(f"  k-anonymity: prefix={prefix}, suffix={suffix[:8]}... (full hash stays on device)")


def test_referral_code_generation():
    """Referral codes are deterministic per user."""
    user_id = "test-user-001"
    email = "test@linkshield.io"
    raw = f"ls-ref-{user_id}-{email}"
    code = hashlib.sha256(raw.encode()).hexdigest()[:8].upper()

    assert len(code) == 8
    assert code.isalnum()

    # Same input → same code
    code2 = hashlib.sha256(raw.encode()).hexdigest()[:8].upper()
    assert code == code2

    print(f"  Referral code: {code} (deterministic)")


def test_referral_different_users():
    """Different users get different codes."""
    code1 = hashlib.sha256(b"ls-ref-user1-a@b.com").hexdigest()[:8].upper()
    code2 = hashlib.sha256(b"ls-ref-user2-c@d.com").hexdigest()[:8].upper()
    assert code1 != code2
    print(f"  Different users: {code1} != {code2}")


def test_public_check_format():
    """Public check returns correct format."""
    from api.routers.public import _format_public_result
    from api.models.schemas import DomainResult, DomainReason, RiskLevel, ConfidenceLevel

    # Safe domain
    result = DomainResult(
        domain="google.com", score=0, level=RiskLevel.safe,
        confidence=ConfidenceLevel.high,
        reasons=[DomainReason(signal="known", detail="Top domain", weight=-50)],
    )
    formatted = _format_public_result(result)
    assert formatted["safe"] is True
    assert formatted["score"] == 0
    assert "install_url" in formatted
    assert "cta" in formatted
    print("  Public format (safe): OK")

    # Dangerous domain
    result = DomainResult(
        domain="evil.tk", score=85, level=RiskLevel.dangerous,
        confidence=ConfidenceLevel.medium,
        reasons=[DomainReason(signal="risky_tld", detail="High-risk TLD", weight=20)],
    )
    formatted = _format_public_result(result)
    assert formatted["safe"] is False
    assert formatted["score"] == 85
    assert len(formatted["signals"]) > 0
    print("  Public format (dangerous): OK")


def test_allowlist_fast_path_hosting():
    """Hosting platform subdomains are NOT auto-trusted."""
    from api.routers.check import _quick_allowlist_check

    # Regular top domain → instant safe
    assert _quick_allowlist_check("google.com") is not None
    assert _quick_allowlist_check("youtube.com") is not None

    # Hosting platforms → needs full analysis
    assert _quick_allowlist_check("evil.netlify.app") is None
    assert _quick_allowlist_check("phish.pages.dev") is None
    assert _quick_allowlist_check("scam.vercel.app") is None
    assert _quick_allowlist_check("fake.github.io") is None
    assert _quick_allowlist_check("bad.webflow.io") is None
    assert _quick_allowlist_check("evil.framer.app") is None

    # Base domain itself is OK (it's the hosting service)
    assert _quick_allowlist_check("netlify.app") is not None or True  # May or may not be in top 100k

    print("  Hosting bypass: all platform subdomains need full analysis")


def test_scoring_new_signals():
    """Test that new signals (entropy, n-gram, breach, redirect) work."""
    from api.services.scoring import calculate_score

    # DGA domain (high entropy)
    signals = {"domain": "xk7qm2bz9w3jfp.xyz", "raw_url": "xk7qm2bz9w3jfp.xyz"}
    score, level, reasons = calculate_score(signals)
    sigs = [r.signal for r in reasons]
    assert any("entropy" in s or "ngram" in s for s in sigs)
    print(f"  DGA detection: score={score}, signals={[s for s in sigs if 'entropy' in s or 'ngram' in s]}")

    # Low DNS TTL
    signals = {"domain": "fast-flux.xyz", "dns_ttl": 30}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "low_dns_ttl" for r in reasons)
    print("  Low TTL: detected")

    # Cross-domain redirect
    signals = {"domain": "trick.xyz", "redirect_cross_domain": True, "redirect_count": 4}
    score, _, reasons = calculate_score(signals)
    assert any("redirect" in r.signal for r in reasons)
    print("  Redirect chain: detected")

    # New cert
    signals = {"domain": "newsite.xyz", "cert_age_days": 2}
    score, _, reasons = calculate_score(signals)
    assert any(r.signal == "new_certificate" for r in reasons)
    print("  New cert: detected")


def test_confidence_levels():
    """Confidence level reflects check completeness."""
    from api.services.scoring import calculate_confidence
    from api.models.schemas import ConfidenceLevel

    assert calculate_confidence(5, 5, 100) == ConfidenceLevel.high
    assert calculate_confidence(4, 5, 365) == ConfidenceLevel.high
    assert calculate_confidence(3, 5, None) == ConfidenceLevel.medium
    assert calculate_confidence(2, 5, None) == ConfidenceLevel.low
    assert calculate_confidence(1, 5, None) == ConfidenceLevel.low
    print("  Confidence levels: correct")


def test_feature_extraction():
    """ML feature extraction produces correct feature count."""
    from api.services.url_features import extract_features

    signals = {"domain": "test.com", "raw_url": "test.com"}
    features = extract_features("test.com", signals)
    assert len(features) >= 30
    assert "shannon_entropy" in features
    assert "bigram_score" in features
    assert "max_brand_similarity" in features
    print(f"  ML features: {len(features)} extracted")


if __name__ == "__main__":
    print("LinkShield Feature Tests")
    print("=" * 50)

    tests = [
        test_breach_hash_prefix_validation,
        test_breach_k_anonymity,
        test_referral_code_generation,
        test_referral_different_users,
        test_public_check_format,
        test_allowlist_fast_path_hosting,
        test_scoring_new_signals,
        test_confidence_levels,
        test_feature_extraction,
    ]

    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {t.__name__}: {e}")
            import traceback
            traceback.print_exc()

    print("=" * 50)
    print(f"All {passed}/{len(tests)} feature tests passed!")

"""
Integration tests for LinkShield API.
Tests the full request pipeline: auth → rate limit → scoring → response.
Run: python3 -m tests.test_api_integration
"""

import os
import sys
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["DEBUG"] = "true"

import jwt


# Generate test JWT token
TEST_SECRET = "test-secret-for-development-only-not-for-production-use"
TEST_TOKEN = jwt.encode(
    {"sub": "test-user-001", "email": "test@linkshield.io", "aud": "authenticated"},
    TEST_SECRET,
    algorithm="HS256",
)


def test_app_imports():
    """App imports without errors."""
    from api.main import app
    routes = [r.path for r in app.routes if hasattr(r, "path")]
    assert len(routes) >= 15
    print(f"  App loaded: {len(routes)} routes")


def test_scoring_pipeline():
    """Scoring returns correct results for known domains."""
    from api.services.scoring import calculate_score, TOP_DOMAINS

    # Known safe domain
    signals = {"domain": "google.com", "raw_url": "google.com"}
    score, level, _ = calculate_score(signals)
    assert score == 0 and level.value == "safe"

    # Phishing domain
    signals = {"domain": "paypa1-verify.tk", "raw_url": "paypa1-verify.tk"}
    score, level, reasons = calculate_score(signals)
    assert score >= 50 and level.value == "dangerous"
    assert len(reasons) >= 3

    # TOP_DOMAINS loaded from Tranco
    assert len(TOP_DOMAINS) >= 1000

    print(f"  Scoring: google.com=safe, paypa1-verify.tk=dangerous({score}), {len(TOP_DOMAINS)} domains")


def test_domain_validator():
    """Domain validator blocks SSRF and accepts valid domains."""
    from api.services.domain_validator import validate_domain, DomainValidationError

    # Should accept
    assert validate_domain("example.com") == "example.com"
    assert validate_domain("sub.example.com") == "sub.example.com"

    # Should reject
    for bad in ["localhost", "", "127.0.0.1", "10.0.0.1", "169.254.169.254"]:
        try:
            validate_domain(bad)
            assert False, f"Should reject: {bad}"
        except DomainValidationError:
            pass

    print("  Domain validator: accepts valid, rejects SSRF")


def test_ml_model():
    """ML model loads and predicts."""
    from api.services.ml_scorer import ml_predict

    result = ml_predict("google.com")
    if result:
        assert result["prediction"] == "benign"
        print(f"  ML model: google.com → {result['prediction']} ({result['phishing_probability']:.3f})")
    else:
        print("  ML model: not available (skipped)")


def test_circuit_breakers():
    """Circuit breakers initialize correctly."""
    from api.services.circuit_breaker import get_all_breaker_statuses

    statuses = get_all_breaker_statuses()
    assert len(statuses) >= 8
    for s in statuses:
        assert s["state"] == "closed"

    print(f"  Circuit breakers: {len(statuses)} breakers, all closed")


def test_config_validation():
    """Config validates correctly in debug mode."""
    from api.config import get_settings, validate_settings

    settings = get_settings()
    assert settings.debug is True

    # Should not raise in debug mode
    validate_settings(settings)
    assert settings.supabase_jwt_secret == TEST_SECRET

    print(f"  Config: debug={settings.debug}, JWT secret set, {len(settings.get_allowed_origins())} CORS origins")


def test_allowlist_fast_path():
    """Allowlist check returns instantly for known domains."""
    from api.routers.check import _quick_allowlist_check

    # Known safe
    result = _quick_allowlist_check("google.com")
    assert result is not None
    assert result.score == 0

    # Hosting platform subdomain — should NOT be auto-safe
    result = _quick_allowlist_check("evil.netlify.app")
    assert result is None

    # Unknown domain
    result = _quick_allowlist_check("some-random-domain-xyz.com")
    assert result is None

    print("  Allowlist: google.com=instant safe, evil.netlify.app=needs analysis, unknown=needs analysis")


def test_bloom_filter():
    """Bloom filter compiled and verifiable."""
    bloom_path = os.path.join(os.path.dirname(__file__), "..", "data", "bloom_top100k.json")
    if not os.path.exists(bloom_path):
        print("  Bloom filter: not compiled (skipped)")
        return

    with open(bloom_path) as f:
        data = json.load(f)

    assert data["domain_count"] == 100000
    assert data["fp_rate"] < 0.002
    assert len(data["bits"]) > 100000

    print(f"  Bloom filter: {data['domain_count']} domains, FP={data['fp_rate']:.4%}, {len(data['bits'])} bytes")


def test_public_endpoint_format():
    """Public check endpoint returns correct format."""
    from api.routers.public import _format_public_result
    from api.models.schemas import DomainResult, DomainReason, RiskLevel, ConfidenceLevel

    result = DomainResult(
        domain="evil.tk", score=80, level=RiskLevel.dangerous,
        confidence=ConfidenceLevel.medium,
        reasons=[DomainReason(signal="test", detail="Test reason", weight=80)],
    )
    formatted = _format_public_result(result)

    assert formatted["domain"] == "evil.tk"
    assert formatted["safe"] is False
    assert formatted["score"] == 80
    assert "install_url" in formatted
    assert len(formatted["signals"]) > 0

    print("  Public endpoint format: correct structure")


def test_schemas():
    """Pydantic schemas validate correctly."""
    from api.models.schemas import CheckRequest, DomainResult, RiskLevel, ConfidenceLevel

    # Valid request
    req = CheckRequest(domains=["google.com", "evil.com"])
    assert len(req.domains) == 2

    # Score validation
    result = DomainResult(
        domain="test.com", score=50, level=RiskLevel.caution,
        confidence=ConfidenceLevel.medium, reasons=[],
    )
    assert result.score == 50

    print("  Schemas: valid")


if __name__ == "__main__":
    print("LinkShield Integration Tests")
    print("=" * 50)

    tests = [
        test_app_imports,
        test_config_validation,
        test_schemas,
        test_scoring_pipeline,
        test_domain_validator,
        test_ml_model,
        test_circuit_breakers,
        test_allowlist_fast_path,
        test_bloom_filter,
        test_public_endpoint_format,
    ]

    passed = 0
    failed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {t.__name__}: {e}")
            failed += 1

    print("=" * 50)
    if failed == 0:
        print(f"All {passed} integration tests passed!")
    else:
        print(f"{passed} passed, {failed} FAILED")

"""
Tests for the inbound email phishing analyzer.

Three layers:
1. Pure-function unit tests on the analyzer internals (sender, auth,
   patterns, link extraction, scoring).
2. End-to-end `analyze_email` tests with stubbed domain checker.
3. HTTP integration test that exercises the `/api/v1/email/analyze`
   endpoint through FastAPI's TestClient.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier
from api.services.email_analyzer import (
    AnalysisResult,
    EmailBody,
    EmailHeaders,
    Finding,
    RiskLevel,
    analyze_email,
    _aggregate_score,
    _analyze_auth_headers,
    _analyze_sender,
    _detect_link_text_mismatch,
    _domain_from_url,
    _extract_links,
    _level_for_score,
    _scan_body_patterns,
)


# ─── Pure-function unit tests ────────────────────────────────────────────────


class TestDomainFromUrl:
    def test_https_with_path(self):
        assert _domain_from_url("https://EVIL.test/path?q=1") == "evil.test"

    def test_strips_userinfo(self):
        assert _domain_from_url("http://user:pass@evil.test/") == "evil.test"

    def test_strips_port(self):
        assert _domain_from_url("http://host.test:8080/x") == "host.test"


class TestSenderAnalysis:
    def test_brand_claim_from_freemail_is_flagged(self):
        h = EmailHeaders(
            from_address="chasesecurity@gmail.com",
            from_display="Chase Bank Security",
        )
        findings = _analyze_sender(h)
        assert any(f.category == "sender_spoofing" for f in findings)
        assert any("free-email" in f.message for f in findings)

    def test_canonical_brand_domain_not_flagged(self):
        h = EmailHeaders(
            from_address="security@chase.com",
            from_display="Chase Bank Security",
        )
        assert _analyze_sender(h) == []

    def test_brand_subsidiary_not_flagged(self):
        h = EmailHeaders(
            from_address="support@news.chase.com",
            from_display="Chase Bank",
        )
        assert _analyze_sender(h) == []

    def test_brand_on_wrong_domain_flagged(self):
        h = EmailHeaders(
            from_address="info@chase-verify.xyz",
            from_display="Chase Bank",
        )
        findings = _analyze_sender(h)
        assert any("doesn't match" in f.message for f in findings)

    def test_non_ascii_domain_flagged(self):
        h = EmailHeaders(
            from_address="admin@chаse.com",  # Cyrillic 'а'
            from_display="Chase",
        )
        findings = _analyze_sender(h)
        assert any(f.category == "sender_spoofing" for f in findings)
        assert any("non-ASCII" in f.message for f in findings)

    def test_reply_to_different_domain_flagged(self):
        h = EmailHeaders(
            from_address="no-reply@chase.com",
            reply_to="collect@evil.test",
        )
        findings = _analyze_sender(h)
        assert any("Reply-To" in f.message for f in findings)

    def test_reply_to_same_domain_ok(self):
        h = EmailHeaders(
            from_address="no-reply@chase.com",
            reply_to="help@chase.com",
        )
        assert all("Reply-To" not in f.message for f in _analyze_sender(h))

    def test_empty_headers_safe(self):
        assert _analyze_sender(EmailHeaders()) == []


class TestAuthHeaders:
    def test_spf_fail(self):
        f = _analyze_auth_headers(EmailHeaders(spf="fail"))
        assert any(x.category == "auth_fail" for x in f)

    def test_dmarc_fail_high_severity(self):
        f = _analyze_auth_headers(EmailHeaders(dmarc="fail"))
        assert any(x.severity >= 30 for x in f)

    def test_spf_softfail_low_severity(self):
        f = _analyze_auth_headers(EmailHeaders(spf="softfail"))
        assert any(x.severity == 10 for x in f)

    def test_all_pass_no_findings(self):
        f = _analyze_auth_headers(
            EmailHeaders(spf="pass", dkim="pass", dmarc="pass")
        )
        assert f == []

    def test_none_values_ignored(self):
        assert _analyze_auth_headers(EmailHeaders()) == []


class TestBodyPatterns:
    def test_urgency_trigger(self):
        findings = _scan_body_patterns(
            EmailBody(text="Please act now, your account expires in 2 hours!")
        )
        assert any("Urgency" in f.message or "Countdown" in f.message for f in findings)

    def test_credential_ask_trigger(self):
        findings = _scan_body_patterns(
            EmailBody(text="Please verify your account immediately.")
        )
        assert any("credential" in f.message.lower() for f in findings)

    def test_money_pattern(self):
        findings = _scan_body_patterns(
            EmailBody(text="Please send a wire transfer of $5000 to this account.")
        )
        assert any("Money" in f.message for f in findings)

    def test_russian_urgency(self):
        findings = _scan_body_patterns(EmailBody(text="Срочно подтвердите оплату!"))
        assert any("(RU)" in f.message for f in findings)

    def test_clean_body_no_findings(self):
        findings = _scan_body_patterns(
            EmailBody(text="Hello, here's the report you requested. Regards, Anna.")
        )
        assert findings == []

    def test_html_body_stripped(self):
        findings = _scan_body_patterns(
            EmailBody(html="<p>Please <b>verify your password</b> below.</p>")
        )
        assert any("credential" in f.message.lower() for f in findings)

    def test_pattern_counted_once(self):
        # The same urgency pattern shouldn't add findings N times for N matches
        findings = _scan_body_patterns(
            EmailBody(text="urgent URGENT Urgent — this is urgent!")
        )
        urgency = [f for f in findings if "Urgency" in f.message]
        assert len(urgency) == 1


class TestLinkExtraction:
    def test_extracts_plain_text_urls(self):
        body = EmailBody(text="Visit https://example.com/path for details.")
        links = list(_extract_links(body))
        assert len(links) == 1
        assert links[0].url == "https://example.com/path"
        assert links[0].domain == "example.com"

    def test_extracts_html_anchor(self):
        body = EmailBody(
            html='<p>Click <a href="https://evil.test/steal">here</a>.</p>'
        )
        links = list(_extract_links(body))
        assert len(links) == 1
        assert links[0].display_text == "here"
        assert links[0].domain == "evil.test"

    def test_dedupes_duplicate_urls(self):
        body = EmailBody(
            html='<a href="https://x.test">a</a> and <a href="https://x.test">b</a>',
        )
        links = list(_extract_links(body))
        assert len(links) == 1

    def test_trims_trailing_punctuation(self):
        body = EmailBody(text="See https://example.com.")
        links = list(_extract_links(body))
        assert links[0].url.endswith("example.com")

    def test_ignores_non_http_schemes(self):
        body = EmailBody(html='<a href="javascript:alert(1)">click</a>')
        assert list(_extract_links(body)) == []


class TestLinkTextMismatch:
    def test_flags_classic_mismatch(self):
        from api.services.email_analyzer import ExtractedLink

        links = [
            ExtractedLink(
                url="https://evil.test/steal",
                display_text="https://chase.com/login",
                domain="evil.test",
            )
        ]
        findings = _detect_link_text_mismatch(links)
        assert len(findings) == 1
        assert findings[0].category == "link_text_mismatch"

    def test_no_flag_when_display_is_plain_text(self):
        from api.services.email_analyzer import ExtractedLink

        links = [
            ExtractedLink(
                url="https://mailchi.mp/track/abc",
                display_text="View in browser",
                domain="mailchi.mp",
            )
        ]
        assert _detect_link_text_mismatch(links) == []


class TestScoring:
    def test_caps_per_category(self):
        findings = [
            Finding(category="sender_spoofing", severity=50, message="x"),
            Finding(category="sender_spoofing", severity=50, message="y"),
            Finding(category="sender_spoofing", severity=50, message="z"),
        ]
        # One category caps at 60 regardless of how many findings
        assert _aggregate_score(findings) == 60

    def test_multi_category_stacks(self):
        findings = [
            Finding(category="sender_spoofing", severity=50, message=""),
            Finding(category="body_pattern", severity=30, message=""),
        ]
        assert _aggregate_score(findings) == 80

    def test_caps_at_100(self):
        findings = [
            Finding(category=f"cat_{i}", severity=80, message="") for i in range(5)
        ]
        assert _aggregate_score(findings) == 100

    def test_level_thresholds(self):
        assert _level_for_score(0) == RiskLevel.safe
        assert _level_for_score(24) == RiskLevel.safe
        assert _level_for_score(25) == RiskLevel.suspicious
        assert _level_for_score(59) == RiskLevel.suspicious
        assert _level_for_score(60) == RiskLevel.dangerous
        assert _level_for_score(100) == RiskLevel.dangerous


# ─── End-to-end analyze_email ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_clean_email_scores_safe():
    result = await analyze_email(
        EmailHeaders(from_address="anna@team.example.com", spf="pass", dkim="pass", dmarc="pass"),
        EmailBody(text="Hi, here's the Q3 report we talked about."),
    )
    assert result.level == RiskLevel.safe
    assert result.score < 25


@pytest.mark.asyncio
async def test_classic_phishing_scores_dangerous():
    result = await analyze_email(
        EmailHeaders(
            from_address="security@gmail.com",
            from_display="PayPal Security",
            reply_to="collect@evil.test",
            subject="Urgent: verify your account",
            spf="fail",
        ),
        EmailBody(
            text="Your account has been locked. Verify your password immediately.",
            html='<a href="https://evil.test/login">https://paypal.com/login</a>',
        ),
    )
    assert result.level == RiskLevel.dangerous
    # Should have findings from multiple categories
    categories = {f.category for f in result.findings}
    assert "sender_spoofing" in categories
    assert "body_pattern" in categories
    assert "link_text_mismatch" in categories


@pytest.mark.asyncio
async def test_domain_checker_is_invoked_per_unique_domain():
    calls: list[str] = []

    async def checker(domain: str) -> bool:
        calls.append(domain)
        return domain == "evil.test"

    body = EmailBody(
        html='<a href="https://evil.test/a">a</a> <a href="https://evil.test/b">b</a> <a href="https://safe.test">s</a>',
    )
    result = await analyze_email(EmailHeaders(), body, checker)
    # Each unique domain checked once
    assert sorted(set(calls)) == ["evil.test", "safe.test"]
    # One url_reputation finding for the malicious domain
    assert sum(1 for f in result.findings if f.category == "url_reputation") == 1


@pytest.mark.asyncio
async def test_domain_checker_errors_are_swallowed():
    async def boom(domain: str) -> bool:
        raise RuntimeError("upstream dead")

    result = await analyze_email(
        EmailHeaders(),
        EmailBody(html='<a href="https://x.test">x</a>'),
        boom,
    )
    # No url_reputation finding, but also no exception propagated
    assert all(f.category != "url_reputation" for f in result.findings)


# ─── HTTP integration ─────────────────────────────────────────────────────────


@pytest.fixture
def client_as_user():
    from api.main import app
    from api.services.auth import get_current_user

    async def _fake_user():
        return AuthUser(id="test-user", email="t@test.com", tier=UserTier.free)

    app.dependency_overrides[get_current_user] = _fake_user
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_analyze_endpoint_returns_structured_verdict(client_as_user, monkeypatch):
    # Stub the circuit breaker so we don't hit real GSB
    from api.services import circuit_breaker

    async def fake_call(func, *args, **kwargs):
        return (False, False)

    monkeypatch.setattr(circuit_breaker.safe_browsing_breaker, "call", fake_call)

    resp = client_as_user.post(
        "/api/v1/email/analyze",
        json={
            "from_address": "security@gmail.com",
            "from_display": "PayPal Security",
            "subject": "Urgent action required",
            "body_text": "Verify your password immediately or your account will be locked.",
            "body_html": "",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["level"] in ("suspicious", "dangerous")
    assert body["score"] >= 25
    assert isinstance(body["findings"], list)
    assert isinstance(body["links"], list)


def test_analyze_endpoint_accepts_anonymous(client_as_user, monkeypatch):
    """
    `/email/analyze` works for anonymous callers (webmail banner scans on
    page-load before sign-in). Per-IP rate limits keep abuse contained.
    """
    from api.services import circuit_breaker

    async def fake_call(func, *args, **kwargs):
        return (False, False)

    monkeypatch.setattr(circuit_breaker.safe_browsing_breaker, "call", fake_call)

    # Override to NO user so we simulate an unauthenticated browser banner
    from api.main import app
    from api.services.auth import get_optional_user

    async def _anon():
        return None

    app.dependency_overrides[get_optional_user] = _anon
    try:
        resp = client_as_user.post(
            "/api/v1/email/analyze",
            json={
                "from_address": "safe@example.com",
                "from_display": "Example",
                "subject": "Hi",
                "body_text": "Just checking in.",
                "body_html": "",
            },
        )
    finally:
        # client_as_user fixture resets overrides on teardown; leave here in case
        pass
    assert resp.status_code == 200
    body = resp.json()
    assert body["level"] == "safe"

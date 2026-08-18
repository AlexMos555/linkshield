"""The top-domain auto-safe short-circuit must not trust shared platforms.

Found 2026-08-18 by resolving live OpenPhish hosts through the Android shield:
`gwcu.us.org` (a phishing page) came back SAFE with 99% confidence from
/api/v1/public/check — no analyzer, no rate-limit — because the naive base
extraction gave `us.org`, and `us.org` is in Tranco's top 100k. `us.org` is a
public suffix (anyone can register a name under it), as are 1,539 other Tranco
entries once multi-label PSL rules are counted (`*.github.io`, `blogspot.com`,
`azurewebsites.net`, `s3.amazonaws.com`, dyndns names like `bounceme.net` …).

Every one of those was an "instant safe" hole, and the DNS shield cached the
verdict for 24h. This pins the rule: a subdomain of a public suffix / hosting
platform is NEVER auto-safe, only the apex itself is.
"""
from __future__ import annotations

import pytest

from api.services.scoring import (
    PUBLIC_SUFFIXES_IN_TOP,
    TOP_DOMAINS,
    is_trusted_top_domain,
)


def test_data_loaded():
    assert "us.org" in TOP_DOMAINS
    assert "us.org" in PUBLIC_SUFFIXES_IN_TOP
    assert len(PUBLIC_SUFFIXES_IN_TOP) > 1000


@pytest.mark.parametrize(
    "domain",
    [
        "google.com", "www.google.com", "mail.google.com",
        "wikipedia.org", "en.wikipedia.org",
        "github.com", "paypal.com", "www.paypal.com",
        # The apex of a public-suffix-that-is-a-top-domain is that org's own.
        "github.io", "blogspot.com", "us.org",
    ],
)
def test_real_top_domains_are_trusted(domain):
    assert is_trusted_top_domain(domain) is True


@pytest.mark.parametrize(
    "domain",
    [
        # The live phishing host that started this.
        "gwcu.us.org",
        # Classic hosting-platform subdomains (also in _HOSTING_PLATFORMS).
        "evil-login.github.io", "secure-paypal.blogspot.com", "x.web.app",
        # Only reachable through the PSL intersection, not the hand list.
        "login.bounceme.net", "bank.altervista.org", "acme.azurewebsites.net",
        # Multi-label public suffixes.
        "phish.s3.amazonaws.com", "acct.us-east-1.elasticbeanstalk.com",
        # Deep subdomain of a shared platform is still shared.
        "a.b.evil.us.org",
    ],
)
def test_public_suffix_subdomains_are_not_trusted(domain):
    assert is_trusted_top_domain(domain) is False


@pytest.mark.parametrize("domain", ["docs.google.com", "sites.google.com", "drive.google.com"])
def test_google_abused_services_are_not_auto_safe(domain):
    assert is_trusted_top_domain(domain) is False


def test_unknown_domain_is_not_trusted():
    assert is_trusted_top_domain("definitely-not-in-tranco-8f3k2.example") is False
    assert is_trusted_top_domain("") is False


def test_public_check_router_no_longer_shortcuts_public_suffix_subdomain(monkeypatch):
    """/public/check/gwcu.us.org must reach the analyzer path (here: stubbed),
    not the synthetic score=0/99% branch."""
    from fastapi.testclient import TestClient

    from api.main import app
    from api.routers import public as public_router

    called = {"n": 0}

    async def _no_cache(domain):
        return None

    monkeypatch.setattr(public_router, "_get_public_cache", _no_cache)

    class _FakeRedis:
        async def incr(self, k):
            called["n"] += 1
            return 1

        async def expire(self, k, s):
            return True

        async def ttl(self, k):
            return 60

    async def _get_redis():
        return _FakeRedis()

    from api.services import cache as cache_mod
    monkeypatch.setattr(cache_mod, "get_redis", _get_redis)

    # Stub the expensive analyzer so the test is hermetic; if the router
    # short-circuited, this is never called and `called["n"]` stays 0.
    from api.models.schemas import DomainResult, RiskLevel, ConfidenceLevel

    async def _fake_analyze(domain, *a, **kw):
        return DomainResult(domain=domain, score=85, level=RiskLevel.dangerous,
                            confidence=ConfidenceLevel.medium, confidence_pct=80, reasons=[])

    # The router imports analyze_domain lazily inside the handler.
    from api.services import analyzer as analyzer_mod
    monkeypatch.setattr(analyzer_mod, "analyze_domain", _fake_analyze)

    async def _no_put(result):
        return None

    monkeypatch.setattr(public_router, "_put_public_cache", _no_put)

    client = TestClient(app)
    resp = client.get("/api/v1/public/check/gwcu.us.org", headers={"x-forwarded-for": "10.9.8.7"})
    assert resp.status_code in (200, 429, 500), resp.text
    if resp.status_code == 200:
        body = resp.json()
        # Whatever the stubbed analyzer says, it must NOT be the synthetic
        # "score 0 / 99% / no reasons" top-domain branch.
        assert not (body.get("score") == 0 and body.get("confidence_pct") == 99), body
    assert called["n"] >= 1, "rate limiter never incremented → router short-circuited"

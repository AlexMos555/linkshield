"""Only a listing of THIS host is blocking evidence (review 2026-09-27).

`verdict_basis: threat_intel` lets the phone block a site. Two sources could
reach it without listing the host at all:

  * PhishStats is searched by URL SUBSTRING, so any listed phishing URL that
    merely contained the name — https://bankspb.ru.secure-login.xyz/,
    evil.com/?r=bankspb.ru, anything under mybankspb.ru — was a "hit": +65,
    'dangerous', basis threat_intel for the real bank. Brand impersonation
    produces exactly such URLs.
  * IPQualityScore's `phishing` flag is the vendor's own scoring of the host,
    like its risk score (already excluded) — judgement, not a listing.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from api.models.schemas import DomainReason, DomainResult, RiskLevel
from api.services import analyzer
from api.services import verdict_basis as vb


def _phishstats_rows(monkeypatch, rows):
    seen = []

    def _handler(request):
        seen.append(str(request.url))
        return httpx.Response(200, json=rows)

    real = httpx.AsyncClient
    monkeypatch.setattr(
        analyzer.httpx, "AsyncClient",
        lambda *a, **k: real(*a, transport=httpx.MockTransport(_handler), **k),
    )
    return seen


@pytest.mark.parametrize("url", [
    "https://bankspb.ru.secure-login.xyz/",         # the name as a subdomain label
    "http://evil.com/?r=bankspb.ru",                # the name in the query
    "https://mybankspb.ru/login",                   # a longer name that contains it
    "https://login.bankspb.ru.evil.top/verify",
])
def test_phishstats_substring_matches_are_not_hits(monkeypatch, url):
    _phishstats_rows(monkeypatch, [{"url": url}])
    assert asyncio.run(analyzer.check_phishstats("bankspb.ru")) is False


@pytest.mark.parametrize("url", [
    "https://bankspb.ru/secure/login",
    "http://www.bankspb.ru/",
    "bankspb.ru/verify",                            # listed without a scheme
])
def test_phishstats_listing_of_the_host_itself_is_a_hit(monkeypatch, url):
    _phishstats_rows(monkeypatch, [{"url": "https://bankspb.ru.evil.xyz/"}, {"url": url}])
    assert asyncio.run(analyzer.check_phishstats("bankspb.ru")) is True


def test_phishstats_compares_idn_hosts_in_wire_form(monkeypatch):
    _phishstats_rows(monkeypatch, [{"url": "https://госуслуги-вход.рф/lk"}])
    assert asyncio.run(analyzer.check_phishstats("xn----dtbbahvtxfyaxc6a.xn--p1ai")) is True


def test_phishstats_asks_for_a_page_of_candidates(monkeypatch):
    seen = _phishstats_rows(monkeypatch, [])
    asyncio.run(analyzer.check_phishstats("bankspb.ru"))
    assert "_size=1&" not in seen[0] and seen[0].endswith("_size=20")


@pytest.mark.parametrize("rows", ["not a list", {"error": "x"}, [None, 3, {"url": 7}]])
def test_phishstats_odd_answers_are_no_hit(monkeypatch, rows):
    _phishstats_rows(monkeypatch, rows)
    assert asyncio.run(analyzer.check_phishstats("bankspb.ru")) is False


def test_ipqs_phishing_flag_is_not_blocking_evidence():
    result = DomainResult(
        domain="bankspb.ru", score=70, level=RiskLevel.dangerous,
        reasons=[DomainReason(signal="ipqs_phishing", detail="x", weight=70)],
    )
    assert vb.derive_verdict_basis(result) not in vb.BLOCKING_BASES
    assert "ipqs_phishing" not in vb.THREAT_INTEL_REASONS


def test_ipqs_flag_alone_never_makes_a_blocking_verdict(offline_analyzer):
    offline_analyzer(site="reachable", values={"ipqs": {"phishing": True, "hit": True, "risk_score": 90}})
    result = asyncio.run(analyzer.analyze_domain("bankspb.ru", budget_s=5.0))
    assert "ipqs_phishing" in {r.signal for r in result.reasons}
    assert result.verdict_basis not in vb.BLOCKING_BASES


def test_a_real_listing_still_is(offline_analyzer):
    offline_analyzer(site="reachable", hits={"phishstats": True})
    result = asyncio.run(analyzer.analyze_domain("bankspb-login.ru", budget_s=5.0))
    assert result.level == RiskLevel.dangerous
    assert result.verdict_basis == "threat_intel"

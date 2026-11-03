"""An IP address is a caution, not a verdict (production, 2026-11-03).

Every bare IP host was 'dangerous': 8.8.8.8 and 1.1.1.1 scored 100 and
GitHub's 140.82.112.4 scored 85 on three reasons — ip_based (+35),
excessive_subdomains ("2 levels above 112.4": the dots of an address,
+15) and ml_high_risk (+35: the model reads 97-99% on any address). On
8.8.8.8 a redirect to dns.google added cross_domain_redirect (+20).

An IP literal is still a real warning sign, so it stays a caution with
that honest reason. 'dangerous' needs evidence about the address: a list
or reputation hit (Safe Browsing, the feeds, IPQS, OTX) or what the page
showed (a brand's favicon). Private and reserved ranges keep their SSRF
answer.
"""
from __future__ import annotations

import asyncio

import pytest

from api.models.schemas import RiskLevel
from api.services.analyzer import analyze_domain, rule_only_result
from api.services.scoring import calculate_score

# A public resolver each, GitHub's web front, a URLhaus Mozi node (benchmark
# 2026-10-04), Google's resolver over IPv6.
PUBLIC_IPS = ["8.8.8.8", "1.1.1.1", "140.82.112.4", "103.249.199.5", "2001:4860:4860::8888"]
# What an address cannot have: subdomains, a name for the model to read.
NOT_ABOUT_AN_ADDRESS = {"excessive_subdomains", "ml_high_risk", "ml_suspicious", "ml_safe_override"}


def _codes(reasons) -> set[str]:
    return {r.signal for r in reasons}


def _ip_signals(host: str, **extra) -> dict:
    """What the analyzer hands the scorer for a bare IP host."""
    return {"domain": host, "raw_url": host, "is_ip_based": True, **extra}


# ── On its name alone ──

@pytest.mark.parametrize("host", PUBLIC_IPS)
def test_an_address_alone_is_a_caution_with_its_reason(host):
    score, level, reasons = calculate_score(_ip_signals(host))
    assert level == RiskLevel.caution, (host, score, [(r.signal, r.weight) for r in reasons])
    ip = [r for r in reasons if r.signal == "ip_based"]
    assert ip and ip[0].detail == "Uses IP address instead of domain name"
    assert not _codes(reasons) & NOT_ABOUT_AN_ADDRESS


@pytest.mark.parametrize("host", PUBLIC_IPS)
def test_the_rule_only_fallback_still_says_it_is_an_address(host):
    """The verdict a router gives when the analysis failed: no is_ip_based
    flag there, the address itself says so."""
    result = rule_only_result(host, raw_url=host)
    assert result.level == RiskLevel.caution
    assert "ip_based" in _codes(result.reasons)
    assert not _codes(result.reasons) & NOT_ABOUT_AN_ADDRESS


def test_ipv6_groups_are_not_a_port():
    """'2001:4860:4860::8888' read as port 4860."""
    for raw in ("2001:4860:4860::8888", "https://[2001:4860:4860::8888]/"):
        _, _, reasons = calculate_score(_ip_signals("2001:4860:4860::8888", raw_url=raw))
        assert "non_standard_port" not in _codes(reasons), raw


# ── What the probes see on an address is not evidence either ──

@pytest.mark.parametrize("probes", [
    # 8.8.8.8 and 1.1.1.1 on 2026-11-03: a redirect to dns.google / one.one.one.one
    {"redirect_count": 1, "redirect_cross_domain": True},
    {"redirect_count": 1, "redirect_cross_domain": True,
     "missing_security_headers": ["content-security-policy", "x-frame-options", "referrer-policy"]},
    # a router, a NAS, a camera: plain HTTP, or a certificate of its own
    {"no_https": True},
    {"certificate_problem": "self_signed"},
    {"certificate_problem": "expired", "missing_security_headers": ["a", "b", "c"]},
])
def test_what_the_probes_see_on_an_address_stays_a_caution(probes):
    score, level, reasons = calculate_score(_ip_signals("8.8.8.8", **probes))
    assert level == RiskLevel.caution, (score, [(r.signal, r.weight) for r in reasons])
    assert score <= 50


def test_a_port_on_an_address_stays_a_caution():
    """URLhaus's Mozi URLs: http://<ip>:<high port>/i — the shape of a
    botnet node, and of a camera or a Plex server."""
    score, level, reasons = calculate_score(
        _ip_signals("103.249.199.5", raw_url="http://103.249.199.5:35908/i", no_https=True))
    assert {"ip_based", "non_standard_port", "no_https"} <= _codes(reasons)
    assert level == RiskLevel.caution, score


# ── Evidence still makes it dangerous ──

@pytest.mark.parametrize("evidence, code", [
    ({"safe_browsing_hit": True, "blocklist_hits": 1}, "safe_browsing"),
    ({"phishstats_hit": True, "blocklist_hits": 1}, "phishstats"),
    ({"urlhaus_hit": True, "blocklist_hits": 1}, "urlhaus"),
    ({"feodo_hit": True, "blocklist_hits": 1}, "feodo"),
    ({"ipqs_phishing": True}, "ipqs_phishing"),
    ({"ipqs_risk_score": 90}, "ipqs_high_risk"),
    ({"alienvault_pulse_count": 3, "alienvault_distinct_pulses": 3}, "alienvault_otx"),
    ({"favicon_cloned": True, "favicon_brand": "PayPal", "favicon_detail": "PayPal's favicon"},
     "favicon_brand_clone"),
])
def test_an_address_with_evidence_stays_dangerous(evidence, code):
    score, level, reasons = calculate_score(_ip_signals("103.249.199.5", **evidence))
    assert code in _codes(reasons)
    assert level == RiskLevel.dangerous, (score, [(r.signal, r.weight) for r in reasons])


def test_an_address_trick_in_the_url_is_still_evidence():
    """paypal.com@<ip>: the browser opens the address, the reader sees PayPal."""
    _, level, reasons = calculate_score(
        _ip_signals("103.249.199.5", raw_url="http://paypal.com@103.249.199.5/login"))
    assert "at_symbol" in _codes(reasons)
    assert level == RiskLevel.dangerous


# ── Names are untouched ──

def test_a_name_keeps_its_subdomain_and_port_rules():
    _, _, reasons = calculate_score({"domain": "a.b.c.evil-example.com",
                                     "raw_url": "http://a.b.c.evil-example.com:35908/"})
    assert {"excessive_subdomains", "non_standard_port"} <= _codes(reasons)


def test_a_bracketed_ipv6_port_is_still_a_port():
    _, _, reasons = calculate_score(
        _ip_signals("2001:db8::1", raw_url="http://[2001:db8::1]:35908/i"))
    assert "non_standard_port" in _codes(reasons)


def test_no_https_on_a_name_is_still_strong():
    """The weak-signal cap is unchanged for names: no HTTPS is strong there."""
    _, level, _ = calculate_score({"domain": "secure-login-portal.example", "no_https": True,
                                   "missing_security_headers": ["a", "b", "c"],
                                   "redirect_cross_domain": True, "redirect_count": 1})
    assert level == RiskLevel.dangerous


# ── Through the analyzer ──

def _reachable_with_redirect(monkeypatch):
    from api.services import analyzer

    async def _redirect(domain):
        return {"reachable": True, "count": 1, "cross_domain": True}

    monkeypatch.setattr(analyzer, "check_redirect_chain", _redirect)


def test_the_analyzer_gives_8888_a_caution_on_heuristics(offline_analyzer, monkeypatch):
    offline_analyzer(exists=None, site="reachable")
    _reachable_with_redirect(monkeypatch)
    result = asyncio.run(analyze_domain("8.8.8.8", budget_s=5.0))
    assert result.level == RiskLevel.caution, [(r.signal, r.weight) for r in result.reasons]
    assert {"ip_based", "cross_domain_redirect"} <= _codes(result.reasons)
    assert not _codes(result.reasons) & NOT_ABOUT_AN_ADDRESS
    # The model was not asked about an address, so the basis does not say it was.
    assert result.verdict_basis == "heuristics"


def test_the_analyzer_keeps_a_listed_address_dangerous(offline_analyzer, monkeypatch):
    offline_analyzer(exists=None, site="reachable", hits={"safe_browsing": True})
    _reachable_with_redirect(monkeypatch)
    result = asyncio.run(analyze_domain("8.8.8.8", budget_s=5.0))
    assert result.level == RiskLevel.dangerous
    assert "safe_browsing" in _codes(result.reasons)
    assert result.verdict_basis == "threat_intel"


# ── Private and reserved ranges: the SSRF answer, as before ──

@pytest.mark.parametrize("host", [
    "192.168.1.1", "10.0.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1",
])
def test_private_and_reserved_addresses_keep_the_ssrf_answer(host, security_events):
    result = asyncio.run(analyze_domain(host, budget_s=5.0))
    assert result.score == 0 and result.level == RiskLevel.caution
    assert [r.signal for r in result.reasons] == ["invalid_domain"]
    assert "is in a blocked range" in result.reasons[0].detail
    assert security_events == [("ssrf_blocked", None)]


def test_the_public_check_refuses_a_private_address(redis_down):
    from fastapi.testclient import TestClient

    from api.main import app

    response = TestClient(app).get("/api/v1/public/check/192.168.1.1")
    assert response.status_code == 400

"""Unreachable is not insecure (report 2026-09-25 #1).

Our scanner runs abroad, and many real Russian sites refuse foreign
connections. The analyzer read "could not connect" as "no HTTPS" (+40) and
"no security headers" (+15), and a .рф name also "redirected" to its own
Unicode spelling (+20). In production that put президент.рф at 77,
bankspb.ru at 57 and mojbiznes.рф at 53 — all 'dangerous' (51+).

These tests pin the fix with the network mocked: a site the scanner cannot
open gets a zero-weight `unreachable_from_scanner` reason and none of those
penalties; known phishing stays 'dangerous' on its threat-intel evidence.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from api.models.schemas import RiskLevel
from api.services import site_probes
from api.services.analyzer import analyze_domain
from api.services.scoring import calculate_score

PENALTIES = {"no_https", "missing_headers", "cross_domain_redirect"}

# The real sites from the report. All exist; from our foreign scanner they
# time out, reset, or present a certificate we cannot verify.
REAL_RU_SITES = [
    "xn--d1abbgf6aiiy.xn--p1ai",   # президент.рф
    "rosreestr.gov.ru",
    "bankspb.ru",
    "xn--90aifddrld7a.xn--p1ai",   # мойбизнес.рф
    "kaluga-gov.ru",
    "vologda-oblast.ru",
]


def _codes(result) -> set[str]:
    return {r.signal for r in result.reasons}


# ── The probes: whether they reached the site, separately from what they saw ──

@pytest.mark.parametrize("exc, kind", [
    (socket.timeout("timed out"), "timeout"),
    (ConnectionRefusedError(), "refused"),
    (ConnectionResetError(), "reset"),
    (ssl.SSLCertVerificationError("unable to get local issuer certificate"), "tls_certificate"),
    (ssl.SSLError("handshake failure"), "tls_handshake"),
])
def test_tls_probe_failure_is_unreachable_not_insecure(exc, kind):
    with patch.object(site_probes.socket, "create_connection", side_effect=exc):
        out = asyncio.run(site_probes.check_ssl("bankspb.ru"))
    assert out == {"reachable": False, "error": kind}
    assert "has_ssl" not in out  # nothing was measured — never "has_ssl: False"


def test_failure_kind_unwraps_httpx_errors():
    wrapped = httpx.ConnectError("boom")
    wrapped.__cause__ = ssl.SSLCertVerificationError("bad cert")
    assert site_probes.failure_kind(wrapped) == "tls_certificate"
    assert site_probes.failure_kind(httpx.ConnectTimeout("slow")) == "timeout"


def _client(**behaviour):
    client = MagicMock()
    for method, value in behaviour.items():
        setattr(client, method, AsyncMock(side_effect=value) if isinstance(value, Exception)
                else AsyncMock(return_value=value))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


def test_headers_probe_does_not_invent_missing_headers():
    with patch.object(site_probes.httpx, "AsyncClient",
                      return_value=_client(head=httpx.ConnectTimeout("slow"))):
        out = asyncio.run(site_probes.check_security_headers("rosreestr.gov.ru"))
    assert out["reachable"] is False
    assert out["missing"] is None  # the old code returned all five as "missing"


def test_headers_probe_never_falls_back_to_plain_http():
    client = _client(head=httpx.ConnectError("refused"))
    with patch.object(site_probes.httpx, "AsyncClient", return_value=client):
        asyncio.run(site_probes.check_security_headers("bankspb.ru"))
    urls = [c.args[0] for c in client.head.call_args_list]
    assert urls == ["https://bankspb.ru/"]


def test_redirect_probe_unreachable_is_neutral():
    with patch.object(site_probes.httpx, "AsyncClient",
                      return_value=_client(get=httpx.ConnectTimeout("slow"))):
        out = asyncio.run(site_probes.check_redirect_chain("kaluga-gov.ru"))
    assert out["reachable"] is False
    assert out["cross_domain"] is False and out["count"] == 0


def test_idn_site_is_not_redirected_to_its_own_unicode_spelling(probe_web):
    """httpx reports the final host decoded — 'мойбизнес.рф' for a request to
    xn--90aifddrld7a.xn--p1ai. That was scored as a cross-domain redirect."""
    probe_web({
        "https://xn--90aifddrld7a.xn--p1ai/": (301, {"location": "https://www.мойбизнес.рф/"}),
    })
    out = asyncio.run(site_probes.check_redirect_chain("xn--90aifddrld7a.xn--p1ai"))
    assert out["reachable"] is True
    assert out["cross_domain"] is False
    assert out["domains_visited"] == ["www.xn--90aifddrld7a.xn--p1ai"]


def test_idn_redirect_to_a_different_site_still_counts(probe_web):
    probe_web({
        "https://xn--90aifddrld7a.xn--p1ai/": (302, {"location": "https://госуслуги-вход.рф/"}),
    })
    out = asyncio.run(site_probes.check_redirect_chain("xn--90aifddrld7a.xn--p1ai"))
    assert out["cross_domain"] is True


def test_ascii_host_round_trips_idn():
    assert site_probes.ascii_host("мойбизнес.рф") == "xn--90aifddrld7a.xn--p1ai"
    assert site_probes.ascii_host("WWW.Example.COM.") == "www.example.com"


# ── The scorer: "not measured" adds nothing ──

def test_scorer_adds_no_penalty_for_unmeasured_site():
    score, level, reasons = calculate_score({
        "domain": "bankspb.ru", "raw_url": "bankspb.ru",
        "no_https": None, "missing_security_headers": None,
        "redirect_cross_domain": False, "site_reachable": False,
    })
    assert not ({r.signal for r in reasons} & PENALTIES)
    assert level != RiskLevel.dangerous


# ── End to end, network mocked ──

@pytest.mark.parametrize("domain", REAL_RU_SITES)
def test_real_russian_sites_unreachable_from_abroad_are_not_dangerous(domain, offline_analyzer):
    offline_analyzer(site="unreachable")
    result = asyncio.run(analyze_domain(domain, budget_s=5.0))

    assert result.level != RiskLevel.dangerous, (domain, result.score, _codes(result))
    assert not (_codes(result) & PENALTIES), _codes(result)
    assert "unreachable_from_scanner" in _codes(result)
    unreachable = next(r for r in result.reasons if r.signal == "unreachable_from_scanner")
    assert unreachable.weight == 0
    assert result.verdict_basis == "unreachable"
    assert result.has_ssl is None  # unknown, not "no SSL"


@pytest.mark.parametrize("domain", [
    "xn--d1abbgf6aiiy.xn--p1ai",            # президент.рф — was +25 for 'xn--' hyphens/n-grams
    "xn--90aifddrld7a.xn--p1ai",            # мойбизнес.рф
    "xn--80aaccp4ajwpkgbl4lpb.xn--p1ai",    # a small .рф site from the report (82 before PR #43)
])
def test_rf_names_are_not_judged_by_their_punycode_spelling(domain, offline_analyzer):
    """The report's second .рф extra: the technical xn-- name scored as a
    random, hyphen-stuffed one. Still absent after PR #43 + this change."""
    offline_analyzer(site="unreachable")
    result = asyncio.run(analyze_domain(domain, budget_s=5.0))
    shape = {"excessive_special_chars", "many_special_chars", "unnatural_ngram",
             "suspicious_ngram", "long_domain_name", "high_digit_ratio", "medium_entropy"}
    assert not (_codes(result) & shape), _codes(result)


RU_BRAND_LOOKALIKES = [
    "gosuslugi-vyplata.ru", "gosuslugl.ru", "avito-dostavka.ru",
    "sberbank-bonus.ru", "wildberries-priz.ru", "tinkoff-vozvrat.ru",
]


@pytest.mark.parametrize("domain", RU_BRAND_LOOKALIKES)
def test_unknown_site_we_could_not_open_is_never_safe(domain, offline_analyzer):
    """Review 2026-09-27: a fresh, geo-fenced Госуслуги / Сбер / Авито
    look-alike has no listing yet, no brand the typosquat list knows, and the
    ML model gives it <10%. With the connection penalties gone it came back
    'safe' — 'Выглядит безопасно' for exactly what reaches the elderly. With
    nothing to vouch for it, it is caution (never a block: basis stays
    'unreachable')."""
    offline_analyzer(site="unreachable")
    result = asyncio.run(analyze_domain(domain, budget_s=5.0))
    assert result.level == RiskLevel.caution, (result.score, _codes(result))
    assert result.verdict_basis == "unreachable"
    reason = next(r for r in result.reasons if r.signal == "unreachable_from_scanner")
    assert "not a widely known site" in reason.detail


def _unreachable_detail(result) -> str:
    return next(r for r in result.reasons if r.signal == "unreachable_from_scanner").detail


def test_widely_known_site_we_could_not_open_can_still_be_safe(offline_analyzer):
    """vologda-oblast.ru — Tranco #294,448, refuses foreign scanners — is not
    pushed to caution by the floor."""
    offline_analyzer(site="unreachable", values={"tranco": {
        "ranked": True, "rank": 294448, "weight": -5, "label": "In the global top 1M",
    }})
    result = asyncio.run(analyze_domain("vologda-oblast.ru", budget_s=5.0))
    assert result.level == RiskLevel.safe
    assert "not a widely known site" not in _unreachable_detail(result)


def test_www_of_a_known_site_is_known_too(offline_analyzer):
    """Tranco ranks registrable domains, and the lookup is by exact host: the
    www. spelling people paste from a letter must not lose the vouch."""
    offline_analyzer(site="unreachable", ranks={"kaluga-gov.ru": 561507})
    known = asyncio.run(analyze_domain("www.kaluga-gov.ru", budget_s=5.0))
    offline_analyzer(site="unreachable")
    unknown = asyncio.run(analyze_domain("www.kaluga-gov.ru", budget_s=5.0))
    assert "not a widely known site" not in _unreachable_detail(known)
    assert "not a widely known site" in _unreachable_detail(unknown)


@pytest.mark.parametrize("domain", ["rosreestr.gov.ru", "nalog.gov.ru", "www.gov.uk"])
def test_government_registry_vouches_for_its_names(domain, offline_analyzer):
    """Tranco ranks gov.ru as ONE name and never rosreestr.gov.ru; only
    federal bodies can register under it."""
    offline_analyzer(site="unreachable")
    result = asyncio.run(analyze_domain(domain, budget_s=5.0))
    assert result.level == RiskLevel.safe
    assert "not a widely known site" not in _unreachable_detail(result)


@pytest.mark.parametrize("domain", ["gosuslugi.ru-gov.site", "x.go.com", "evil-gov.ru"])
def test_government_lookalikes_are_not_vouched_for(domain, offline_analyzer):
    offline_analyzer(site="unreachable")
    result = asyncio.run(analyze_domain(domain, budget_s=5.0))
    assert result.level != RiskLevel.safe


def test_shared_platform_tenant_never_borrows_the_platforms_rank(offline_analyzer):
    """321da.tw1.ru is whoever rented it; tw1.ru being popular vouches for
    nothing (report #7)."""
    offline_analyzer(site="unreachable", ranks={"tw1.ru": 9000})
    result = asyncio.run(analyze_domain("321da.tw1.ru", budget_s=5.0))
    assert result.level != RiskLevel.safe


def test_unreachable_text_neither_reassures_nor_alarms(offline_analyzer):
    """Phishing kits hide from foreign scanners too: "not a sign of danger"
    was a promise the evidence does not support."""
    offline_analyzer(site="unreachable")
    result = asyncio.run(analyze_domain("kaluga-gov.ru", budget_s=5.0))
    detail = next(r for r in result.reasons if r.signal == "unreachable_from_scanner").detail
    assert "not a sign of danger" not in detail
    assert "says nothing either way" in detail


def test_unreachable_site_counts_as_less_evidence(offline_analyzer):
    offline_analyzer(site="unreachable")
    unreachable = asyncio.run(analyze_domain("bankspb.ru", budget_s=5.0))
    offline_analyzer(site="reachable")
    reachable = asyncio.run(analyze_domain("bankspb.ru", budget_s=5.0))
    assert unreachable.confidence_pct < reachable.confidence_pct


def test_known_phishing_stays_dangerous_when_unreachable(offline_analyzer):
    """p6ihks.casa was 'dangerous, 78' in production. Its listings, not the
    connection failures, are what must carry that verdict."""
    offline_analyzer(site="unreachable", hits={"urlhaus": True, "safe_browsing": True})
    result = asyncio.run(analyze_domain("p6ihks.casa", budget_s=5.0))
    assert result.level == RiskLevel.dangerous
    assert result.verdict_basis == "threat_intel"


def test_reachable_site_is_still_measured(offline_analyzer):
    """The fix must not blind the probes: a reachable site's real
    measurements still reach the scorer."""
    offline_analyzer(site="reachable")
    result = asyncio.run(analyze_domain("example-shop.ru", budget_s=5.0))
    assert "unreachable_from_scanner" not in _codes(result)
    assert result.has_ssl is True

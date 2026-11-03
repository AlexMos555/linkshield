"""Evidence-only zones (scoring.EVIDENCE_ONLY_TENANT_ZONES): a customer's site
under a top-100k platform's temporary addresses gets no instant 'safe' from
the allowlist, and no hygiene rule or model verdict either. The evidence
sources run, and the answer is 'safe' unless one of them speaks.

On 2026-11-03 zrg.okx.mybluehost.me, a PhishTank phish that Google's Safe
Browsing lists, was "safe 0" from the allowlist on the live /public/check:
no check ran. Judged like any other name (the first version of #396), about
half of Bluehost's real temporary addresses went to caution or worse on the
shared server's certificate, forwards to the customer's own domain and the
model's opinion of Bluehost's own website-<hex> names.
"""
from __future__ import annotations

import asyncio

import pytest

from api.models.schemas import RiskLevel
from api.services import scoring
from api.services.analyzer import analyze_domain, rule_only_result

BLUEHOST = "mybluehost.me"

# Real temporary addresses measured with the full analyzer for #396, with
# what the probes saw there and what the full rules made of it.
REAL = [
    # no security headers
    ("fmf.dqm.mybluehost.me", dict(missing_security_headers=["csp", "hsts", "xfo"])),
    # a forward to the customer's own domain (+20)
    ("hxb.rqh.mybluehost.me", dict(missing_security_headers=["csp"], redirect_count=1, redirect_cross_domain=True)),
    # another site's certificate on the shared server (+30)
    ("zrw.udl.mybluehost.me", dict(certificate_problem="wrong_host")),
    # a certificate a day old and a forward (caution 50 on the full rules)
    ("agm.dfv.mybluehost.me", dict(missing_security_headers=["csp"], cert_age_days=1, redirect_count=1,
                                   redirect_cross_domain=True)),
    # Bluehost's own name for a site an account adds: the model said 0.9+
    ("website-3c718dc1.jdm.diw.mybluehost.me", dict(missing_security_headers=["csp"], redirect_count=1,
                                                    redirect_cross_domain=True)),
    ("www.website-fa76de8b.xva.vgj.mybluehost.me", dict(cert_age_days=28)),
    ("kawarthacottagevacations-ca.ryu.fke.mybluehost.me", dict(missing_security_headers=["csp"])),
    ("logicocfe01-com-uy.mez.uth.mybluehost.me", dict(missing_security_headers=["csp"])),
]


def _signals(domain: str, **extra) -> dict:
    return {"domain": domain, "raw_url": domain, "checks_succeeded": 12, "total_checks": 13,
            "site_reachable": True, "cert_age_days": 30, **extra}


def _score(domain: str, **extra):
    score, level, reasons = scoring.calculate_score(_signals(domain, **extra))
    return score, level.value, {r.signal: r.weight for r in reasons if r.weight}


# ── Which names ──

@pytest.mark.parametrize("host", [
    "zrg.okx.mybluehost.me", "fmf.dqm.mybluehost.me", "www.fsp.liz.mybluehost.me",
    "website-911ca792.qup.hak.mybluehost.me",
])
def test_bluehosts_customers_are_evidence_only_and_never_instant_safe(host):
    assert scoring.is_evidence_only_tenant(host) is True
    assert scoring.is_trusted_top_domain(host) is False


@pytest.mark.parametrize("host", ["mybluehost.me", "www.mybluehost.me"])
def test_bluehosts_own_names_keep_the_allowlist(host):
    assert scoring.is_evidence_only_tenant(host) is False
    assert scoring.is_trusted_top_domain(host) is True
    assert _score(host) == (0, "safe", {"known_legitimate": -50})


@pytest.mark.parametrize("host", [
    # tenant_suffix_of() also answers for the curated tenant_suffixes
    "x.tw1.ru", "polite-tulumba-704e1b.netlify.app", "my-bakery.zapier.app",
    # the zones left out after the measured pass of #396
    "agentlegend1.ac-page.com", "abenti.hospedagemdesites.ws",
    "mybluehost.me.evil.com", "example.com",
])
def test_no_other_name_is_evidence_only(host):
    assert scoring.is_evidence_only_tenant(host) is False


def test_the_zone_is_a_top_100k_name():
    """Only a zone the allowlist would vouch for needs this: elsewhere the
    full rules apply anyway."""
    assert all(z in scoring.TOP_DOMAINS for z in scoring.EVIDENCE_ONLY_TENANT_ZONES)


def test_the_platforms_rank_is_not_its_customers():
    """An OTX report about a tenant is about the tenant: Bluehost's #11,072
    neither waives nor halves it (scoring._RANK_TENANT_SUFFIXES)."""
    host = "zrg.okx.mybluehost.me"
    assert scoring._platform_tenant_site(host) == "okx.mybluehost.me"
    assert scoring.popularity_rank({"tranco_registrable_rank": 11_072}, host) is None
    assert scoring._tenant_label(host) is None  # no name rule reads it anyway


# ── Real sites: nothing but evidence counts ──

@pytest.mark.parametrize("host,seen", REAL)
def test_a_real_temporary_address_is_safe_without_evidence(host, seen):
    assert _score(host, **seen) == (0, "safe", {})


def test_the_model_is_not_consulted(monkeypatch):
    from api.services import ml_scorer

    monkeypatch.setattr(ml_scorer, "ml_predict", lambda domain: {"phishing_probability": 0.99, "confidence": 0.99})
    assert _score("website-3c718dc1.jdm.diw.mybluehost.me") == (0, "safe", {})
    # the same name anywhere else is judged by it
    assert "ml_high_risk" in _score("website-3c718dc1.jdm.diw.zq7example.com")[2]


# ── Evidence still speaks ──

@pytest.mark.parametrize("hit,expected", [
    ({"safe_browsing_hit": True}, (80, "dangerous", {"safe_browsing": 80})),
    ({"phishtank_hit": True}, (70, "dangerous", {"phishtank": 70})),
    ({"phishstats_hit": True}, (65, "dangerous", {"phishstats": 65})),
    ({"ipqs_phishing": True}, (70, "dangerous", {"ipqs_phishing": 70})),
    ({"ipqs_risk_score": 90}, (40, "caution", {"ipqs_high_risk": 40})),
    ({"favicon_cloned": True}, (35, "caution", {"favicon_brand_clone": 35})),
    # OTX at full weight, with the platform's rank beside it
    ({"alienvault_pulse_count": 3, "tranco_registrable_rank": 11_072}, (30, "caution", {"alienvault_otx": 30})),
    ({"alienvault_pulse_count": 8, "tranco_registrable_rank": 11_072}, (60, "dangerous", {"alienvault_otx_high": 60})),
])
def test_a_list_or_report_still_decides(hit, expected):
    assert _score("zrg.okx.mybluehost.me", **hit) == expected


def test_the_motivating_phish_is_dangerous_on_googles_listing():
    """zrg.okx.mybluehost.me: Safe Browsing's Transparency Report listed it
    as phishing on 2026-11-03; production asks Web Risk since that day."""
    assert _score("zrg.okx.mybluehost.me", safe_browsing_hit=True, missing_security_headers=["csp"])[:2] == (80, "dangerous")


@pytest.mark.parametrize("host,brand", [
    ("paypal.abc.def.mybluehost.me", "paypal"),          # a brand as a whole label
    ("paypal-login.abc.def.mybluehost.me", "paypal"),    # a brand next to a lure word
    ("sberbank.abc.def.mybluehost.me", "sberbank"),
    ("abc.paypal-verify.mybluehost.me", "paypal"),
])
def test_a_brand_in_the_customers_name_is_evidence(host, brand):
    score, level, reasons = _score(host)
    assert (score, level, reasons) == (30, "caution", {"brand_subdomain_abuse": 30})
    # with a report beside it, dangerous
    assert _score(host, alienvault_pulse_count=3)[:2] == (60, "dangerous")


@pytest.mark.parametrize("host", [r[0] for r in REAL] + ["website-911ca792.qup.hak.mybluehost.me"])
def test_no_brand_rule_fires_on_bluehosts_own_names(host):
    assert scoring._check_brand_in_subdomain(host) is None
    assert scoring._check_brand_on_hosting_tenant(host, scoring.EVIDENCE_ONLY_TENANT_ZONES) is None


# ── The analyzer ──

def test_an_unreachable_tenant_is_not_floored_to_caution(offline_analyzer):
    """No probe judges these sites, an unreachable one included: the
    allowlist answered 'safe' for it, and nothing lists it."""
    offline_analyzer(site="unreachable", ranks={BLUEHOST: 11_072})
    result = asyncio.run(analyze_domain("fmf.dqm.mybluehost.me", budget_s=5.0))
    codes = {r.signal for r in result.reasons}
    assert result.level == RiskLevel.safe
    assert "unreachable_from_scanner" in codes and "user_content_platform" in codes


def test_an_unreachable_listed_tenant_is_dangerous(offline_analyzer):
    offline_analyzer(site="unreachable", hits={"safe_browsing": True})
    result = asyncio.run(analyze_domain("zrg.okx.mybluehost.me", budget_s=5.0))
    assert result.level == RiskLevel.dangerous
    assert result.verdict_basis == "threat_intel"


def test_a_reachable_tenant_says_anyone_can_publish_there(offline_analyzer):
    offline_analyzer(site="reachable")
    result = asyncio.run(analyze_domain("qyd.wqb.mybluehost.me", budget_s=5.0))
    assert result.level == RiskLevel.safe and result.score == 0
    assert "user_content_platform" in {r.signal for r in result.reasons}
    # the rules found nothing; the model was not asked
    assert result.verdict_basis == "heuristics"


def test_the_llm_judge_does_not_weigh_in(offline_analyzer, monkeypatch):
    """Its features are the probes', which do not count here: a brand
    caution stays one. The analyzer asks the judge through opinion_now
    since #399 (a cached opinion, or a live call left running)."""
    from api.services import llm_judge

    asked = []

    async def _opinion_now(signals, score, level):
        asked.append(signals["domain"])
        return llm_judge.CACHED, {"verdict": "safe", "confidence": 0.9, "one_line_reason": "x", "score_shift": -20}

    monkeypatch.setattr(llm_judge, "opinion_now", _opinion_now)
    offline_analyzer(site="reachable")
    result = asyncio.run(analyze_domain("paypal.abc.def.mybluehost.me", budget_s=5.0))
    assert (result.level, result.score) == (RiskLevel.caution, 30)
    assert asked == []
    # elsewhere the judge is asked as before
    asyncio.run(analyze_domain("paypal-login.netlify.app", budget_s=5.0))
    assert asked == ["paypal-login.netlify.app"]


def test_the_fallback_without_analysis_is_safe_as_the_allowlist_was():
    result = rule_only_result("fmf.dqm.mybluehost.me")
    assert (result.level, result.score) == (RiskLevel.safe, 0)
    assert result.checks_incomplete == ["analysis"]


def test_the_authenticated_check_has_no_fast_path_for_them():
    from api.routers.check import _quick_allowlist_check

    assert _quick_allowlist_check("zrg.okx.mybluehost.me") is None
    assert _quick_allowlist_check("mybluehost.me") is not None

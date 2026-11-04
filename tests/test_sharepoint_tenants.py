"""Microsoft 365 tenants: an organisation's SharePoint and OneDrive for Business.

<org>.sharepoint.com is an organisation's SharePoint Online and
<org>-my.sharepoint.com its OneDrive for Business. The label is the
organisation's Microsoft 365 tenant name, the one it picked when it signed
up: a company's tenant carries its own name, brand included. sharepoint.com
is a tenant suffix (data/hosting_platforms.json), so the scorer read that
label as a name someone picked for a free site, and its name rules — a brand
as the whole label (brand_subdomain_abuse), the ML model's opinion of the
label (ml_high_risk / ml_suspicious), a brand word that lifts the weak-signal
cap (_tenant_brand_word) — are evidence there. On a tenant they are not:

Review 2026-11-04: microsoft-my.sharepoint.com (Microsoft's own OneDrive for
Business) was 'dangerous 75' with no intel at all — ml_high_risk 35 and three
weak signals. Measured that day with the full analyzer, no intel: 11 of 37
tenants that are the brand's own Entra tenant (the tenant behind
<brand>.onmicrosoft.com is the one that verified the brand's domain:
paypal, wellsfargo, barclays, stripe, shopify …) were 'dangerous', 5 by the
model and 6 by the brand as the whole label. None of 60 other real tenants
(30 from Tranco's subdomain list, 30 from Common Crawl) was 'dangerous', nor
any of the 19 PhishTank-verified phishing tenants — all compromised
organisations' OneDrives, which none of these name rules ever caught.

So on a tenant site (scoring.is_organization_tenant_site) those three are
weak, as scoring.WEAK_SIGNALS are: they still count, but with only weak
signals beside them the verdict stops at caution. Everything else is as
on every other platform: listings and OTX reports about the tenant count in
full, and a brand next to a lure word (paypal-login) — not how anyone names
an organisation — is still brand abuse.
"""
from __future__ import annotations

import pytest

import api.services.ml_scorer as ml_scorer
from api.services import scoring

# What the site probes saw: weak signals only (WEAK_SIGNALS), as on every
# measured tenant (SharePoint answers without most security headers).
HYGIENE = {
    "missing_security_headers": ["strict-transport-security", "content-security-policy", "x-frame-options"],
    "dns_ttl": 30,
}
MORE_HYGIENE = {**HYGIENE, "redirect_cross_domain": True}


@pytest.fixture
def model(monkeypatch):
    """Sets the model's opinion of every name: `model(p)`, or `model(None)`
    for no model. The served model's opinion moves with each retrain."""
    def set_opinion(p):
        monkeypatch.setattr(ml_scorer, "ml_predict",
                            (lambda d: None) if p is None else (lambda d: {"phishing_probability": p, "confidence": 0.9}))
    set_opinion(None)
    return set_opinion


def _score(host: str, **signals) -> tuple[int, str, dict[str, int]]:
    score, level, reasons = scoring.calculate_score({"domain": host, "raw_url": host, **signals})
    return score, level.value, {r.signal: r.weight for r in reasons}


@pytest.mark.parametrize("host, opinion, extra, name_reason", [
    # the review's host: the model's opinion of 'microsoft-my' (0.95 in production)
    ("microsoft-my.sharepoint.com", 0.95, HYGIENE, ("ml_high_risk", 35)),
    ("wellsfargo-my.sharepoint.com", 0.95, HYGIENE, ("ml_high_risk", 35)),
    ("spotify-my.sharepoint.com", 0.7, HYGIENE, ("ml_suspicious", 20)),
    # the brand as the tenant's whole name
    ("barclays.sharepoint.com", None, HYGIENE, ("brand_subdomain_abuse", 30)),
    ("stripe.sharepoint.com", None, HYGIENE, ("brand_subdomain_abuse", 30)),
    # a brand word in the name lifted the weak-signal cap
    ("paypal-my.sharepoint.com", None, MORE_HYGIENE, ("cross_domain_redirect", 20)),
    # Microsoft's pre-release ring: 'dangerous 86' by name on 2026-11-04
    ("microsoft.sharepoint-df.com", 0.95, HYGIENE, ("brand_subdomain_abuse", 30)),
])
def test_a_tenant_s_name_alone_makes_a_caution_not_dangerous(model, host, opinion, extra, name_reason):
    model(opinion)
    score, level, reasons = _score(host, **extra)
    assert (score, level) == (scoring.DANGEROUS_ABOVE, "caution")
    signal, weight = name_reason
    assert reasons[signal] == weight            # still shown, still counted
    assert sum(w for w in reasons.values() if w > 0) > scoring.DANGEROUS_ABOVE


@pytest.mark.parametrize("host, opinion, extra", [
    ("microsoft-my.vercel.app", 0.95, HYGIENE),
    ("paypal-my.pages.dev", 0.7, HYGIENE),
    ("barclays.netlify.app", None, HYGIENE),
    ("paypal-my.pages.dev", None, MORE_HYGIENE),
    ("barclays.sharepoint-example.com", None, HYGIENE),   # a brand as a subdomain of a registered name
])
def test_the_same_names_elsewhere_are_judged_as_before(model, host, opinion, extra):
    model(opinion)
    _, level, _ = _score(host, **extra)
    assert level == "dangerous", host


@pytest.mark.parametrize("host", [
    "paypal-login.sharepoint.com",
    "microsoft-account-verify.sharepoint.com",
    "secure-paypal-my.sharepoint.com",
])
def test_a_brand_next_to_a_lure_word_on_a_tenant_is_still_brand_abuse(model, host):
    score, level, reasons = _score(host, **HYGIENE)
    assert reasons["brand_subdomain_abuse"] == 30
    assert level == "dangerous" and score > scoring.DANGEROUS_ABOVE


@pytest.mark.parametrize("evidence, signal", [
    ({"alienvault_indicator": "hostname", "alienvault_pulse_count": 6,
      "alienvault_distinct_pulses": 6, "alienvault_newest_report_days": 3}, "alienvault_otx_high"),
    ({"safe_browsing_hit": True}, "safe_browsing"),
    ({"urlhaus_hit": True}, "urlhaus"),
])
def test_evidence_about_a_tenant_counts_in_full(model, evidence, signal):
    """A compromised organisation's OneDrive is the usual SharePoint phish:
    reports and listings about the tenant make it 'dangerous', as anywhere."""
    model(0.95)
    _, level, reasons = _score("microsoft-my.sharepoint.com", **HYGIENE, **evidence)
    assert level == "dangerous" and signal in reasons


def test_fresh_otx_reports_beside_the_name_make_it_dangerous(model):
    """One to five fresh OTX reports are strong (not WEAK_SIGNALS): with the
    model's opinion and hygiene they still make 'dangerous'."""
    model(0.95)
    _, level, reasons = _score("contoso-my.sharepoint.com", **HYGIENE, alienvault_indicator="hostname",
                               alienvault_pulse_count=2, alienvault_distinct_pulses=2,
                               alienvault_newest_report_days=5)
    assert reasons["alienvault_otx"] == 30 and level == "dangerous"


@pytest.mark.parametrize("host, expected", [
    ("contoso.sharepoint.com", True),
    ("contoso-my.sharepoint.com", True),
    ("CONTOSO-MY.SharePoint.com.", True),
    ("contoso-my.sharepoint.cn", True),         # 21Vianet's SharePoint (China)
    ("microsoft.sharepoint-df.com", True),      # Microsoft's own pre-release ring
    ("microsoft.sharepoint.com", False),        # an operator host: Microsoft's own, allowlisted
    ("www.sharepoint.com", False),
    ("sharepoint.com", False),
    ("sharepoint.cn", False),
    ("x.contoso.sharepoint.com", False),        # a name below a tenant, not the tenant's site
    ("contoso.netlify.app", False),
    ("contoso.sharepoint-example.com", False),
    ("contoso.sharepoint.us", False),           # not measured: no tenant found
])
def test_which_hosts_are_an_organisation_s_tenant(host, expected):
    assert scoring.is_organization_tenant_site(host) is expected


def test_the_operator_s_own_tenant_stays_allowlisted(model):
    model(0.95)
    assert scoring.is_trusted_top_domain("microsoft.sharepoint.com")
    assert _score("microsoft.sharepoint.com", **HYGIENE)[1] == "safe"

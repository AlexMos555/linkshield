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
organisations' OneDrives, whose names say nothing.

So on a tenant verified as the brand's own (scoring.organization_tenant_brand:
the label without Microsoft's own '-my' / '-admin' suffix is a name in
data/organization_tenants.json) those three are weak, as scoring.WEAK_SIGNALS
are: they still count, but with only weak signals beside them the verdict
stops at caution. A name exactly equal to a brand is not enough (review
2026-11-04): 16 brand words have no Entra tenant at all — telegram, binance,
tinkoff … anyone can sign up as <brand>.onmicrosoft.com and get
<brand>-my.sharepoint.com — and many others belong to tenants nobody has
tied to the brand (facebook, lloyds, ozon …). Those are judged as on main.
Only there: a brand with something added or misspelt is a name
somebody else picked (review 2026-11-04: micosoft-my, 0ffice365, docusignus,
barclaysdocs … exist, and none is the brand's own Entra tenant), and so is
a name with no brand at all — two Phishing.Database phishing tenants
(appriver3651007637-my, appriver3651009905-my) were 'dangerous' by the
model alone. On those the model counts in full, as on main. Everything else
is as on every other platform: listings and OTX reports about the tenant
count in full, and a brand next to a lure word (paypal-login) — not how
anyone names an organisation — is still brand abuse.
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
    # <org>-admin.sharepoint.com: the tenant's SharePoint admin centre,
    # created by Microsoft for every tenant (review 2026-11-04: microsoft-admin
    # 61, facebook-admin 66 'dangerous' by the model on main)
    ("microsoft-admin.sharepoint.com", 0.95, HYGIENE, ("ml_high_risk", 35)),
    ("barclays-admin.sharepoint.com", 0.95, HYGIENE, ("ml_high_risk", 35)),
    ("wellsfargo-admin.sharepoint.com", 0.95, HYGIENE, ("ml_high_risk", 35)),
    ("netflix-admin.sharepoint.com", 0.7, HYGIENE, ("ml_suspicious", 20)),
    # the brand as the tenant's whole name
    ("barclays.sharepoint.com", None, HYGIENE, ("brand_subdomain_abuse", 30)),
    ("stripe.sharepoint.com", None, HYGIENE, ("brand_subdomain_abuse", 30)),
    # a Russian-list brand as the whole name: Tele2 AB's tenant (tele2.com and
    # tele2.se are verified in the tenant behind tele2.onmicrosoft.com)
    ("tele2.sharepoint.com", None, HYGIENE, ("brand_subdomain_abuse", 30)),
    # a brand word in the name lifted the weak-signal cap
    ("paypal-my.sharepoint.com", None, MORE_HYGIENE, ("cross_domain_redirect", 20)),
])
def test_a_tenant_s_name_alone_makes_a_caution_not_dangerous(model, host, opinion, extra, name_reason):
    model(opinion)
    score, level, reasons = _score(host, **extra)
    assert (score, level) == (scoring.DANGEROUS_ABOVE, "caution")
    signal, weight = name_reason
    assert reasons[signal] == weight            # still shown, still counted
    assert sum(w for w in reasons.values() if w > 0) > scoring.DANGEROUS_ABOVE


@pytest.mark.parametrize("host, opinion, extra", [
    # no Entra tenant by that name on 2026-11-04 (AADSTS90002): free for anyone
    ("telegram-my.sharepoint.com", 0.95, HYGIENE),
    ("sovcombank-my.sharepoint.com", 0.95, HYGIENE),
    ("binance-my.sharepoint.com", 0.95, HYGIENE),
    ("kucoin-my.sharepoint.com", 0.95, HYGIENE),
    ("tinkoff-my.sharepoint.com", 0.95, HYGIENE),
    ("telegram-admin.sharepoint.com", 0.95, HYGIENE),
    ("aliexpress.sharepoint.com", None, HYGIENE),
    ("binance.sharepoint.com", None, HYGIENE),
    ("gitlab.sharepoint.com", None, HYGIENE),
    ("mbway.sharepoint.com", None, HYGIENE),
    ("pochtabank.sharepoint.com", None, HYGIENE),
    # a tenant by that name exists but is not the one behind the brand's
    # domain (measured 2026-11-04: facebook-my, lloyds-my, socialsecurity-my;
    # ozon and tbank are Russian-list brands)
    ("facebook-my.sharepoint.com", 0.95, HYGIENE),
    ("facebook-admin.sharepoint.com", 0.95, HYGIENE),
    ("socialsecurity-my.sharepoint.com", 0.95, HYGIENE),
    ("whatsapp-my.sharepoint.com", 0.95, HYGIENE),
    ("lloyds-my.sharepoint.com", 0.95, HYGIENE),
    ("ozon.sharepoint.com", None, HYGIENE),
    ("tbank.sharepoint.com", None, HYGIENE),
    # a brand-named tenant measured but not as the brand's (allegro, santander)
    ("allegro-my.sharepoint.com", 0.95, HYGIENE),
    ("santander-my.sharepoint.com", 0.95, HYGIENE),
    # a verified brand's word, but in another cloud: no brand-owned tenant
    # measured there (wellsfargo, binance .partner.onmschina.cn do not exist)
    ("wellsfargo-my.sharepoint.cn", 0.95, HYGIENE),
    ("binance-my.sharepoint.cn", 0.95, HYGIENE),
    ("microsoft.sharepoint-df.com", 0.95, HYGIENE),
    # a verified brand with a hyphen inserted: not the tenant's name
    ("pay-pal-my.sharepoint.com", 0.95, HYGIENE),
])
def test_a_brand_named_tenant_not_verified_as_the_brand_s_is_judged_as_on_main(model, host, opinion, extra):
    """Only the tenants in data/organization_tenants.json get the weak name
    signals: a brand word as a tenant's whole name is a name anyone can take
    where the brand has no tenant by it (review 2026-11-04: telegram-my on
    the previous head was caution 50, on main dangerous 70)."""
    assert scoring.organization_tenant_brand(host) is None
    model(opinion)
    score, level, reasons = _score(host, **extra)
    assert level == "dangerous" and score > scoring.DANGEROUS_ABOVE
    assert reasons.get("ml_high_risk") == 35 or reasons.get("brand_subdomain_abuse") == 30


@pytest.mark.parametrize("host, opinion, signal", [
    # a brand misspelt (each exists in DNS; review 2026-11-04: none is the
    # brand's own Entra tenant; main 60-75 'dangerous' by the model)
    ("micosoft-my.sharepoint.com", 0.95, "ml_high_risk"),
    ("mircosoft-my.sharepoint.com", 0.95, "ml_high_risk"),
    ("mircosoft.sharepoint.com", 0.95, "ml_high_risk"),
    ("0ffice365.sharepoint.com", 0.95, "ml_high_risk"),
    ("0ffice365-my.sharepoint.com", 0.95, "ml_high_risk"),
    # a brand with a word added
    ("microsoftteams.sharepoint.com", 0.95, "ml_high_risk"),
    ("microsoftteams-my.sharepoint.com", 0.95, "ml_high_risk"),
    ("outlook365.sharepoint.com", 0.95, "ml_high_risk"),
    ("docusignus-my.sharepoint.com", 0.95, "ml_high_risk"),
    ("barclaysdocs.sharepoint.com", 0.95, "ml_high_risk"),
    ("sberbankcloud-my.sharepoint.com", 0.95, "ml_high_risk"),
    ("microsoftdocuments-my.sharepoint.com", 0.95, "ml_high_risk"),
    ("microsoft365-my.sharepoint.com", 0.7, "ml_suspicious"),
    ("microsoftsharing-my.sharepoint.com", 0.7, "ml_suspicious"),
    # no brand at all: phishing tenants in the Phishing.Database snapshot
    ("appriver3651007637-my.sharepoint.com", 0.95, "ml_high_risk"),
    ("appriver3651009905-my.sharepoint.com", 0.7, "ml_suspicious"),
])
def test_on_a_tenant_not_named_exactly_after_a_brand_the_model_counts_in_full(model, host, opinion, signal):
    """Only a tenant named exactly after a brand is how the brand's own tenant
    looks; on any other name the model's opinion is as strong as on main."""
    model(None)
    assert _score(host, **HYGIENE)[1] != "dangerous"      # the name's shape and hygiene alone: no
    model(opinion)
    score, level, reasons = _score(host, **HYGIENE)
    assert level == "dangerous" and score > scoring.DANGEROUS_ABOVE
    assert reasons[signal] == {"ml_high_risk": 35, "ml_suspicious": 20}[signal]


@pytest.mark.parametrize("host", [
    "paypal-docs.sharepoint.com",
    "microsoft-docs.sharepoint.com",
    "docusign-us.sharepoint.com",
])
def test_a_brand_word_beside_another_word_still_lifts_the_weak_signal_cap(model, host):
    """A brand as one word of a longer name (_tenant_brand_word) lets weak
    signals add up past caution, as on every hosting platform: that is not
    how a brand's own tenant is named."""
    score, level, reasons = _score(host, **MORE_HYGIENE)
    assert "brand_subdomain_abuse" not in reasons
    assert level == "dangerous" and score > scoring.DANGEROUS_ABOVE


@pytest.mark.parametrize("host, brand", [
    ("microsoft-my.sharepoint.com", "microsoft"),       # OneDrive for Business
    ("microsoft-admin.sharepoint.com", "microsoft"),    # the SharePoint admin centre
    ("barclays.sharepoint.com", "barclays"),
    ("BARCLAYS-MY.SharePoint.com.", "barclays"),
    ("tele2.sharepoint.com", "tele2"),                  # a Russian-list brand of 4+ letters
    ("royalmail.sharepoint.com", "royalmail"),          # a site, no OneDrive: the same tenant
    ("royalmail-admin.sharepoint.com", "royalmail"),
    ("pay-pal.sharepoint.com", None),                   # hyphens are not removed
    ("microsoft.sharepoint-df.com", None),              # other clouds: none verified
    ("wellsfargo-my.sharepoint.cn", None),
    ("telegram-my.sharepoint.com", None),               # a brand word, no tenant of the brand's
    ("facebook-my.sharepoint.com", None),               # a tenant, not the one behind facebook.com
    ("ozon.sharepoint.com", None),
    ("allegro-my.sharepoint.com", None),
    ("micosoft-my.sharepoint.com", None),               # misspelt
    ("microsoft365-my.sharepoint.com", None),           # a brand with something added
    ("barclaysdocs.sharepoint.com", None),
    ("paypal-docs.sharepoint.com", None),
    ("microsoft-my-my.sharepoint.com", None),           # only Microsoft's own suffix, once
    ("appriver3651007637-my.sharepoint.com", None),
    ("contoso-my.sharepoint.com", None),
    ("my.sharepoint.com", None),
    ("x.microsoft-my.sharepoint.com", None),            # not a tenant's own site
    ("microsoft.sharepoint.com", None),                 # the operator's host: allowlisted
    ("microsoft-my.vercel.app", None),                  # not a Microsoft 365 tenant
])
def test_which_tenants_are_named_exactly_after_a_brand(host, brand):
    assert scoring.organization_tenant_brand(host) == brand


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
    "sberbank-online.sharepoint.com",
    "tele2-bonus.sharepoint.com",
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


@pytest.mark.parametrize("host", [
    "contoso-my.sharepoint.com",
    # named exactly after a brand: the model's opinion is weak there, the
    # reports are what makes it 'dangerous'
    "microsoft-my.sharepoint.com",
])
def test_fresh_otx_reports_beside_the_name_make_it_dangerous(model, host):
    """One to five fresh OTX reports are strong (not WEAK_SIGNALS): with the
    model's opinion and hygiene they still make 'dangerous'."""
    model(0.95)
    _, level, reasons = _score(host, **HYGIENE, alienvault_indicator="hostname",
                               alienvault_pulse_count=2, alienvault_distinct_pulses=2,
                               alienvault_newest_report_days=5)
    assert reasons["alienvault_otx"] == 30 and level == "dangerous"


@pytest.mark.parametrize("host, expected", [
    ("contoso.sharepoint.com", True),
    ("contoso-my.sharepoint.com", True),
    ("CONTOSO-MY.SharePoint.com.", True),
    ("contoso-my.sharepoint.cn", False),        # 21Vianet's SharePoint (China): no verified tenant
    ("microsoft.sharepoint-df.com", False),     # Microsoft's pre-release ring: none verified
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


def test_the_verified_tenant_list_is_checked_data():
    """data/organization_tenants.json: each name is a brand word the scorer
    knows, with the brand's domain and the Entra tenant both resolve to."""
    import json
    import os
    import re
    path = os.path.join(os.path.dirname(scoring.__file__), "..", "..", "data", "organization_tenants.json")
    with open(path) as f:
        doc = json.load(f)
    assert doc["checked"] == "2026-11-04"
    tenants = doc["tenants"]
    assert len(tenants) == 37
    assert set(tenants) == set(scoring.VERIFIED_ORGANIZATION_TENANTS)
    for name, entry in tenants.items():
        assert name in scoring._TENANT_BRAND_WORDS, name
        assert re.fullmatch(r"[a-z0-9]+", name), name
        assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", entry["entra_tenant"]), name
        assert "." in entry["domain"], name
    # the names of the review's no-tenant and other-owner cases are not in it
    for name in ("telegram", "binance", "tinkoff", "kucoin", "sovcombank", "pochtabank", "aliexpress",
                 "facebook", "lloyds", "socialsecurity", "whatsapp", "ozon", "tbank", "allegro", "santander"):
        assert name not in tenants, name


def test_no_list_means_no_tenant_is_trusted(tmp_path, monkeypatch):
    """A missing or broken file fails closed: every tenant is judged as on main."""
    monkeypatch.setattr(scoring, "_DATA_DIR", str(tmp_path))
    assert scoring._load_verified_organization_tenants() == frozenset()
    (tmp_path / "organization_tenants.json").write_text("{not json")
    assert scoring._load_verified_organization_tenants() == frozenset()
    (tmp_path / "organization_tenants.json").write_text('{"tenants": {"telegram": {}, "Bad-Name": {}}}')
    assert scoring._load_verified_organization_tenants() == frozenset({"telegram"})

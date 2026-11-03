"""The name rules on the platforms found after the served model was trained
(data/hosting_platforms.json tenant_suffixes_not_in_model: zapier.app,
edgeone.dev), and the model's verdict there.

Until the retrain the name rules read nothing of a tenant's name there:
neither the platform's ('zapier' and 'edgeone' were judged for every tenant
before 2026-11-03) nor yet the customer's. The served model already judges
that name without knowing the zone is shared (is_hosting_subdomain 0), and
reading the customer's label beside it moved 48 sites that look real by
their page titles up a level on the 602 live tenants of the Common Crawl
index, 28 of them to 'dangerous' (PR #396). After the retrain the rules
read the customer's label, without what the platform generated: the six hex
digits Zapier adds and its default project names (zapbot-3afcd4).

The model's verdict counts as on any other site: a rule that made it weak
on these zones cost a confirmed phish its 'dangerous'
(gastric-turquoise-uqpzxsmk.edgeone.dev, review of #396).
"""
from __future__ import annotations

import random

import pytest

from api.services import hosting_platforms as hp
from api.services import scoring

NOT_IN_MODEL = sorted(hp.TENANT_SUFFIXES_NOT_IN_MODEL)
# Left out after the measured pass of #396: read as before.
LEFT_OUT = ("ac-page.com", "hospedagemdesites.ws")

# The name-shape rules (scoring 3.13-3.32).
LEXICAL = {
    "high_entropy", "medium_entropy", "high_digit_ratio", "long_domain_name",
    "unnatural_ngram", "suspicious_ngram", "abnormal_vowel_ratio", "consonant_cluster",
}
NAME_JUDGED = LEXICAL | {"suspicious_keyword"}

# Hygiene a real site often shows: no security headers, a renewed
# certificate, two hops.
WEAK = dict(missing_security_headers=["csp", "hsts", "xfo"], cert_age_days=2, redirect_count=2)

# What every Zapier and EdgeOne tenant shows the probes: no security headers
# (missing_headers +15 on all 71 hosts measured for #396) and the platform's
# wildcard certificate. A tenant name test without them has a 20-point
# margin no real tenant has (review of #396).
PLATFORM = dict(site_reachable=True, cert_wildcard=True, cert_age_days=30,
                missing_security_headers=["content-security-policy", "strict-transport-security", "x-frame-options"])


def _signals(domain: str, **extra) -> dict:
    return {"domain": domain, "raw_url": domain, "checks_succeeded": 18, "total_checks": 18, **extra}


def _by_name(host: str):
    score, level, reasons = scoring.calculate_score({"domain": host, "raw_url": host})
    return score, level.value, {r.signal for r in reasons if r.weight > 0}


# ── The name rules read no tenant's name there until the retrain ──

@pytest.fixture
def after_the_retrain(monkeypatch):
    """The name rules as they will read these zones once the retrain moves
    them into tenant_suffixes (the model then knows them as shared)."""
    monkeypatch.setattr(scoring, "TENANT_SUFFIXES_NOT_IN_MODEL", frozenset())


@pytest.mark.parametrize("suffix", NOT_IN_MODEL)
def test_until_the_retrain_no_tenant_label_is_judged(suffix):
    """Neither the platform's name ('zapier', 'edgeone' before 2026-11-03)
    nor yet the customer's: with the served model judging the same name, it
    put 28 real sites at 'dangerous' (scoring._TENANT_LABEL_SUFFIXES)."""
    for host in (f"my-bakery.{suffix}", f"shop.my-bakery.{suffix}", f"paypal-login.{suffix}"):
        assert scoring._tenant_label(host) == "", host
    assert scoring._tenant_label(suffix) is None
    assert scoring._tenant_label(f"www.{suffix}") is None


@pytest.mark.parametrize("suffix", NOT_IN_MODEL)
def test_the_customers_label_is_the_name_judged_after_the_retrain(suffix, after_the_retrain):
    assert scoring._tenant_label(f"my-bakery.{suffix}") == "my-bakery"
    assert scoring._tenant_label(f"shop.my-bakery.{suffix}") == "my-bakery"
    assert scoring._tenant_label(f"paypal-login.{suffix}") == "paypal-login"
    assert scoring._tenant_label(suffix) is None
    assert scoring._tenant_label(f"www.{suffix}") is None


@pytest.mark.parametrize("label", ["my-bakery", "shop.my-bakery"])
@pytest.mark.parametrize("suffix", NOT_IN_MODEL)
def test_a_plain_site_name_on_a_listed_platform_stays_safe_by_name(suffix, label):
    """A real customer's site is judged by its own name: nothing comes from
    the platform's name, nor from the level every tenant has by construction
    (shop.my-bakery is one level above the site my-bakery.<zone>, not two;
    with the first draft's 66 zones a plain name drew points from the
    platform's on 14 of them: 'mybluehost', 'clickfunnels', 'formstack')."""
    score, level, signals = _by_name(f"{label}.{suffix}")
    assert level == "safe", (suffix, label, score, signals)
    assert not signals & (LEXICAL | {"excessive_subdomains", "excessive_special_chars"}), (suffix, signals)
    if label == "my-bakery":
        assert "many_special_chars" not in signals, (suffix, signals)


@pytest.mark.parametrize("suffix", NOT_IN_MODEL)
def test_a_lure_name_is_judged_on_the_customers_label_after_the_retrain(suffix, after_the_retrain):
    """paypal-login.<zone> will read 'paypal-login', as on the curated
    platforms (netlify.app): before 2026-11-03 it read 'zapier' and
    'edgeone'."""
    host = f"paypal-login.{suffix}"
    reference = _by_name("paypal-login.netlify.app")[2] & NAME_JUDGED
    assert "suspicious_keyword" in reference
    assert _by_name(host)[2] & NAME_JUDGED == reference, suffix


@pytest.mark.parametrize("host,on_main", [
    # real sites that reading the customer's label put at 'dangerous'
    ("emnlp-2025-speakers.zapier.app", (43, "caution")),
    ("zapier-blog-suggestions.zapier.app", (43, "caution")),
    ("familia-de-magdala.zapier.app", (43, "caution")),
    ("productivitybootcamp.edgeone.dev", (50, "caution")),
    # and at caution
    ("evrotobg.zapier.app", (15, "safe")), ("getoutandtry.zapier.app", (15, "safe")),
    ("aiovtue.edgeone.dev", (15, "safe")),
])
def test_real_tenants_are_judged_as_on_main_until_the_retrain(host, on_main):
    """The 602 live tenants of the Common Crawl index, measured with the
    full analyzer on 2026-11-03: none changes level against main."""
    score, level, reasons = scoring.calculate_score(_signals(host, **PLATFORM))
    assert not {r.signal for r in reasons if r.weight > 0} & NAME_JUDGED
    assert (score, level.value) == on_main


@pytest.mark.parametrize("host,signal", [
    # two levels above the customer's own site are still two
    ("a.b.my-bakery.zapier.app", "excessive_subdomains"),
    ("a.b.my-bakery.edgeone.dev", "excessive_subdomains"),
    # and the customer's own hyphens still count
    ("secure-verify-account-login.zapier.app", "excessive_special_chars"),
])
def test_the_customers_own_shape_still_counts(host, signal):
    assert signal in _by_name(host)[2]


@pytest.mark.parametrize("host,site", [
    ("shop.my-bakery.zapier.app", "my-bakery.zapier.app"),
    ("my-bakery.edgeone.dev", "my-bakery.edgeone.dev"),
    ("my-bakery.netlify.app", None), ("www.zapier.app", None), ("zapier.app", None),
    # left out after the measured pass: read as before
    *((f"shop.my-bakery.{zone}", None) for zone in LEFT_OUT),
])
def test_the_site_the_shape_rules_count_from(host, site):
    assert scoring._not_in_model_tenant_site(host) == site


@pytest.mark.parametrize("zone", LEFT_OUT)
def test_the_left_out_zones_are_named_as_before(zone):
    assert scoring._tenant_label(f"my-bakery.{zone}") is None
    assert scoring._platform_tenant_site(f"my-bakery.{zone}") is None


@pytest.mark.parametrize("host", ["shop.my-bakery.netlify.app", "a.b.duckdns.org"])
def test_the_curated_platforms_are_read_as_before(host):
    """Out of scope here: on the curated lists the address-shape rules still
    count from the platform (a measured pass of its own)."""
    assert "excessive_subdomains" in _by_name(host)[2]


# ── Zapier's own default addresses are not the customer's name ──

# Today (the zone reads as nothing) and once the retrain lets the rules read
# the customer's label.
WHEN = ["today", "after_the_retrain"]


def _when(request, when):
    if when == "after_the_retrain":
        request.getfixturevalue("after_the_retrain")


@pytest.mark.parametrize("label,suffix,customers", [
    ("zapbot-3afcd4", "zapier.app", ""), ("faqbot-7323fc", "zapier.app", ""),
    ("form-interface-c45407", "zapier.app", ""), ("new-form-project-bc6d19", "zapier.app", ""),
    # a name the customer typed keeps its words, without Zapier's hex
    ("biroq-consulting-5b6b12", "zapier.app", "biroq-consulting"),
    ("paypal-login-1a2b3c", "zapier.app", "paypal-login"),
    # Zapier's own id for the page
    ("cmp8f64bv001l4v51du7zjkae", "zapier.app", ""), ("cmr0hmmju0043sagds5pvb9nk", "zapier.app", ""),
    # an address the customer picked is read whole
    ("evrotobg", "zapier.app", "evrotobg"), ("youmoneypl-04172025", "zapier.app", "youmoneypl-04172025"),
    ("publicsectorcapabilitiesindex", "zapier.app", "publicsectorcapabilitiesindex"),
    # a customer's word of the same length, no digits
    ("competitionscandicflowxyz", "zapier.app", "competitionscandicflowxyz"),
    # only on zapier.app
    ("zapbot-3afcd4", "edgeone.dev", "zapbot-3afcd4"),
    ("polite-tulumba-704e1b", "netlify.app", "polite-tulumba-704e1b"),
])
def test_what_zapier_generated_is_left_out_of_the_name(label, suffix, customers):
    assert scoring._without_generated_slug(label, suffix) == customers


@pytest.mark.parametrize("host,label", [
    ("zapbot-3afcd4.zapier.app", ""), ("www.new-form-project-bc6d19.zapier.app", ""),
    ("biroq-consulting-5b6b12.zapier.app", "biroq-consulting"), ("evrotobg.zapier.app", "evrotobg"),
])
def test_the_label_judged_after_the_retrain_leaves_out_what_zapier_generated(host, label, after_the_retrain):
    assert scoring._tenant_label(host) == label


@pytest.mark.parametrize("when", WHEN)
@pytest.mark.parametrize("name", sorted(scoring._ZAPIER_DEFAULT_NAMES))
def test_no_name_rule_judges_a_default_zapier_address(name, when, request):
    """zapbot-3afcd4 (a chatbot named 'LeeAnn', 2024-01) went from safe 15
    to caution 31 on its hex alone, faqbot-7323fc (a support bot) to 25:
    the name rules read '3afcd4' (review of #396). The model and the
    address-wide hyphen count (3.15) still read the host, as on main."""
    _when(request, when)
    rng = random.Random(name)
    for _ in range(40):
        host = f"{name}-{rng.getrandbits(24):06x}.zapier.app"
        _, _, reasons = scoring.calculate_score(_signals(host, **PLATFORM))
        assert not {r.signal for r in reasons if r.weight > 0} & NAME_JUDGED, host


@pytest.mark.parametrize("when", WHEN)
@pytest.mark.parametrize("name", ["zapbot", "faqbot"])
def test_a_chatbot_on_its_default_address_stays_safe(name, when, request):
    """Every one of 200 random zapbot-<hex> hosts went from safe to caution
    with the platform's signals (review of #396)."""
    _when(request, when)
    rng = random.Random(name)
    for host in [f"{name}-3afcd4.zapier.app", f"{name}-7323fc.zapier.app"] + [
            f"{name}-{rng.getrandbits(24):06x}.zapier.app" for _ in range(200)]:
        score, level, _ = scoring.calculate_score(_signals(host, **PLATFORM))
        assert (score, level.value) == (15, "safe"), host


def test_a_customers_name_before_zapiers_hex_is_judged_as_without_it(after_the_retrain):
    assert _by_name("paypal-login-1a2b3c.zapier.app")[2] & NAME_JUDGED == _by_name("paypal-login.zapier.app")[2] & NAME_JUDGED
    assert "suspicious_keyword" in _by_name("paypal-login-1a2b3c.zapier.app")[2]


@pytest.mark.parametrize("when", WHEN)
@pytest.mark.parametrize("suffix", NOT_IN_MODEL)
def test_a_plain_site_name_with_the_platforms_signals_stays_safe(suffix, when, request):
    _when(request, when)
    score, level, reasons = scoring.calculate_score(_signals(f"my-bakery.{suffix}", **PLATFORM))
    assert (score, level.value) == (15, "safe"), [r.signal for r in reasons]


# ── The model's verdict counts on these tenants (review of #396) ──

@pytest.fixture
def model_says_phishing(monkeypatch):
    from api.services import ml_scorer

    monkeypatch.setattr(ml_scorer, "ml_predict", lambda domain: {"phishing_probability": 0.95, "confidence": 0.9})


@pytest.mark.parametrize("host,extra,on_main", [
    # docs/benchmarks/2026-08-17-fresh-urls.json: 'dangerous 58' in
    # production, the model's 0.95 + missing headers + the hyphens
    ("gastric-turquoise-uqpzxsmk.edgeone.dev", {}, 58),
    # the other EdgeOne phish of the benchmarks (the model's 0.92-0.93):
    # one more weak signal makes them 'dangerous 65' on main
    ("bigbuxshop-dpsbmzniwema.edgeone.dev", {"dns_ttl": 30}, 65),
    ("supprtrcb-dpldxysyz96q.edgeone.dev", {"dns_ttl": 30}, 65),
    ("mailbox-dpr3yixp1qk1.edgeone.dev", {"dns_ttl": 30}, 65),
])
def test_the_model_still_makes_a_confirmed_phish_dangerous(host, extra, on_main):
    """The first version of this PR made the model's verdict a weak signal
    on these zones and capped these at caution 50. Replaces the test that
    pinned that cap (new-form-project-bc6d19.zapier.app at caution 50: a
    real site the model puts at 'dangerous', as it does on main)."""
    score, level, reasons = scoring.calculate_score(_signals(host, **PLATFORM, **extra))
    assert "ml_high_risk" in {r.signal for r in reasons}
    assert level.value == "dangerous" and score >= on_main, (score, [r.signal for r in reasons])


@pytest.mark.parametrize("host,extra", [
    # OTX reports, now that the platform's rank waives none
    ("divace-coinsquare.zapier.app", {"alienvault_pulse_count": 3}),
    # a brand in the customer's own name (_tenant_brand_word)
    ("ledger-start-ldgrlive.zapier.app", {}),
])
def test_a_strong_signal_still_makes_a_tenant_dangerous(model_says_phishing, host, extra):
    _, level, _ = scoring.calculate_score(_signals(host, **WEAK, **extra))
    assert level.value == "dangerous"


def test_on_the_curated_platforms_the_model_counts_as_before(model_says_phishing):
    _, level, _ = scoring.calculate_score(_signals("new-form-project-bc6d19.netlify.app", **WEAK))
    assert level.value == "dangerous"

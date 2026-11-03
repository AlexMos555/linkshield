"""Shared platforms found after the served model was trained: a tenant never
inherits its platform's popularity rank (or, for a top-100k platform, its
allowlist trust), the name rules judge the customer's own name, and the
model's verdict on the tenant is weak until a retrain teaches it the zone.

zapier.app (Zapier Interfaces) and edgeone.dev (Tencent EdgeOne Pages)
carried PhishTank phishing in the weekly benchmarks of 2026-06-17 to
2026-11-01 with no tenant rule, so their rank, where production has one,
spoke for every tenant: an OTX report of one to five pulses was waived.

data/hosting_platforms.json tenant_suffixes would also move the ML model's
tenant feature (ml_features.shared_tenant), which changes only with a retrain
(model_meta.json shared_suffixes). These platforms are its separate
'tenant_suffixes_not_in_model' list: the allowlist, the rank readers and the
name rules take it, the model does not (as 'not_in_model' in
data/typosquat_targets.json).
"""
from __future__ import annotations

import json
import os

import pytest

from api.services import hosting_platforms as hp
from api.services import scoring
from api.services.ml_features import extract_ml_features, shared_tenant

DATA = os.path.join(os.path.dirname(__file__), "..", "data", "hosting_platforms.json")
NOT_IN_MODEL = sorted(hp.TENANT_SUFFIXES_NOT_IN_MODEL)

# Each zone joined after the full analyzer was run on its real tenants'
# sites and on its known phishing, before and after (PR #396, 2026-11-03).
# A new zone needs the same pass. The first draft listed 66, and real
# Tistory blogs, Cafe24 shops and Wufoo forms went from 'safe' to caution
# 30 on the platforms' own DNS and headers. The pass also left out the three
# top-100k zones it started from: out of the allowlist, about half of
# Bluehost's real temporary addresses (mybluehost.me) went to caution, 16 of
# 41 ActiveCampaign pages (ac-page.com) and all 20 Locaweb sites measured
# (hospedagemdesites.ws).
MEASURED = frozenset({"zapier.app", "edgeone.dev"})
LEFT_OUT = ("mybluehost.me", "ac-page.com", "hospedagemdesites.ws")

# The allowlist-only zones of 2026-10-27 (sakura.ne.jp, hostgator.com.br …):
# their rank rule stays as it was until it is measured on their operators'
# own hosts.
OLDER_ALLOWLIST_ONLY = sorted(scoring._ALLOWLIST_TENANT_ZONES - hp.TENANT_SUFFIXES_NOT_IN_MODEL)

# Phishing tenants of the weekly benchmarks (docs/benchmarks/*-fresh-urls.json,
# PhishTank, 2026-06-17 to 2026-11-01).
SEEN_PHISHING = [
    "ledgr-start.zapier.app", "divace-coinsquare.zapier.app",
    "yourmailaccount.edgeone.dev", "mailbox-dpr3yixp1qk1.edgeone.dev",
    "gastric-turquoise-uqpzxsmk.edgeone.dev", "supprtrcb-dpldxysyz96q.edgeone.dev",
    "bigbuxshop-dpsbmzniwema.edgeone.dev",
]

# The name-shape rules (scoring 3.13-3.32).
LEXICAL = {
    "high_entropy", "medium_entropy", "high_digit_ratio", "long_domain_name",
    "unnatural_ngram", "suspicious_ngram", "abnormal_vowel_ratio", "consonant_cluster",
}
NAME_JUDGED = LEXICAL | {"suspicious_keyword"}

# Hygiene a real site often shows: no security headers, a renewed
# certificate, two hops.
WEAK = dict(missing_security_headers=["csp", "hsts", "xfo"], cert_age_days=2, redirect_count=2)


def _signals(domain: str, **extra) -> dict:
    return {"domain": domain, "raw_url": domain, "checks_succeeded": 18, "total_checks": 18, **extra}


def _otx(reasons) -> int:
    return sum(r.weight for r in reasons if r.signal.startswith("alienvault_otx"))


def _by_name(host: str):
    score, level, reasons = scoring.calculate_score({"domain": host, "raw_url": host})
    return score, level.value, {r.signal for r in reasons if r.weight > 0}


# ── The list ──

def test_the_list_is_loaded_and_well_formed():
    with open(DATA) as f:
        groups = json.load(f)["tenant_suffixes_not_in_model"]
    assert isinstance(groups.get("_why"), str) and "retrain" in groups["_why"]
    listed = [n for k, names in groups.items() if not k.startswith("_") for n in names]
    assert len(listed) == len(set(listed)) == len(NOT_IN_MODEL)
    for name in NOT_IN_MODEL:
        assert name == name.lower().strip(".") and "." in name and " " not in name, name


def test_only_measured_zones_are_listed():
    assert hp.TENANT_SUFFIXES_NOT_IN_MODEL == MEASURED


def test_the_list_names_no_suffix_the_model_or_another_list_already_has():
    """Once a retrain moves a name into tenant_suffixes it leaves this list."""
    known = (scoring._SCORER_SHARED_SUFFIXES | hp.TENANT_SUFFIXES | hp.DYNAMIC_DNS_SUFFIXES
             | hp.USER_CONTENT_HOSTS | hp.OPERATOR_SUFFIXES)
    assert hp.TENANT_SUFFIXES_NOT_IN_MODEL.isdisjoint(known)


def test_no_top_entry_sits_under_a_listed_suffix():
    """Every top-100k entry is its own registrant's site, so none may become a
    'tenant' here: the rule only ever takes trust from names under a platform."""
    under = [d for d in scoring.TOP_DOMAINS
             if any(d.endswith("." + s) for s in hp.TENANT_SUFFIXES_NOT_IN_MODEL)]
    assert under == []


def test_missing_list_degrades_to_nothing(tmp_path):
    assert hp._load_tenant_suffixes_not_in_model(str(tmp_path / "absent.json")) == frozenset()


# ── The allowlist ──

@pytest.mark.parametrize("host", SEEN_PHISHING)
def test_seen_phishing_tenants_are_not_instant_safe(host):
    assert scoring.is_trusted_top_domain(host) is False


@pytest.mark.parametrize("suffix", NOT_IN_MODEL)
def test_no_tenant_of_a_listed_platform_is_trusted(suffix):
    assert scoring.is_trusted_top_domain(f"zq7tenant.{suffix}") is False
    assert scoring.is_trusted_top_domain(f"a.zq7tenant.{suffix}") is False
    assert suffix in scoring._ALLOWLIST_TENANT_ZONES


# ── The popularity rank ──

# zapier.app and edgeone.dev are not top-100k names: their top-1M rank is in
# production Redis only, so these ranks are assumed.
@pytest.mark.parametrize("host,platform_rank", [
    ("divace-coinsquare.zapier.app", 150_000),
    ("www.divace-coinsquare.zapier.app", 150_000),
    ("bigbuxshop-dpsbmzniwema.edgeone.dev", 400_000),
])
def test_a_tenant_does_not_take_its_platforms_rank(host, platform_rank):
    assert scoring.popularity_rank({"tranco_registrable_rank": platform_rank}, host) is None
    _, _, reasons = scoring.calculate_score(_signals(
        host, alienvault_pulse_count=3, tranco_registrable_rank=platform_rank))
    assert _otx(reasons) == 30, host


def test_a_tenant_ranked_itself_is_judged_by_its_own_rank():
    sig = _signals("popular-tenant.zapier.app", tranco_ranked=True, tranco_rank=50_000,
                   tranco_weight=-8, tranco_registrable_rank=150_000)
    assert scoring.popularity_rank(sig) == 50_000


@pytest.mark.parametrize("host,rank", [
    ("zapier.app", 150_000), ("www.zapier.app", 150_000),
    ("edgeone.dev", 400_000), ("www.edgeone.dev", 400_000),
])
def test_the_platforms_own_names_keep_its_rank(host, rank):
    assert scoring.popularity_rank({"tranco_registrable_rank": rank}, host) == rank
    _, _, reasons = scoring.calculate_score(_signals(host, alienvault_pulse_count=3, tranco_registrable_rank=rank))
    assert _otx(reasons) == 0, host


@pytest.mark.parametrize("host,site", [
    ("divace-coinsquare.zapier.app", "divace-coinsquare.zapier.app"),
    ("www.divace-coinsquare.zapier.app", "divace-coinsquare.zapier.app"),
    ("supprtrcb-dpldxysyz96q.edgeone.dev", "supprtrcb-dpldxysyz96q.edgeone.dev"),
])
def test_the_customers_own_name_is_what_rdap_surbl_and_otx_read(host, site):
    assert scoring._platform_tenant_site(host) == site


def test_the_older_allowlist_only_zones_keep_their_rank_rule():
    """Their tenants' rank hole is the same, but closing it also takes the
    platform's rank from the operators' own hosts under the zone, which no
    list names yet (review of #396: financeiro.hostgator.com.br, safe 20 ->
    caution 25). A follow-up measures it on those hosts first."""
    assert len(OLDER_ALLOWLIST_ONLY) == 11
    assert scoring._RANK_TENANT_SUFFIXES.isdisjoint(OLDER_ALLOWLIST_ONLY)


@pytest.mark.parametrize("host,rank", [
    ("financeiro.hostgator.com.br", 54_905), ("loja.hostgator.com.br", 54_905),
])
def test_an_operators_own_host_keeps_its_platforms_rank(host, rank):
    score, level, reasons = scoring.calculate_score(_signals(host, tranco_registrable_rank=rank, **WEAK))
    assert "new_certificate" not in {r.signal for r in reasons}
    assert (score, level.value) == (20, "safe")


# ── The name rules judge the customer's name ──

@pytest.mark.parametrize("suffix", NOT_IN_MODEL)
def test_the_customers_label_is_the_name_judged(suffix):
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
def test_a_lure_name_is_judged_on_the_customers_label(suffix):
    """paypal-login.<zone> reads 'paypal-login', as on the curated platforms
    (netlify.app): until now it read 'zapier' and 'edgeone'."""
    host = f"paypal-login.{suffix}"
    reference = _by_name("paypal-login.netlify.app")[2] & NAME_JUDGED
    assert "suspicious_keyword" in reference
    assert _by_name(host)[2] & NAME_JUDGED == reference, suffix


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


# ── The model's verdict on these tenants is weak until the retrain ──

@pytest.fixture
def model_says_phishing(monkeypatch):
    from api.services import ml_scorer

    monkeypatch.setattr(ml_scorer, "ml_predict", lambda domain: {"phishing_probability": 0.95, "confidence": 0.9})


def test_the_models_verdict_alone_with_weak_signals_is_a_caution(model_says_phishing):
    """The served model never saw these zones as shared (is_hosting_subdomain
    0): measured 2026-11-03 it put 2 of 22 real Zapier interfaces and 8 of
    18 real EdgeOne sites at 'dangerous' with nothing but weak signals
    beside it (new-form-project-bc6d19, claude-agent-starter-python). That
    is a caution."""
    host = "new-form-project-bc6d19.zapier.app"
    score, level, reasons = scoring.calculate_score(_signals(host, **WEAK))
    assert "ml_high_risk" in {r.signal for r in reasons}
    assert (score, level.value) == (scoring.DANGEROUS_ABOVE, "caution")


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


# ── The model reads none of it ──

@pytest.mark.parametrize("suffix", NOT_IN_MODEL)
def test_the_model_still_reads_a_tenant_as_before(suffix):
    host = f"paypal-login.{suffix}"
    assert hp.tenant_suffix_of(host) is None
    assert hp.tenant_suffix_of(host, scoring._SCORER_SHARED_SUFFIXES) is None
    assert shared_tenant(host) == (None, None)
    assert scoring.is_hosting_platform_site(host) is False


def test_the_models_features_of_a_tenant_are_unchanged():
    features = extract_ml_features("divace-coinsquare.zapier.app")
    assert features["is_hosting_subdomain"] == 0.0
    assert features["in_top_domains"] == 0.0

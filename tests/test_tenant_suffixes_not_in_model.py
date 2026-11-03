"""Shared platforms found after the served model was trained: a tenant never
inherits its platform's allowlist trust or popularity rank.

zrg.okx.mybluehost.me, a PhishTank phish of 2026-11-01, came back from the
live /public/check as "safe 0", verdict_basis allowlist, without analysis:
mybluehost.me (Bluehost's temporary domains) is #11,072 of data/top_100k.json
and no tenant rule named it. zapier.app (Zapier Interfaces) and edgeone.dev
(Tencent EdgeOne Pages) carried phishing in the same weekly benchmarks with
no tenant rule either, so their rank, had they one, spoke for the tenants.

data/hosting_platforms.json tenant_suffixes would also move the ML model's
tenant feature (ml_features.shared_tenant), which changes only with a retrain
(model_meta.json shared_suffixes). These platforms are its separate
'tenant_suffixes_not_in_model' list: the allowlist and the rank readers take
it, the model does not (as 'not_in_model' in data/typosquat_targets.json).
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
TOP_NOT_IN_MODEL = [s for s in NOT_IN_MODEL if s in scoring.TOP_DOMAINS]

# Phishing tenants of the weekly benchmarks (docs/benchmarks/*-fresh-urls.json,
# PhishTank) and of the 2026-10-21 URLhaus snapshot.
SEEN_PHISHING = [
    "zrg.okx.mybluehost.me",
    "divace-coinsquare.zapier.app", "ledgr-start.zapier.app",
    "bigbuxshop-dpsbmzniwema.edgeone.dev", "supprtrcb-dpldxysyz96q.edgeone.dev",
    "mailbox-dpr3yixp1qk1.edgeone.dev", "yourmailaccount.edgeone.dev",
    "nunziatatecnologie.ac-page.com", "embalageral.hospedagemdesites.ws",
]


def _signals(domain: str, **extra) -> dict:
    return {"domain": domain, "raw_url": domain, "checks_succeeded": 18, "total_checks": 18, **extra}


def _otx(reasons) -> int:
    return sum(r.weight for r in reasons if r.signal.startswith("alienvault_otx"))


# ── The list ──

def test_the_list_is_loaded_and_well_formed():
    with open(DATA) as f:
        groups = json.load(f)["tenant_suffixes_not_in_model"]
    assert isinstance(groups.get("_why"), str) and "retrain" in groups["_why"]
    assert {"mybluehost.me", "zapier.app", "edgeone.dev"} <= hp.TENANT_SUFFIXES_NOT_IN_MODEL
    listed = [n for k, names in groups.items() if not k.startswith("_") for n in names]
    assert len(listed) == len(set(listed)) == len(NOT_IN_MODEL)
    for name in NOT_IN_MODEL:
        assert name == name.lower().strip(".") and "." in name and " " not in name, name


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

def test_the_bluehost_tenant_is_not_instant_safe():
    from api.routers.check import _quick_allowlist_check

    host = "zrg.okx.mybluehost.me"
    assert scoring.top_domain_key(host) == "mybluehost.me"
    assert scoring.is_trusted_top_domain(host) is False
    assert _quick_allowlist_check(host) is None
    _, _, reasons = scoring.calculate_score(_signals(host))
    assert "known_legitimate" not in {r.signal for r in reasons}


def test_public_check_analyses_the_bluehost_tenant(monkeypatch, fake_redis):
    from fastapi.testclient import TestClient

    from api.main import app
    from api.models.schemas import DomainResult, RiskLevel
    from api.services import analyzer as analyzer_mod
    from api.services import competitor_verdicts

    analysed: list[str] = []

    async def _analyze(domain, *a, **k):
        analysed.append(domain)
        return DomainResult(domain=domain, score=30, level=RiskLevel.caution, reasons=[],
                            verdict_basis="heuristics")

    async def _no_competitors(*a, **k):
        return []

    monkeypatch.setattr(analyzer_mod, "analyze_domain", _analyze)
    monkeypatch.setattr(competitor_verdicts, "gather_competitor_verdicts", _no_competitors)
    body = TestClient(app).get("/api/v1/public/check/zrg.okx.mybluehost.me").json()
    assert analysed == ["zrg.okx.mybluehost.me"]
    assert body["verdict_basis"] != "allowlist", body


@pytest.mark.parametrize("host", SEEN_PHISHING)
def test_seen_phishing_tenants_are_not_instant_safe(host):
    assert scoring.is_trusted_top_domain(host) is False


@pytest.mark.parametrize("suffix", NOT_IN_MODEL)
def test_no_tenant_of_a_listed_platform_is_trusted(suffix):
    assert scoring.is_trusted_top_domain(f"zq7tenant.{suffix}") is False
    assert scoring.is_trusted_top_domain(f"a.zq7tenant.{suffix}") is False


@pytest.mark.parametrize("apex", TOP_NOT_IN_MODEL)
def test_the_platform_itself_keeps_its_trust(apex):
    assert scoring.is_trusted_top_domain(apex) is True
    assert scoring.is_trusted_top_domain(f"www.{apex}") is True


# ── The popularity rank ──

@pytest.mark.parametrize("host,platform_rank", [
    ("zrg.okx.mybluehost.me", 11_072),
    ("divace-coinsquare.zapier.app", 150_000),
    ("bigbuxshop-dpsbmzniwema.edgeone.dev", 400_000),
    ("nunziatatecnologie.ac-page.com", 33_601),
    ("forms.acme.wufoo.com", 1_245),
    # The allowlist-only zones of 2026-10-27 take the same rule.
    ("khakiweasel42.sakura.ne.jp", 756),
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
    ("mybluehost.me", 11_072), ("www.mybluehost.me", 11_072), ("www.zapier.app", 150_000),
    ("tistory.com", 2_703), ("www.tistory.com", 2_703),
])
def test_the_platforms_own_names_keep_its_rank(host, rank):
    assert scoring.popularity_rank({"tranco_registrable_rank": rank}, host) == rank
    _, _, reasons = scoring.calculate_score(_signals(host, alienvault_pulse_count=3, tranco_registrable_rank=rank))
    assert _otx(reasons) == 0, host


@pytest.mark.parametrize("host,site", [
    ("zrg.okx.mybluehost.me", "okx.mybluehost.me"),
    ("divace-coinsquare.zapier.app", "divace-coinsquare.zapier.app"),
    ("forms.acme.wufoo.com", "acme.wufoo.com"),
])
def test_the_customers_own_name_is_what_rdap_surbl_and_otx_read(host, site):
    assert scoring._platform_tenant_site(host) == site


@pytest.mark.parametrize("suffix", NOT_IN_MODEL)
def test_a_plain_site_name_on_a_listed_platform_stays_safe_by_name(suffix):
    """Out of the allowlist, a real customer's site is judged by the rest of
    the pipeline. Its name alone must not make a warning: a zone two levels
    under its registrable (blog.fc2.com) would give every tenant
    excessive_subdomains, so none is listed."""
    _, level, reasons = scoring.calculate_score({"domain": f"my-bakery.{suffix}"})
    assert level.value == "safe", (suffix, [r.signal for r in reasons])
    assert "excessive_subdomains" not in {r.signal for r in reasons}


# ── The model reads none of it ──

@pytest.mark.parametrize("suffix", NOT_IN_MODEL)
def test_the_model_still_reads_a_tenant_as_before(suffix):
    host = f"paypal-login.{suffix}"
    assert hp.tenant_suffix_of(host) is None
    assert hp.tenant_suffix_of(host, scoring._SCORER_SHARED_SUFFIXES) is None
    assert shared_tenant(host) == (None, None)
    assert scoring.is_hosting_platform_site(host) is False


def test_the_models_features_of_the_bluehost_tenant_are_its_platforms_name():
    features = extract_ml_features("zrg.okx.mybluehost.me")
    assert features["is_hosting_subdomain"] == 0.0
    assert features["in_top_domains"] == 1.0
    assert features["user_part_length"] == len("mybluehost")

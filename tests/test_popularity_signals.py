"""What the top-1M rank changes in a verdict besides its own bonus.

Since 2026-10-23 the allowlist (data/top_100k.json) is the licensed ranking
(Majestic Million + Chrome UX Report), and ~45,000 names Tranco's top 100k
carried now rank 100k-1M. Two rules had leaned on the allowlist alone and
turned those real sites into warnings once they left it:

* AlienVault OTX pulses mention popular sites as campaign victims. Gated on
  the allowlist files only, rostelecom.ru, rosbank.ru, beget.ru and
  dream11.com went from safe to caution 27, and ddos-guard.net to dangerous
  67. The OTX mention also counted as a blocklist hit, which keeps the LLM
  judge from looking at the caution.
* A company's own GitLab, Jira or Confluence (gitlab.tcsbank.ru,
  confluence.bcs.ru) drew brand_subdomain_abuse once the parent left the
  allowlist: 19 such hosts in CrUX Russia's top 50,000 went dangerous.

Also held here: the suffixes and shorteners the licensed list ranks that
must never be instant-safe, and government hosts that must never read as a
hosting tenant (the ICANN-suffix fold, scripts/build_top_domains.py).
"""
from __future__ import annotations

import pytest

from api.services import analyzer, scoring
from api.services.ml_features import shared_tenant


def _signals(domain: str, **extra) -> dict:
    return {"domain": domain, "raw_url": domain, "checks_succeeded": 18, "total_checks": 18, **extra}


def _otx(reasons) -> int:
    return sum(r.weight for r in reasons if r.signal.startswith("alienvault_otx"))


# ── OTX ──

@pytest.mark.parametrize("rank,pulses,weight", [
    (None, 3, 30), (None, 30, 60),            # unranked: full weight, as before
    (203_832, 3, 0), (175_389, 5, 0),         # top 1M, up to 5 pulses: a victim reference
    (432_973, 30, 30),                        # top 1M, more: halved
    (50_000, 30, 0), (100_000, 8, 0),         # top 100k: skipped
])
def test_otx_weight_follows_the_top_1m_rank(rank, pulses, weight):
    domain = "otx-gating-example.net"
    assert not scoring.is_trusted_top_domain(domain) and domain not in scoring.TOP_10K_RANKS
    extra = {"alienvault_pulse_count": pulses}
    if rank:
        extra.update(tranco_ranked=True, tranco_rank=rank, tranco_weight=-3 if rank > 100_000 else -8,
                     tranco_registrable_rank=rank)
    _, _, reasons = scoring.calculate_score(_signals(domain, **extra))
    assert _otx(reasons) == weight


def test_the_registrable_rank_gates_otx_for_a_subdomain():
    _, _, reasons = scoring.calculate_score(_signals(
        "shop.otx-gating-example.net", alienvault_pulse_count=4, tranco_registrable_rank=150_000))
    assert _otx(reasons) == 0


def _outcomes(pulses: int, tranco: dict) -> dict:
    return {"alienvault": ({"pulse_count": pulses, "hit": pulses > 0}, True), "tranco": (tranco, True)}


def test_an_otx_mention_of_a_ranked_name_is_not_a_blocklist_hit():
    """So the LLM judge (gate 2: blocklist_hits > 0 → skip) can still look at
    a caution the mention causes."""
    ranked = {"ranked": True, "rank": 432_973, "weight": -3, "label": "x", "registrable_rank": 432_973}
    sig = analyzer._build_signals("ddos-guard.net", "ddos-guard.net", False, _outcomes(30, ranked))
    assert sig["blocklist_hits"] == 0 and sig["tranco_registrable_rank"] == 432_973
    sub = {"ranked": False, "rank": None, "weight": 0, "label": "", "registrable_rank": 90_000}
    assert analyzer._build_signals("a.example.org", "", False, _outcomes(2, sub))["blocklist_hits"] == 0
    unranked = {"ranked": False, "rank": None, "weight": 0, "label": "", "registrable_rank": None}
    assert analyzer._build_signals("x.example", "", False, _outcomes(2, unranked))["blocklist_hits"] == 1


def test_a_ranked_name_with_otx_pulses_stays_out_of_dangerous():
    tranco = {"ranked": True, "rank": 432_973, "weight": -3, "label": "x", "registrable_rank": 432_973}
    sig = analyzer._build_signals("ddos-guard.net", "ddos-guard.net", False, _outcomes(30, tranco))
    _, level, _ = scoring.calculate_score(sig)
    assert level.value != "dangerous"


# ── A company's own GitLab ──

def _brand(reasons) -> bool:
    return any(r.signal == "brand_subdomain_abuse" for r in reasons)


def test_a_self_hosted_product_under_a_ranked_registrable_is_not_brand_abuse():
    _, _, reasons = scoring.calculate_score(_signals("gitlab.tcsbank.ru", tranco_registrable_rank=40_000))
    assert not _brand(reasons)
    for host in ("jira.rambler-co.ru", "confluence.bcs.ru", "bitbucket.example-corp.com"):
        _, _, reasons = scoring.calculate_score(_signals(host, tranco_registrable_rank=300_000))
        assert not _brand(reasons), host


@pytest.mark.parametrize("host,extra", [
    ("gitlab.tcsbank.ru", {}),                                          # parent not ranked
    ("git-lab.tcsbank.ru", {"tranco_registrable_rank": 40_000}),        # not the product's own label
    ("paypal.tcsbank.ru", {"tranco_registrable_rank": 40_000}),         # not a self-hosted product
])
def test_the_exemption_is_narrow(host, extra):
    _, _, reasons = scoring.calculate_score(_signals(host, **extra))
    assert _brand(reasons), host


# ── Never instant-safe ──

@pytest.mark.parametrize("host", [
    "x.easywp.com", "02-com.preview-domain.com", "airdrop.ct.ws", "bank.blogspot.cl", "a.blogspot.sk",
    "b.blogspot.ae", "c.byethost7.com", "at7t.univer.se", "acc.gt.tc", "z.drv.tw", "a.softr.app",
    "a.mybluemix.net", "x.22web.org", "y.blogcu.com", "z.eoldal.hu", "x.page.gd", "a.webnode.cz",
    "bright.cloud.serverless.com",
])
def test_tenants_of_platforms_the_licensed_list_ranks_are_not_instant_safe(host):
    assert scoring.is_trusted_top_domain(host) is False


@pytest.mark.parametrize("host", ["s.gy", "help-orders.s.gy", "short.gy", "bityli.com", "me2.do", "chilp.it",
                                  "abrir.link", "beam.to", "l1nq.com", "encurtador.dev"])
def test_shorteners_the_licensed_list_ranks_are_not_instant_safe(host):
    assert scoring._is_url_shortener(host)
    assert scoring.is_trusted_top_domain(host) is False


@pytest.mark.parametrize("host", [
    "saladofuturo.educacao.sp.gov.br", "eproc-consulta.tjsp.jus.br", "srv265.hrdc-drhc.gc.ca",
    "tp-chp-prd.state.mi.us", "sistemas-renavam.detran.pa.gov.br", "apps1.ams-sga.cra-arc.gc.ca",
    "overseas-healthcare.nhsbsa.nhs.uk", "www.nhs.uk", "aaccc.admissions.nic.in", "www.gov.br",
])
def test_a_government_host_is_never_a_hosting_tenant(host):
    """With gc.ca, nhs.uk or sp.gov.br ranked as names, every ICANN rule under
    them joined data/public_suffixes_in_top.json and the model read these
    hosts as tenants of a hosting platform (is_hosting_subdomain): their
    median score rose from 0.087 to 0.297 and 32 CrUX hosts went from caution
    to dangerous (verifier, 2026-10-23)."""
    assert shared_tenant(host)[0] is None, host
    assert not (scoring.PUBLIC_SUFFIXES_IN_TOP & {"gc.ca", "nhs.uk", "sp.gov.br", "jus.br", "mi.us", "nic.in"})

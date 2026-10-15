"""Recall fixes after the 2026-10-11 weekly benchmark (recall 98.5% -> 91.9%).

Since features_version 5 the ML model reads a hosting tenant by its own label,
so it no longer calls every *.vercel.app / *.duckdns.org name phishing. Two
name rules take back part of what that cost, without the model:

  * a brand next to a lure word on a hosting tenant, written the way the kits
    write it: a counter on the lure (facebook-login0, facebooklogin17), the
    lure glued to more letters (facebookloginuser), or support/security
    (gmail-support.netlify.app) — scoring._is_tenant_lure;
  * a name on a free dynamic-DNS service (havuwuzu.ipv64.net) —
    'dynamic_dns_host', and ns01.info (ChangeIP) is no longer a trusted
    top-100k name for its customers' hosts.

The legitimate lists below must not move.
"""
from pathlib import Path

import pytest

from api.services import ml_scorer
from api.services.hosting_platforms import dynamic_dns_suffix_of
from api.services.scoring import (
    DYNAMIC_DNS_WEIGHT,
    _check_brand_on_hosting_tenant,
    calculate_score,
    is_trusted_top_domain,
)

ROOT = Path(__file__).resolve().parent.parent


def _hosts(path: Path) -> list[str]:
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line.split("|")[0].strip())
    return out


def _signals(host: str) -> set[str]:
    _, _, reasons = calculate_score({"domain": host, "raw_url": host})
    return {r.signal for r in reasons}


@pytest.fixture
def no_ml(monkeypatch):
    monkeypatch.setattr(ml_scorer, "ml_predict", lambda domain: None)


# ── Brand + lure word on a hosting tenant ──

@pytest.mark.parametrize("host, brand", [
    # OpenPhish / phishunt, 2026-10-15
    ("facebooklogin17.blogspot.com", "facebook"),
    ("facebook-login0.blogspot.com", "facebook"),
    ("facebooklogin99999.blogspot.com", "facebook"),
    ("facebookloginuser.blogspot.com", "facebook"),
    ("facebookloginguidance.blogspot.com", "facebook"),
    ("facebook-supports.blogspot.com", "facebook"),
    ("facebook-new-security.blogspot.com", "facebook"),
    ("facebookcustomersupportnumber25.blogspot.com", "facebook"),
    ("gmail-support.netlify.app", "gmail"),
    ("support-instagram.github.io", "instagram"),
    # what the rule caught before still counts
    ("paypal-login.netlify.app", "paypal"),
    ("sberbank-online.pages.dev", "sberbank"),
])
def test_brand_with_a_lure_as_kits_write_it(host, brand):
    assert _check_brand_on_hosting_tenant(host) == brand


@pytest.mark.parametrize("host", [
    # fan pages, clones, a counter alone, a brand alone: not lures
    "facebook-benjamin.blogspot.com",
    "facebook-2024.blogspot.com",
    "netflix-clone.vercel.app",
    "netflix-lake.vercel.app",
    "sber-hackathon.github.io",
    "vkusvill-bonus.netlify.app",
    "supportfacebook.example.com",  # not a hosting tenant
])
def test_no_brand_lure_on_ordinary_names(host):
    assert _check_brand_on_hosting_tenant(host) is None


# ── Dynamic DNS ──

@pytest.mark.parametrize("host, suffix", [
    ("gedivan.duckdns.org", "duckdns.org"),
    ("havuwuzu.ipv64.net", "ipv64.net"),
    ("obeduhizud.home64.de", "home64.de"),
    ("uhidovos.ddnss.org", "ddnss.org"),
    ("kebemus.serveirc.com", "serveirc.com"),
    ("mb-way.ns01.info", "ns01.info"),
])
def test_dynamic_dns_hosts(host, suffix, no_ml):
    assert dynamic_dns_suffix_of(host) == suffix
    _, _, reasons = calculate_score({"domain": host, "raw_url": host})
    hit = [r for r in reasons if r.signal == "dynamic_dns_host"]
    assert hit and hit[0].weight == DYNAMIC_DNS_WEIGHT


@pytest.mark.parametrize("host", [
    "duckdns.org", "www.duckdns.org", "ddns.net", "noip.com", "afraid.org",
    "freedns.afraid.org", "checkip.dyndns.org", "example.com", "github.io",
])
def test_not_a_dynamic_dns_customer(host):
    assert dynamic_dns_suffix_of(host) is None


def test_the_signal_alone_stays_safe(no_ml):
    """A plain name on dynamic DNS is not called anything by this rule alone."""
    score, level, _ = calculate_score({"domain": "nas.ddns.net", "raw_url": "nas.ddns.net"})
    assert level.value == "safe" and score <= 20


def test_changeip_customers_are_not_trusted_as_top_domains():
    # ns01.info is in the Tranco top-100k; its customers' names were answered
    # 'safe' without analysis (mb-way.ns01.info, an MB WAY phish).
    assert not is_trusted_top_domain("mb-way.ns01.info")


def test_dynamic_dns_signal_needs_other_evidence_for_dangerous(no_ml):
    signals = {"domain": "havuwuzu.ipv64.net", "raw_url": "havuwuzu.ipv64.net",
               "missing_security_headers": ["csp", "hsts", "xfo"]}
    _, level, reasons = calculate_score(dict(signals))
    assert "dynamic_dns_host" in {r.signal for r in reasons}
    assert level.value != "dangerous"


# ── Legitimate lists: nothing moves ──

LEGIT_LISTS = (
    ROOT / "tests" / "data" / "ru_heuristics_legit.txt",
    ROOT / "data" / "benchmark_legit_ru.txt",
)


@pytest.mark.parametrize("path", LEGIT_LISTS, ids=lambda p: p.name)
def test_legit_lists_never_carry_the_new_signals(path):
    hits = []
    for host in _hosts(path):
        if dynamic_dns_suffix_of(host) or _check_brand_on_hosting_tenant(host):
            hits.append(host)
    assert hits == []

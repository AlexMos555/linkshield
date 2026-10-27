"""Top sites under a multi-label public suffix are trusted like .com ones.

Found 2026-10-27 in production: /public/check/www.amazon.co.uk answered
"caution, 40" — favicon_brand_clone ("serves the amazon favicon but is hosted
on www.amazon.co.uk") plus missing_headers. The allowlist looked a host up by
its last two labels, 'co.uk', and no top-100k entry is a public suffix: the
list is keyed by registrable domain (scripts/build_top_domains.py folds it
with scoring.registrable_domain and the PSL's ICANN section), so 11,232 of
its 100,000 entries — bbc.co.uk, yahoo.co.jp, amazon.com.br, www.nhs.uk,
hdfc.bank.in — and every subdomain of them were never instant-safe.

And the favicon check compared the host to a brand's verified_hosts exactly,
so www.amazon.co.uk, Amazon's own site, was a "clone" of amazon.co.uk.
"""
from __future__ import annotations

import asyncio
import json

import pytest

from api.services import dnsbl_checks, scoring
from api.services.scoring import (
    TOP_10K_RANKS,
    TOP_DOMAINS,
    _check_suspicious_keywords,
    calculate_score,
    is_trusted_top_domain,
)


def top_domain_key(host):
    return scoring.top_domain_key(host)


# ── The allowlist ──

@pytest.mark.parametrize(("host", "entry"), [
    ("amazon.co.uk", "amazon.co.uk"),
    ("www.amazon.co.uk", "amazon.co.uk"),
    ("bbc.co.uk", "bbc.co.uk"),
    ("www.bbc.co.uk", "bbc.co.uk"),
    ("yahoo.co.jp", "yahoo.co.jp"),
    ("www.yahoo.co.jp", "yahoo.co.jp"),
    ("amazon.com.br", "amazon.com.br"),
    ("www.amazon.com.br", "amazon.com.br"),
    ("abc.net.au", "abc.net.au"),
    ("www.abc.net.au", "abc.net.au"),
    ("barclays.co.uk", "barclays.co.uk"),
    ("www.halifax.co.uk", "halifax.co.uk"),
    ("www.gov.uk", "www.gov.uk"),
    ("www.tax.service.gov.uk", "service.gov.uk"),  # GDS-run: only government services
    ("correios.com.br", "correios.com.br"),
])
def test_top_sites_under_compound_suffixes_are_trusted(host, entry):
    assert entry in TOP_DOMAINS
    assert top_domain_key(host) == entry
    assert is_trusted_top_domain(host) is True


@pytest.mark.parametrize(("host", "entry"), [
    # Keys the top-list builder took from the PSL's ICANN section, under
    # suffixes the compound-ccTLD heuristic does not know (nhs.uk, bank.in).
    ("www.nhs.uk", "www.nhs.uk"),
    ("www.england.nhs.uk", "england.nhs.uk"),
    ("netbanking.hdfc.bank.in", "hdfc.bank.in"),
])
def test_entries_the_psl_folded_are_reached_through_their_subdomains(host, entry):
    assert entry in TOP_DOMAINS
    assert top_domain_key(host) == entry
    assert is_trusted_top_domain(host) is True


@pytest.mark.parametrize("host", ["web.de", "www.web.de", "mail.web.de", "www.id.me"])
def test_two_label_top_names_shaped_like_suffixes_keep_their_trust(host):
    """web.de and id.me look like compound suffixes to the heuristic
    (registrable_domain('www.web.de') is 'www.web.de'); a registrable-only
    lookup would have dropped these hosts, trusted before."""
    assert is_trusted_top_domain(host) is True


@pytest.mark.parametrize("suffix", [
    "co.uk", "com.br", "co.jp", "com.au", "net.au", "gov.uk", "org.uk", "ac.uk",
    "co.za", "com.cn", "gov.in", "ne.jp", "nhs.uk", "bank.in",
])
def test_a_public_suffix_is_never_trusted(suffix):
    assert suffix not in TOP_DOMAINS
    assert top_domain_key(suffix) is None
    assert is_trusted_top_domain(suffix) is False
    assert is_trusted_top_domain(f"unlisted-zq7.{suffix}") is False


@pytest.mark.parametrize("host", [
    "amazon-login.co.uk",
    "www.amazon-login.co.uk",
    "amazon-uk.co.uk",
    "paypal.com.br-secure.example",
    "login.amazon.co.uk.evil.example",
    "amazon.co.uk.evil.example",
    "www.bbc.co.uk.verify-zq7.example",
    "yahoo-co-jp.example",
])
def test_phishing_shaped_names_under_the_same_suffixes_are_not_trusted(host):
    assert is_trusted_top_domain(host) is False


@pytest.mark.parametrize("host", [
    # Shared platforms under a compound suffix, already curated.
    "secure-login.blogspot.co.uk", "paypal.blogspot.com.br",
    # A PSL private suffix that public_suffixes_in_top.json misses (its rules
    # are keyed by their last two labels, 'ne.jp'): Sakura's rental server.
    "khakiweasel42.sakura.ne.jp", "a.b.sakura.ne.jp",
    # Free hosting and shop builders, with phishing tenants in the feeds of
    # 2026-10-27 (dothome.co.kr 15, isweb.co.kr 3, the two shop builders 3 each).
    "conditions2auth.dothome.co.kr", "bk1bp4r.isweb.co.kr",
    "magalu-rio-de-janeiro.lojaintegrada.com.br", "portalsefz2026.lojavirtualnuvem.com.br",
    "cz84.webeden.co.uk", "a581514.shop2000.com.tw",
])
def test_tenants_of_shared_platforms_under_compound_suffixes_are_not_trusted(host):
    assert is_trusted_top_domain(host) is False


@pytest.mark.parametrize("host", ["sakura.ne.jp", "www.sakura.ne.jp", "dothome.co.kr", "www.dothome.co.kr"])
def test_the_platforms_own_hosts_stay_trusted(host):
    assert is_trusted_top_domain(host) is True


def test_scorer_layer2_names_the_entry_it_matched():
    score, level, reasons = calculate_score({"domain": "www.amazon.co.uk", "raw_url": "www.amazon.co.uk"})
    assert (score, level.value) == (0, "safe")
    assert [r.signal for r in reasons] == ["known_legitimate"]
    assert reasons[0].detail == (
        f"Known legitimate domain: amazon.co.uk. Ranked #{TOP_10K_RANKS['amazon.co.uk']} globally"
    )

    _, _, reasons = calculate_score({"domain": "netbanking.hdfc.bank.in"})
    assert reasons[0].detail.startswith("Known legitimate domain: hdfc.bank.in. Ranked #")


def test_authenticated_check_fast_path_matches():
    from api.routers.check import _quick_allowlist_check

    result = _quick_allowlist_check("www.bbc.co.uk")
    assert result is not None and result.level.value == "safe"
    assert result.reasons[0].detail == f"Known legitimate domain: bbc.co.uk. Ranked #{TOP_10K_RANKS['bbc.co.uk']} globally"
    assert _quick_allowlist_check("amazon-login.co.uk") is None
    assert _quick_allowlist_check("khakiweasel42.sakura.ne.jp") is None


def test_public_check_answers_a_compound_top_site_from_the_allowlist(monkeypatch, fake_redis):
    from fastapi.testclient import TestClient

    from api.main import app
    from api.services import analyzer as analyzer_mod
    from api.services import competitor_verdicts

    async def _boom(*a, **k):
        raise AssertionError("a top site must not be analysed")

    async def _no_competitors(*a, **k):
        return []

    monkeypatch.setattr(analyzer_mod, "analyze_domain", _boom)
    monkeypatch.setattr(competitor_verdicts, "gather_competitor_verdicts", _no_competitors)
    body = TestClient(app).get("/api/v1/public/check/www.amazon.co.uk").json()
    assert body["level"] == "safe" and body["verdict_basis"] == "allowlist", body


# ── The other "registrable domain" readers ──

def test_surbl_is_asked_about_the_registrable_domain(monkeypatch):
    """SURBL lists registrable domains; 'co.uk.multi.surbl.org' is never listed."""
    asked: list[str] = []

    async def _query(name):
        asked.append(name)
        return []

    monkeypatch.setattr(dnsbl_checks, "_query", _query)
    for host in ("login.evil-shop.co.uk", "evil-shop.co.uk", "a.b.evil.com.br", "login.evil.xyz"):
        asyncio.run(dnsbl_checks.check_surbl(host))
    assert asked == [
        "evil-shop.co.uk.multi.surbl.org",
        "evil-shop.co.uk.multi.surbl.org",
        "evil.com.br.multi.surbl.org",
        "evil.xyz.multi.surbl.org",
    ]


@pytest.mark.parametrize(("host", "word"), [
    ("secure-login.co.uk", "secure"),
    ("www.secure-login.co.uk", "secure"),
    ("alert-newlogin.co.uk", "alert"),
    ("cba-secure.com.au", "secure"),
    ("secure-login.com", "secure"),
    ("paypal-login.spb.ru", "login"),  # a name registered under an open Russian zone
    # A word left of the registered name is not the name's.
    ("login.bbc-shop.co.uk", None),
    ("bbc.co.uk", None),
])
def test_keyword_rule_reads_the_registered_name(host, word):
    assert _check_suspicious_keywords(host) == word


def test_keyword_reaches_the_score_under_a_compound_suffix():
    _, _, reasons = calculate_score({"domain": "secure-login.co.uk", "raw_url": "secure-login.co.uk"})
    assert "suspicious_keyword" in {r.signal for r in reasons}


# ── The favicon brand-clone check ──

AMAZON_HASH = "0123456789abcdef01234567"


@pytest.fixture
def gallery(monkeypatch, tmp_path):
    """A two-brand gallery: Amazon, and a brand that lists a shared hosting
    platform among its hosts (a shop on myshopify.com)."""
    data = {
        "amazon": {"verified_hosts": ["amazon.com", "www.amazon.com", "amazon.co.uk"],
                   "known_favicon_hashes": [AMAZON_HASH]},
        "shopbrand": {"verified_hosts": ["shopbrand.example", "myshopify.com"],
                      "known_favicon_hashes": ["fedcba9876543210fedcba98"]},
    }
    path = tmp_path / "gal.json"
    path.write_text(json.dumps(data))
    import api.services.favicon_hash as mod
    monkeypatch.setattr(mod, "GALLERY_PATH", path)
    monkeypatch.setattr(mod, "_gallery_cache", None)
    return data


def _serve(monkeypatch, digest):
    """Every host serves an icon hashing to `digest`; no favicon cache."""
    import api.services.favicon_hash as mod

    async def _fetch(domain):
        return b"\x00\x00\x01\x00icon"

    async def _no_redis():
        raise ConnectionError("no cache in this test")

    monkeypatch.setattr(mod, "_fetch_favicon", _fetch)
    monkeypatch.setattr(mod, "_hash_bytes", lambda b: digest)
    monkeypatch.setattr(mod, "get_redis", _no_redis)


def _clone(host):
    from api.services.favicon_hash import check_favicon_brand_clone
    return asyncio.run(check_favicon_brand_clone(host))


@pytest.mark.parametrize("host", ["amazon.co.uk", "www.amazon.co.uk", "smile.amazon.co.uk", "WWW.Amazon.co.uk"])
def test_a_subdomain_of_a_verified_host_is_the_brands_own(host, gallery, monkeypatch):
    _serve(monkeypatch, AMAZON_HASH)
    out = _clone(host)
    assert (out["cloned"], out["brand"], out["weight"]) == (False, "amazon", 0)


@pytest.mark.parametrize("host", [
    "amazon-login.co.uk", "xamazon.co.uk", "wwwamazon.co.uk",
    "amazon.co.uk.evil.example", "login.amazon.co.uk-verify.example",
])
def test_look_alikes_of_a_verified_host_are_clones(host, gallery, monkeypatch):
    _serve(monkeypatch, AMAZON_HASH)
    out = _clone(host)
    assert (out["cloned"], out["brand"], out["weight"]) == (True, "amazon", 35)


def test_a_tenant_of_a_shared_platform_is_not_the_brands_own(gallery, monkeypatch):
    """A verified host that is itself a hosting platform vouches for its own
    name, not for every customer's site under it."""
    _serve(monkeypatch, "fedcba9876543210fedcba98")
    assert _clone("myshopify.com")["cloned"] is False
    assert _clone("evil-shop.myshopify.com")["cloned"] is True


def test_production_gallery_calls_amazons_regional_sites_its_own(monkeypatch):
    import api.services.favicon_hash as mod

    monkeypatch.setattr(mod, "_gallery_cache", None)
    amazon = mod._load_gallery()["amazon"]
    _serve(monkeypatch, amazon["known_favicon_hashes"][0])
    for host in ("www.amazon.co.uk", "www.amazon.co.jp", "www.amazon.com.br", "www.amazon.de"):
        assert _clone(host)["cloned"] is False, host
    assert _clone("amazon-co-jp.example")["cloned"] is True


def test_no_verified_host_in_the_gallery_is_a_shared_platform(monkeypatch):
    """The subdomain rule is only sound while no verified host is a place
    where anyone can get a subdomain."""
    import api.services.favicon_hash as mod
    from api.services.hosting_platforms import dynamic_dns_suffix_of, tenant_suffix_of
    from api.services.scoring import _SCORER_SHARED_SUFFIXES

    monkeypatch.setattr(mod, "_gallery_cache", None)
    gallery = mod._load_gallery()
    for slug, brand in gallery.items():
        if slug.startswith("_"):
            continue
        for host in brand["verified_hosts"]:
            probe = f"tenant-zq7.{host}"
            assert tenant_suffix_of(probe, _SCORER_SHARED_SUFFIXES) is None, (slug, host)
            assert dynamic_dns_suffix_of(probe) is None, (slug, host)

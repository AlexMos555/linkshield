"""The registrable domain by the Public Suffix List (api/services/public_suffix.py).

Until 2026-10-28 the service drew the registrable domain (eTLD+1) with a
compound-ccTLD heuristic: a 2-letter ccTLD under a generic second level
(co, com, gov, ac, web, id …) took three labels, anything else two, and the
Russian PSL zones were an overlay on top. It missed real ICANN suffixes —
paypal-secure.my.id was a subdomain of 'my.id' and paypa1.me.uk of 'me.uk',
so the extension's credential guard never saw the brand in the name and
every owner under such a suffix was one "site" — and it invented suffixes:
login.web.de was its own registrable domain, as if web.de were a registry.

These tests hold the matcher to the PSL algorithm (exact, wildcard and
exception rules, the default rule), to the vendored list's integrity, to
the Russian overlay's old answers, and the model's features to the old
reading (they are paired with a trained model; a new reading needs a
retrain).
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from api.services import public_suffix as ps

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

# A list in the PSL's own format, small enough to read: an ICANN section
# with exact, wildcard and exception rules and an IDN rule, and a PRIVATE
# section that must not leak into the ICANN rules.
TINY = """\
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0.

// VERSION: 2026-01-01_00-00-00_UTC
// COMMIT: 0123456789abcdef

// ===BEGIN ICANN DOMAINS===

uk
co.uk
ltd.uk
*.sch.uk
jp
*.kobe.jp
!city.kobe.jp
ck
*.ck
!www.ck
cn
公司.cn
com

// ===END ICANN DOMAINS===
// ===BEGIN PRIVATE DOMAINS===

// GitHub
github.io
*.compute.example.com

// ===END PRIVATE DOMAINS===
"""


@pytest.fixture(scope="module")
def tiny():
    return ps.parse(TINY)


# ── The algorithm, on a list small enough to read ──

def test_parse_reads_both_sections_apart(tiny):
    assert tiny.version == "2026-01-01_00-00-00_UTC"
    assert tiny.commit == "0123456789abcdef"
    assert {"co.uk", "ltd.uk", "uk", "com", "xn--55qx5d.cn"} <= tiny.icann.exact
    assert tiny.icann.wildcards == frozenset({"sch.uk", "kobe.jp", "ck"})
    assert tiny.icann.exceptions == frozenset({"city.kobe.jp", "www.ck"})
    assert "github.io" in tiny.private.exact and "github.io" not in tiny.icann.exact
    assert tiny.private.wildcards == frozenset({"compute.example.com"})


@pytest.mark.parametrize(("host", "expected"), [
    # The default rule: an unlisted TLD is a suffix of one label.
    ("www.example.com", "example.com"),
    ("a.b.c.example.org", "example.org"),
    ("example.com", "example.com"),
    # Exact multi-label rules.
    ("login.example.co.uk", "example.co.uk"),
    ("shop.example.ltd.uk", "example.ltd.uk"),
    # A suffix by itself answers itself (doh_gateway's old contract: com.au).
    ("co.uk", "co.uk"),
    ("uk", "uk"),
    # Wildcards: every child of kobe.jp is itself a suffix …
    ("a.b.kobe.jp", "a.b.kobe.jp"),
    ("b.kobe.jp", "b.kobe.jp"),
    ("www.school.foo.sch.uk", "school.foo.sch.uk"),
    # … the base itself is a name under the next rule …
    ("kobe.jp", "kobe.jp"),
    ("www.kobe.jp", "www.kobe.jp"),
    # … and an exception takes one label back.
    ("www.city.kobe.jp", "city.kobe.jp"),
    ("city.kobe.jp", "city.kobe.jp"),
    ("www.ck", "www.ck"),
    ("a.www.ck", "www.ck"),
    ("a.b.ck", "a.b.ck"),
    # The private section is not mixed in.
    ("foo.github.io", "github.io"),
    ("a.b.compute.example.com", "example.com"),
])
def test_the_psl_algorithm(tiny, host, expected):
    assert tiny.icann.registrable(host) == expected


@pytest.mark.parametrize(("host", "expected"), [
    # IDN: matched in ASCII, answered in the spelling it was asked in.
    ("www.例子.公司.cn", "例子.公司.cn"),
    ("www.xn--fsqu00a.xn--55qx5d.cn", "xn--fsqu00a.xn--55qx5d.cn"),
    # Case and the root's dot.
    ("WWW.Example.CO.UK.", "example.co.uk"),
    (".example.com", "example.com"),
    # IP literals are their own site, never their last two numbers.
    ("192.168.1.10", "192.168.1.10"),
    ("10.0.1.10", "10.0.1.10"),
    ("[::1]", "[::1]"),
    ("2001:db8::1", "2001:db8::1"),
    # A single label, and nothing.
    ("localhost", "localhost"),
    ("", ""),
    ("...", ""),
])
def test_input_forms(tiny, host, expected):
    assert tiny.icann.registrable(host) == expected


@pytest.mark.parametrize("text", [
    "",
    "co.uk\n",                                                      # no section markers
    TINY.replace("// ===END ICANN DOMAINS===", ""),                 # a section left open
    TINY.replace("// VERSION: 2026-01-01_00-00-00_UTC\n", ""),      # no version line
    TINY.replace("co.uk\n", "co..uk\n"),                            # an empty label
    TINY.replace("co.uk\n", "co.*.uk\n"),                           # a wildcard not leftmost
    TINY.replace("co.uk\n", "!co.uk\n"),                            # an exception under no wildcard
])
def test_a_malformed_list_is_refused(text):
    with pytest.raises(ValueError):
        ps.parse(text)


# ── The vendored list ──

def test_the_vendored_list_is_the_psl_and_loaded():
    """Fails loudly when data/public_suffix_list.dat is truncated, replaced or
    not loaded: without it the service falls back to the old heuristic."""
    text = (DATA / ps.PSL_FILE).read_text(encoding="utf-8")
    assert text.startswith("// This Source Code Form is subject to the terms of the Mozilla Public\n"), \
        "the MPL-2.0 notice must stay at the top of the vendored file"
    listed = ps.parse(text)
    assert ps.LOAD_ERROR is None, ps.LOAD_ERROR
    assert ps.LIST is not None and ps.LIST.version == listed.version
    assert listed.version and listed.commit
    # Counts on 2026-10-22: 6,925 exact ICANN rules (5,485 with 2+ labels),
    # 16 wildcards, 8 exceptions; 3,152 + 296 private.
    assert len(listed.icann.exact) > 6_000
    assert sum("." in r for r in listed.icann.exact) > 5_000
    assert len(listed.icann.wildcards) >= 10 and len(listed.icann.exceptions) >= 5
    assert len(listed.private.exact) > 2_000
    assert {"co.uk", "my.id", "io.vn", "me.uk", "nhs.uk", "lg.jp", "bank.in", "gc.ca", "sp.gov.br"} <= listed.icann.exact
    assert {"kobe.jp", "ck"} <= listed.icann.wildcards
    assert {"city.kobe.jp", "www.ck"} <= listed.icann.exceptions
    # Not public suffixes, whatever the old heuristic said.
    assert not {"web.de", "id.me", "sch.gr", "net.hr", "gov.hu"} & listed.icann.exact


def test_the_vendored_list_is_attributed():
    notes = (ROOT / "docs" / "THIRD_PARTY_FEEDS.md").read_text(encoding="utf-8")
    assert "data/public_suffix_list.dat" in notes and "MPL 2.0" in notes


# ── The service's registrable domain: ICANN rules, the Russian zones on top ──

@pytest.mark.parametrize(("host", "expected"), [
    # The suffixes the heuristic did not know (2026-10-27 review).
    ("paypal-secure.my.id", "paypal-secure.my.id"),
    ("www.paypal-secure.my.id", "paypal-secure.my.id"),
    ("apple-id.io.vn", "apple-id.io.vn"),
    ("paypa1.me.uk", "paypa1.me.uk"),
    ("shop.example.ltd.uk", "example.ltd.uk"),
    ("www.england.nhs.uk", "england.nhs.uk"),
    ("www.city.lg.jp", "city.lg.jp"),
    ("netbanking.hdfc.bank.in", "hdfc.bank.in"),
    ("srv.hrdc-drhc.gc.ca", "hrdc-drhc.gc.ca"),
    # The suffixes it invented: one owner each (web.de: 1&1's name servers;
    # com.be: Amazon's, SOA root.amazon.com), or a government's.
    ("login.web.de", "web.de"),
    ("www.web.de", "web.de"),
    ("account.id.me", "id.me"),
    ("www.school.sch.gr", "sch.gr"),
    ("www.net.hr", "net.hr"),
    ("www.amazon.com.be", "com.be"),
    ("kau.gov.hu", "gov.hu"),
    # The registries it split rightly, which the ICANN section does not
    # list (2026-10-28 review): the PSL's PRIVATE rules of its shape …
    ("acessar-conta-br.co.ua", "acessar-conta-br.co.ua"),
    ("www.acessar-conta-br.co.ua", "acessar-conta-br.co.ua"),
    ("mail.confirm-lnstagram.com.de", "confirm-lnstagram.com.de"),
    ("rainbet.co.no", "rainbet.co.no"),
    ("easybank-kundenservice-mijndomein.co.nl", "easybank-kundenservice-mijndomein.co.nl"),
    ("pracuj-w-domu.co.pl", "pracuj-w-domu.co.pl"),
    ("accounts.jagex.com-cs.co.cz", "com-cs.co.cz"),
    ("shop.evil.biz.ua", "evil.biz.ua"),
    ("lnstagram.com.se", "lnstagram.com.se"),
    # … and data/cctld_registries.json, those in neither section.
    ("pgesaccntspprtaccs.co.vu", "pgesaccntspprtaccs.co.vu"),
    ("www.out-owa.co.nf", "out-owa.co.nf"),
    ("correos-particulares.info.gf", "correos-particulares.info.gf"),
    ("roblox.com.tg", "roblox.com.tg"),
    ("ledger.com.tl", "ledger.com.tl"),
    ("x.ibftrader.id.hn", "ibftrader.id.hn"),
    ("co.ua", "co.ua"),
    ("co.vu", "co.vu"),
    # Unchanged.
    ("login.example.co.uk", "example.co.uk"),
    ("apple.com.cn", "apple.com.cn"),
    ("com.au", "com.au"),
    # The Russian zones (PSL private section, kept as an overlay).
    ("kvs.gov.spb.ru", "gov.spb.ru"),
    ("gosuslugi-lk.spb.ru", "gosuslugi-lk.spb.ru"),
    ("spb.ru", "spb.ru"),
    ("a.b.hosting.myjino.ru", "a.b.hosting.myjino.ru"),
    ("www.отель.сочи.рус", "отель.сочи.рус"),
    # The private section is still not mixed in: tenants are the curated
    # platform lists' business (hosting_platforms.json, tenant zones).
    ("foo.github.io", "github.io"),
    ("x.blogspot.com", "blogspot.com"),
    ("192.168.1.10", "192.168.1.10"),
])
def test_registrable_domain(host, expected):
    assert ps.registrable_domain(host) == expected


def _ru_corpus() -> list[str]:
    hosts: set[str] = set()
    for path in (ROOT / "tests/data/ru_heuristics_legit.txt", ROOT / "tests/data/ru_heuristics_phish.txt",
                 DATA / "benchmark_legit_ru.txt"):
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                hosts.add(line.split(" | ")[0].strip().lower())
    tsv = (ROOT / "tests/data/extension_name_rules_parity.tsv").read_text(encoding="utf-8")
    hosts.update(r.split("\t")[0] for r in tsv.splitlines() if r and not r.startswith("#"))
    hosts.update(json.loads((DATA / "top_100k.json").read_text(encoding="utf-8")))
    rules = json.loads((DATA / "ru_public_suffixes.json").read_text(encoding="utf-8"))
    hosts.update(r.removeprefix("*.") for r in rules)
    hosts.update(f"www.x.{r.removeprefix('*.')}" for r in rules)
    return sorted(hosts)


def test_the_russian_zones_answer_exactly_as_before():
    """Every name under a Russian PSL rule gets scoring._ru_registrable_domain()'s
    answer, the one ~30 tests and the model's features were built on."""
    from api.services.scoring import _ru_registrable_domain

    wrong = [h for h in _ru_corpus() if (ru := _ru_registrable_domain(h)) and ps.registrable_domain(h) != ru]
    assert wrong == []


def test_no_icann_rule_reaches_under_a_russian_zone():
    """The overlay is merged into the ICANN rules, longest rule first. That is
    'the Russian rule, else the ICANN one' only while no ICANN rule is longer
    than one label under the overlay's TLDs: a list refresh that adds one
    must be looked at, not merged silently."""
    tlds = {r.rsplit(".", 1)[1] for r in ps.RU_OVERLAY.exact | ps.RU_OVERLAY.wildcards}
    icann = ps.LIST.icann
    under = sorted(r for r in icann.exact | icann.wildcards | icann.exceptions
                   if "." in r and r.rsplit(".", 1)[1] in tlds)
    under += sorted(w for w in icann.wildcards if w in tlds)
    assert tlds >= {"ru", "su"} and under == []


def test_the_overlay_is_the_scorers_russian_list():
    from api.services import scoring

    assert ps.RU_OVERLAY.exact == scoring.RU_PUBLIC_SUFFIXES
    assert ps.RU_OVERLAY.wildcards == scoring._RU_WILDCARD_SUFFIXES


# ── The registries the heuristic split and the ICANN section does not list ──

def _listed(rules: ps.SuffixRules, zone: str) -> bool:
    labels = zone.split(".")
    return rules.suffix_length(labels, default=0) >= len(labels)


def test_the_registry_overlay_is_the_psls_private_registries_of_the_heuristics_shape():
    """Read ICANN-only, every owner under co.ua, co.nl, com.de … became one
    site (2026-10-28 review: acessar-conta-br.co.ua took co.ua's top-1M rank
    #278,678 for a vouch). The heuristic split them because they have its
    shape — a generic second level under a 2-letter ccTLD — and the PSL
    lists them as registries, if only in its PRIVATE section. Exactly those
    are kept: not github.io or blogspot.com, which the curated platform
    lists decide."""
    derived = ps.private_registries(ps.LIST)
    expected = {r for r in ps.LIST.private.exact
                if ps.heuristic_suffix(r) and not _listed(ps.LIST.icann, r) and not _listed(ps.RU_OVERLAY, r)}
    assert derived == expected
    assert {"co.ua", "co.nl", "co.no", "co.pl", "co.cz", "co.de", "com.de", "com.se", "biz.ua", "ltd.ua"} <= derived
    assert not {"github.io", "blogspot.com", "pages.dev", "com.ru", "spb.ru"} & derived
    assert derived <= ps.REGISTRY_OVERLAY.exact


def test_the_curated_registries_are_the_heuristics_and_in_no_psl_section():
    """data/cctld_registries.json only keeps a split the heuristic made (no
    new boundary the old reading did not draw), only where the PSL says
    nothing (else the entry is the PSL's to keep), and with its evidence."""
    curated = json.loads((DATA / ps.REGISTRY_FILE).read_text(encoding="utf-8"))
    zones = curated["zones"]
    assert {"co.vu", "co.nf", "info.gf", "com.tc", "com.tg", "com.tl", "com.nl", "co.pt", "biz.kg", "id.hn",
            "go.ro", "co.cc", "co.nr"} <= set(zones)
    for zone, evidence in zones.items():
        assert zone == ps.ascii_name(zone) and zone.count(".") == 1, zone
        assert ps.heuristic_suffix(zone), f"{zone}: the heuristic did not split it"
        assert not _listed(ps.LIST.icann, zone) and not _listed(ps.LIST.private, zone), f"{zone} is in the PSL"
        assert len(evidence) > 20, f"{zone}: no evidence"
        assert ps.registrable_domain(f"www.x.{zone}") == f"x.{zone}"
    # One owner's names stay merged, as the PSL has them (biz.nf: crt.sh
    # shows only its operator's own names, cp1, order, secure, www).
    assert not {"web.de", "id.me", "com.be", "net.hr", "in.gr", "gov.hu", "sch.gr", "biz.nf"} & set(zones)
    assert ps.REGISTRY_OVERLAY.exact == ps.private_registries(ps.LIST) | set(zones)


def test_every_registry_split_is_one_the_heuristic_made():
    """The overlay never draws a boundary the old reading did not: under
    each of its zones the legacy registrable domain is the same."""
    from api.services.scoring import legacy_registrable_domain

    for zone in sorted(ps.REGISTRY_OVERLAY.exact):
        for host in (f"x.{zone}", f"a.b.x.{zone}", zone):
            assert ps.registrable_domain(host) == legacy_registrable_domain(host), host


# ── Who reads which ──

def test_the_service_reads_one_registrable_domain():
    from api.services import doh_gateway, scoring

    for host in ("paypal-secure.my.id", "login.web.de", "kvs.gov.spb.ru", "gosuslugi-lk.spb.ru", "a.b.example.co.uk"):
        assert scoring.registrable_domain(host) == doh_gateway._registrable_domain(host) == ps.registrable_domain(host)
    # PR #354 (doh_upstream._zone_of) calls the gateway's helper by this signature.
    assert list(inspect.signature(doh_gateway._registrable_domain).parameters) == ["qname"]


@pytest.mark.parametrize(("host", "legacy"), [
    ("paypal-secure.my.id", "my.id"),
    ("www.web.de", "www.web.de"),
    ("kvs.gov.spb.ru", "gov.spb.ru"),
    ("login.example.co.uk", "example.co.uk"),
    ("192.168.1.10", "1.10"),
])
def test_the_legacy_reading_is_kept_for_the_model(host, legacy):
    from api.services.scoring import legacy_registrable_domain

    assert legacy_registrable_domain(host) == legacy


def test_without_the_list_the_old_reading_is_served(monkeypatch):
    """A missing or malformed data/public_suffix_list.dat is logged at import
    and the service keeps the reading it had (the Russian zones, else the
    heuristic) rather than the last two labels."""
    from api.services.scoring import legacy_registrable_domain

    monkeypatch.setattr(ps, "_RULES", None)
    for host in ("login.example.co.uk", "paypal-secure.my.id", "www.web.de", "kvs.gov.spb.ru", "www.отель.сочи.рус",
                 "a.b.hosting.myjino.ru", "localhost", ""):
        assert ps.registrable_domain(host) == legacy_registrable_domain(host), host


class _NoPsl:
    """Stands in for the loaded rules: any read of the new matcher fails."""

    def registrable(self, host):  # pragma: no cover — reaching it is the failure
        raise AssertionError(f"the model's features read the Public Suffix List for {host!r}")


_FEATURE_HOSTS = (
    "paypal-secure.my.id", "www.paypal-secure.my.id", "03316951.zi-xz.my.id", "login.web.de",
    "api.id.me", "amazon.com.be", "hsbc.bank.in", "www.111.nhs.uk", "x.com.de", "kvs.gov.spb.ru",
    "gosuslugi-lk.spb.ru", "paypal.com.evil.xyz", "accounts.google.sn.cn", "www.отель.сочи.рус",
    "xn--80abap1arsf.xn--p1ai", "192.168.1.10", "localhost", "foo.github.io",
)


def test_the_models_features_never_read_the_public_suffix_list(monkeypatch):
    """The served model was trained on the old reading (model_meta.json
    feature_data); a new reading is a retrain, not a side effect."""
    from api.services.ml_features import extract_ml_features
    from api.services.url_features import extract_features

    before = {h: (extract_ml_features(h), extract_features(h, {})) for h in _FEATURE_HOSTS}
    monkeypatch.setattr(ps, "_RULES", _NoPsl())
    after = {h: (extract_ml_features(h), extract_features(h, {})) for h in _FEATURE_HOSTS}
    assert after == before


# ── What the rules read now ──

def _signals(domain: str, **extra) -> dict:
    return {"domain": domain, "raw_url": domain, "checks_succeeded": 18, "total_checks": 18, **extra}


@pytest.mark.parametrize("host", ["gosuslugi-lk.spb.ru", "apple.com.msk.ru", "vk-login.nov.ru"])
def test_otx_scores_names_under_a_ranked_russian_zone(host):
    """The OTX gate keyed every x.spb.ru on 'spb.ru' (the heuristic had no
    Russian zones), which is top-10k #758: no report about any name under
    spb.ru or msk.ru (#2547) ever scored, and under nov.ru it was halved."""
    from api.services import scoring

    assert not scoring.is_trusted_top_domain(host)
    _, _, reasons = scoring.calculate_score(_signals(host, alienvault_pulse_count=3))
    assert sum(r.weight for r in reasons if r.signal.startswith("alienvault_otx")) == 30


@pytest.mark.parametrize(("host", "weight"), [
    # The OTX gate asks whether the registrable domain is a top-10k name — a
    # popularity question, so rank_registrable_domain's: a zone no list
    # knows (org.zz) waives no report about a name the reading before
    # 2026-10-28 kept apart from it …
    ("evil.org.zz", 30),
    ("login.evil.org.zz", 30),
    # … a registry overlay zone neither (biz.ua is #5653 of the top-10k) …
    ("shop.evil.biz.ua", 30),
    # … while a top-10k registrant still speaks for its own subdomains.
    ("login.shop.org.zz", 0),
])
def test_otx_is_not_waived_by_a_popular_zone_above_the_registrant(monkeypatch, host, weight):
    from api.services import scoring

    monkeypatch.setattr(scoring, "TOP_10K_RANKS", {**scoring.TOP_10K_RANKS, "org.zz": 900, "shop.org.zz": 950})
    assert not scoring.is_trusted_top_domain(host)
    _, _, reasons = scoring.calculate_score(_signals(host, alienvault_pulse_count=3))
    assert sum(r.weight for r in reasons if r.signal.startswith("alienvault_otx")) == weight


@pytest.mark.parametrize(("host", "apex"), [
    ("paypal-secure.my.id", True),   # a registration under the ICANN suffix my.id
    ("herzen.spb.ru", True),         # one under the spb.ru zone
    ("shop.com.be", False),          # com.be is Amazon's name (no PSL rule), shop its subdomain
    ("login.example.co.uk", False),
    ("example.co.uk", True),
    # Registrations under the registry overlay's zones, as the heuristic had
    # them: ICANN-only, 1,231 feed hosts lost the check (74 co.vu ones went
    # caution -> safe).
    ("181page9707ik0647recovery789.co.vu", True),
    ("confirm-lnstagram.com.de", True),
    ("acessar-conta-br.co.ua", True),
    ("mail.confirm-lnstagram.com.de", False),
    # An IP address is its own registrable domain now, but has no mail to
    # miss: check_dns answers has_mx False for every IP URL, and "No MX
    # record" (+8) on the 713 IP hosts of the phishing review sets was noise.
    ("192.168.1.10", False),
    ("[2001:db8::1]", False),
])
def test_no_mx_is_judged_on_the_registrable_domain(host, apex):
    from api.services import scoring

    _, _, reasons = scoring.calculate_score(_signals(host, dns_has_mx=False))
    assert any(r.signal == "no_mx_record" for r in reasons) is apex


@pytest.mark.parametrize(("host", "ranks", "vouched"), [
    # A registry's rank vouches for nobody under it (the heuristic read 'my.id').
    ("paypal-secure.my.id", {"my.id": 900}, False),
    ("www.paypal-secure.my.id", {"my.id": 900, "paypal-secure.my.id": 50_000}, True),
    # The registries the overlay keeps: the zone's rank (Tranco top-1M of
    # 2026-10-21: co.ua #278,678, co.cz #129,724) is not a customer's.
    ("acessar-conta-br.co.ua", {"co.ua": 278_678}, False),
    ("www.acessar-conta-br.co.ua", {"co.ua": 278_678}, False),
    ("accounts.jagex.com-cs.co.cz", {"co.cz": 129_724}, False),
    ("shop.evil.biz.ua", {"biz.ua": 5653}, False),
    ("evil.com.de", {"com.de": 40_000}, False),
    ("correos-particulares.info.gf", {"info.gf": 270_247}, False),
    # A zone neither the PSL nor the overlay lists lends its rank to no name
    # the reading before 2026-10-28 kept apart from it: not an unknown
    # registry's (org.zz) and, as then, not one owner's either (web.de).
    ("evil.org.zz", {"org.zz": 1_000}, False),
    ("login.web.de", {"web.de": 2424}, False),
    ("www.shop.org.zz", {"org.zz": 1_000, "shop.org.zz": 30_000}, True),
])
def test_an_unreachable_sites_vouch_reads_the_registrable_domain(monkeypatch, host, ranks, vouched):
    import asyncio

    from api.services import analyzer
    from api.services.analysis_budget import Deadline

    async def _rank(name):
        return ranks.get(name)

    monkeypatch.setattr(analyzer, "get_tranco_rank", _rank)
    assert asyncio.run(analyzer._name_is_vouched_for(host, {"domain": host}, Deadline(5.0))) is vouched


@pytest.mark.parametrize(("host", "ranks", "expected"), [
    # The registrable's rank the scorer reads for OTX, a fresh certificate
    # and self-hosted products (signals tranco_registrable_rank).
    ("www.paypal-secure.my.id", {"my.id": 900, "paypal-secure.my.id": 50_000}, 50_000),
    ("evil.co.ua", {"co.ua": 278_678}, None),
    ("login.evil.co.ua", {"co.ua": 278_678, "evil.co.ua": 9_000}, 9_000),
    ("paypal-login.co.vu", {"co.vu": 1_000}, None),
    # Not a zone the PSL does not list, nor one owner's 2-label name: what
    # the reading before 2026-10-28 ranked.
    ("evil.org.zz", {"org.zz": 1_000}, None),
    ("login.web.de", {"web.de": 2424}, None),
    ("www.amazon.com.be", {"com.be": 1946, "amazon.com.be": 4_000}, 4_000),
])
def test_the_registrable_rank_never_reads_a_zone_above_the_registrant(monkeypatch, host, ranks, expected):
    import asyncio

    from api.services import tranco

    async def _rank(name):
        return ranks.get(name)

    monkeypatch.setattr(tranco, "get_tranco_rank", _rank)
    assert asyncio.run(tranco._registrable_rank(host, None)) == expected


@pytest.mark.parametrize(("host", "expected"), [
    ("www.paypal-secure.my.id", "paypal-secure.my.id"),
    ("evil.co.ua", "evil.co.ua"),
    ("login.web.de", "login.web.de"),
    ("www.web.de", "www.web.de"),
    ("a.evil.org.zz", "evil.org.zz"),
    ("www.amazon.com.be", "amazon.com.be"),
    ("kvs.gov.spb.ru", "gov.spb.ru"),
    ("www.bbc.co.uk", "bbc.co.uk"),
    ("www.nhs.uk", "www.nhs.uk"),
])
def test_the_name_whose_rank_counts(host, expected):
    from api.services.scoring import rank_registrable_domain

    assert rank_registrable_domain(host) == expected


def test_surbl_is_asked_about_the_registrants_name(monkeypatch):
    import asyncio

    from api.services import dnsbl_checks

    asked: list[str] = []

    async def _query(name):
        asked.append(name)
        return []

    monkeypatch.setattr(dnsbl_checks, "_query", _query)
    hosts = {
        "www.paypal-secure.my.id": "paypal-secure.my.id",
        "login.web.de": "web.de",
        # SURBL lists names under these zones, never the zone (its own
        # two-level-tlds list carries co.ua, co.vu, com.de, com.se, biz.ua).
        "www.acessar-conta-br.co.ua": "acessar-conta-br.co.ua",
        "000012151000.co.vu": "000012151000.co.vu",
        "x.evil.com.de": "evil.com.de",
        # … and the platforms' customers (pages.dev, vercel.app, duckdns.org
        # are on that list too): the customer's name, as the OTX key reads it.
        "a.paypal-login.pages.dev": "paypal-login.pages.dev",
        "spoti-klient.vercel.app": "spoti-klient.vercel.app",
    }
    for host in hosts:
        asyncio.run(dnsbl_checks.check_surbl(host))
    assert asked == [f"{name}.multi.surbl.org" for name in hosts.values()]


@pytest.mark.parametrize(("host", "word", "model_sees_it"), [
    # The model's own keyword feature still reads the legacy name ('my', 'me').
    ("acc-recovery-support-live.my.id", "recovery", 0.0),
    ("secure-login.me.uk", "secure", 0.0),
    # Feed phishing under the registry overlay's zones, named 'com' when
    # com.de was read as the site (mail.confirm-lnstagram.com.de went
    # dangerous 53 -> caution 43 on the ICANN-only reading); the heuristic,
    # and so the model, read the registrant's name.
    ("confirm-lnstagram.com.de", "confirm", 1.0),
    ("mail.confirm-lnstagram.com.de", "confirm", 1.0),
    ("icloud-alert.com.de", "alert", 1.0),
    ("trezor-wallet.com.de", "wallet", 1.0),
])
def test_the_keyword_rule_reads_the_registered_name(host, word, model_sees_it):
    from api.services import ml_features, scoring

    assert scoring._check_suspicious_keywords(host) == word
    assert ml_features.extract_ml_features(host)["has_suspicious_keyword"] == model_sees_it


def test_a_confirmed_threat_is_recorded_under_its_own_name():
    from api.services import confirmed_threats

    assert confirmed_threats.site_name("x.paypal-secure.my.id") == "paypal-secure.my.id"
    assert confirmed_threats.site_name("gosuslugi-lk.spb.ru") == "gosuslugi-lk.spb.ru"
    assert confirmed_threats.site_name("www.acessar-conta-br.co.ua") == "acessar-conta-br.co.ua"
    assert confirmed_threats.is_recordable_host("paypal-secure.my.id")
    assert confirmed_threats.is_recordable_host("pgesaccntspprtaccs.co.vu")


# ── The refresh script (scripts/refresh_public_suffix_list.py) ──

def _refresh():
    import importlib
    import sys

    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    return importlib.import_module("refresh_public_suffix_list")


def test_the_refresh_script_checks_the_vendored_copy():
    assert _refresh().main(["--check"]) == 0


def test_the_refresh_refuses_an_older_truncated_or_overlapping_list():
    refresh = _refresh()
    text = (DATA / ps.PSL_FILE).read_text(encoding="utf-8")
    current = ps.parse(text)
    assert refresh.problems(current, current) == []
    older = ps.parse(text.replace(f"// VERSION: {current.version}", "// VERSION: 2020-01-01_00-00-00_UTC"))
    assert any("older" in p for p in refresh.problems(older, current))
    truncated = ps.parse("\n".join(line for line in text.splitlines() if not line.endswith(".jp")))
    assert any("keeps only" in p for p in refresh.problems(truncated, current))
    under = ps.parse(text.replace("\nru\n", "\nru\nx.ru\n", 1))
    assert any("Russian overlay" in p for p in refresh.problems(under, current))


def test_the_refresh_writes_the_list_byte_for_byte(tmp_path):
    refresh = _refresh()
    source = DATA / ps.PSL_FILE
    out = tmp_path / "public_suffix_list.dat"
    assert refresh.main(["--from", str(source), "--out", str(out)]) == 0
    assert out.read_bytes() == source.read_bytes()
    bad = tmp_path / "bad.dat"
    bad.write_text("co.uk\n", encoding="utf-8")
    out.write_bytes(b"kept")
    assert refresh.main(["--from", str(bad), "--out", str(out)]) == 1
    assert out.read_bytes() == b"kept"


@pytest.mark.parametrize("broken", [b"", b"co.uk\n", b"\xff\xfe not utf-8"])
def test_the_refresh_repairs_a_broken_vendored_copy(tmp_path, monkeypatch, capsys, broken):
    """With data/public_suffix_list.dat truncated the service is already on
    the heuristic fallback, and this script is how the file is replaced: it
    says the copy is unreadable and goes on without the comparisons that
    need it, instead of dying in a traceback."""
    refresh = _refresh()
    source = DATA / ps.PSL_FILE
    vendored = tmp_path / ps.PSL_FILE
    vendored.write_bytes(source.read_bytes()[:100_000] if broken == b"" else broken)
    monkeypatch.setattr(refresh, "VENDORED", vendored)
    assert refresh.main(["--from", str(source), "--dry-run"]) == 0
    assert "unreadable" in capsys.readouterr().err
    assert refresh.main(["--from", str(source)]) == 0
    assert vendored.read_bytes() == source.read_bytes()


def test_the_refresh_reports_the_private_registries_it_moves():
    """A refresh that adds or drops a PRIVATE rule of the heuristic's shape
    moves a registry boundary (public_suffix.private_registries): the
    report says which."""
    refresh = _refresh()
    text = (DATA / ps.PSL_FILE).read_text(encoding="utf-8")
    current = ps.parse(text)
    without = ps.parse(text.replace("\nco.ua\n", "\n", 1))
    lines = "\n".join(refresh.report(without, current))
    assert "co.ua" in lines and "registr" in lines

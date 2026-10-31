"""The registrable domain by the Public Suffix List (api/services/public_suffix.py).

Until 2026-10-28 the service drew the registrable domain (eTLD+1) with a
compound-ccTLD heuristic: a 2-letter ccTLD under a generic second level
(co, com, gov, ac, web, id …) took three labels, anything else two, and the
Russian PSL zones were an overlay on top. It missed real ICANN suffixes —
paypal-secure.my.id was a subdomain of 'my.id' and paypa1.me.uk of 'me.uk',
so the extension's credential guard never saw the brand in the name and
every owner under such a suffix was one "site" — and it invented suffixes:
login.web.de was its own registrable domain, as if web.de were a registry.

The service reads the PSL's ICANN section now, and keeps the heuristic's
splits as a default the named one-owner zones are the exception to
(data/cctld_second_levels.json): an open zone read as one name is a hole,
one owner's read as a registry only costs what it did before.

These tests hold the matcher to the PSL algorithm (exact, wildcard and
exception rules, the default rule) and the ccTLD default, to the vendored
list's integrity, to the Russian overlay's old answers, a site to never
being wider than the heuristic's but under a named zone, and the model's
features to the old reading (they are paired with a trained model; a new
reading needs a retrain).
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path

import pytest

from api.services import public_suffix as ps
from api.services import scoring

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
    assert {"github.io"} <= tiny.private.exact and tiny.icann.exact.isdisjoint({"github.io"})
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


# ── The ccTLD default: a generic second level under a 2-letter TLD ──

@pytest.fixture(scope="module")
def tiny_cc(tiny):
    return tiny.icann._replace(cc_second_levels=frozenset({"co", "com", "gov", "web", "sch"}),
                               cc_names=frozenset({"web.de"}))


@pytest.mark.parametrize(("host", "expected"), [
    # Every generic label under a 2-letter TLD is a suffix, listed or not,
    # as the compound-ccTLD heuristic read it: a stranger's name there is
    # a site of its own …
    ("paypal-login.co.zz", "paypal-login.co.zz"),
    ("a.b.paypal-login.com.de", "paypal-login.com.de"),
    ("kau.gov.hu", "kau.gov.hu"),
    ("co.zz", "co.zz"),
    ("x.web.zz", "x.web.zz"),
    # … but a zone named as one owner's is that owner's name …
    ("login.web.de", "web.de"),
    ("web.de", "web.de"),
    # … a longer listed rule still prevails, and nothing changes under a
    # longer TLD or for a label that is not generic.
    ("login.example.co.uk", "example.co.uk"),
    ("www.school.foo.sch.uk", "school.foo.sch.uk"),
    ("www.city.kobe.jp", "city.kobe.jp"),
    ("a.www.ck", "www.ck"),
    ("x.co.com", "co.com"),
    ("x.org.zz", "org.zz"),
])
def test_the_cctld_default(tiny_cc, host, expected):
    assert tiny_cc.registrable(host) == expected


def test_only_the_labels_a_rule_can_reach_are_converted(monkeypatch):
    """parse_qname maps an 8-bit DNS label to U+FFFD, and doh_upstream's
    zone key reads the registrable domain of every forwarded query: a 4 KB
    name of such labels was punycoded label by label, 4.2 ms of the event
    loop per query against 0.1 ms before the PSL (2026-10-28 final review).
    Now no label is punycoded at all: the rules' IDN labels are looked up
    decoded (SuffixRules.idn_labels), and the answer is the one converting
    every label gives."""
    real = ps.ascii_label
    calls: list[str] = []

    def counting(label: str) -> str:
        calls.append(label)
        return real(label)

    def converting_all(host: str) -> str:
        parts = host.lower().split(".")
        k = ps._RULES.suffix_length([real(p) for p in parts])
        return host if len(parts) <= k else ".".join(parts[-(k + 1):])

    long_name = ".".join(["\ufffd" * 63] * 64)
    monkeypatch.setattr(ps, "ascii_label", counting)
    for tail in ("com", "co.uk", "kobe.jp", "city.kobe.jp", "pvt.k12.ma.us", "spb.ru", "hosting.myjino.ru",
                 "xn--p1ai", "公司.cn", "сочи.рус", "co.zz", "web.de", "ne.pw", "\ufffd"):
        host = f"{long_name}.{tail}"
        calls.clear()
        got = ps.registrable_domain(host)
        assert calls == [], tail
        assert got == converting_all(host), tail
    # Every IDN label of a rule is looked up, and nothing else.
    rule_labels = {label for rule in ps._RULES.exact | ps._RULES.wildcards | ps._RULES.exceptions
                   for label in rule.split(".") if label.startswith("xn--")}
    assert set(ps._RULES.idn_labels.values()) == rule_labels and len(rule_labels) > 100
    assert all(real(u) == a for u, a in ps._RULES.idn_labels.items())
    for host in ("www.例子.公司.cn", "a.отель.сочи.рус", "x.y.公司.香港", "www.東京.jp", "a.b.c.кoбe.jp"):
        calls.clear()
        assert ps.registrable_domain(host) == converting_all(host), host
        assert calls == [], host
    assert ps.registrable_domain("www.例子.公司.cn") == "例子.公司.cn"
    assert ps.registrable_domain("a.отель.сочи.рус") == "отель.сочи.рус"
    # A TLD of two letters decoded (аб, xn--80ac in ASCII) is no 2-letter TLD
    # for the ccTLD default, in either spelling.
    assert ps.registrable_domain("x.com.аб") == "com.аб"
    assert ps.registrable_domain(f"x.com.{real('аб')}") == f"com.{real('аб')}"


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
    # The zones of its shape that are one owner's name, not a registry
    # (data/cctld_second_levels.json 'names': web.de, 1&1's name servers;
    # com.be, Amazon's, SOA root.amazon.com …): read as the PSL reads them.
    ("login.web.de", "web.de"),
    ("www.web.de", "web.de"),
    ("account.id.me", "id.me"),
    ("www.net.hr", "net.hr"),
    ("www.amazon.com.be", "com.be"),
    ("www.in.gr", "in.gr"),
    ("www.ne.se", "ne.se"),
    ("repo.or.cz", "or.cz"),
    ("www.ne.ch", "ne.ch"),
    # Every other zone of its shape stays split, as it split it: the PSL
    # does not list a government's zone (gov.hu, sch.gr) …
    ("kau.gov.hu", "kau.gov.hu"),
    ("www.school.sch.gr", "school.sch.gr"),
    # … nor the free zones of dynamic-DNS services, read as one site each
    # until the 2026-10-28 final review (ChangeIP: ne.pw, asn.im, or.lt …;
    # FreeDNS: govt.hu, mil.nf) …
    ("www.aceoouu-asosmaoemsnouu.adqxeha.ne.pw", "adqxeha.ne.pw"),
    ("paypal-login.ne.pw", "paypal-login.ne.pw"),
    ("www.secure-paypal.asn.im", "secure-paypal.asn.im"),
    ("x.microsoft-login.or.lt", "microsoft-login.or.lt"),
    ("appleid-verify.sch.in", "appleid-verify.sch.in"),
    ("office365-login.govt.hu", "office365-login.govt.hu"),
    ("usmc.mil.nf", "usmc.mil.nf"),
    # … nor one no list knows yet …
    ("login.evil.org.zz", "evil.org.zz"),
    # … nor the PSL's PRIVATE rules of its shape …
    ("acessar-conta-br.co.ua", "acessar-conta-br.co.ua"),
    ("www.acessar-conta-br.co.ua", "acessar-conta-br.co.ua"),
    ("mail.confirm-lnstagram.com.de", "confirm-lnstagram.com.de"),
    ("rainbet.co.no", "rainbet.co.no"),
    ("easybank-kundenservice-mijndomein.co.nl", "easybank-kundenservice-mijndomein.co.nl"),
    ("pracuj-w-domu.co.pl", "pracuj-w-domu.co.pl"),
    ("accounts.jagex.com-cs.co.cz", "com-cs.co.cz"),
    ("shop.evil.biz.ua", "evil.biz.ua"),
    ("lnstagram.com.se", "lnstagram.com.se"),
    # … nor the open zones in neither section (data/cctld_second_levels.json
    # 'registries', the evidence; the default splits them).
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


# ── The ccTLD second levels no PSL section lists (data/cctld_second_levels.json) ──

def _listed(rules: ps.SuffixRules, zone: str) -> bool:
    labels = zone.split(".")
    return rules.suffix_length(labels, default=0) >= len(labels)


def _cctld_file() -> dict:
    return json.loads((DATA / ps.CCTLD_FILE).read_text(encoding="utf-8"))


def test_the_named_zones_are_one_owners_own_and_in_no_psl_section():
    """A zone of the heuristic's shape is a registry unless it is named:
    reading an open zone as one name makes its strangers one site (the
    2026-10-28 final review: ne.pw, asn.im, or.lt, govt.hu …), reading one
    owner's zone as a registry only costs what it cost before. So a name
    must be one company's or organisation's own zone, with its evidence; not
    a government zone (gov, edu, sch …: split, as before, and the guard
    treats each as one site by itself), not in the PSL (else the entry is
    the PSL's to keep), and not a known open zone."""
    data = _cctld_file()
    names = data["names"]
    assert set(names) == ps.CCTLD_NAMES
    assert {"web.de", "id.me", "com.be", "net.hr", "in.gr", "ne.se", "or.cz"} <= set(names)
    from api.services.scoring import _RESTRICTED_ZONE_LABELS

    for zone, evidence in names.items():
        assert zone == ps.ascii_name(zone) and ps.heuristic_suffix(zone), zone
        assert zone.split(".")[0] not in _RESTRICTED_ZONE_LABELS, f"{zone}: a government zone stays split"
        assert not _listed(ps.LIST.icann, zone) and not _listed(ps.LIST.private, zone), f"{zone} is in the PSL"
        assert not _listed(ps.RU_OVERLAY, zone), zone
        assert len(evidence) > 40, f"{zone}: no evidence"
        for host in (zone, f"www.{zone}", f"a.b.{zone}"):
            assert ps.registrable_domain(host) == zone, host
    assert not set(names) & set(data["registries"])


@pytest.mark.parametrize("host", ["paypal.com.govt.hu", "login.gov.gob.li", "apple.com.edu.si", "x.com.go.ro"])
def test_a_tld_bought_under_a_free_zone_with_a_restricted_label_dresses_the_host_up(host):
    """FreeDNS's govt.hu, ChangeIP's gob.li and edu.si, RCS&RDS's go.ro: their
    label reads like a government's, their names are anyone's. Read as
    restricted zones, paypal.com.govt.hu lost its fake-TLD signal and the
    extension's guard took every name there for one site (2026-10-31)."""
    from api.services.scoring import _has_fake_tld_in_subdomain, _registered_tld_lookalike

    assert _registered_tld_lookalike(host) is not None, host
    assert _has_fake_tld_in_subdomain(host), host


def test_no_open_zone_is_a_restricted_one_and_the_governments_stay():
    from api.services.scoring import _RESTRICTED_ZONE_LABELS, _is_restricted_zone, _registered_tld_lookalike

    open_zones = set(_cctld_file()["registries"])
    assert open_zones == ps.CCTLD_OPEN_ZONES
    labelled = {z for z in open_zones if z.split(".")[0] in _RESTRICTED_ZONE_LABELS}
    assert {"govt.hu", "mil.nf", "edu.si", "gob.li", "sch.in", "go.ro"} <= labelled
    assert not any(_is_restricted_zone(z) for z in open_zones)
    for zone in ("gov.hu", "gov.hr", "gov.uk", "ac.uk", "go.jp", "gob.mx", "gov.ru", "edu.ru"):
        assert _is_restricted_zone(zone), zone
    assert _registered_tld_lookalike("com.gov.uk") is None


@pytest.mark.parametrize("host, trusted", [
    ("paypal-login.go.ro", False),   # RCS&RDS's customers' zone, in the top 100k
    ("paypal-login.or.tv", False),
    ("go.ro", True),                 # the zone itself and its www
    ("www.go.ro", True),
    ("paypal-login.gov.ro", True),   # a restricted zone: the government's names
    ("geo.web.ru", True),            # one owner's zone ('names')
    ("www.bbc.co.uk", True),
    ("www.amazon.com.be", True),
])
def test_a_name_under_an_open_zone_in_the_top_list_is_not_the_zones(host, trusted):
    """The top list is folded without the ccTLD default, so go.ro is an
    entry, and every name under it was "safe 0" without analysis until
    2026-10-31 (scoring._is_open_zone_above)."""
    from api.services.scoring import is_trusted_top_domain

    assert is_trusted_top_domain(host) is trusted


def test_the_open_zone_rule_refuses_only_the_open_zones_of_the_top_list():
    """No entry or its www loses the allowlist; a name under an entry does
    only where the entry is an open zone (the FAITID zones and biz.ua were
    refused already, as shared suffixes). or.tv no longer exists and is
    tombstoned (data/top_domains_dead.json): no key at all."""
    from api.services.scoring import TOP_DOMAINS, _is_open_zone_above, top_domain_key

    lost = [h for e in TOP_DOMAINS for h in (e, "www." + e)
            if top_domain_key(h) and _is_open_zone_above(h, top_domain_key(h))]
    assert lost == []
    refused = {e for e in TOP_DOMAINS
               if top_domain_key("mail." + e) == e and _is_open_zone_above("mail." + e, e)}
    assert refused == {"go.ro", "biz.ua", "msk.ru", "msk.su", "nov.ru", "pp.ru", "spb.ru", "spb.su"}


@pytest.mark.parametrize("broken", ["psl", "cctld"])
def test_without_the_zone_data_the_open_zone_rule_stays_out(monkeypatch, broken):
    """The fallback readings split web.de and know no open zone: the rule
    would take login.web.de's allowlist and give paypal-login.go.ro one."""
    if broken == "psl":
        monkeypatch.setattr(ps, "LOAD_ERROR", "OSError: test")
    else:
        monkeypatch.setattr(ps, "CCTLD_NAMES", frozenset())
    assert scoring._is_open_zone_above("login.web.de", "web.de") is False
    assert scoring._is_open_zone_above("paypal-login.go.ro", "go.ro") is False


def test_the_open_zones_stay_split():
    """The free zones found merged by the ICANN-only reading (co.vu, info.gf
    …: 2026-10-28 review) and by the reading with a list of registries
    (ChangeIP's ne.pw — 135 phishing hosts of Phishing.Database's links,
    asn.im, or.lt …; FreeDNS's govt.hu and mil.nf: the final review) are
    split by the default, not by their entry: the entry is the evidence."""
    registries = _cctld_file()["registries"]
    assert {"co.vu", "co.nf", "info.gf", "com.tg", "go.ro",
            "ne.pw", "asn.im", "asn.me", "asn.lc", "sch.in", "or.lt", "or.st", "id.gd", "gob.li", "biz.si",
            "edu.si", "govt.hu", "mil.nf"} <= set(registries)
    for zone, evidence in registries.items():
        assert zone == ps.ascii_name(zone) and ps.heuristic_suffix(zone), zone
        assert not _listed(ps.LIST.icann, zone) and not _listed(ps.LIST.private, zone), f"{zone} is in the PSL"
        assert len(evidence) > 40, f"{zone}: no evidence"
        assert ps.registrable_domain(f"www.x.{zone}") == f"x.{zone}"
        assert ps.registrable_domain(zone) == zone


def test_the_psls_private_registries_of_the_cctld_shape_stay_split():
    """co.ua, co.nl, com.de … are registries by the PSL's own account, if
    only in its PRIVATE section: the default keeps them split (ICANN-only,
    acessar-conta-br.co.ua took co.ua's top-1M rank #278,678 for a vouch).
    The rest of PRIVATE (github.io, blogspot.com) stays out."""
    zones = sorted(r for r in ps.LIST.private.exact
                   if ps.heuristic_suffix(r) and not _listed(ps.LIST.icann, r) and not _listed(ps.RU_OVERLAY, r))
    assert {"co.ua", "co.nl", "co.no", "co.pl", "co.cz", "co.de", "com.de", "com.se", "biz.ua", "ltd.ua"} <= set(zones)
    for zone in zones:
        assert ps.registrable_domain(f"www.x.{zone}") == f"x.{zone}", zone


def _corpus_for_the_invariant() -> list[str]:
    hosts = set(_ru_corpus())
    hosts.update(f"www.{h}" for h in json.loads((DATA / "top_100k.json").read_text(encoding="utf-8")))
    data = _cctld_file()
    for zone in (*data["names"], *data["registries"]):
        hosts.update((zone, f"x.{zone}", f"a.b.{zone}"))
    two_letter = sorted(t for t in ps.LIST.icann.exact if "." not in t and len(t) == 2)
    assert len(two_letter) >= 240
    for tld in (*two_letter, "zz"):
        for label in ps.CCTLD_SECOND_LEVELS:
            hosts.update((f"{label}.{tld}", f"x.{label}.{tld}", f"a.b.x.{label}.{tld}"))
    return sorted(hosts)


def test_a_site_is_never_wider_than_before_but_under_a_named_zone():
    """The reading before 2026-10-28 (legacy_registrable_domain) split every
    generic second level of a 2-letter ccTLD; this one keeps every such
    split and adds the ICANN section's suffixes. So a registrable domain is
    never shorter than the legacy one — no stranger becomes part of a site
    he was not part of — except under a named zone (login.web.de → web.de)."""
    from api.services.scoring import legacy_registrable_domain

    wider = [h for h in _corpus_for_the_invariant()
             if (new := ps.registrable_domain(h)).count(".") < legacy_registrable_domain(h).count(".")
             and new not in ps.CCTLD_NAMES]
    assert wider == []


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
    # Open zones with a restricted label (2026-10-31): the rules read them
    # as anyone's, the model keeps the reading it was trained on.
    "paypal.com.govt.hu", "login.gov.gob.li", "apple.com.edu.si", "x.com.go.ro",
)


def test_the_models_features_never_read_the_public_suffix_list(monkeypatch):
    """The served model was trained on the old reading (model_meta.json
    feature_data); a new reading is a retrain, not a side effect."""
    from api.services.ml_features import extract_ml_features
    from api.services.url_features import extract_features

    before = {h: (extract_ml_features(h), extract_features(h, {})) for h in _FEATURE_HOSTS}
    monkeypatch.setattr(ps, "_RULES", _NoPsl())
    monkeypatch.setattr(scoring, "CCTLD_OPEN_ZONES", frozenset())
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
    # … a registry the ccTLD default splits neither (biz.ua is #5653 of the
    # top-10k) …
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
    # Registrations under the ccTLD default's zones, as the heuristic had
    # them: ICANN-only, 1,231 feed hosts lost the check (74 co.vu ones went
    # caution -> safe).
    ("181page9707ik0647recovery789.co.vu", True),
    ("confirm-lnstagram.com.de", True),
    ("acessar-conta-br.co.ua", True),
    ("mail.confirm-lnstagram.com.de", False),
    # … and under every zone of that shape the PSL does not list (2026-10-28
    # final review: secure-login-verify.ne.pw lost the +8 and went
    # dangerous 56 -> caution 38); not under a named one (login.web.de is
    # web.de's subdomain).
    ("secure-login-verify.ne.pw", True),
    ("nid-session.govt.hu", True),
    ("evil.com.tv", True),
    ("login.web.de", False),
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
    ("x.paypal-login.ne.pw", {"ne.pw": 5_000}, None),
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
        # … and every other zone of that shape the PSL does not list: SURBL's
        # list carries 147 of them (com.tv, biz.nf, mil.nf, gov.hu …), which
        # a list of registries left merged (2026-10-28 final review).
        "x.evil.com.tv": "evil.com.tv",
        "evil.biz.nf": "evil.biz.nf",
        "kau.gov.hu": "kau.gov.hu",
        "www.paypal-login.ne.pw": "paypal-login.ne.pw",
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
    # Feed phishing under the ccTLD default's zones, named 'com' when
    # com.de was read as the site (mail.confirm-lnstagram.com.de went
    # dangerous 53 -> caution 43 on the ICANN-only reading); the heuristic,
    # and so the model, read the registrant's name.
    ("confirm-lnstagram.com.de", "confirm", 1.0),
    ("mail.confirm-lnstagram.com.de", "confirm", 1.0),
    ("icloud-alert.com.de", "alert", 1.0),
    ("trezor-wallet.com.de", "wallet", 1.0),
    # Under the free zones no list knew, named 'ne', 'asn', 'or', 'sch' and
    # 'govt' by the PSL's reading with a list of registries (2026-10-28 final
    # review: wellsfargo-login.or.lt went caution 30 -> safe 20).
    ("secure-login-verify.ne.pw", "secure", 1.0),
    ("paypal-login.ne.pw", "login", 1.0),
    ("secure-paypal.asn.im", "secure", 1.0),
    ("wellsfargo-login.or.lt", "login", 1.0),
    ("appleid-verify.sch.in", "verify", 1.0),
    ("office365-login.govt.hu", "login", 1.0),
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
    # The free zones' tenants are recordable under their own names again.
    assert confirmed_threats.site_name("www.paypal-login.ne.pw") == "paypal-login.ne.pw"
    for host in ("paypal-login.ne.pw", "secure-paypal.asn.im", "wellsfargo-login.or.lt", "nid-session.govt.hu"):
        assert confirmed_threats.is_recordable_host(host), host


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


def test_the_refresh_reports_what_moves_a_boundary():
    """A dropped ICANN rule makes every name under it one site, unless the
    ccTLD default keeps the zone split (com.cn); a zone of
    data/cctld_second_levels.json's 'names' the list now carries is the
    list's to read (tests above fail until it is dropped there). The report
    says which, so neither is merged silently (2026-10-28 final review)."""
    refresh = _refresh()
    text = (DATA / ps.PSL_FILE).read_text(encoding="utf-8")
    current = ps.parse(text)
    candidate = ps.parse(text.replace("\nmy.id\n", "\n", 1).replace("\ncom.cn\n", "\nweb.de\n", 1))
    lines = refresh.report(candidate, current)
    merged = next(line for line in lines if "one site" in line)
    assert "my.id" in merged and "com.cn" not in merged
    kept = next(line for line in lines if "still split" in line)
    assert "com.cn" in kept and "my.id" not in kept
    assert any("web.de" in line and "names" in line for line in lines)
    assert not any("one site" in line or "names" in line for line in refresh.report(current, current))

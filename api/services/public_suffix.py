"""The registrable domain (eTLD+1) by the Public Suffix List.

One rule for "where one site ends", for the scorer, the DoH gateway and the
browser extension (scripts/build_extension_scorer_data.py ships the same
rules to utils/name-rules.js):

  * the PSL's ICANN section — exact, wildcard ('*.kobe.jp') and exception
    ('!city.kobe.jp') rules, and the default rule (an unlisted TLD is a
    one-label suffix) — from data/public_suffix_list.dat, vendored with its
    VERSION line and refreshed by scripts/refresh_public_suffix_list.py;
  * the Russian zones of data/ru_public_suffixes.json on top (spb.ru,
    gov.ru, the .рус cities …): all 102 of its rules are in the PSL's
    PRIVATE section, and the scorer has read them as registries since
    2026-09-27 (scoring._ru_registrable_domain), so they stay;
  * the registry overlay (REGISTRY_OVERLAY): the second levels of 2-letter
    ccTLDs the compound-ccTLD heuristic below split and where every name is
    a separate registrant's, though the ICANN section does not list them —
    the PSL's PRIVATE rules of that shape (co.ua, com.de, co.nl, co.pl,
    biz.ua …, private_registries()) and data/cctld_registries.json, those in
    neither section (co.vu, co.nf, info.gf, com.tg …). Read ICANN-only,
    1,262 hosts of the 2026-10-24 feed snapshot (co.vu 1,100, com.de 74,
    co.ua 21) became subdomains of their zone: one site with every stranger
    there, named 'co' or 'com' to the brand and keyword checks, and vouched
    for by the zone's top-1M rank (co.ua #278,678, co.cz #129,724) — the
    2026-10-28 review.

The rest of the PRIVATE section (github.io, blogspot.com, vercel.app …) is
deliberately left out: which platform's subdomains are separate customers is
decided by the curated lists (data/hosting_platforms.json, tenant zones,
public_suffixes_in_top.json), which also say whose rank vouches for whom.
Mixed in silently, the list would have split 194,233 of the 699,287 hosts of
the 2026-10-24 feed snapshot into "own sites" behind the curated machinery's
back. None of the overlay's zones has a platform's shape: a ccTLD's second
level is a registry, not somebody's product.

Until 2026-10-28 the rule was a compound-ccTLD heuristic (a 2-letter ccTLD
under a generic second level — co, com, gov, ac, web, id … — takes three
labels, else two), kept here as heuristic_registrable_domain() because the
phishing model's features are still read with it (scoring.
legacy_registrable_domain; a new reading is a retrain). Against the PSL,
measured on 2026-10-27/28: it read 572 of the top-100k names under 122 ICANN
suffixes it did not know (my.id, io.vn, hl.cn, me.uk, ltd.uk, nhs.uk, lg.jp,
bank.in, gc.ca, sp.gov.br …) as one site per suffix, and invented 23
suffixes that no PSL section lists (web.de, id.me, gov.hu, sch.gr, net.hr …).
On the feed snapshot it differed on 5,463 hosts (0.78%); 3,584 of them under
my.id, where paypal-secure.my.id was the name 'my' to every brand check.

Cost, measured 2026-10-28 on 200,000 top-100k, www. and feed hosts:
1.2 µs a call (the heuristic took 0.56 µs, the scorer's old "Russian zone,
else heuristic" 2.1 µs), ~45 ms to parse the list once at import. A name
under a TLD with no multi-label rule (.com, .net, .org, .ru …) is answered
after one dict lookup.

Stdlib only: the DoH gateway and the refresh script import it, and so may
the builders that run without the scorer's dependencies.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Iterable, Mapping, NamedTuple, Optional

logger = logging.getLogger("cleanway.public_suffix")

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data")
PSL_FILE = "public_suffix_list.dat"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
RU_OVERLAY_FILE = "ru_public_suffixes.json"
REGISTRY_FILE = "cctld_registries.json"

_SECTIONS = ("ICANN", "PRIVATE")


def ascii_label(label: str) -> str:
    """One label in its ASCII (punycode) spelling, as the rules are stored.
    The same conversion as scoring._ascii_label and the builders."""
    if label.isascii():
        return label
    try:
        return "xn--" + label.encode("punycode").decode("ascii")
    except UnicodeError:
        return label


def ascii_name(name: str) -> str:
    return ".".join(ascii_label(p) for p in name.lower().split("."))


def is_ip_literal(dom: str) -> bool:
    # IPv6 (bare or as a URL host, [::1]) has a colon; an IPv4 address ends in
    # a number, which no TLD is (RFC 3696 §2). Its registrable domain is
    # itself, not its last two numbers (10.0.1.10 vs 192.168.1.10).
    if ":" in dom:
        return True
    if not dom[-1:].isdigit():  # the common case, without splitting
        return False
    tld = dom.rpartition(".")[2]
    return tld.isascii() and tld.isdigit()


class SuffixRules(NamedTuple):
    """One set of PSL rules, in ASCII: exact rules, the bases of '*.' rules
    and the names of '!' rules, with the longest rule (in labels) under each
    TLD, so a name under .com — no rule longer than the TLD — is answered
    after one lookup."""
    exact: frozenset[str]
    wildcards: frozenset[str]
    exceptions: frozenset[str]
    depth: Mapping[str, int]
    exception_tlds: frozenset[str]

    def suffix_length(self, labels: list[str], default: int = 1) -> int:
        """How many trailing labels of `labels` (ASCII) are the public
        suffix: the prevailing rule's length — an exception rule's minus
        one, else the longest matching rule's — or `default` when no rule
        longer than one label matches (the PSL's default rule '*': 1)."""
        n = len(labels)
        depth = self.depth.get(labels[-1], 1) if n else 1
        if depth < 2 or n < 2:
            return default
        top = min(depth, n)
        if labels[-1] in self.exception_tlds:
            for k in range(top, 1, -1):
                if ".".join(labels[-k:]) in self.exceptions:
                    return k - 1
        for k in range(top, 1, -1):
            if ".".join(labels[-k:]) in self.exact or ".".join(labels[1 - k:]) in self.wildcards:
                return k
        return default

    def registrable(self, host: str) -> str:
        """The registrable domain of `host` under these rules, in the
        spelling it was given (ASCII or decoded IDN): the public suffix plus
        one label. A suffix by itself, a single label and an IP literal
        answer themselves; '' for nothing."""
        dom = (host or "").lower().strip(".")
        if not dom or is_ip_literal(dom):
            return dom
        parts = dom.split(".")
        if len(parts) == 1:
            return dom
        labels = parts if dom.isascii() else [ascii_label(p) for p in parts]
        k = self.suffix_length(labels)
        return dom if len(parts) <= k else ".".join(parts[-(k + 1):])


def rules_from(exact: Iterable[str], wildcards: Iterable[str] = (), exceptions: Iterable[str] = ()) -> SuffixRules:
    exact, wildcards, exceptions = frozenset(exact), frozenset(wildcards), frozenset(exceptions)
    depth: dict[str, int] = {}
    for names, extra in ((exact, 0), (wildcards, 1), (exceptions, 0)):
        for name in names:
            tld = name.rpartition(".")[2]
            depth[tld] = max(depth.get(tld, 1), name.count(".") + 1 + extra)
    return SuffixRules(exact, wildcards, exceptions, depth, frozenset(e.rpartition(".")[2] for e in exceptions))


def merge(*rule_sets: SuffixRules) -> SuffixRules:
    return rules_from(
        frozenset().union(*(r.exact for r in rule_sets)),
        frozenset().union(*(r.wildcards for r in rule_sets)),
        frozenset().union(*(r.exceptions for r in rule_sets)),
    )


class PublicSuffixList(NamedTuple):
    version: str
    commit: str
    icann: SuffixRules
    private: SuffixRules


def _check_rule(line: str, lineno: int) -> str:
    body = line[1:] if line.startswith("!") else line[2:] if line.startswith("*.") else line
    labels = body.split(".")
    if not body or "" in labels or any("*" in label or "!" in label for label in labels):
        raise ValueError(f"public suffix list line {lineno}: malformed rule {line!r}")
    return ascii_name(body)


def parse(text: str) -> PublicSuffixList:
    """The list's VERSION, COMMIT and its two sections' rules, in ASCII.

    Strict, so a truncated or substituted file fails here (and in
    tests/test_public_suffix.py) instead of drawing site boundaries wrong:
    both sections opened and closed in order, a VERSION line, every rule
    well-formed (no empty label, '*' only as the leftmost label, '!' only
    in front), and every exception under a wildcard of its own section."""
    version = commit = ""
    found: dict[str, tuple[set[str], set[str], set[str]]] = {}
    section: Optional[str] = None
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if line.startswith("// VERSION:"):
            version = line.split(":", 1)[1].strip()
        elif line.startswith("// COMMIT:"):
            commit = line.split(":", 1)[1].strip()
        for name in _SECTIONS:
            if line == f"// ===BEGIN {name} DOMAINS===":
                if section is not None or name in found:
                    raise ValueError(f"public suffix list line {lineno}: unexpected {line!r}")
                section = name
                found[name] = (set(), set(), set())
            elif line == f"// ===END {name} DOMAINS===":
                if section != name:
                    raise ValueError(f"public suffix list line {lineno}: unexpected {line!r}")
                section = None
        if not line or line.startswith("//"):
            continue
        if section is None:
            raise ValueError(f"public suffix list line {lineno}: rule outside a section: {line!r}")
        # "Each line is only read up to the first whitespace" (publicsuffix.org/list).
        rule = line.split()[0]
        exact, wild, exc = found[section]
        name = _check_rule(rule, lineno)
        (exc if rule.startswith("!") else wild if rule.startswith("*.") else exact).add(name)
    if section is not None or set(found) != set(_SECTIONS):
        raise ValueError("not the Public Suffix List: the ICANN and PRIVATE section markers are missing or unclosed")
    if not version:
        raise ValueError("public suffix list has no '// VERSION:' line")
    for name, (_exact, wild, exc) in found.items():
        orphans = sorted(e for e in exc if e.partition(".")[2] not in wild)
        if orphans:
            raise ValueError(f"public suffix list {name} exceptions under no wildcard: {orphans[:5]}")
    icann, private = (rules_from(*found[name]) for name in _SECTIONS)
    return PublicSuffixList(version, commit, icann, private)


def overlay_rules(rules: Iterable[str]) -> SuffixRules:
    """Rules in data/ru_public_suffixes.json's form: 'spb.ru',
    '*.hosting.myjino.ru' (no exceptions there)."""
    rules = [r.lower().strip(".") for r in rules]
    return rules_from((r for r in rules if not r.startswith("*.")), (r[2:] for r in rules if r.startswith("*.")))


# ── The compound-ccTLD heuristic: the reading before 2026-10-28 ──
#
# Verbatim from doh_gateway._registrable_domain as it was on 2026-10-27
# (scripts/build_top_domains.py keeps a copy for the popularity ranking, and
# the extension one: name-rules.js heuristicRegistrable). Only the phishing
# model's inputs read it now (scoring.legacy_registrable_domain): its
# features are paired with a trained model (model_meta.json feature_data),
# so they change at a retrain, not with this rule.

# Generic second-level labels used under 2-letter ccTLDs (com.cn, co.nz, com.tr,
# co.il, com.ar, ...).
CCTLD_SECOND_LEVELS = frozenset({
    "com", "co", "org", "net", "gov", "edu", "ac", "mil", "gob", "gouv",
    "or", "ne", "go", "in", "nom", "gen", "ltd", "plc", "sch", "asn",
    "id", "biz", "info", "web", "gv", "govt",
})
_HEURISTIC_COMPOUND = frozenset({
    "co.uk", "ac.uk", "gov.uk", "org.uk", "co.jp", "co.in",
    "com.au", "com.br", "com.mx", "co.kr", "co.za", "com.sg",
})


def heuristic_suffix(name: str) -> bool:
    """Does heuristic_registrable_domain() read the 2-label `name` as a
    public suffix (co.uk, com.de, co.vu, web.de), i.e. keep x.<name> apart?"""
    parts = name.split(".")
    if len(parts) != 2:
        return False
    return name in _HEURISTIC_COMPOUND or (len(parts[1]) == 2 and parts[0] in CCTLD_SECOND_LEVELS)


def heuristic_registrable_domain(qname: str) -> str:
    """The old best-effort registrable domain: the last three labels for a
    2-letter ccTLD under a generic second level (apple.com.cn, bbc.co.uk),
    else the last two. A name of one or two labels answers itself."""
    if not qname:
        return ""
    parts = qname.strip(".").lower().split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    last_two = ".".join(parts[-2:])
    if last_two in _HEURISTIC_COMPOUND:
        return ".".join(parts[-3:])
    tld, sld = parts[-1], parts[-2]
    if len(tld) == 2 and sld in CCTLD_SECOND_LEVELS:
        return ".".join(parts[-3:])
    return last_two


def _covered(rules: SuffixRules, zone: str) -> bool:
    """Is `zone` (ASCII) a public suffix under `rules` by itself?"""
    labels = zone.split(".")
    return rules.suffix_length(labels, default=0) >= len(labels)


def private_registries(psl: PublicSuffixList, ru: Optional[SuffixRules] = None) -> frozenset[str]:
    """The PSL's PRIVATE-section rules the compound-ccTLD heuristic also read
    as suffixes (heuristic_suffix: co.ua, com.de, com.se, co.nl, co.no,
    co.pl, co.cz, co.de, biz.ua, ltd.ua, gov.nl …: 30 on the list of
    2026-10-22), less those the ICANN section or the Russian overlay already
    covers: registries by the PSL's own account, split before 2026-10-28
    and kept split. Taken from the vendored list, so a refresh that adds or
    drops one moves the boundary (scripts/refresh_public_suffix_list.py
    reports it)."""
    ru = RU_OVERLAY if ru is None else ru
    return frozenset(r for r in psl.private.exact
                     if heuristic_suffix(r) and not _covered(psl.icann, r) and not _covered(ru, r))


def _load_curated_registries() -> frozenset[str]:
    try:
        with open(os.path.join(_DATA_DIR, REGISTRY_FILE), encoding="utf-8") as f:
            return frozenset(ascii_name(z) for z in json.load(f)["zones"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        logger.error("%s not loaded (%s): its zones read as names", REGISTRY_FILE, exc)
        return frozenset()


# ── The loaded rules ──

def _load() -> tuple[Optional[PublicSuffixList], SuffixRules, Optional[str]]:
    try:
        with open(os.path.join(_DATA_DIR, RU_OVERLAY_FILE), encoding="utf-8") as f:
            ru = overlay_rules(json.load(f))
    except (OSError, ValueError) as exc:
        logger.error("%s not loaded (%s): Russian zones read as names", RU_OVERLAY_FILE, exc)
        ru = rules_from(())
    try:
        with open(os.path.join(_DATA_DIR, PSL_FILE), encoding="utf-8") as f:
            return parse(f.read()), ru, None
    except (OSError, ValueError) as exc:
        logger.error("%s not loaded (%s): registrable domains fall back to the compound-ccTLD heuristic",
                     PSL_FILE, exc)
        return None, ru, f"{type(exc).__name__}: {exc}"


LIST, RU_OVERLAY, LOAD_ERROR = _load()
CURATED_REGISTRIES = _load_curated_registries()
REGISTRY_OVERLAY = rules_from(
    (private_registries(LIST) if LIST is not None else frozenset()) | CURATED_REGISTRIES)
# ICANN, the Russian overlay and the registry overlay in one table, as one
# list's rules: the longest matching rule prevails. The Russian overlay's
# TLDs carry no ICANN rule longer than the TLD (tests/test_public_suffix.py),
# so there the Russian rule is the one that applies — scoring's "Russian
# rule, else ..." order; the registry overlay's exact 2-label rules simply
# join their TLD's ICANN rules (name-rules.js merges them the same way).
_RULES: Optional[SuffixRules] = merge(LIST.icann, RU_OVERLAY, REGISTRY_OVERLAY) if LIST is not None else None


def registrable_domain(host: str) -> str:
    """The registrable domain of `host` (ASCII or decoded IDN; case and a
    trailing dot ignored), in the spelling it was given:
    login.example.co.uk → example.co.uk, paypal-secure.my.id → itself,
    login.web.de → web.de, kvs.gov.spb.ru → gov.spb.ru,
    www.acessar-conta-br.co.ua → acessar-conta-br.co.ua. A public suffix by
    itself, a single label and an IP literal answer themselves."""
    rules = _RULES
    if rules is None:  # the vendored list did not load (logged at import);
        # the heuristic splits the registry overlay's zones by itself
        dom = (host or "").lower().strip(".")
        k = RU_OVERLAY.suffix_length([ascii_label(p) for p in dom.split(".")], default=0) if dom else 0
        return ".".join(dom.split(".")[-(k + 1):]) if k else heuristic_registrable_domain(dom)
    return rules.registrable(host)

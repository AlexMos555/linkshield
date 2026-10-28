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
  * the ccTLD default (SuffixRules.cc_second_levels): a generic second
    level under a 2-letter TLD — co, com, net, org, gov, edu, web, id …,
    CCTLD_SECOND_LEVELS — is a public suffix whether a PSL section lists it
    or not, as the compound-ccTLD heuristic below read it, except the zones
    data/cctld_second_levels.json names as one owner's (web.de, id.me,
    com.be …: CCTLD_NAMES, read as the PSL reads them).

The default splits because the two ways of being wrong are not alike. An
open zone read as one name makes every stranger under it one site with the
attacker: named 'co' or 'ne' to the brand and keyword checks, no apex for
"no MX", a password form posting to a neighbour "the same site" to the
extension's guard, the zone's rank vouching for all of them. Read
ICANN-only, 1,262 hosts of the 2026-10-24 feed snapshot (co.vu 1,100, com.de
74, co.ua 21) were (the 2026-10-28 review); with a list of such registries
on top, the zones nobody had listed still were — ChangeIP's free ne.pw,
asn.im, or.lt …, FreeDNS's govt.hu and mil.nf, 135 phishing hosts of
Phishing.Database's links under ne.pw alone (the final review: 5,148 zones
of that shape are in no PSL section, 1,844 of them have name servers). One
owner's zone read as a registry only costs what it cost before 2026-10-28
(login.web.de its own site), and the named zones are those that cost
something. So registrable_domain() is never shorter than the heuristic's
reading but under a named zone (tests/test_public_suffix.py): it only adds
the ICANN suffixes the heuristic did not know.

The rest of the PRIVATE section (github.io, blogspot.com, vercel.app …) is
deliberately left out: which platform's subdomains are separate customers is
decided by the curated lists (data/hosting_platforms.json, tenant zones,
public_suffixes_in_top.json), which also say whose rank vouches for whom.
Mixed in silently, the list would have split 194,233 of the 699,287 hosts of
the 2026-10-24 feed snapshot into "own sites" behind the curated machinery's
back. Its rules of the ccTLD default's shape (co.ua, com.de, co.nl …) are
split by the default anyway.

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
under a TLD with no multi-label rule (.com, .net, .org …) is answered
after one dict lookup, and no label of a non-ASCII name is punycoded: the
rules' IDN labels are looked up decoded (SuffixRules.idn_labels), as many as
a rule can reach (four at most).

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
CCTLD_FILE = "cctld_second_levels.json"

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
    after one lookup. With cc_second_levels, also the ccTLD default: each of
    those labels under any 2-letter TLD is a rule of two labels, but for the
    zones in cc_names (the service's rules; a parsed list has neither)."""
    exact: frozenset[str]
    wildcards: frozenset[str]
    exceptions: frozenset[str]
    depth: Mapping[str, int]
    exception_tlds: frozenset[str]
    cc_second_levels: frozenset[str] = frozenset()
    cc_names: frozenset[str] = frozenset()
    idn_labels: Mapping[str, str] = {}

    def _cc_default(self, labels: list[str]) -> bool:
        tld = labels[-1]
        return (len(tld) == 2 and labels[-2] in self.cc_second_levels
                and labels[-2] + "." + tld not in self.cc_names)

    def suffix_length(self, labels: list[str], default: int = 1) -> int:
        """How many trailing labels of `labels` (ASCII) are the public
        suffix: the prevailing rule's length — an exception rule's minus
        one, else the longest matching rule's, the ccTLD default among them
        — or `default` when no rule longer than one label matches (the
        PSL's default rule '*': 1). Only the last max(depth) labels are
        read."""
        n = len(labels)
        if n < 2:
            return default
        tld = labels[-1]
        depth = self.depth.get(tld, 1)
        cc = self._cc_default(labels)
        if depth < 2 and not cc:
            return default
        top = min(depth, n)
        if tld in self.exception_tlds:
            for k in range(top, 1, -1):
                if ".".join(labels[-k:]) in self.exceptions:
                    return k - 1
        for k in range(top, 1, -1):
            if ".".join(labels[-k:]) in self.exact or ".".join(labels[1 - k:]) in self.wildcards:
                return k
        return 2 if cc else default

    def registrable(self, host: str) -> str:
        """The registrable domain of `host` under these rules, in the
        spelling it was given (ASCII or decoded IDN): the public suffix plus
        one label. A suffix by itself, a single label and an IP literal
        answer themselves; '' for nothing.

        A non-ASCII name is not punycoded: only the labels a rule can reach
        are looked up in idn_labels (_rule_label). The DoH gateway asks
        this for every query it forwards (doh_upstream._zone_of), and a
        4 KB name of 8-bit labels, each punycoded, cost 4.2 ms of the event
        loop (2026-10-28 final review)."""
        dom = (host or "").lower().strip(".")
        if not dom or is_ip_literal(dom):
            return dom
        parts = dom.split(".")
        n = len(parts)
        if n == 1:
            return dom
        if dom.isascii():
            labels = parts
        else:
            tld = self._rule_label(parts[-1])
            if not tld.isascii():  # an IDN TLD no rule has: the default rule
                return ".".join(parts[-2:])
            reach = self.depth.get(tld, 1)
            if self.cc_second_levels and len(tld) == 2:
                reach = max(reach, 2)
            if reach < 2:
                return ".".join(parts[-2:])
            labels = [self._rule_label(p) for p in parts[-reach:-1]] + [tld]
        k = self.suffix_length(labels)
        return dom if n <= k else ".".join(parts[-(k + 1):])

    def _rule_label(self, label: str) -> str:
        """`label` as the rules spell it: an ASCII label as it is, a decoded
        IDN label in punycode when a rule has it (idn_labels), any other as
        it is — it matches no rule either way, since punycode is one-to-one
        (a wildcard's label matches anything and is never compared)."""
        return label if label.isascii() else self.idn_labels.get(label, label)


def rules_from(exact: Iterable[str], wildcards: Iterable[str] = (), exceptions: Iterable[str] = ()) -> SuffixRules:
    exact, wildcards, exceptions = frozenset(exact), frozenset(wildcards), frozenset(exceptions)
    depth: dict[str, int] = {}
    idn: dict[str, str] = {}
    seen: set[str] = set()
    for names, extra in ((exact, 0), (wildcards, 1), (exceptions, 0)):
        for name in names:
            tld = name.rpartition(".")[2]
            depth[tld] = max(depth.get(tld, 1), name.count(".") + 1 + extra)
            if "xn--" not in name:
                continue
            for label in name.split("."):
                if label.startswith("xn--") and label not in seen:
                    seen.add(label)
                    try:
                        idn[label[4:].encode("ascii").decode("punycode")] = label
                    except UnicodeError:  # no label punycodes to it: nothing to look up
                        pass
    return SuffixRules(exact, wildcards, exceptions, depth, frozenset(e.rpartition(".")[2] for e in exceptions),
                       idn_labels=idn)


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


def _load_cctld_names() -> frozenset[str]:
    """The zones of data/cctld_second_levels.json's 'names': one owner's,
    read as a name rather than by the ccTLD default. Without the file every
    such zone is split, the reading before 2026-10-28 — never the other way
    round."""
    try:
        with open(os.path.join(_DATA_DIR, CCTLD_FILE), encoding="utf-8") as f:
            return frozenset(ascii_name(z) for z in json.load(f)["names"])
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        logger.error("%s not loaded (%s): one owner's ccTLD zones (web.de, id.me …) read as registries",
                     CCTLD_FILE, exc)
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
CCTLD_NAMES = _load_cctld_names()
# ICANN and the Russian overlay in one table, as one list's rules, with the
# ccTLD default: the longest matching rule prevails. The Russian overlay's
# TLDs carry no ICANN rule longer than the TLD (tests/test_public_suffix.py),
# so there the Russian rule, else the ccTLD default, is the one that applies
# — scoring's "Russian rule, else the heuristic" order; elsewhere the
# default is one more two-label rule (name-rules.js adds it the same way).
def service_rules(psl: PublicSuffixList) -> SuffixRules:
    """The rules registrable_domain() reads with `psl` vendored (the refresh
    script asks what a new list would change)."""
    return merge(psl.icann, RU_OVERLAY)._replace(cc_second_levels=CCTLD_SECOND_LEVELS, cc_names=CCTLD_NAMES)


_RULES: Optional[SuffixRules] = service_rules(LIST) if LIST is not None else None


def registrable_domain(host: str) -> str:
    """The registrable domain of `host` (ASCII or decoded IDN; case and a
    trailing dot ignored), in the spelling it was given:
    login.example.co.uk → example.co.uk, paypal-secure.my.id → itself,
    kvs.gov.spb.ru → gov.spb.ru, www.acessar-conta-br.co.ua →
    acessar-conta-br.co.ua, x.paypal-login.ne.pw → paypal-login.ne.pw,
    kau.gov.hu → itself, login.web.de → web.de (a named zone). A public
    suffix by itself, a single label and an IP literal answer themselves."""
    rules = _RULES
    if rules is None:  # the vendored list did not load (logged at import):
        # the Russian zones, else the heuristic — the reading before 2026-10-28
        dom = (host or "").lower().strip(".")
        parts = dom.split(".") if dom else []
        reach = max(RU_OVERLAY.depth.values(), default=1)
        k = RU_OVERLAY.suffix_length([RU_OVERLAY._rule_label(p) for p in parts[-reach:]], default=0) if parts else 0
        return ".".join(parts[-(k + 1):]) if k else heuristic_registrable_domain(dom)
    return rules.registrable(host)

#!/usr/bin/env python3
"""Build the browser extension's copy of the server's name-rule data.

The extension scores a site with no network before (and, when the API is
slow or unreachable, instead of) asking the server. Its brand list was a
hand-copied 50 names with no Russian brand, and its PSL helper knew no
Russian zone: sberbamk.ru and t1nkoff.ru scored 0, kvs.gov.spb.ru (the St
Petersburg government) 50/caution. The server fixed both in PRs #61 and #62;
this script carries the fix across instead of a second hand copy.

Everything is read from the server's own module, api.services.scoring, which
loads it from data/typosquat_targets.json, data/typosquat_targets_ru.json and
data/ru_public_suffixes.json — so the extension compares against exactly the
names, official domains, exemptions and per-name switches the server does.
Evidence strings stay on the server; the extension only needs the verdicts.

Outputs:
    packages/extension-core/src/utils/scorer-data.js
        The data, as a classic script that sets `cleanwayScorerData` on the
        global object (content scripts) or `self` (the background module).
        Read by src/utils/name-rules.js.
    tests/data/extension_name_rules_parity.tsv
        What the server's name rules answer for ~6,000 hosts: the labelled
        Russian sets, every listed brand domain, the seeded typo variants of
        every Russian brand name and a sample of the global ones, and edge
        cases. scripts/test-local-scorer.mjs holds the JavaScript port of the
        rules (name-rules.js) to this table in all four extension trees, so
        a server rule change that is not ported fails CI.

Usage:
    python3 scripts/build_extension_scorer_data.py           # write both
    python3 scripts/build_extension_scorer_data.py --check   # exit 1 if stale
    bash scripts/build-extensions.sh                          # then fan out

No network. tests/test_extension_scorer_data.py runs --check in pytest.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable, Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DATA_JS = ROOT / "packages" / "extension-core" / "src" / "utils" / "scorer-data.js"
PARITY_TSV = ROOT / "tests" / "data" / "extension_name_rules_parity.tsv"
LABELLED_SETS = (
    ROOT / "tests" / "data" / "ru_heuristics_legit.txt",
    ROOT / "tests" / "data" / "ru_heuristics_phish.txt",
    ROOT / "data" / "benchmark_legit_ru.txt",
)
# One in this many seeded variants of the GLOBAL brands goes into the parity
# table (all of the Russian ones do): the global rules did not change in this
# port's source PRs, and 8,000 rows would add little but size.
GLOBAL_VARIANT_STRIDE = 4

# Shapes the rules were changed for, each named in PR #61 / #62 or found
# while porting. Not labelled: the table records whatever the server says.
EDGE_CASES = (
    # #61: PSL-aware registrable domain, length rules, fake TLDs under zones
    "kvs.gov.spb.ru", "zenit.kfis.gov.spb.ru", "gov.spb.ru", "ako.ru", "etsp.ru", "ngpedia.ru",
    "ikar.ru", "ugpr.ru", "spb.ru", "adm.nov.ru", "museum.vladimir.ru", "vk.com.msk.ru",
    "gosuslugi.gov.msk.ru", "paypal.com.spb.ru", "sberbank.ru.msk.ru", "com.msk.ru",
    "edu.gov.ru", "a.edu.gov.ru", "x.spb.ru", "a.b.hosting.myjino.ru", "b.hosting.myjino.ru",
    "dhl.top", "dh1.com", "up5.com", "1kea.com", "eb4y.com", "c1ti.com", "dhll.com", "upss.com",
    "office365.com", "0ffice365.com", "sberbank.spb.ru", "vk.nov.ru", "gosuslugi-lk.spb.ru",
    "vk-login.nov.ru", "ok-stroy.spb.ru", "gook.spb.ru", "paypal.spb.ru", "paypal.com.ru",
    "cdek.msk.ru", "beeline.com.ru", "megafon.spb.ru",
    # #62: Russian brands, exemptions, slips, shared names, zones
    "sberbamk.ru", "t1nkoff.ru", "gosuslugl.ru", "0zon.ru", "wildberies.ru", "avlto.ru",
    "yandex.ru.com", "yandx.ru", "yandx.ru.com", "vk.ru.com", "mail.ru.com", "avito-ru.com",
    "sberbank-ru.com", "sberbankru.com", "gosuslugirus.ru", "vtb-team.ru", "theozon.ru",
    "tbankapp.ru", "mtscom.ru", "vkweb.ru", "thevk.net", "gomts.com", "mts-team.com",
    "trybeeline.com", "ozonweb.com", "ozon.shop", "vtb.top", "ozon.pl", "ozon.co", "tbank.com",
    "tbank.help", "tele2.top", "tele5.de", "megafox.ru", "tirkoff.ru", "beelink.ru",
    "swedbank.com", "mbank.pl", "upstore.ru", "aviator.com", "kontakt.ru", "rutor.ru",
    "altabank.ru", "oberbank.at", "gazorombank.ru", "sovkombank.ru", "yandez.ru", "magafon.ru",
    "wegafon.ru", "51gosuslugi.ru", "23gosuslugi.ru", "irsnet.gov", "mydpd.at", "myups.biz",
    "dhllogin.com", "ozone.pl", "zoon.ru", "megafoon.nl",
    "xn--90ab2c.xn--p1ai", "www.xn--90ab2c.xn--p1ai", "online.xn--90ab2c.xn--p1ai",
    "xn--90ab2c.xn--p1acf", "xn--80abap1arsf.xn--p1ai", "xn--c1aapkosapc.xn--p1ai", "xn--90ab2c.com",
    # the extension's own regression table (scripts/test-local-scorer.mjs)
    "google.com", "paypal.com", "github.io", "metamask.github.io", "paypa1.com",
    "paypal.evil.com", "paypal.com.evil.xyz", "wellsfargo-secure.com", "rnetamask.io",
    "apple.com.cn", "hsbc.co.uk", "barclays.co.uk", "signin.ebay.co.uk", "store.steampowered.com",
    "login.microsoftonline.com.evil.tk", "sub.domain.example.co.uk", "www.shop.co.uk",
    "xn--pypal-4ve.com", "xn--80ak6aa92e.com", "paypal.xn--80abap1arsf.xn--p1ai",
    "secure-login-paypal-verify.tk", "google.ru", "amazon.de", "yandex.kz",
    # malformed / degenerate input must not crash either side
    "a", "xn--", "xn---.com", "xn--a.com", "....xn--p1ai", "ru.com", "a.ru.com",
    # astral-plane letters: one character to Python, two UTF-16 units to JS
    # (p𝐚ypal with a mathematical bold a, pa😀ypal, сбер𝐚)
    "xn--pypal-cl00d.com", "xn--paypal-4v74e.com", "xn--90ai7ab24840d.com",
)


def _labelled_hosts() -> list[str]:
    hosts: list[str] = []
    for path in LABELLED_SETS:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                hosts.append(line.split(" | ")[0].strip())
    return hosts


def _ascii_host(host: str) -> str:
    """The wire form the extension receives: each non-ASCII label punycoded."""
    from api.services.scoring import _ascii_label

    return ".".join(_ascii_label(label) for label in host.split("."))


def _variant_hosts() -> list[str]:
    sys.path.insert(0, str(ROOT / "scripts"))
    import eval_typo_variants as variants  # noqa: E402 — a sibling script, not a package

    ru = [r["host"] for r in variants.build_variants("ru")]
    world = [r["host"] for r in variants.build_variants("global")]
    return ru + world[::GLOBAL_VARIANT_STRIDE]


def parity_hosts() -> list[str]:
    """Every host the parity table covers, ASCII, in a stable order."""
    from api.services import scoring

    listed = sorted(d for d in scoring._BRAND_LEGIT_DOMAINS if d.isascii())
    candidates: Iterable[str] = (
        *EDGE_CASES,
        *_labelled_hosts(),
        *listed,
        *(f"www.{d}" for d in listed),
        *_variant_hosts(),
    )
    seen: set[str] = set()
    out: list[str] = []
    for host in candidates:
        ascii_host = _ascii_host(host.lower())
        if ascii_host not in seen:
            seen.add(ascii_host)
            out.append(ascii_host)
    return out


def server_verdict(host: str) -> list[str]:
    """The server's name rules on one ASCII host, as the table's columns."""
    from api.services import scoring

    unicode_host = scoring._decode_idn(host)
    typo = scoring._check_typosquatting_v2(unicode_host)
    return [
        host,
        f"{typo[0]}|{typo[1]}" if typo else "-",
        scoring._check_brand_in_subdomain(host) or "-",
        scoring._check_brand_under_open_zone(host) or "-",
        "1" if scoring._has_fake_tld_in_subdomain(host) else "0",
        str(scoring._apparent_subdomain_levels(host)),
        scoring.registrable_domain(host),
    ]


PARITY_HEADER = (
    "# GENERATED by scripts/build_extension_scorer_data.py from api/services/scoring.py — do not edit.\n"
    "# The server's name rules on each host; scripts/test-local-scorer.mjs holds the extension's\n"
    "# port (packages/extension-core/src/utils/name-rules.js) to every row.\n"
    "# host\ttyposquat (legit|method)\tbrand_in_subdomain\tbrand_under_open_zone\tfake_tld\t"
    "subdomain_levels\tregistrable_domain\n"
)


def render_parity() -> str:
    rows = ["\t".join(server_verdict(h)) for h in parity_hosts()]
    return PARITY_HEADER + "\n".join(rows) + "\n"


def _sorted(items: Iterable[str]) -> list[str]:
    return sorted(items)


def _flags(rule) -> str:
    """A _NameRule as five 0/1 flags, in field order."""
    return "".join("1" if getattr(rule, f) else "0" for f in rule._fields)


def scorer_data() -> dict:
    """The name-rule data the extension needs, from the server's module."""
    from api.services import doh_gateway, ru_lures, scoring

    targets = list(scoring.TYPOSQUAT_TARGETS.items())
    global_names = list(scoring.GLOBAL_TYPOSQUAT_TARGETS)
    # The merge puts the global list first, in its own order; the port relies
    # on it (brand_in_subdomain reads the first globalCount entries only).
    assert [n for n, _ in targets[: len(global_names)]] == global_names, "global brands must come first"
    rule_fields = list(scoring._NameRule._fields)
    return {
        "targets": [[n, d] for n, d in targets],
        "globalCount": len(global_names),
        "ruleFields": rule_fields,
        "rules": {n: [_flags(scoring._NAME_RULES[n]), _flags(scoring._NAME_RULES_AT_HOME[n])] for n, _ in targets},
        "officialDomains": _sorted(scoring._BRAND_OFFICIAL_DOMAINS),
        "unrelatedDomains": _sorted(scoring._BRAND_LEGIT_DOMAINS - scoring._BRAND_OFFICIAL_DOMAINS),
        "notTypos": {n: _sorted(v) for n, v in sorted(scoring._BRAND_NOT_TYPOS.items())},
        "sharedNames": _sorted(scoring._SHARED_NAMES),
        "ruPublicSuffixes": _sorted(scoring.RU_PUBLIC_SUFFIXES),
        "ruWildcardSuffixes": _sorted(scoring._RU_WILDCARD_SUFFIXES),
        "ruRestrictedZones": _sorted(scoring._RU_RESTRICTED_ZONES),
        "restrictedZoneLabels": _sorted(scoring._RESTRICTED_ZONE_LABELS),
        "regionalGovernmentDomains": _sorted(scoring.REGIONAL_GOVERNMENT_DOMAINS),
        "cctldSecondLevels": _sorted(doh_gateway._CCTLD_SECOND_LEVELS),
        "fakeTldLabels": _sorted(scoring._FAKE_TLD_LABELS),
        "registeredFakeTldLabels": _sorted(scoring._REGISTERED_FAKE_TLD_LABELS),
        "ruZoneBrands": list(scoring._RU_ZONE_BRANDS_LONGEST_FIRST),
        "ruZoneBrandPartMin": scoring._RU_ZONE_BRAND_PART_MIN,
        "lureTlds": _sorted(scoring._LURE_TLDS),
        "ruTlds": _sorted(scoring._RU_TLDS),
        "ruLookalikeZones": _sorted(scoring._RU_LOOKALIKE_ZONES),
        "charSubs": dict(sorted(scoring._CHAR_SUBS.items())),
        "confusables": dict(sorted(scoring._CONFUSABLES.items())),
        "glyphSubs": [list(pair) for pair in scoring._GLYPH_SUBS],
        "keyboardRows": [list(rows) for rows in scoring._KEYBOARD_ROWS],
        "similarLetters": _sorted("".join(sorted(pair)) for pair in scoring._SIMILAR_LETTERS),
        "vowels": "".join(sorted(scoring._VOWELS)),
        "genericTails": list(scoring._GENERIC_TAILS),
        "comboKeywords": _sorted(scoring._COMBOSQUAT_KEYWORDS),
        "comboGenericSuffixes": _sorted(scoring._COMBO_GENERIC_SUFFIXES),
        "comboGenericPrefixes": _sorted(scoring._COMBO_GENERIC_PREFIXES),
        "comboCountrySuffixes": _sorted(scoring._COMBO_COUNTRY_SUFFIXES),
        # Russian lure words (ru_lures) as skeletons, and the tables the
        # skeleton is built from, so the port folds spellings exactly as the
        # server does instead of keeping its own copy of them.
        "lureWords": _sorted(ru_lures.LURE_WORDS),
        "lureStems": list(ru_lures.LURE_STEMS),
        "brandLureWords": {n: _sorted(v) for n, v in sorted(scoring._BRAND_LURE_WORDS.items())},
        "skeletonCyrillic": dict(ru_lures._CYRILLIC_TO_LATIN),
        "skeletonFolds": [list(pair) for pair in ru_lures._LATIN_FOLDS],
        "skeletonDigits": {chr(k): v for k, v in sorted(ru_lures._DIGIT_LETTERS.items())},
        "typosquatMinLabel": scoring._TYPOSQUAT_MIN_LABEL,
        "shapeMinLabel": scoring._SHAPE_MIN_LABEL,
        "fuzzyMinLabel": scoring._FUZZY_MIN_LABEL,
        "twoEditMinLabel": scoring._TWO_EDIT_MIN_LABEL,
    }


DATA_JS_HEADER = """\
// GENERATED by scripts/build_extension_scorer_data.py — do not edit by hand.
//
// The server's name-rule data (api/services/scoring.py, loaded there from
// data/typosquat_targets.json, data/typosquat_targets_ru.json and
// data/ru_public_suffixes.json): the brands the typosquat rule compares
// against, every Russian brand family's official domains and the verified
// same-shaped sites of other owners, the per-name switches, the Russian
// public suffixes and the rule constants. Read by name-rules.js.
//
// To change it, edit the data file or the server rule, then run
//     python3 scripts/build_extension_scorer_data.py
//     bash scripts/build-extensions.sh
// CI (tests/test_extension_scorer_data.py) fails when this file is stale.
//
// A classic script, like link-target.js: a content script gets the global,
// the background module imports it for its side effect, Node tests load it
// in a vm context. Data only — no DOM, no chrome.*.
"""


def render_data_js() -> str:
    # One key per line, each value compact: a data change shows as a changed
    # line under its key, and the file stays small enough to load per page.
    lines = [
        f"    {json.dumps(key)}: {json.dumps(value, ensure_ascii=False, separators=(',', ':'))}"
        for key, value in scorer_data().items()
    ]
    return (
        DATA_JS_HEADER
        + "(function (root) {\n"
        + '  "use strict";\n'
        + "  root.cleanwayScorerData = {\n"
        + ",\n".join(lines)
        + "\n  };\n"
        + '})(typeof self !== "undefined" ? self : globalThis);\n'
    )


OUTPUTS = ((DATA_JS, render_data_js), (PARITY_TSV, render_parity))


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true", help="exit 1 when an output is stale, write nothing")
    args = ap.parse_args(argv)
    stale = []
    for path, render in OUTPUTS:
        text = render()
        current = path.read_text(encoding="utf-8") if path.exists() else None
        if current == text:
            continue
        if args.check:
            stale.append(path.relative_to(ROOT))
        else:
            path.write_text(text, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
    if stale:
        print(
            "Stale: " + ", ".join(str(p) for p in stale)
            + ". Run: python3 scripts/build_extension_scorer_data.py && bash scripts/build-extensions.sh",
            file=sys.stderr,
        )
        return 1
    if args.check:
        print("extension scorer data: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())

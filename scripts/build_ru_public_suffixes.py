#!/usr/bin/env python3
"""Build data/ru_public_suffixes.json — every PSL rule under .ru/.su/.рф/.рус.

Why: the scorer judged a host by its last two labels, so for a name under a
regional or reserved public suffix it judged the SUFFIX. kvs.gov.spb.ru was
compared with brand names as 'spb' ("Impersonates ups.com"), its 'gov' label
was read as a fake TLD, and its one subdomain level was counted as three —
100/dangerous for the St Petersburg government (production, 2026-09-27).
data/public_suffixes_in_top.json cannot fix that: it only holds rules whose
base ranks in Tranco, so adygeya.ru, vladimir.ru, the .su regions and the
.рус city zones are missing from it. See scoring._registrable_domain().

Output: sorted list of the multi-label PSL rules (ICANN and private sections)
whose TLD is ru, su, xn--p1ai (рф) or xn--p1acf (рус), in ASCII (punycode)
form. Wildcard rules keep their '*.': '*.hosting.myjino.ru' makes
b.hosting.myjino.ru itself a public suffix, so a.b.hosting.myjino.ru is the
registrable domain — stripping the '*.' would put it one level too high.
Exception rules ('!') have no meaning here: the build fails if one appears
under these TLDs (none today). ~100 rules: the cctld.ru
reserved zones (gov.ru, mil.ru, edu.ru, ac.ru, int.ru), the FAITID regional
zones (spb.ru, msk.ru, nov.ru, adygeya.ru, … and their .su twins), MSK-IX
(net.ru, org.ru, pp.ru), com.ru, ras.ru, the .рус city zones, and a few
hosting platforms (myjino.ru, mcdir.ru …).

Usage:
    python3 scripts/build_ru_public_suffixes.py            # write the file
    python3 scripts/build_ru_public_suffixes.py --check    # exit 1 if stale

No API key; fetches the PSL.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "ru_public_suffixes.json"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"
TLDS = frozenset({"ru", "su", "xn--p1ai", "xn--p1acf"})


def _ascii(rule: str) -> str:
    """Punycode each non-ASCII label: 'сочи.рус' → 'xn--h1aliz.xn--p1acf'."""
    return ".".join(
        label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii")
        for label in rule.split(".")
    )


def parse(psl_text: str) -> list[str]:
    """The rules under TLDS, ASCII, wildcards kept as '*.<base>'. Raises
    ValueError on an exception rule ('!') under TLDS: the scorer's lookup
    does not implement them, and dropping one silently would mis-draw a
    registrable boundary."""
    out: set[str] = set()
    for raw in psl_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        exception = line.startswith("!")
        wildcard = line.startswith("*.")
        body = _ascii(line.lstrip("!").removeprefix("*.").lower())
        if "." not in body or body.rsplit(".", 1)[1] not in TLDS:
            continue
        if exception:
            raise ValueError(f"PSL exception rule {line!r}: not supported by scoring._ru_suffix_length()")
        out.add("*." + body if wildcard else body)
    return sorted(out)


def build() -> list[str]:
    return parse(urllib.request.urlopen(PSL_URL, timeout=60).read().decode("utf-8"))


def main() -> int:
    rules = build()
    if "--check" in sys.argv:
        current = json.loads(OUT.read_text()) if OUT.exists() else []
        if current != rules:
            print(f"STALE: {OUT.relative_to(ROOT)} differs ({len(current)} vs {len(rules)} rules)")
            print("  → rerun: python3 scripts/build_ru_public_suffixes.py")
            return 1
        print(f"OK: {len(rules)} rules up to date")
        return 0
    OUT.write_text(json.dumps(rules, indent=0) + "\n")
    print(f"wrote {len(rules)} rules to {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

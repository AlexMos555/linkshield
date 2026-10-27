#!/usr/bin/env python3
"""Refresh data/public_suffix_list.dat, the vendored Public Suffix List.

The scorer, the DoH gateway and the browser extensions draw the registrable
domain from this copy (api/services/public_suffix.py): its ICANN section,
with data/ru_public_suffixes.json on top. It changes only through this
script — no workflow runs it — so a new list is a reviewed commit, not a
silent change of where every site ends.

What it does:
  1. fetches https://publicsuffix.org/list/public_suffix_list.dat (or reads
     --from FILE);
  2. refuses it unless public_suffix.parse() accepts it (both section
     markers, a VERSION line, every rule well-formed), its VERSION is not
     older than the vendored one, it keeps at least MIN_KEPT of the ICANN
     rules, and no ICANN rule reaches under a Russian overlay zone (the
     overlay is merged into the ICANN rules on that assumption,
     tests/test_public_suffix.py);
  3. prints what changed in the ICANN section, and whether the PSL's
     Russian rules still match data/ru_public_suffixes.json — that file is
     the model's input too (scoring.legacy_registrable_domain), so it is
     rebuilt (scripts/build_ru_public_suffixes.py) with a retrain, not here;
  4. writes the list byte for byte (its MPL 2.0 notice and VERSION line
     included).

Then regenerate what is built from it:
    python3 scripts/build_extension_scorer_data.py
    bash scripts/build-extensions.sh
    bash scripts/build-store-artifacts.sh   # and the AMO source archive,
                                            # docs/STORE_SUBMISSION_KIT.md §5

Usage:
    python3 scripts/refresh_public_suffix_list.py              # fetch, check, write
    python3 scripts/refresh_public_suffix_list.py --from FILE  # a copy already downloaded
    python3 scripts/refresh_public_suffix_list.py --dry-run    # check and report, write nothing
    python3 scripts/refresh_public_suffix_list.py --check      # the vendored copy parses (no network)

Standard library only.
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from api.services import public_suffix as ps  # noqa: E402 — after the path fix

VENDORED = ROOT / "data" / ps.PSL_FILE
RU_OVERLAY = ROOT / "data" / ps.RU_OVERLAY_FILE
# A list that lost more than 2% of the ICANN rules is truncated or not the
# PSL; the ICANN section changes by a few dozen rules a year.
MIN_KEPT = 0.98
_RU_TLDS = frozenset({"ru", "su", "xn--p1ai", "xn--p1acf"})


def fetch(url: str = ps.PSL_URL, timeout: float = 60.0) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "cleanway-psl-refresh/1"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 — a fixed https URL
        return response.read()


def _rules(rules: ps.SuffixRules) -> set[str]:
    return set(rules.exact) | {"*." + w for w in rules.wildcards} | {"!" + e for e in rules.exceptions}


def problems(candidate: ps.PublicSuffixList, current: Optional[ps.PublicSuffixList]) -> list[str]:
    """Why `candidate` must not replace `current` ([] when it may)."""
    out = []
    if current is not None:
        if candidate.version < current.version:
            out.append(f"VERSION {candidate.version} is older than the vendored {current.version}")
        kept = len(_rules(candidate.icann) & _rules(current.icann)) / max(1, len(_rules(current.icann)))
        if kept < MIN_KEPT:
            out.append(f"keeps only {kept:.1%} of the vendored ICANN rules (at least {MIN_KEPT:.0%} expected)")
    overlay_tlds = {r.rsplit(".", 1)[1] for r in ps.RU_OVERLAY.exact | ps.RU_OVERLAY.wildcards}
    under = sorted(r for r in _rules(candidate.icann)
                   if "." in r.lstrip("*.!") and r.rsplit(".", 1)[1] in overlay_tlds
                   or r.startswith("*.") and r[2:] in overlay_tlds)
    if under:
        out.append(f"ICANN rules under the Russian overlay's TLDs, which the merge assumes there are none: {under[:10]}")
    return out


def report(candidate: ps.PublicSuffixList, current: Optional[ps.PublicSuffixList]) -> list[str]:
    """What changed, for the commit message, and the Russian overlay's drift."""
    lines = [f"candidate: VERSION {candidate.version}, COMMIT {candidate.commit}, "
             f"{len(candidate.icann.exact)} exact ICANN rules, {len(candidate.icann.wildcards)} wildcards, "
             f"{len(candidate.icann.exceptions)} exceptions"]
    if current is not None:
        old, new = _rules(current.icann), _rules(candidate.icann)
        added, removed = sorted(new - old), sorted(old - new)
        lines.append(f"vendored:  VERSION {current.version}; ICANN rules +{len(added)} -{len(removed)}")
        lines += [f"  + {r}" for r in added[:40]] + [f"  - {r}" for r in removed[:40]]
        if len(added) > 40 or len(removed) > 40:
            lines.append("  … (first 40 each)")
    psl_ru = {r for r in _rules(candidate.icann) | _rules(candidate.private)
              if "." in r.lstrip("*.!") and r.rsplit(".", 1)[1] in _RU_TLDS}
    overlay = set(json.loads(RU_OVERLAY.read_text(encoding="utf-8")))
    if psl_ru != overlay:
        lines.append(f"NOTE: the PSL's Russian rules differ from {RU_OVERLAY.relative_to(ROOT)} "
                     f"(+{sorted(psl_ru - overlay)[:10]} -{sorted(overlay - psl_ru)[:10]}). That file is the "
                     "model's input too: rebuild it (scripts/build_ru_public_suffixes.py) with a retrain.")
    return lines


def _load_vendored() -> Optional[ps.PublicSuffixList]:
    try:
        return ps.parse(VENDORED.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--from", dest="source", type=Path, help="read the list from FILE instead of fetching it")
    ap.add_argument("--dry-run", action="store_true", help="check and report, write nothing")
    ap.add_argument("--check", action="store_true", help="only check that the vendored copy parses (no network)")
    ap.add_argument("--out", type=Path, default=VENDORED, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    if args.check:
        try:
            listed = ps.parse(args.out.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"{args.out}: {exc}", file=sys.stderr)
            return 1
        print(f"{args.out.name}: OK, VERSION {listed.version}, {len(listed.icann.exact)} exact ICANN rules")
        return 0

    raw = args.source.read_bytes() if args.source else fetch()
    try:
        candidate = ps.parse(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 1
    current = _load_vendored() if args.out == VENDORED else None
    print("\n".join(report(candidate, current)))
    refused = problems(candidate, current)
    if refused:
        print("refused:\n  " + "\n  ".join(refused), file=sys.stderr)
        return 1
    if args.dry_run:
        return 0
    args.out.write_bytes(raw)
    print(f"wrote {args.out}. Next: python3 scripts/build_extension_scorer_data.py && bash scripts/build-extensions.sh "
          "&& bash scripts/build-store-artifacts.sh (docs/STORE_SUBMISSION_KIT.md §5 for the AMO source archive)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

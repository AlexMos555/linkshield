#!/usr/bin/env python3
"""Build data/public_suffixes_in_top.json — PSL rules that are also top domains.

Why: the top 100k ranks `us.org`, `github.io`, `blogspot.com`,
`azurewebsites.net`, dyndns names like `bounceme.net`, and 1,500+ others that
are PUBLIC SUFFIXES — anyone can register a name under them. The scorer's and
the public router's "base domain in TOP_DOMAINS → instant safe" rule treated
every subdomain of those as a top domain. `gwcu.us.org` (live phishing) came
back "safe, 99%" that way on 2026-08-18. `is_trusted_top_domain()` consults
this file to refuse the shortcut for strict subdomains of these suffixes.

Output: sorted list of every PSL rule (wildcards stripped, exceptions
dropped) whose last-two-labels base is in data/top_100k.json or in
data/infrastructure_domains.txt. Multi-label rules (s3.amazonaws.com,
us-east-1.elasticbeanstalk.com) are kept. The infrastructure names are
bases too because the phone's popular veto holds them
(scripts/build_mobile_assets.py): a vetoed registrable whose tenant
suffixes the phone does not know makes every tenant unblockable
(x.blob.core.windows.net under windows.net — the 783-of-1,548 case).

scripts/build_top_domains.py rebuilds this file in the same run as
data/top_100k.json (rules_in_top(), with the PSL it fetched), so the two
can never disagree; the list was Tranco's top 100k until 2026-10-23.

Usage:
    python3 scripts/build_public_suffixes_in_top.py            # write file
    python3 scripts/build_public_suffixes_in_top.py --check    # exit 1 if stale
    python3 scripts/build_public_suffixes_in_top.py --verify-consistency  # offline, CI

No API key; fetches the PSL.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOP = ROOT / "data" / "top_100k.json"
INFRASTRUCTURE = ROOT / "data" / "infrastructure_domains.txt"
OUT = ROOT / "data" / "public_suffixes_in_top.json"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"


def load_infrastructure(path: Path = INFRASTRUCTURE) -> set[str]:
    """data/infrastructure_domains.txt: one name per line, '#' comments."""
    if not path.exists():
        return set()
    names = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip().lower()
        if line:
            names.add(line)
    return names


def bases() -> set[str]:
    """The names whose PSL rules this file holds: the top 100k and the
    infrastructure list."""
    return {d.lower() for d in json.loads(TOP.read_text())} | load_infrastructure()


def _base(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def rules_in_top(top: set[str], psl_text: str) -> list[str]:
    """Every PSL rule ('*.' stripped, exceptions dropped) whose
    last-two-labels base is in `top`, sorted."""
    top = {d.lower() for d in top}
    out: set[str] = set()
    for raw in psl_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//") or line.startswith("!"):
            continue
        if line.startswith("*."):
            line = line[2:]
        rule = line.lower()
        if "." in rule and _base(rule) in top:
            out.add(rule)
    return sorted(out)


def build() -> list[str]:
    psl = urllib.request.urlopen(PSL_URL, timeout=60).read().decode("utf-8")
    return rules_in_top(bases(), psl)


def verify_consistency() -> int:
    """Offline invariant, safe to run in per-PR CI (no PSL fetch): every rule
    in the committed file must have its registrable base in top_100k.json
    or in the infrastructure list. Catches the common drift — top_100k
    refreshed but the intersection not rebuilt — without going red on
    unrelated PRs when Mozilla edits the PSL upstream (that direction is
    caught by the full --check)."""
    top = bases()
    rules = json.loads(OUT.read_text())
    orphans = [r for r in rules if _base(r) not in top]
    if orphans:
        print(f"STALE: {len(orphans)} rules in {OUT.relative_to(ROOT)} whose base left top_100k, e.g. {orphans[:5]}")
        print("  → rerun: python3 scripts/build_top_domains.py (or this script)")
        return 1
    print(f"OK: all {len(rules)} public-suffix rules still have their base in top_100k or the infrastructure list")
    return 0


def main() -> int:
    if "--verify-consistency" in sys.argv:
        return verify_consistency()
    rules = build()
    if "--check" in sys.argv:
        current = json.loads(OUT.read_text()) if OUT.exists() else []
        if current != rules:
            print(f"STALE: {OUT.relative_to(ROOT)} differs ({len(current)} vs {len(rules)} rules)")
            return 1
        print(f"OK: {len(rules)} rules, up to date")
        return 0
    OUT.write_text(json.dumps(rules, indent=0) + "\n")
    print(f"wrote {OUT.relative_to(ROOT)}: {len(rules)} rules")
    return 0


if __name__ == "__main__":
    sys.exit(main())

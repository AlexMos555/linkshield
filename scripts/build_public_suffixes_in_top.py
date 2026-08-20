#!/usr/bin/env python3
"""Build data/public_suffixes_in_top.json — PSL rules that are also top domains.

Why: Tranco's top 100k ranks `us.org`, `github.io`, `blogspot.com`,
`azurewebsites.net`, dyndns names like `bounceme.net`, and 1,500+ others that
are PUBLIC SUFFIXES — anyone can register a name under them. The scorer's and
the public router's "base domain in TOP_DOMAINS → instant safe" rule treated
every subdomain of those as a top domain. `gwcu.us.org` (live phishing) came
back "safe, 99%" that way on 2026-08-18. `is_trusted_top_domain()` consults
this file to refuse the shortcut for strict subdomains of these suffixes.

Output: sorted list of every PSL rule (wildcards stripped, exceptions
dropped) whose last-two-labels base is in data/top_100k.json. Multi-label
rules (s3.amazonaws.com, us-east-1.elasticbeanstalk.com) are kept.

Usage:
    python3 scripts/build_public_suffixes_in_top.py            # write file
    python3 scripts/build_public_suffixes_in_top.py --check    # exit 1 if stale

Re-run whenever data/top_100k.json is refreshed. No API key; fetches the PSL.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOP = ROOT / "data" / "top_100k.json"
OUT = ROOT / "data" / "public_suffixes_in_top.json"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"


def _base(domain: str) -> str:
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def build() -> list[str]:
    top = {d.lower() for d in json.loads(TOP.read_text())}
    psl = urllib.request.urlopen(PSL_URL, timeout=60).read().decode("utf-8")
    out: set[str] = set()
    for raw in psl.splitlines():
        line = raw.strip()
        if not line or line.startswith("//") or line.startswith("!"):
            continue
        if line.startswith("*."):
            line = line[2:]
        rule = line.lower()
        if "." in rule and _base(rule) in top:
            out.add(rule)
    return sorted(out)


def verify_consistency() -> int:
    """Offline invariant, safe to run in per-PR CI (no PSL fetch): every rule
    in the committed file must have its registrable base in top_100k.json.
    Catches the common drift — top_100k refreshed but the intersection not
    rebuilt — without going red on unrelated PRs when Mozilla edits the PSL
    upstream (that direction is caught by the refresh job's full --check)."""
    top = {d.lower() for d in json.loads(TOP.read_text())}
    rules = json.loads(OUT.read_text())
    orphans = [r for r in rules if _base(r) not in top]
    if orphans:
        print(f"STALE: {len(orphans)} rules in {OUT.relative_to(ROOT)} whose base left top_100k, e.g. {orphans[:5]}")
        print("  → rerun: python3 scripts/build_public_suffixes_in_top.py")
        return 1
    print(f"OK: all {len(rules)} public-suffix rules still rank in top_100k")
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

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

Plus the tenant zones of data/tenant_zones.json, whatever their popularity
(shared_suffix_rules): every PRIVATE-section rule of a listed operator
(trycloudflare.com, cloud.goog, ngrok.io …) and the zones the PSL does not
carry (<bucket>.s3.cloud.ru). The file is also where the scorer, the ML
model, the publisher, the extension and the phone learn which hosts are
tenants, and a zone's tenants count nowhere in the licensed ranking
(build_top_domains.fold drops them), so its own name rarely ranks: 468
rules under 235 such names left this file with Tranco on 2026-10-23.

scripts/build_top_domains.py rebuilds this file in the same run as
data/top_100k.json (shared_suffix_rules(), with the PSL it fetched), so the
two can never disagree; the list was Tranco's top 100k until 2026-10-23.

Usage:
    python3 scripts/build_public_suffixes_in_top.py            # write file
    python3 scripts/build_public_suffixes_in_top.py --check    # exit 1 if stale
    python3 scripts/build_public_suffixes_in_top.py --verify-consistency  # offline, CI

No API key; fetches the PSL.
"""
from __future__ import annotations

import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import NamedTuple, Optional

ROOT = Path(__file__).resolve().parents[1]
TOP = ROOT / "data" / "top_100k.json"
INFRASTRUCTURE = ROOT / "data" / "infrastructure_domains.txt"
TENANT_ZONES = ROOT / "data" / "tenant_zones.json"
OUT = ROOT / "data" / "public_suffixes_in_top.json"
PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

_PRIVATE_BEGIN = "===BEGIN PRIVATE DOMAINS==="
_NAME = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")
_EVIDENCE = re.compile(r"^Verified \d{4}-\d{2}-\d{2}: \S")


class TenantZones(NamedTuple):
    """data/tenant_zones.json: the operators whose PSL private-section
    rules are kept whatever their popularity, the zones the PSL lacks
    (zone → dated evidence), and which operators are domain registries (the
    blocklist publisher promotes a registrant's name there: see the file's
    'registries' section)."""
    psl_operators: frozenset[str]
    not_in_psl: dict[str, str]
    registries: frozenset[str] = frozenset()


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


def load_tenant_zones(path: Path = TENANT_ZONES) -> TenantZones:
    """data/tenant_zones.json, checked. A missing file adds nothing; a
    malformed one raises ValueError (the build keeps the previous files)."""
    if not path.exists():
        return TenantZones(frozenset(), {}, frozenset())
    doc = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError(f"{path.name}: not an object")
    operators = doc.get("psl_operators") or {}
    names = operators.get("names", []) if isinstance(operators, dict) else None
    if not isinstance(names, list):
        raise ValueError(f"{path.name}: psl_operators.names must be a list")
    for name in names:
        if not isinstance(name, str) or not _NAME.match(name) or name.count(".") != 1:
            raise ValueError(f"{path.name}: psl_operators: {name!r} is not a lowercase registrable name")
    zones = {k: v for k, v in (doc.get("not_in_psl") or {}).items() if not k.startswith("_")}
    for zone, why in zones.items():
        if not _NAME.match(zone):
            raise ValueError(f"{path.name}: not_in_psl: {zone!r} is not a lowercase host name")
        if not isinstance(why, str) or not _EVIDENCE.match(why):
            raise ValueError(f"{path.name}: not_in_psl: {zone!r} needs 'Verified YYYY-MM-DD: <evidence>'")
    registries = doc.get("registries") or {}
    if not isinstance(registries, dict):
        raise ValueError(f"{path.name}: registries must map each zone to its evidence")
    registries = {k: v for k, v in registries.items() if not k.startswith("_")}
    for zone, why in registries.items():
        if zone not in names:
            raise ValueError(f"{path.name}: registries: {zone!r} is not a psl_operators name")
        if not isinstance(why, str) or not _EVIDENCE.match(why):
            raise ValueError(f"{path.name}: registries: {zone!r} needs 'Verified YYYY-MM-DD: <evidence>'")
    return TenantZones(frozenset(names), zones, frozenset(registries))


def bases() -> set[str]:
    """The names whose PSL rules this file holds by popularity: the top 100k
    and the infrastructure list."""
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


def private_rules(psl_text: str) -> set[str]:
    """Every multi-label rule of the PSL's PRIVATE section, '*.' stripped,
    exceptions dropped."""
    out: set[str] = set()
    in_private = False
    for raw in psl_text.splitlines():
        line = raw.strip()
        if _PRIVATE_BEGIN in line:
            in_private = True
        if not in_private or not line or line.startswith("//") or line.startswith("!"):
            continue
        rule = (line[2:] if line.startswith("*.") else line).lower()
        if "." in rule:
            out.add(rule)
    return out


def shared_suffix_rules(top: set[str], psl_text: str, zones: Optional[TenantZones] = None,
                        infrastructure: Optional[set[str]] = None) -> list[str]:
    """What data/public_suffixes_in_top.json holds: rules_in_top() for the
    top names and the infrastructure list, every private-section rule of a
    data/tenant_zones.json operator, and its zones the PSL does not carry.
    Sorted."""
    zones = load_tenant_zones() if zones is None else zones
    infrastructure = load_infrastructure() if infrastructure is None else infrastructure
    rules = set(rules_in_top(set(top) | infrastructure, psl_text))
    rules |= {r for r in private_rules(psl_text) if _base(r) in zones.psl_operators}
    rules |= set(zones.not_in_psl)
    return sorted(rules)


def build() -> list[str]:
    psl = urllib.request.urlopen(PSL_URL, timeout=60).read().decode("utf-8")
    return shared_suffix_rules({d.lower() for d in json.loads(TOP.read_text())}, psl)


def verify_consistency() -> int:
    """Offline invariant, safe to run in per-PR CI (no PSL fetch): every rule
    in the committed file must have its registrable base in top_100k.json
    or in the infrastructure list. Catches the common drift — top_100k
    refreshed but the intersection not rebuilt — without going red on
    unrelated PRs when Mozilla edits the PSL upstream (that direction is
    caught by the full --check)."""
    zones = load_tenant_zones()
    top = bases() | zones.psl_operators
    rules = json.loads(OUT.read_text())
    orphans = [r for r in rules if _base(r) not in top and r not in zones.not_in_psl]
    if orphans:
        print(f"STALE: {len(orphans)} rules in {OUT.relative_to(ROOT)} whose base left top_100k, e.g. {orphans[:5]}")
        print("  → rerun: python3 scripts/build_top_domains.py (or this script)")
        return 1
    missing = sorted(set(zones.not_in_psl) - set(rules))
    if missing:
        print(f"STALE: data/tenant_zones.json zones missing from {OUT.relative_to(ROOT)}: {missing[:5]}")
        print("  → rerun: python3 scripts/build_top_domains.py (or this script)")
        return 1
    print(f"OK: all {len(rules)} public-suffix rules have their base in top_100k, the infrastructure list "
          "or data/tenant_zones.json")
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

#!/usr/bin/env python3
"""Per-module coverage floors for the security- and money-critical code.

The suite-wide `--cov-fail-under` in CI only guards the average: a webhook
handler or the JWT verifier can lose half its tests while the total barely
moves. This script reads a Cobertura `coverage.xml` (what
`pytest --cov=api --cov-report=xml` writes) and fails if any module listed in
FLOORS drops below its own floor.

The number compared is coverage.py's "Cover" column: (covered lines +
covered branches) / (lines + branches). Branch data is present because
pyproject.toml sets `[tool.coverage.run] branch = true`; without it the
number degrades to plain line coverage.

How it is enforced in CI without touching .github/workflows: tests/conftest.py
imports the pytest hook from tests/critical_coverage_plugin.py, which calls
`check()` right after pytest-cov has written its reports, whenever the run
was started with `--cov-fail-under` (CI always passes it). A floor failure
fails the pytest step exactly like the total `--cov-fail-under` does.

Standalone:
    python scripts/check_critical_coverage.py [path/to/coverage.xml]

Raising a floor is always fine. Lowering one needs a reason in the PR.
"""
from __future__ import annotations

import fnmatch
import re
import sys
import xml.etree.ElementTree as ET  # nosec B405 — parses our own coverage.xml
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional

# Patterns are repo-relative POSIX paths; fnmatch syntax ("*" also crosses
# "/"). Every pattern must match at least one measured file, so a rename
# can't silently drop a module out of the gate. When several patterns match
# one file, the most specific (longest) pattern wins.
FLOORS: Dict[str, float] = {
    # Auth: JWT / JWKS verification.
    "api/services/auth.py": 97.0,
    "api/routers/auth.py": 94.0,
    # Client IP trust (Cloudflare / proxies), rate limiting, request guards.
    "api/services/proxy_trust.py": 97.0,
    "api/services/rate_limiter.py": 97.0,
    "api/services/request_guards.py": 97.0,
    "api/services/security_alerts.py": 97.0,
    # SSRF: everything that decides whether we may connect to a host.
    "api/services/domain_validator.py": 97.0,
    "api/services/site_probes.py": 97.0,
    "api/services/pinned_http.py": 93.0,
    # Stripe.
    "api/routers/payments.py": 97.0,
    "api/services/stripe_billing.py": 97.0,
    # RevenueCat (store purchases).
    "api/routers/revenuecat.py": 97.0,
    "api/services/revenuecat.py": 97.0,
    "api/services/revenuecat_sync.py": 97.0,
    # Personal data: export, delete, retention, devices.
    "api/routers/user.py": 96.0,
    "api/services/retention.py": 97.0,
    "api/services/account_purge.py": 95.0,
    "api/services/account_devices.py": 97.0,
    "api/services/supabase_keys.py": 97.0,
    # Licensed threat-intel switches.
    "api/services/licensed_intel.py": 97.0,
    # DoH: parses untrusted binary DNS from the internet.
    "api/routers/doh.py": 97.0,
    "api/services/doh_gateway.py": 95.0,
    "api/services/doh_filter.py": 97.0,
    "api/services/doh_wire.py": 97.0,
    # Billing (off in production today, still money code).
    # Small modules (errors.py: 31 statements) move ~3 points per line.
    "api/billing/*.py": 93.0,
}

# Matched by a pattern above but deliberately not gated, with the reason.
EXCLUDED: Dict[str, str] = {
    "api/billing/store/postgres.py": (
        "needs a real Postgres (tests/billing/test_store.py runs only with "
        "BILLING_TEST_DATABASE_URL); CI has none"
    ),
}

_CONDITION_RE = re.compile(r"\((\d+)/(\d+)\)")


@dataclass
class FileCoverage:
    path: str
    lines: int
    lines_hit: int
    branches: int
    branches_hit: int

    @property
    def percent(self) -> float:
        total = self.lines + self.branches
        if total == 0:
            return 100.0
        return 100.0 * (self.lines_hit + self.branches_hit) / total


@dataclass
class Result:
    path: str
    pattern: str
    floor: float
    percent: Optional[float]  # None: pattern matched no file

    @property
    def ok(self) -> bool:
        return self.percent is not None and self.percent + 1e-9 >= self.floor


def _repo_relative(source: str, filename: str, repo_root: Path) -> str:
    full = PurePosixPath(source.replace("\\", "/")) / filename.replace("\\", "/")
    root = PurePosixPath(repo_root.resolve().as_posix())
    try:
        return str(full.relative_to(root))
    except ValueError:
        pass
    # coverage.xml written in a container or another checkout: anchor on the
    # first "api/" component of the absolute path.
    parts = full.parts
    if "api" in parts:
        return str(PurePosixPath(*parts[parts.index("api"):]))
    return str(full)


def parse_coverage_xml(xml_path: Path, repo_root: Path) -> Dict[str, FileCoverage]:
    tree = ET.parse(xml_path)  # nosec B314 — trusted, locally generated file
    root = tree.getroot()
    sources = [s.text or "" for s in root.iter("source")] or [str(repo_root)]
    files: Dict[str, FileCoverage] = {}
    for cls in root.iter("class"):
        filename = cls.get("filename") or ""
        lines = lines_hit = branches = branches_hit = 0
        for line in cls.iter("line"):
            lines += 1
            if int(line.get("hits", "0")) > 0:
                lines_hit += 1
            if line.get("branch") == "true":
                m = _CONDITION_RE.search(line.get("condition-coverage", ""))
                if m:
                    branches_hit += int(m.group(1))
                    branches += int(m.group(2))
        # With several <source> roots, keep the one that resolves inside api/.
        path = None
        for source in sources:
            candidate = _repo_relative(source, filename, repo_root)
            if candidate.startswith("api/"):
                path = candidate
                break
        path = path or _repo_relative(sources[0], filename, repo_root)
        files[path] = FileCoverage(path, lines, lines_hit, branches, branches_hit)
    return files


def _best_pattern(path: str, patterns: Iterable[str]) -> Optional[str]:
    matching = [p for p in patterns if fnmatch.fnmatchcase(path, p)]
    return max(matching, key=len) if matching else None


def check(
    files: Dict[str, FileCoverage],
    floors: Optional[Dict[str, float]] = None,
    excluded: Optional[Dict[str, str]] = None,
) -> List[Result]:
    floors = FLOORS if floors is None else floors
    excluded = EXCLUDED if excluded is None else excluded
    results: List[Result] = []
    matched_patterns = set()
    for path in sorted(files):
        pattern = _best_pattern(path, floors)
        if pattern is None:
            continue
        matched_patterns.add(pattern)
        if path in excluded:
            continue
        results.append(Result(path, pattern, floors[pattern], files[path].percent))
    for pattern in floors:
        if pattern not in matched_patterns:
            results.append(Result(pattern, pattern, floors[pattern], None))
    return results


def format_report(results: List[Result]) -> List[str]:
    width = max([len(r.path) for r in results] + [6])
    out = [f"{'Module':<{width}}  {'Cover':>6}  {'Floor':>6}"]
    for r in sorted(results, key=lambda r: (r.ok, r.path)):
        cover = "MISSING" if r.percent is None else f"{r.percent:5.1f}%"
        flag = "" if r.ok else "  <-- below floor" if r.percent is not None else "  <-- not in coverage report"
        out.append(f"{r.path:<{width}}  {cover:>6}  {r.floor:5.1f}%{flag}")
    return out


def failures(results: List[Result]) -> List[Result]:
    return [r for r in results if not r.ok]


def main(argv: List[str]) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    xml_path = Path(argv[1]) if len(argv) > 1 else repo_root / "coverage.xml"
    if not xml_path.is_file():
        print(f"critical coverage: {xml_path} not found — run pytest --cov=api --cov-report=xml first", file=sys.stderr)
        return 2
    results = check(parse_coverage_xml(xml_path, repo_root))
    for line in format_report(results):
        print(line)
    bad = failures(results)
    if bad:
        print(f"\nFAIL: {len(bad)} critical module(s) below their coverage floor (scripts/check_critical_coverage.py).")
        return 1
    print(f"\nOK: {len(results)} critical modules at or above their floor.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

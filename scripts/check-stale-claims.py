#!/usr/bin/env python3
"""Fail CI if any forbidden stale credibility claim appears in source.

After the 2026-06-17 validation pass, the project committed to these values:
  - AUC                    0.95 (not 0.9988)
  - Fresh-URL recall       measured in docs/benchmarks/latest.json (gated); never a hardcoded 93.5%
  - Training samples       24,000 (not 18K, not 18,000)
  - Measured FPR           0.08%  (not 0.0%)

This script greps the repo for any resurrection of the OLD values. CI fails
on any hit so a future change can't accidentally re-introduce inflated
marketing. Allowlist below documents the few places where the OLD value
is intentionally cited (CHANGELOG history, this file, etc.).

Usage:
  python3 scripts/check-stale-claims.py

Exits 0 on clean, 1 on any forbidden claim found.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# (pattern, human-readable description)
FORBIDDEN = [
    (r"\b0\.9988\b", "stale AUC 0.9988 — use 0.95"),
    (r"\b91\.1%", "stale detection_rate 91.1% — recall is measured in latest.json, not hardcoded"),
    (r"\b91% detection", "stale '91% detection' — recall comes from latest.json (gated), not a fixed number"),
    (r"\b18K\+? domains", "stale '18K domains' — use '24,000 verified domains'"),
    (r"\b18,?000 (samples|domains)", "stale '18000 samples' — use '24,000'"),
]

# Paths excluded from the scan (these legitimately reference the old values).
EXCLUDE_DIRS = {
    "node_modules", ".next", ".git", "dist", "build",
    ".venv", "venv", "__pycache__", ".pytest_cache",
    "playwright-report", "test-results",
}

# Specific files allowed to keep the old strings (history, this script itself).
EXCLUDE_FILES = {
    # This script intentionally mentions the forbidden patterns.
    "scripts/check-stale-claims.py",
    # Auto-memory snapshots are point-in-time records — they intentionally
    # reflect what was true when they were written.
    # (No paths inside the repo proper qualify; the auto-memory lives outside
    # the repo at ~/.claude/projects/.../memory/.)
}

# Text-shaped extensions to scan.
SCAN_EXTS = {
    ".py", ".ts", ".tsx", ".js", ".jsx", ".json",
    ".md", ".mdx", ".yml", ".yaml", ".toml", ".html",
}


def is_excluded(path: Path) -> bool:
    rel = path.relative_to(REPO_ROOT).as_posix()
    if rel in EXCLUDE_FILES:
        return True
    for part in path.parts:
        if part in EXCLUDE_DIRS:
            return True
    return False


def scan_file(path: Path) -> list[tuple[int, str, str]]:
    """Return list of (line_number, matched_text, description) for any hit."""
    hits: list[tuple[int, str, str]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return hits
    for lineno, line in enumerate(text.splitlines(), 1):
        for pattern, desc in FORBIDDEN:
            m = re.search(pattern, line)
            if m:
                hits.append((lineno, m.group(0), desc))
    return hits


def main() -> int:
    all_hits: dict[Path, list[tuple[int, str, str]]] = {}
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file() or is_excluded(path):
            continue
        if path.suffix.lower() not in SCAN_EXTS:
            continue
        hits = scan_file(path)
        if hits:
            all_hits[path] = hits

    if not all_hits:
        print(
            "OK: no stale credibility claims found in repo. "
            f"Scanned for {len(FORBIDDEN)} patterns."
        )
        return 0

    print("STALE CLAIMS FAIL — found forbidden marketing numbers:", file=sys.stderr)
    for path, hits in sorted(all_hits.items()):
        rel = path.relative_to(REPO_ROOT).as_posix()
        for lineno, match, desc in hits:
            print(f"  {rel}:{lineno}: '{match}' — {desc}", file=sys.stderr)
    print(
        "\nFix: replace these strings with the validated values from "
        "data/model_meta.json (AUC 0.95) and the weekly benchmark "
        "(recall read from latest.json, 24,000 training samples). If a hit is legitimate "
        "(e.g. quoting historical text), add the path to EXCLUDE_FILES "
        "in this script.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

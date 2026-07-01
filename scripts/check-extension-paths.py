#!/usr/bin/env python3
"""Fail if any chrome.runtime.getURL(...) or <script src="..."> reference
in the extension trees points at a file that doesn't exist on disk.

The 2026-07-01 pre-launch audit found that:
  - ext-01: dozens of chrome.runtime.getURL("utils/...") calls used the
    wrong prefix (should have been "src/utils/..."). Result: Family Hub
    fan-out, threat-counter, paywall-nudge silently no-ops on install.
  - ext-02: options.html loaded vendor scripts with a relative path that
    resolved to src/options/utils/... (404 on every install).
  - Follow-up: family-notifier called getURL("public/icon-192.png") but
    no icon-192.png ever existed — notifications rendered a blank tile.

Grep would have caught all three in seconds, but nothing in CI grepped.
This script fills that gap.

Exit 0 = all paths resolve, exit 1 = at least one broken.

Run:
    python3 scripts/check-extension-paths.py

Extension roots audited (all four are shipped independently):
    extension/                          — Chrome (source-of-truth for MV3)
    packages/extension-core/            — shared source that build syncs
    extension-firefox/                  — Firefox MV2 fork
    extension-safari/                   — Safari fork

Store artifacts under dist/ are intentionally NOT audited — the build
copies from these trees, so fixing the source auto-fixes the artifact.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXTENSION_ROOTS = [
    "extension",
    "packages/extension-core",
    "extension-firefox",
    "extension-safari",
]

GET_URL_RE = re.compile(r'chrome\.runtime\.getURL\(["\']([^"\']+)["\']\)')
SCRIPT_SRC_RE = re.compile(r'<script[^>]+src="([^"]+)"')


def audit_tree(root: Path) -> list[str]:
    missing: list[str] = []

    for js in root.rglob("*.js"):
        try:
            text = js.read_text(errors="ignore")
        except OSError:
            continue
        for m in GET_URL_RE.finditer(text):
            rel = m.group(1)
            target = root / rel
            if not target.exists():
                # Report path relative to REPO_ROOT for tidiness.
                try:
                    js_rel = js.relative_to(REPO_ROOT)
                except ValueError:
                    js_rel = js
                missing.append(
                    f"{js_rel}: chrome.runtime.getURL('{rel}') → "
                    f"{target.relative_to(REPO_ROOT)} (missing)"
                )

    for html in root.rglob("*.html"):
        try:
            text = html.read_text(errors="ignore")
        except OSError:
            continue
        for m in SCRIPT_SRC_RE.finditer(text):
            src = m.group(1)
            if src.startswith(("http://", "https://", "//", "data:")):
                continue
            target = (html.parent / src).resolve()
            if not target.exists():
                try:
                    html_rel = html.relative_to(REPO_ROOT)
                except ValueError:
                    html_rel = html
                missing.append(
                    f"{html_rel}: <script src='{src}'> → {target} (missing)"
                )

    return missing


def main() -> int:
    total_missing: list[str] = []
    trees_checked = 0
    for root_name in EXTENSION_ROOTS:
        root = REPO_ROOT / root_name
        if not root.exists():
            # Tree may be trimmed intentionally (e.g. safari on a machine
            # without Xcode). Skip silently.
            continue
        trees_checked += 1
        total_missing.extend(audit_tree(root))

    if total_missing:
        print(
            f"check-extension-paths: FAILED — {len(total_missing)} broken path(s) "
            f"across {trees_checked} extension tree(s):",
            file=sys.stderr,
        )
        for m in total_missing:
            print(f"  {m}", file=sys.stderr)
        print(
            "\nFix: verify the target file exists at the printed location, "
            "or update the reference.",
            file=sys.stderr,
        )
        return 1

    print(
        f"check-extension-paths: OK — every asset reference across "
        f"{trees_checked} extension tree(s) resolves."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

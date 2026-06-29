#!/usr/bin/env python3
"""Verify every non-EN locale ships the same top-level namespaces as en.json.

Catches the "namespace silently missing → next-intl renders raw keys" failure
mode that bit us on /transparency/methodology in commit 04c08a0 (the namespace
was only in en.json; 9 non-EN locales rendered `Methodology.page_title` as
literal text for ~10 days before anyone noticed).

Usage:
  python3 scripts/check-i18n-parity.py

Exits 0 if every locale has every en namespace.
Exits 1 with a diff if any locale is missing a namespace.

This script is structural only — it does NOT check whether translated values
differ from English. An English-fallback value still has the right key, so
this script passes. Catching English-fallback drift is a separate job done
manually during the translation pass.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MESSAGES_DIR = REPO_ROOT / "landing" / "messages"


def main() -> int:
    en_path = MESSAGES_DIR / "en.json"
    if not en_path.exists():
        print(f"FATAL: {en_path} missing", file=sys.stderr)
        return 2

    en = json.loads(en_path.read_text(encoding="utf-8"))
    en_namespaces = set(en.keys())

    bad = []
    for locale_file in sorted(MESSAGES_DIR.glob("*.json")):
        if locale_file.name == "en.json":
            continue
        locale = locale_file.stem
        data = json.loads(locale_file.read_text(encoding="utf-8"))
        loc_namespaces = set(data.keys())
        missing = en_namespaces - loc_namespaces
        extra = loc_namespaces - en_namespaces
        if missing or extra:
            bad.append((locale, sorted(missing), sorted(extra)))

    if not bad:
        print(
            f"OK: every locale ({len(list(MESSAGES_DIR.glob('*.json'))) - 1} non-en) "
            f"has all {len(en_namespaces)} namespaces from en.json"
        )
        return 0

    print("i18n parity FAILED:", file=sys.stderr)
    for locale, missing, extra in bad:
        if missing:
            print(f"  {locale}.json missing namespaces: {missing}", file=sys.stderr)
        if extra:
            print(f"  {locale}.json has extra namespaces: {extra}", file=sys.stderr)
    print(
        "\nFix: copy the missing namespace blocks from en.json into the offending "
        "locale files. English-fallback content is acceptable as a placeholder; "
        "real translation can land in a follow-up PR.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

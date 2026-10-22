#!/usr/bin/env python3
"""Verify every non-EN locale ships the same top-level namespaces as en.json,
and that no sentence is left in English on a localized page.

Catches the "namespace silently missing → next-intl renders raw keys" failure
mode that bit us on /transparency/methodology in commit 04c08a0 (the namespace
was only in en.json; 9 non-EN locales rendered `Methodology.page_title` as
literal text for ~10 days before anyone noticed).

It also catches the quieter twin: a key that exists in every locale but still
holds the English text. The 2026-10-22 sweep found /ru/dns showing four
English paragraphs (one promising an extension nobody can install yet) and
the home page's privacy heading in English in seven languages — both indexed.
A non-EN value of LONG_WORDS words or more that is identical to en.json now
fails; short values ("Cleanway", "RuStore", "SHA-256") are names, not
untranslated copy.

Usage:
  python3 scripts/check-i18n-parity.py

Exits 0 if every locale has every en namespace and no long English value.
Exits 1 with a diff otherwise.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
MESSAGES_DIR = REPO_ROOT / "landing" / "messages"

# A sentence, not a name: four words or more.
LONG_WORDS = 4
# "Namespace.key" paths whose English text is deliberate in every locale.
# Empty today; add a path with a comment saying why, never a whole namespace.
ENGLISH_ON_PURPOSE: frozenset[str] = frozenset()


def leaves(node: object, path: str = "") -> Iterator[tuple[str, str]]:
    """(dotted path, text) for every string leaf, list items as path[i]."""
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from leaves(value, f"{path}.{key}" if path else key)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from leaves(value, f"{path}[{index}]")


def untranslated(en: dict, data: dict) -> list[str]:
    """Paths whose long value is byte-for-byte the English one."""
    english = dict(leaves(en))
    return sorted(
        path
        for path, text in leaves(data)
        if english.get(path) == text
        and len(text.split()) >= LONG_WORDS
        and path not in ENGLISH_ON_PURPOSE
    )


def main() -> int:
    en_path = MESSAGES_DIR / "en.json"
    if not en_path.exists():
        print(f"FATAL: {en_path} missing", file=sys.stderr)
        return 2

    en = json.loads(en_path.read_text(encoding="utf-8"))
    en_namespaces = set(en.keys())

    bad = []
    english_left: list[tuple[str, list[str]]] = []
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
        left = untranslated(en, data)
        if left:
            english_left.append((locale, left))

    if not bad and not english_left:
        print(
            f"OK: every locale ({len(list(MESSAGES_DIR.glob('*.json'))) - 1} non-en) "
            f"has all {len(en_namespaces)} namespaces from en.json and no English sentence"
        )
        return 0

    if bad:
        print("i18n parity FAILED:", file=sys.stderr)
        for locale, missing, extra in bad:
            if missing:
                print(f"  {locale}.json missing namespaces: {missing}", file=sys.stderr)
            if extra:
                print(f"  {locale}.json has extra namespaces: {extra}", file=sys.stderr)
        print(
            "\nFix: copy the missing namespace blocks from en.json into the offending "
            "locale files, then translate them.",
            file=sys.stderr,
        )
    if english_left:
        print("i18n FAILED: English text on localized pages:", file=sys.stderr)
        for locale, paths in english_left:
            for path in paths:
                print(f"  {locale}: {path}", file=sys.stderr)
        print(
            "\nFix: translate these in packages/i18n-strings/src/<locale>.json and run "
            "scripts/build-i18n.py. If a value must stay English, add its path to "
            "ENGLISH_ON_PURPOSE with the reason.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())

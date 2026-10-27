#!/usr/bin/env python3
"""Verify every non-EN locale ships the same top-level namespaces as en.json,
that no sentence is left in English on a localized page, and that no string
in any namespace is a note to the translator.

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

And the note left where the string should be. Through mobile.* it reached
users twice before #310 (2026-10-27): every History row in Arabic read "Plural
variants: … Single-string fallback: …", the Italian breach card read
"found_body_one: \"…\" / found_body_other: …". The landing site, the three
extensions and the emails render the other namespaces of the source
(landing.*, extension.*, email.*), and nothing looked there. So every string
a surface renders from packages/i18n-strings/src/<locale>.json, in every
namespace and every locale (en included), goes through the rule
scripts/check-mobile-i18n.py applies to the generated mobile files
(scripts/i18n_notes.py). That is read from the source, not the generated
files: emails have none, and mobile/i18n drops the landing lists (FAQ,
terms, pricing bullets).

Usage:
  python3 scripts/check-i18n-parity.py

Exits 0 if every locale has every en namespace, no long English value and
no translator note. Exits 1 with a diff otherwise.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
MESSAGES_DIR = REPO_ROOT / "landing" / "messages"
SOURCE_DIR = REPO_ROOT / "packages" / "i18n-strings" / "src"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from i18n_notes import is_translator_note  # noqa: E402

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


def source_strings(node: object, path: str = "") -> Iterator[tuple[str, str]]:
    """(dotted key, text) for every string a surface renders from the source.

    A {"text": …} leaf (extension, email) renders its text only: its
    `description` is chrome.i18n's note for translators, which no browser
    shows, and `placeholders` are substitution specs. Landing and mobile
    values are plain strings, and landing lists go item by item as key[i].
    """
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        if isinstance(node.get("text"), str):
            yield path, node["text"]
            return
        for key, value in node.items():
            yield from source_strings(value, f"{path}.{key}" if path else key)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from source_strings(value, f"{path}[{index}]")


def translator_notes(source: dict) -> list[str]:
    """Keys of the source whose rendered value is a note, not the string."""
    return sorted(key for key, text in source_strings(source) if is_translator_note(key, text))


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

    noted: list[tuple[str, list[str]]] = []
    for source_file in sorted(SOURCE_DIR.glob("*.json")):
        notes = translator_notes(json.loads(source_file.read_text(encoding="utf-8")))
        if notes:
            noted.append((source_file.stem, notes))

    if not bad and not english_left and not noted:
        print(
            f"OK: every locale ({len(list(MESSAGES_DIR.glob('*.json'))) - 1} non-en) "
            f"has all {len(en_namespaces)} namespaces from en.json and no English sentence; "
            f"no translator note in any namespace of {len(list(SOURCE_DIR.glob('*.json')))} source locales"
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
    if noted:
        print("i18n FAILED: a translator note where the string should be:", file=sys.stderr)
        for locale, keys in noted:
            for key in keys:
                print(f"  {locale}: {key}", file=sys.stderr)
        print(
            "\nFix: put the string itself in packages/i18n-strings/src/<locale>.json "
            "(where the code passes no count, one wording that reads right for any "
            "number) and run scripts/build-i18n.py. A note for translators goes in the "
            "PR, or in an extension/email leaf's \"description\", never in the value.",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    sys.exit(main())

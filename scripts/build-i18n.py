#!/usr/bin/env python3
"""Generate extension _locales/ + landing messages/ from the single source of truth.

Source: packages/i18n-strings/src/{locale}.json

Outputs:
  extension/_locales/{locale}/messages.json         (chrome.i18n format)
  extension-firefox/_locales/{locale}/messages.json
  extension-safari/_locales/{locale}/messages.json
  landing/messages/{locale}.json                    (next-intl format)

Run: python3 scripts/build-i18n.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = ROOT / "packages" / "i18n-strings" / "src"
SUPPORTED_LOCALES = ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"]

EXTENSION_DIRS = [
    ROOT / "extension",
    ROOT / "extension-firefox",
    ROOT / "extension-safari",
]
LANDING_MESSAGES_DIR = ROOT / "landing" / "messages"
MOBILE_MESSAGES_DIR = ROOT / "mobile" / "i18n"


# Extension namespaces that get flattened back to chrome.i18n format.
# Mapping preserves EXACT chrome.i18n keys already used by popup.html/popup.js/manifest.
# A dict means per-key rename; a string means prefix (applied to all keys in namespace).
EXTENSION_NS_TO_FLAT_PREFIX = {
    "extension.meta": {
        "name": "extension_name",
        "description": "extension_description",
    },
    "extension.popup": {
        # Two keys keep the "popup_" prefix from the legacy format
        "brand": "popup_brand",
        "settings_title": "popup_settings_title",
        # Everything else stays bare — fallthrough default handled in build logic
    },
    "extension.common": "",          # trust_footer
    "extension.block_page": "block_",
    "extension.welcome": "welcome_",
}

# For popup namespace: keys NOT in the dict above use bare names (no prefix).
# This is legacy-compatible: status_safe_title, action_close_tab, aha_found_scams, etc.


def load_source(locale: str) -> dict[str, Any]:
    path = SOURCE_DIR / f"{locale}.json"
    if not path.exists():
        sys.exit(f"ERROR: source file missing: {path}")
    with open(path) as f:
        return json.load(f)


def flatten_for_extension(source: dict[str, Any]) -> dict[str, Any]:
    """Convert nested source → flat chrome.i18n messages dict."""
    out: dict[str, Any] = {}

    def get_ns(dotted_path: str) -> dict[str, Any]:
        node = source
        for part in dotted_path.split("."):
            if part not in node:
                return {}
            node = node[part]
        return node

    for ns_path, mapping in EXTENSION_NS_TO_FLAT_PREFIX.items():
        ns_data = get_ns(ns_path)
        if not ns_data:
            continue
        for key, value in ns_data.items():
            if isinstance(mapping, dict):
                # Dict: explicit renames; keys not in dict keep bare name
                flat_key = mapping.get(key, key)
            elif isinstance(mapping, str):
                # String: prefix applied to every key
                flat_key = mapping + key
            else:
                flat_key = key

            if not isinstance(value, dict) or "text" not in value:
                continue

            entry: dict[str, Any] = {"message": value["text"]}
            if "placeholders" in value:
                entry["placeholders"] = value["placeholders"]
            if "description" in value:
                entry["description"] = value["description"]
            out[flat_key] = entry

    return out


def namespace_for_landing(source: dict[str, Any]) -> dict[str, Any]:
    """
    Convert nested source → next-intl CamelCase namespaces.

    Any snake_case ``landing.*`` key is copied to its PascalCase counterpart.
    Explicit overrides (e.g. ``faq`` → ``FAQ``) win over auto-camelization;
    unknown keys fall through via ``_camelize`` so new sections don't require
    a script edit.
    """
    explicit = {
        "nav": "Nav",
        "hero": "Hero",
        "final_cta": "FinalCta",
        "footer": "Footer",
        "language_switcher": "LanguageSwitcher",
        "faq": "FAQ",  # keep acronym uppercase
    }
    landing_ns = source.get("landing", {})
    out: dict[str, Any] = {}
    for key, value in landing_ns.items():
        target = explicit.get(key) or _camelize(key)
        out[target] = value
    return out


def _camelize(snake: str) -> str:
    """``how_it_works`` → ``HowItWorks``."""
    return "".join(p[:1].upper() + p[1:] for p in snake.split("_") if p)


def flatten_for_mobile(source: dict[str, Any]) -> dict[str, str]:
    """Convert nested source → flat dotted-key dict for react-i18next.

    Leaf extraction:
      - if value is {text, placeholders?}  →  take text, convert $DOMAIN$ → {{domain}}
      - if value is plain string (landing namespace)  →  keep as-is
    Result: {"extension.popup.status_safe_title": "This page is safe", ...}
    """
    out: dict[str, str] = {}

    def walk(node: Any, prefix: str) -> None:
        if isinstance(node, str):
            out[prefix] = node
            return
        if isinstance(node, dict):
            if "text" in node and isinstance(node["text"], str):
                text: str = node["text"]
                placeholders = node.get("placeholders") or {}
                # chrome.i18n uses $DOMAIN$, i18next uses {{domain}}
                for ph_name in placeholders:
                    text = text.replace(f"${ph_name.upper()}$", f"{{{{{ph_name}}}}}")
                out[prefix] = text
                return
            for k, v in node.items():
                walk(v, f"{prefix}.{k}" if prefix else k)

    walk(source, "")
    return out


def write_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    tmp.replace(path)


def validate_parity(sources: dict[str, dict[str, Any]]) -> list[str]:
    warnings: list[str] = []
    reference = sources["en"]

    def is_leaf(v: Any) -> bool:
        return isinstance(v, str) or (isinstance(v, dict) and "text" in v)

    def walk(ref_node: Any, locale: str, node: Any, path: str = "") -> None:
        if isinstance(ref_node, dict) and not is_leaf(ref_node):
            for k, v in ref_node.items():
                child_path = f"{path}.{k}" if path else k
                if not isinstance(node, dict) or k not in node:
                    warnings.append(f"[{locale}] missing key: {child_path}")
                    continue
                walk(v, locale, node[k], child_path)

    for loc, src in sources.items():
        if loc == "en":
            continue
        walk(reference, loc, src)
    return warnings


def main() -> int:
    print(f"Source: {SOURCE_DIR.relative_to(ROOT)}/")

    sources = {loc: load_source(loc) for loc in SUPPORTED_LOCALES}

    warnings = validate_parity(sources)
    if warnings:
        print(f"\n⚠️  {len(warnings)} missing-key warnings:")
        for w in warnings[:10]:
            print(f"   {w}")
        if len(warnings) > 10:
            print(f"   ... and {len(warnings) - 10} more")
        print("  (falling back to English — fix translations before publishing)")
    else:
        print("✓ All locales have parity with English")

    total_written = 0
    for ext_dir in EXTENSION_DIRS:
        for loc in SUPPORTED_LOCALES:
            flat = flatten_for_extension(sources[loc])
            path = ext_dir / "_locales" / loc / "messages.json"
            write_atomic(path, flat)
            total_written += 1

    for loc in SUPPORTED_LOCALES:
        ns = namespace_for_landing(sources[loc])
        path = LANDING_MESSAGES_DIR / f"{loc}.json"
        write_atomic(path, ns)
        total_written += 1

    for loc in SUPPORTED_LOCALES:
        flat = flatten_for_mobile(sources[loc])
        path = MOBILE_MESSAGES_DIR / f"{loc}.json"
        write_atomic(path, flat)
        total_written += 1

    print(f"\n✓ Wrote {total_written} locale files")
    print(f"  {len(EXTENSION_DIRS) * len(SUPPORTED_LOCALES)} extension _locales/")
    print(f"  {len(SUPPORTED_LOCALES)} landing/messages/")
    print(f"  {len(SUPPORTED_LOCALES)} mobile/i18n/")

    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Fail if the landing site promises something the product does not do.

The 2026-09-25 service check (report items #11 and #12) found the Russian
landing telling people that their browsing history never leaves the phone
(checked site names go to our server and on to Google Safe Browsing), that
Cleanway works alongside NordVPN / ExpressVPN (on Android only one VPN runs at
a time), "Add to Chrome" while no browser listing is live, "Google Play soon"
while Google Play is blocked, a hand-written "1,842,630 checks" / "0.08% false
positives" report, and literal `$DATE$` placeholders on the page.

This guard pins those fixes so they cannot quietly come back. It scans:

  * every ``landing.*`` string in packages/i18n-strings/src/<locale>.json
    (the source of truth — landing/messages/ is generated from it), and
  * the landing's own source (landing/app, components, lib), where a few
    strings still live in code.

Usage:
  python3 scripts/check-landing-claims.py

Exits 0 when clean, 1 with one line per finding otherwise.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = REPO_ROOT / "packages" / "i18n-strings" / "src"
LANDING_DIR = REPO_ROOT / "landing"
INSTALL_URLS = LANDING_DIR / "lib" / "install-urls.ts"
CODE_DIRS = ("app", "components", "lib")
CODE_EXTS = {".ts", ".tsx"}


@dataclass(frozen=True)
class Rule:
    pattern: re.Pattern[str]
    why: str
    #: Only strings under this dotted key prefix (e.g. "landing.android").
    scope: str = "landing"
    #: Only these locales; empty means every locale.
    locales: tuple[str, ...] = ()
    #: Key prefixes inside the scope where the phrase is legitimate.
    exempt: tuple[str, ...] = ()


def _rule(pattern: str, why: str, scope: str = "landing", locales: tuple[str, ...] = (),
          exempt: tuple[str, ...] = ()) -> Rule:
    return Rule(re.compile(pattern, re.IGNORECASE), why, scope, locales, exempt)


# next-intl formats ICU `{name}` arguments. A chrome.i18n-style `$NAME$` in a
# landing string is rendered literally — "Snapshot: $DATE$" on the live page.
PLACEHOLDER = re.compile(r"\$[A-Z][A-Z_]*\$")

STRING_RULES: tuple[Rule, ...] = (
    _rule(r"NordVPN|ExpressVPN",
          "names a VPN we 'work alongside' — on Android only one VPN runs; turning another on stops Cleanway's shield"),
    _rule(r"1[\s.,  ]?842[\s.,  ]?630",
          "hand-written check count from the pre-launch transparency fixture"),
    _rule(r"\b0[.,]08\s?%",
          "hand-written false-positive rate — false positives have never been measured"),
    _rule(r"browsing (data|history)[^.]{0,40}(never leaves|stays on|lives only on)",
          "checked site names do leave the device (our server, then Google Safe Browsing and others)",
          locales=("en",)),
    _rule(r"zero data stored", "the server stores accounts, caches and hashed IPs", locales=("en",)),
    _rule(r"analyst team", "there is no analyst team verifying reports", locales=("en",)),
    _rule(r"\ball 5\b", "'All 5 platforms' — only the Android app is live", locales=("en",)),
    _rule(r"никогда не покида",
          "«никогда не покидает устройство» — имена проверяемых сайтов уходят на наш сервер и дальше",
          locales=("ru",)),
    _rule(r"ничего не узна", "«мы ничего не узнаём» — неправда: имена проверяемых сайтов мы получаем",
          locales=("ru",)),
    _rule(r"команд\w* аналитик", "«проверено командой аналитиков» — такой команды нет", locales=("ru",)),
    _rule(r"\bвсе 5\b", "«Платформы: все 5» — живо только приложение для Android", locales=("ru",)),
    _rule(r"Google Play",
          "promises a Google Play listing — Play is blocked (targetSdk); say only that RuStore is coming",
          scope="landing.android",
          # Naming Google Play Protect's warning (and that we are not on Play) is fine.
          exempt=("landing.android.warn_protect", "landing.android.screenshot_alt_protect")),
)

# Chrome CTAs are allowed again the moment install-urls.ts marks Chrome live.
CHROME_CTA_RULES: tuple[Rule, ...] = (
    _rule(r"add to chrome", "Chrome listing is not live (install-urls.ts)", locales=("en",)),
    _rule(r"добав\w* в chrome", "расширение для Chrome ещё не опубликовано (install-urls.ts)", locales=("ru",)),
)

CODE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"lives only on your device|stays on your device|Zero data stored", re.IGNORECASE),
     "hard-coded privacy over-claim"),
    (re.compile(r"analyst team", re.IGNORECASE), "hard-coded 'analyst team' claim"),
)
CODE_CHROME_RULE = (re.compile(r"Add to Chrome", re.IGNORECASE), "hard-coded Chrome CTA while Chrome is not live")


def chrome_is_live() -> bool:
    """Read the `available` flag of the chrome entry in install-urls.ts."""
    text = INSTALL_URLS.read_text(encoding="utf-8")
    match = re.search(r"chrome:\s*\{[^}]*?available:\s*(true|false)", text, re.DOTALL)
    if not match:
        sys.exit(f"FATAL: could not find chrome.available in {INSTALL_URLS}")
    return match.group(1) == "true"


def landing_strings(node: object, path: str) -> Iterator[tuple[str, str]]:
    """Yield (dotted path, text) for every string leaf under `node`."""
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for key, value in node.items():
            yield from landing_strings(value, f"{path}.{key}")
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from landing_strings(value, f"{path}[{index}]")


def in_scope(rule: Rule, locale: str, path: str) -> bool:
    if rule.locales and locale not in rule.locales:
        return False
    if any(path.startswith(prefix) for prefix in rule.exempt):
        return False
    return path == rule.scope or path.startswith(f"{rule.scope}.") or path.startswith(f"{rule.scope}[")


def check_strings(rules: tuple[Rule, ...]) -> list[str]:
    findings: list[str] = []
    for source in sorted(SOURCE_DIR.glob("*.json")):
        locale = source.stem
        landing = json.loads(source.read_text(encoding="utf-8")).get("landing", {})
        for path, text in landing_strings(landing, "landing"):
            if PLACEHOLDER.search(text):
                findings.append(f"{locale}: {path}: literal placeholder {PLACEHOLDER.search(text).group(0)} "
                                "— use an ICU {{name}} argument")
            for rule in rules:
                if in_scope(rule, locale, path) and rule.pattern.search(text):
                    findings.append(f"{locale}: {path}: {rule.why}")
    return findings


def code_files() -> Iterator[Path]:
    for directory in CODE_DIRS:
        for path in sorted((LANDING_DIR / directory).rglob("*")):
            if path.suffix in CODE_EXTS and "node_modules" not in path.parts:
                yield path


def check_code(chrome_live: bool) -> list[str]:
    rules = CODE_RULES if chrome_live else (*CODE_RULES, CODE_CHROME_RULE)
    findings: list[str] = []
    for path in code_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith(("//", "*", "/*")):
                continue
            for pattern, why in rules:
                if pattern.search(line):
                    rel = path.relative_to(REPO_ROOT).as_posix()
                    findings.append(f"{rel}:{lineno}: {why}")
    return findings


def main() -> int:
    chrome_live = chrome_is_live()
    string_rules = STRING_RULES if chrome_live else (*STRING_RULES, *CHROME_CTA_RULES)
    findings = check_strings(string_rules) + check_code(chrome_live)
    if not findings:
        print(f"OK: no known-false landing claims ({len(string_rules)} string rules, chrome live={chrome_live}).")
        return 0
    print("LANDING CLAIMS FAIL — the site promises something the product does not do:", file=sys.stderr)
    for finding in findings:
        print(f"  {finding}", file=sys.stderr)
    print("\nFix the source string in packages/i18n-strings/src/ (then run scripts/build-i18n.py) "
          "or the landing code. See docs/PRIVACY.md for what the product really does.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

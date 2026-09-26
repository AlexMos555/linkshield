#!/usr/bin/env python3
"""Fail if the landing site promises something the product does not do.

The 2026-09-25 service check (report items #11 and #12) found the Russian
landing telling people that their browsing history never leaves the phone
(checked site names go to our server and on to Google Safe Browsing), that
Cleanway works alongside NordVPN / ExpressVPN (on Android only one VPN runs at
a time), "Add to Chrome" while no browser listing is live, "Google Play soon"
while Google Play is blocked, a hand-written "1,842,630 checks" / "0.08% false
positives" report, and literal `$DATE$` placeholders on the page. The review
of the fix found more: an IP "never stored in plain form" that sits raw in the
rate limiter, Sentry "stripped of site names" while traces keep request URLs,
a "block screen" button that does not exist, and a policy describing app
version 1.0.2 before it shipped.

This guard pins those fixes so they cannot quietly come back — in all ten
languages, not just the two someone happened to read. It scans:

  * every ``landing.*`` string in packages/i18n-strings/src/<locale>.json
    (the source of truth — landing/messages/ is generated from it),
  * the landing's own source (landing/app, components, lib), where a few
    strings still live in code, and
  * the app version the privacy policy describes, against mobile/app.json.

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
from typing import Iterator, Mapping

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = REPO_ROOT / "packages" / "i18n-strings" / "src"
LANDING_DIR = REPO_ROOT / "landing"
INSTALL_URLS = LANDING_DIR / "lib" / "install-urls.ts"
APP_JSON = REPO_ROOT / "mobile" / "app.json"
CODE_DIRS = ("app", "components", "lib")
CODE_EXTS = {".ts", ".tsx"}
LOCALES = ("en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar")

Sources = Mapping[str, dict]


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


@dataclass(frozen=True)
class Claim:
    """One false promise, spelled the way each language would bring it back."""
    why: str
    patterns: Mapping[str, str]
    scope: str = "landing"


def localized(claim: Claim) -> tuple[Rule, ...]:
    missing = set(LOCALES) - set(claim.patterns)
    if missing:
        raise ValueError(f"claim {claim.why!r} has no pattern for {sorted(missing)}")
    return tuple(_rule(pattern, claim.why, claim.scope, (locale,)) for locale, pattern in claim.patterns.items())


# next-intl formats ICU `{name}` arguments. A chrome.i18n-style `$NAME$` in a
# landing string is rendered literally — "Snapshot: $DATE$" on the live page.
PLACEHOLDER = re.compile(r"\$[A-Z][A-Z_]*\$")

GLOBAL_RULES: tuple[Rule, ...] = (
    _rule(r"NordVPN|ExpressVPN",
          "names a VPN we 'work alongside' — on Android only one VPN runs; turning another on stops Cleanway's shield"),
    _rule(r"1[\s.,  ]?842[\s.,  ]?630",
          "hand-written check count from the pre-launch transparency fixture"),
    _rule(r"\b0[.,]08\s?%",
          "hand-written false-positive rate — false positives have never been measured"),
    _rule(r"Google Play",
          "promises a Google Play listing — Play is blocked (targetSdk); say only that RuStore is coming",
          scope="landing.android",
          # Naming Google Play Protect's warning (and that we are not on Play) is fine.
          exempt=("landing.android.warn_protect", "landing.android.screenshot_alt_protect")),
)

CLAIMS: tuple[Claim, ...] = (
    Claim("browsing history 'never leaves the device' — checked site names go to our server and on to "
          "Google Safe Browsing and others", {
              "en": r"browsing (data|history)[^.]{0,40}(never leaves|stays on|lives only on)",
              "ru": r"никогда не покида",
              "es": r"(historial|navegaci[oó]n)[^.]{0,40}nunca sale",
              "pt": r"(hist[oó]rico|navega[cç][aã]o)[^.]{0,40}nunca sai",
              "fr": r"(historique|navigation)[^.]{0,40}ne quitte jamais",
              "de": r"(Browserverlauf|Browserdaten|Surfverlauf)[^.]{0,40}(verl[aä]ss\w* nie|niemals)",
              "it": r"(cronologia|navigazione)[^.]{0,40}non lascia mai",
              "id": r"(riwayat|penjelajahan)[^.]{0,40}tidak pernah meninggalkan",
              "hi": r"ब्राउज़िंग[^।]{0,60}कभी",
              "ar": r"التصفح[^.]{0,40}لا يغادر",
          }),
    Claim("'we learn nothing' — we receive the names of checked sites", {
        "en": r"(learn|know)s? nothing about",
        "ru": r"ничего не узна",
        "es": r"no sabr[aá]n nada",
        "pt": r"n[aã]o saber[aã]o nada",
        "fr": r"n'apprendront rien",
        "de": r"erfahren[^.]{0,30}nichts",
        "it": r"non sapranno nulla",
        "id": r"tidak akan tahu apa pun",
        "hi": r"कुछ पता नहीं चलेगा",
        "ar": r"لن يعرف المهاجمون شيئ",
    }),
    Claim("'zero data stored' — the server stores accounts, caches and rate-limit counters", {
        "en": r"zero data stored",
        "ru": r"ноль данных|никаких данных не хран",
        "es": r"cero datos",
        "pt": r"zero dados",
        "fr": r"z[ée]ro donn[ée]e",
        "de": r"null daten",
        "it": r"zero dati",
        "id": r"nol data",
        "hi": r"शून्य डेटा",
        "ar": r"صفر بيانات",
    }),
    Claim("'verified by our analyst team' — there is no analyst team", {
        "en": r"analyst team",
        "ru": r"команд\w* аналитик",
        "es": r"equipo de analistas",
        "pt": r"equipe de analistas",
        "fr": r"[ée]quipe d.analystes",
        "de": r"analysten-?team|team von analysten",
        "it": r"(team|squadra) di analisti",
        "id": r"tim analis",
        "hi": r"विश्लेषकों की टीम",
        "ar": r"فريق (من )?المحلل",
    }),
    Claim("'all 5 platforms' — only the Android app is live", {
        "en": r"\ball 5\b",
        "ru": r"\bвсе 5\b",
        "es": r"\btodas las 5\b|\blas 5\b",
        "pt": r"\btodas as 5\b",
        "fr": r"\btoutes les 5\b|\bles 5\b",
        "de": r"\balle 5\b",
        "it": r"\btutte le 5\b",
        "id": r"\bsemua 5\b",
        "hi": r"सभी 5",
        "ar": r"كل الـ?5",
    }),
    Claim("the IP address is not 'never stored in plain form' — the rate limiter keeps it raw for up to an hour", {
        "en": r"not stored (as is|raw)",
        "ru": r"в открытом виде (он )?не хран|не хранится в открытом",
        "es": r"no se guarda tal cual",
        "pt": r"n[aã]o [ée] guardado como est",
        "fr": r"n'est pas conserv\w* telle? quelle?",
        "de": r"nicht im klartext gespeichert",
        "it": r"non viene conservato cos[iì] com",
        "id": r"tidak disimpan apa adanya",
        "hi": r"जैसा का तैसा नहीं रखा",
        "ar": r"لا يُ?حفظ كما هو",
    }),
    Claim("Sentry is not 'stripped of site names' — API and app traces keep request URLs", {
        "en": r"remove site names",
        "ru": r"убираем из них имена сайтов",
        "es": r"quitamos de ellos los nombres de sitios",
        "pt": r"tiramos deles nomes de sites",
        "fr": r"retirons les noms de sites",
        "de": r"entfernen wir seitennamen",
        "it": r"togliamo i nomi dei siti",
        "id": r"menghapus nama situs",
        "hi": r"साइटों के नाम और पते हटा",
        "ar": r"نزيل منها أسماء المواقع",
    }),
    Claim("the shield's traffic 'goes nowhere' — lookups of unblocked sites go to Cloudflare / Quad9", {
        "en": r"traffic doesn't travel anywhere",
        "ru": r"трафик[^.]{0,30}никуда не уходит",
        "es": r"tr[aá]fico no viaja a ning[uú]n",
        "pt": r"tr[aá]fego n[aã]o vai para lugar nenhum",
        "fr": r"trafic ne transite nulle part",
        "de": r"datenverkehr wird dar[üu]ber nirgendwohin",
        "it": r"traffico non passa da nessuna parte",
        "id": r"lalu lintas anda tidak dikirim ke mana pun",
        "hi": r"ट्रैफ़िक इसके ज़रिए कहीं नहीं",
        "ar": r"لا تمرّ حركة بياناتك عبرها",
    }),
    Claim("the Android app has no block screen — a DNS block shows the browser's own error page; "
          "'Not a scam — allow it' lives in History and in the block notification", {
              "en": r"block screen",
              "ru": r"экран\w* блокировки",
              "es": r"pantalla de bloqueo",
              "pt": r"tela de bloqueio",
              "fr": r"[ée]cran de blocage",
              "de": r"sperrbildschirm",
              "it": r"schermata di blocco",
              "id": r"layar pemblokiran",
              "hi": r"ब्लॉक वाली स्क्रीन",
              "ar": r"شاشة الحظر",
          }, scope="landing.support"),
    Claim("the benchmark counts the server's 'dangerous' verdicts, not blocking on the phone "
          "(the on-device list covers a fraction of fresh phishing)", {
              "en": r"\bblock",
              "ru": r"блокир",
              "es": r"bloque",
              "pt": r"bloque",
              "fr": r"bloqu",
              "de": r"blockier",
              "it": r"blocc",
              "id": r"blokir",
              "hi": r"ब्लॉक",
              "ar": r"حظر|محظور",
          }, scope="landing.hero.badge"),
)

# Chrome CTAs are allowed again the moment install-urls.ts marks Chrome live.
CHROME_CTA: Claim = Claim("Chrome listing is not live (install-urls.ts)", {
    "en": r"add to chrome",
    "ru": r"добав\w* в chrome",
    "es": r"a[ñn]adir a chrome",
    "pt": r"adicionar ao chrome",
    "fr": r"ajouter [àa] chrome",
    "de": r"zu chrome hinzuf",
    "it": r"aggiungi a chrome",
    "id": r"tambahkan ke chrome",
    "hi": r"chrome में जोड़",
    "ar": r"إضافة إلى chrome",
})

STRING_RULES: tuple[Rule, ...] = GLOBAL_RULES + tuple(rule for claim in CLAIMS for rule in localized(claim))
CHROME_CTA_RULES: tuple[Rule, ...] = localized(CHROME_CTA)

CODE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"lives only on your device|stays on your device|Zero data stored", re.IGNORECASE),
     "hard-coded privacy over-claim"),
    (re.compile(r"analyst team", re.IGNORECASE), "hard-coded 'analyst team' claim"),
)
CODE_CHROME_RULE = (re.compile(r"Add to Chrome", re.IGNORECASE), "hard-coded Chrome CTA while Chrome is not live")

# A dotted x.y.z version. The look-arounds skip IP addresses (1.1.1.1, 9.9.9.9).
VERSION = re.compile(r"(?<![\d.])(\d+)\.(\d+)\.(\d+)(?![\d.])")
POLICY_SCOPE = "landing.privacy_policy"


def chrome_is_live() -> bool:
    """Read the `available` flag of the chrome entry in install-urls.ts."""
    text = INSTALL_URLS.read_text(encoding="utf-8")
    match = re.search(r"chrome:\s*\{[^}]*?available:\s*(true|false)", text, re.DOTALL)
    if not match:
        sys.exit(f"FATAL: could not find chrome.available in {INSTALL_URLS}")
    return match.group(1) == "true"


def released_app_version() -> tuple[int, int, int]:
    """The Android app version that ships (mobile/app.json expo.version)."""
    raw = json.loads(APP_JSON.read_text(encoding="utf-8"))["expo"]["version"]
    match = VERSION.fullmatch(raw)
    if not match:
        sys.exit(f"FATAL: expo.version {raw!r} in {APP_JSON} is not x.y.z")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def load_sources() -> dict[str, dict]:
    """{locale: the `landing` subtree} for every source file."""
    return {
        source.stem: json.loads(source.read_text(encoding="utf-8")).get("landing", {})
        for source in sorted(SOURCE_DIR.glob("*.json"))
    }


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


def check_strings(rules: tuple[Rule, ...], sources: Sources) -> list[str]:
    findings: list[str] = []
    for locale, landing in sources.items():
        for path, text in landing_strings(landing, "landing"):
            placeholder = PLACEHOLDER.search(text)
            if placeholder:
                findings.append(f"{locale}: {path}: literal placeholder {placeholder.group(0)} "
                                "— use an ICU {{name}} argument")
            findings.extend(f"{locale}: {path}: {rule.why}"
                            for rule in rules if in_scope(rule, locale, path) and rule.pattern.search(text))
    return findings


def check_app_version(sources: Sources, released: tuple[int, int, int]) -> list[str]:
    """The site describes the app that ships — not the next one.

    No landing string may name a version newer than mobile/app.json, and the
    privacy policy must name the released one. The second half is the tripwire:
    the release that bumps app.json fails here until someone re-checks the
    policy's DNS section against CleanwayVpnService.kt and rewrites it.
    """
    shown = ".".join(str(part) for part in released)
    findings: list[str] = []
    for locale, landing in sources.items():
        policy_names_release = False
        for path, text in landing_strings(landing, "landing"):
            for match in VERSION.finditer(text):
                version = tuple(int(part) for part in match.groups())
                if version > released:
                    findings.append(f"{locale}: {path}: names app version {match.group(0)}, newer than the "
                                    f"released {shown} (mobile/app.json) — describe only what ships")
                if version == released and path.startswith(POLICY_SCOPE):
                    policy_names_release = True
        if not policy_names_release:
            findings.append(f"{locale}: {POLICY_SCOPE}: does not describe the released app {shown} "
                            "(mobile/app.json) — re-check section 3 against CleanwayVpnService.kt, then name it")
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
    sources = load_sources()
    findings = (check_strings(string_rules, sources)
                + check_app_version(sources, released_app_version())
                + check_code(chrome_live))
    if not findings:
        print(f"OK: no known-false landing claims ({len(string_rules)} string rules, {len(sources)} locales, "
              f"chrome live={chrome_live}).")
        return 0
    print("LANDING CLAIMS FAIL — the site promises something the product does not do:", file=sys.stderr)
    for finding in findings:
        print(f"  {finding}", file=sys.stderr)
    print("\nFix the source string in packages/i18n-strings/src/ (then run scripts/build-i18n.py) "
          "or the landing code. See docs/PRIVACY.md for what the product really does.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

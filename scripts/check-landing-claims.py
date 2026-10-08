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

It also holds the operator-billed subscription's copy (landing.billing,
landing.cancel, the billing sections of the terms and the policy, the home
teaser's operator variant — all rendered only with NEXT_PUBLIC_BILLING_ENABLED
on) to a paid product's truth: nothing "free", no Stripe or dollar prices where
the operator bills the phone account, and no hand-written price (prices are
settings, passed as ICU arguments — landing/lib/billing.ts).

The world's /pricing (landing.pricing) is held to the same discipline: its
prices come from the API (landing/lib/world-pricing.ts), so no string may
hand-write a dollar amount, and none may repeat the old claim that the price
tier is "detected from your Stripe billing country" (it follows the country
of the connection, and never came from Stripe).

Usage:
  python3 scripts/check-landing-claims.py
  python3 scripts/check-landing-claims.py --billing-on

`--billing-on` is the review before the founder flips the flag: it applies the
"free" rules to every landing string a Russian visitor will still see with the
subscription on, and lists what must be re-worded or consciously kept. It is
advisory and not part of CI while the flag is off.

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
    # 2026-10 device plan: world prices come from the API as ICU arguments. A
    # hand-written "$4.99" outlived the plan it described once already.
    _rule(r"\$\s?\d",
          "hand-writes a dollar price on /pricing — prices come from the API (landing/lib/world-pricing.ts)",
          scope="landing.pricing"),
    # 2026-10-08 store readiness: /business sold "$3.99/user/month" with a
    # 14-day trial, SSO and phishing simulations — none of it exists. A team
    # buys the same device plan; its prices live on /pricing (from the API).
    _rule(r"\$\s?\d",
          "hand-writes a dollar price on /business — a team buys the device plan; link to /pricing instead",
          scope="landing.business"),
    _rule(r"billing country",
          "says the price tier comes from the Stripe billing country — it follows the country of the connection "
          "(the `cc` the page sends), and checkout charges that same country's price",
          scope="landing.pricing"),
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
    Claim("Sentry is not 'stripped of site names' — the app's traces keep request URLs, "
          "and an API error can quote a site in its exception message (the API's URLs, spans "
          "and request bodies are cut since 2026-09-27; the app's traces are not yet)", {
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
          "'Not a scam — allow it' lives in History", {
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
    Claim("the block notification has no 'Not a scam' button since app 1.0.3 — one tap on a pop-up is what "
          "a scammer on the phone asks for; a site is allowed only in History, behind a scam warning", {
              "en": r"button[^.]{0,30}in the block notification",
              "ru": r"кнопк\w*[^.]{0,30}в уведомлении о блокировке",
              "es": r"bot[oó]n[^.]{0,30}en la notificaci[oó]n de bloqueo",
              "pt": r"bot[aã]o[^.]{0,30}na notifica[cç][aã]o de bloqueio",
              "fr": r"bouton[^.]{0,40}dans la notification de blocage",
              "de": r"schaltfl[aä]che[^.]{0,40}in der sperr-benachrichtigung",
              "it": r"pulsante[^.]{0,30}nella notifica di blocco",
              "id": r"tombol[^.]{0,30}di notifikasi pemblokiran",
              "hi": r"सूचना[^।]{0,40}बटन",
              "ar": r"الزر[^.]{0,30}إشعار الحظر",
          }, scope="landing.support"),
    Claim("names one app version as the one that sends something — every later version sends it too, and "
          "the policy then reads as if they did not; say 'from version X' (1.0.3 review: the install number)", {
              "en": r"app version \d+\.\d+\.\d+ (also )?sends",
              "ru": r"(приложение версии|версия приложения) \d+\.\d+\.\d+ (переда[её]т|отправляет)",
              "es": r"la versi[oó]n \d+\.\d+\.\d+ de la app (tambi[eé]n )?env[ií]a",
              "pt": r"a vers[aã]o \d+\.\d+\.\d+ do app (tamb[eé]m )?envia",
              "fr": r"la version \d+\.\d+\.\d+ de l'appli (envoie|transmet)",
              "de": r"(sendet|übermittelt) die App-Version \d+\.\d+\.\d+",
              "it": r"la versione \d+\.\d+\.\d+ dell'app (invia|trasmette)",
              "id": r"aplikasi versi \d+\.\d+\.\d+ (juga )?mengirim",
              "hi": r"ऐप का संस्करण \d+\.\d+\.\d+[^।]{0,40}भेजता",
              "ar": r"يرسل الإصدار \d+\.\d+\.\d+",
          }, scope="landing.privacy_policy"),
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
    # 2026-10-08 store readiness: an "automatic SMS check" exists only on the
    # unmerged RuStore branch (feat/sms-auto-rustore); the site and the Google
    # Play build check a message only when the person shares or pastes it, and
    # the app requests no SMS permission (mobile/scripts/check-android-permissions.mjs).
    # The benefit may appear only in RuStore-specific copy, never on the site.
    Claim("promises an automatic SMS / message check — the site's and Play's app checks only a message the "
          "person shares or pastes (no SMS permission); the automatic check is RuStore-only", {
              "en": r"automatic(ally)?\W+(\w+\W+)?(sms|text message|message)s?\W+check|"
                    r"(sms|text messages?|messages?)\W+(are\W+)?checked automatically",
              "ru": r"автоматическ\w*\W+проверк\w*\W+(sms|смс|сообщени)|(sms|смс|сообщени\w*)\W+проверя\w*\W+автоматически",
              "es": r"(verificaci[oó]n|comprobaci[oó]n|revisi[oó]n) autom[aá]tica de (sms|mensajes)",
              "pt": r"(verifica[cç][aã]o|checagem) autom[aá]tica de (sms|mensagens)",
              "fr": r"(v[ée]rification|contr[oô]le) automatique des (sms|messages)",
              "de": r"automatische\w* (sms|nachrichten)[- ]?(pr[üu]fung|check)",
              "it": r"(verifica|controllo) automatic[ao] (degli |dei )?(sms|messaggi)",
              "id": r"(pemeriksaan|cek) (sms|pesan) otomatis",
              "hi": r"(sms|एसएमएस|मैसेज|संदेश)\w*\W+(की\W+)?(स्वचालित|ऑटोमैटिक|अपने आप)",
              "ar": r"(فحص|تحقق)\W+(تلقائي\W+)?(لل)?(رسائل|sms)\W*(النصية\W+)?تلقائي",
          }),
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

# ---- The operator-billed subscription (behind NEXT_PUBLIC_BILLING_ENABLED) ----
# The strings the flag reveals. The trial is "без оплаты" / "nothing charged" —
# a window, not a price — so none of them may call the product free.
BILLING_SCOPES: tuple[str, ...] = (
    "landing.billing",
    "landing.cancel",
    "landing.terms.billing",
    "landing.privacy_policy.billing",
    "landing.pricing_teaser.operator",
)
# The pages that sell: the operator bills the phone account in rubles, so
# Stripe and dollar prices have no place on them (the legal sections may still
# describe Stripe for other countries).
BILLING_SALES_SCOPES: tuple[str, ...] = ("landing.billing", "landing.cancel", "landing.pricing_teaser.operator")

FREE_WORDS: Mapping[str, str] = {
    "en": r"\bfree\b",
    "ru": r"бесплат",
    "es": r"\bgratis\b|gratuit",
    "pt": r"gr[aá]tis|gratuit",
    "fr": r"gratuit",
    "de": r"kostenlos|\bgratis\b|umsonst",
    "it": r"\bgratis\b|gratuit",
    "id": r"\bgratis\b|cuma-cuma",
    "hi": r"मुफ़्त|मुफ्त|निःशुल्क|फ़्री|फ्री",
    "ar": r"مجان",
}
FREE_WHY = ("calls the subscription free — only the trial window is without charge; say "
            "'без оплаты' / 'nothing charged', never 'free'")
# The ruble prices a string must never spell out. 2026-10-07 device plan: 99 ₽
# for 3 devices and +29 ₽ per extra device (both ICU arguments: {price},
# {extra}). 270 and 399 are the retired three- and five-phone plans — still
# banned, so a stale string cannot bring them back.
HARDCODED_PRICE = re.compile(r"\b(99|29|270|399)\s?(₽|руб|rub\b)", re.IGNORECASE)
STRIPE_OR_DOLLARS = re.compile(r"stripe|\$\s?\d|\bUSD\b", re.IGNORECASE)


def billing_rules() -> tuple[Rule, ...]:
    rules: list[Rule] = []
    for scope in BILLING_SCOPES:
        rules.extend(localized(Claim(FREE_WHY, FREE_WORDS, scope=scope)))
        rules.append(Rule(HARDCODED_PRICE, "hard-codes a price — prices are settings (landing/lib/billing.ts) "
                                           "passed as ICU arguments", scope))
    for scope in BILLING_SALES_SCOPES:
        rules.append(Rule(STRIPE_OR_DOLLARS, "names Stripe or a dollar price on the operator-billing pages — "
                                             "the operator bills the phone account in rubles", scope))
    return tuple(rules)


# Strings a Russian visitor no longer sees once the flag is on: the free-only
# /pricing and the free-only teaser are replaced by the operator variants.
BILLING_ON_EXEMPT: tuple[str, ...] = (
    "landing.pricing.free_",
    "landing.pricing_teaser.free_only",
    "landing.pricing_teaser.free_body_with_plans",
    "landing.pricing_teaser.plans_link",
)


def billing_on_review_rules() -> tuple[Rule, ...]:
    """With the subscription on, 'free' anywhere on the Russian landing needs a second look."""
    return tuple(Rule(re.compile(pattern, re.IGNORECASE),
                      "BILLING ON: says 'free' on a page a paying Russian visitor sees — re-word, or keep knowingly "
                      "(the install and the trial are without charge; the product is not)",
                      "landing", (locale,), BILLING_ON_EXEMPT + BILLING_SCOPES)
                 for locale, pattern in FREE_WORDS.items())


STRING_RULES: tuple[Rule, ...] = (GLOBAL_RULES
                                  + tuple(rule for claim in CLAIMS for rule in localized(claim))
                                  + billing_rules())
CHROME_CTA_RULES: tuple[Rule, ...] = localized(CHROME_CTA)

CODE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"lives only on your device|stays on your device|Zero data stored", re.IGNORECASE),
     "hard-coded privacy over-claim"),
    # The old /pricing FAQ: "Tier detected from your Stripe billing country". The
    # tier never came from Stripe; it follows the country the page sends.
    (re.compile(r"Stripe billing country", re.IGNORECASE), "hard-coded false claim about how the price tier is chosen"),
    (re.compile(r"analyst team", re.IGNORECASE), "hard-coded 'analyst team' claim"),
    # 2026-10-08: the old /business page hard-coded "$3.99/user/month". Prices
    # per user or seat do not exist; the plan counts devices (lib/world-pricing.ts).
    (re.compile(r"\$\s?\d+(\.\d+)?\s*/\s*(user|seat)", re.IGNORECASE), "hard-coded per-user price — the plan counts devices"),
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


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    billing_on = "--billing-on" in args
    chrome_live = chrome_is_live()
    string_rules = STRING_RULES if chrome_live else (*STRING_RULES, *CHROME_CTA_RULES)
    if billing_on:
        string_rules = (*string_rules, *billing_on_review_rules())
    sources = load_sources()
    findings = (check_strings(string_rules, sources)
                + check_app_version(sources, released_app_version())
                + check_code(chrome_live))
    if not findings:
        print(f"OK: no known-false landing claims ({len(string_rules)} string rules, {len(sources)} locales, "
              f"chrome live={chrome_live}, billing-on review={billing_on}).")
        return 0
    print("LANDING CLAIMS FAIL — the site promises something the product does not do:", file=sys.stderr)
    for finding in findings:
        print(f"  {finding}", file=sys.stderr)
    print("\nFix the source string in packages/i18n-strings/src/ (then run scripts/build-i18n.py) "
          "or the landing code. See docs/PRIVACY.md for what the product really does.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

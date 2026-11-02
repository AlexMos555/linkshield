#!/usr/bin/env python3
"""Mobile i18n contract check — run locally or in CI, exits non-zero on drift.

Three invariants, each of which has been violated for real:

1. KEY PARITY — every generated locale carries exactly the same flat
   `mobile.*` key set as English. A key present in en but missing in ru
   renders as the literal dotted key on screen (the QR scanner shipped
   with its entire namespace missing — the camera-permission rationale
   displayed as "mobile.scanner.permission_body").

2. PLACEHOLDER PARITY — every `{{token}}` in an English value appears
   byte-exact in every translation. A translated or dropped token renders
   as literal braces or silently loses the number it was carrying.

3. USED KEYS EXIST — every string literal naming a key of any namespace
   of packages/i18n-strings/src (`t("mobile.…")`, `t("extension.…")`, …)
   referenced in mobile/app, mobile/src or mobile/modules resolves in the
   generated en.json, accounting for i18next plural suffixes (base key
   present is sufficient — i18next tries the v4 suffix the locale's plural
   rule picks, _one/_few/_other…, and falls back to the base key when that
   variant is absent). The app reads extension.* too (the locked-account
   modal), and landing.* / email.* never reach mobile/i18n
   (scripts/i18n_mobile.py), so a reference to one of those fails by name:
   each would show the raw key on screen.

4. NO LINKS, NO PHONE NUMBERS IN OUR OWN NOTIFICATIONS — the
   `mobile.android_native.*` strings are what the service posts (block
   alerts, the after-call notice). A link or a number in a notification is
   exactly what a scam notification looks like, and the person must never
   learn to tap one of ours; the site name stays plain text.

5. VALUES ARE TRANSLATIONS, NOT NOTES — every `mobile.*` value is what the
   screen renders, so it must hold the string itself, not a note to the
   translator. Plural variants shipped that way first (ar
   `mobile.report.times_one` as "times_one: «…» (and optionally add _two
   …)"), then base keys did: ar `mobile.history.minutes_ago` showed "Add
   Arabic plural variants: … Single-string fallback: …" on every History
   row, and it `mobile.breach.found_body` showed "found_body_one: \"…\" /
   found_body_other: \"…\"". The rule lives in scripts/i18n_notes.py, which
   check-i18n-parity.py also runs over every namespace of the source
   (landing, extension and email too). And no v3 `<base>_plural` keys: i18next 24+
   never reads them, so they only mislead the next translator.

Every invariant holds for what Android shows: the base file plus
mobile/i18n/android/<locale>.json, the few strings only Android has (only
src/i18n/resources.android.ts imports them, so they stay out of the iPhone's
bundle — scripts/i18n_mobile.py). A key is in one of the two, never both,
and every locale splits its keys the way English does.

Dynamic template-literal keys (`mobile.result.verdict_${level}`) cannot be
checked statically and are intentionally out of scope here.
"""
import json
import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN = os.path.join(ROOT, "mobile", "i18n")
GEN_ANDROID = os.path.join(GEN, "android")
SOURCE_EN = os.path.join(ROOT, "packages", "i18n-strings", "src", "en.json")
PH = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")
NATIVE_PREFIX = "mobile.android_native."
LINK = re.compile(r"https?://|www\.|tel:", re.IGNORECASE)
PHONE = re.compile(r"\+?\d[\d\s\-()]{6,}\d")

sys.path.insert(0, os.path.join(ROOT, "scripts"))
from i18n_mobile import MOBILE_SKIP_NAMESPACES  # noqa: E402
from i18n_notes import is_translator_note  # noqa: E402

# A key literal of any namespace the source has, not only mobile.*.
with open(SOURCE_EN, encoding="utf-8") as _f:
    NAMESPACES = sorted(json.load(_f))
KEY_REF = re.compile(r'["`]((?:' + "|".join(map(re.escape, NAMESPACES)) + r')\.[a-z0-9_.]+)["`]')

failures = []


locales = {}
android_only = {}
en_all = {}  # every key the app can look up in English, any namespace
for path in sorted(glob.glob(os.path.join(GEN, "*.json"))):
    code = os.path.basename(path)[:-5]
    data = json.load(open(path, encoding="utf-8"))
    android_path = os.path.join(GEN_ANDROID, f"{code}.json")
    extra = json.load(open(android_path, encoding="utf-8")) if os.path.exists(android_path) else {}
    both = sorted(set(data) & set(extra))
    if both:
        failures.append(f"{code}: in both the base file and android/: {both[:5]}")
    android_only[code] = set(extra)
    data = {**data, **extra}
    if code == "en":
        en_all = data
    locales[code] = {k: v for k, v in data.items() if k.startswith("mobile.")}

if "en" not in locales:
    print("FATAL: mobile/i18n/en.json not found or carries no mobile.* keys")
    sys.exit(1)

en = locales["en"]

stray = sorted({os.path.basename(p)[:-5] for p in glob.glob(os.path.join(GEN_ANDROID, "*.json"))} - set(locales))
if stray:
    failures.append(f"android/ files with no base locale file: {stray}")
for code, keys in sorted(android_only.items()):
    if keys != android_only["en"]:
        failures.append(f"{code}: android/ keys differ from en's: {sorted(android_only['en'] ^ keys)[:5]}")

dead_v3_plurals = sorted(k for k in en if k.endswith("_plural") and k[: -len("_plural")] in en)
if dead_v3_plurals:
    failures.append(f"v3 _plural keys i18next no longer reads: {dead_v3_plurals}")

for code, flat in sorted(locales.items()):
    missing = sorted(set(en) - set(flat))
    extra = sorted(set(flat) - set(en))
    if missing or extra:
        failures.append(f"{code}: missing={missing[:5]} extra={extra[:5]}")
        continue
    ph_bad = [
        k for k in en
        if set(PH.findall(str(en[k]))) != set(PH.findall(str(flat[k])))
    ]
    empty = [k for k in en if not str(flat[k]).strip()]
    if ph_bad:
        failures.append(f"{code}: placeholder mismatch in {ph_bad[:8]}")
    if empty:
        failures.append(f"{code}: empty values {empty[:5]}")
    tappable = [
        k for k, v in flat.items()
        if k.startswith(NATIVE_PREFIX) and (LINK.search(str(v)) or PHONE.search(str(v)))
    ]
    if tappable:
        failures.append(f"{code}: notification strings carry a link or a phone number {tappable[:5]}")
    noted = sorted(k for k, v in flat.items() if is_translator_note(k, str(v)))
    if noted:
        failures.append(f"{code}: values hold a translator note, not a string {noted[:5]}")

used = set()
for folder in ("app", "src", "modules"):
    for ext in ("ts", "tsx"):
        for path in glob.glob(os.path.join(ROOT, "mobile", folder, "**", f"*.{ext}"), recursive=True):
            if f"{os.sep}node_modules{os.sep}" in path:
                continue
            with open(path, encoding="utf-8") as f:
                for match in KEY_REF.finditer(f.read()):
                    used.add(match.group(1))

left_out = sorted(k for k in used if k.startswith(MOBILE_SKIP_NAMESPACES))
if left_out:
    failures.append(
        f"referenced keys of a namespace scripts/i18n_mobile.py keeps out of mobile/i18n: {left_out}"
    )
unresolved = sorted(k for k in used if k not in en_all and k not in left_out)
if unresolved:
    failures.append(f"referenced keys absent from en.json (+ android/en.json): {unresolved}")

if failures:
    print("MOBILE I18N CHECK FAILED:")
    for f in failures:
        print("  " + f)
    sys.exit(1)

print(
    f"mobile i18n OK: {len(locales)} locales × {len(en)} keys "
    f"({len(android_only['en'])} Android-only), "
    f"{len(used)} referenced keys resolve, placeholders exact"
)

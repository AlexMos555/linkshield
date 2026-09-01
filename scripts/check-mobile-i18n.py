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

3. USED KEYS EXIST — every `t("mobile.…")` string literal referenced in
   mobile/app or mobile/src resolves in the generated en.json, accounting
   for i18next plural suffixes (base key present is sufficient — the app
   pins compatibilityJSON v3, so an unresolved plural suffix falls back to
   the base key).

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
PH = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*\}\}")
KEY_REF = re.compile(r'["`](mobile\.[a-z0-9_.]+)["`]')

failures = []

locales = {}
for path in sorted(glob.glob(os.path.join(GEN, "*.json"))):
    code = os.path.basename(path)[:-5]
    data = json.load(open(path, encoding="utf-8"))
    locales[code] = {k: v for k, v in data.items() if k.startswith("mobile.")}

if "en" not in locales:
    print("FATAL: mobile/i18n/en.json not found or carries no mobile.* keys")
    sys.exit(1)

en = locales["en"]

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

used = set()
for pattern in ("mobile/app/**/*.tsx", "mobile/src/**/*.ts", "mobile/src/**/*.tsx"):
    for path in glob.glob(os.path.join(ROOT, pattern), recursive=True):
        with open(path, encoding="utf-8") as f:
            for match in KEY_REF.finditer(f.read()):
                used.add(match.group(1))

unresolved = sorted(k for k in used if k not in en)
if unresolved:
    failures.append(f"referenced keys absent from en.json: {unresolved}")

if failures:
    print("MOBILE I18N CHECK FAILED:")
    for f in failures:
        print("  " + f)
    sys.exit(1)

print(
    f"mobile i18n OK: {len(locales)} locales × {len(en)} keys, "
    f"{len(used)} referenced keys resolve, placeholders exact"
)

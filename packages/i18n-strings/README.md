# @cleanway/i18n-strings

Single source of truth for UI strings across all Cleanway clients (extensions × 3, landing, mobile).

## Why this exists

Before: same string "This is a scam site" was copy-pasted into:
- `extension/_locales/en/messages.json`
- `extension-firefox/_locales/en/messages.json`
- `extension-safari/_locales/en/messages.json`
- `landing/messages/en.json`
- (soon) `mobile/i18n/en.json`

30+ files to keep in sync. One misspelled translation = inconsistent UX.

**Now:** edit `src/en.json` once, run `scripts/build-i18n.py`, everyone picks it up.

## Structure

```
src/
├── en.json          ← English source of truth (edit this)
├── ru.json          ← Russian (draft native-quality)
├── es.json          ← Spanish (draft)
├── pt.json          ← Portuguese (draft)
├── fr.json          ← French (draft)
├── de.json          ← German (draft)
├── it.json          ← Italian (draft)
├── id.json          ← Indonesian (draft)
├── hi.json          ← Hindi (draft)
└── ar.json          ← Arabic (draft, RTL)
```

## Namespaces

Strings are organized by UI surface to avoid naming collisions:

- **extension.popup** → status card, action buttons, stats
- **extension.block_page** → STOP overlay for scam sites
- **extension.welcome** → first-run onboarding
- **extension.common** → shared across extension screens
- **extension.meta** → extension_name + description (Chrome Web Store)
- **landing.nav** → nav bar
- **landing.hero** → hero section
- **landing.final_cta** → footer CTA
- **landing.footer** → footer links
- **landing.language_switcher** → lang dropdown
- **shared.scam_glossary** → replacements for jargon ("phishing" → "scam site")

## Build output

Running `python3 scripts/build-i18n.py` produces:

### Extension locales (Chrome i18n format)
```
extension/_locales/{locale}/messages.json
extension-firefox/_locales/{locale}/messages.json
extension-safari/_locales/{locale}/messages.json
```
Flat key structure (`extension_name`, `popup_status_safe_title`, ...) as required by `chrome.i18n.getMessage()`.

### Landing (next-intl format)
```
landing/messages/{locale}.json
```
Namespaced structure (`Nav`, `Hero`, `FinalCta`, ...) as used by `useTranslations()`.

Each build:
- Validates every locale has the same keys as `en.json`
- Warns about missing translations (falls back to English)
- Writes both formats atomically

## Adding a new string

1. Add the English key in `src/en.json` under the appropriate namespace
2. Add translations in all 9 other language files
3. Run `python3 scripts/build-i18n.py`
4. Verify the key appears in the generated files for your target client
5. Use the key in code:
   - Extension: `chrome.i18n.getMessage("popup_status_safe_title")`
   - Landing: `useTranslations("Nav")("features")`

## Adding a new language

1. Add the locale code to `SUPPORTED_LOCALES` in `scripts/build-i18n.py`
2. Create `src/{locale}.json` with all keys translated
3. Run build script
4. Add the locale to `landing/i18n/routing.ts` `locales` array
5. Ship it

## Quality gates

- Pre-commit hook: verify all locale files have matching key sets
- CI: fail build if any locale is missing a key that exists in `en.json`
- (Planned) Translation review workflow: non-English changes require native-reviewer approval

# Landing Localization Status

Origin: docs/AUDIT-2026-05-24-deep.md landing-a11y-i18n HIGH —
"14 of 18 locale-routed pages are English-only despite living under [locale]".

## Done

| Page | Status | Namespace |
|---|---|---|
| `/[locale]` (Hero/Features/etc.) | ✅ localized | `Hero`, `Features`, `HowItWorks`, `PricingTeaser`, `Comparison`, `Privacy`, `Testimonials`, `FAQ`, `FinalCta`, `Nav`, `LanguageSwitcher`, `Footer` |
| `/[locale]/success` | ✅ localized + `<main>` + WCAG-AA contrast fix | `Success` (13 keys × 10 locales) |
| `/[locale]/account/restore` | ✅ localized | `AccountRestore` (17 keys × 10 locales) |
| `/[locale]/privacy-policy` | 🟡 `<main>` landmark added; copy stays English (legal text is jurisdiction-specific by design) | — |
| `/[locale]/terms` | 🟡 `<main>` landmark added; copy stays English (same reason) | — |
| `/[locale]/business` | 🟡 `<main>` landmark added; copy still English (B2B audience often EN-only initially) | — |

## Remaining work

Each page below ships with hardcoded English strings inside `<h1>` /
`<p>` / button labels / metadata. Migration pattern is identical to
the `success` page work (commit ad-hoc-success-i18n) — see that as
the canonical example:

1. Add `landing.{page}.*` keys to `packages/i18n-strings/src/en.json`
   with native English copy.
2. Mirror into the other 9 locales (the `/tmp/translate_landing_success.py`
   one-shot script is a template — adapt names + values).
3. Run `python3 scripts/build-i18n.py` to propagate into
   `landing/messages/{locale}.json` under the PascalCase `{Page}` namespace.
4. In the page itself, replace the literal string in the JSX with
   `t("key")` from `await getTranslations({locale, namespace: "{Page}"})`.

| Page | Strings ~ | Notes |
|---|---|---|
| `/[locale]/pricing` (`page.tsx` + `PricingClient.tsx`) | 50+ | High traffic; conversion-critical |
| `/[locale]/signup` (`page.tsx` + `SignupForm.tsx`) | 25 | Auth flow entry point |
| `/[locale]/check/[domain]` | 30 | SSR + JSON-LD; SEO-relevant |
| `/[locale]/audit/[domain]` | ~20 | Same patterns as check |
| `/[locale]/family/join` | ~12 | Linked from QR invites |
| `/[locale]/ref/[code]` | ~10 | Referral landing |

## Pricing / SignupForm — extra notes

These are client components using `useTranslations()` (not `getTranslations`
which is server-only). The pattern is already wired in
`landing/app/[locale]/account/restore/RestoreClient.tsx` — mirror the
`"use client"` + `useTranslations("{Namespace}")` setup there.

## Estimated effort

Per page (one developer): 30–60 min to identify strings + 9 × ~10 min
to translate. Pricing alone is ~6h. Full landing locales is ~25h.

## Trade-offs that justified the partial pass

- Quality matters: machine-translated copy on a privacy-first product
  looks careless and undermines the brand.
- Legal pages staying English is industry-standard (the localized
  privacy-policy still needs lawyer review per jurisdiction; English
  remains the authoritative version even when localized).
- Success / AccountRestore are the highest-impact conversion +
  retention pages, prioritised first.

## How to keep this honest

Once a page is localized, move its row from "Remaining" to "Done"
in this doc and bump the namespace count.

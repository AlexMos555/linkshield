# Operator-billed subscription — the landing (plan A.11 / A.12)

**Status: built, switched off.** `NEXT_PUBLIC_BILLING_ENABLED` is unset in the
Vercel project; with it unset the site renders exactly as before. The API side
is `docs/BILLING.md` (branch `feat/billing-core`); the legal drafts are
`docs/legal/`; the T2 one-pager is `docs/T2_ONEPAGER.md`.

## The flag and the settings

`NEXT_PUBLIC_*` is inlined at build time: changing any of these needs a
redeploy **without build cache** (the same lesson as `NEXT_PUBLIC_APK_URL`).
Parsing and defaults: `landing/lib/billing.ts`; the env binding:
`landing/lib/billing-config.ts`. Names mirror the API's `BILLING_*` settings so
the server and the site can be configured from one sheet.

| Env | Default | Meaning |
|---|---|---|
| `NEXT_PUBLIC_BILLING_ENABLED` | unset (off) | `1` / `true` / `yes` / `on` switches everything below on |
| `NEXT_PUBLIC_BILLING_PRICE_SOLO_RUB` / `_FAMILY3_RUB` / `_FAMILY5_RUB` | 99 / 270 / 399 | monthly prices; whole rubles, a malformed value falls back to the default |
| `NEXT_PUBLIC_BILLING_TRIAL_DAYS` / `NEXT_PUBLIC_BILLING_GRACE_DAYS` | 14 / 7 | the windows the copy pluralises on |
| `NEXT_PUBLIC_BILLING_LAPSE_POLICY` | `basic` | `basic` (list blocking continues, weekly list, yellow shield) or `off`; picks the sentence in the FAQ, the cancel page, the terms |
| `NEXT_PUBLIC_BILLING_SELLER_NAME` / `_SELLER_INN` (12 digits) / `_SELLER_OGRNIP` (15 digits) | unset | the requisites block; until all three are well-formed the page says they are pending instead of printing blanks |
| `NEXT_PUBLIC_BILLING_STOP_NUMBER` | unset | 4–6 digit short number for SMS «СТОП»; until set the cancel page says the number is pending |
| `NEXT_PUBLIC_SUPPORT_PHONE` | unset | E.164 (`+7…`), shown on the pricing page when set |
| `NEXT_PUBLIC_SUPPORT_EMAIL_LIVE` | unset | existing flag — the address appears once the mailbox works |

## What the flag changes (Russian visitors only)

"Russian visitor" is `lib/paid-plans.ts`: the `ru` locale, or a known `RU`
country (edge geo header / `?cc=`). Everyone else keeps the Stripe plans and is
untouched by the flag. `pricingVariant()` names the three outcomes:
`stripe` / `free` (today) / `operator` (flag on).

| Surface | Flag off (today) | Flag on |
|---|---|---|
| `/pricing` | `FreePricing` (free-only, no prices) | `OperatorPricing`: badge, trial note, three plan cards (price per month, per phone), what is included, how it works, FAQ (auto-charge, cancel, no money, Wi-Fi/other operator, who sees the number, refunds), requisites block, support block, links to `/cancel`, `/terms`, `/privacy-policy`; Product/FAQ JSON-LD in RUB |
| `/cancel` | 404 (localized) | cancel + refund page: four channels (app, SMS «СТОП», support, operator), what follows, refunds, support |
| `/terms` | section 4 "Платные тарифы" (no paid plans in Russia, Stripe elsewhere) | that section is replaced **in place** (by id `payments`) by `terms.billing.section` + the lapse-policy sentence; numbering and every other section unchanged |
| `/privacy-policy` | section 12 "Оплата" | replaced in place by `privacy_policy.billing.section` (phone number, separate database in Russia, who else sees it, retention; Stripe for other countries) |
| `/` (home) teaser | "Защита бесплатна … Платных тарифов в России сейчас нет", no plans link | "Подписка со счёта телефона", trial + "от 99 ₽ в месяц", link to `/pricing` |
| `sitemap.xml` | no `/cancel` | `/cancel` in all languages |

Nothing else changes. In particular the existing strings — including every
"blocking stays free" sentence — are untouched in the source; the swapped
sections are simply not rendered for Russian visitors while the flag is on.
Grandfathering of pre-launch installs is the founder's open decision.

## Strings

All in `packages/i18n-strings/src/<locale>.json`, ten languages, Russian
first; regenerate with `python3 scripts/build-i18n.py`:

- `landing.billing.*` → `Billing` (server-only namespace)
- `landing.cancel.*` → `Cancel` (server-only)
- `landing.terms.billing.{section, lapse_basic, lapse_off}`
- `landing.privacy_policy.billing.section`
- `landing.pricing_teaser.operator.{heading, body, plans_link}`
- `id: "payments"` added to the existing payment section of the terms and the policy (text untouched)

Numbers never live in the strings: prices and windows are ICU arguments
(`{solo}`, `{family3}`, `{family5}`, `{days, plural, …}`, `{grace, plural, …}`,
`{lapse}`), prices passed as text so no locale re-digits them.

## Guards

- `scripts/check-landing-claims.py` — new rules for the billing scopes: no
  "free" in any language (the trial is "без оплаты"), no hand-written
  `99/270/399 ₽`, no Stripe or dollar prices on the selling pages.
  `--billing-on` is the pre-flip review: it applies the "free" rules to every
  string a paying Russian visitor still sees (hero, features, FAQ, Android
  page, DNS page, check page, terms section 3 …) and lists what to re-word or
  knowingly keep. Advisory; about 27 findings per locale today.
- `scripts/test-landing-honesty.mjs` — table tests for `lib/billing.ts`
  (defaults, env parsing, variant, requisites, STOP number, `replaceSection`),
  and for the strings: every billing key in every language with English's ICU
  arguments, the `billing`/`payments` section ids, both lapse sentences, no
  hard-coded price; `Billing`/`Cancel` stay out of the client bundle.
- `landing/e2e/billing.spec.ts` — both flag states; each half skips when the
  other is live. `.github/workflows/e2e-landing.yml` builds and runs the
  landing twice (`billing: [off, on]`).

## Before the founder flips the flag

1. Set the env in Vercel: the flag, the prices and windows if they differ from
   the defaults, the lapse policy, the three requisites, the STOP number, the
   support phone; `NEXT_PUBLIC_SUPPORT_EMAIL_LIVE=1` once the mailbox works.
2. Publish the offer (`docs/legal/OFFER_RU.md` after the lawyer) and link it
   from the pricing page and the app's confirmation screen — not wired yet.
3. Run `python3 scripts/check-landing-claims.py --billing-on` and re-word the
   remaining "free" copy on the Russian pages (hero, features, FAQ, `/android`,
   `/dns`, `/check`, terms section 3, Android OG tags) or decide to keep each.
4. Redeploy without build cache; open `/ru/pricing`, `/ru/cancel`, `/ru/terms`,
   `/ru/privacy-policy`, `/ru` from a phone on a Russian SIM.

## Not in this PR

- The cancel-by-number web form (`POST /billing/v1/cancel-by-phone`): the
  billing host and its CSP origin do not exist yet; the cancel page lists the
  other channels and says the SMS number is pending.
- An `/offer` page: the offer is a draft; publishing a draft behind a flag the
  founder can flip risks shipping it unreviewed.
- Prices from `GET /billing/v1/plans` instead of env: env keeps the page
  static and the flag state reproducible in CI; revisit when the billing host
  is live.

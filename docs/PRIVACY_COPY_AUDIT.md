# Privacy-copy honesty audit (2026-07-12) — ready for your sign-off

Everything below is **code-grounded**. This session already fixed the landing hero,
the testimonial, and 4 landing claims (commits `eb756da`, `82a3d3a`). This doc covers
the **remaining** "never leaves your device" overclaims, plus a data-retention check so
the wording is provably true. I did **not** rewrite these myself — the marketing voice
is yours; approve/adjust the suggested wording and I'll apply it across all 10 locales.

## What the backend ACTUALLY stores at rest (verified)

From `supabase/migrations/*` + `api/routers/public.py`:

| Stored | Detail |
|---|---|
| `users`, `subscriptions` | email + subscription status |
| `user_settings` | skill level, font scale, voice-alert prefs |
| `devices` | a per-install **random** UUID (not hardware-derived) |
| `families`, `family_members`, `family_alerts` | Family Hub — **alert bodies are E2E-encrypted** (server stores ciphertext) |
| `feedback_reports` | domains a user explicitly reported as wrong |
| `audit_log` | account actions (pin change, org invites) — not browsing |
| `weekly_aggregates`, `rate_limits`, `watchtower_alerts` | anonymous aggregates / ops |

**Crucially: there is NO per-user browsing-history table.** The `/public/check` cache is
**domain-only, shared across all users, 24h TTL** — it is not linked to a user. So
"we don't keep a history of the sites you visit" is **true**. But "servers store *only*
email and subscription" is **false** (see above).

## The remaining claims to fix

| # | Location (i18n key) | Current (FALSE/overclaim) | Why it's wrong | Suggested honest wording |
|---|---|---|---|---|
| 1 | `extension.common.trust_footer.text` (10 locales) | "Your data never leaves this device" | Domains egress to `/public/check`; webmail body to `/email/analyze` | "We check domains — never your full URLs or page content" |
| 2 | `extension.welcome.trust_footer.text` (10 locales) | "Free forever for blocking. Your data never leaves this device." | same | "Free forever for blocking. We only check domain names — never your full browsing." |
| 3 | `email.welcome.body_p2.text` | "Your browsing data never leaves your device. We only check domain names…" | self-contradictory | "We only check domain names — never your full URLs or page content — and we don't keep a history of the sites you visit." |
| 4 | `landing.faq.items[0].a` | "…Our servers store **only** your email and subscription status…" | also stores settings, device UUID, family (encrypted), feedback, audit, aggregates | "Our servers store your account and settings, your family group (alerts end-to-end encrypted), and anonymous aggregates — **not a history of the sites you visit.**" |
| 5 | `extension.welcome.step2_desc.text` | "We only check domain names. Your browsing history never leaves this device." | **Defensible / accurate** — keep (optionally tighten) | (no change needed) |

## How to apply
Say the word (approve as-is, or tweak the wording) and I'll:
1. Edit the source in `packages/i18n-strings/src/` (EN) for claims 1-4.
2. Translate 1-3 natively into es/hi/pt/ru/ar/fr/de/it/id (claim 4 is landing-only,
   EN-fallback in the other locales — one edit covers all).
3. Rebuild i18n + verify no drift + commit.

This closes the last honesty gap before the Chrome Web Store submission (reviewers
compare onboarding copy to actual behaviour).

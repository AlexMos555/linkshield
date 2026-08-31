# Cleanway — Tele2 Go-Live Checklist

Ordered path from "code is ready" to "a Tele2 subscriber installs and is
protected, with an account that syncs." **[F]** = founder-only, **[C]** = Claude.
Status 2026-08-31. Launch model: free protection + account/sync, Android-only, RU-first.

---

## ✅ Done (Claude, 2026-08-31 autonomous pass)

- **PR opened** → https://github.com/AlexMos555/linkshield/pull/39 (74 commits, main ← feat/shield-checklist-phase1)
- **Release keystore generated** — `~/cleanway-release/` (RSA 4096, valid to 2054,
  `CN=Cleanway`). ⚠️ **Founder must back this up** — see "Founder must do" #1.
- **Supabase anon key wired** — `mobile/.env` (git-ignored), verified live against
  the project (HTTP 200). `isSupabaseConfigured()` now true ⇒ sign-in works in builds.
- **Supabase email templates fixed** — `{{ .Token }}` added to Magic Link + Confirm
  Signup via the Management API, so the 6-digit code actually reaches users. The
  `{{ .ConfirmationURL }}` link is preserved for the web magic-link flow. RU-first
  copy, EN fallback below the divider. (Backup of the previous config kept.)
- Everything from the build sprint: `/android` funnel page, `/support`, in-app
  update check, release-signing plugin + versionCode 1.0.0/100, honest store
  listing + RuStore runbook, link-guard home card + no-browser loop fix,
  passwordless email-OTP sign-in, keystore git-ignore fix.

## 🚨 Blockers found on 2026-08-31 that only the founder can clear

### 1. Supabase email is capped at **2 emails/hour** — the account launch is dead on arrival
`rate_limit_email_sent: 2`, built-in Supabase SMTP, no custom `smtp_host`. Two
Tele2 users per hour could receive a login code. **Fix:** point Supabase at a real
SMTP provider. The backend already uses **Resend** (`RESEND_API_KEY`, set in
Railway) — reuse it. *Give Claude that key and the Supabase SMTP config is one
Management-API call.* Without this, launch with accounts is not possible.

### 2. `support@cleanway.ai` cannot receive mail — **no MX records**
`dig MX cleanway.ai` → empty; SPF is `v=spf1 -all` and DMARC `p=reject` (a
deliberate "this domain sends no mail" lockdown). The store listings declare this
address, so today it bounces. **Fix:** add mail hosting (Yandex 360 / Google
Workspace / a forwarder) and its MX records. If you later send mail *from*
@cleanway.ai, the provider must also be added to SPF or DMARC `p=reject` will
bounce it.

---

## Founder must do (ordered)

1. **Back up the keystore — today.** `~/cleanway-release/cleanway-release.jks` +
   `keystore.properties` (the password is inside). Password manager **+ one offline
   copy**. Losing it = every user reinstalls forever.
   *Optional, costs nothing right now (zero installed users): regenerate it
   yourself so the key never passed through an AI transcript — command in
   docs/RUSTORE_SUBMISSION.md §1, then re-run the build.*
2. **Merge PR #39** → publishes `/android`, `/support`, `/api/v1/mobile/version`
   (all 404 in prod until then). Railway + Vercel deploy from `main`.
3. **Real SMTP** (blocker #1) — hand Claude the Resend key, or configure it in the
   Supabase dashboard: Project Settings → Auth → SMTP.
4. **Mail for `support@`** (blocker #2).
5. **Host the APK** — the signed APK is built. Publish it (a GitHub Release on
   this public repo works — Claude can do it on request) and set
   `NEXT_PUBLIC_APK_URL` in Vercel. ⚠️ **Then trigger a redeploy**: Next inlines
   every `NEXT_PUBLIC_*` value at build time and the page is statically
   prerendered per locale, so setting the variable alone changes nothing until
   the site is rebuilt. *Vercel needs your login; Claude has no token.*
6. **RuStore developer account** (ЕСИА, физлицо OK), then submit: listing copy in
   `mobile/STORE_LISTING.md`, data-safety + VpnService answers in
   `docs/RUSTORE_SUBMISSION.md` §3–4. **RuStore only** — Google Play now requires
   targetSdk 36 (we ship 34, an Expo SDK 52 constraint), so Play is a post-launch
   project, not a parallel track. RuStore's floor is 28, so our build qualifies.
7. **Plug in the Samsung and authorize USB debugging** so the end-to-end run can be
   verified on a real device (no device is currently attached).

## Verify together (needs a device + your accounts)
- Install → shield turns on → blocks a known-bad domain.
- Email → code arrives → signed in → a setting changed on the web shows in the app.
- Bump versionCode, rebuild, reinstall over the top (proves updates work).

## Out of scope for this launch
iOS (no Org Apple account) · web→app deep-link token handoff (the shared email +
shared Supabase project is the unifier) · mobile IAP/billing.

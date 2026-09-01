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

### 3. Anyone can burn the login-email budget — no CAPTCHA on the auth endpoint
`POST /auth/v1/otp` is public by design and needs only the anon key, which ships
inside the APK. With no CAPTCHA configured, a script can request codes in a loop
and exhaust the project's email quota, so real users stop receiving login codes.
It is mostly theoretical at 2 emails/hour (blocker #1 dwarfs it), but the moment
real SMTP is wired this becomes the cheapest way to deny sign-in to everyone —
and it costs money per message.

**Mobile client wiring: DONE, and inert until configured.** `sendEmailOtp()`
takes an optional captcha token, the sign-in screen fetches one when
`EXPO_PUBLIC_CAPTCHA_URL` is set, and `cleanway://captcha-return` receives it
(`mobile/src/services/captcha.ts`, `mobile/app/captcha-return.tsx`). With the
variable unset — today — the flow is byte-identical to before: no captcha, no
browser hop, no extra request, the same OTP body on the wire.

**Still to do, in this order:**
1. Create an hCaptcha or Turnstile account and get a sitekey (founder-gated —
   this is the only reason the blocker is still open).
2. Build the hosted challenge page (`landing/app/auth/captcha`) that renders the
   widget and redirects to `cleanway://captcha-return?nonce=…&token=…`, and add
   the provider's origins to the CSP in `landing/next.config.ts`
   (`script-src` / `frame-src` / `connect-src`). NOT yet built — it needs the
   provider decision from step 1.
3. Pass `options.captchaToken` in `landing/app/[locale]/signup/SignupForm.tsx`.
   **This is not optional.** The Supabase switch is PROJECT-WIDE, not
   per-client: turning it on breaks web sign-up at the same instant it protects
   mobile.
4. Set `EXPO_PUBLIC_CAPTCHA_URL` and ship a new APK — `EXPO_PUBLIC_*` is inlined
   at build time, so already-installed builds send no token and cannot sign in
   until they update (the app names that case explicitly rather than showing a
   generic error).
5. Only then enable it in Supabase (Authentication → Settings → Bot and abuse
   protection).

---

## CI: all 14 checks green (2026-09-01) — including npm-audit and Vercel

The landing audit is at **0 vulnerabilities** and the Vercel preview deploys,
simultaneously, without weakening any check. What it took, for the record:

- The root cause of every failed `overrides` attempt: npm on this machine never
  truly resolved — with node_modules present it reconstructs the lockfile from
  `node_modules/.package-lock.json`, so "delete the lock and reinstall" was a
  no-op. A sandbox with manifests only (no lock, no node_modules) forces a real
  network resolve, and there the overrides simply work.
- The fix that survived: **next 15.5.25** (patch release — the first to allow
  the patched sharp 0.35.x) + a global **postcss ^8.5.23 override** (dedupes
  away the vulnerable copy Next bundles) + `npm update nanoid fast-uri`.
- **react-email 6 broke the Vercel deploy** (green everywhere else, including an
  identical fresh-install-and-build on Ubuntu). It went back to 3.x; the global
  next override covers its nested copy, so the audit stays clean regardless.
  If anyone bumps react-email again, watch the Vercel check specifically.
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
   Supabase dashboard: Project Settings → Auth → SMTP. **Turn on CAPTCHA in the
   same pass** (blocker #3): once sending actually works, an unprotected OTP
   endpoint is the cheapest way for anyone to deny sign-in to every user.
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

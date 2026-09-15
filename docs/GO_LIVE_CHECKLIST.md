# Cleanway — Tele2 Go-Live Checklist

Ordered path from "code is ready" to "a Tele2 subscriber installs and is
protected, with an account that syncs." **[F]** = founder-only, **[C]** = Claude.
Status 2026-09-13 (previous pass 2026-08-31). Launch model: free protection + account/sync, Android-only, RU-first.

---

## ✅ Done

### Since 2026-09-01

- **PR #39 merged 2026-09-01** — https://github.com/AlexMos555/linkshield/pull/39 → `main`
  as `e240442` (11 checks passed, 3 skipped by path filter). Railway + Vercel
  deployed from `main`: `/android`, `/support`, `/api/v1/mobile/version` are live.
- **Release v1.0.0 published on GitHub 2026-09-01** — the only asset is
  `cleanway-1.0.0-100-arm.apk` (an earlier `…-1.0.0-arm.apk` name that circulated
  in notes is wrong and 404s). Stable URL:
  `https://github.com/AlexMos555/linkshield/releases/download/v1.0.0/cleanway-1.0.0-100-arm.apk`
- **Supabase OTP length fixed 2026-09-13** — `mailer_otp_length` was **8** while the
  app accepts exactly **6** digits (`OTP_CODE_LEN = 6` in `mobile/src/services/auth.ts`,
  `maxLength` on the code input), so no emailed code could ever be typed in. Set to 6.

### 2026-08-31 autonomous pass

- **PR opened** (74 commits, main ← feat/shield-checklist-phase1) — merged since, see above.
- **Release keystore generated** (RSA 4096, valid to 2054, `CN=Cleanway`). It lives
  in the founder's backup (password manager + one offline copy) and in the build
  sandbox's `android/` folder — never in the repo. See "Founder must do" #1.
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

**Status 2026-09-13: still open** — SMTP is still Supabase's built-in sender, Resend
is not wired. What the DNS side needs, so it is not rediscovered: the zone is edited
in **Squarespace Domains** (not Google Cloud DNS, and not "the registrar" panel).
Resend must verify the **apex** `cleanway.ai` (DMARC is `adkim=s`, strict DKIM
alignment, so a subdomain-only verification would fail DMARC); its records go on
`send.cleanway.ai` (return-path MX + SPF TXT) and `resend._domainkey` (DKIM). The
apex SPF `v=spf1 -all` can stay as it is. The OTP-length mismatch (8 sent vs 6
accepted) that would have made every delivered code useless is already fixed (see Done).

### 2. `support@cleanway.ai` cannot receive mail — **no MX records**
`dig MX cleanway.ai` → empty; SPF is `v=spf1 -all` and DMARC `p=reject` (a
deliberate "this domain sends no mail" lockdown). The store listings declare this
address, so today it bounces. **Fix:** add mail hosting (Yandex 360 / Google
Workspace / a forwarder) and its MX records. If you later send mail *from*
@cleanway.ai, the provider must also be added to SPF or DMARC `p=reject` will
bounce it.

**Status 2026-09-13: still open** — `dig MX cleanway.ai` is still empty, so
`support@`, `privacy@`, `legal@` and `business@` all bounce (the landing, the store
listing and the privacy policy all name them). Records go in Squarespace Domains.

### 3. Anyone can burn the login-email budget — no CAPTCHA on the auth endpoint
`POST /auth/v1/otp` is public by design and needs only the anon key, which ships
inside the APK. With no CAPTCHA configured, a script can request codes in a loop
and exhaust the project's email quota, so real users stop receiving login codes.
It is mostly theoretical at 2 emails/hour (blocker #1 dwarfs it), but the moment
real SMTP is wired this becomes the cheapest way to deny sign-in to everyone —
and it costs money per message.

**Mobile client wiring: DONE, shipped inert in v1.0.0.** `sendEmailOtp()`
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
   (`script-src` / `frame-src` / `connect-src`). In progress as of 2026-09-13
   (separate change); it still needs the provider sitekey from step 1 to go live.
3. Pass `options.captchaToken` in `landing/app/[locale]/signup/SignupForm.tsx`
   (in progress with step 2). **This is not optional.** The Supabase switch is PROJECT-WIDE, not
   per-client: turning it on breaks web sign-up at the same instant it protects
   mobile.
4. Set `EXPO_PUBLIC_CAPTCHA_URL` and ship a new APK — `EXPO_PUBLIC_*` is inlined
   at build time, so already-installed builds send no token and cannot sign in
   until they update (the app names that case explicitly rather than showing a
   generic error).
5. Only then enable it in Supabase (Authentication → Settings → Bot and abuse
   protection). **Enable it LAST** — after the web challenge page is deployed AND
   the new APK is the one people download; the toggle is project-wide, so flipping
   it earlier locks out web sign-up and every v1.0.0 install at once.

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

1. **Keep the keystore alive — both copies.** `cleanway-release.jks` +
   `keystore.properties` (the password is inside) live in your backup (password
   manager **+ one offline copy**) and in the build sandbox's `android/` folder.
   They are not in the repo and no longer sit in a home-folder path. Losing the key
   = every user reinstalls forever.
   *Regenerating is **no longer free**: the signed v1.0.0 APK has been downloaded,
   so a new key means pulling the GitHub release and telling every installed user
   to uninstall/reinstall. The "zero installed users" window closed on 2026-09-01.*
   ⚠️ **Never run `expo prebuild --clean` in the sandbox** — it wipes `android/`,
   and a rebuild without `android/keystore.properties` falls back to **debug**
   signing (`mobile/plugins/withReleaseSigning.js` prints a Gradle warning, but the
   build still ends in BUILD SUCCESSFUL). A debug-signed 1.0.1 will not install
   over the release-signed 1.0.0.
2. ✅ **Merge PR #39 — DONE 2026-09-01** (`e240442`; 11 checks passed, 3 skipped by
   path filter). `/android`, `/support`, `/api/v1/mobile/version` are live in prod.
3. **Real SMTP** (blocker #1) — hand Claude the Resend key, or configure it in the
   Supabase dashboard: Project Settings → Auth → SMTP. Verify the apex domain in
   Resend first (records in Squarespace Domains, see blocker #1). **Do not flip the
   CAPTCHA toggle in the same pass** (blocker #3): it is project-wide, so it goes on
   LAST — after the web challenge page ships and the new APK is what people
   download. Until then, keep the send budget in mind: once real SMTP works, an
   unprotected OTP endpoint is the cheapest way to deny sign-in to everyone.
4. **Mail for `support@`** (blocker #2) — still no MX on 2026-09-13; `privacy@`,
   `legal@`, `business@` are equally dead. Records go in Squarespace Domains.
5. ✅ **Host the APK — DONE 2026-09-01**: GitHub Release `v1.0.0`, asset
   `cleanway-1.0.0-100-arm.apk`. ⏳ **Still open — wire the URL (this is now your
   first move):** `/ru/android` shows «скоро» because `NEXT_PUBLIC_APK_URL` is
   unset in Vercel. Set exactly:

   ```
   NEXT_PUBLIC_APK_URL=https://github.com/AlexMos555/linkshield/releases/download/v1.0.0/cleanway-1.0.0-100-arm.apk
   ```

   then **Deployments → Redeploy → untick "Use existing Build Cache"**. Next
   inlines every `NEXT_PUBLIC_*` value at build time and the page is statically
   prerendered per locale, so setting the variable alone changes nothing, and a
   cached rebuild keeps the old «скоро». *Vercel needs your login; Claude has no
   token.* Check the result from a phone, not the laptop.
   **Railway** has `MOBILE_APK_URL` unset too, but that only matters for the
   *next* release: the app compares version **names** (`mobile/src/lib/update-check.ts`)
   and the server defaults are already `1.0.0` / `100`, so v1.0.0 installs see no
   spurious update. For a 1.0.1 release set all three in Railway:
   `MOBILE_LATEST_VERSION_NAME=1.0.1`, `MOBILE_LATEST_VERSION_CODE=101`,
   `MOBILE_APK_URL=<the new release asset URL>`.
6. **RuStore developer account** (ЕСИА, физлицо OK), then submit: listing copy in
   `mobile/STORE_LISTING.md`, data-safety + VpnService answers in
   `docs/RUSTORE_SUBMISSION.md` §3–4. **RuStore only** — Google Play now requires
   targetSdk 36 (we ship 34, an Expo SDK 52 constraint), so Play is a post-launch
   project, not a parallel track. RuStore's floor is 28, so our build qualifies.
7. **Plug in the Samsung and authorize USB debugging** for the end-to-end run. The
   A16 was last tested 2026-08-25 via `adb` with a **debug** build. Never tested:
   the release APK through the browser install path, the Play Protect + Samsung
   **Auto Blocker** prompts, an update installed over the top, an emailed login
   code, and mobile data (all runs so far were on Wi-Fi).

## Verify together (needs a device + your accounts)
- On the A16, over **mobile data**: open `/ru/android` in the phone browser →
  download `cleanway-1.0.0-100-arm.apk` → get past Samsung **Auto Blocker** (One UI
  6+ blocks sideloads outright until it is switched off in Settings → Security and
  privacy → Auto Blocker), the unknown-sources prompt and Play Protect → install.
  Note every prompt's exact wording for the `/android` walkthrough.
- Install → shield turns on → blocks a known-bad domain; `gosuslugi.ru` resolves.
- Email → 6-digit code arrives → signed in → a setting changed on the web shows in
  the app.
- Bump versionCode, rebuild, reinstall over the top (proves updates work — and
  that the build is still release-signed, see "Founder must do" #1).

## Launch-night ops (not blocking the first small cohort)
- **Monitor:** probe `GET /health/deep` (a HEAD returns 405, and `/health` is always
  200, so neither proves anything) plus a GET on `/api/v1/blocklist/dns`. The
  `dns-canary` GitHub workflow already runs every 2–6 h; its failures so far were
  noise (being de-noised separately) — treat it as a second opinion, not the pager.
- **Cloudflare:** none yet. The v1.0.0 APK hard-codes
  `https://api.cleanway.ai/api/v1/blocklist/dns` and does not follow redirects, so a
  CDN on a *different* hostname only helps phones on APK 1.0.1+; fronting
  `api.cleanway.ai` itself works for v1.0.0. Fine for the first cohort — the
  blocklist GET no longer 429s a CGNAT gateway (only full sends are metered, with a
  high ceiling).

## Out of scope for this launch
iOS (no Org Apple account) · web→app deep-link token handoff (the shared email +
shared Supabase project is the unifier) · mobile IAP/billing.

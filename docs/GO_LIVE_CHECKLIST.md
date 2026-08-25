# Cleanway — Tele2 Go-Live Checklist

The ordered path from "code is ready" to "a Tele2 subscriber installs and is
protected, with an account that syncs." Owner tags: **[F]** founder-only,
**[C]** Claude. Status as of 2026-08-25. Launch model: **free protection +
account/sync**, Android-only, RU-first.

Everything Claude can build is **done and on branch `feat/shield-checklist-phase1`**
(backend 1084 tests green). The remaining critical path is almost entirely
founder actions — they gate the launch.

---

## Phase 0 — flip the switch (nothing is live until this)

1. **[F] Merge `feat/shield-checklist-phase1` → `main`.** Railway (API) and
   Vercel (landing) deploy from `main`, so until this merge the `/android` page,
   `GET /api/v1/mobile/version`, the honest listing, and every fix on the branch
   are NOT in production. *(Claude can prepare the PR on request; merging/deploy
   is the founder's call.)*
2. **[C] After merge:** verify prod — `/android` renders, `GET /api/v1/mobile/version`
   returns 200, blocklist still 200 under load. *(~5 min, once merged.)*

## Phase 1 — signing identity (the app's permanent identity)

3. **[F] Generate the release keystore** (FIRST hardware move):
   `keytool -genkeypair -v -keystore cleanway-release.jks -alias cleanway -keyalg RSA -keysize 4096 -validity 10000 -storetype PKCS12`
   Back it up in a password manager **+ one offline copy**. Losing it = every
   user reinstalls forever. Claude must never hold it.
4. **[F] Create `mobile/android/keystore.properties`** (git-ignored — verify with
   `git check-ignore`). Recipe: docs/RUSTORE_SUBMISSION.md §1. The signing plugin
   picks it up on the next prebuild automatically.

## Phase 2 — auth + sync (the account/sync launch model)

5. **[F] Put the public anon key in the build** — `EXPO_PUBLIC_SUPABASE_ANON_KEY`
   in `mobile/.env` (local build) and eas.json/EAS (cloud). Public, RLS-gated,
   safe. Without it, sign-in is dead. docs/MOBILE_AUTH.md §1.
6. **[F] Add `{{ .Token }}` to the Supabase email templates** (Magic Link +
   Confirm signup) so the 6-digit code actually reaches users; enable the Email
   provider + a real SMTP for Tele2 volume. docs/MOBILE_AUTH.md §2–3.
7. **[F+C] Verify auth+sync end-to-end on a device:** email → code → signed in →
   a setting changed on the web appears in the app. *(Founder provides the built
   app + a phone; Claude helps debug.)*

## Phase 3 — build + host the APK

8. **[F] Build the signed release** — `./gradlew assembleRelease -PreactNativeArchitectures=arm64-v8a`
   (~42 MB direct APK) and `bundleRelease` (AAB for stores). Confirm it's
   release-signed (not debug) and updates over itself. docs/RUSTORE_SUBMISSION.md §2.
9. **[F] Host the signed APK** (GitHub Release or R2 + CDN) and set
   `NEXT_PUBLIC_APK_URL` in Vercel → the `/android` download button goes live.
10. **[F] Confirm `support@cleanway.ai`** receives mail (store listings require a
    working support address).

## Phase 4 — store channel (better path for non-technical users)

11. **[F] Register the RuStore developer account** (ЕСИА, физлицо OK). Google Play
    secondary. docs/RUSTORE_SUBMISSION.md.
12. **[F] Submit to RuStore** — upload the AAB, paste the honest RU listing
    (`mobile/STORE_LISTING.md`), the Data-Safety answers and the VpnService
    justification (both in docs/RUSTORE_SUBMISSION.md §3–4).

## Phase 5 — pre-blast hardening (before a large Tele2 send)

13. **[C] Full Cloudflare in front of the blocklist** — the no-429 patch is
    enough for a small cohort; CDN before any large blast. *(Claude can spec;
    needs founder's CF/DNS.)*
14. **[F] Stand up an uptime/latency monitor** on `/health` + the blocklist path,
    with a push channel for launch week.
15. **[F] Tele2 SMS copy sign-off** — phishing framing, never "VPN"; cohort size;
    send window.

---

## What's already done (Claude side) — reference

- ✅ `/android` funnel page + install-urls flip · ✅ honest RU store listing +
  RuStore runbook + support page
- ✅ Release-signing config plugin + explicit versionCode (1.0.0/100, matches the
  update server) · ✅ keystore + native dirs git-ignored
- ✅ `GET /api/v1/mobile/version` + in-app update banner · ✅ blocklist no-429 (CGNAT-safe)
- ✅ Link-guard home shield card + no-browser loop fix · ✅ notification locale fix
- ✅ Passwordless email-OTP sign-in (unified with web, reviewed + hardened) + anon-key plumbing
- ✅ Family/settings sync already reads the same session the OTP flow produces — no rewire needed

## Out of scope for this launch
- iOS (no Org Apple account) · web→app deep-link token handoff (fragile; the
  shared email + shared Supabase project is the unifier) · mobile IAP/billing.

---

### The single highest-leverage next step
**Merge to `main` (step 1) + generate the keystore (step 3).** Nothing downstream
goes live or signs correctly until those two exist — and they're both yours.

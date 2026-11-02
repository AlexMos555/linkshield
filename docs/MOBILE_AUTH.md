# Mobile auth — passwordless email code (unified with the web)

The app signs in with a **one-time code emailed to the user** (Supabase GoTrue
email OTP; 6 digits today, and from 1.0.5 any 6–8 digit code is accepted), not a password. It talks to the **same Supabase project** as the
website, so the **same email is the same account** on both surfaces and
settings/family sync just works — no fragile web→app token handoff, nothing to
remember. An account is entirely optional: "continue without an account" keeps
the free on-device protection working with zero sign-in.

Flow: `mobile/app/auth.tsx` → `sendEmailOtp(email)` (`POST /auth/v1/otp`,
`create_user:true`, via `src/utils/otp-request.ts` — captcha on demand, below) → user types the code → `verifyEmailOtp(email, code)`
(`POST /auth/v1/verify`, `type:"email"`) → session in SecureStore.

---

## Founder setup (3 things — all one-time)

### 1. Put the public client keys in the build
Mobile auth is dead until a Supabase client key reaches the bundle:
`EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY` (preferred) or the legacy
`EXPO_PUBLIC_SUPABASE_ANON_KEY`. Release builds carry **both**.

- **Local builds from the mirror** (the gradle APKs / AAB and the iPhone
  archive — `docs/RUSTORE_SUBMISSION.md` §2, `docs/IOS.md` §1.1): `mobile/.env`
  (copy `mobile/.env.example`, git-ignored) with both keys; the mirror's rsync
  takes it along and Metro inlines every `EXPO_PUBLIC_*` var at build time.
  Both recipes check the built bundle for the publishable key before upload.
  `mobile/.env` carries it since 2026-10-25.
- **EAS cloud build:** add the same vars as EAS project environment variables.

**From 1.0.5 (and on the web): the publishable key is preferred.** Set
`EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY` (EAS environment variable, or
`mobile/.env`) and, for the site, `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` in
Vercel — the `sb_publishable_…` value from Supabase dashboard → Project
Settings → API Keys (or the Management API, `GET
https://api.supabase.com/v1/projects/bpyqgzzclsbfvxthyfsf/api-keys` with
`SUPABASE_ACCESS_TOKEN` from the root `.env`: the entry of type `publishable`).
When both are set the app sends the publishable key
(`resolveSupabaseClientKey` in `mobile/src/utils/supabase-key.ts`, pinned in
`mobile/scripts/test-auth-error-key.mjs`; the site: `landing/lib/supabase/public-key.ts`);
the anon key stays as the fallback. The extension gets the key from the site's
connect page and already accepts `sb_publishable_…`. Nothing decodes the key
as a JWT to accept it; a `sb_secret_…` key or a `service_role` JWT is refused in
either slot. Order to retire the legacy HS256 JWT secret:
1. ★ set both publishable variables (EAS environment variable and
   `mobile/.env` for the app, Vercel for the site), redeploy the site; every
   app build from then on carries the key — check each bundle before upload
   (`docs/IOS.md` §1.1, `docs/RUSTORE_SUBMISSION.md` §2);
2. wait until every build **without** the publishable key is negligible —
   every build up to 1.0.6 made before 2026-10-25 (`mobile/.env` had no
   publishable key until then): iPhone 1.0.4 (3), 1.0.5 (4), 1.0.6 (5) and
   (6); Android 1.0.3 (103), and any 1.0.6 (107) file built before that date
   (not to be uploaded: they are rebuilt, `docs/RUSTORE_SUBMISSION.md` §2).
   Their only key is the anon JWT. Once it is disabled Supabase answers their
   every sign-in call with 401, and since #273 a 401 on the token refresh
   signs the person out (`refreshFailure`,
   `mobile/src/utils/account-session.ts`): every signed-in user of a 1.0.6
   build is signed out and cannot sign back in (older builds just fail every
   account call). The first builds with the key are the next iPhone build
   after 1.0.6 (6) and the Android 1.0.6 (107) files rebuilt from 2026-10-25
   on; if 1.0.6 (6) is the version App Review approves, it stays in this count
   until its users update;
3. ★ Supabase → API Keys → disable the legacy anon/service_role keys, then
   revoke the legacy JWT secret. The API's own server-side Supabase calls
   (`api/`, `SUPABASE_ANON_KEY` / service key) must be moved to the new keys
   before this step.

The legacy key is the **anon / public** key (Supabase dashboard → Project Settings →
API → Project API keys → `anon` `public`). It is safe to embed — every web page
already ships it and all access is gated by Row-Level Security. It is **not**
the `service_role` key; never put that in the app.

### 2. ⚠️ Make the email carry the CODE, not just a link
By default Supabase's email templates include only a magic **link**
(`{{ .ConfirmationURL }}`). The in-app flow needs the **code**, so you
must add `{{ .Token }}` to the templates or users will get an email with no code
to type.

Supabase dashboard → **Authentication → Email Templates**, edit **Magic Link**
(and **Confirm signup**, since new users hit that path) to include the token,
e.g.:

```html
<h2>Ваш код входа в Cleanway</h2>
<p>Введите этот код в приложении:</p>
<p style="font-size:28px;letter-spacing:6px;font-weight:700">{{ .Token }}</p>
<p>Код действует ограниченное время. Если вы не запрашивали вход — просто
проигнорируйте это письмо.</p>
```

Keep it RU-first (the launch audience). You can leave the `{{ .ConfirmationURL }}`
link in too — the app ignores it and uses the code.

### 3. Enable the Email provider + confirm sender
Authentication → Providers → **Email** = enabled. Make sure a From address is
configured (Supabase's built-in SMTP is rate-limited; for launch volume wire a
real SMTP/provider so codes actually arrive). Test end-to-end on a device before
the Tele2 push: enter email → receive code → sign in → confirm a setting made on
the web appears in the app.

---

## Auth hardening: captcha and 8-digit codes — enablement order

Two Supabase Auth settings the audit recommends would **lock out every
installed 1.0.4** if flipped today:

| Setting | Today | Why 1.0.4 breaks |
|---|---|---|
| Captcha protection (Turnstile) | off | 1.0.4 sends no captcha token → `captcha_failed` on every code request |
| `mailer_otp_length` | 6 | 1.0.4 accepts exactly six digits (`/^\d{6}$/`) |

1.0.5 is ready for both:

- **Codes of 6–8 digits** are accepted by the app (`mobile/src/utils/otp-code.ts`)
  and by `/signup` (`landing/lib/signup-flow.ts`); the texts no longer say "6".
- **Captcha on demand.** Store builds carry
  `EXPO_PUBLIC_CAPTCHA_URL=https://cleanway.ai/auth/captcha` (`mobile/eas.json`).
  The code request still goes out WITHOUT a token; only if GoTrue answers
  `captcha_failed` does the app open that page (Turnstile), get the token back
  through `cleanway://captcha-return` (nonce-checked), and resend with
  `gotrue_meta_security.captcha_token` — the same field supabase-js fills from
  `options.captchaToken`. After that, resends in the session go captcha-first.
  While captcha is off, nobody sees anything and the request bytes are unchanged.
  `verifyOtp` needs no token.
- **iPhone: the challenge must open inside the app.** App Review 4.0 rejects a
  sign-in step that leaves the app for Safari, and once captcha is on every
  iPhone sign-in — the reviewer's included — goes through this page. 1.0.6
  (build 5) and later open it in an in-app sheet (ASWebAuthenticationSession,
  `mobile/modules/cleanway-safari`, no new dependency); the sheet catches the
  `cleanway://captcha-return` redirect itself, with the same nonce check.
  **1.0.5 build 4 and older still switch to Safari** (`Linking.openURL`).
  Android keeps the browser hop and the deep link (`app/captcha-return.tsx`).
- **Web:** `/signup` already passes the Turnstile token as
  `signInWithOtp({ options: { captchaToken } })` (`SignupForm.tsx`).

### Order (founder steps marked ★)

1. **Ship 1.0.6 everywhere** — App Store, Google Play, RuStore and the direct APK
   on cleanway.ai. On Android 1.0.6 (107) is the first published build that
   can solve the captcha (1.0.5 was not published there). Local gradle builds
   (direct APK / RuStore) read `mobile/.env`, not `eas.json`: add
   `EXPO_PUBLIC_CAPTCHA_URL` there too.
   **On iPhone that means 1.0.6 (build 5)** — the first build with
   the in-app sheet (above). Build 4 opens Safari, so it must not be the App
   Store build on the day captcha goes on: ship the next iOS build first, and
   in step 3 count build 4 together with 1.0.4 and older.
2. ★ **Turnstile sitekey on the web.** Cloudflare dashboard → Turnstile → add a
   widget for `cleanway.ai` (Managed). Put its **sitekey** in Vercel as
   `NEXT_PUBLIC_TURNSTILE_SITE_KEY` and redeploy. One widget serves both
   `/signup` and the app's challenge page (`/auth/captcha`, same hostname) —
   Supabase holds a single captcha secret, so they MUST be the same widget.
   Check: `/auth/captcha` no longer shows the "Turnstile test mode" notice.
   (As of 2026-10-14 the production build has no sitekey — test mode.)
3. **Wait for adoption.** Store consoles: the share of active installs on
   1.0.4 and older is what will be locked out. Pick a threshold (e.g. <5%);
   older builds show "update the app" on `captcha_failed`
   (`mobile.auth.err_captcha_update`), not a generic error.
4. ★ **Enable captcha in Supabase.** First update the App Store's App Privacy
   answers: on iPhone the challenge now opens inside the app, so what
   Turnstile sees can no longer be put down to the browser (`docs/IOS.md`
   §3.5). Then:
   Dashboard → Authentication → Attack
   Protection → Enable Captcha protection → provider **Turnstile** → the
   widget's **secret key** from step 2. Immediately test: web `/signup`, a
   1.0.6 Android phone and an iPhone on the build with the sheet (the
   challenge page should open once — on iPhone as a sheet over the app, never
   Safari — then the code arrives). Rollback = switch it off; nothing else to
   undo.
5. ★ **Later: 8-digit codes.** Once 1.0.4 and older are negligible, set
   `OTP_LENGTH = 8` in `scripts/supabase_mail.py` and apply it (or Dashboard →
   Authentication → Email → OTP length = 8). Then update the code-length range
   in `otp-code.ts` / `signup-flow.ts` only if you ever go beyond 8.

---

## Web ↔ app account model
- Web `/signup` is a passwordless magic-link (a Stripe-checkout gate). The app
  is passwordless email-OTP. Both create/authenticate the SAME Supabase user, so
  a person who signed up on either side signs into the app with the same email.
- There is intentionally **no** deep-link token handoff from the web into the
  app (it's fragile across email clients and PKCE contexts). The unifier is the
  shared email + shared Supabase project, verified by the code the user types.

## Store reviewers' account (a password for one address)
App Store, Google Play and RuStore reviewers cannot receive a code we email to
the account we give them. So `EXPO_PUBLIC_REVIEW_EMAILS` (comma-separated,
case-insensitive exact match after trim; set to `review@cleanway.ai` in the
`preview` / `production` profiles of `mobile/eas.json`, exported for local
Android builds; unset = off) makes the sign-in screen show a password field for
those addresses only, signing in with `signIn(email, password)` (captcha on
demand, like the code request) — `mobile/src/utils/review-login.ts`. Every
other address keeps the code flow byte for byte (pinned in
`mobile/scripts/test-auth-error-key.mjs`). The account and its password:
`scripts/create_review_account.py`, `docs/runbooks/app-review-account.md`.

## Notes for future work
- The old email+password functions (`signUp`/`sendPasswordResetEmail`) remain
  in `mobile/src/services/auth.ts` unused; `signIn` is used only by the
  reviewers' account above. Don't add a password field for anyone else — it
  re-splits web (passwordless) and app.
- CI should block a release where `isSupabaseConfigured()` would be false (empty
  URL/anon key) — a build that ships with auth silently dead is the failure mode
  this whole doc exists to prevent.

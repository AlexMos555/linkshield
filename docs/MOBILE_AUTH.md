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

### 1. Put the public anon key in the build
Mobile auth is dead until `EXPO_PUBLIC_SUPABASE_ANON_KEY` reaches the bundle.

- **Local `gradlew` build (the direct-APK path):** create `mobile/.env` (copy
  `mobile/.env.example`, git-ignored) and paste the key. Metro inlines every
  `EXPO_PUBLIC_*` var at build time.
- **EAS cloud build:** add the same var to the `env` block of each profile in
  `mobile/eas.json`, or as an EAS project env var.

The key is the **anon / public** key (Supabase dashboard → Project Settings →
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
- **Web:** `/signup` already passes the Turnstile token as
  `signInWithOtp({ options: { captchaToken } })` (`SignupForm.tsx`).

### Order (founder steps marked ★)

1. **Ship 1.0.5 everywhere** — App Store, Google Play, RuStore and the direct APK
   on cleanway.ai. Local gradle builds (direct APK / RuStore) read
   `mobile/.env`, not `eas.json`: add `EXPO_PUBLIC_CAPTCHA_URL` there too.
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
4. ★ **Enable captcha in Supabase**: Dashboard → Authentication → Attack
   Protection → Enable Captcha protection → provider **Turnstile** → the
   widget's **secret key** from step 2. Immediately test: web `/signup` and a
   1.0.5 phone (the challenge page should open once, then the code arrives).
   Rollback = switch it off; nothing else to undo.
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

## Notes for future work
- The old email+password functions (`signIn`/`signUp`/`sendPasswordResetEmail`)
  remain in `mobile/src/services/auth.ts` but are no longer used by the screen;
  keep or remove them, but don't reintroduce a password field without a reason —
  it re-splits web (passwordless) and app.
- CI should block a release where `isSupabaseConfigured()` would be false (empty
  URL/anon key) — a build that ships with auth silently dead is the failure mode
  this whole doc exists to prevent.

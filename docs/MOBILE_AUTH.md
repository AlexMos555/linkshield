# Mobile auth — passwordless email code (unified with the web)

The app signs in with a **6-digit code emailed to the user** (Supabase GoTrue
email OTP), not a password. It talks to the **same Supabase project** as the
website, so the **same email is the same account** on both surfaces and
settings/family sync just works — no fragile web→app token handoff, nothing to
remember. An account is entirely optional: "continue without an account" keeps
the free on-device protection working with zero sign-in.

Flow: `mobile/app/auth.tsx` → `sendEmailOtp(email)` (`POST /auth/v1/otp`,
`create_user:true`) → user types the code → `verifyEmailOtp(email, code)`
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
(`{{ .ConfirmationURL }}`). The in-app flow needs the **6-digit code**, so you
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

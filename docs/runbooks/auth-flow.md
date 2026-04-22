# Auth Flow Audit (Mobile)

Status: **#10 audit complete** — P0 bugs fixed, remaining work itemized.
Scope: the Cleanway mobile app (Expo/React Native). Landing + extension
currently have no auth UI (they rely on the mobile app to sign in and the
API token to be copied into their storage — see the `Open questions`
section below for a proposal).

## Supabase session contract

| Piece | Value | Where |
|---|---|---|
| Access token | 1h JWT from GoTrue | `SecureStore["auth_token"]` |
| Refresh token | Long-lived | `SecureStore["refresh_token"]` |
| User email | `user.email` from GoTrue | `SecureStore["user_email"]` |
| Expiry | Unix seconds | `SecureStore["token_expires_at"]` |

All writes + reads go through `mobile/src/services/auth.ts`. Never read
these keys directly from UI — the service handles near-expiry refresh
transparently.

## Covered flows

| Flow | Status | File | Notes |
|---|---|---|---|
| Sign in (email + password) | ✅ Works | `auth.ts::signIn` | 10s timeout, typed `AuthError` on failure |
| Sign up | ✅ Works | `auth.ts::signUp` | Returns `null` when email confirmation required — UI prompts user to check inbox |
| Sign out | ✅ Works | `auth.ts::signOut` | Best-effort API call + clears SecureStore |
| Token refresh | ✅ Works | `auth.ts::refreshAccessToken` | Called transparently by `restoreSession` when <2 min to expiry; clears session on 401 |
| Session restore on cold boot | ✅ Works | `app/_layout.tsx` + `auth.ts::restoreSession` | Runs in `useEffect`, sets in-memory token for `@cleanway/api-client` |
| Password reset request | ✅ Works | `auth.ts::sendPasswordResetEmail` | GoTrue's `/recover` returns 200 even for non-existent emails (anti-enumeration) |
| Guest mode | ✅ Works | `auth.tsx::"Continue without account"` | No auth = no sync, check quota only |

## P0 bugs — fixed this session

1. **Hardcoded placeholder creds** (`"https://YOUR_PROJECT.supabase.co"`, `"YOUR_ANON_KEY"`). Every auth call was guaranteed to fail. Fixed by:
   - Centralizing config in `mobile/src/services/supabase.ts` that reads `EXPO_PUBLIC_SUPABASE_URL` / `EXPO_PUBLIC_SUPABASE_ANON_KEY` with runtime placeholder detection (`YOUR_PROJECT`, etc. reject → empty string).
   - Throwing `SupabaseNotConfiguredError` on any auth call when empty.
   - UI surfaces a "not configured" error instead of bouncing opaquely.

2. **No token refresh**. Access tokens expire in 1h; after that every authenticated API call silently 401'd until the user manually signed out and back in. Fixed with `refreshAccessToken` + `restoreSession` preflight.

3. **No session restore on app boot**. Users who closed the app had to sign in again every time they opened it, even though the refresh token was still valid. Fixed in `_layout.tsx`.

4. **No password reset flow**. UI only exposed login/signup. Added a third mode in `auth.tsx` with email-only input and GoTrue `/recover` integration.

5. **Validation drift**. Email check was `email.includes("@")`, password was `>= 6`. Replaced with regex-based email validation and 8-char minimum in `validateEmail` / `validatePassword`, exported from `auth.ts` so they can be reused everywhere.

6. **Password visible in UI errors**. The original flow alerted raw GoTrue error messages like `"Invalid login credentials"` and `"Email not confirmed"` but with no hierarchy. Now `AuthError` is a typed class with `code`, `status`, `message` so UI can branch on `code === "email_not_confirmed"`.

## P1 gaps — recommended follow-ups

1. **Email verification deep link**. Supabase sends a `https://<project>.supabase.co/auth/v1/verify?token=...` link. On mobile we should register the scheme `cleanway://verify?token=...` as the `redirectTo` and handle it in a deep-link route. Currently the user has to click the email link on a device where the mobile app can intercept it.
2. **OAuth providers**. Mobile has zero social login. Apple Sign In is mandatory for App Store approval if any third-party auth is offered — so consider adding it along with Google when we wire OAuth.
3. **Biometric gate** (optional but a good practice). Cache an "unlocked-until-ts" boolean; prompt `LocalAuthentication.authenticateAsync` when starting the app if a session exists. Improves mobile security without hurting UX.
4. **Rate limit awareness**. Backend rate-limits login attempts but the mobile UI doesn't show a "try again in N seconds" countdown. Parse the `Retry-After` header from a 429 and surface.
5. **Extension auth**. Currently the Chrome extension has no UI for signing in. Proposal: instead of duplicating GoTrue flows, the extension opens `https://<app>/auth/session` in a browser tab, the user signs in, and a `postMessage` / `chrome.runtime.sendMessage` bridge hands the access token to the background script. This scales to Safari/Firefox with one shared flow.
6. **Landing auth**. Similar story — landing doesn't currently have sign in/up pages. When/if we add a web dashboard, use `@supabase/ssr` server-side.
7. **Session revocation on password reset**. GoTrue does NOT invalidate existing sessions when the user resets their password. After a successful reset, the mobile app should force a `signOut()` to prune the old tokens.
8. **Refresh token rotation**. Supabase optionally rotates refresh tokens — enable in Supabase dashboard, then store the new `refresh_token` from every response in `persistSession` (already done).

## Test coverage

| Surface | Coverage |
|---|---|
| `validateEmail` / `validatePassword` pure functions | Covered once a Jest setup lands (see `docs/runbooks/e2e-testing.md#mobile`). Current: zero. |
| `signIn` / `signUp` / `refreshAccessToken` network paths | Need `fetch`-mock test. Deferred with the rest of mobile unit tests. |
| `restoreSession` timing logic | Need fake `Date.now()` + SecureStore mock. Deferred. |
| `AuthError` status codes | Need fixture responses per GoTrue status. Deferred. |

The auth service is designed for testability — SecureStore is the only
external dependency beyond `fetch`, and no global state leaks between
calls. When we wire Jest (jest-expo preset), these tests fall out easily.

## Security checklist

- [x] Secrets read from env or `expoConfig.extra`, never hardcoded in source
- [x] Placeholder values (`YOUR_PROJECT`, `YOUR_ANON_KEY`) rejected at config-read time
- [x] Access + refresh tokens stored in `SecureStore` (Keychain/Keystore), never `AsyncStorage` or plain files
- [x] Email regex rejects `a@b` + common typos
- [x] 8-character password minimum
- [x] 10-second network timeout via `AbortController` on every auth call
- [x] Errors never include server stack traces — only sanitized `AuthError.message`
- [x] 401 on refresh token → clear all session keys (prevent zombie refresh loops)
- [x] GoTrue `/recover` used for password reset (anti-enumeration 200 response)
- [ ] Biometric gate at app cold boot (P1)
- [ ] Rate limiter 429 `Retry-After` surfaced in UI (P1)
- [ ] Deep-link email confirmation handler (P1)
- [ ] OAuth providers (Apple Sign In mandatory if we ship any) (P1)

## Open questions

- **Should the extension do its own sign-in?** Leaning no — one sign-in flow in the mobile app is simpler. Bridge via browser tab + postMessage.
- **How do we rotate the Supabase anon key?** Build-time env. We need a process doc for rotating EAS secrets without bricking existing installs.
- **Supabase RLS policies vs. server-side middleware** — our FastAPI backend already checks JWT signatures server-side (via `supabase_jwt_secret`). The RLS policies in `supabase/migrations/00[1-4]_*.sql` are defense-in-depth. Keep both.

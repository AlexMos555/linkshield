/**
 * Optional CAPTCHA gate for the email-OTP request.
 *
 * WHY THIS EXISTS
 * Supabase can require a captcha token on `POST /auth/v1/otp`. That switch is
 * project-wide and server-side; the moment it is flipped, every client that
 * sends no token gets `400 captcha_failed`. This module is the client half,
 * wired ahead of the flip so turning it on is a config change, not a code
 * change.
 *
 * OFF BY DEFAULT — AND OFF MEANS BYTE-IDENTICAL
 * The whole feature hangs off one build-time env var. With
 * `EXPO_PUBLIC_CAPTCHA_URL` unset `isCaptchaRequired()` is false, the sign-in
 * screen never calls anything here, no browser opens, no extra request is
 * made, and the OTP body is exactly what it always was.
 *
 * SET MEANS "READY", NOT "ALWAYS"
 * Store builds from 1.0.5 set it (mobile/eas.json). Even then the challenge
 * opens only when GoTrue answers `captcha_failed` (src/utils/otp-request.ts),
 * so until Supabase captcha protection is switched on nobody sees it.
 *
 * WHY A HOSTED PAGE AND NOT AN INLINE WIDGET
 * A captcha is HTML+JS; rendering it in-app needs a webview. `react-native-webview`
 * is not a dependency of this app (nor is `expo-web-browser`), and adding a
 * native dependency means a prebuild, a new signed APK and a store
 * resubmission, on a workspace where the root hoists a different react-native
 * than the app pins (see docs/RUSTORE_SUBMISSION.md). So the challenge is
 * hosted on the web (landing/app/auth/captcha) and the token comes back to
 * the app's already registered `cleanway://` scheme. No new dependencies.
 *
 * HOW IT OPENS
 *   • iPhone: in an in-app sheet — ASWebAuthenticationSession, our own few
 *     lines in modules/cleanway-safari, handed in by the sign-in screen as an
 *     AuthSheet. App Review 4.0 rejects a sign-in that leaves the app for
 *     Safari, and from the day Supabase captcha is on every iPhone sign-in
 *     (the reviewer's included) goes through this page. The sheet catches the
 *     page's redirect to cleanway://captcha-return itself and hands the URL
 *     back here — no deep link, no AppState guessing.
 *   • Android, and an iPhone binary without the sheet: `Linking.openURL` to
 *     the browser; the redirect comes back as a deep link to
 *     mobile/app/captcha-return.tsx.
 *
 * A side benefit: the PROVIDER and SITEKEY live only on the web page, so
 * switching hCaptcha <-> Turnstile or rotating a sitekey never needs a rebuild.
 * The app only ever learns "here is a URL that yields a token".
 *
 * FLOW
 *   requestCaptchaToken()
 *     -> opens CAPTCHA_URL?nonce=<random> (sheet or browser, above)
 *     -> web page solves the challenge
 *     -> page redirects to cleanway://captcha-return?nonce=<same>&token=<token>
 *     -> the sheet returns that URL (iPhone), or captcha-return.tsx calls
 *        deliverCaptchaToken() (browser) — the nonce must match either way
 *     -> the promise resolves with the token
 *   Anything else (user backs out, timeout, no browser) resolves `null`, and
 *   the caller shows a plain "try again" — it never hangs and never throws.
 */

// Nonces need real entropy. Hermes has no built-in crypto.getRandomValues;
// this polyfill (already a dependency, used by src/lib/family-crypto.ts) adds
// it. MUST be imported before the first getRandomValues call.
import "react-native-get-random-values";

import { AppState, Linking, type NativeEventSubscription } from "react-native";
import Constants from "expo-constants";

// ─── Configuration ────────────────────────────────────────────────
//
// Resolution order mirrors src/services/supabase.ts exactly:
// 1. EXPO_PUBLIC_CAPTCHA_URL — inlined at build time by Expo/Metro.
// 2. Constants.expoConfig.extra.captchaUrl — per-environment override.
// 3. "" — feature off.

const PLACEHOLDER_MARKERS = [
  "YOUR_CAPTCHA_URL",
  "REPLACE_WITH_CAPTCHA_URL",
  "example.com",
];

function cleanValue(v: string | undefined | null): string {
  const s = (v ?? "").trim();
  if (!s) return "";
  if (PLACEHOLDER_MARKERS.some((m) => s.includes(m))) return "";
  return s;
}

/**
 * Only an https:// URL may ever reach `Linking.openURL` or the in-app sheet
 * (whose native half refuses anything else too). A misconfigured value
 * (`intent://`, `javascript:`, a bare host) must disable the feature rather
 * than hand an arbitrary scheme to the OS. Same guard shape as
 * `isSafeDownloadUrl` in src/lib/update-check.ts.
 */
function isHttpsUrl(v: string): boolean {
  return /^https:\/\/[^\s]+$/i.test(v);
}

const CONFIGURED_URL = cleanValue(
  process.env.EXPO_PUBLIC_CAPTCHA_URL ||
    (Constants.expoConfig?.extra?.captchaUrl as string | undefined),
);

export const CAPTCHA_URL: string = isHttpsUrl(CONFIGURED_URL) ? CONFIGURED_URL : "";

if (__DEV__ && CONFIGURED_URL && !CAPTCHA_URL) {
  // Loud in dev, silent in production: a non-https value is a pilot error, and
  // failing closed (captcha disabled) without a word is how it stays unnoticed.
  console.warn(
    "[captcha] EXPO_PUBLIC_CAPTCHA_URL is set but is not an https:// URL — captcha disabled.",
  );
}

/** Where the challenge page sends the token (landing/lib/turnstile.ts RETURN_TARGETS). */
const RETURN_SCHEME = "cleanway";
const RETURN_URL = `${RETURN_SCHEME}://captcha-return`;

/**
 * The iPhone's in-app web sheet (modules/cleanway-safari). Passed in rather
 * than imported, so this file keeps importing only packages and
 * mobile/scripts/test-captcha-service.mjs can stand in for it.
 */
export interface AuthSheet {
  /** False on Android and in a binary without the native half. */
  available(): boolean;
  /** Resolves the `<callbackScheme>://…` URL the page navigated to, or null (closed, failed). Never rejects. */
  open(url: string, callbackScheme: string): Promise<string | null>;
  /** Dismisses the sheet if it is still up. */
  cancel(): void;
}

/** True only when a challenge URL is configured. False today, by design. */
export function isCaptchaRequired(): boolean {
  return CAPTCHA_URL.length > 0;
}

// ─── Pending-request state ────────────────────────────────────────

/** Hard ceiling on a solve. Generous: reading a captcha takes real people time. */
const SOLVE_TIMEOUT_MS = 180_000;

/**
 * Once the app is foregrounded again, how long we still wait for the deep link
 * to arrive before calling it a cancellation. The user returning WITHOUT a
 * token (they backed out of the browser) is indistinguishable from a token
 * still in flight, so we give the link a window instead of hanging until
 * SOLVE_TIMEOUT_MS. Misfiring here costs the user one "try again"; not having
 * it costs them a three-minute frozen spinner.
 */
const RETURN_GRACE_MS = 4_000;

interface Pending {
  readonly nonce: string;
  readonly resolve: (token: string | null) => void;
  timeout: ReturnType<typeof setTimeout> | null;
  grace: ReturnType<typeof setTimeout> | null;
  appState: NativeEventSubscription | null;
  /** Set once the app has actually gone to the browser. */
  backgrounded: boolean;
  /** The in-app sheet while it is up: settling for any other reason dismisses it. */
  sheet: AuthSheet | null;
}

let pending: Pending | null = null;

/** Resolve the outstanding request exactly once and drop every listener/timer. */
function settle(token: string | null): void {
  const entry = pending;
  if (!entry) return;
  pending = null;
  if (entry.timeout) clearTimeout(entry.timeout);
  if (entry.grace) clearTimeout(entry.grace);
  entry.appState?.remove();
  entry.sheet?.cancel();
  entry.resolve(token);
}

function onAppStateChange(state: string): void {
  const entry = pending;
  if (!entry) return;

  if (state !== "active") {
    // Off to the browser. Any grace countdown from an earlier bounce is stale.
    entry.backgrounded = true;
    if (entry.grace) {
      clearTimeout(entry.grace);
      entry.grace = null;
    }
    return;
  }

  // Back in the app. If the deep link is coming, it lands within a few frames
  // of this; if it doesn't, the user gave up.
  if (!entry.backgrounded || entry.grace) return;
  entry.grace = setTimeout(() => settle(null), RETURN_GRACE_MS);
}

// ─── Public API ───────────────────────────────────────────────────

/**
 * Run the challenge and resolve with a token, or `null` when it did not
 * complete for ANY reason (not configured, no browser, cancelled, timed out).
 * Never rejects — the caller has one branch to write. With an available
 * [sheet] (iPhone) the page opens in it; otherwise in the browser.
 */
export function requestCaptchaToken(sheet?: AuthSheet): Promise<string | null> {
  if (!isCaptchaRequired()) return Promise.resolve(null);

  // Never leave two challenges outstanding: a second tap supersedes the first.
  cancelCaptcha();

  const nonce = newNonce();
  return new Promise<string | null>((resolve) => {
    const entry: Pending = {
      nonce,
      resolve,
      timeout: null,
      grace: null,
      appState: null,
      backgrounded: false,
      sheet: null,
    };
    pending = entry;
    entry.timeout = setTimeout(() => settle(null), SOLVE_TIMEOUT_MS);

    const separator = CAPTCHA_URL.includes("?") ? "&" : "?";
    const url = `${CAPTCHA_URL}${separator}nonce=${encodeURIComponent(nonce)}`;

    if (sheet?.available()) {
      entry.sheet = sheet;
      sheet.open(url, RETURN_SCHEME).then(
        (returned) => {
          if (pending !== entry) return; // cancelled, timed out or superseded meanwhile
          entry.sheet = null; // it has closed itself
          const back = parseCaptchaReturn(returned);
          if (!back || !deliverCaptchaToken(back.nonce, back.token)) settle(null);
        },
        () => {
          if (pending === entry) settle(null);
        },
      );
      return;
    }

    entry.appState = AppState.addEventListener("change", onAppStateChange);
    Linking.openURL(url).catch(() => settle(null));
  });
}

/**
 * The nonce and token from `cleanway://captcha-return?nonce=…&token=…` (the
 * page builds it with encodeURIComponent), or null for any other URL or a
 * malformed escape. A repeated parameter keeps its first value, as
 * captcha-return.tsx does.
 */
export function parseCaptchaReturn(url: string | null): { nonce: string; token: string } | null {
  if (!url || !url.startsWith(`${RETURN_URL}?`)) return null;
  const query = url.slice(RETURN_URL.length + 1).split("#")[0];
  const found: { nonce?: string; token?: string } = {};
  for (const part of query.split("&")) {
    const eq = part.indexOf("=");
    const key = eq < 0 ? part : part.slice(0, eq);
    if ((key !== "nonce" && key !== "token") || found[key] !== undefined) continue;
    try {
      found[key] = decodeURIComponent(eq < 0 ? "" : part.slice(eq + 1));
    } catch {
      return null;
    }
  }
  return { nonce: found.nonce ?? "", token: found.token ?? "" };
}

/**
 * Hand a token back from the `cleanway://captcha-return` deep link.
 *
 * The nonce must match the outstanding request. Without that check any app on
 * the device could fire our scheme and inject a token of its choosing into a
 * sign-in the user did not start. Returns whether the delivery was accepted —
 * a stale or unsolicited one is dropped silently.
 */
export function deliverCaptchaToken(nonce: string, token: string): boolean {
  const entry = pending;
  if (!entry) return false;
  if (!nonce || nonce !== entry.nonce) return false;
  settle(token.trim() ? token.trim() : null);
  return true;
}

/**
 * Abandon any outstanding request (screen unmounted, user navigated away).
 * Safe to call when nothing is pending.
 */
export function cancelCaptcha(): void {
  settle(null);
}

// ─── Internals ────────────────────────────────────────────────────

/** 128 bits of hex — one-time, single-use, tied to exactly one solve. */
function newNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

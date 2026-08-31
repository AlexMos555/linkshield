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
 * `EXPO_PUBLIC_CAPTCHA_URL` unset (today's state — the founder has no captcha
 * account yet) `isCaptchaRequired()` is false, the sign-in screen never calls
 * anything here, no browser opens, no extra request is made, and the OTP body
 * is exactly what it is today. The only cost is one `.length > 0` check.
 *
 * WHY A BROWSER ROUND-TRIP AND NOT AN INLINE WIDGET
 * A captcha is HTML+JS; rendering it in-app needs a webview. `react-native-webview`
 * is not a dependency of this app (nor is `expo-web-browser`), and both are
 * NATIVE modules — adding one means a prebuild, a new signed APK and a store
 * resubmission, on a workspace where the root hoists a different react-native
 * than the app pins (see docs/RUSTORE_SUBMISSION.md). So the challenge is
 * hosted on the web (landing/app/auth/captcha), opened with `Linking.openURL`
 * from react-native core, and the token comes back through the app's already
 * registered `cleanway://` scheme. Zero new dependencies.
 *
 * A side benefit: the PROVIDER and SITEKEY live only on the web page, so
 * switching hCaptcha <-> Turnstile or rotating a sitekey never needs a rebuild.
 * The app only ever learns "here is a URL that yields a token".
 *
 * Upgrade path when a native dep is acceptable: `expo-web-browser`'s
 * `openAuthSessionAsync` gives the same flow without the deep-link hop.
 *
 * FLOW
 *   requestCaptchaToken()
 *     -> opens CAPTCHA_URL?nonce=<random>
 *     -> web page solves the challenge
 *     -> page redirects to cleanway://captcha-return?nonce=<same>&token=<token>
 *     -> mobile/app/captcha-return.tsx calls deliverCaptchaToken()
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
 * Only an https:// URL may ever reach `Linking.openURL`. A misconfigured value
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
 * Never rejects — the caller has one branch to write.
 */
export function requestCaptchaToken(): Promise<string | null> {
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
    };
    pending = entry;
    entry.timeout = setTimeout(() => settle(null), SOLVE_TIMEOUT_MS);
    entry.appState = AppState.addEventListener("change", onAppStateChange);

    const separator = CAPTCHA_URL.includes("?") ? "&" : "?";
    const url = `${CAPTCHA_URL}${separator}nonce=${encodeURIComponent(nonce)}`;
    Linking.openURL(url).catch(() => settle(null));
  });
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

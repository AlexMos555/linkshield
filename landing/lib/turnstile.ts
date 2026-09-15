/**
 * Cloudflare Turnstile — the pure, framework-free half of the captcha flow.
 *
 * Two consumers:
 *   • components/TurnstileWidget.tsx renders the widget on /signup.
 *   • app/auth/captcha/page.tsx hosts the challenge for the MOBILE app, which
 *     opens `/auth/captcha?nonce=<32 hex>` in the system browser and expects
 *     `cleanway://captcha-return?nonce=<same>&token=<token>` back
 *     (mobile/src/services/captcha.ts + mobile/app/captcha-return.tsx).
 *
 * Everything that decides WHAT ends up in that deep link lives here so it can
 * be table-tested without a DOM (scripts/test-turnstile-lib.mjs). The page
 * must never build the redirect from arbitrary query input — an unchecked
 * `scheme` param would turn it into an open redirector into any app on the
 * device.
 *
 * Sitekey: NEXT_PUBLIC_TURNSTILE_SITE_KEY. When unset we fall back to
 * Cloudflare's documented always-pass TEST key and report `testMode`, which
 * the UI renders as a visible notice — a test key in production must be
 * impossible to miss. Supabase validates the token only while its CAPTCHA
 * protection is switched on; until then the token is accepted and ignored.
 */

export const TURNSTILE_SCRIPT_URL =
  "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";

/** Cloudflare's documented dummy sitekey: visible widget, always passes. */
export const TURNSTILE_TEST_SITE_KEY = "1x00000000000000000000AA";

export interface TurnstileSiteKey {
  readonly key: string;
  /** True when the always-pass test key is in use — the UI must say so. */
  readonly testMode: boolean;
}

export function resolveTurnstileSiteKey(
  configured: string | undefined | null,
): TurnstileSiteKey {
  const key = (configured ?? "").trim();
  if (key) return { key, testMode: false };
  return { key: TURNSTILE_TEST_SITE_KEY, testMode: true };
}

/**
 * Build-time value. Next inlines `process.env.NEXT_PUBLIC_*` only when the
 * full name is spelled out literally, hence no helper around the lookup.
 */
export const TURNSTILE_SITE_KEY: TurnstileSiteKey = resolveTurnstileSiteKey(
  process.env.NEXT_PUBLIC_TURNSTILE_SITE_KEY,
);

// ─── Mobile deep-link contract ────────────────────────────────────

/** Exactly what mobile's `newNonce()` produces: 16 random bytes as lowercase hex. */
const NONCE_RE = /^[0-9a-f]{32}$/;

/**
 * Allowlist of return targets, keyed by the optional `scheme` query param.
 * The app registers the `cleanway` scheme (mobile/app.json) and today sends
 * no `scheme` at all; the key exists so a future dev-build scheme is one
 * line here rather than a free-form parameter.
 */
const RETURN_TARGETS = {
  cleanway: "cleanway://captcha-return",
} as const;

export type ReturnScheme = keyof typeof RETURN_TARGETS;
export const DEFAULT_RETURN_SCHEME: ReturnScheme = "cleanway";

export type CaptchaRequest =
  | { readonly ok: true; readonly nonce: string; readonly scheme: ReturnScheme }
  | { readonly ok: false; readonly reason: "missing_nonce" | "bad_nonce" | "bad_scheme" };

function isReturnScheme(value: string): value is ReturnScheme {
  return Object.prototype.hasOwnProperty.call(RETURN_TARGETS, value);
}

/** Validate the query string the mobile app opened us with. */
export function parseCaptchaRequest(search: string): CaptchaRequest {
  const params = new URLSearchParams(search);
  const nonce = params.get("nonce");
  if (!nonce) return { ok: false, reason: "missing_nonce" };
  if (!NONCE_RE.test(nonce)) return { ok: false, reason: "bad_nonce" };
  const scheme = params.get("scheme") ?? DEFAULT_RETURN_SCHEME;
  if (!isReturnScheme(scheme)) return { ok: false, reason: "bad_scheme" };
  return { ok: true, nonce, scheme };
}

/**
 * The deep link handed to the OS once Turnstile succeeds. Returns null for
 * anything outside the contract, so a caller can never emit a half-built URL.
 */
export function buildCaptchaReturnUrl(
  scheme: string,
  nonce: string,
  token: string,
): string | null {
  if (!isReturnScheme(scheme) || !NONCE_RE.test(nonce)) return null;
  const cleanToken = token.trim();
  if (!cleanToken) return null;
  const query = `nonce=${encodeURIComponent(nonce)}&token=${encodeURIComponent(cleanToken)}`;
  return `${RETURN_TARGETS[scheme]}?${query}`;
}

// ─── Browser-side script loader ───────────────────────────────────

export interface TurnstileRenderOptions {
  readonly sitekey: string;
  readonly callback: (token: string) => void;
  readonly "error-callback"?: (code: string) => void;
  readonly "expired-callback"?: () => void;
  readonly "timeout-callback"?: () => void;
  readonly theme?: "auto" | "light" | "dark";
  readonly size?: "normal" | "flexible" | "compact";
  readonly language?: string;
  readonly "refresh-expired"?: "auto" | "manual" | "never";
}

export interface TurnstileApi {
  render(container: HTMLElement, options: TurnstileRenderOptions): string | undefined;
  reset(widgetId?: string): void;
  remove(widgetId: string): void;
}

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

let scriptPromise: Promise<TurnstileApi> | null = null;

/**
 * Load api.js once and resolve with the global it defines. A failed load
 * (offline, blocked CDN, CSP) rejects and clears the memo so a retry can
 * inject a fresh <script>.
 */
export function loadTurnstile(): Promise<TurnstileApi> {
  if (typeof window === "undefined") {
    return Promise.reject(new Error("turnstile: no window"));
  }
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (scriptPromise) return scriptPromise;

  scriptPromise = new Promise<TurnstileApi>((resolve, reject) => {
    const script = document.createElement("script");
    script.src = TURNSTILE_SCRIPT_URL;
    script.async = true;
    script.defer = true;
    script.addEventListener("load", () => {
      if (window.turnstile) resolve(window.turnstile);
      else reject(new Error("turnstile: api.js loaded without defining window.turnstile"));
    });
    script.addEventListener("error", () => {
      script.remove();
      scriptPromise = null;
      reject(new Error("turnstile: api.js failed to load"));
    });
    document.head.appendChild(script);
  });
  return scriptPromise;
}

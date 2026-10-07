/**
 * Sign-in for the extension: the website → extension token handoff and the
 * session's upkeep. ES module, no `chrome` at top level — every browser call
 * goes through the `deps` passed to createAuthSession(), so
 * scripts/test-extension-auth.mjs drives it in plain Node.
 *
 * The flow
 * --------
 * 1. "Sign in" (popup or settings) → startSignIn(): a random `state` is kept
 *    in storage and https://cleanway.ai/<locale>/extension/connect?state=…
 *    opens in a tab.
 * 2. That page needs a signed-in website session (it goes through the
 *    magic-link / code sign-in first), shows the email and a Connect button.
 *    Connect asks the API for a session OF THE EXTENSION'S OWN
 *    (POST /api/v1/auth/extension-session — copying the website's tokens
 *    would make the two clients rotate one refresh token and Supabase would
 *    revoke both) and posts it to the page's own window.
 * 3. content/connect-relay.js — a content script that runs ONLY on that page
 *    of that exact origin — forwards it here as AUTH_CONNECT.
 * 4. acceptHandoff() checks the sender (our own content script, top frame,
 *    https://cleanway.ai, the connect path), the state (the one this install
 *    started, at most 30 minutes old, used once) and the tokens' shape, then
 *    stores them.
 *
 * Why a content-script relay and not `externally_connectable`: Firefox does
 * not support externally_connectable for web pages and Safari's support is
 * partial, while a content script plus window.postMessage works the same in
 * all three. The relay is limited to one path of one origin by the manifest
 * AND re-checks both at run time, and the background re-checks the sender.
 *
 * Tokens never go into a URL or a log line. They live in
 * chrome.storage.local under the keys below; `auth_token` is the access token
 * every authed call already reads.
 */

export const CONNECT_ORIGIN = "https://cleanway.ai";
// The production Supabase project. The refresh token is only ever sent here,
// whatever the page says.
export const SUPABASE_URL = "https://bpyqgzzclsbfvxthyfsf.supabase.co";

export const STATE_TTL_MS = 30 * 60 * 1000; // long enough to fetch a sign-in code from the inbox
export const REFRESH_MARGIN_S = 5 * 60; // refresh when less than this is left
export const RETRY_DELAY_S = 2 * 60; // after a refresh that could not reach the server

export const KEYS = Object.freeze({
  access: "auth_token",
  refresh: "auth_refresh_token",
  expiresAt: "auth_expires_at",
  email: "auth_email",
  userId: "auth_user_id",
  anonKey: "auth_anon_key",
  state: "auth_connect_state",
  signedOutReason: "auth_signed_out_reason",
});
const SESSION_KEYS = [KEYS.access, KEYS.refresh, KEYS.expiresAt, KEYS.email, KEYS.userId, KEYS.anonKey];

// The ten languages the site has; English lives at the apex (localePrefix "as-needed").
const SITE_LOCALES = ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"];
const CONNECT_PATH_RE = /^\/(?:(?:en|ru|es|pt|fr|de|it|id|hi|ar)\/)?extension\/connect\/?$/;
const STATE_RE = /^[A-Za-z0-9_-]{43}$/; // 32 random bytes, base64url, no padding

// ── Small pure helpers ───────────────────────────────────────────────

function base64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** 32 bytes from the platform CSPRNG, base64url (43 characters). */
export function generateState(cryptoImpl = globalThis.crypto) {
  const bytes = new Uint8Array(32);
  cryptoImpl.getRandomValues(bytes);
  return base64url(bytes);
}

export function isValidState(value) {
  return typeof value === "string" && STATE_RE.test(value);
}

/** Length-independent comparison so a wrong guess learns nothing from timing. */
export function statesMatch(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** The browser's UI language → one of the site's locales ("pt-BR" → "pt"). */
export function siteLocale(uiLanguage) {
  const base = String(uiLanguage || "").toLowerCase().split(/[-_]/)[0];
  return SITE_LOCALES.includes(base) ? base : "en";
}

export function connectUrl(state, uiLanguage) {
  const locale = siteLocale(uiLanguage);
  const prefix = locale === "en" ? "" : `/${locale}`;
  return `${CONNECT_ORIGIN}${prefix}/extension/connect?state=${encodeURIComponent(state)}`;
}

/** Exactly https://cleanway.ai + the connect path; any query, no other origin. */
export function isConnectPageUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch (e) {
    return false;
  }
  return parsed.origin === CONNECT_ORIGIN && CONNECT_PATH_RE.test(parsed.pathname);
}

/**
 * AUTH_CONNECT is honoured only from our own content script in the top frame
 * of the connect page. An extension page (no tab) or any other site is refused.
 */
export function isConnectSender(sender, runtimeId) {
  if (!sender || sender.id !== runtimeId || !sender.tab) return false;
  if (typeof sender.frameId === "number" && sender.frameId !== 0) return false;
  const url = sender.url || (sender.tab && sender.tab.url);
  if (!isConnectPageUrl(url)) return false;
  // Chrome reports the origin separately; when it does, it must agree.
  if (sender.origin !== undefined && sender.origin !== CONNECT_ORIGIN) return false;
  return true;
}

/** Sign in / out / status: only the extension's own pages (popup, settings). */
export function isExtensionPageSender(sender, runtimeId, extensionBaseUrl) {
  if (!sender || sender.id !== runtimeId) return false;
  return typeof sender.url === "string" && typeof extensionBaseUrl === "string" &&
    extensionBaseUrl.length > 0 && sender.url.startsWith(extensionBaseUrl);
}

function decodeJwtPayload(token) {
  const parts = typeof token === "string" ? token.split(".") : [];
  if (parts.length !== 3 || !parts.every((p) => /^[A-Za-z0-9_-]+$/.test(p))) return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
    const payload = JSON.parse(new TextDecoder().decode(bytes));
    return payload && typeof payload === "object" ? payload : null;
  } catch (e) {
    return null;
  }
}

/** The public anon key: a Supabase JWT with role "anon", or a publishable key. */
export function isValidAnonKey(key) {
  if (typeof key !== "string" || key.length > 2048) return false;
  if (/^sb_publishable_[A-Za-z0-9_-]{10,}$/.test(key)) return true;
  const payload = decodeJwtPayload(key);
  return Boolean(payload && payload.role === "anon");
}

/**
 * Check what the page handed over and turn it into what we store. The access
 * token's signature can't be checked here (the API does that on every call);
 * this refuses anything that is not a live user token of OUR project.
 *
 * @returns {{ok: true, session: object} | {ok: false, error: string}}
 */
export function parseHandoffSession(raw, { nowS, supabaseUrl = SUPABASE_URL } = {}) {
  if (!raw || typeof raw !== "object") return { ok: false, error: "invalid_session" };
  const access = raw.access_token;
  const refresh = raw.refresh_token;
  if (typeof access !== "string" || access.length > 8192) return { ok: false, error: "invalid_session" };
  if (typeof refresh !== "string" || !/^[A-Za-z0-9_-]{8,512}$/.test(refresh)) {
    return { ok: false, error: "invalid_session" };
  }
  if (!isValidAnonKey(raw.anon_key)) return { ok: false, error: "invalid_session" };
  const claims = decodeJwtPayload(access);
  if (!claims || typeof claims.sub !== "string" || !claims.sub) return { ok: false, error: "invalid_session" };
  if (claims.aud !== "authenticated") return { ok: false, error: "invalid_session" };
  if (claims.iss !== `${supabaseUrl}/auth/v1`) return { ok: false, error: "wrong_project" };
  const exp = Number(claims.exp);
  if (!Number.isFinite(exp) || exp <= nowS) return { ok: false, error: "expired" };
  const expiresAt = Number.isInteger(raw.expires_at) && raw.expires_at > nowS ? Math.min(raw.expires_at, exp) : exp;
  return {
    ok: true,
    session: {
      [KEYS.access]: access,
      [KEYS.refresh]: refresh,
      [KEYS.expiresAt]: expiresAt,
      [KEYS.email]: typeof claims.email === "string" ? claims.email : "",
      [KEYS.userId]: claims.sub,
      [KEYS.anonKey]: raw.anon_key,
    },
  };
}

export function needsRefresh(expiresAt, nowS, marginS = REFRESH_MARGIN_S) {
  return !Number.isFinite(expiresAt) || expiresAt - nowS <= marginS;
}

/**
 * Supabase's refresh: POST /auth/v1/token?grant_type=refresh_token with the
 * public anon key. `fatal` means the server REFUSED the refresh token (revoked,
 * already used, user gone) — only then is the user signed out. A network error
 * or a 5xx/429 keeps the session for a retry: a laptop waking up offline must
 * not lose its sign-in.
 */
export async function refreshSession({ fetchImpl, supabaseUrl = SUPABASE_URL, anonKey, refreshToken, nowS }) {
  let resp;
  try {
    resp = await fetchImpl(`${supabaseUrl}/auth/v1/token?grant_type=refresh_token`, {
      method: "POST",
      headers: { "Content-Type": "application/json", apikey: anonKey },
      body: JSON.stringify({ refresh_token: refreshToken }),
      cache: "no-store",
      credentials: "omit",
    });
  } catch (e) {
    return { ok: false, fatal: false };
  }
  if (resp.status >= 400 && resp.status < 500 && resp.status !== 408 && resp.status !== 429) {
    return { ok: false, fatal: true };
  }
  if (!resp.ok) return { ok: false, fatal: false };
  let body;
  try {
    body = await resp.json();
  } catch (e) {
    return { ok: false, fatal: false };
  }
  // A 200 we can't use (a proxy's error page, a truncated body) is retried,
  // not treated as a revoked session.
  const parsed = parseHandoffSession({ ...body, anon_key: anonKey }, { nowS, supabaseUrl });
  if (!parsed.ok) return { ok: false, fatal: false };
  return { ok: true, session: parsed.session };
}

// ── The stateful part ────────────────────────────────────────────────

/**
 * @param {object} deps
 * @param {{get: Function, set: Function, remove: Function}} deps.storage  chrome.storage.local-shaped (promises)
 * @param {Function} deps.fetchImpl
 * @param {() => number} [deps.now]       ms clock
 * @param {Function} [deps.openTab]       (url) => void
 * @param {() => string} [deps.uiLanguage]
 * @param {(whenMs: number|null) => void} [deps.scheduleRefresh]  arm (or clear, with null) the refresh alarm
 * @param {(accessToken: string) => Promise<void>} [deps.onSignedIn]  e.g. registerDevice
 * @param {string} [deps.supabaseUrl]
 */
export function createAuthSession(deps) {
  const {
    storage,
    fetchImpl,
    now = () => Date.now(),
    openTab = () => {},
    uiLanguage = () => "en",
    scheduleRefresh = () => {},
    onSignedIn = async () => {},
    supabaseUrl = SUPABASE_URL,
  } = deps;
  const nowS = () => Math.floor(now() / 1000);
  let inflight = null; // one refresh at a time: a rotated token must never be sent twice

  async function read(keys) {
    try {
      return (await storage.get(keys)) || {};
    } catch (e) {
      return {};
    }
  }

  function armFor(expiresAt) {
    scheduleRefresh(Math.max(now() + 30_000, (expiresAt - REFRESH_MARGIN_S) * 1000));
  }

  async function startSignIn() {
    const state = generateState();
    await storage.set({ [KEYS.state]: { value: state, created_at: now() } });
    const url = connectUrl(state, uiLanguage());
    await openTab(url);
    return url;
  }

  async function signOut(reason = null) {
    const current = await read([KEYS.access, KEYS.anonKey]);
    await storage.remove([...SESSION_KEYS, KEYS.state]);
    if (reason) await storage.set({ [KEYS.signedOutReason]: reason });
    else await storage.remove(KEYS.signedOutReason);
    scheduleRefresh(null);
    // Best effort: end this session on the server too. It is the extension's
    // own session, so the website stays signed in.
    if (!reason && current[KEYS.access] && current[KEYS.anonKey]) {
      try {
        await fetchImpl(`${supabaseUrl}/auth/v1/logout?scope=local`, {
          method: "POST",
          headers: { apikey: current[KEYS.anonKey], Authorization: `Bearer ${current[KEYS.access]}` },
          credentials: "omit",
        });
      } catch (e) { /* offline: the local sign-out already happened */ }
    }
  }

  /**
   * @returns {Promise<{ok: true, email: string} | {ok: false, error: string}>}
   */
  async function acceptHandoff(message, sender, runtimeId) {
    if (!isConnectSender(sender, runtimeId)) return { ok: false, error: "bad_sender" };
    if (!message || !isValidState(message.state)) return { ok: false, error: "state_mismatch" };
    const stored = (await read([KEYS.state]))[KEYS.state];
    if (!stored || !statesMatch(stored.value, message.state)) return { ok: false, error: "state_mismatch" };
    // The state is spent from here on, whatever happens next.
    await storage.remove(KEYS.state);
    if (!(now() - stored.created_at >= 0 && now() - stored.created_at <= STATE_TTL_MS)) {
      return { ok: false, error: "state_expired" };
    }
    const parsed = parseHandoffSession(message.session, { nowS: nowS(), supabaseUrl });
    if (!parsed.ok) return { ok: false, error: parsed.error };
    await storage.set(parsed.session);
    await storage.remove(KEYS.signedOutReason);
    armFor(parsed.session[KEYS.expiresAt]);
    try {
      await onSignedIn(parsed.session[KEYS.access]);
    } catch (e) { /* device registration is best effort */ }
    return { ok: true, email: parsed.session[KEYS.email] };
  }

  async function doRefresh() {
    const s = await read([KEYS.refresh, KEYS.anonKey, KEYS.expiresAt]);
    if (!s[KEYS.refresh] || !s[KEYS.anonKey]) return { signedIn: false };
    if (!needsRefresh(s[KEYS.expiresAt], nowS())) {
      armFor(s[KEYS.expiresAt]);
      return { signedIn: true, refreshed: false };
    }
    const result = await refreshSession({
      fetchImpl, supabaseUrl, anonKey: s[KEYS.anonKey], refreshToken: s[KEYS.refresh], nowS: nowS(),
    });
    if (result.ok) {
      await storage.set(result.session);
      armFor(result.session[KEYS.expiresAt]);
      return { signedIn: true, refreshed: true };
    }
    if (result.fatal) {
      await signOut("expired");
      return { signedIn: false, signedOut: true };
    }
    scheduleRefresh(now() + RETRY_DELAY_S * 1000);
    return { signedIn: true, refreshed: false, offline: true };
  }

  /** Refresh if the access token is (nearly) expired. Safe to call often. */
  function ensureFresh() {
    if (!inflight) inflight = doRefresh().finally(() => { inflight = null; });
    return inflight;
  }

  async function status() {
    await ensureFresh();
    const s = await read([KEYS.access, KEYS.email, KEYS.signedOutReason, KEYS.state]);
    const pending = s[KEYS.state] && now() - s[KEYS.state].created_at <= STATE_TTL_MS;
    return {
      signedIn: Boolean(s[KEYS.access]),
      email: s[KEYS.access] ? s[KEYS.email] || "" : "",
      pending: !s[KEYS.access] && Boolean(pending),
      signedOutReason: s[KEYS.access] ? null : s[KEYS.signedOutReason] || null,
    };
  }

  return { startSignIn, acceptHandoff, ensureFresh, signOut, status };
}

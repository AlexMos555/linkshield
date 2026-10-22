/**
 * Two lookups a content script needs, made by the background.
 *
 *   BREACH_PREFIX   {prefix: 5 hex chars of a password's SHA-1}
 *                   → {ok: true, suffixes: [{suffix, count}]}
 *                   content/password-pwned.js matches its own suffix in the
 *                   page; the password and the full hash never leave it.
 *   VERIFIED_HOSTS  {brand: "paypal"}
 *                   → {ok: true, hosts: ["paypal.com", …]}
 *                   content/credential-guardian.js: a form that looks like a
 *                   brand's and posts to that brand's own sign-in host is
 *                   not warned about.
 *   Anything wrong  → {ok: false, error: "bad_sender" | "bad_prefix" |
 *                     "bad_brand" | "unavailable"}
 *
 * Both used to be fetched by the content scripts themselves. In Chromium
 * (and likely Safari) a content script's request is the PAGE's request: it
 * carried the visited site's origin, and api.cleanway.ai answers those
 * without CORS headers, so the browser threw the answer away. The leak
 * warning never appeared and the guard warned about real brand sign-ins.
 * From the background the request carries the extension's origin (its host
 * permission covers the API), no page origin and no referrer.
 *
 * Only content scripts on real web pages may ask (isWebPageSender). Brand
 * answers are kept for the worker's life; a failed lookup is not.
 */

import { isWebPageSender } from "./safari-native.js";

export const BREACH_PREFIX_RE = /^[0-9A-F]{5}$/;
const SUFFIX_RE = /^[0-9A-F]{35}$/;
const BRAND_RE = /^[a-z0-9_-]{2,64}$/;
const LOOKUP_TIMEOUT_MS = 8000;
const MAX_BRAND_HOSTS = 50;

/**
 * @param {object} deps
 * @param {(url: string, init: object) => Promise<Response>} deps.fetchImpl
 * @param {() => string} deps.apiBase  the allowlisted API base (utils/api-base.js)
 * @returns the background's onMessage hook: true when the message was ours
 *   (reply async), false when it was refused at once, undefined otherwise
 */
export function createPageLookups({ fetchImpl, apiBase }) {
  const brandHosts = new Map();

  async function getJson(path) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), LOOKUP_TIMEOUT_MS);
    try {
      const resp = await fetchImpl(`${apiBase()}${path}`, {
        method: "GET",
        credentials: "omit",
        referrerPolicy: "no-referrer",
        signal: ctrl.signal,
      });
      if (!resp.ok) return null;
      const data = await resp.json();
      return data && typeof data === "object" ? data : null;
    } catch (e) {
      return null;
    } finally {
      clearTimeout(timer);
    }
  }

  async function breachPrefix(msg) {
    const prefix = typeof msg.prefix === "string" ? msg.prefix.toUpperCase() : "";
    if (!BREACH_PREFIX_RE.test(prefix)) return { ok: false, error: "bad_prefix" };
    const data = await getJson(`/api/v1/breach/check/${prefix}`);
    if (!data) return { ok: false, error: "unavailable" };
    const rows = Array.isArray(data.suffixes) ? data.suffixes : [];
    const suffixes = [];
    for (const row of rows) {
      const suffix = row && typeof row.suffix === "string" ? row.suffix.toUpperCase() : "";
      if (SUFFIX_RE.test(suffix) && Number.isInteger(row.count) && row.count >= 0) suffixes.push({ suffix, count: row.count });
    }
    return { ok: true, suffixes };
  }

  async function verifiedHosts(msg) {
    const brand = typeof msg.brand === "string" ? msg.brand.toLowerCase() : "";
    if (!BRAND_RE.test(brand)) return { ok: false, error: "bad_brand" };
    if (brandHosts.has(brand)) return { ok: true, hosts: brandHosts.get(brand) };
    const data = await getJson(`/api/v1/credentials/verified?brand=${encodeURIComponent(brand)}`);
    if (!data) return { ok: false, error: "unavailable" };
    const hosts = (Array.isArray(data.hosts) ? data.hosts : [])
      .filter((h) => typeof h === "string" && h)
      .map((h) => h.toLowerCase())
      .slice(0, MAX_BRAND_HOSTS);
    brandHosts.set(brand, hosts);
    return { ok: true, hosts };
  }

  return function handlePageLookup(msg, sender, respond) {
    if (!msg || (msg.type !== "BREACH_PREFIX" && msg.type !== "VERIFIED_HOSTS")) return undefined;
    if (!isWebPageSender(sender)) {
      respond({ ok: false, error: "bad_sender" });
      return false;
    }
    const work = msg.type === "BREACH_PREFIX" ? breachPrefix(msg) : verifiedHosts(msg);
    work.then(respond).catch(() => {
      try { respond({ ok: false, error: "unavailable" }); } catch (e) { /* port closed */ }
    });
    return true;
  };
}

/**
 * Sentry event PII scrubber — TypeScript twin of api/services/sentry_scrubber.py.
 *
 * Same redaction philosophy: walk the event tree and replace any leaf
 * string that matches a known PII pattern. Always-redact keys take
 * precedence. Wired into every Sentry init (client / server / edge)
 * via `beforeSend` and `beforeBreadcrumb` hooks.
 *
 * Marketing copy says we are privacy-first; shipping raw user emails
 * + JWTs + Stripe IDs into Sentry contradicts that — Sentry retains
 * events up to 90 days and employees of Cleanway-the-business have
 * read access.
 */
import type { ErrorEvent, EventHint, Breadcrumb, BreadcrumbHint } from "@sentry/nextjs";

interface PiiPattern {
  pattern: RegExp;
  replacement: string;
}

// Order matters — JWT must match BEFORE the generic Bearer header so
// the token gets replaced rather than the literal word "Bearer".
const PII_PATTERNS: PiiPattern[] = [
  {
    pattern: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
    replacement: "[redacted-jwt]",
  },
  {
    pattern: /Bearer\s+[A-Za-z0-9._\-+/=]{8,}/gi,
    replacement: "Bearer [redacted]",
  },
  {
    pattern: /(sk|pk|rk)_(live|test)_[A-Za-z0-9]{16,}/g,
    replacement: "[redacted-stripe-key]",
  },
  {
    pattern:
      /(cus|sub|pi|ch|cs|tok|re|in|seti|src|prod|price)_[A-Za-z0-9]{14,}/g,
    replacement: "[redacted-stripe-id]",
  },
  {
    pattern: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24}\b/g,
    replacement: "[redacted-email]",
  },
  {
    pattern: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi,
    replacement: "[redacted-uuid]",
  },
  {
    pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    replacement: "[redacted-ip]",
  },
  {
    pattern: /\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b/g,
    replacement: "[redacted-ip6]",
  },
];

const ALWAYS_REDACT_KEYS: ReadonlySet<string> = new Set([
  "password",
  "passwd",
  "secret",
  "api_key",
  "apikey",
  "access_token",
  "refresh_token",
  "auth_token",
  "authorization",
  "cookie",
  "set-cookie",
  "session",
  "supabase_service_key",
  "supabase_jwt_secret",
  "stripe_secret_key",
  "stripe_webhook_secret",
  "parental_pin",
  "parental_pin_hash",
  "pin",
  "recovery_code",
  "ssn",
  "credit_card",
  "card_number",
  "cvv",
  // Browsing context — the domain / URL a user is checking. Mirrors the
  // backend scrubber (api/services/sentry_scrubber.py) added in the 2026-07-01
  // audit BE-4 pass; the TypeScript twins were missed then. Cleanway's
  // privacy invariant is "even on breach, attackers learn nothing about
  // your online activity" — so a domain must never reach Sentry (a
  // third-party sink with 90-day retention + employee read access).
  "domain",
  "raw_url",
  "url",
  "hostname",
]);

function scrubString(s: string): string {
  let out = s;
  for (const { pattern, replacement } of PII_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  return out;
}

function scrub(node: unknown): unknown {
  if (typeof node === "string") {
    return scrubString(node);
  }
  if (Array.isArray(node)) {
    return node.map(scrub);
  }
  if (node !== null && typeof node === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      if (typeof k === "string" && ALWAYS_REDACT_KEYS.has(k.toLowerCase())) {
        out[k] = "[redacted]";
      } else {
        out[k] = scrub(v);
      }
    }
    return out;
  }
  return node;
}

/**
 * One-way hash of the user id so we still get "same user repeatedly"
 * correlation without leaking the auth.uid() itself.
 *
 * Uses Web Crypto SubtleDigest where available (browser, edge,
 * Node ≥ 19). Falls back to leaving the id intact if SubtleDigest is
 * absent — Sentry's downstream pipeline will just see the raw id;
 * losing the privacy property is preferable to crashing the scrubber.
 */
async function hashUserId(id: string): Promise<string> {
  try {
    const enc = new TextEncoder().encode(id);
    const buf = await crypto.subtle.digest("SHA-256", enc);
    const hex = Array.from(new Uint8Array(buf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    return "u_" + hex.slice(0, 16);
  } catch {
    return id;
  }
}

export function beforeSendScrub(event: ErrorEvent, _hint: EventHint): ErrorEvent | PromiseLike<ErrorEvent | null> | null {
  // user context: drop high-impact fields, hash the id (best-effort).
  if (event.user) {
    if (event.user.email) delete event.user.email;
    if (event.user.ip_address) delete event.user.ip_address;
    if (event.user.username) delete event.user.username;
    if (event.user.id) {
      // Sync attempt only — hashUserId returns a Promise, but
      // beforeSend is allowed to be sync-only. We let it be async via
      // PromiseLike — Sentry awaits.
      return hashUserId(String(event.user.id)).then((hashed) => {
        if (event.user) event.user.id = hashed;
        return scrub(event) as ErrorEvent;
      });
    }
  }
  return scrub(event) as ErrorEvent;
}

export function beforeBreadcrumbScrub(
  crumb: Breadcrumb,
  _hint?: BreadcrumbHint,
): Breadcrumb | null {
  return scrub(crumb) as Breadcrumb;
}

/**
 * Sentry PII scrubber — mobile twin of landing/lib/sentry-scrub.ts and
 * api/services/sentry_scrubber.py.
 *
 * Same redaction philosophy: walk the event tree and replace any leaf
 * string that matches a known PII pattern. Always-redact keys take
 * precedence. Wired into @sentry/react-native's Sentry.init() at app
 * boot via beforeSend + beforeBreadcrumb hooks.
 *
 * Marketing copy says we are privacy-first; shipping raw user emails
 * + JWTs + Stripe IDs into Sentry contradicts that — events retain
 * up to 90 days and employees of Cleanway-the-business have read
 * access.
 *
 * We use unknown / Record-shaped types here rather than the package's
 * own Event/ErrorEvent/Breadcrumb because @sentry/react-native's
 * runtime contract is "walk the tree, return the mutated/replaced
 * tree" — types aren't load-bearing for correctness, but they ARE
 * load-bearing for compile success across the various v6.x type
 * shape changes.
 */

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
]);

function scrubString(s: string): string {
  let out = s;
  for (const { pattern, replacement } of PII_PATTERNS) {
    out = out.replace(pattern, replacement);
  }
  return out;
}

export function scrub(node: unknown): unknown {
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
 * Sentry init's beforeSend takes whatever event shape the current
 * SDK version uses. We return either the scrubbed event (mutated
 * shallow) or null to drop. Cast to `any` only at the boundary so
 * the rest of the code stays type-safe.
 */
export function beforeSendScrub(event: unknown): unknown {
  if (event && typeof event === "object") {
    const e = event as Record<string, unknown>;
    const user = e.user as Record<string, unknown> | undefined;
    if (user) {
      delete user.email;
      delete user.ip_address;
      delete user.username;
    }
  }
  return scrub(event);
}

export function beforeBreadcrumbScrub(crumb: unknown): unknown {
  return scrub(crumb);
}

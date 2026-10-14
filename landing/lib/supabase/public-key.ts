/**
 * Which Supabase client key the site sends as `apikey` — mirrors
 * mobile/src/utils/supabase-key.ts.
 *
 * WHY TWO NAMES
 * Supabase is replacing the legacy anon key (an HS256 JWT signed with the
 * project's JWT secret) with a publishable key (`sb_publishable_…`, not a JWT).
 * The legacy JWT secret can only be revoked once no shipped client still
 * depends on the anon JWT. So the site reads
 * `NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY` first and falls back to
 * `NEXT_PUBLIC_SUPABASE_ANON_KEY`: setting the new variable in Vercel is the whole
 * migration, no code change.
 *
 * NOTHING HERE DECODES THE KEY AS A JWT TO ACCEPT IT
 * A publishable key has no payload; any "is this a JWT with role anon" check
 * would reject it (the e2e build even uses a made-up string). The key is
 * decoded only to REFUSE a service_role JWT, and
 * an `sb_secret_` key is refused by prefix — both are server-only secrets
 * that must never be inlined into a page bundle. Anything else (an anon JWT,
 * a publishable key, a format we don't know yet) is passed through.
 *
 * Kept free of Next/React so scripts/test-signup-flow.mjs can pin it.
 */

const PLACEHOLDER_MARKERS = [
  "YOUR_PROJECT",
  "YOUR_ANON_KEY",
  "YOUR_PUBLISHABLE_KEY",
  "example.supabase.co",
  // The literals shipped in .env.example. Without them, copying the
  // example to .env and forgetting to paste the real key produced a build that
  // LOOKED configured and failed every request with "Invalid API key", instead
  // of the honest "sign-in is unavailable in this build".
  "REPLACE_WITH_PUBLIC_ANON_KEY",
  "REPLACE_WITH_PUBLISHABLE_KEY",
];

/** Trimmed value, or "" for unset / an unedited placeholder. */
export function cleanSupabaseValue(v: string | undefined | null): string {
  const s = (v ?? "").trim();
  if (!s) return "";
  if (PLACEHOLDER_MARKERS.some((m) => s.includes(m))) return "";
  // An unexpanded "$EXPO_PUBLIC_…" / "$NEXT_PUBLIC_…" reference (a build
  // profile naming a variable that was never defined) is not a key.
  if (s.startsWith("$")) return "";
  return s;
}

export type SupabaseKeyKind = "publishable" | "legacy_jwt" | "secret" | "unknown";

/** The `role` claim of a JWT, or null when `key` is not a decodable JWT. */
function jwtRole(key: string): string | null {
  const parts = key.split(".");
  if (parts.length !== 3) return null;
  try {
    const b64 = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const payload = JSON.parse(atob(padded)) as { role?: unknown };
    return typeof payload.role === "string" ? payload.role : null;
  } catch {
    return null;
  }
}

export function supabaseKeyKind(key: string): SupabaseKeyKind {
  if (key.startsWith("sb_publishable_")) return "publishable";
  if (key.startsWith("sb_secret_")) return "secret";
  const role = jwtRole(key);
  if (role === "service_role") return "secret";
  if (role !== null) return "legacy_jwt";
  return "unknown";
}

/**
 * The key to send: the publishable one when set, else the legacy anon key.
 * A secret-flavoured value in either slot counts as unset — a build without
 * sign-in is recoverable, a service_role key in a public bundle is not.
 */
export function resolveSupabaseClientKey(candidates: {
  readonly publishable?: string | null;
  readonly anon?: string | null;
}): string {
  for (const raw of [candidates.publishable, candidates.anon]) {
    const key = cleanSupabaseValue(raw);
    if (key && supabaseKeyKind(key) !== "secret") return key;
  }
  return "";
}

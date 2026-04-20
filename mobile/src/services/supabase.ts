/**
 * Supabase configuration — single source of truth for URL + anon key.
 *
 * Values resolve from (in priority order):
 * 1. `EXPO_PUBLIC_SUPABASE_URL` / `EXPO_PUBLIC_SUPABASE_ANON_KEY` — inlined at
 *    build time via Expo's public-env mechanism (recommended for EAS builds).
 * 2. `Constants.expoConfig.extra.supabaseUrl` / `.supabaseAnonKey` — set via
 *    `app.config.ts` when you need per-environment overrides at runtime.
 * 3. Empty string fallback — the app boots but every auth call fails fast
 *    with a clear error. NEVER ship a build with empty values — CI must
 *    block any release where these are blank.
 *
 * Hardcoded placeholders (`"YOUR_PROJECT.supabase.co"`) are explicitly
 * considered unconfigured and rejected — this unblocks local dev while
 * catching the common pilot-error of forgetting to set env vars.
 */

import Constants from "expo-constants";

const PLACEHOLDER_MARKERS = [
  "YOUR_PROJECT",
  "YOUR_ANON_KEY",
  "example.supabase.co",
];

function cleanValue(v: string | undefined | null): string {
  const s = (v ?? "").trim();
  if (!s) return "";
  if (PLACEHOLDER_MARKERS.some((m) => s.includes(m))) return "";
  return s;
}

export const SUPABASE_URL: string = cleanValue(
  process.env.EXPO_PUBLIC_SUPABASE_URL ||
    (Constants.expoConfig?.extra?.supabaseUrl as string | undefined),
);

export const SUPABASE_ANON_KEY: string = cleanValue(
  process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY ||
    (Constants.expoConfig?.extra?.supabaseAnonKey as string | undefined),
);

export function isSupabaseConfigured(): boolean {
  return SUPABASE_URL.length > 0 && SUPABASE_ANON_KEY.length > 0;
}

export class SupabaseNotConfiguredError extends Error {
  constructor() {
    super(
      "Supabase URL or anon key is not configured. " +
        "Set EXPO_PUBLIC_SUPABASE_URL and EXPO_PUBLIC_SUPABASE_ANON_KEY in your environment or eas.json.",
    );
    this.name = "SupabaseNotConfiguredError";
  }
}

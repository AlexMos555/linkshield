/**
 * Supabase configuration — single source of truth for URL + client key.
 *
 * Values resolve from (in priority order):
 * 1. `EXPO_PUBLIC_SUPABASE_URL` and the client key — inlined at build time
 *    via Expo's public-env mechanism (recommended for EAS builds). The key is
 *    `EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY` (`sb_publishable_…`) when set,
 *    else the legacy `EXPO_PUBLIC_SUPABASE_ANON_KEY` JWT — see
 *    src/utils/supabase-key.ts for why both exist.
 * 2. `Constants.expoConfig.extra.supabaseUrl` / `.supabasePublishableKey` /
 *    `.supabaseAnonKey` — set via `app.config.ts` when you need
 *    per-environment overrides at runtime.
 * 3. Empty string fallback — the app boots but every auth call fails fast
 *    with a clear error. NEVER ship a build with empty values — CI must
 *    block any release where these are blank.
 *
 * Hardcoded placeholders (`"YOUR_PROJECT.supabase.co"`) are explicitly
 * considered unconfigured and rejected — this unblocks local dev while
 * catching the common pilot-error of forgetting to set env vars. So is a
 * server-only secret (`sb_secret_…`, a service_role JWT) pasted by mistake.
 */

import Constants from "expo-constants";
import { cleanSupabaseValue, resolveSupabaseClientKey } from "../utils/supabase-key";

const extra = Constants.expoConfig?.extra as
  | { supabaseUrl?: string; supabasePublishableKey?: string; supabaseAnonKey?: string }
  | undefined;

export const SUPABASE_URL: string = cleanSupabaseValue(
  process.env.EXPO_PUBLIC_SUPABASE_URL || extra?.supabaseUrl,
);

/**
 * The key sent as `apikey`. Named ANON for history; it holds the publishable
 * key whenever one is configured. Each `process.env.EXPO_PUBLIC_*` must stay a
 * literal member access — Metro inlines only that exact form.
 */
export const SUPABASE_ANON_KEY: string = resolveSupabaseClientKey({
  publishable: process.env.EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY || extra?.supabasePublishableKey,
  anon: process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY || extra?.supabaseAnonKey,
});

export function isSupabaseConfigured(): boolean {
  return SUPABASE_URL.length > 0 && SUPABASE_ANON_KEY.length > 0;
}

export class SupabaseNotConfiguredError extends Error {
  constructor() {
    super(
      "Supabase URL or client key is not configured. " +
        "Set EXPO_PUBLIC_SUPABASE_URL and EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY " +
        "(or the legacy EXPO_PUBLIC_SUPABASE_ANON_KEY) in your environment or eas.json.",
    );
    this.name = "SupabaseNotConfiguredError";
  }
}

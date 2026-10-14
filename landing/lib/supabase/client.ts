/**
 * Supabase client for browser-side code (client components).
 *
 * Reads NEXT_PUBLIC_SUPABASE_URL + the client key
 * (NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY, else NEXT_PUBLIC_SUPABASE_ANON_KEY)
 * from the environment at build time. Both must be set in Vercel for prod
 * and in .env.local for dev — falling back to empty strings here keeps
 * tsc / next build happy when the env is unconfigured.
 *
 * Storage: cookies (via @supabase/ssr) so SSR can also read the session.
 * That makes /pricing's checkout button see the same auth state as
 * /signup did when it logged the user in.
 */
"use client";

import { createBrowserClient } from "@supabase/ssr";

import { resolveSupabaseClientKey } from "./public-key";

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL || "";
// Publishable key (sb_publishable_…) preferred, legacy anon JWT as fallback —
// lib/supabase/public-key.ts. Both reads stay literal so Next inlines them.
const SUPABASE_ANON_KEY = resolveSupabaseClientKey({
  publishable: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY,
  anon: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
});

let _client: ReturnType<typeof createBrowserClient> | null = null;

export function getSupabaseClient() {
  if (!_client) {
    _client = createBrowserClient(SUPABASE_URL, SUPABASE_ANON_KEY);
  }
  return _client;
}

/**
 * Returns true when build-time env vars are present. Use to gate UI
 * that depends on auth — render a "soon" placeholder until Supabase is
 * configured rather than a broken form.
 */
export function isAuthConfigured(): boolean {
  return Boolean(SUPABASE_URL && SUPABASE_ANON_KEY);
}

/**
 * The project URL and the PUBLIC client key (publishable or legacy anon), for
 * the extension connect page: the extension needs it to refresh its own session at
 * <project>/auth/v1/token. Both are already in every page's bundle.
 */
export function supabasePublicConfig(): { url: string; anonKey: string } {
  return { url: SUPABASE_URL, anonKey: SUPABASE_ANON_KEY };
}

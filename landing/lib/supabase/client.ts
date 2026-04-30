/**
 * Supabase client for browser-side code (client components).
 *
 * Reads NEXT_PUBLIC_SUPABASE_URL + NEXT_PUBLIC_SUPABASE_ANON_KEY from
 * the environment at build time. Both must be set in Vercel for prod
 * and in .env.local for dev — falling back to empty strings here keeps
 * tsc / next build happy when the env is unconfigured.
 *
 * Storage: cookies (via @supabase/ssr) so SSR can also read the session.
 * That makes /pricing's checkout button see the same auth state as
 * /signup did when it logged the user in.
 */
"use client";

import { createBrowserClient } from "@supabase/ssr";

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL || "";
const SUPABASE_ANON_KEY = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || "";

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

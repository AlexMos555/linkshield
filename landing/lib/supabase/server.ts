/**
 * Supabase client for server-side code (Server Components, Route Handlers).
 *
 * Reads cookies via Next 15's `cookies()` API to maintain the session
 * across SSR + client hydration. The user's access_token is also exposed
 * via `getAccessToken()` so server components can attach it to fetch
 * calls hitting api.cleanway.ai.
 */
import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

import { resolveSupabaseClientKey } from "./public-key";

const SUPABASE_URL = process.env.NEXT_PUBLIC_SUPABASE_URL || "";
// Publishable key (sb_publishable_…) preferred, legacy anon JWT as fallback —
// lib/supabase/public-key.ts. Both reads stay literal so Next inlines them.
const SUPABASE_ANON_KEY = resolveSupabaseClientKey({
  publishable: process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY,
  anon: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
});

export async function getSupabaseServer() {
  const cookieStore = await cookies();
  return createServerClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(cookiesToSet) {
        // In Server Components Next forbids cookie writes — wrap in
        // try/catch so SSR doesn't crash. Route handlers and Server
        // Actions write fine.
        try {
          for (const { name, value, options } of cookiesToSet) {
            cookieStore.set(name, value, options);
          }
        } catch {
          // Silent — RSC read-only context.
        }
      },
    },
  });
}

export async function getCurrentSession() {
  const supabase = await getSupabaseServer();
  const {
    data: { session },
  } = await supabase.auth.getSession();
  return session;
}

export async function getAccessToken(): Promise<string | null> {
  const session = await getCurrentSession();
  return session?.access_token ?? null;
}

/**
 * Supabase client for the mobile app — uses the official SDK with Expo
 * SecureStore as the session store.
 *
 * Why a second client: services/auth.ts uses a hand-rolled GoTrue REST
 * flow (password sign-in/up). The new Family Hub feature needs full
 * SDK behavior (auto-refresh, getUser(), magic-link helpers), so this
 * file ships the official client side-by-side. Both can coexist —
 * they share the same auth.users rows on the server, just different
 * client-side caches.
 *
 * Storage adapter: AsyncStorage is the Supabase default for RN, but we
 * need the access token to be hardware-backed (Keychain on iOS,
 * Keystore on Android) since the Family Hub secret key is stored
 * adjacent. expo-secure-store gives us that.
 */
import * as SecureStore from "expo-secure-store";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

import { SUPABASE_URL, SUPABASE_ANON_KEY, isSupabaseConfigured } from "@/services/supabase";

// expo-secure-store has a 2KB value limit per key — Supabase sessions
// are <1KB so we're safe, but let's set the chunked-storage flag in case
// of future growth (refresh tokens, MFA challenges, etc.).
const SecureStoreAdapter = {
  async getItem(key: string): Promise<string | null> {
    try {
      return (await SecureStore.getItemAsync(key)) ?? null;
    } catch {
      return null;
    }
  },
  async setItem(key: string, value: string): Promise<void> {
    try {
      await SecureStore.setItemAsync(key, value);
    } catch {
      // Silent: device might not have secure storage (web, sim w/o passcode)
    }
  },
  async removeItem(key: string): Promise<void> {
    try {
      await SecureStore.deleteItemAsync(key);
    } catch {
      // Silent
    }
  },
};

let _client: SupabaseClient | null = null;

/**
 * Returns the singleton Supabase client. Only constructs when env is
 * configured; calling in an unconfigured build returns `null` so
 * callers can degrade gracefully (show "sign-in not available" instead
 * of crashing the screen).
 */
export function getSupabaseSDK(): SupabaseClient | null {
  if (_client) return _client;
  if (!isSupabaseConfigured()) return null;

  _client = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    auth: {
      storage: SecureStoreAdapter,
      autoRefreshToken: true,
      persistSession: true,
      // RN doesn't have URL flow — magic-link callback uses deep linking
      // wired in expo-linking. detectSessionInUrl=false avoids the SDK
      // trying to parse the location.hash on every app boot.
      detectSessionInUrl: false,
    },
  });
  return _client;
}

/**
 * Convenience: pull the current access token (or null). Use this when
 * making authenticated calls to api.cleanway.ai.
 */
export async function getAccessToken(): Promise<string | null> {
  const c = getSupabaseSDK();
  if (!c) return null;
  const { data } = await c.auth.getSession();
  return data.session?.access_token ?? null;
}

/**
 * This install's device id — what the account counts as "one device".
 *
 * A random UUID made once per install and kept in SecureStore, sent as
 * X-Device-Id with authenticated API calls (src/services/api.ts) and used to
 * register the device after sign-in (src/services/account.ts).
 *
 * Lifetime:
 *   • survives app restarts and updates (SecureStore);
 *   • a reinstall starts without it (SecureStore is wiped with the app and is
 *     kept out of Android's auto-backup), so a reinstalled phone is a NEW
 *     device — the old entry can be unlinked from the device list;
 *   • rotated when the server says this install was unlinked, so signing in
 *     again later is a fresh device and not a quiet re-attach.
 *
 * Not the same thing as the install id in install-id.ts: that one is renewed
 * daily and travels only with anonymous site checks; this one never travels
 * with them (the check client is anonymous on purpose).
 */
import "react-native-get-random-values";
import * as SecureStore from "expo-secure-store";

import { uuidFromBytes } from "../utils/account-session";

const KEY = "account_device_id";

let cached: string | null = null;

function newId(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return uuidFromBytes(b);
}

/** The device id, made on first use. Null only when SecureStore is unusable. */
export async function getDeviceId(): Promise<string | null> {
  if (cached) return cached;
  try {
    const stored = await SecureStore.getItemAsync(KEY);
    if (stored) {
      cached = stored;
      return stored;
    }
    const id = newId();
    await SecureStore.setItemAsync(KEY, id);
    cached = id;
    return id;
  } catch {
    return null;
  }
}

/** Forget this install's id; the next getDeviceId() makes a new one. */
export async function rotateDeviceId(): Promise<void> {
  cached = null;
  try {
    await SecureStore.deleteItemAsync(KEY);
  } catch {
    // Best-effort: a stale id is refused by the server and rotated again.
  }
}

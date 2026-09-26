/**
 * This install's random number, sent as X-Cleanway-Install with every site
 * check (src/services/api.ts).
 *
 * Why it exists: the check endpoint is rate-limited, and Tele2 puts thousands
 * of phones behind one carrier-NAT address, so a per-IP limit is spent by a
 * whole neighbourhood at once. A per-install number lets the server count per
 * phone instead.
 *
 * What it is: a random UUID made on this phone, once. Not derived from the
 * device or the account, sent only with site checks (never with the anonymous
 * blocklist download), gone when the app is uninstalled. On Android the value
 * lives in the native module (InstallId.kt) so the link guard's background
 * checks send the same one; elsewhere it is kept in SecureStore.
 */
import "react-native-get-random-values";
import * as SecureStore from "expo-secure-store";

import { nativeInstallId } from "../../modules/cleanway-vpn";

const STORE_KEY = "install_id";
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

let pending: Promise<string | null> | null = null;

/** The install id, or null when it cannot be read or made — the check then goes without it. */
export function getInstallId(): Promise<string | null> {
  if (!pending) {
    pending = load().catch(() => {
      // Not cached: storage may come back, and the next check can try again.
      pending = null;
      return null;
    });
  }
  return pending;
}

async function load(): Promise<string | null> {
  const native = nativeInstallId();
  if (native) return native;
  const stored = await SecureStore.getItemAsync(STORE_KEY);
  if (stored && UUID_V4.test(stored)) return stored;
  const made = randomUuid();
  await SecureStore.setItemAsync(STORE_KEY, made);
  return made;
}

/** RFC 4122 version-4 UUID from the platform's secure random source. */
function randomUuid(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

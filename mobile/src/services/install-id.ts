/**
 * This install's random number, sent as X-Cleanway-Install with every site
 * check (src/services/api.ts).
 *
 * Why it exists: the check endpoint is rate-limited, and Tele2 puts thousands
 * of phones behind one carrier-NAT address, so a per-IP limit is spent by a
 * whole neighbourhood at once. A per-install number lets the server count per
 * phone instead.
 *
 * What it is: a random UUID made on this phone, not derived from the device or
 * the account, sent only with site checks (never with the anonymous blocklist
 * download), and replaced by a new one every day — the limit counts per hour,
 * and the server can never tie more than a day of checks together.
 *
 * On Android the native module keeps it (InstallId.kt: renewed daily, stored
 * where Android's backup never copies it), so the link guard's background
 * checks send the same number. Elsewhere it lives only in memory: a new one
 * each time the app starts, and each day it keeps running.
 */
import "react-native-get-random-values";

import { nativeInstallId } from "../../modules/cleanway-vpn";

const RENEW_AFTER_MS = 24 * 60 * 60 * 1000;

let inMemory: { id: string; madeAt: number } | null = null;

/** The install id, or null when it cannot be made — the check then goes without it. */
export async function getInstallId(): Promise<string | null> {
  const native = nativeInstallId();
  if (native) return native;
  try {
    const now = Date.now();
    if (!inMemory || now - inMemory.madeAt >= RENEW_AFTER_MS || now < inMemory.madeAt) {
      inMemory = { id: randomUuid(), madeAt: now };
    }
    return inMemory.id;
  } catch {
    return null;
  }
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

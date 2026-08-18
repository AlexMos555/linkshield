import { Platform } from "react-native";

/** One entry of the DNS shield's persisted block log (see BlockLog.kt). */
export interface ShieldRow {
  domain: string;
  ts: number;
  kind: "blocked" | "warned";
}

interface ShieldLogModule {
  recentShieldBlocks(limit?: number): ShieldRow[];
}

/**
 * Read the shield's block log. Android-only; the native module is required
 * lazily so a platform without it (iOS today, Expo Go) simply reports none.
 */
export function recentShieldBlocks(limit = 100): ShieldRow[] {
  if (Platform.OS !== "android") return [];
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const mod = require("../../modules/cleanway-vpn") as ShieldLogModule;
    return mod.recentShieldBlocks(limit) ?? [];
  } catch {
    return [];
  }
}

import { Platform } from "react-native";

/** One entry of the DNS shield's persisted block log (see BlockLog.kt). */
export interface ShieldRow {
  domain: string;
  ts: number;
  /**
   * "blocked": the query got NXDOMAIN — the site never opened.
   * "warned": the verdict arrived after the first lookup had been forwarded.
   * "allowed": the person said "not a scam" and rescued it.
   */
  kind: "blocked" | "warned" | "allowed";
}

interface ShieldLogModule {
  recentShieldBlocks(limit?: number): ShieldRow[];
  allowedDomains(): string[];
  allowDomain(domain: string): boolean;
  removeAllowedDomain(domain: string): void;
}

function shieldModule(): ShieldLogModule | null {
  if (Platform.OS !== "android") return null;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require("../../modules/cleanway-vpn") as ShieldLogModule;
  } catch {
    return null;
  }
}

/** Sites the person marked "not a scam" — shown and revocable in Settings. */
export function allowedSites(): string[] {
  try {
    return shieldModule()?.allowedDomains() ?? [];
  } catch {
    return [];
  }
}

/** Mark a site as not-a-scam (from a block row / the notification action). */
export function allowSite(domain: string): boolean {
  try {
    return shieldModule()?.allowDomain(domain) ?? false;
  } catch {
    return false;
  }
}

/** Undo an allow — the site can be blocked again. */
export function removeAllowedSite(domain: string): void {
  try {
    shieldModule()?.removeAllowedDomain(domain);
  } catch {
    /* not available on this platform */
  }
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

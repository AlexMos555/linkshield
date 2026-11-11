import { Platform } from "react-native";

/** One entry of the shields' persisted block log (see BlockLog.kt). */
export interface ShieldRow {
  domain: string;
  ts: number;
  /**
   * "blocked": the site never opened (DNS refused it, or the link guard
   * stopped the tapped link).
   * "warned": the link guard let the link open; its site was flagged after.
   * "allowed": the person said "not a scam" and rescued it.
   */
  kind: "blocked" | "warned" | "allowed";
  /** Which shield acted: "dns" (All apps) or "link" (Link checking); null for allows. */
  source?: "dns" | "link" | null;
}

/** The module itself, so a name it does not export cannot type-check here (test-no-vpn-names.mjs). */
type ShieldLogModule = typeof import("../../modules/cleanway-vpn");

/**
 * Outside any try block on purpose: Metro keeps the path of a require()
 * written in one, even in a release bundle (test-no-vpn-names.mjs).
 */
// eslint-disable-next-line @typescript-eslint/no-require-imports
const requireShieldModule = () => require("../../modules/cleanway-vpn") as ShieldLogModule;

function shieldModule(): ShieldLogModule | null {
  if (Platform.OS !== "android") return null;
  try {
    return requireShieldModule();
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

/** Mark a site as not-a-scam (History's detail sheet, behind its scam-warning confirm). */
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
    const mod = requireShieldModule();
    return mod.recentShieldBlocks(limit) ?? [];
  } catch {
    return [];
  }
}

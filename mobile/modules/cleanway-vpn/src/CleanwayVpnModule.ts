import { NativeModule, requireNativeModule } from 'expo';

import { BlocklistStatus, CleanwayVpnModuleEvents, ShieldBlockEntry } from './CleanwayVpn.types';

declare class CleanwayVpnModule extends NativeModule<CleanwayVpnModuleEvents> {
  /** Requests VPN consent (once) then starts the local DNS-filter VPN. Resolves false if the user declines. */
  startVpn(): Promise<boolean>;
  /** Tears the VPN tunnel down. */
  stopVpn(): Promise<void>;
  openVpnSettings(): boolean;
  /** True while the tunnel is active (reflects real service state). */
  isRunning(): boolean;
  /**
   * Epoch millis of the last canary query the service answered with NXDOMAIN,
   * 0 if it never has. The shield's proof of life — see verifyFiltering().
   * Optional so an app running against an older native build degrades to
   * "unverified" instead of crashing.
   */
  /**
   * Monotonic count of canary queries the service has answered. Compared by
   * delta in verifyFiltering() — see that function for why it is a counter
   * and not a timestamp. Optional so an app running against an older native
   * build degrades to "unverified" instead of crashing.
   */
  canaryAnswerCount?(): number;
  /** True if the user last chose ON. Optional: older native builds lack it. */
  wasUserEnabled?(): boolean;
  /**
   * Hostname of the device's strict Private DNS provider, or null when the
   * setting is Off/Automatic. Strict + our tunnel = no DNS for any app.
   */
  privateDnsStrictHost?(): string | null;
  /** Opens the settings screen where Private DNS lives. */
  openPrivateDnsSettings?(): boolean;
  /** Persisted block log, newest first. Optional: older native builds lack it. */
  recentBlocks?(limit: number): ShieldBlockEntry[];
  /** Number of block-log entries with ts >= sinceMs. */
  blockCountSince?(sinceMs: number): number;
  /** Lifetime totals per kind — {blocked, warned, allowed}. */
  blockLifetimeCounts?(): { blocked?: number; warned?: number; allowed?: number };
  /** Loaded blocklist + freshness. Optional: older native builds lack it. */
  blocklistStatus?(): BlocklistStatus;
  /** Fetch the list now (background). */
  refreshBlocklist?(): void;
  /** Monotonic count of list-canary answers — proof the loaded list is live. */
  listCanaryAnswerCount?(): number;
  /** Sites the person marked "not a scam". */
  allowedDomains?(): string[];
  allowDomain?(domain: string): boolean;
  removeAllowedDomain?(domain: string): void;
}

export default requireNativeModule<CleanwayVpnModule>('CleanwayVpn');

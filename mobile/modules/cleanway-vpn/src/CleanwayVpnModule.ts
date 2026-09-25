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
  /** Open a URL in a real (non-Cleanway) browser. False if none available. */
  openInBrowser?(url: string): boolean;
  /** True when Cleanway is the default web-link handler (browser role). */
  /** Persist the chosen UI locale for native notifications. */
  setNotificationLocale?(code: string): void;
  isDefaultLinkHandler?(): boolean;
  /** Ask the OS to make Cleanway the default link handler. */
  requestLinkHandler?(): Promise<boolean>;
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
  /**
   * On-device check of a message's text. Raw native shape — index.ts
   * validates it into a MessageAnalysis. Optional: older native builds lack it.
   */
  analyzeMessage?(text: string): Promise<Record<string, unknown>>;
  /** The blocklisted suffix covering this host (DNS rules), or null. */
  matchBlocklist?(host: string): Promise<string | null>;
  /** A blocklist exists for the link guard: the shield's, or a synced copy on disk. */
  linkListAvailable?(): Promise<boolean>;
  /** This APK's manifest requests RECEIVE_SMS: the RuStore build. Optional: older native builds lack it. */
  smsAutoSupported?(): boolean;
  /** How the app was installed. Raw shape — index.ts validates it into an InstallSource. */
  installSource?(): Record<string, unknown>;
  /** The automatic SMS check's state. Raw shape — index.ts validates it into an SmsShieldStatus. */
  smsShieldStatus?(): Record<string, unknown>;
  /** Turn the automatic SMS check on or off (the receiver component). False in the browser APK. */
  setSmsShieldEnabled?(enabled: boolean): boolean;
  /** Ask for RECEIVE_SMS; resolves true when granted. */
  requestSmsPermission?(): Promise<boolean>;
  /** SMS the automatic check flagged, newest first. Raw shape — index.ts validates each one. */
  recentSmsEvents?(limit: number): unknown[];
  /** This app's page in system Settings (permissions, "Allow restricted settings", battery). */
  openAppDetailsSettings?(): boolean;
  /** Where the SMS warnings can be switched back on: our channel's page, or the app's notification page. */
  openSmsNotificationSettings?(): boolean;
}

export default requireNativeModule<CleanwayVpnModule>('CleanwayVpn');

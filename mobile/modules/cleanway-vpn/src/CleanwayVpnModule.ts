import { NativeModule, requireNativeModule } from 'expo';

import { BlocklistStatus, CallStatePayload, CleanwayVpnModuleEvents, ShieldBlockEntry } from './CleanwayVpn.types';

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
  /** Why protection last stopped by itself ("revoked" | "private_dns"), null when not known. */
  lastStopReason?(): string | null;
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
  /** A blocklist exists for the link guard: the shield's, a synced copy on disk, or the bundled seed. */
  linkListAvailable?(): Promise<boolean>;
  /** Pause blocking until this epoch-ms time; the tunnel stays up and resumes by itself. */
  pauseProtection?(untilMs: number): void;
  /** End a timed pause now. */
  resumeProtection?(): void;
  /** End of the current pause (epoch ms), 0 when not paused. */
  pausedUntil?(): number;
  /** This install's random id, sent as X-Cleanway-Install with site checks. */
  installId?(): string;
  /** False when the person switched Cleanway's notifications off. */
  notificationsEnabled?(): boolean;
  /** Open this app's system notification settings. */
  openNotificationSettings?(): boolean;
  /** Is the person on the phone, and when did the last call end? Optional: older native builds lack it. */
  callState?(): CallStatePayload;
  /** The app saw something the after-call notice should name (CallGuard.kt). */
  noteCallEvent?(kind: string): void;
  /** Bring the phone app (its in-call screen) to the front. */
  showInCallScreen?(): boolean;
  /** The saved "close one" number, or null. Kept on the phone only. */
  closeContactPhone?(): string | null;
  /** Save (or clear with null) the "close one" number; false when not dialable. */
  setCloseContactPhone?(phone: string | null): boolean;
  /** Open the phone app on the saved number; false when none is saved. */
  dialCloseContact?(): boolean;
}

export default requireNativeModule<CleanwayVpnModule>('CleanwayVpn');

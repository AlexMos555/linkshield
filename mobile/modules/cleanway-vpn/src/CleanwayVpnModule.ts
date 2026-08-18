import { NativeModule, requireNativeModule } from 'expo';

import { CleanwayVpnModuleEvents } from './CleanwayVpn.types';

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
}

export default requireNativeModule<CleanwayVpnModule>('CleanwayVpn');

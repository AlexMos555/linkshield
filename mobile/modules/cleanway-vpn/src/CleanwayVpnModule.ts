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
  lastCanaryAnswerAtMs?(): number;
}

export default requireNativeModule<CleanwayVpnModule>('CleanwayVpn');

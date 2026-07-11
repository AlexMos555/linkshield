import { NativeModule, requireNativeModule } from 'expo';

import { CleanwayVpnModuleEvents } from './CleanwayVpn.types';

declare class CleanwayVpnModule extends NativeModule<CleanwayVpnModuleEvents> {
  /** Requests VPN consent (once) then starts the local DNS-filter VPN. Resolves false if the user declines. */
  startVpn(): Promise<boolean>;
  /** Tears the VPN tunnel down. */
  stopVpn(): Promise<void>;
  /** True while the tunnel is active (reflects real service state). */
  isRunning(): boolean;
}

export default requireNativeModule<CleanwayVpnModule>('CleanwayVpn');

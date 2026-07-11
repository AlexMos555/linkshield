import { registerWebModule, NativeModule } from 'expo';

import { CleanwayVpnModuleEvents } from './CleanwayVpn.types';

// Web has no VPN — provide a no-op so the JS API is uniform across platforms.
class CleanwayVpnModule extends NativeModule<CleanwayVpnModuleEvents> {
  async startVpn(): Promise<boolean> {
    return false;
  }
  async stopVpn(): Promise<void> {}
  isRunning(): boolean {
    return false;
  }
}

export default registerWebModule(CleanwayVpnModule);

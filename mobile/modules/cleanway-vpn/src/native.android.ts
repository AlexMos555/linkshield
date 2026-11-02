import { requireNativeModule } from 'expo';

import type { NativeShieldModule, NativeSubscription, ShieldService, ShieldStoppedPayload } from './CleanwayVpn.types';

/**
 * Android: the Kotlin module (android/.../CleanwayVpnModule.kt). Metro picks
 * this file for Android builds only; iOS and web get ./native.ts, so nothing
 * in an iPhone build asks for a native module the iPhone does not have.
 *
 * Kotlin names its start/stop calls, its settings screen and its stop event
 * after Android's VPN. This file is the only place in the shared code that
 * says those names (mobile/scripts/test-no-vpn-names.mjs): everything else
 * goes through ShieldService. The calls into Kotlin stay exactly as they were.
 */
interface KotlinShieldCalls {
  startVpn(): Promise<boolean>;
  stopVpn(): Promise<void>;
  isRunning(): boolean;
  openVpnSettings(): boolean;
  /** KeepAlivePolicy.Rearm in lower case. Optional: older native builds lack it. */
  rearmShield?(): string;
  addListener(event: 'onVpnStopped', listener: (p: ShieldStoppedPayload) => void): NativeSubscription;
}

const CleanwayVpn = requireNativeModule<NativeShieldModule & KotlinShieldCalls>('CleanwayVpn');

/** Every neutral call goes straight to the Kotlin module. */
const NativeShield: NativeShieldModule = CleanwayVpn;
export default NativeShield;

export const shieldService: ShieldService = {
  start: () => CleanwayVpn.startVpn(),
  stop: () => CleanwayVpn.stopVpn(),
  running: () => CleanwayVpn.isRunning(),
  openSystemSettings: () => CleanwayVpn.openVpnSettings(),
  rearm: () => {
    const decision = CleanwayVpn.rearmShield?.();
    return decision === 'other_vpn' ? 'other_tunnel' : decision;
  },
  addStoppedListener: (listener) => CleanwayVpn.addListener('onVpnStopped', listener),
};

import type { NativeShieldModule, ShieldService } from './CleanwayVpn.types';

/**
 * iPhone and web: this module is Android-only (expo-module.config.json), so
 * there is no native side to ask for — requireNativeModule would throw at
 * launch, and the app imports index.ts at launch (src/i18n, app/_layout.tsx).
 * None of the module's calls exist here; index.ts answers each one "not on
 * this platform", and a subscription is one that never fires. Android builds
 * get ./native.android.ts instead (Metro's platform extensions).
 */
const NativeShield: NativeShieldModule = {
  addListener: () => ({ remove() {} }),
};
export default NativeShield;

/** No shield to start, nothing running, no settings screen for it, never stopped. */
export const shieldService: ShieldService = {
  start: async () => false,
  stop: async () => {},
  running: () => false,
  openSystemSettings: () => false,
  rearm: () => undefined,
  addStoppedListener: () => ({ remove() {} }),
};

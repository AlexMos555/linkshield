import type { CleanwayVpnNativeModule } from './CleanwayVpn.types';

/**
 * iPhone and web: this module is Android-only (expo-module.config.json), so
 * there is no native side to ask for — requireNativeModule would throw at
 * launch, and the app imports index.ts at launch (src/i18n, app/_layout.tsx).
 * None of the calls exist here; index.ts answers each one "not on this
 * platform", and a subscription is one that never fires. Android builds get
 * ./native.android.ts instead (Metro's platform extensions).
 */
const native: CleanwayVpnNativeModule = {
  addListener: () => ({ remove() {} }),
};

export default native;

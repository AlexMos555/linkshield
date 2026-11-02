import { requireNativeModule } from 'expo';

import type { CleanwayVpnNativeModule } from './CleanwayVpn.types';

/**
 * Android: the Kotlin module (android/.../CleanwayVpnModule.kt) itself. Metro
 * picks this file for Android builds only; iOS and web get ./native.ts, so
 * nothing in an iPhone build asks for a native module the iPhone does not have.
 */
export default requireNativeModule<CleanwayVpnNativeModule>('CleanwayVpn');

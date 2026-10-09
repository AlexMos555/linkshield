import { Platform } from 'react-native';
import { requireOptionalNativeModule } from 'expo';

import { NO_SAFARI_EXTENSION, parseSafariFacts, type SafariExtensionFacts } from '../../src/utils/platform-features';

/**
 * The Safari Web Extension's status (iPhone only). Native half:
 * ios/CleanwaySafariModule.swift. What each field means and how the home
 * card turns them into a status: src/utils/platform-features.ts
 * (SafariExtensionFacts, safariLayerState).
 */
export type SafariExtensionStatus = SafariExtensionFacts;
export const NOT_BUNDLED = NO_SAFARI_EXTENSION;

interface NativeSafari {
  getStatus(): Promise<Record<string, unknown>>;
  openSettings(): Promise<boolean>;
}

// Optional: Android and web have no such module, and an app built before the
// module existed must not crash on launch.
const native = Platform.OS === 'ios' ? requireOptionalNativeModule<NativeSafari>('CleanwaySafari') : null;

export async function getSafariExtensionStatus(): Promise<SafariExtensionStatus> {
  if (!native) return NOT_BUNDLED;
  try {
    return parseSafariFacts(await native.getStatus());
  } catch {
    return NOT_BUNDLED;
  }
}

/** Opens the extension's page in Settings (iOS 26.2+). False where iOS cannot. */
export async function openSafariExtensionSettings(): Promise<boolean> {
  if (!native) return false;
  try {
    return (await native.openSettings()) === true;
  } catch {
    return false;
  }
}

import { Platform } from 'react-native';
import { requireOptionalNativeModule } from 'expo';

import { NO_SAFARI_EXTENSION, parseSafariFacts, type SafariExtensionFacts } from '../../src/utils/platform-features';

/**
 * The Safari Web Extension's status (iPhone only). Native half:
 * ios/CleanwaySafariModule.swift. What each field means and how the home
 * card turns them into a status: src/utils/platform-features.ts
 * (SafariExtensionFacts, safariLayerState).
 *
 * Also the in-app web sheet (ASWebAuthenticationSession) the sign-in
 * captcha opens on iPhone instead of switching to Safari: app/auth.tsx
 * hands these functions to src/services/captcha.ts as its AuthSheet.
 */
export type SafariExtensionStatus = SafariExtensionFacts;
export const NOT_BUNDLED = NO_SAFARI_EXTENSION;

interface NativeSafari {
  getStatus(): Promise<Record<string, unknown>>;
  openSettings(): Promise<boolean>;
  // Absent in binaries built before the in-app captcha sheet existed.
  openAuthSession?(url: string, callbackScheme: string): Promise<string | null>;
  cancelAuthSession?(): Promise<void>;
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

/** Can this build open a web page in the in-app sheet? iPhone builds with the native half only. */
export function authSessionAvailable(): boolean {
  return typeof native?.openAuthSession === 'function';
}

/**
 * Opens the https [url] in an in-app sheet (ASWebAuthenticationSession) that
 * closes itself as soon as the page navigates to `<callbackScheme>://…` and
 * resolves that URL. Null when the person closed the sheet, it could not
 * open, or this build has no sheet. Never rejects.
 */
export async function openAuthSession(url: string, callbackScheme: string): Promise<string | null> {
  if (!native?.openAuthSession) return null;
  try {
    const returned = await native.openAuthSession(url, callbackScheme);
    return typeof returned === 'string' && returned ? returned : null;
  } catch {
    return null;
  }
}

/** Dismisses the sheet if one is open (its openAuthSession resolves null). */
export function cancelAuthSession(): void {
  native?.cancelAuthSession?.().catch(() => undefined);
}

import { Platform } from 'react-native';
import { requireOptionalNativeModule } from 'expo';

/**
 * The app's side of the iPhone scam-text filter (docs/IOS.md §5). The filter
 * itself is the CleanwaySmsFilter extension (plugins/withSmsFilter.js), which
 * checks each SMS from an unknown sender on the phone, offline.
 *
 * Optional native module: an Android build, or an iOS build older than the
 * filter, has none — every function then answers "no".
 */
interface CleanwaySmsFilterNative {
  isInstalled(): boolean;
  setRemoteConfig(json: string): boolean;
}

const Native: CleanwaySmsFilterNative | null =
  Platform.OS === 'ios' ? requireOptionalNativeModule<CleanwaySmsFilterNative>('CleanwaySmsFilter') : null;

/**
 * This build carries the filter extension. NOT "the filter is on": Apple gives
 * an app no way to know whether the person enabled it in Settings.
 */
export function smsFilterInstalled(): boolean {
  try {
    return Native?.isInstalled() ?? false;
  } catch {
    return false;
  }
}

/**
 * Leave the server's switches for the on-device text model (the update
 * check's `remote_config`, serialised by src/lib/remote-config.ts) in the app
 * group, where the filter extension reads them for every message. False when
 * nothing was stored (not iOS, an older build, not a config); the switches
 * stored before stay in force.
 */
export function setSmsFilterRemoteConfig(json: string): boolean {
  try {
    return Native?.setRemoteConfig(json) ?? false;
  } catch {
    return false;
  }
}

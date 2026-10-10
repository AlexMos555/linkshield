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
  /** The filter's engine on one message, in the app (newer builds only). */
  analyzeMessage?(text: string): Promise<unknown>;
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

/**
 * This iPhone build can run the scam-text engine inside the app (the in-app
 * "Check a text message"). False on Android, web and iOS builds from before
 * the engine was linked into the app.
 */
export function iosMessageCheckSupported(): boolean {
  try {
    return typeof Native?.analyzeMessage === 'function';
  } catch {
    return false;
  }
}

/**
 * The engine's raw answer for one message (the same wire shape as Android's
 * MessageCheck), or undefined when this build has no engine. Throws when the
 * engine failed; the caller turns that into "couldn't check", never "fine".
 */
export async function analyzeMessageOnIos(text: string): Promise<unknown> {
  return Native?.analyzeMessage ? Native.analyzeMessage(text) : undefined;
}

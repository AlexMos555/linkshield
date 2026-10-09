/**
 * Expo Router's hook for URLs the system opens the app with.
 *
 * The iOS share extension (expo-share-intent) hands a shared link or text to
 * the app by opening `cleanway://dataUrl=cleanwayShareKey…`; the shared data
 * itself waits in the app group, where ShareIntentProvider (app/_layout.tsx)
 * reads it. Expo Router treated that URL as a route and showed "Unmatched
 * Route" instead of the check (found on the iOS simulator, 2026-10-09). Such a
 * URL now lands on the home screen, and ShareIntentRouter takes the person on
 * to the link or message check. Android hands shares over as an intent, not a
 * URL, so nothing changes there. Every other URL is routed as before.
 */
import { getShareExtensionKey } from "expo-share-intent";

export function redirectSystemPath({ path }: { path: string; initial: boolean }): string {
  try {
    if (path.includes(`dataUrl=${getShareExtensionKey()}`)) return "/";
    return path;
  } catch {
    // Never strand the person on a broken route because of a malformed URL.
    return "/";
  }
}

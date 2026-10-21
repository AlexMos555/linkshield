import { useEffect, useRef } from "react";
import { AccessibilityInfo, Platform } from "react-native";

/**
 * Say a status out loud to VoiceOver when it changes — "Checking…", then
 * "Dangerous — google-login.top". A screen reader does not notice on its own
 * that a spinner became a verdict.
 *
 * iOS only: on Android the same container carries
 * accessibilityLiveRegion, and TalkBack reads that by itself — announcing
 * here too would make it speak twice. Pass null when there is nothing to say.
 */
export function useAnnounce(message: string | null | undefined): void {
  const last = useRef<string | null>(null);
  useEffect(() => {
    if (!message) {
      // Cleared: the same words may be said again the next time they show.
      last.current = null;
      return;
    }
    if (message === last.current) return;
    last.current = message;
    if (Platform.OS === "ios") AccessibilityInfo.announceForAccessibility(message);
  }, [message]);
}

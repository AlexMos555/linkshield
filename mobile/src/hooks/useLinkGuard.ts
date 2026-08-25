/**
 * useLinkGuard — is Cleanway the phone's default link handler?
 *
 * The link guard (LinkGuardActivity) is the exact SMS-phishing defense the
 * Tele2 cohort is sold: when Cleanway is the default handler, a tapped link
 * opens Cleanway first, which checks it and forwards safe ones instantly. But
 * that only works if the user actually granted the role, so the home card must
 * reflect the REAL system state — never a placebo "on". `isDefaultLinkHandler()`
 * is a live check against Android's RoleManager, so a green card here is honest.
 *
 * Android only (the role + activity don't exist on iOS). We re-check on focus
 * so returning from the system default-apps dialog updates the card at once.
 */
import { useCallback, useState } from "react";
import { Platform } from "react-native";
import { useFocusEffect } from "expo-router";

import { isDefaultLinkHandler, requestLinkHandler } from "../../modules/cleanway-vpn";

export interface LinkGuardStatus {
  available: boolean; // Android + a native build new enough to expose the API
  on: boolean; // Cleanway IS the default link handler right now
  enable: () => Promise<void>;
}

export function useLinkGuard(): LinkGuardStatus {
  const available = Platform.OS === "android";
  const [on, setOn] = useState(false);

  const refresh = useCallback(() => {
    if (!available) return;
    try {
      setOn(isDefaultLinkHandler());
    } catch {
      // Older native build without the API → treat as not-default (offer setup).
      setOn(false);
    }
  }, [available]);

  useFocusEffect(refresh);

  const enable = useCallback(async () => {
    if (!available) return;
    try {
      await requestLinkHandler();
    } catch {
      // User dismissed the system dialog, or the API is unavailable — leave the
      // card in its setup state; nothing to surface.
    }
    // The role grant lands after the system dialog closes; re-check shortly
    // after so the card flips to "on" without needing a manual refresh.
    setTimeout(refresh, 800);
  }, [available, refresh]);

  return { available, on, enable };
}

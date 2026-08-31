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

import {
  isDefaultLinkHandler,
  isLinkHandlerSupported,
  requestLinkHandler,
} from "../../modules/cleanway-vpn";

export interface LinkGuardStatus {
  /** Android AND a version where holding the role can actually be verified. */
  available: boolean;
  /** Cleanway IS the default link handler right now (live system check). */
  on: boolean;
  enable: () => Promise<void>;
  /** Open the system default-apps screen — the only way to hand the role back. */
  manage: () => Promise<void>;
}

export function useLinkGuard(): LinkGuardStatus {
  // Android 7-9 has no RoleManager, so we cannot verify the role. Rather than
  // park a permanently-failing "Set up" button on those phones, the card is
  // hidden there — unverifiable is not the same as off, and neither may be
  // dressed up as protection.
  const [available] = useState(() => {
    if (Platform.OS !== "android") return false;
    try {
      return isLinkHandlerSupported();
    } catch {
      return false; // older native build without the API
    }
  });
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

  // There is no API to RELEASE the browser role, so the honest exit is the
  // system screen where the user can hand it to another app. Without this the
  // card was a one-way door: on, with no way back from inside the app.
  const manage = useCallback(async () => {
    if (!available) return;
    try {
      await requestLinkHandler();
    } catch {
      // dialog dismissed / unavailable — nothing to surface
    }
    setTimeout(refresh, 800);
  }, [available, refresh]);

  return { available, on, enable, manage };
}

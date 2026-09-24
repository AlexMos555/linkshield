import { useCallback, useEffect, useState } from "react";
import { AppState, Platform } from "react-native";
import { useFocusEffect } from "expo-router";

import { isDefaultLinkHandler, isVpnRunning } from "../../modules/cleanway-vpn";

export interface ProtectionActive {
  /** A shield exists on this platform (Android). */
  available: boolean;
  /** Something can block right now: the network shield is running, or the link guard holds the browser role. */
  active: boolean;
}

function readActive(): boolean {
  if (Platform.OS !== "android") return false;
  return isVpnRunning() || isDefaultLinkHandler();
}

/**
 * Is anything able to block right now? For History's empty state, which must
 * not say "nothing blocked yet" to someone whose protection is off.
 *
 * Plain synchronous reads of real system state — the service's running flag
 * and the live RoleManager check — re-read on focus and on foreground. No
 * canary probe: proving that filtering works is the home screen's job, and a
 * second probe here would only duplicate it. Read at first render too, so the
 * screen never flashes "protection is off" at someone whose shield is on.
 */
export function useProtectionActive(): ProtectionActive {
  const [available] = useState(() => Platform.OS === "android");
  const [active, setActive] = useState(readActive);

  const refresh = useCallback(() => setActive(readActive()), []);

  useFocusEffect(refresh);

  useEffect(() => {
    const sub = AppState.addEventListener("change", (state) => {
      if (state === "active") refresh();
    });
    return () => sub.remove();
  }, [refresh]);

  return { available, active };
}

/**
 * useKeepAlive — what keeps the network shield running with the app closed:
 * the battery exemption, the phone maker's own battery manager, block
 * alerts, Always-on VPN (src/utils/keep-alive.ts holds the rows).
 *
 * Re-read on focus, on every return to the foreground (the person comes
 * back from a system settings screen, where these switches live) and when
 * the shield's own state changes (Always-on is readable only while it runs).
 */
import { useCallback, useEffect, useState } from "react";
import { AppState, Platform } from "react-native";
import { useFocusEffect } from "expo-router";

import {
  keepAliveStatus,
  notificationsEnabled,
  openOemBackgroundSettings,
  openVpnSettings,
  requestBatteryExemption,
  turnOnBlockNotifications,
  type KeepAliveStatus,
} from "../../modules/cleanway-vpn";

const UNKNOWN: KeepAliveStatus = { batteryUnrestricted: null, alwaysOn: null, oem: null };

export interface KeepAlive {
  status: KeepAliveStatus;
  /** Block alerts will be heard; null when this build cannot tell. */
  notifications: boolean | null;
  requestBattery: () => void;
  openOemSettings: () => void;
  turnOnNotifications: () => Promise<void>;
  openAlwaysOn: () => void;
  refresh: () => void;
}

/** [shieldKey] changes whenever the shield's state does, so Always-on is re-read when it can be. */
export function useKeepAlive(shieldKey: string): KeepAlive {
  const [status, setStatus] = useState<KeepAliveStatus>(UNKNOWN);
  const [notifications, setNotifications] = useState<boolean | null>(null);

  const refresh = useCallback(() => {
    if (Platform.OS !== "android") return;
    setStatus(keepAliveStatus());
    setNotifications(notificationsEnabled());
  }, []);

  useFocusEffect(useCallback(() => {
    refresh();
    const sub = AppState.addEventListener("change", (next) => {
      if (next === "active") refresh();
    });
    return () => sub.remove();
  }, [refresh]));

  useEffect(() => {
    refresh();
  }, [shieldKey, refresh]);

  const requestBattery = useCallback(() => {
    // The dialog (or settings screen) returns through AppState "active".
    requestBatteryExemption();
  }, []);

  const openOemSettings = useCallback(() => {
    openOemBackgroundSettings();
  }, []);

  const turnOnNotifications = useCallback(async () => {
    await turnOnBlockNotifications();
    setNotifications(notificationsEnabled());
  }, []);

  const openAlwaysOn = useCallback(() => {
    openVpnSettings();
  }, []);

  return { status, notifications, requestBattery, openOemSettings, turnOnNotifications, openAlwaysOn, refresh };
}

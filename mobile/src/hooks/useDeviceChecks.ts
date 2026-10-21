/**
 * Part 1 of "Проверка защиты": what this phone can tell about its own
 * protection, read live, with the one fix each problem has.
 *
 * Built from the same sources as the home screen and Settings — the shield
 * hook, the link-guard role check, the notification switch — plus the
 * battery restriction. No new permissions: each value is the app's own.
 */
import { useCallback, useState } from "react";
import { AppState } from "react-native";
import { useFocusEffect, useRouter } from "expo-router";
import { useTranslation } from "react-i18next";

import {
  backgroundRestricted, notificationsEnabled, openAppSettings, turnOnBlockNotifications,
} from "../../modules/cleanway-vpn";
import { deviceChecks, type DeviceCheck, type FixAction } from "../utils/checkup";
import { clockTime } from "../utils/relative-time";
import { useLinkGuard } from "./useLinkGuard";
import { useNetworkShield } from "./useNetworkShield";

export interface DeviceChecks {
  rows: DeviceCheck[];
  fix: (action: FixAction) => void;
}

export function useDeviceChecks(): DeviceChecks {
  const router = useRouter();
  const { i18n } = useTranslation();
  const network = useNetworkShield();
  const linkGuard = useLinkGuard();
  const [alertsOn, setAlertsOn] = useState<boolean | null>(() => notificationsEnabled());
  const [restricted, setRestricted] = useState<boolean | null>(() => backgroundRestricted());

  const reread = useCallback(() => {
    setAlertsOn(notificationsEnabled());
    setRestricted(backgroundRestricted());
  }, []);

  // On focus AND on return from system settings, where both switches live:
  // the screen stays focused while the person is over there.
  useFocusEffect(useCallback(() => {
    reread();
    const sub = AppState.addEventListener("change", (next) => {
      if (next === "active") reread();
    });
    return () => sub.remove();
  }, [reread]));

  const rows = deviceChecks({
    shield: network.available
      ? {
          state: network.state,
          probing: network.probing,
          interrupted: network.interrupted,
          pausedTime: clockTime(network.pausedUntil, i18n.language),
          privateDnsHost: network.privateDnsHost,
          list: network.blocklist,
        }
      : null,
    linkGuard: linkGuard.available ? { on: linkGuard.on } : null,
    alertsOn,
    backgroundRestricted: restricted,
  });

  const { resume, openPrivateDnsSettings, refreshBlocklist } = network;
  const { enable: enableLinkGuard } = linkGuard;
  const fix = useCallback((action: FixAction) => {
    switch (action) {
      case "shield_on":
        // The home screen owns the turn-on flow and its disclosure (Play
        // requires it before Android's own VPN dialog) — one copy, not two.
        router.navigate({ pathname: "/", params: { setup: "1" } });
        return;
      case "shield_resume":
        resume();
        return;
      case "private_dns":
        openPrivateDnsSettings();
        return;
      case "links_on":
        void enableLinkGuard();
        return;
      case "alerts_on":
        void turnOnBlockNotifications().then(reread);
        return;
      case "battery":
        openAppSettings();
        return;
      case "list_refresh":
        refreshBlocklist();
        return;
    }
  }, [router, resume, openPrivateDnsSettings, refreshBlocklist, enableLinkGuard, reread]);

  return { rows, fix };
}

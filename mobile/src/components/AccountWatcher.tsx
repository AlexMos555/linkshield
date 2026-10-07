import { useEffect } from "react";
import { Alert, AppState } from "react-native";
import { useRouter } from "expo-router";
import { useTranslation } from "react-i18next";

import { getSessionState, startSessionKeeper } from "../services/auth";
import { deviceRevokedEvents } from "../services/api";
import { accountEvents, heartbeatIfDue, signOutUnlinkedDevice } from "../services/account";

/**
 * App-wide account upkeep, mounted once in app/_layout.tsx:
 *   • keeps the session fresh (refresh ahead of expiry, on foreground);
 *   • links / heartbeats this phone while signed in (at most every 6 h);
 *   • no free device seat → opens the Account screen in "unlink one" mode;
 *   • this phone was unlinked elsewhere (403 device_revoked on any call) →
 *     signs out here, makes a new device id, and says so plainly.
 */
export function AccountWatcher() {
  const router = useRouter();
  const { t } = useTranslation();

  useEffect(() => startSessionKeeper(), []);

  useEffect(() => {
    let alive = true;
    const beat = () => {
      void (async () => {
        const st = await getSessionState();
        if (alive && st.kind === "ok") await heartbeatIfDue();
      })();
    };
    beat();
    const sub = AppState.addEventListener("change", (next) => {
      if (next === "active") beat();
    });
    return () => {
      alive = false;
      sub.remove();
    };
  }, []);

  useEffect(() => {
    let handling = false;
    const onRevokedCall = () => {
      if (handling) return;
      handling = true;
      void signOutUnlinkedDevice().finally(() => {
        handling = false;
      });
    };
    const onRevoked = () => {
      Alert.alert(t("mobile.account.revoked_title"), t("mobile.account.revoked_body"));
    };
    const onLimit = () => {
      router.push({ pathname: "/account", params: { limit: "1" } });
    };
    deviceRevokedEvents.on("revoked", onRevokedCall);
    accountEvents.on("revoked", onRevoked);
    accountEvents.on("limit", onLimit);
    return () => {
      deviceRevokedEvents.off("revoked", onRevokedCall);
      accountEvents.off("revoked", onRevoked);
      accountEvents.off("limit", onLimit);
    };
  }, [router, t]);

  return null;
}

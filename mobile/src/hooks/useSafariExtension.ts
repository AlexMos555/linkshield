import { useCallback, useEffect, useState } from "react";
import { AppState, Linking, Platform } from "react-native";

import {
  NOT_BUNDLED,
  getSafariExtensionStatus,
  openSafariExtensionSettings,
  type SafariExtensionStatus,
} from "../../modules/cleanway-safari";
import { SAFARI_TEST_URL, SAFARI_TEST_URL_FALLBACK, safariLayerState } from "../utils/platform-features";

/**
 * The Safari Web Extension's layer on the iPhone home card. Re-read every
 * time the app comes back to the foreground: the setup happens in Settings
 * and in Safari, and the card should say "On" the moment the person returns.
 */
export function useSafariExtension() {
  const [facts, setFacts] = useState<SafariExtensionStatus>(NOT_BUNDLED);

  const refresh = useCallback(async () => {
    if (Platform.OS !== "ios") return;
    setFacts(await getSafariExtensionStatus());
  }, []);

  useEffect(() => {
    if (Platform.OS !== "ios") return undefined;
    refresh();
    const sub = AppState.addEventListener("change", (state) => {
      if (state === "active") refresh();
    });
    return () => sub.remove();
  }, [refresh]);

  /** True when iOS opened the extension's own Settings page (iOS 26.2+). */
  const openSettings = useCallback(() => openSafariExtensionSettings(), []);

  /** Opens cleanway.ai in Safari, where the extension reports that it runs. */
  const openTestPage = useCallback(async () => {
    try {
      await Linking.openURL(SAFARI_TEST_URL);
    } catch {
      // iOS 16 and older do not know x-safari-https; Safari is the default
      // browser for nearly everyone there anyway.
      await Linking.openURL(SAFARI_TEST_URL_FALLBACK).catch(() => {});
    }
  }, []);

  return {
    facts,
    layer: safariLayerState(facts, Date.now()),
    /** iOS 26.2+ can open the extension's Settings page directly. */
    canOpenSettings: facts.bundled && facts.stateKnown,
    refresh,
    openSettings,
    openTestPage,
  };
}

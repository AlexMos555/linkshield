/**
 * useSmsShield — the automatic check of every incoming SMS (RuStore build).
 *
 * The check itself is native: a receiver in its own process reads each SMS as
 * it arrives, checks it on the phone and warns with a notification. The app
 * only turns it on and off and tells the truth about it. That truth comes
 * from the phone every time (smsShieldStatus(): permission, receiver,
 * notifications, battery), re-read on focus and on every return to the app —
 * the person fixes things in system Settings, and the card must show the
 * result the moment they come back.
 *
 * Turning it on (docs/PRIVACY.md, "Automatic SMS check"):
 *  1. our own disclosure first, in plain words: checked on the phone, the text
 *     is never sent or kept, a warning if it looks like a scam — before the
 *     first request (a retry after a refusal or the restricted-settings steps
 *     goes straight to Android: the person has read it);
 *  2. Android's SMS dialog. Refused where Android will not ask again
 *     (Android 15+ "restricted settings"; a second no or "don't ask again";
 *     an installer that never allowed SMS for this app) → step-by-step help
 *     to allow it in App info, since no tap inside the app can. A first "no"
 *     in the dialog is respected: the card still offers "Turn on";
 *  3. Android 13+'s notification dialog — a check that cannot warn is not
 *     protection, and the card says so if it is refused;
 *  4. the switch, then a fresh read.
 *
 * In every other build (the APK from cleanway.ai, iOS) `supported` is false
 * and every action is a no-op: the app never offers a switch that cannot work.
 */
import { useCallback, useEffect, useState } from "react";
import { Alert, AppState, Platform } from "react-native";
import { useFocusEffect } from "expo-router";
import { useTranslation } from "react-i18next";

import {
  SMS_SHIELD_UNSUPPORTED,
  askNotificationPermission,
  openAppDetailsSettings,
  openSmsNotificationSettings,
  requestBlockNotificationPermission,
  requestSmsPermission,
  setSmsShieldEnabled,
  smsAutoSupported,
  smsShieldStatus,
  type SmsShieldStatus,
} from "../../modules/cleanway-vpn";
import {
  isSmsShieldVerified,
  smsShieldAction,
  smsShieldView,
  type SmsShieldView,
} from "../utils/sms-shield-view";

export interface SmsShield {
  /** This build checks incoming SMS by itself (the RuStore APK). Fixed for the app's lifetime. */
  supported: boolean;
  status: SmsShieldStatus;
  view: SmsShieldView;
  /** Counts toward the hero: every link of the chain holds (see sms-shield-view.ts). */
  verified: boolean;
  /** An Android dialog or Settings trip is in flight; taps are ignored meanwhile. */
  busy: boolean;
  /** The disclosure, Android's dialogs, then the switch. */
  turnOn: () => void;
  /** Ask, then switch the check off. The permission stays, so turning it back on is one tap. */
  confirmPause: () => void;
  /** The current state's one action (sms-shield-view.ts smsShieldAction). */
  fix: () => void;
}

/** Android 15: "restricted settings" cover SMS from here on (SmsPermissionState.RESTRICTED_FROM_SDK). */
const RESTRICTED_FROM_SDK = 35;

function readStatus(supported: boolean): SmsShieldStatus {
  return supported ? smsShieldStatus() : SMS_SHIELD_UNSUPPORTED;
}

export function useSmsShield(): SmsShield {
  const { t } = useTranslation();
  const [supported] = useState(smsAutoSupported);
  const [status, setStatus] = useState<SmsShieldStatus>(() => readStatus(supported));
  const [busy, setBusy] = useState(false);

  const refresh = useCallback((): SmsShieldStatus => {
    const next = readStatus(supported);
    setStatus(next);
    return next;
  }, [supported]);

  useFocusEffect(useCallback(() => {
    refresh();
  }, [refresh]));

  useEffect(() => {
    if (!supported) return;
    const sub = AppState.addEventListener("change", (s) => {
      // Back from App info / notification settings: show what changed there.
      if (s === "active") refresh();
    });
    return () => sub.remove();
  }, [supported, refresh]);

  const offerSettings = useCallback((title: string, body: string, open: () => void) => {
    Alert.alert(title, body, [
      { text: t("mobile.shield.disclosure.cancel"), style: "cancel" },
      { text: t("mobile.shield.sms_auto.open_settings"), onPress: open },
    ]);
  }, [t]);

  /** Permission held: ask for notifications (13+), flip the switch, read back. */
  const switchOn = useCallback(async () => {
    // The answer is read back through the status, not used here: a refusal
    // leaves the check running and the card saying warnings cannot show.
    await requestBlockNotificationPermission();
    if (!setSmsShieldEnabled(true)) {
      Alert.alert(t("mobile.shield.sms_auto.enable_failed_title"), t("mobile.shield.sms_auto.enable_failed_body"));
    }
    refresh();
  }, [t, refresh]);

  /**
   * Whether a refusal needs help is read from Android's own answer after it
   * (canAskAgain), not guessed from how fast it came: on the emulator a
   * silent refusal took an activity round trip, as long as a quick "no".
   */
  const askAndSwitchOn = useCallback(async () => {
    setBusy(true);
    try {
      const granted = await requestSmsPermission();
      if (granted) {
        await switchOn();
        return;
      }
      const after = refresh();
      if (after.permission === "restricted_maybe") {
        offerSettings(
          t("mobile.shield.sms_auto.restricted_title"),
          t("mobile.shield.sms_auto.restricted_body"),
          () => void openAppDetailsSettings(),
        );
      } else if (!after.canAskAgain) {
        // On Android 15+ this can also be the restriction on a store install
        // (whether RuStore's are exempt is not known): name that step too, so
        // the person is not sent to a switch that is locked.
        const body = Platform.OS === "android" && Platform.Version >= RESTRICTED_FROM_SDK
          ? `${t("mobile.shield.sms_auto.denied_restricted_hint")}\n\n${t("mobile.shield.sms_auto.denied_body")}`
          : t("mobile.shield.sms_auto.denied_body");
        offerSettings(t("mobile.shield.sms_auto.denied_title"), body, () => void openAppDetailsSettings());
      }
      // Otherwise the person said no in Android's dialog: respected. The card
      // says access was not given and still offers "Turn on".
    } finally {
      setBusy(false);
    }
  }, [t, refresh, switchOn, offerSettings]);

  const turnOn = useCallback(() => {
    if (!supported || busy) return;
    // Already allowed (a pause, or allowed in Settings): no Android dialog is
    // coming, so there is nothing to explain before it.
    if (status.permission === "granted") {
      void switchOn();
      return;
    }
    // Asked before: the person read the explanation and is trying again
    // (after a refusal, or after the restricted-settings steps).
    if (status.permission !== "not_requested") {
      void askAndSwitchOn();
      return;
    }
    Alert.alert(
      t("mobile.shield.sms_auto.disclosure_title"),
      t("mobile.shield.sms_auto.disclosure_body"),
      [
        { text: t("mobile.shield.disclosure.cancel"), style: "cancel" },
        { text: t("mobile.shield.disclosure.continue"), onPress: () => void askAndSwitchOn() },
      ],
      { cancelable: true },
    );
  }, [supported, busy, status.permission, t, switchOn, askAndSwitchOn]);

  const confirmPause = useCallback(() => {
    if (!supported) return;
    Alert.alert(
      t("mobile.shield.sms_auto.pause_confirm_title"),
      t("mobile.shield.sms_auto.pause_confirm_body"),
      [
        { text: t("mobile.settings.clear_cancel"), style: "cancel" },
        {
          text: t("mobile.shield.sms_auto.pause_confirm_action"),
          style: "destructive",
          onPress: () => {
            setSmsShieldEnabled(false);
            refresh();
          },
        },
      ],
    );
  }, [supported, t, refresh]);

  /**
   * Warnings cannot show. Ask Android first where it still can (13+); a "no"
   * in that dialog is respected. Android refusing to ask again, or a switch
   * the dialog does not cover (the app's own, our channel), sends the person
   * to the screen that holds it.
   */
  const fixNotifications = useCallback(async () => {
    setBusy(true);
    try {
      const answer = await askNotificationPermission();
      if (refresh().notificationsEnabled) return;
      if (answer !== "denied") openSmsNotificationSettings();
    } finally {
      setBusy(false);
    }
  }, [refresh]);

  const view = smsShieldView(status);

  const fix = useCallback(() => {
    if (!supported || busy) return;
    switch (smsShieldAction(view)) {
      case "enable":
      case "request_sms":
        turnOn();
        return;
      case "open_app_settings":
        openAppDetailsSettings();
        return;
      case "open_notifications":
        void fixNotifications();
        return;
      case null:
        return;
    }
  }, [supported, busy, view, turnOn, fixNotifications]);

  return { supported, status, view, verified: isSmsShieldVerified(view), busy, turnOn, confirmPause, fix };
}

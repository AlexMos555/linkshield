/**
 * Account actions shared by Settings and the Account screen.
 *
 * Delete account (Google Play requires it in apps that have accounts):
 * confirm → DELETE /api/v1/user/account (cancels a Stripe plan at once and
 * starts the 30-day grace) → sign out here. The server refuses — and deletes
 * nothing — when the subscription can't be cancelled; the person is told to
 * try again instead of being signed out of an account that still exists.
 *
 * A plan bought in Google Play (or the App Store) is NOT cancelled by
 * deleting the account: only the person can cancel a store subscription, in
 * the store — the app cannot. So before the usual confirmation, a paid store
 * plan gets its own question: open Google Play's subscriptions page, or
 * delete anyway (docs/runbooks/revenuecat.md §8).
 */
import { Alert, Linking } from "react-native";
import Constants from "expo-constants";
import type { TFunction } from "i18next";

import { deleteAccount, getEntitlement, type EntitlementResponse } from "./api";
import { signOut } from "./auth";
import { rotateDeviceId } from "./device-id";
import { clearKeypair } from "../lib/family-crypto";
import { manageUrlFor, playSubscriptionsUrl, storeSubscriptionToCancel } from "../utils/store-billing";

const ANDROID_PACKAGE = Constants.expoConfig?.android?.package ?? "ai.cleanway.app";
const APP_STORE_SUBSCRIPTIONS_URL = "https://apps.apple.com/account/subscriptions";

export async function signOutEverywhereLocal(): Promise<void> {
  await signOut();
  try {
    // The Family E2E secret key leaves with the account (see Settings).
    await clearKeypair();
  } catch {
    // Best-effort: the key is device-scoped; the account is gone.
  }
}

/**
 * Ask, delete, sign out. `onDeleted` runs after the local sign-out. [known]
 * is the plan the screen already has; without it the plan is read first.
 */
export function confirmDeleteAccount(
  t: TFunction,
  onDeleted: () => void,
  known?: EntitlementResponse | null,
): void {
  void (async () => {
    let ent = known ?? null;
    if (!ent) {
      // Offline: no store notice can be decided — the delete itself will
      // fail and say so, deleting nothing.
      ent = (await getEntitlement().catch(() => ({ data: null }))).data ?? null;
    }
    const store = storeSubscriptionToCancel(ent);
    if (!store) {
      askDelete(t, onDeleted);
      return;
    }
    const storeName = store === "google_play" ? "Google Play" : "App Store";
    // "play" = accept only a store's own page, whatever build this is.
    const url =
      manageUrlFor(ent, "play") ??
      (store === "google_play" ? playSubscriptionsUrl(ANDROID_PACKAGE) : APP_STORE_SUBSCRIPTIONS_URL);
    Alert.alert(
      t("mobile.account.delete_store_title", { store: storeName }),
      t("mobile.account.delete_store_body", { store: storeName }),
      [
        { text: t("mobile.settings.clear_cancel"), style: "cancel" },
        {
          text: t("mobile.account.delete_store_open", { store: storeName }),
          onPress: () => void Linking.openURL(url).catch(() => undefined),
        },
        {
          text: t("mobile.account.delete_store_continue"),
          style: "destructive",
          onPress: () => askDelete(t, onDeleted),
        },
      ],
    );
  })();
}

function askDelete(t: TFunction, onDeleted: () => void): void {
  Alert.alert(t("mobile.account.delete_confirm_title"), t("mobile.account.delete_confirm_body"), [
    { text: t("mobile.settings.clear_cancel"), style: "cancel" },
    {
      text: t("mobile.account.delete_confirm"),
      style: "destructive",
      onPress: () => {
        void (async () => {
          const { error } = await deleteAccount();
          if (error) {
            Alert.alert(t("mobile.account.delete_failed_title"), t("mobile.account.delete_failed_body"));
            return;
          }
          // Signs RevenueCat out too (services/auth.ts → store-billing.ts).
          await signOutEverywhereLocal();
          // A later sign-in with the same email (to restore within 30 days)
          // is a fresh device, not this one.
          await rotateDeviceId();
          Alert.alert(t("mobile.account.delete_done_title"), t("mobile.account.delete_done_body"));
          onDeleted();
        })();
      },
    },
  ]);
}

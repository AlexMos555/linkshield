/**
 * Account actions shared by Settings and the Account screen.
 *
 * Delete account (Google Play requires it in apps that have accounts):
 * confirm → DELETE /api/v1/user/account (cancels a Stripe plan at once and
 * starts the 30-day grace) → sign out here. The server refuses — and deletes
 * nothing — when the subscription can't be cancelled; the person is told to
 * try again instead of being signed out of an account that still exists.
 */
import { Alert } from "react-native";
import type { TFunction } from "i18next";

import { deleteAccount } from "./api";
import { signOut } from "./auth";
import { rotateDeviceId } from "./device-id";
import { clearKeypair } from "../lib/family-crypto";

export async function signOutEverywhereLocal(): Promise<void> {
  await signOut();
  try {
    // The Family E2E secret key leaves with the account (see Settings).
    await clearKeypair();
  } catch {
    // Best-effort: the key is device-scoped; the account is gone.
  }
}

/** Ask, delete, sign out. `onDeleted` runs after the local sign-out. */
export function confirmDeleteAccount(t: TFunction, onDeleted: () => void): void {
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

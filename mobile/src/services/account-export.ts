/**
 * "Download my data" on the Account screen — the right of access (GDPR
 * Art. 15, 152-FZ art. 14): GET /api/v1/user/export, written as a JSON file
 * to the app's cache and handed to the system share sheet (save to Files or
 * Drive, send by email). The next export overwrites the file, and the system
 * may clear the cache directory.
 *
 * expo-sharing and expo-file-system are required lazily, so a build whose
 * native half is missing them shares the text itself instead of crashing.
 */
import { Alert, Share } from "react-native";
import type { TFunction } from "i18next";

import { exportAccountData } from "./api";

/** cleanway-data-2026-10-22.json — the date the copy was made (UTC). */
export function exportFileName(now: Date): string {
  return `cleanway-data-${now.toISOString().slice(0, 10)}.json`;
}

export async function downloadAccountData(t: TFunction): Promise<void> {
  const { data, error } = await exportAccountData();
  if (!data) {
    // An unlinked phone: the app-wide listener signs it out (services/api.ts).
    if (error.kind === "forbidden" && error.code === "device_revoked") return;
    Alert.alert(
      t("mobile.account.export_failed_title"),
      t(error.kind === "rate_limited" ? "mobile.account.export_rate_limited" : "mobile.account.export_failed_body"),
    );
    return;
  }
  const text = JSON.stringify(data, null, 2);
  const title = t("mobile.account.export_share_title");
  if (await shareAsFile(text, exportFileName(new Date()), title)) return;
  await Share.share({ title, message: text }).catch(() => undefined);
}

async function shareAsFile(text: string, name: string, title: string): Promise<boolean> {
  try {
    const Sharing = require("expo-sharing") as typeof import("expo-sharing");
    const { File, Paths } = require("expo-file-system") as typeof import("expo-file-system");
    if (!(await Sharing.isAvailableAsync())) return false;
    const file = new File(Paths.cache, name);
    file.create({ overwrite: true });
    // Async since Expo SDK 58 (expo-file-system 58): without the await the
    // share sheet got an empty or half-written file, and a failed write
    // skipped the catch below instead of falling back to the text.
    await file.write(text);
    await Sharing.shareAsync(file.uri, { mimeType: "application/json", UTI: "public.json", dialogTitle: title });
    return true;
  } catch {
    return false;
  }
}

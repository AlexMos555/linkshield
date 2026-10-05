/**
 * Subscription reminders as local notifications (billing-reminders.ts
 * decides when and which; this file only hands them to the OS).
 *
 * Scheduled with a date trigger, so a grace reminder fires on day 3 with the
 * app closed. Never a link: the body says to open the Cleanway app, and the
 * tap opens the app itself. expo-notifications is loaded lazily and every
 * call is best effort — a phone that refused notifications simply gets none,
 * and the subscription card in the app says the same thing.
 */
import { Platform } from "react-native";

import { type Reminder, reminderCopyKeys } from "../utils/billing-reminders";

type NotificationsModule = typeof import("expo-notifications");

const CHANNEL_ID = "cleanway_subscription";

let channelReady = false;

function load(): NotificationsModule | null {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require("expo-notifications") as NotificationsModule;
  } catch {
    return null;
  }
}

async function ensureChannel(n: NotificationsModule, name: string): Promise<void> {
  if (channelReady || Platform.OS !== "android") return;
  try {
    await n.setNotificationChannelAsync(CHANNEL_ID, { name, importance: n.AndroidImportance.DEFAULT });
    channelReady = true;
  } catch {
    // Without a channel Android 8+ drops the notification; nothing else breaks.
  }
}

/**
 * Schedules [reminders]; returns the ids it managed to schedule. A reminder
 * whose time has come (the lapse notice) is shown at once.
 */
export async function scheduleReminders(
  reminders: readonly Reminder[],
  t: (key: string) => string,
  nowSec: number,
): Promise<string[]> {
  const n = load();
  if (!n || reminders.length === 0) return [];
  await ensureChannel(n, t("mobile.billing.reminder_channel"));
  const done: string[] = [];
  for (const r of reminders) {
    const keys = reminderCopyKeys(r.kind);
    const content = { title: t(keys.title), body: t(keys.body), data: { billing: r.kind } };
    const date = new Date(r.atSec * 1000);
    const trigger = r.atSec <= nowSec
      ? null
      : ({ type: n.SchedulableTriggerInputTypes.DATE, date, channelId: CHANNEL_ID } as Parameters<typeof n.scheduleNotificationAsync>[0]["trigger"]);
    try {
      await n.scheduleNotificationAsync({ identifier: r.id, content, trigger });
      done.push(r.id);
    } catch {
      // Permission refused, or the OS said no: skip this one.
    }
  }
  return done;
}

/** Cancels reminders scheduled earlier (ids from [scheduleReminders]). */
export async function cancelReminders(ids: readonly string[]): Promise<void> {
  const n = load();
  if (!n) return;
  for (const id of ids) {
    try {
      await n.cancelScheduledNotificationAsync(id);
    } catch {
      // Already fired or never existed.
    }
  }
}

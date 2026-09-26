import type { TFunction } from "i18next";

/** "Just now", "5 min ago", "Yesterday"… — for list rows. Empty for an unreadable time. */
export function relativeTime(ms: number, t: TFunction, now: number = Date.now()): string {
  if (!Number.isFinite(ms)) return "";
  const minutes = Math.max(0, Math.round((now - ms) / 60000));
  if (minutes < 1) return t("mobile.history.just_now");
  if (minutes < 60) return t("mobile.history.minutes_ago", { minutes });
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return t("mobile.history.hours_ago", { hours });
  const days = Math.floor(hours / 24);
  if (days === 1) return t("mobile.history.yesterday");
  if (days < 7) return t("mobile.history.days_ago", { days });
  return new Date(ms).toLocaleDateString();
}

/**
 * "24 September, 14:32" in the app's language — for a detail view, where
 * "3 days ago" alone is not enough to match an event to what the person did.
 * Falls back to the device format if this language has no locale data.
 */
export function absoluteTime(ms: number, language: string): string {
  if (!Number.isFinite(ms)) return "";
  const date = new Date(ms);
  try {
    return date.toLocaleString(language, { day: "numeric", month: "long", hour: "2-digit", minute: "2-digit" });
  } catch {
    return date.toLocaleString();
  }
}

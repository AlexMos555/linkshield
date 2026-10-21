/**
 * When the app reminds about the subscription, and with what words — pure,
 * pinned by scripts/test-billing-reminders.mjs.
 *
 * The rules (billing plan §2.5, A.10):
 *  - trial: once when 3 days are left, once on the last day;
 *  - grace: never "in the red" and never nagging — one reminder on days 1, 3,
 *    5 and 7 after the failed charge (the server's own retry days), at most
 *    four, none after the grace window;
 *  - lapsed: once, when protection actually changed;
 *  - never two reminders closer than [MIN_GAP_SEC] apart, whatever else is true;
 *  - a reminder NEVER carries a link. Scam SMS carry links; ours say "open the
 *    Cleanway app" and nothing a person could tap into. The test reads the
 *    generated locale files and fails on any URL in a reminder.
 *
 * The app schedules these as local notifications (billing-notify.ts), so they
 * fire with the app closed; the ids make a re-schedule replace, not duplicate.
 */
import type { BillingView } from "./billing-view";

const DAY = 86_400;

/** Days after the failed charge on which a grace reminder may be shown. */
export const GRACE_REMINDER_DAYS: readonly number[] = [1, 3, 5, 7];
/** The grace window the server grants (BILLING_GRACE_DAYS default); the first day is the failed charge. */
const GRACE_DAYS = 7;
/** Two reminders are never closer than this. */
export const MIN_GAP_SEC = 2 * DAY - 3600;
/** Reminders per subscription period, at most. */
export const MAX_PER_PERIOD = 4;

export type ReminderKind = "trial_ending" | "trial_last_day" | "grace" | "lapsed_basic" | "lapsed_off";

export interface Reminder {
  /** Stable: scheduling the same id again replaces the earlier one. */
  id: string;
  kind: ReminderKind;
  /** When to show it (unix seconds); never in the past. */
  atSec: number;
}

function trialReminders(endsAt: number, nowSec: number): Reminder[] {
  const out: Reminder[] = [];
  const threeDays = endsAt - 3 * DAY;
  const lastDay = endsAt - 1 * DAY;
  if (threeDays > nowSec) out.push({ id: `billing:trial:${endsAt}:3`, kind: "trial_ending", atSec: threeDays });
  if (lastDay > nowSec) out.push({ id: `billing:trial:${endsAt}:1`, kind: "trial_last_day", atSec: lastDay });
  return out;
}

function graceReminders(graceUntil: number, nowSec: number): Reminder[] {
  const start = graceUntil - GRACE_DAYS * DAY;
  return GRACE_REMINDER_DAYS
    .map((day) => ({ id: `billing:grace:${graceUntil}:${day}`, kind: "grace" as const, atSec: start + day * DAY }))
    .filter((r) => r.atSec > nowSec && r.atSec <= graceUntil)
    .slice(0, MAX_PER_PERIOD);
}

/** Keeps the first of any two reminders closer than [MIN_GAP_SEC]. */
export function spaced(reminders: readonly Reminder[]): Reminder[] {
  const sorted = [...reminders].sort((a, b) => a.atSec - b.atSec);
  return sorted.reduce<Reminder[]>((kept, r) => {
    const last = kept[kept.length - 1];
    return last && r.atSec - last.atSec < MIN_GAP_SEC ? kept : [...kept, r];
  }, []);
}

/**
 * Everything to schedule for [view] from [nowSec] on. The lapsed reminder is
 * "now" (the moment the app learns protection changed); the caller drops ids
 * it has shown before (`alreadyShown`), so it fires once.
 */
export function remindersFor(view: BillingView, nowSec: number, alreadyShown: ReadonlySet<string> = new Set()): Reminder[] {
  let planned: Reminder[];
  switch (view.kind) {
    case "trial":
      planned = trialReminders(view.endsAt, nowSec);
      break;
    case "grace":
      planned = graceReminders(view.graceUntil, nowSec);
      break;
    case "lapsed":
      planned = view.mode === "full" ? [] : [{
        id: `billing:lapsed:${view.mode}:${view.after}`,
        kind: view.mode === "basic" ? "lapsed_basic" : "lapsed_off",
        atSec: nowSec,
      }];
      break;
    default:
      planned = [];
  }
  return spaced(planned.filter((r) => !alreadyShown.has(r.id)));
}

/** The i18n keys of a reminder's title and body (mobile.billing.reminder_*). */
export function reminderCopyKeys(kind: ReminderKind): { title: string; body: string } {
  return { title: `mobile.billing.reminder_${kind}_title`, body: `mobile.billing.reminder_${kind}_body` };
}

/** Pure: does [text] carry anything a person could tap as a link? */
export function looksLikeLink(text: string): boolean {
  return /https?:\/\/|www\.|[a-z0-9-]+\.(ru|ai|com|рф)\b|:\/\//i.test(text);
}

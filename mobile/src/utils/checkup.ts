/**
 * "Проверка защиты" (roadmap №4) — the decisions behind the screen, kept
 * pure so mobile/scripts/test-checkup.mjs can pin them.
 *
 * Part 1: what the phone can check about itself. Each row says only what
 * was actually read on this phone; a state it cannot read is left out,
 * never shown as fine, and a check still running says so.
 *
 * Part 2: the steps a family does once. Cleanway cannot see any of them
 * (a ban on Госуслуги, a word agreed aloud), so "done" is the person's own
 * mark and the screen says exactly that. The only exception is the saved
 * number for "Позвонить близкому", which the app does know about.
 */
import { normalizePhone } from "./phone-number";
import type { OfficialLinkId } from "../config/official-links";

// ── Part 1: the phone checks itself ─────────────────────────────────────

/** Mirror of ShieldCard's ShieldState, kept structural so this file stays React-free. */
export type ShieldStateLike =
  | "setup" | "on" | "paused" | "conflict" | "network-blocked" | "unverified" | "offline";

export interface DeviceCheckInput {
  /** The "All apps" shield, or null where this build has none (iOS). */
  shield: {
    state: ShieldStateLike;
    probing: boolean;
    interrupted: boolean;
    /** When a pause ends, already formatted for the screen ("14:35"). */
    pausedTime: string;
    privateDnsHost: string | null;
    list: { count: number; stale: boolean; ageMs: number | null };
  } | null;
  /** The link guard, or null where it cannot be verified (Android < 10, iOS). */
  linkGuard: { on: boolean } | null;
  /** Null: this build cannot tell. */
  alertsOn: boolean | null;
  /** Null: this build or Android version cannot tell. */
  backgroundRestricted: boolean | null;
}

export type DeviceCheckId = "shield" | "links" | "alerts" | "battery" | "list";

/** ok: read and fine. fix: read and wrong, with a fix. wait: cannot be told right now. */
export type DeviceCheckStatus = "ok" | "fix" | "wait";

export type FixAction =
  | "shield_on" | "shield_resume" | "private_dns" | "links_on" | "alerts_on" | "battery" | "list_refresh";

export interface DeviceCheck {
  id: DeviceCheckId;
  status: DeviceCheckStatus;
  /** i18n key of the row's one sentence. */
  key: string;
  params?: Record<string, string | number>;
  /** What "Исправить" does; only on status "fix". */
  fix?: FixAction;
}

const HOUR_MS = 3_600_000;

/** States in which the shield's service runs and holds a list. */
const RUNNING: ReadonlySet<ShieldStateLike> = new Set(["on", "paused", "unverified", "offline"]);

function shieldRow(shield: NonNullable<DeviceCheckInput["shield"]>): DeviceCheck {
  const row = (status: DeviceCheckStatus, key: string, fix?: FixAction, params?: DeviceCheck["params"]): DeviceCheck =>
    ({ id: "shield", status, key, ...(fix ? { fix } : {}), ...(params ? { params } : {}) });
  switch (shield.state) {
    case "conflict":
      return row("fix", "mobile.checkup.device.shield_conflict", "private_dns", { host: shield.privateDnsHost ?? "" });
    case "setup":
      return shield.interrupted
        ? row("fix", "mobile.checkup.device.shield_stopped", "shield_on")
        : row("fix", "mobile.checkup.device.shield_off", "shield_on");
    case "paused":
      return row("fix", "mobile.checkup.device.shield_paused", "shield_resume", { time: shield.pausedTime });
    case "on":
      return row("ok", "mobile.checkup.device.shield_on");
    default:
      // Probe in flight: "checking", never a flash of the negative state.
      if (shield.probing) return row("wait", "mobile.checkup.device.shield_checking");
      return shield.state === "offline"
        ? row("wait", "mobile.checkup.device.shield_offline")
        : row("wait", "mobile.checkup.device.shield_unverified");
  }
}

/**
 * The list is its own truth: a green tunnel with an old list blocks nothing
 * new. Only the running shield keeps it fresh, so with the shield off the
 * row waits on the shield row instead of offering a second, useless fix.
 */
function listRow(shield: NonNullable<DeviceCheckInput["shield"]>): DeviceCheck {
  if (!RUNNING.has(shield.state)) {
    return { id: "list", status: "wait", key: "mobile.checkup.device.list_needs_shield" };
  }
  const { count, stale, ageMs } = shield.list;
  if (count <= 0) return { id: "list", status: "fix", key: "mobile.checkup.device.list_missing", fix: "list_refresh" };
  if (stale) return { id: "list", status: "fix", key: "mobile.checkup.device.list_stale", fix: "list_refresh" };
  const hours = Math.round((ageMs ?? 0) / HOUR_MS);
  return hours < 1
    ? { id: "list", status: "ok", key: "mobile.checkup.device.list_fresh_now" }
    : { id: "list", status: "ok", key: "mobile.checkup.device.list_fresh", params: { hours } };
}

/** Part 1 rows, in screen order. Only what this phone can actually tell. */
export function deviceChecks(input: DeviceCheckInput): DeviceCheck[] {
  const rows: DeviceCheck[] = [];
  if (input.shield) rows.push(shieldRow(input.shield));
  if (input.linkGuard) {
    rows.push(input.linkGuard.on
      ? { id: "links", status: "ok", key: "mobile.checkup.device.links_on" }
      : { id: "links", status: "fix", key: "mobile.checkup.device.links_off", fix: "links_on" });
  }
  if (input.alertsOn !== null) {
    rows.push(input.alertsOn
      ? { id: "alerts", status: "ok", key: "mobile.checkup.device.alerts_on" }
      : { id: "alerts", status: "fix", key: "mobile.checkup.device.alerts_off", fix: "alerts_on" });
  }
  if (input.backgroundRestricted !== null) {
    rows.push(input.backgroundRestricted
      ? { id: "battery", status: "fix", key: "mobile.checkup.device.battery_restricted", fix: "battery" }
      : { id: "battery", status: "ok", key: "mobile.checkup.device.battery_ok" });
  }
  if (input.shield) rows.push(listRow(input.shield));
  return rows;
}

/** How many rows need "Исправить" — a count of facts, not a score. */
export function fixCount(rows: readonly DeviceCheck[]): number {
  return rows.filter((r) => r.status === "fix").length;
}

// ── Part 2: what the family does once ───────────────────────────────────

export type FamilyStepId =
  | "credit_ban" | "sim_ban" | "second_hand" | "caller_id" | "install_block" | "code_word" | "call_close_one";

export interface FamilyStep {
  id: FamilyStepId;
  /** Exists only under Russian law (Госуслуги, 41-ФЗ) or names Russian services. */
  russiaOnly: boolean;
  /** An Android system setting; iPhones cannot install apps from a chat at all. */
  androidOnly: boolean;
  /** The official page its button opens (config/official-links.ts). */
  link?: OfficialLinkId;
}

/**
 * Screen order = the roadmap's order: the two free state bans first (the
 * biggest measured effect), then the bank and the phone, then the family.
 *
 * The numbers in the cards' "зачем" lines (mobile.checkup.<step>.why), as
 * of 2026-09-27 — re-check them with the links every quarter:
 *  - credit_ban: ~30 млн человек — Григоренко, ПМЭФ, 04.06.2026
 *    (interfax.ru/forumspb/1093901); доля кредитов в украденном 37% → 18%
 *    за 2025 год — ЦБ (itsec.ru/news/zb-soobshil-o-snizhenii-doli-kreditnogo-moshennichestva-v-bankovskih-hisheniyah).
 *  - sim_ban: больше 1,8 млн человек — там же, interfax.ru/forumspb/1093901.
 *  - second_hand: больше 3,5 млн человек — kommersant.ru/doc/8710726.
 *  - caller_id: 29,3 млрд ₽ украдено за 2025 год, вернули 5,9% — ЦБ,
 *    cbr.ru/analytics/ib/operations_survey/2025/ (the roadmap's "92% —
 *    social engineering" could not be found there, so it is not used).
 *  - install_block: около 1,5 млн заражённых Android-телефонов — F6,
 *    safe.cnews.ru/news/line/2026-06-25_staryj_novyj_frod_ushcherb.
 */
export const FAMILY_STEPS: readonly FamilyStep[] = [
  { id: "credit_ban", russiaOnly: true, androidOnly: false, link: "credit_ban" },
  { id: "sim_ban", russiaOnly: true, androidOnly: false, link: "sim_ban" },
  { id: "second_hand", russiaOnly: true, androidOnly: false },
  { id: "caller_id", russiaOnly: true, androidOnly: false },
  { id: "install_block", russiaOnly: false, androidOnly: true },
  { id: "code_word", russiaOnly: false, androidOnly: false },
  { id: "call_close_one", russiaOnly: false, androidOnly: false },
];

const STEP_IDS: ReadonlySet<string> = new Set(FAMILY_STEPS.map((s) => s.id));

/** The steps that apply to this person and this phone. */
export function familySteps(opts: { russia: boolean; android: boolean }): FamilyStep[] {
  return FAMILY_STEPS.filter((s) => (opts.russia || !s.russiaOnly) && (opts.android || !s.androidOnly));
}

/**
 * "Сделано N из M". A step counts when the person marked it — except the
 * call step, which counts exactly when a number is saved: that one the app
 * can see, so it neither needs nor accepts a mark.
 */
export function familyProgress(
  steps: readonly FamilyStep[],
  marks: ReadonlySet<FamilyStepId>,
  closeOneSaved: boolean,
): { done: number; total: number } {
  const done = steps.filter((s) => (s.id === "call_close_one" ? closeOneSaved : marks.has(s.id))).length;
  return { done, total: steps.length };
}

/** Marks read back from storage: known step ids only, each once, never the call step. */
export function parseMarks(raw: string | null): FamilyStepId[] {
  if (!raw) return [];
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    const ids = parsed.filter(
      (id): id is FamilyStepId => typeof id === "string" && STEP_IDS.has(id) && id !== "call_close_one",
    );
    return [...new Set(ids)];
  } catch {
    return [];
  }
}

/** A new list with [id] marked or unmarked; the input is left as it was. */
export function toggleMark(marks: readonly FamilyStepId[], id: FamilyStepId): FamilyStepId[] {
  return marks.includes(id) ? marks.filter((m) => m !== id) : [...marks, id];
}

// ── The saved number ────────────────────────────────────────────────────

export interface CloseOne {
  /** As the person wrote it or the address book had it; may be absent. */
  name: string | null;
  /** Always a normalizePhone() result. */
  number: string;
}

/** Longest name kept — it only has to fit on a button. */
export const MAX_NAME_LENGTH = 40;

/** A contact worth saving, or null when the number cannot be dialled. */
export function makeCloseOne(name: string | null | undefined, number: string | null | undefined): CloseOne | null {
  const dialable = normalizePhone(number);
  if (!dialable) return null;
  const trimmed = typeof name === "string" ? name.trim().slice(0, MAX_NAME_LENGTH) : "";
  return { name: trimmed.length > 0 ? trimmed : null, number: dialable };
}

/** The saved contact read back from storage, re-validated; null when absent or broken. */
export function parseCloseOne(raw: string | null): CloseOne | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return null;
    const { name, number } = parsed as { name?: unknown; number?: unknown };
    return makeCloseOne(typeof name === "string" ? name : null, typeof number === "string" ? number : null);
  } catch {
    return null;
  }
}

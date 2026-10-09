/**
 * The iPhone's DNS protection setup, as a pure state machine — no React
 * Native — so mobile/scripts/test-ios-dns.mjs runs it under plain node.
 * docs/IOS.md §4.
 *
 * iOS splits the setup in two, and only the first half is the app's:
 *   1. the app saves Cleanway's encrypted DNS (NEDNSSettingsManager);
 *   2. the person picks "Cleanway" in Settings → General → VPN & Device
 *      Management → DNS. The app cannot do this, cannot open that page, and
 *      learns about it only by reading isEnabled again.
 * So the layer is "on" only when iOS says the saved configuration is ours,
 * current, and enabled — never because the app asked for it. That is iOS's
 * word, not a proof that lookups reach Cleanway (another VPN can take DNS
 * over): a canary through the resolver, as Android's shield has, needs a
 * public name the gateway alone blocks — docs/IOS.md §4.5.
 */
import type { IosDnsError, IosDnsReport } from "../../modules/cleanway-vpn/src/IosDnsSettings";
import type { IosLayerStatus } from "./platform-features";

/**
 *   unavailable — not an iPhone, or a native build without DNS settings;
 *   checking    — not read from iOS yet;
 *   add         — nothing saved (or an outdated/foreign configuration): step 1;
 *   turn_on     — saved, waiting for the person in Settings: step 2;
 *   on          — saved, current and enabled.
 */
export type IosDnsPhase = "unavailable" | "checking" | "add" | "turn_on" | "on";

export type IosDnsAction = "status" | "install" | "remove";

export interface IosDnsState {
  supported: boolean;
  /** Last report from iOS; null until the first read. */
  report: IosDnsReport | null;
  /** A call in flight. */
  busy: IosDnsAction | null;
  /** The call that produced `report`, so an error can be worded for it. */
  lastAction: IosDnsAction | null;
}

export const INITIAL_IOS_DNS: IosDnsState = { supported: false, report: null, busy: null, lastAction: null };

export function iosDnsPhase(state: IosDnsState): IosDnsPhase {
  if (!state.supported) return "unavailable";
  const r = state.report;
  if (!r) return "checking";
  // An old configuration (another server URL) is redone by step 1: saving
  // replaces it. Whether iOS keeps it enabled across that save is not
  // documented — the report read back after the save says.
  if (!r.installed || !r.current) return "add";
  if (!r.enabled) return "turn_on";
  return "on";
}

/** What the home card shows for the DNS layer. "checking" offers the setup, never a check mark. */
export function iosDnsLayerStatus(phase: IosDnsPhase): IosLayerStatus {
  if (phase === "unavailable") return "coming";
  return phase === "on" ? "on" : "setup";
}

// ── Transitions ───────────────────────────────────────────────────────

export function iosDnsStarted(state: IosDnsState, action: IosDnsAction): IosDnsState {
  return { ...state, busy: action };
}

/**
 * A call came back. A null report (no native support after all) makes the
 * layer unavailable rather than guessing. The report always replaces the old
 * one: it is what iOS holds after the call, failed or not.
 */
export function iosDnsFinished(state: IosDnsState, action: IosDnsAction, report: IosDnsReport | null): IosDnsState {
  if (!report) return { supported: false, report: null, busy: null, lastAction: action };
  return { supported: true, report, busy: state.busy === action ? null : state.busy, lastAction: action };
}

// ── The setup sheet ───────────────────────────────────────────────────

export type IosDnsStepState = "done" | "current" | "todo";

export interface IosDnsSheet {
  steps: { add: IosDnsStepState; turnOn: IosDnsStepState };
  /** The one main button: save the configuration, or go to Settings; null when on. */
  primary: { action: "install" | "open_settings"; labelKey: string; busy: boolean } | null;
  statusKey: string;
  /** Shown under the status when the last call failed. */
  errorKey: string | null;
  /** "Remove from iPhone" — only when something of ours is saved. */
  removable: boolean;
  removing: boolean;
}

const STATUS_KEYS: Record<IosDnsPhase, string> = {
  unavailable: "mobile.ios.dns.status_add",
  checking: "mobile.ios.dns.status_checking",
  add: "mobile.ios.dns.status_add",
  turn_on: "mobile.ios.dns.status_turn_on",
  on: "mobile.ios.dns.status_on",
};

const ERROR_KEYS: Record<IosDnsAction, string> = {
  status: "mobile.ios.dns.error_status",
  install: "mobile.ios.dns.error_add",
  remove: "mobile.ios.dns.error_remove",
};

/** The wording for a failed call; null when the last call went through. */
export function iosDnsErrorKey(state: IosDnsState): string | null {
  const error: IosDnsError | null | undefined = state.report?.error;
  if (!error || !state.lastAction) return null;
  return ERROR_KEYS[state.lastAction];
}

export function iosDnsSheet(state: IosDnsState): IosDnsSheet {
  const phase = iosDnsPhase(state);
  const added = phase === "turn_on" || phase === "on";
  const steps = {
    add: added ? "done" : "current",
    turnOn: phase === "on" ? "done" : phase === "turn_on" ? "current" : "todo",
  } as const;
  let primary: IosDnsSheet["primary"] = null;
  if (phase === "add" || phase === "checking") {
    const busy = state.busy === "install";
    primary = { action: "install", labelKey: busy ? "mobile.ios.dns.adding" : "mobile.ios.dns.add", busy: busy || phase === "checking" };
  } else if (phase === "turn_on") {
    primary = { action: "open_settings", labelKey: "mobile.ios.dns.open_settings", busy: false };
  }
  return {
    steps,
    primary,
    statusKey: STATUS_KEYS[phase],
    errorKey: iosDnsErrorKey(state),
    removable: state.supported && state.report?.installed === true && state.busy === null,
    removing: state.busy === "remove",
  };
}

/** Every key the sheet can show — for the i18n contract test. */
export const IOS_DNS_SHEET_KEYS: readonly string[] = [
  "mobile.ios.dns.title",
  "mobile.ios.dns.privacy_title",
  "mobile.ios.dns.privacy_body",
  "mobile.ios.dns.step_add_title",
  "mobile.ios.dns.step_add_body",
  "mobile.ios.dns.step_on_title",
  "mobile.ios.dns.step_on_body",
  "mobile.ios.dns.add",
  "mobile.ios.dns.adding",
  "mobile.ios.dns.open_settings",
  "mobile.ios.dns.note_off",
  "mobile.ios.dns.note_vpn",
  "mobile.ios.dns.remove",
  "mobile.ios.dns.removing",
  "mobile.ios.dns.done",
  "mobile.ios.dns.step_done",
  ...Object.values(STATUS_KEYS),
  ...Object.values(ERROR_KEYS),
];

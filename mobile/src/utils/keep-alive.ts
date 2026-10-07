import type { KeepAliveStatus } from "../../modules/cleanway-vpn/src/CleanwayVpn.types";

/**
 * The "Keep protection on" checklist (home screen): what keeps the network
 * shield running after the app is closed, and which of it is done.
 *
 * Honesty contract, same as the shields: a row says "done" only for what the
 * phone itself reports. A setting the app cannot read is never ticked —
 * the phone maker's own battery manager ("manual") is shown as a step to do
 * once, and a value the phone does not report (null) is left out rather
 * than guessed.
 */

export type KeepAliveRowId = "running" | "battery" | "oem" | "notifications" | "always_on";

/**
 * ok — the phone reports it is set. todo — the phone reports it is not, and
 * it matters. optional — not needed, offered (Always-on VPN). manual — the
 * app cannot read it; a step to do once. unknown — the shield is up but not
 * proven, or paused; nothing to tap here.
 */
export type KeepAliveRowState = "ok" | "todo" | "optional" | "manual" | "unknown";

/** The network shield as this list needs it (folded from useNetworkShield's state). */
export type KeepAliveShield = "on" | "unproven" | "paused" | "off";

export interface KeepAliveRow {
  id: KeepAliveRowId;
  state: KeepAliveRowState;
}

export interface KeepAliveInput {
  shield: KeepAliveShield;
  status: KeepAliveStatus;
  /** Block alerts will be heard (null: this build cannot tell). */
  notifications: boolean | null;
}

/** useNetworkShield's card state → what this list says about it. */
export function shieldForKeepAlive(state: string, verified: boolean): KeepAliveShield {
  if (state === "paused") return "paused";
  if (state === "on" && verified) return "on";
  if (state === "on" || state === "unverified" || state === "offline") return "unproven";
  return "off";
}

/**
 * The rows, most important first: the shield itself, then the battery
 * exemption (what an OEM kill most often comes down to), the phone maker's
 * own manager, alerts, and Always-on VPN last because it is optional.
 */
export function keepAliveRows({ shield, status, notifications }: KeepAliveInput): KeepAliveRow[] {
  const rows: KeepAliveRow[] = [
    { id: "running", state: shield === "on" ? "ok" : shield === "off" ? "todo" : "unknown" },
  ];
  if (status.batteryUnrestricted !== null) {
    rows.push({ id: "battery", state: status.batteryUnrestricted ? "ok" : "todo" });
  }
  if (status.oem !== null) rows.push({ id: "oem", state: "manual" });
  if (notifications !== null) rows.push({ id: "notifications", state: notifications ? "ok" : "todo" });
  // Readable only while the tunnel is up (VpnService.isAlwaysOn). Anything
  // but a reported "on" is offered, never shown as missing: protection
  // already returns by itself after a reboot without it.
  rows.push({ id: "always_on", state: status.alwaysOn === true ? "ok" : "optional" });
  return rows;
}

/** Steps the person still has to take (optional and unknown rows do not count). */
export function keepAliveTodo(rows: readonly KeepAliveRow[]): number {
  return rows.filter((r) => r.state === "todo").length;
}

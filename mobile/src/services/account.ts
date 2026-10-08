/**
 * Linking this phone to the signed-in account.
 *
 * The subscription counts devices (docs/ACCOUNTS_BILLING_PLAN.md §5), so
 * right after sign-in the app registers this install, and on each start /
 * return to the foreground it sends a heartbeat (at most every 6 hours).
 * The server answers:
 *   • ok      — linked (or already linked);
 *   • limit   — every device seat is taken: the account screen opens in its
 *               "unlink one / add a device" mode (app/account.tsx);
 *   • revoked — this install was unlinked elsewhere: sign out here and make
 *               a new device id, so signing in again is a new device.
 * Offline / server trouble changes nothing; the next heartbeat tries again.
 */
import { Platform } from "react-native";
import Constants from "expo-constants";
import { EventEmitter } from "events";

import {
  registerDevice,
  errorDetail,
  type AccountDevice,
  type EntitlementResponse,
} from "./api";
import { getDeviceId, rotateDeviceId } from "./device-id";
import { rememberEntitlement } from "./freemium";
import { signOutEverywhereLocal } from "./account-actions";
import { accountFailure, defaultDeviceName, heartbeatDue } from "../utils/account-session";

export type LinkResult =
  | { kind: "ok"; entitlement: EntitlementResponse }
  | { kind: "limit"; deviceLimit: number; devices: AccountDevice[] }
  | { kind: "revoked" }
  | { kind: "signed_out" }
  | { kind: "retry" };

/**
 * App-wide account notices:
 *   "limit"   — no free device seat for this phone (payload: LinkResult)
 *   "revoked" — this phone was unlinked and is now signed out
 */
export const accountEvents = new EventEmitter();

let _lastHeartbeatAt: number | null = null;

function thisDeviceName(): string | null {
  // The model only ("Pixel 8"). Deliberately NOT Constants.deviceName: on
  // iOS that is the owner's own name for the phone ("Anna's iPhone") — a
  // person's name the server has no need for. Without a model (iOS) the
  // device list shows the platform instead.
  const constants = Platform.constants as { Model?: unknown } | undefined;
  return defaultDeviceName(constants?.Model, null);
}

/** Link this install to the signed-in account (idempotent). */
export async function linkThisDevice(): Promise<LinkResult> {
  const deviceId = await getDeviceId();
  if (!deviceId) return { kind: "retry" };
  const platform = Platform.OS === "ios" ? "ios" : "android";
  const { data, error } = await registerDevice({
    device_id: deviceId,
    platform,
    name: thisDeviceName(),
    app_version: Constants.expoConfig?.version ?? null,
  });
  if (data) {
    _lastHeartbeatAt = Date.now();
    // The free plan's limit reads the plan from here too (no extra request).
    void rememberEntitlement(data.entitlement);
    return { kind: "ok", entitlement: data.entitlement };
  }
  switch (accountFailure(error)) {
    case "limit": {
      const detail = errorDetail(error) ?? {};
      return {
        kind: "limit",
        deviceLimit: typeof detail.device_limit === "number" ? detail.device_limit : 0,
        devices: Array.isArray(detail.devices) ? (detail.devices as AccountDevice[]) : [],
      };
    }
    case "revoked":
      return { kind: "revoked" };
    case "signed_out":
      return { kind: "signed_out" };
    default:
      return { kind: "retry" };
  }
}

/**
 * Sign out because this install was unlinked: local session gone, Family
 * key gone (as on a normal sign-out), a NEW device id for the next sign-in.
 * `notify` = it happened elsewhere, so the person is told why (not when
 * they unlinked this phone themselves on the Account screen).
 */
export async function signOutUnlinkedDevice(notify: boolean = true): Promise<void> {
  await signOutEverywhereLocal();
  await rotateDeviceId();
  _lastHeartbeatAt = null;
  if (notify) accountEvents.emit("revoked");
}

/**
 * Right after sign-in. A stale id the server already knows as unlinked
 * (signed out on another device, then signed back in here) is replaced and
 * tried once more.
 */
export async function linkAfterSignIn(): Promise<LinkResult> {
  let result = await linkThisDevice();
  if (result.kind === "revoked") {
    await rotateDeviceId();
    result = await linkThisDevice();
  }
  if (result.kind === "revoked") await signOutUnlinkedDevice();
  return result;
}

/** On app start / foreground, when signed in. Throttled to every 6 hours. */
export async function heartbeatIfDue(): Promise<void> {
  if (!heartbeatDue(_lastHeartbeatAt, Date.now())) return;
  const result = await linkThisDevice();
  if (result.kind === "revoked") {
    await signOutUnlinkedDevice();
  } else if (result.kind === "limit") {
    accountEvents.emit("limit", result);
  }
}

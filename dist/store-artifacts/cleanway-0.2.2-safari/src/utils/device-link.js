/**
 * This browser as a device of the signed-in account.
 *
 * The subscription counts devices (docs/ACCOUNTS_BILLING_PLAN.md §5); a
 * browser with the extension signed in is one. After sign-in, and then at
 * most every 6 hours, the extension links itself with
 * POST /api/v1/me/devices (platform "extension", the per-install id kept in
 * chrome.storage.local as `device_hash`). The server answers:
 *   201/200                  linked (idempotent)
 *   409 device_limit_reached every seat of the plan is taken
 *   403 device_revoked       this install was unlinked from the account
 * Anything else (offline, 5xx, an older server) changes nothing.
 *
 * ES module with no `chrome` at top level: utils/auth-session.js decides
 * what each answer means for the session and scripts/test-extension-auth.mjs
 * drives both in plain Node.
 */

export const DEVICE_ID_KEY = "device_hash";
export const HEARTBEAT_KEY = "device_heartbeat_at";
export const HEARTBEAT_MS = 6 * 60 * 60 * 1000;

const BROWSER_NAMES = { chrome: "Chrome", firefox: "Firefox", safari: "Safari", edge: "Edge" };

/** What the device list shows for this browser: "Chrome", "Firefox", … */
export function browserName(family) {
  return BROWSER_NAMES[family] || "Browser";
}

/** The API's device id pattern (api/routers/account.py). */
export function isValidDeviceId(value) {
  return typeof value === "string" && /^[A-Za-z0-9_-]{16,128}$/.test(value);
}

export function heartbeatDue(lastMs, nowMs) {
  if (!Number.isFinite(lastMs) || lastMs > nowMs) return true;
  return nowMs - lastMs >= HEARTBEAT_MS;
}

/** `detail.code` of an error answer, or null. */
export function errorCode(body) {
  const detail = body && typeof body === "object" ? body.detail : null;
  return detail && typeof detail === "object" && typeof detail.code === "string" ? detail.code : null;
}

/**
 * Map the answer of POST /api/v1/me/devices.
 * @returns {{ok: true} | {ok: false, error: "device_limit_reached", deviceLimit: number|null}
 *   | {ok: false, error: "device_revoked"} | {ok: false, error: "unavailable"}}
 */
export function linkResult(status, body) {
  if (status === 200 || status === 201) return { ok: true };
  const code = errorCode(body);
  if (status === 409 && code === "device_limit_reached") {
    const limit = body.detail.device_limit;
    return { ok: false, error: "device_limit_reached", deviceLimit: Number.isInteger(limit) ? limit : null };
  }
  if (status === 403 && code === "device_revoked") return { ok: false, error: "device_revoked" };
  return { ok: false, error: "unavailable" };
}

/**
 * POST /api/v1/me/devices. Never throws.
 * @param {{fetchImpl: Function, apiBase: string, token: string, deviceId: string,
 *          browser: string, appVersion: string}} args
 */
export async function linkDevice({ fetchImpl, apiBase, token, deviceId, browser, appVersion }) {
  if (!token || !isValidDeviceId(deviceId)) return { ok: false, error: "unavailable" };
  let resp;
  try {
    resp = await fetchImpl(`${apiBase}/api/v1/me/devices`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
        "X-Device-Id": deviceId,
      },
      body: JSON.stringify({
        device_id: deviceId,
        platform: "extension",
        name: browserName(browser),
        app_version: typeof appVersion === "string" ? appVersion.slice(0, 32) : null,
      }),
      credentials: "omit",
    });
  } catch (e) {
    return { ok: false, error: "unavailable" };
  }
  let body = null;
  if (!resp.ok) {
    try {
      body = await resp.json();
    } catch (e) { /* not JSON: unavailable below */ }
  }
  return linkResult(resp.status, body);
}

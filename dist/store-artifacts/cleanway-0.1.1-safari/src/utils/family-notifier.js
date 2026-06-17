/**
 * Family Hub local-notifications poller.
 *
 * The auto-fan-out path (family-fanout.js) ensures Mom's blocks reach
 * Grandma's server inbox in real time. This module closes the rest of
 * the loop: every minute or so, fetch the inbox, decrypt the unseen
 * envelopes, and surface them as OS notifications via the
 * chrome.notifications API.
 *
 * Why local + not server-pushed:
 *   - Server-pushed notifications need FCM (Android) / APNs (iOS) /
 *     Web Push VAPID keys + a backend push subscription store.
 *   - Local polling is good enough for the 1-minute SLA the strategy
 *     doc describes ("real-time block alerts").
 *   - Saves us from adding a third-party push provider before we have
 *     a real deploy story for it.
 *
 * Dedup:
 *   chrome.storage.local["family_last_seen_alert_id"] — UUID of the
 *   most-recent alert we've already shown. Anything newer than that
 *   is fresh. Server orders by created_at desc so the first row IS
 *   the newest; we walk the list until we hit the last_seen.
 *
 * Click handling: notification.onClicked opens the Family Hub section
 * of the Options page. Wired in background/index.js, not here, so the
 * persistent listener doesn't get redefined per poll.
 */

const SEEN_KEY = "family_last_seen_alert_id";
const ALARM_NAME = "cleanway_family_poll";
const NOTIFICATION_PREFIX = "cleanway-family:";

/**
 * Register the periodic alarm. Idempotent — Chrome dedups by name so
 * calling this on every SW startup is fine. The alarm fires while the
 * SW is alive AND wakes a torn-down SW back up.
 */
export function ensureFamilyPollAlarm(periodMinutes = 1) {
  try {
    chrome.alarms.create(ALARM_NAME, {
      periodInMinutes: Math.max(1, periodMinutes),
    });
  } catch {
    // alarms permission missing or API unavailable — silent
  }
}

export function isFamilyPollAlarm(alarmName) {
  return alarmName === ALARM_NAME;
}

/**
 * Pull the inbox, decrypt new envelopes, fire notifications.
 * Best-effort: every error path returns 0 silently.
 *
 * @returns {Promise<number>} number of notifications shown
 */
export async function pollAndNotify() {
  let stored;
  try {
    stored = await chrome.storage.local.get(["auth_token", SEEN_KEY]);
  } catch {
    return 0;
  }
  if (!stored || !stored.auth_token) return 0;

  // Need the cached family — without it we have nothing to poll.
  let fanoutMod, cryptoMod, apiMod;
  try {
    fanoutMod = await import(chrome.runtime.getURL("utils/family-fanout.js"));
    cryptoMod = await import(chrome.runtime.getURL("utils/family-crypto.js"));
    apiMod = await import(chrome.runtime.getURL("utils/family-api.js"));
  } catch {
    return 0;
  }

  const cache = await fanoutMod.getCachedFamilyState();
  if (!cache) return 0;

  let kp;
  try {
    kp = await cryptoMod.getOrCreateKeypair();
  } catch {
    return 0;
  }
  if (!kp || !kp.secretKeyB64) return 0;

  const list = await apiMod.listAlerts(stored.auth_token, cache.family_id);
  if (!list || !Array.isArray(list.alerts) || list.alerts.length === 0) {
    return 0;
  }

  const lastSeen = stored[SEEN_KEY] || null;
  const fresh = [];
  for (const env of list.alerts) {
    if (lastSeen && env.id === lastSeen) break; // we've caught up
    if (!env.ciphertext_b64 || !env.nonce_b64 || !env.sender_pubkey_b64) continue;
    const opened = cryptoMod.decryptForMe(
      {
        ciphertext_b64: env.ciphertext_b64,
        nonce_b64: env.nonce_b64,
        sender_pubkey_b64: env.sender_pubkey_b64,
      },
      kp.secretKeyB64,
    );
    if (!opened) continue;
    fresh.push({ id: env.id, alert: opened, at: env.created_at });
  }

  if (fresh.length === 0) {
    // Bump last_seen so we don't re-walk this list next minute.
    if (list.alerts[0] && list.alerts[0].id !== lastSeen) {
      try { await chrome.storage.local.set({ [SEEN_KEY]: list.alerts[0].id }); } catch {}
    }
    return 0;
  }

  // Show notifications. Walk OLDEST first (reverse) so the most recent
  // is what the user sees on top of the stack.
  fresh.reverse();
  for (const item of fresh) {
    const domain = item.alert.domain || "(unknown domain)";
    const level = (item.alert.level || "block").toString();
    const title = level === "dangerous"
      ? "Family member protected from a scam"
      : "Family alert";
    const message = `${domain} — ${level}`;
    try {
      // eslint-disable-next-line no-await-in-loop
      await new Promise((resolve) => {
        chrome.notifications.create(
          NOTIFICATION_PREFIX + item.id,
          {
            type: "basic",
            iconUrl: chrome.runtime.getURL("public/icon-192.png"),
            title,
            message,
            priority: 1,
          },
          () => resolve(),
        );
      });
    } catch {
      // chrome.notifications may not be available (rare browsers /
      // permission denied) — skip silently and keep the loop going.
    }
  }

  // Mark the newest as seen — list[0] before reverse was the newest.
  try {
    await chrome.storage.local.set({ [SEEN_KEY]: list.alerts[0].id });
  } catch {
    // Silent
  }

  return fresh.length;
}

/**
 * notification ID → "open Family Hub on click" URL. Used by the
 * persistent onClicked listener in background/index.js.
 */
export function isFamilyNotificationId(notificationId) {
  return typeof notificationId === "string" && notificationId.startsWith(NOTIFICATION_PREFIX);
}

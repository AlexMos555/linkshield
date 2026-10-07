/**
 * The background's half of sign-in: wires utils/auth-session.js to the
 * browser (storage, tabs, alarms, messages). See that file for the flow and
 * the security checks; this one only connects them. index.js keeps a single
 * onMessage and a single onAlarm listener and hands both to us first.
 *
 * Messages handled here:
 *   AUTH_CONNECT        from content/connect-relay.js on cleanway.ai/…/extension/connect
 *   AUTH_START_SIGN_IN  from the popup / settings page — opens the connect tab
 *   AUTH_STATUS         from the popup / settings page — {signedIn, email, pending, signedOutReason}
 *   AUTH_SIGN_OUT       from the settings page — forgets the tokens
 * Anything else falls through to the main listener in index.js.
 */

import { registerDevice } from "../utils/api.js";
import { createAuthSession, isExtensionPageSender } from "../utils/auth-session.js";

const AUTH_REFRESH_ALARM = "cleanway_auth_refresh";

function browserPlatform() {
  let base = "";
  try { base = chrome.runtime.getURL(""); } catch (e) { /* tests */ }
  if (base.startsWith("moz-extension:")) return "firefox";
  if (base.startsWith("safari-web-extension:")) return "safari";
  if (typeof navigator !== "undefined" && /\bEdg\//.test(navigator.userAgent || "")) return "edge";
  return "chrome";
}

function scheduleRefresh(whenMs) {
  if (!chrome.alarms) return;
  try {
    if (whenMs === null) chrome.alarms.clear(AUTH_REFRESH_ALARM);
    else chrome.alarms.create(AUTH_REFRESH_ALARM, { when: whenMs });
  } catch (e) { /* alarms unavailable: refreshed on the next popup/settings open instead */ }
}

export const auth = createAuthSession({
  storage: chrome.storage.local,
  fetchImpl: (url, init) => fetch(url, init),
  openTab: (url) => chrome.tabs.create({ url }),
  uiLanguage: () => {
    try { return chrome.i18n.getUILanguage(); } catch (e) { return "en"; }
  },
  scheduleRefresh,
  onSignedIn: async (accessToken) => {
    let appVersion = "0.0.0";
    try { appVersion = chrome.runtime.getManifest().version; } catch (e) { /* keep default */ }
    await registerDevice(accessToken, { platform: browserPlatform(), appVersion });
  },
});

const PAGE_ACTIONS = {
  AUTH_START_SIGN_IN: () => auth.startSignIn().then(() => ({ ok: true })),
  AUTH_STATUS: () => auth.status(),
  AUTH_SIGN_OUT: () => auth.signOut().then(() => ({ ok: true })),
};

/**
 * Called first by the background's one onMessage listener (index.js).
 * Returns true when the message was ours (the reply is sent asynchronously),
 * undefined otherwise so the main listener handles it.
 */
export function handleAuthMessage(msg, sender, respond) {
  if (!msg || typeof msg.type !== "string") return undefined;
  let work = null;
  if (msg.type === "AUTH_CONNECT") {
    work = auth.acceptHandoff(msg, sender, chrome.runtime.id);
  } else if (Object.prototype.hasOwnProperty.call(PAGE_ACTIONS, msg.type)) {
    let base = "";
    try { base = chrome.runtime.getURL(""); } catch (e) { /* refuse below */ }
    work = isExtensionPageSender(sender, chrome.runtime.id, base)
      ? PAGE_ACTIONS[msg.type]()
      : Promise.resolve({ ok: false, error: "bad_sender" });
  } else {
    return undefined;
  }
  work.then(respond).catch(() => {
    try { respond({ ok: false, error: "internal" }); } catch (e) { /* port closed */ }
  });
  return true;
}

/** Called by the background's one onAlarm listener; true when it was ours. */
export function handleAuthAlarm(alarm) {
  if (!alarm || alarm.name !== AUTH_REFRESH_ALARM) return false;
  auth.ensureFresh().catch(() => {});
  return true;
}

// Worker start (browser launch, wake-up): refresh a token that expired while
// the worker slept, and re-arm the alarm the browser may have dropped.
auth.ensureFresh().catch(() => {});

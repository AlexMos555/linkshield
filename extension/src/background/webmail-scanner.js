/**
 * The webmail scanner switch: whether content/webmail.js runs at all.
 *
 * The scanner sends the email a person opens (subject, sender, reply-to,
 * text, link addresses) to /api/v1/email/analyze, so it is OFF unless the
 * person turned it on in Settings. Off means the script is not injected:
 * no manifest entry loads it. When `webmailScannerEnabled === true` is in
 * chrome.storage.local, this module registers it with
 * scripting.registerContentScripts for the four mail origins and injects it
 * into mail tabs that are already open; when the flag goes away it
 * unregisters it, and the copies already running in open tabs stop
 * themselves on the same storage change (content/webmail.js).
 *
 * One mechanism for all three builds: `scripting` (Chrome 96+, Safari
 * 15.4+, Firefox 102+ including MV2) plus the four mail origins as
 * OPTIONAL host permissions, requested by the Settings page when the person
 * turns the scanner on. A browser without scripting.registerContentScripts
 * cannot run the scanner; Settings says so instead of showing a switch that
 * does nothing.
 *
 * Nothing here turns the scanner on. The flag only ever becomes true from
 * the Settings switch, so an update leaves every existing install off.
 */

export const WEBMAIL_FLAG = "webmailScannerEnabled";
export const WEBMAIL_SCRIPT_ID = "cleanway-webmail";
export const WEBMAIL_MATCHES = Object.freeze([
  "https://mail.google.com/*",
  "https://outlook.office.com/*",
  "https://outlook.live.com/*",
  "https://mail.yahoo.com/*",
]);
export const WEBMAIL_FILES = Object.freeze(["src/content/webmail.js"]);

/** Only a literal `true` turns it on: a missing key, "true" or 1 do not. */
export function isWebmailScannerEnabled(stored) {
  return Boolean(stored) && stored[WEBMAIL_FLAG] === true;
}

/** True when this browser can register a content script at run time. */
export function webmailScannerSupported(api) {
  return Boolean(api && api.scripting && typeof api.scripting.registerContentScripts === "function");
}

function scriptDefinition(persist) {
  const def = {
    id: WEBMAIL_SCRIPT_ID,
    matches: [...WEBMAIL_MATCHES],
    js: [...WEBMAIL_FILES],
    runAt: "document_idle",
    allFrames: false,
  };
  if (persist) def.persistAcrossSessions = true;
  return def;
}

async function registeredIds(scripting) {
  try {
    const list = await scripting.getRegisteredContentScripts({ ids: [WEBMAIL_SCRIPT_ID] });
    return (list || []).map((s) => s.id);
  } catch (e) {
    // Older engines take no filter.
    const list = await scripting.getRegisteredContentScripts();
    return (list || []).map((s) => s.id).filter((id) => id === WEBMAIL_SCRIPT_ID);
  }
}

async function register(scripting) {
  try {
    await scripting.registerContentScripts([scriptDefinition(true)]);
  } catch (e) {
    const msg = String((e && e.message) || e);
    if (/duplicate/i.test(msg)) return;
    // An engine that cannot keep it across restarts: register for this
    // session; every background start re-syncs anyway.
    await scripting.registerContentScripts([scriptDefinition(false)]);
  }
}

// Mail tabs that were open before the switch was turned on get the script
// now, so "on" works without a reload. The script itself refuses to start
// twice in one page.
async function injectIntoOpenTabs(api) {
  if (!api.tabs || typeof api.tabs.query !== "function" || typeof api.scripting.executeScript !== "function") return 0;
  let tabs = [];
  try {
    tabs = await api.tabs.query({ url: [...WEBMAIL_MATCHES] });
  } catch (e) {
    return 0;
  }
  let injected = 0;
  for (const tab of tabs || []) {
    if (!tab || tab.id == null) continue;
    try {
      await api.scripting.executeScript({ target: { tabId: tab.id }, files: [...WEBMAIL_FILES] });
      injected++;
    } catch (e) { /* tab closed, discarded or not allowed — it gets the script on its next load */ }
  }
  return injected;
}

/**
 * Wires the switch to one browser API object (`chrome`). Returns `sync`,
 * which brings the registration in line with the stored flag; every call
 * runs after the previous one, so a start-up sync and a storage change
 * cannot register the script twice.
 */
export function createWebmailScanner(api) {
  let chain = Promise.resolve();

  async function syncOnce({ injectOpen = false } = {}) {
    if (!webmailScannerSupported(api)) return { supported: false, registered: false };
    const stored = await api.storage.local.get(WEBMAIL_FLAG);
    const want = isWebmailScannerEnabled(stored);
    const have = (await registeredIds(api.scripting)).length > 0;
    if (want && !have) await register(api.scripting);
    if (!want && have) await api.scripting.unregisterContentScripts({ ids: [WEBMAIL_SCRIPT_ID] });
    if (want && injectOpen) await injectIntoOpenTabs(api);
    return { supported: true, registered: want };
  }

  function sync(opts) {
    const run = chain.then(() => syncOnce(opts));
    chain = run.catch(() => {});
    return run;
  }

  // Off also gives back the mail-site access the browser granted for it.
  // Best effort: Chrome refuses to drop an origin that a required content
  // script (the link badges on <all_urls>) already covers.
  async function releasePermission() {
    if (!api.permissions || typeof api.permissions.remove !== "function") return;
    try { await api.permissions.remove({ origins: [...WEBMAIL_MATCHES] }); } catch (e) { /* see above */ }
  }

  function onStorageChanged(changes, area) {
    if (area !== "local" || !changes || !Object.prototype.hasOwnProperty.call(changes, WEBMAIL_FLAG)) return;
    const on = changes[WEBMAIL_FLAG].newValue === true;
    sync({ injectOpen: on }).catch(() => {});
    if (!on) releasePermission();
  }

  // Taking the mail-site access away in the browser's own extension
  // settings turns the switch off too, so Settings never shows "on" for a
  // scanner the browser no longer lets run.
  function onPermissionsRemoved(removed) {
    const origins = (removed && removed.origins) || [];
    if (!origins.some((o) => WEBMAIL_MATCHES.includes(o))) return;
    api.storage.local.set({ [WEBMAIL_FLAG]: false }).catch(() => {});
  }

  // Installs from before the switch existed were granted the four mail
  // origins at install time. On update, give them back unless the person
  // has since turned the scanner on.
  async function releaseIfOff() {
    const stored = await api.storage.local.get(WEBMAIL_FLAG);
    if (!isWebmailScannerEnabled(stored)) await releasePermission();
  }

  return { sync, onStorageChanged, onPermissionsRemoved, releasePermission, releaseIfOff };
}

/** Background wiring: listeners plus a sync on every worker start. */
export function installWebmailScanner(api) {
  const scanner = createWebmailScanner(api);
  try {
    api.storage.onChanged.addListener(scanner.onStorageChanged);
  } catch (e) { /* storage events unavailable — the start-up sync still runs */ }
  try {
    if (api.permissions && api.permissions.onRemoved) api.permissions.onRemoved.addListener(scanner.onPermissionsRemoved);
  } catch (e) { /* permissions events unavailable */ }
  try {
    api.runtime.onInstalled.addListener(() => { scanner.releaseIfOff().catch(() => {}); });
  } catch (e) { /* onInstalled unavailable */ }
  // A restart may have dropped a session-only registration, and an install
  // that never turned the scanner on must not carry one.
  scanner.sync().catch(() => {});
  return scanner;
}

/**
 * What counts as a "blocked scam": a block page the user actually saw, once
 * per site per day.
 *
 * The link check sees every link host on every page, and the page check runs
 * again on every reload. Counting those as blocks used to send relatives
 * "a scam site was blocked" about links grandma never opened, added one to
 * the account's threat counter per reload, and let a spam folder in webmail
 * walk a free user into the upgrade nudge without meeting a single threat.
 *
 * Now only the content script's block page reports a block (PAGE_BLOCKED),
 * only for the page it is on, and this ledger lets each site count once a
 * day. The ledger holds hostnames of blocked scam pages for at most 24 hours,
 * on this device only.
 */

const LEDGER_KEY = "blocked_pages_today";
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_ENTRIES = 200;

// Entries from the last 24 hours, newest first, capped so storage stays small.
function recentEntries(stored, now) {
  if (!stored || typeof stored !== "object") return {};
  const fresh = Object.entries(stored)
    .filter(([, ts]) => typeof ts === "number" && ts <= now && now - ts < DAY_MS)
    .sort((a, b) => b[1] - a[1])
    .slice(0, MAX_ENTRIES - 1);
  return Object.fromEntries(fresh);
}

/**
 * Record a block of `host` and say whether it is the first one today.
 * Not atomic on its own: callers serialise it (the background's stats mutex).
 *
 * @param {string} host
 * @param {number} [now]
 * @returns {Promise<boolean>} true the first time `host` is blocked in 24 hours
 */
export async function claimFirstBlockToday(host, now = Date.now()) {
  const data = await chrome.storage.local.get([LEDGER_KEY]);
  const ledger = recentEntries(data && data[LEDGER_KEY], now);
  if (Object.prototype.hasOwnProperty.call(ledger, host)) return false;
  await chrome.storage.local.set({ [LEDGER_KEY]: { ...ledger, [host]: now } });
  return true;
}

/**
 * The host a PAGE_BLOCKED message may speak for, or null.
 *
 * Only a content script in a tab's top frame can report, and only about the
 * page it is running on, so no message can make the background count or
 * report some other site.
 *
 * @param {{ domain?: unknown }} msg
 * @param {{ tab?: { id?: number }, frameId?: number, url?: string }} sender
 * @returns {string|null}
 */
export function blockedPageHost(msg, sender) {
  if (!sender || !sender.tab || sender.tab.id == null) return null;
  if (typeof sender.frameId === "number" && sender.frameId !== 0) return null;
  if (!msg || typeof msg.domain !== "string") return null;
  let pageHost;
  try {
    pageHost = new URL(sender.url).hostname.toLowerCase();
  } catch (e) {
    return null;
  }
  return pageHost && msg.domain.toLowerCase() === pageHost ? pageHost : null;
}

/**
 * The count on the toolbar icon: how many risky sites (caution or
 * dangerous) the page in THIS tab is, or links to. Red when one of them is
 * dangerous, amber when all are caution, nothing when there are none.
 *
 * It used to be one global badge, set without a tabId and never cleared: a
 * red "3" from one page stayed on every tab, including clean ones, and the
 * number was only the last batch of links. Now each tab counts risky hosts
 * (one host counts once however many links point at it) per DOCUMENT: the
 * content script sends an id it made for its document with every check
 * (content/index.js), and a check from another document makes the tab show
 * that one's count.
 *
 * Not tabs.onUpdated "loading": Chromium fires it for history.pushState, a
 * #fragment link and a back/forward-cache restore too, where the page and
 * its links stay the same and nothing scans them again — the count went
 * blank on every SPA. A cross-document navigation resets the tab's badge in
 * the browser itself (Chrome, Firefox), and the new page's own check paints
 * its count. A page restored from the back/forward cache keeps its id, so
 * its stored count comes back with its page check.
 *
 * The counts live in chrome.storage.session where the browser has it, so a
 * restarted worker keeps counting from where it was; else in memory. A
 * closed tab is forgotten.
 */

export const BADGE_KEY = "toolbar_badge_tabs";
export const BADGE_RED = "#ef4444";
export const BADGE_AMBER = "#f59e0b";
const MAX_HOSTS = 200;
const MAX_PAGES = 300;
const MAX_DOC_ID = 64;

/** Pure: the badge for one page's risky hosts. */
export function badgeFor(entry) {
  const dangerous = (entry && entry.dangerous) || [];
  const caution = (entry && entry.caution) || [];
  const n = dangerous.length + caution.length;
  return { text: n === 0 ? "" : n > 99 ? "99+" : String(n), color: dangerous.length ? BADGE_RED : BADGE_AMBER };
}

/** Pure: entry plus the risky results of one check (a host is counted once). */
export function addResults(entry, results) {
  const dangerous = new Set((entry && entry.dangerous) || []);
  const caution = new Set((entry && entry.caution) || []);
  for (const r of results || []) {
    if (!r || typeof r.domain !== "string" || !r.domain) continue;
    if (r.level === "dangerous") {
      dangerous.add(r.domain);
      caution.delete(r.domain);
    } else if (r.level === "caution" && !dangerous.has(r.domain)) {
      caution.add(r.domain);
    }
  }
  return { dangerous: [...dangerous].slice(0, MAX_HOSTS), caution: [...caution].slice(0, MAX_HOSTS) };
}

/** Pure: a document id as the content script sends it, else null. */
export function docIdOf(value) {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_DOC_ID ? value : null;
}

const pageKey = (tabId, doc) => `${tabId}:${doc}`;

function settle(p) {
  if (p && typeof p.catch === "function") p.catch(() => { /* the tab is gone */ });
}

export function createToolbarBadge(api, { session = null } = {}) {
  // `action` in MV3, `browserAction` in Firefox MV2; absent on mobile
  // browsers with no toolbar.
  const toolbar = api && (api.action || api.browserAction);
  const available = Boolean(toolbar) && typeof toolbar.setBadgeText === "function";
  const shown = new Map(); // tabId → the document whose count the tab shows
  let memory = {};
  let chain = Promise.resolve();

  function serial(task) {
    const run = chain.then(task, task);
    chain = run.catch(() => {});
    return run;
  }

  async function load() {
    if (!session) return memory;
    try {
      const d = await session.get([BADGE_KEY]);
      const v = d && d[BADGE_KEY];
      return v && typeof v === "object" ? v : {};
    } catch (e) {
      return memory;
    }
  }

  async function save(all) {
    const keys = Object.keys(all);
    if (keys.length > MAX_PAGES) for (const k of keys.slice(0, keys.length - MAX_PAGES)) delete all[k];
    memory = all;
    if (!session) return;
    try {
      await session.set({ [BADGE_KEY]: all });
    } catch (e) { /* the memory copy holds it */ }
  }

  // Not awaited: a toolbar call that never settles (no test drives Safari's)
  // must not hold up every count after it. Issued in order, applied in order.
  function paint(tabId, entry) {
    const { text, color } = badgeFor(entry);
    try {
      settle(toolbar.setBadgeText({ tabId, text }));
      if (text && typeof toolbar.setBadgeBackgroundColor === "function") {
        settle(toolbar.setBadgeBackgroundColor({ tabId, color }));
      }
    } catch (e) { /* the tab is gone */ }
  }

  /**
   * A check from document `doc` arrived from tab `tabId`: from now on the tab
   * shows that document's count. Call it when the message arrives, before
   * anything is awaited, so a late answer for the page the tab left is not
   * painted over the one it is on.
   */
  function enter(tabId, doc) {
    const id = docIdOf(doc);
    if (available && Number.isInteger(tabId) && id) shown.set(tabId, id);
  }

  /** Count one check's results for its document; repaint if the tab shows it. */
  function record(tabId, doc, results) {
    const id = docIdOf(doc);
    if (!available || !Number.isInteger(tabId) || !id) return Promise.resolve();
    return serial(async () => {
      if (!shown.has(tabId)) return; // the tab was closed meanwhile
      const all = await load();
      const key = pageKey(tabId, id);
      const before = all[key];
      const entry = addResults(before, results);
      const changed = JSON.stringify(entry) !== JSON.stringify(before || { dangerous: [], caution: [] });
      if (changed) {
        all[key] = entry;
        await save(all);
      }
      if (shown.get(tabId) === id) paint(tabId, entry);
    });
  }

  function forget(tabId) {
    shown.delete(tabId);
    return serial(async () => {
      const all = await load();
      const prefix = `${tabId}:`;
      const gone = Object.keys(all).filter((k) => k.startsWith(prefix));
      if (gone.length === 0) return;
      for (const k of gone) delete all[k];
      await save(all);
    });
  }

  if (available) {
    try {
      api.tabs.onRemoved.addListener((tabId) => { forget(tabId).catch(() => {}); });
    } catch (e) { /* tabs events unavailable: closed tabs age out at MAX_PAGES */ }
  }

  return { available, enter, record };
}

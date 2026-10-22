/**
 * The count on the toolbar icon: how many risky sites (caution or
 * dangerous) the page in THIS tab is, or links to, since it last loaded.
 * Red when one of them is dangerous, amber when all are caution, nothing
 * when there are none.
 *
 * It used to be one global badge, set without a tabId and never cleared: a
 * red "3" from one page stayed on every tab, including clean ones, and the
 * number was only the last batch of links. Now each tab has its own set of
 * risky hosts (one host counts once however many links point at it), a
 * navigation ("loading") clears it, and a closed tab is forgotten. The sets
 * live in chrome.storage.session where the browser has it, so a restarted
 * worker keeps counting from where it was; else in memory.
 *
 * A check answered after its tab moved on (a slow API, then a click) is not
 * counted on the new page: every navigation starts a new generation.
 */

export const BADGE_KEY = "toolbar_badge_tabs";
export const BADGE_RED = "#ef4444";
export const BADGE_AMBER = "#f59e0b";
const MAX_HOSTS = 200;
const MAX_TABS = 300;

/** Pure: the badge for one tab's risky hosts. */
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

export function createToolbarBadge(api, { session = null } = {}) {
  // `action` in MV3, `browserAction` in Firefox MV2; absent on mobile
  // browsers with no toolbar.
  const toolbar = api && (api.action || api.browserAction);
  const available = Boolean(toolbar) && typeof toolbar.setBadgeText === "function";
  const generations = new Map(); // tabId → navigations seen by this worker
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
    if (keys.length > MAX_TABS) for (const k of keys.slice(0, keys.length - MAX_TABS)) delete all[k];
    memory = all;
    if (!session) return;
    try {
      await session.set({ [BADGE_KEY]: all });
    } catch (e) { /* the memory copy holds it */ }
  }

  async function paint(tabId, entry) {
    const { text, color } = badgeFor(entry);
    try {
      await toolbar.setBadgeText({ tabId, text });
      if (text && typeof toolbar.setBadgeBackgroundColor === "function") {
        await toolbar.setBadgeBackgroundColor({ tabId, color });
      }
    } catch (e) { /* the tab is gone */ }
  }

  /** The tab's current generation: pass it back to record(). */
  function generation(tabId) {
    return generations.get(tabId) || 0;
  }

  function record(tabId, gen, results) {
    if (!available || !Number.isInteger(tabId)) return Promise.resolve();
    return serial(async () => {
      if (generation(tabId) !== gen) return; // the tab moved on meanwhile
      const all = await load();
      const before = all[tabId];
      const entry = addResults(before, results);
      const changed = JSON.stringify(entry) !== JSON.stringify(before || { dangerous: [], caution: [] });
      if (changed) {
        all[tabId] = entry;
        await save(all);
      }
      await paint(tabId, entry);
    });
  }

  function forget(tabId, { repaint }) {
    generations.set(tabId, generation(tabId) + 1);
    return serial(async () => {
      const all = await load();
      if (tabId in all) {
        delete all[tabId];
        await save(all);
      }
      if (repaint) await paint(tabId, null);
    });
  }

  if (available) {
    try {
      api.tabs.onUpdated.addListener((tabId, info) => {
        if (info && info.status === "loading") forget(tabId, { repaint: true }).catch(() => {});
      });
    } catch (e) { /* tabs events unavailable: the badge still follows its tab */ }
    try {
      api.tabs.onRemoved.addListener((tabId) => { forget(tabId, { repaint: false }).catch(() => {}); });
    } catch (e) { /* idem */ }
  }

  return { available, generation, record };
}

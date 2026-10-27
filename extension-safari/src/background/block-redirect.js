/**
 * Blocking a dangerous page by taking the tab away from it.
 *
 * The block page used to be an overlay appended to the scam page's own DOM
 * by a content script — the page could remove it (or never let it paint)
 * and carry on. Now content/index.js reports the verdict (BLOCK_PAGE) and
 * the background navigates the tab to the extension's own
 * src/blocked/blocked.html, a page the scam site cannot script or reach
 * (not a web_accessible_resource: only the extension can open it).
 *
 *   BLOCK_PAGE     content script, top frame, about its own page →
 *                  {action: "navigated"}  the tab went to blocked.html
 *                  {action: "proceed"}    the person already chose "open
 *                                         anyway" for this site in this tab
 *                  {action: "overlay"}    this browser refused the navigation:
 *                                         block-page.js was injected, the
 *                                         content script shows the old overlay
 *                  {action: "none"}       nothing to block / bad sender
 *   BLOCK_PROCEED  blocked.html → "open anyway": allowed for that site in
 *                  that tab (BYPASS_TTL_MS), and the tab goes back to the
 *                  address that was blocked — read from the block page's own
 *                  URL, which the browser reports, never from the message.
 *
 * The allowances live in chrome.storage.session where the browser has it
 * (TRUSTED_CONTEXTS, see utils/token-store.js), so a service-worker restart
 * between "open anyway" and the page loading keeps them; else in memory.
 */

import "../utils/blocked-url.js"; // sets self.cleanwayBlockedUrl (classic UMD file)

const blockedUrl = self.cleanwayBlockedUrl;

export const BYPASS_KEY = "block_bypass";
export const BYPASS_TTL_MS = 60 * 60 * 1000;
const MAX_BYPASSES = 100;

/**
 * Where "open anyway" allowances are kept: {tabId: {host, until}}.
 * @param {object} api  chrome / browser
 */
export function createBypassStore(api, now = () => Date.now()) {
  let memory = {};
  const area = (() => {
    try {
      const s = api && api.storage && api.storage.session;
      return s && typeof s.get === "function" && typeof s.set === "function" ? s : null;
    } catch (e) {
      return null;
    }
  })();

  async function load() {
    if (!area) return memory;
    try {
      const d = await area.get([BYPASS_KEY]);
      const v = d && d[BYPASS_KEY];
      return v && typeof v === "object" ? v : {};
    } catch (e) {
      return memory;
    }
  }

  async function save(all) {
    memory = all;
    if (!area) return;
    try {
      await area.set({ [BYPASS_KEY]: all });
    } catch (e) { /* memory copy still holds it */ }
  }

  function fresh(all) {
    const t = now();
    const kept = Object.entries(all || {})
      .filter(([, v]) => v && typeof v.host === "string" && typeof v.until === "number" && v.until > t)
      .slice(-MAX_BYPASSES);
    return Object.fromEntries(kept);
  }

  return {
    async allow(tabId, host) {
      const all = fresh(await load());
      all[String(tabId)] = { host, until: now() + BYPASS_TTL_MS };
      await save(all);
    },
    async isAllowed(tabId, host) {
      const entry = fresh(await load())[String(tabId)];
      return Boolean(entry) && entry.host === host;
    },
    async forgetTab(tabId) {
      const all = fresh(await load());
      if (!(String(tabId) in all)) return;
      delete all[String(tabId)];
      await save(all);
    },
  };
}

/** A content script in a tab's top frame, about the http(s) page it is on. */
export function pageSender(sender) {
  if (!sender || !sender.tab || sender.tab.id == null) return null;
  if (typeof sender.frameId === "number" && sender.frameId !== 0) return null;
  let u;
  try {
    u = new URL(sender.url);
  } catch (e) {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  return { tabId: sender.tab.id, host: u.hostname.toLowerCase(), url: sender.url };
}

/** The verdict the block page shows: only the fields it renders. */
export function verdictFor(host, cached, reported) {
  const pick = cached && cached.level === "dangerous" ? cached
    : reported && reported.level === "dangerous" ? reported : null;
  if (!pick) return null;
  return {
    domain: host,
    level: "dangerous",
    confidence_pct: pick.confidence_pct,
    reasons: Array.isArray(pick.reasons) ? pick.reasons : [],
  };
}

/**
 * Wire the two messages. Returns a handler for the background's single
 * onMessage listener: true when the message was ours (reply async),
 * undefined otherwise.
 *
 * @param {object} deps
 * @param {object} deps.api                 chrome / browser
 * @param {(host: string) => object|null} deps.getCached  the background's verdict cache
 * @param {(host: string, tabId: number) => Promise<void>} deps.onShown  count + report a shown block
 * @param {(tabId: number) => void} deps.onProceeded  the person opened the site anyway
 */
export function createBlockRedirect({ api, getCached, onShown, onProceeded }) {
  const bypass = createBypassStore(api);
  const base = (() => {
    try { return api.runtime.getURL(""); } catch (e) { return ""; }
  })();

  async function injectOverlay(tabId) {
    if (!api.scripting || typeof api.scripting.executeScript !== "function") return false;
    try {
      await api.scripting.executeScript({
        target: { tabId, frameIds: [0] },
        files: ["src/content/block-page.js"], // reason-labels.js is already a content script
      });
      return true;
    } catch (e) {
      return false;
    }
  }

  async function onBlockPage(msg, sender) {
    const page = pageSender(sender);
    if (!page || !msg || typeof msg.domain !== "string" || msg.domain.toLowerCase() !== page.host) {
      return { action: "none" };
    }
    const verdict = verdictFor(page.host, getCached(page.host), msg.result);
    if (!verdict) return { action: "none" };
    if (await bypass.isAllowed(page.tabId, page.host)) {
      onProceeded(page.tabId);
      return { action: "proceed" };
    }
    const target = blockedUrl.build(base, verdict, page.url);
    if (target) {
      try {
        await api.tabs.update(page.tabId, { url: target });
        onShown(page.host, page.tabId).catch(() => {});
        return { action: "navigated" };
      } catch (e) { /* this browser refused: the overlay below */ }
    }
    // Last resort, on a browser that won't navigate a tab to an extension
    // page: the in-page overlay (removable by the page, but better than no
    // warning). The content script reports it with PAGE_BLOCKED once shown.
    return (await injectOverlay(page.tabId)) ? { action: "overlay" } : { action: "none" };
  }

  // The tab is taken away from the block page only after the reply is sent:
  // the page unloads with that navigation, and a reply still on its way finds
  // no page (Firefox then logs "Promise rejected after context unloaded"
  // against blocked.js). Hence {reply, navigate} instead of navigating here.
  async function onProceed(sender) {
    const refused = { reply: { ok: false } };
    if (!sender || !sender.tab || sender.tab.id == null) return refused;
    if (sender.id !== undefined && sender.id !== api.runtime.id) return refused;
    if (!blockedUrl.isBlockedPageUrl(sender.url, base)) return refused;
    const shown = blockedUrl.parse(sender.url);
    if (!shown.domain || !shown.url) return refused;
    await bypass.allow(sender.tab.id, shown.domain);
    const tabId = sender.tab.id;
    return { reply: { ok: true }, navigate: () => api.tabs.update(tabId, { url: shown.url }) };
  }

  try {
    api.tabs.onRemoved.addListener((tabId) => { bypass.forgetTab(tabId).catch(() => {}); });
  } catch (e) { /* tabs events unavailable — allowances still expire */ }

  return function handleBlockMessage(msg, sender, respond) {
    if (!msg || (msg.type !== "BLOCK_PAGE" && msg.type !== "BLOCK_PROCEED")) return undefined;
    const failed = msg.type === "BLOCK_PAGE" ? { action: "none" } : { ok: false };
    const work = msg.type === "BLOCK_PAGE"
      ? onBlockPage(msg, sender).then((reply) => ({ reply }))
      : onProceed(sender);
    work.then(({ reply, navigate }) => {
      try { respond(reply); } catch (e) { /* the page is already gone */ }
      if (!navigate) return;
      try {
        const going = navigate();
        if (going && typeof going.catch === "function") going.catch(() => { /* the tab is gone: nothing to open */ });
      } catch (e) { /* tabs.update unavailable */ }
    }).catch(() => {
      try { respond(failed); } catch (e) { /* port closed */ }
    });
    return true;
  };
}

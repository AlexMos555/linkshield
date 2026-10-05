/**
 * Cleanway Background — v4 (module service worker)
 *
 * Loaded as an ES module ("type": "module" in all three manifests) and
 * pulls its helpers in with STATIC imports. It used to be a classic
 * service worker that loaded them with import(), which the service-worker
 * spec forbids: every call threw, the try/catch around it hid the error,
 * and the threat counter, Family Hub alerts, the Family Hub poller and the
 * daily 30-day history prune never ran for anyone.
 * scripts/test-extension-sw.mjs now drives this file in a real Chromium.
 *
 * Optional browser APIs (context menus, notifications, keyboard commands,
 * the toolbar badge) are feature-checked before use: Yandex Browser on
 * Android, Safari and Firefox each lack some of them, and one unguarded
 * top-level `undefined.addListener` would abort the whole module — every
 * listener after it, including the link check, would never register.
 */

import "./browser-compat.js"; // must stay first: aliases chrome → browser in Firefox
import "../utils/link-target.js"; // sets self.cleanwayLinkTarget (classic UMD file)
// The offline scorer the content script runs, in the same order the manifests
// load it: the generated data, the server's name rules, then the scorer
// (self.cleanwayLocalScorer). Classic files, imported for their side effect.
import "../utils/scorer-data.js";
import "../utils/name-rules.js";
import "../utils/local-scorer.js";
import { incrementThreatCounter } from "../utils/api.js";
import { clearFamilyCache, fanOutAlerts, refreshFamilyCache } from "../utils/family-fanout.js";
import {
  isFamilyNotificationId,
  isFamilyPollAlarm,
  pollAndNotify,
  syncFamilyPollAlarm,
} from "../utils/family-notifier.js";
import { pruneOldChecks } from "../utils/storage.js";
import { blockedPageHost, claimFirstBlockToday } from "./page-blocks.js";
import { isKnownSafeHost, isUserContentHost } from "./trusted-hosts.js";

const HISTORY_PRUNE_ALARM = "cleanway_history_prune";
const EMPTY_STATS = Object.freeze({ total_checks: 0, threats_blocked: 0, threats_warned: 0 });

function _t(key, subs) {
  try {
    return chrome.i18n.getMessage(key, subs || []) || key;
  } catch (e) {
    return key;
  }
}

/**
 * Service-worker debug mode toggle. The original code had 6 unconditional
 * console.log lines on the /check hot path — every URL the user opened
 * fired one or more. In production that's pointless DevTools noise and
 * eats a non-trivial amount of CPU. Match the content-script convention
 * (`_debugMode = false` since the audit batch) so prod ships quiet.
 *
 * Override at runtime from DevTools:
 *   chrome.storage.local.set({ cleanway_debug: true })
 * Or set DEBUG=true on extension reload (manifest cant carry env vars).
 * (Audit extension-mv3 LOW "6 console.log calls in hot-path background.js
 * fire on every URL check".)
 */
let _debugMode = false;
try {
  chrome.storage.local.get("cleanway_debug").then(function(d) {
    if (d && d.cleanway_debug === true) _debugMode = true;
  }).catch(function() {});
} catch (e) { /* storage unavailable in some test contexts */ }

function _log() {
  if (_debugMode) console.log.apply(console, ["[LS]"].concat(Array.from(arguments)));
}

/**
 * Minimal serial mutex for the MV3 service worker. Pure JS closure
 * pattern — no external dep, no setTimeout. Each runExclusive() call
 * waits for the previous critical section's promise to resolve, then
 * runs its task. The chain head is the only mutable state.
 *
 * Used by updateStats() and the blocked-page ledger (page-blocks.js) so
 * concurrent messages from multiple tabs can't lose increments or count
 * one block twice. (Audit extension-mv3 MEDIUM stats counter race.)
 */
const _statsMutex = (() => {
  let chain = Promise.resolve();
  return {
    async runExclusive(task) {
      const run = chain.then(task, task);
      // Swallow rejection in the chain so a failed task doesn't poison
      // every subsequent run; the original promise still rejects.
      chain = run.catch(() => {});
      return run;
    },
  };
})();

// API base — production Railway default, override via Options page (chrome.storage.local.api_url)
let API_BASE = "https://api.cleanway.ai";
try {
  chrome.storage.local.get("api_url").then(function(data) {
    if (data && typeof data.api_url === "string" && data.api_url.startsWith("http")) {
      API_BASE = data.api_url.replace(/\/$/, "");
    }
  }).catch(function() {});
  chrome.storage.onChanged.addListener(function(changes, area) {
    if (area === "local" && changes && changes.api_url && typeof changes.api_url.newValue === "string") {
      API_BASE = changes.api_url.newValue.replace(/\/$/, "");
    }
  });
} catch (e) { /* ignore */ }

// ── Cache (bounded LRU) ──
// MV3 service workers can stay alive for hours during active browsing.
// A plain Map grows unbounded — every distinct domain the user sees adds
// an entry that's never evicted unless re-queried (the TTL check in
// getCached returns null but doesn't delete). On a heavy day of news +
// social scrolling that's easily 10k+ entries, hundreds of KB resident.
//
// JavaScript's Map preserves insertion order, so we can implement LRU
// cheaply: on hit, re-insert to bump to the tail; on size cap, evict
// the head (oldest). 1000 entries cover any realistic browsing session.
const _CACHE_TTL_MS = 3600000;       // 1 hour
const _CACHE_MAX_ENTRIES = 1000;
const _cache = new Map();

function getCached(d) {
  const e = _cache.get(d);
  if (!e) return null;
  if (Date.now() - e.ts > _CACHE_TTL_MS) {
    _cache.delete(d);  // actively reap stale entry
    return null;
  }
  // LRU touch: move to tail by re-inserting
  _cache.delete(d);
  _cache.set(d, e);
  return e.r;
}

function setCached(d, r) {
  // Evict oldest if at cap. Map.keys() iterates in insertion order, so
  // .next().value is the oldest entry (least recently inserted/touched).
  if (_cache.size >= _CACHE_MAX_ENTRIES) {
    const oldest = _cache.keys().next().value;
    if (oldest !== undefined) _cache.delete(oldest);
  }
  _cache.set(d, { r, ts: Date.now() });
}

// ── Fetch with timeout ──
// The previous version raced fetch() against a setTimeout-reject, which
// rejects the OUTER promise on timeout but leaves the underlying fetch
// running until the network stack finishes. Under a fetch-storm (e.g. a
// SPA generating links faster than the API responds) that piles up
// abandoned requests holding sockets, descriptors and listeners — slow
// memory bloat in the service worker.
//
// AbortController fixes it: signal goes into fetch(), and on timeout
// we call abort() which actively cancels the request. Resources reclaim
// immediately.
function fetchWithTimeout(url, ms) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  return fetch(url, { signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

// ── Local scoring (instant, no network) ──
// The content script's scorer (utils/local-scorer.js), not a copy: this used
// to be a second, weaker one — 20 brands, the last two labels read as the
// site — that called eBay UK's real sign-in host dangerous. It answers the
// popup and the context menu whenever the API does not.
function scoreLocally(domain) {
  return self.cleanwayLocalScorer.localScore(domain);
}

// ── Verdicts that need no API call ──
// See trusted-hosts.js for which hosts and why. A user-content host gets
// neither green nor red: the path of the page never leaves the browser, so
// nothing — not the API either — can tell a real form there from a scam one.
function localVerdict(domain) {
  if (isUserContentHost(domain)) {
    return {
      domain,
      score: null,
      level: "user_content",
      reasons: [{ signal: "user_content", detail: _t("badge_reason_user_content"), weight: 0 }],
      source: "platform",
    };
  }
  if (isKnownSafeHost(domain)) {
    return { domain, score: 0, level: "safe", reasons: [{signal:"known",detail:_t("badge_reason_official_site"),weight:-50}] };
  }
  return null;
}

// The API's English `signals` with their machine-readable `reason_codes`
// (positionally aligned), so the badge can show each reason in the user's
// language (content/reason-labels.js).
function apiReasons(data) {
  const codes = Array.isArray(data.reason_codes) ? data.reason_codes : [];
  return (data.signals || []).map((detail, i) => ({
    signal: typeof codes[i] === "string" ? codes[i] : "api",
    detail,
    weight: 10,
  }));
}

// ── Main handler ──
// `page` is true for the check of the page the user is on (content/index.js),
// false for links on it, the popup and the context menu.
async function handleCheck(domains, { page = false } = {}) {
  _log("Checking", domains.length, "domains");
  const results = [];
  const toCheck = [];

  for (const domain of domains) {
    const cached = getCached(domain);
    if (cached) { results.push(cached); continue; }
    const shortcut = localVerdict(domain);
    if (shortcut) {
      setCached(domain, shortcut);
      results.push(shortcut);
      continue;
    }
    toCheck.push(domain);
  }

  // Score ALL unknown domains locally FIRST (instant)
  const localResults = {};
  for (const d of toCheck) {
    localResults[d] = scoreLocally(d);
    _log("Local:", d, "score=" + localResults[d].score, localResults[d].level);
  }

  // Try API for each domain (with 3s timeout), improve local result if API responds
  for (const d of toCheck) {
    try {
      const resp = await fetchWithTimeout(`${API_BASE}/api/v1/public/check/${encodeURIComponent(d)}`, 3000);
      if (resp.ok) {
        const data = await resp.json();
        const r = {
          domain: data.domain || d,
          score: data.score,
          level: data.level,
          reasons: apiReasons(data),
          source: "api",
        };
        _log("API:", d, "score=" + r.score, r.level);
        setCached(d, r);
        results.push(r);
        continue;
      }
    } catch (e) {
      _log("API timeout/error for", d, "- using local score");
    }

    // Use local result
    const lr = localResults[d];
    setCached(d, lr);
    results.push(lr);
  }

  await recordCheckStats(results, page);

  // Badge — `action` in MV3, `browserAction` in Firefox MV2; absent on
  // mobile browsers with no toolbar.
  try {
    const toolbar = chrome.action || chrome.browserAction;
    const threats = results.filter(r => r.level === "dangerous" || r.level === "caution").length;
    if (toolbar && threats > 0) {
      toolbar.setBadgeText({ text: String(threats) });
      toolbar.setBadgeBackgroundColor({ color: results.some(r => r.level === "dangerous") ? "#ef4444" : "#f59e0b" });
    }
  } catch (e) {}

  _log("Returning", results.length, "results");
  return { results };
}

// ── On-device stats ──
// Read/modify/write on chrome.storage.local.stats, serialised by the mutex:
// the service worker handles messages from several tabs at once, and two
// interleaved read/modify/write cycles would lose an increment. (Audit
// extension-mv3 MEDIUM "Stats counter has an unguarded read-modify-write
// race in the MV3 service worker".)
function updateStats(change) {
  return _statsMutex.runExclusive(async () => {
    const data = await chrome.storage.local.get(["stats"]);
    const stats = { ...EMPTY_STATS, ...(data.stats || {}) };
    await chrome.storage.local.set({ stats: change(stats) });
  });
}

// "Links checked" and "Warnings" in the popup. A dangerous LINK is a
// warning — its badge turns red, nothing is blocked. The page the user is on
// counts as a blocked scam only once its block page reports in
// (onPageBlocked), so it is left out here rather than counted twice.
async function recordCheckStats(results, page) {
  const warned = results.filter((r) => r.level === "caution" || (r.level === "dangerous" && !page)).length;
  try {
    await updateStats((stats) => ({
      ...stats,
      total_checks: stats.total_checks + results.length,
      threats_warned: stats.threats_warned + warned,
    }));
  } catch (e) {
    _log("Stats update failed:", e);
  }
}

// ── A block page is on screen ──
// content/index.js reports it after rendering the overlay. See page-blocks.js
// for why this, and never a link verdict, is what counts as a blocked scam.
async function onPageBlocked(msg, sender) {
  const host = blockedPageHost(msg, sender);
  if (!host) return;
  promoteCredentialGuard(sender.tab.id);
  const firstToday = await _statsMutex.runExclusive(() => claimFirstBlockToday(host));
  if (!firstToday) return;
  await updateStats((stats) => ({ ...stats, threats_blocked: stats.threats_blocked + 1 }));
  await reportBlockToAccount(host);
}

// The user may click past the block page. From then on the credential guard
// on that tab asks before ANY password leaves the page, not only when its
// own form checks fire (credential-guardian.js, strict mode).
function promoteCredentialGuard(tabId) {
  try {
    const sent = chrome.tabs.sendMessage(tabId, { type: "CREDGUARD_STRICT" });
    if (sent && typeof sent.catch === "function") sent.catch(() => {});
  } catch (e) { /* tab already gone — nothing to protect */ }
}

// The account's threat counter (the freemium gate) and the family hear only
// about blocks the API itself confirmed. The offline scorer reads nothing
// but the name — a guess, however careful — and must never reach a relative
// as "a scam site was blocked". Anonymous users send nothing.
async function reportBlockToAccount(host) {
  const verdict = getCached(host);
  if (!verdict || verdict.source !== "api" || verdict.level !== "dangerous") return;
  const stored = await chrome.storage.local.get(["auth_token"]);
  const token = stored && stored.auth_token;
  if (!token) return;
  await incrementThreatCounter(token, 1);
  try {
    // Encrypted on this device to each relative's key; the server stays blind.
    await fanOutAlerts(token, [verdict]);
  } catch (e) {
    _log("Family alert failed:", e);
  }
}

// The right-click "check this link" judges where the link really goes
// (utils/link-target.js). A redirector that hides its destination gets an
// honest "unknown" instead of the wrapper's own reputation.
async function checkLinkUrl(href) {
  const target = self.cleanwayLinkTarget.resolveLinkHost(href);
  if (!target) return null;
  if (!target.host) {
    let via = "";
    try { via = new URL(href).hostname; } catch (e) { /* unreachable: resolveLinkHost parsed it */ }
    return {
      domain: via,
      score: null,
      level: "unknown",
      reasons: [{ signal: "url_shortener", detail: "The link hides where it really goes", weight: 0 }],
    };
  }
  const r = await handleCheck([target.host]);
  return r.results[0] || null;
}

// ── Messages ──
chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  if (msg.type === "CHECK_DOMAINS") {
    // .catch() prevents an uncaught promise rejection from silently
    // closing the message channel — the content script then waits the
    // full timeout for a respond() that never comes. Returning an
    // explicit error shape lets callers fall back to local scoring.
    // (Audit extension-mv3 MEDIUM "handleCheck(...).then(respond) has
    // no .catch() — rejection closes the message channel silently".)
    // Credential-guard strict mode is NOT decided here: this message also
    // carries every link on the page, and a page must not turn strict just
    // for linking to a scam. It follows the page's own block (PAGE_BLOCKED).
    handleCheck(msg.domains, { page: msg.page === true })
      .then(respond)
      .catch((err) => {
        try { respond({ error: "background_failure", message: String(err && err.message ? err.message : err) }); }
        catch (e) { /* port closed before respond fired — nothing we can do */ }
      });
    return true;
  }
  if (msg.type === "PAGE_BLOCKED") {
    onPageBlocked(msg, sender).catch((e) => _log("Block report failed:", e));
    return false;
  }
  if (msg.type === "MODERN_PHISH_SIGNAL") {
    // Strategy #11. Modern-phish-guard reports a BitB / overlay /
    // tab-napping detection on the sender's tab. We persist a small
    // counter so the popup can show "X protections triggered today"
    // and the weekly report can credit the right surface. We do NOT
    // forward the host to the backend — privacy invariant holds
    // (server-blind by design).
    try {
      chrome.storage.local.get(["modernPhishCount"]).then((d) => {
        const next = (d.modernPhishCount || 0) + 1;
        chrome.storage.local.set({ modernPhishCount: next }).catch(() => {});
      }).catch(() => {});
    } catch (e) { /* ignore */ }
    // Fire-and-forget — no respond() needed.
    return false;
  }
  if (msg.type === "GET_STATS") {
    chrome.storage.local.get(["stats"])
      .then((d) => respond(d.stats || {}))
      .catch(() => respond({}));
    return true;
  }
  // Open a tab — used by Privacy Audit's "Share grade" button. Content
  // scripts can't reliably open new windows (popup blockers, sandboxed
  // hosts), so we delegate to the background which has the tabs perm.
  if (msg.type === "OPEN_TAB" && typeof msg.url === "string") {
    try {
      // Whitelist: only open URLs we own. A compromised content script
      // shouldn't be able to use the background as a generic tab opener.
      if (msg.url.startsWith("https://cleanway.ai/")) {
        chrome.tabs.create({ url: msg.url });
      }
    } catch (e) {}
    return false;
  }

  // Close the tab that asked us to. The block page's "Go back to safety"
  // button (block-page.js) falls back to this message when there is no
  // history entry to return to — e.g. the scam link was opened in a fresh
  // tab straight from an email. Scope is deliberately narrow: we only ever
  // close the SENDER's own tab, never an arbitrary id from the message
  // body, so a compromised content script can't close other tabs.
  if (msg.type === "CLOSE_TAB") {
    try {
      if (sender && sender.tab && sender.tab.id != null) {
        chrome.tabs.remove(sender.tab.id);
      }
    } catch (e) { /* tab already gone / no id — non-fatal */ }
    return false;
  }
});

// ── Context menu + recurring alarms ──
chrome.runtime.onInstalled.addListener((details) => {
  // First-run onboarding: open the welcome tab ONLY on a fresh install
  // (not on updates/reloads). welcome.html shipped since launch but nothing
  // ever opened it, so new users landed on a bare toolbar icon with no
  // first-value moment. Extension-own pages open in a tab via getURL without
  // needing web_accessible_resources. (2026-07-04 audit: dead onboarding.)
  if (details && details.reason === "install") {
    try {
      chrome.tabs.create({ url: chrome.runtime.getURL("src/popup/welcome.html") });
    } catch (e) { /* tabs unavailable — non-fatal */ }
  }
  installContextMenus();
});

// Right-click menu, in the browser's language. Absent on mobile browsers
// (Yandex on Android), so feature-check instead of letting it throw.
//
// removeAll() first so re-running onInstalled (fires on update/reload, and
// the SW can replay it) doesn't hit "Cannot create item with duplicate id".
// removeAll()'s callback is ASYNC, so removeAll+create alone is NOT race-safe:
// if onInstalled runs twice (SW restart replay, or a dev reload), both
// removeAll calls can complete before either callback runs, and then both
// callbacks create the same ids -> "Cannot create item with duplicate id
// audit-page" surfaced in chrome://extensions. Pass a callback to each
// create() so the benign duplicate is READ (and thus cleared) instead of
// bubbling up as an unchecked runtime.lastError.
function installContextMenus() {
  if (!chrome.contextMenus) return;
  chrome.contextMenus.removeAll(() => {
    // Read lastError to clear it (removeAll on an empty menu set is fine).
    void chrome.runtime.lastError;
    chrome.contextMenus.create(
      { id: "check-link", title: _t("menu_check_link"), contexts: ["link"] },
      () => void chrome.runtime.lastError,
    );
    chrome.contextMenus.create(
      { id: "audit-page", title: _t("menu_privacy_audit"), contexts: ["page"] },
      () => void chrome.runtime.lastError,
    );
  });
}

// Family Hub poller — surfaces relatives' alerts as OS notifications, every
// minute. Armed only while there is someone to hear from: a signed-in user
// with a family. For everyone else a 1-minute alarm would wake the worker
// (and evaluate TweetNaCl) just to find nothing to do. Re-checked on every
// worker start and whenever the sign-in or the family changes.
syncFamilyPollAlarm().catch(() => {});

function onFamilyStorageChanged(changes, area) {
  if (area !== "local" || !changes) return;
  const token = changes.auth_token;
  if (token && !token.newValue) {
    // Signed out: the next account must not inherit this family's keys.
    clearFamilyCache();
  } else if (token && token.newValue && !token.oldValue) {
    // Signed in: learn the family now, not the next time Options is opened.
    refreshFamilyCache(token.newValue).catch(() => {});
  }
  if (token || changes.family_cache) syncFamilyPollAlarm().catch(() => {});
}

try {
  chrome.storage.onChanged.addListener(onFamilyStorageChanged);
} catch (e) { /* storage events unavailable — the start-up sync still ran */ }

// Daily history prune — Privacy Policy promises 30-day on-device
// retention. Created only when missing: re-creating on every SW wake
// would restart the 24h clock each time and it might never fire. Checked
// on every start rather than only onInstalled because the browser may
// drop alarms on restart or update.
function ensureHistoryPruneAlarm() {
  if (!chrome.alarms) return;
  chrome.alarms.get(HISTORY_PRUNE_ALARM).then((existing) => {
    if (existing) return;
    chrome.alarms.create(HISTORY_PRUNE_ALARM, {
      delayInMinutes: 5,           // first prune shortly after install
      periodInMinutes: 24 * 60,    // every 24h after that
    });
  }).catch(() => { /* alarms unavailable — nothing to schedule */ });
}
ensureHistoryPruneAlarm();

async function onAlarm(alarm) {
  if (isFamilyPollAlarm(alarm.name)) {
    try {
      await pollAndNotify();
    } catch (e) {
      // Silent — pollAndNotify is fail-open. A missed minute is fine.
    }
    return;
  }

  // Daily local-history prune (30-day rolling retention per Privacy Policy)
  if (alarm.name === HISTORY_PRUNE_ALARM) {
    try {
      const deleted = await pruneOldChecks();
      _log("History prune removed", deleted, "rows");
    } catch (e) {
      // Silent — IndexedDB transient failure isn't user-facing. Worst
      // case is one missed daily prune; tomorrow's run catches up.
    }
  }
}

if (chrome.alarms) chrome.alarms.onAlarm.addListener(onAlarm);

if (chrome.notifications) {
  chrome.notifications.onClicked.addListener((notificationId) => {
    if (!isFamilyNotificationId(notificationId)) return;
    // Open the Options page Family Hub section. chrome.runtime.
    // openOptionsPage() is the canonical way; some MV3 builds need a
    // tabs.create fallback if the options page isn't declared.
    try {
      chrome.runtime.openOptionsPage();
    } catch {
      chrome.tabs.create({ url: chrome.runtime.getURL("src/options/options.html") });
    }
    chrome.notifications.clear(notificationId);
  });
}

if (chrome.contextMenus) {
  chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === "check-link" && info.linkUrl) {
      try {
        const result = await checkLinkUrl(info.linkUrl);
        if (result) chrome.tabs.sendMessage(tab.id, { type: "SHOW_CHECK_RESULT", result });
      } catch (e) {}
    }
    if (info.menuItemId === "audit-page") chrome.tabs.sendMessage(tab.id, { type: "RUN_PRIVACY_AUDIT" });
  });
}

if (chrome.commands) {
  chrome.commands.onCommand.addListener(async (cmd) => {
    if (cmd === "check-page") {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs[0]?.url) {
        const domain = new URL(tabs[0].url).hostname;
        const r = await handleCheck([domain]);
        if (r.results[0]) chrome.tabs.sendMessage(tabs[0].id, { type: "SHOW_CHECK_RESULT", result: r.results[0] });
      }
    }
  });
}

_log("Background ready, API:", API_BASE);

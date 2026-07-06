// build-extensions.sh firefox shim: re-alias chrome to browser so Promise APIs work under MV2
if (typeof browser !== "undefined" && (typeof chrome === "undefined" || !chrome.storage || typeof chrome.storage.local.get === "function")) { var chrome = browser; }
/**
 * Cleanway Background — v3 (bullet-proof)
 */

// Load TweetNaCl into the SW global scope BEFORE any handlers run, so
// utils/family-crypto.js (loaded later via dynamic import) finds
// globalThis.nacl. importScripts is the only way to do this in MV3
// classic-script SWs; if it fails (manifest mode mismatch, manifest
// glob excluded the file), Family Hub fan-out is silently disabled.
try {
  importScripts(
    chrome.runtime.getURL("src/utils/vendor/tweetnacl.min.js"),
    chrome.runtime.getURL("src/utils/vendor/tweetnacl-util.min.js")
  );
} catch (e) {
  console.warn("[Cleanway] tweetnacl load failed; family fan-out disabled:", e && e.message);
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
 * Used by handleCheck() to guard chrome.storage.local.stats RMW so
 * concurrent CHECK_DOMAINS messages from multiple tabs can't lose
 * increments. (Audit extension-mv3 MEDIUM stats counter race.)
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
chrome.storage.local.get(["api_url"], d => { if (d.api_url) API_BASE = d.api_url; });

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

// ── Safe domains ──
const SAFE = new Set(["google.com","youtube.com","facebook.com","amazon.com","wikipedia.org","twitter.com","instagram.com","linkedin.com","reddit.com","apple.com","microsoft.com","github.com","netflix.com","whatsapp.com","tiktok.com","yahoo.com","bing.com","zoom.us","paypal.com","stripe.com","x.com","shopify.com","wordpress.com","medium.com","notion.so","slack.com","discord.com","telegram.org","spotify.com","twitch.tv","stackoverflow.com","cloudflare.com","dropbox.com","adobe.com","ebay.com","walmart.com","chase.com","cnn.com","bbc.com","nytimes.com","google.ru","vk.com","yandex.ru","mail.ru"]);

function baseDomain(d) { var p = d.split("."); return p.length >= 2 ? p.slice(-2).join(".") : d; }

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
const _HR = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".buzz",".icu",".cam",".live",".online",".site",".loan",".download",".zip",".mov",".sbs",".cfd"];
const _SW = ["login","signin","verify","update","confirm","secure","account","password","wallet","payment","invoice","banking","reset","suspend","locked","unlock"];
const _CS = {"1":"l","0":"o","3":"e","@":"a","5":"s"};
const _BR = {"paypal":"paypal.com","apple":"apple.com","google":"google.com","amazon":"amazon.com","microsoft":"microsoft.com","netflix":"netflix.com","facebook":"facebook.com","instagram":"instagram.com","whatsapp":"whatsapp.com","chase":"chase.com","coinbase":"coinbase.com","binance":"binance.com","dhl":"dhl.com","fedex":"fedex.com","ups":"ups.com","ebay":"ebay.com","steam":"store.steampowered.com","discord":"discord.com","telegram":"telegram.org","linkedin":"linkedin.com"};

function scoreLocally(domain) {
  let s = 0; const R = []; const P = domain.split("."); const tld = "." + P[P.length-1];
  const nm = P.length >= 2 ? P[P.length-2] : domain;
  const nmClean = nm.replace(/[-_](verify|login|secure|update|account|confirm|alert|support|help|app|web|mail|team)$/, "");

  for (const b in _BR) {
    if (nm === b || domain === _BR[b] || baseDomain(domain) === _BR[b]) continue;
    let norm = nmClean; for (const c in _CS) norm = norm.replaceAll(c, _CS[c]);
    if (norm === b) { s += 40; R.push({signal:"typosquatting",detail:"Impersonates "+_BR[b],weight:40}); break; }
    if (nm.replaceAll("-","") === b) { s += 30; R.push({signal:"typosquatting",detail:"Impersonates "+_BR[b]+" (hyphen)",weight:30}); break; }
    if (nm.startsWith(b) && nm.length > b.length) {
      const sf = nm.slice(b.length).replace(/^[-_]/,"");
      if (_SW.includes(sf)) { s += 25; R.push({signal:"combosquatting",detail:"Fake "+_BR[b]+"-"+sf,weight:25}); break; }
    }
    if (nm.length === b.length && nm.length >= 4) {
      let diffs = 0; for (let i = 0; i < nm.length; i++) if (nm[i] !== b[i]) diffs++;
      if (diffs <= 2) { s += 25; R.push({signal:"similar",detail:"Similar to "+_BR[b],weight:25}); break; }
    }
  }

  // Brand in subdomain
  if (P.length > 2) {
    for (let i = 0; i < P.length - 2; i++) {
      const cl = P[i].replaceAll("-","");
      if (_BR[cl] && baseDomain(domain) !== _BR[cl]) { s += 30; R.push({signal:"brand_sub",detail:"'"+cl+"' brand in subdomain",weight:30}); break; }
    }
  }

  if (_HR.includes(tld)) { s += 20; R.push({signal:"risky_tld",detail:"High-risk TLD "+tld,weight:20}); }
  for (const w of _SW) { if (domain.includes(w)) { s += 10; R.push({signal:"keyword",detail:"Contains '"+w+"'",weight:10}); break; } }
  if (P.length > 3) { s += 15; R.push({signal:"subdomains",detail:P.length+" levels deep",weight:15}); }
  if (nm.length > 20) { s += 10; R.push({signal:"long",detail:"Long name ("+nm.length+")",weight:10}); }
  if ((domain.match(/-/g)||[]).length >= 3) { s += 10; R.push({signal:"hyphens",detail:"Many hyphens",weight:10}); }

  s = Math.min(s, 100);
  return { domain, score: s, level: s <= 20 ? "safe" : s <= 50 ? "caution" : "dangerous", reasons: R, source: "local" };
}

// ── Main handler ──
async function handleCheck(domains) {
  _log("Checking", domains.length, "domains");
  const results = [];
  const toCheck = [];

  for (const domain of domains) {
    const cached = getCached(domain);
    if (cached) { results.push(cached); continue; }
    if (SAFE.has(baseDomain(domain))) {
      const r = { domain, score: 0, level: "safe", reasons: [{signal:"known",detail:"Known safe",weight:-50}] };
      setCached(domain, r);
      results.push(r);
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
          reasons: (data.signals || []).map(s => ({signal:"api",detail:s,weight:10})),
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

  // Track stats — guarded by an async mutex.
  //
  // The MV3 service worker can dispatch multiple handleCheck() calls
  // concurrently (one per tab message in flight). Without serialisation,
  // two read/modify/write cycles on chrome.storage.local.stats can
  // interleave: A reads {blocked:5}, B reads {blocked:5}, both write
  // {blocked:6} — and one block is lost from the user's lifetime tally.
  // (Audit extension-mv3 MEDIUM "Stats counter has an unguarded
  // read-modify-write race in the MV3 service worker".)
  //
  // The mutex is a single rotating promise chain in module scope; each
  // handleCheck appends its critical section to the chain and awaits
  // the chain head. Under low contention this is effectively free.
  let dangerousBlocksThisBatch = 0;
  try {
    await _statsMutex.runExclusive(async () => {
      const data = await chrome.storage.local.get(["stats"]);
      const stats = data.stats || { total_checks: 0, threats_blocked: 0, threats_warned: 0 };
      for (const r of results) {
        stats.total_checks++;
        if (r.level === "dangerous") {
          stats.threats_blocked++;
          dangerousBlocksThisBatch++;
        }
        if (r.level === "caution") stats.threats_warned++;
      }
      await chrome.storage.local.set({ stats });
    });
  } catch (e) {}

  // Server-side lifetime counter for the Pricing v2 freemium gating —
  // only increment for confirmed DANGEROUS blocks (caution/warnings
  // don't count against the threshold). Best-effort: silent on
  // network errors and on anonymous users (no auth_token).
  if (dangerousBlocksThisBatch > 0) {
    try {
      const stored = await chrome.storage.local.get(["auth_token"]);
      if (stored && stored.auth_token) {
        const apiModule = await import(chrome.runtime.getURL("src/utils/api.js"));
        await apiModule.incrementThreatCounter(stored.auth_token, dangerousBlocksThisBatch);

        // Family Hub auto-fan-out: encrypt this batch of dangerous
        // results to every sibling's pubkey (cached by options.js
        // last time the user opened Family Hub) and POST to
        // /family/{id}/alerts. Server stays blind — encryption
        // happens here. Dedup window inside fanOutAlerts prevents
        // spam from page reloads.
        try {
          const fanout = await import(chrome.runtime.getURL("src/utils/family-fanout.js"));
          const dangerous = results.filter(r => r.level === "dangerous");
          await fanout.fanOutAlerts(stored.auth_token, dangerous);
        } catch (e) {
          // Silent — family alerts are courtesy; never block UX.
        }
      }
    } catch (e) {
      // No-op: a missed sync just means the popup nudge appears later
      // than ideal — block UX itself is unaffected.
    }
  }

  // Badge
  try {
    const threats = results.filter(r => r.level === "dangerous" || r.level === "caution").length;
    if (threats > 0) {
      chrome.action.setBadgeText({ text: String(threats) });
      chrome.action.setBadgeBackgroundColor({ color: results.some(r => r.level === "dangerous") ? "#ef4444" : "#f59e0b" });
    }
  } catch (e) {}

  _log("Returning", results.length, "results");
  return { results };
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
    handleCheck(msg.domains)
      .then((results) => {
        // Strategy #1 expansion: promote credential-guardian to
        // strict mode in the tab that asked for the check if ANY of
        // the returned results is dangerous. Strict mode intercepts
        // form submit instead of just warning above it — the right
        // posture when we already know the page is hostile.
        try {
          if (sender && sender.tab && sender.tab.id != null) {
            const dangerous = Array.isArray(results)
              ? results.some((r) => r && r.level === "dangerous")
              : false;
            if (dangerous) {
              chrome.tabs
                .sendMessage(sender.tab.id, { type: "CREDGUARD_STRICT" })
                .catch(() => {
                  // Content script may not be present (block-page
                  // overlay races the SW response). Non-fatal.
                });
            }
          }
        } catch (e) { /* ignore */ }
        respond(results);
      })
      .catch((err) => {
        try { respond({ error: "background_failure", message: String(err && err.message ? err.message : err) }); }
        catch (e) { /* port closed before respond fired — nothing we can do */ }
      });
    return true;
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
  // removeAll() first so re-running onInstalled (fires on update/reload, and
  // the SW can replay it) doesn't hit "Cannot create item with duplicate id".
  chrome.contextMenus.removeAll(() => {
    // Read lastError to clear it (removeAll on an empty menu set is fine).
    void chrome.runtime.lastError;
    chrome.contextMenus.create({ id: "check-link", title: "Check with Cleanway", contexts: ["link"] });
    chrome.contextMenus.create({ id: "audit-page", title: "Privacy Audit", contexts: ["page"] });
  });
  // Family Hub poller — fires every minute while the user is signed
  // in + has a family cached. Fan-out (background side) ensures the
  // server has the alert; this poller surfaces incoming siblings'
  // alerts as OS notifications.
  void (async () => {
    try {
      const notifier = await import(chrome.runtime.getURL("src/utils/family-notifier.js"));
      notifier.ensureFamilyPollAlarm(1);
    } catch (e) { /* alarms permission missing — silent */ }
  })();

  // Daily history prune — Privacy Policy promises 30-day on-device
  // retention; the prune helper has been there since launch but
  // nobody was actually invoking it, so IndexedDB grew unbounded.
  // chrome.alarms persists across SW eviction, so once installed the
  // schedule keeps firing without further setup.
  chrome.alarms.create("cleanway_history_prune", {
    delayInMinutes: 5,           // first prune shortly after install
    periodInMinutes: 24 * 60,    // every 24h after that
  });
});

// Re-arm the alarm on every SW startup (the SW can get evicted; alarms
// survive eviction, but installing on startup is idempotent insurance).
void (async () => {
  try {
    const notifier = await import(chrome.runtime.getURL("src/utils/family-notifier.js"));
    notifier.ensureFamilyPollAlarm(1);
  } catch (e) { /* silent */ }
})();

chrome.alarms.onAlarm.addListener(async (alarm) => {
  // Family Hub minute poller
  try {
    const notifier = await import(chrome.runtime.getURL("src/utils/family-notifier.js"));
    if (notifier.isFamilyPollAlarm(alarm.name)) {
      await notifier.pollAndNotify();
      return;
    }
  } catch (e) {
    // Silent — pollAndNotify is fail-open. A missed minute is fine.
  }

  // Daily local-history prune (30-day rolling retention per Privacy Policy)
  if (alarm.name === "cleanway_history_prune") {
    try {
      const storage = await import(chrome.runtime.getURL("src/utils/storage.js"));
      await storage.pruneOldChecks();
    } catch (e) {
      // Silent — IndexedDB transient failure isn't user-facing. Worst
      // case is one missed daily prune; tomorrow's run catches up.
    }
  }
});

chrome.notifications.onClicked.addListener(async (notificationId) => {
  try {
    const notifier = await import(chrome.runtime.getURL("src/utils/family-notifier.js"));
    if (!notifier.isFamilyNotificationId(notificationId)) return;
    // Open the Options page Family Hub section. chrome.runtime.
    // openOptionsPage() is the canonical way; some MV3 builds need a
    // tabs.create fallback if the options page isn't declared.
    try {
      chrome.runtime.openOptionsPage();
    } catch {
      chrome.tabs.create({ url: chrome.runtime.getURL("src/options/options.html") });
    }
    chrome.notifications.clear(notificationId);
  } catch (e) { /* silent */ }
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "check-link" && info.linkUrl) {
    try {
      const domain = new URL(info.linkUrl).hostname.toLowerCase();
      const r = await handleCheck([domain]);
      if (r.results[0]) chrome.tabs.sendMessage(tab.id, { type: "SHOW_CHECK_RESULT", result: r.results[0] });
    } catch (e) {}
  }
  if (info.menuItemId === "audit-page") chrome.tabs.sendMessage(tab.id, { type: "RUN_PRIVACY_AUDIT" });
});

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

_log("Background ready, API:", API_BASE);

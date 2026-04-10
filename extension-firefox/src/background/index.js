/**
 * LinkShield — Background Service Worker (Manifest V3)
 * Self-contained: no ES module imports (MV3 service workers don't support cross-file imports)
 *
 * Pipeline: bloom filter → in-memory cache → API
 */

// ═══════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════

const API_BASE = "http://localhost:8000"; // Change to https://api.linkshield.io in production
const CACHE_TTL = { safe: 3600000, caution: 900000, dangerous: 300000 };
const BLOOM_SIZE = 1437759;
const BLOOM_HASH_COUNT = 10;

// ═══════════════════════════════════════════════════
// IN-MEMORY CACHE
// ═══════════════════════════════════════════════════

const _cache = new Map();

function getCached(domain) {
  const e = _cache.get(domain);
  if (!e) return null;
  const ttl = CACHE_TTL[e.result.level] || 3600000;
  if (Date.now() - e.ts > ttl) { _cache.delete(domain); return null; }
  return e.result;
}

function setCached(domain, result) {
  _cache.set(domain, { result, ts: Date.now() });
  if (_cache.size > 5000) {
    const oldest = [..._cache.entries()].sort((a, b) => a[1].ts - b[1].ts).slice(0, 1000);
    for (const [k] of oldest) _cache.delete(k);
  }
}

// ═══════════════════════════════════════════════════
// BLOOM FILTER (MurmurHash3)
// ═══════════════════════════════════════════════════

let _bloomBits = null;

function murmurhash3(key, seed) {
  let h = seed >>> 0;
  for (let i = 0; i < key.length; i++) {
    let k = key.charCodeAt(i);
    k = Math.imul(k, 0xcc9e2d51);
    k = (k << 15) | (k >>> 17);
    k = Math.imul(k, 0x1b873593);
    h ^= k;
    h = (h << 13) | (h >>> 19);
    h = Math.imul(h, 5) + 0xe6546b64;
  }
  h ^= key.length;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h >>> 0;
}

function bloomCheck(domain) {
  if (!_bloomBits) return false;
  const d = domain.toLowerCase();
  for (let i = 0; i < BLOOM_HASH_COUNT; i++) {
    const pos = murmurhash3(d, (i * 0x9e3779b9) >>> 0) % BLOOM_SIZE;
    if ((_bloomBits[pos >>> 3] & (1 << (pos & 7))) === 0) return false;
  }
  return true;
}

async function loadBloomFilter() {
  try {
    const stored = await chrome.storage.local.get(["bloom_filter", "bloom_meta"]);
    if (stored.bloom_filter && stored.bloom_meta) {
      const age = Date.now() - (stored.bloom_meta.timestamp || 0);
      if (age < 86400000) { // 24h
        _bloomBits = new Uint8Array(stored.bloom_filter);
        console.log(`[LS] Bloom loaded from cache: ${_bloomBits.length} bytes`);
        return;
      }
    }
  } catch (e) {}

  // Build minimal local bloom from hardcoded top domains
  const top = [
    "google.com","youtube.com","facebook.com","amazon.com","wikipedia.org",
    "twitter.com","instagram.com","linkedin.com","reddit.com","apple.com",
    "microsoft.com","github.com","netflix.com","whatsapp.com","tiktok.com",
    "yahoo.com","bing.com","zoom.us","paypal.com","stripe.com","x.com",
    "shopify.com","wordpress.com","medium.com","notion.so","slack.com",
    "discord.com","telegram.org","spotify.com","twitch.tv","stackoverflow.com",
    "cloudflare.com","dropbox.com","adobe.com","salesforce.com","ebay.com",
    "walmart.com","chase.com","bankofamerica.com","cnn.com","bbc.com",
    "nytimes.com","washingtonpost.com","forbes.com","bloomberg.com",
    "pinterest.com","tumblr.com","gmail.com","outlook.com","office.com",
  ];
  const bits = new Uint8Array(Math.ceil(BLOOM_SIZE / 8));
  for (const d of top) {
    for (let i = 0; i < BLOOM_HASH_COUNT; i++) {
      const pos = murmurhash3(d, (i * 0x9e3779b9) >>> 0) % BLOOM_SIZE;
      bits[pos >>> 3] |= (1 << (pos & 7));
    }
  }
  _bloomBits = bits;
  console.log(`[LS] Bloom built locally: ${top.length} domains`);
}

// ═══════════════════════════════════════════════════
// API CLIENT
// ═══════════════════════════════════════════════════

async function apiCheckDomains(domains, token) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;

  try {
    const resp = await fetch(`${API_BASE}/api/v1/check`, {
      method: "POST",
      headers,
      body: JSON.stringify({ domains }),
    });
    if (resp.status === 429) return { error: "rate_limit", detail: await resp.json() };
    if (!resp.ok) return { error: "api_error", status: resp.status };
    return await resp.json();
  } catch (e) {
    return { error: "network", message: e.message };
  }
}

// ═══════════════════════════════════════════════════
// MAIN CHECK HANDLER
// ═══════════════════════════════════════════════════

async function handleCheckDomains(domains) {
  const results = [];
  const needsApi = [];

  for (const domain of domains) {
    // 1. Cache
    const cached = getCached(domain);
    if (cached) { results.push({ ...cached, cached: true }); continue; }

    // 2. Bloom filter
    if (bloomCheck(domain)) {
      const safe = {
        domain, score: 0, level: "safe", confidence: "high",
        reasons: [{ signal: "known_legitimate", detail: "Known safe domain", weight: -50 }],
        source: "bloom",
      };
      setCached(domain, safe);
      results.push(safe);
      continue;
    }

    // 3. API needed
    needsApi.push(domain);
  }

  if (needsApi.length > 0) {
    const storage = await chrome.storage.local.get(["auth_token"]);
    const resp = await apiCheckDomains(needsApi, storage.auth_token || null);

    if (resp.results) {
      for (const r of resp.results) {
        setCached(r.domain, r);
        results.push(r);
        if (r.level === "dangerous" || r.level === "caution") {
          await addRecentThreat(r);
        }
        if (r.level === "dangerous") {
          chrome.action.setBadgeText({ text: "!" });
          chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
          setTimeout(() => chrome.action.setBadgeText({ text: "" }), 30000);

          // Push notification
          try {
            chrome.notifications.create("threat-" + Date.now(), {
              type: "basic",
              iconUrl: "public/icons/icon128.png",
              title: "Dangerous link detected!",
              message: r.domain + " — Score: " + r.score + "/100. " + (r.reasons && r.reasons[0] ? r.reasons[0].detail : ""),
              priority: 2,
            });
          } catch(e) {}
        }
      }
    } else if (resp.error === "rate_limit") {
      for (const d of needsApi) {
        results.push({
          domain: d, score: 25, level: "caution",
          reasons: [{ signal: "rate_limited", detail: "Upgrade for unlimited checks", weight: 0 }],
        });
      }
    } else if (resp.error === "network") {
      // API unavailable — return unknown with warning
      for (const d of needsApi) {
        results.push({
          domain: d, score: 30, level: "caution",
          reasons: [{ signal: "api_unavailable", detail: "Could not reach LinkShield API", weight: 0 }],
        });
      }
    }
  }

  await trackStats(results);
  return { results };
}

// ═══════════════════════════════════════════════════
// STATS & STORAGE
// ═══════════════════════════════════════════════════

async function addRecentThreat(result) {
  const data = await chrome.storage.local.get(["recent_threats"]);
  const threats = data.recent_threats || [];
  threats.unshift({ domain: result.domain, score: result.score, level: result.level, time: new Date().toISOString() });
  await chrome.storage.local.set({ recent_threats: threats.slice(0, 50) });
}

async function trackStats(results) {
  const data = await chrome.storage.local.get(["stats"]);
  const stats = data.stats || { total_checks: 0, threats_blocked: 0, threats_warned: 0, first_scan: null };
  if (!stats.first_scan) stats.first_scan = new Date().toISOString();
  stats.last_scan = new Date().toISOString();
  for (const r of results) {
    stats.total_checks++;
    if (r.level === "dangerous") stats.threats_blocked++;
    if (r.level === "caution") stats.threats_warned++;
  }
  await chrome.storage.local.set({ stats });
}

// ═══════════════════════════════════════════════════
// CONTEXT MENU
// ═══════════════════════════════════════════════════

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "check-link", title: "Check link with LinkShield", contexts: ["link"] });
  chrome.contextMenus.create({ id: "audit-page", title: "Privacy Audit this page", contexts: ["page"] });
  loadBloomFilter();
  chrome.alarms.create("cleanup", { periodInMinutes: 60 });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "check-link" && info.linkUrl) {
    try {
      const url = new URL(info.linkUrl);
      const resp = await handleCheckDomains([url.hostname.toLowerCase()]);
      if (resp.results?.[0]) {
        chrome.tabs.sendMessage(tab.id, { type: "SHOW_CHECK_RESULT", result: resp.results[0] });
      }
    } catch (e) {}
  }
  if (info.menuItemId === "audit-page") {
    chrome.tabs.sendMessage(tab.id, { type: "RUN_PRIVACY_AUDIT" });
  }
});

// ═══════════════════════════════════════════════════
// MESSAGE LISTENER
// ═══════════════════════════════════════════════════

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "CHECK_DOMAINS") {
    handleCheckDomains(message.domains).then(sendResponse);
    return true; // async
  }
  if (message.type === "GET_STATS") {
    chrome.storage.local.get(["stats"]).then(d => sendResponse(d.stats || {}));
    return true;
  }
  if (message.type === "PRIVACY_AUDIT_RESULT") {
    chrome.storage.local.get(["audits"]).then(d => {
      const audits = d.audits || {};
      audits[message.result.domain] = message.result;
      chrome.storage.local.set({ audits });
    });
  }
  if (message.type === "EMAIL_PAGE_DETECTED") {
    chrome.storage.local.get(["aha_moment"]).then(d => {
      const aha = d.aha_moment || { email_scans: 0 };
      aha.email_scans++;
      chrome.storage.local.set({ aha_moment: aha });
    });
  }
});

// ═══════════════════════════════════════════════════
// ALARMS
// ═══════════════════════════════════════════════════

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "cleanup") {
    const now = Date.now();
    for (const [k, v] of _cache) {
      if (now - v.ts > 3600000) _cache.delete(k);
    }
  }
});

// Track install date for security score
chrome.storage.local.get(["install_date"], function(data) {
  if (!data.install_date) {
    chrome.storage.local.set({ install_date: new Date().toISOString() });
  }
});

// Load bloom on startup
loadBloomFilter();

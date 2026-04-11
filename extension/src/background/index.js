/**
 * LinkShield Background — Simplified & Working
 */

let API_BASE = "http://localhost:8000";
chrome.storage.local.get(["api_url"], function(data) {
  if (data.api_url) API_BASE = data.api_url;
});

// ── Cache ──
const _cache = new Map();
function getCached(d) { const e = _cache.get(d); if (!e) return null; if (Date.now() - e.ts > 3600000) { _cache.delete(d); return null; } return e.r; }
function setCached(d, r) { _cache.set(d, { r, ts: Date.now() }); if (_cache.size > 5000) _cache.clear(); }

// ── Known safe domains (mini bloom) ──
const SAFE = new Set(["google.com","youtube.com","facebook.com","amazon.com","wikipedia.org","twitter.com","instagram.com","linkedin.com","reddit.com","apple.com","microsoft.com","github.com","netflix.com","whatsapp.com","tiktok.com","yahoo.com","bing.com","zoom.us","paypal.com","stripe.com","x.com","shopify.com","wordpress.com","medium.com","notion.so","slack.com","discord.com","telegram.org","spotify.com","twitch.tv","stackoverflow.com","cloudflare.com","dropbox.com","adobe.com","ebay.com","walmart.com","chase.com","cnn.com","bbc.com","nytimes.com"]);

function baseDomain(d) { var p = d.split("."); return p.length >= 2 ? p.slice(-2).join(".") : d; }

// ── Check domains ──
async function handleCheck(domains) {
  console.log("[LS-BG] handleCheck called with", domains.length, "domains");
  const results = [];
  const needsApi = [];

  for (const domain of domains) {
    // Cache
    const cached = getCached(domain);
    if (cached) { results.push(cached); continue; }
    // Safe list
    if (SAFE.has(baseDomain(domain))) {
      const r = { domain, score: 0, level: "safe", reasons: [{ signal: "known", detail: "Known safe domain", weight: -50 }] };
      setCached(domain, r);
      results.push(r);
      continue;
    }
    needsApi.push(domain);
  }

  // Fetch from public API (no auth needed)
  for (const domain of needsApi) {
    try {
      console.log("[LS-BG] Checking via API:", domain);
      const resp = await fetch(`${API_BASE}/api/v1/public/check/${encodeURIComponent(domain)}`);
      if (resp.ok) {
        const data = await resp.json();
        const r = {
          domain: data.domain || domain,
          score: data.score,
          level: data.level,
          reasons: (data.signals || []).map(s => ({ signal: "api", detail: s, weight: 10 })),
        };
        console.log("[LS-BG] API result:", domain, "score=" + r.score, r.level);
        setCached(domain, r);
        results.push(r);

        if (r.level === "dangerous") {
          chrome.action.setBadgeText({ text: "!" });
          chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
          setTimeout(() => chrome.action.setBadgeText({ text: "" }), 30000);
          try {
            chrome.notifications.create("threat-" + Date.now(), {
              type: "basic", iconUrl: "public/icons/icon128.png",
              title: "Dangerous link!", message: domain + " — Score: " + r.score, priority: 2,
            });
          } catch (e) {}
        }
        continue;
      }
    } catch (e) {
      console.log("[LS-BG] API error for", domain, e.message);
    }

    // Local fallback
    const r = localFallback(domain);
    console.log("[LS-BG] Local fallback:", domain, "score=" + r.score, r.level);
    setCached(domain, r);
    results.push(r);
  }

  // Track stats
  const data = await chrome.storage.local.get(["stats"]);
  const stats = data.stats || { total_checks: 0, threats_blocked: 0, threats_warned: 0 };
  for (const r of results) {
    stats.total_checks++;
    if (r.level === "dangerous") stats.threats_blocked++;
    if (r.level === "caution") stats.threats_warned++;
  }
  await chrome.storage.local.set({ stats });

  console.log("[LS-BG] Returning", results.length, "results");
  return { results };
}

// ── Local scoring fallback ──
const _HR = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".buzz",".icu",".cam",".live",".online",".site"];
const _SW = ["login","signin","verify","update","confirm","secure","account","password","wallet","payment","invoice","banking","reset","suspend","locked"];
const _CS = {"1":"l","0":"o","3":"e","@":"a","5":"s"};
const _BR = {"paypal":"paypal.com","apple":"apple.com","google":"google.com","amazon":"amazon.com","microsoft":"microsoft.com","netflix":"netflix.com","facebook":"facebook.com","instagram":"instagram.com","whatsapp":"whatsapp.com","chase":"chase.com","coinbase":"coinbase.com","binance":"binance.com"};

function localFallback(domain) {
  let s = 0; const R = []; const P = domain.split("."); const tld = "." + P[P.length-1];
  const nm = P.length >= 2 ? P[P.length-2] : domain;
  const nmClean = nm.replace(/[-_](verify|login|secure|update|account|confirm|alert|support)$/, "");

  // Typosquat
  for (const b in _BR) {
    if (nm === b || domain === _BR[b]) continue;
    let norm = nmClean; for (const c in _CS) norm = norm.split(c).join(_CS[c]);
    if (norm === b) { s += 40; R.push({signal:"typosquatting",detail:"Impersonates " + _BR[b],weight:40}); break; }
    if (nm.replace(/-/g,"") === b) { s += 30; R.push({signal:"typosquatting",detail:"Impersonates " + _BR[b],weight:30}); break; }
    if (nm.startsWith(b) && nm.length > b.length) {
      const sf = nm.slice(b.length).replace(/^-/,"");
      if (_SW.indexOf(sf) !== -1) { s += 25; R.push({signal:"combosquatting",detail:"Impersonates " + _BR[b],weight:25}); break; }
    }
  }

  if (_HR.indexOf(tld) !== -1) { s += 20; R.push({signal:"risky_tld",detail:"High-risk TLD " + tld,weight:20}); }
  for (const w of _SW) { if (domain.indexOf(w) !== -1) { s += 10; R.push({signal:"keyword",detail:"Contains '" + w + "'",weight:10}); break; } }
  if (P.length > 3) { s += 15; R.push({signal:"subdomains",detail:P.length + " levels deep",weight:15}); }
  if (nm.length > 20) { s += 10; R.push({signal:"long",detail:"Long domain name",weight:10}); }

  s = Math.min(s, 100);
  return { domain, score: s, level: s <= 20 ? "safe" : s <= 50 ? "caution" : "dangerous", reasons: R };
}

// ── Message listener ──
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("[LS-BG] Message:", message.type);

  if (message.type === "CHECK_DOMAINS") {
    handleCheck(message.domains).then(result => {
      console.log("[LS-BG] Sending response:", result.results.length, "results");
      sendResponse(result);
    });
    return true; // async
  }

  if (message.type === "GET_STATS") {
    chrome.storage.local.get(["stats"]).then(d => sendResponse(d.stats || { total_checks: 0, threats_blocked: 0, threats_warned: 0 }));
    return true;
  }
});

// ── Context menu ──
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "check-link", title: "Check link with LinkShield", contexts: ["link"] });
  chrome.contextMenus.create({ id: "audit-page", title: "Privacy Audit this page", contexts: ["page"] });
  chrome.storage.local.get(["install_date"], d => {
    if (!d.install_date) chrome.storage.local.set({ install_date: new Date().toISOString() });
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === "check-link" && info.linkUrl) {
    try {
      const domain = new URL(info.linkUrl).hostname.toLowerCase();
      const resp = await handleCheck([domain]);
      if (resp.results[0]) chrome.tabs.sendMessage(tab.id, { type: "SHOW_CHECK_RESULT", result: resp.results[0] });
    } catch (e) {}
  }
  if (info.menuItemId === "audit-page") {
    chrome.tabs.sendMessage(tab.id, { type: "RUN_PRIVACY_AUDIT" });
  }
});

// ── Keyboard shortcut ──
chrome.commands.onCommand.addListener(async (cmd) => {
  if (cmd === "check-page") {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0] && tabs[0].url) {
      try {
        const domain = new URL(tabs[0].url).hostname;
        const resp = await handleCheck([domain]);
        if (resp.results[0]) chrome.tabs.sendMessage(tabs[0].id, { type: "SHOW_CHECK_RESULT", result: resp.results[0] });
      } catch (e) {}
    }
  }
});

console.log("[LS-BG] Background loaded, API:", API_BASE);

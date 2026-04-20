/**
 * LinkShield Background — v3 (bullet-proof)
 */

// API base — production Railway default, override via Options page (chrome.storage.local.api_url)
let API_BASE = "https://web-production-fe08.up.railway.app";
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

// ── Cache ──
const _cache = new Map();
function getCached(d) { const e = _cache.get(d); if (!e || Date.now() - e.ts > 3600000) return null; return e.r; }
function setCached(d, r) { _cache.set(d, { r, ts: Date.now() }); }

// ── Safe domains ──
const SAFE = new Set(["google.com","youtube.com","facebook.com","amazon.com","wikipedia.org","twitter.com","instagram.com","linkedin.com","reddit.com","apple.com","microsoft.com","github.com","netflix.com","whatsapp.com","tiktok.com","yahoo.com","bing.com","zoom.us","paypal.com","stripe.com","x.com","shopify.com","wordpress.com","medium.com","notion.so","slack.com","discord.com","telegram.org","spotify.com","twitch.tv","stackoverflow.com","cloudflare.com","dropbox.com","adobe.com","ebay.com","walmart.com","chase.com","cnn.com","bbc.com","nytimes.com","google.ru","vk.com","yandex.ru","mail.ru"]);

function baseDomain(d) { var p = d.split("."); return p.length >= 2 ? p.slice(-2).join(".") : d; }

// ── Fetch with timeout ──
function fetchWithTimeout(url, ms) {
  return Promise.race([
    fetch(url),
    new Promise((_, reject) => setTimeout(() => reject(new Error("timeout")), ms))
  ]);
}

// ── Local scoring (instant, no network) ──
const _HR = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".buzz",".icu",".cam",".live",".online",".site",".loan",".download"];
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
  console.log("[LS] Checking", domains.length, "domains");
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
    console.log("[LS] Local:", d, "score=" + localResults[d].score, localResults[d].level);
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
        console.log("[LS] API:", d, "score=" + r.score, r.level);
        setCached(d, r);
        results.push(r);
        continue;
      }
    } catch (e) {
      console.log("[LS] API timeout/error for", d, "- using local score");
    }

    // Use local result
    const lr = localResults[d];
    setCached(d, lr);
    results.push(lr);
  }

  // Track stats
  try {
    const data = await chrome.storage.local.get(["stats"]);
    const stats = data.stats || { total_checks: 0, threats_blocked: 0, threats_warned: 0 };
    for (const r of results) {
      stats.total_checks++;
      if (r.level === "dangerous") stats.threats_blocked++;
      if (r.level === "caution") stats.threats_warned++;
    }
    await chrome.storage.local.set({ stats });
  } catch (e) {}

  // Badge
  try {
    const threats = results.filter(r => r.level === "dangerous" || r.level === "caution").length;
    if (threats > 0) {
      chrome.action.setBadgeText({ text: String(threats) });
      chrome.action.setBadgeBackgroundColor({ color: results.some(r => r.level === "dangerous") ? "#ef4444" : "#f59e0b" });
    }
  } catch (e) {}

  console.log("[LS] Returning", results.length, "results");
  return { results };
}

// ── Messages ──
chrome.runtime.onMessage.addListener((msg, sender, respond) => {
  if (msg.type === "CHECK_DOMAINS") {
    handleCheck(msg.domains).then(respond);
    return true;
  }
  if (msg.type === "GET_STATS") {
    chrome.storage.local.get(["stats"]).then(d => respond(d.stats || {}));
    return true;
  }
});

// ── Context menu ──
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "check-link", title: "Check with LinkShield", contexts: ["link"] });
  chrome.contextMenus.create({ id: "audit-page", title: "Privacy Audit", contexts: ["page"] });
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

console.log("[LS] Background ready, API:", API_BASE);

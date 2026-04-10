/**
 * LinkShield — Background Service Worker (Manifest V3)
 * Self-contained: no ES module imports (MV3 service workers don't support cross-file imports)
 *
 * Pipeline: bloom filter → in-memory cache → API
 */

// ═══════════════════════════════════════════════════
// CONFIG
// ═══════════════════════════════════════════════════

// API URL — configurable from options page
let API_BASE = "http://localhost:8000";

// Load custom API URL from storage (set in options)
chrome.storage.local.get(["api_url"], function(data) {
  if (data.api_url) API_BASE = data.api_url;
});
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
      // API unavailable — use full local scoring engine
      for (const d of needsApi) {
        var lr = localScoreFull(d);
        setCached(d, lr);
        results.push(lr);
        if (lr.level === "dangerous") {
          chrome.action.setBadgeText({ text: "!" });
          chrome.action.setBadgeBackgroundColor({ color: "#ef4444" });
          setTimeout(() => chrome.action.setBadgeText({ text: "" }), 30000);
          try {
            chrome.notifications.create("threat-" + Date.now(), {
              type: "basic", iconUrl: "public/icons/icon128.png",
              title: "Dangerous link detected!", priority: 2,
              message: lr.domain + " — Score: " + lr.score + "/100. " + (lr.reasons[0] ? lr.reasons[0].detail : ""),
            });
          } catch(e) {}
        }
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

// ═══════════════════════════════════════════════════
// LOCAL SCORING ENGINE (full offline — 13 signals)
// ═══════════════════════════════════════════════════

var _BRANDS={"paypal":"paypal.com","apple":"apple.com","google":"google.com","amazon":"amazon.com","microsoft":"microsoft.com","netflix":"netflix.com","facebook":"facebook.com","instagram":"instagram.com","whatsapp":"whatsapp.com","linkedin":"linkedin.com","twitter":"twitter.com","github":"github.com","dropbox":"dropbox.com","spotify":"spotify.com","adobe":"adobe.com","slack":"slack.com","discord":"discord.com","ebay":"ebay.com","walmart":"walmart.com","chase":"chase.com","wellsfargo":"wellsfargo.com","bankofamerica":"bankofamerica.com","coinbase":"coinbase.com","binance":"binance.com","youtube":"youtube.com","yahoo":"yahoo.com","tiktok":"tiktok.com","reddit":"reddit.com","zoom":"zoom.us","stripe":"stripe.com","fedex":"fedex.com","ups":"ups.com","usps":"usps.com","dhl":"dhl.com","citi":"citi.com","metamask":"metamask.io","telegram":"telegram.org","icloud":"icloud.com","outlook":"outlook.com","gmail":"gmail.com","roblox":"roblox.com"};
var _HR_TLDS=[".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".buzz",".icu",".cam",".live",".online",".site",".loan",".download"];
var _MR_TLDS=[".info",".biz",".cc",".pw",".ws",".club",".space",".fun",".monster"];
var _SUS_WORDS=["login","signin","verify","update","confirm","secure","account","banking","password","reset","suspend","locked","unlock","wallet","payment","invoice","billing","refund","recovery","alert","urgent","expired"];
var _HOSTING=["pages.dev","workers.dev","r2.dev","netlify.app","vercel.app","herokuapp.com","github.io","gitlab.io","web.app","firebaseapp.com","webflow.io","framer.app","wixstudio.com","blogspot.com","lovable.app","replit.app","webcindario.com"];
var _CSUBS={"1":"l","0":"o","3":"e","@":"a","5":"s"};

function localScoreFull(domain) {
  var s=0, R=[], P=domain.split("."), tld="."+P[P.length-1];
  var base=P.length>=2?P.slice(-2).join("."):domain, nm=P.length>=2?P[P.length-2]:domain;

  // Typosquat
  for(var b in _BRANDS){var leg=_BRANDS[b];if(domain===leg||base===leg)continue;
    if(nm===b&&"."+leg.split(".").pop()!==tld){s+=30;R.push({signal:"typosquatting",detail:"Impersonates "+leg+" (wrong TLD)",weight:30});break}
    if(nm===b)continue;
    var norm=nm;for(var c in _CSUBS)norm=norm.split(c).join(_CSUBS[c]);
    if(norm===b){s+=30;R.push({signal:"typosquatting",detail:"Impersonates "+leg+" (char substitution)",weight:30});break}
    if(nm.replace(/-/g,"")===b&&nm.indexOf("-")!==-1){s+=25;R.push({signal:"typosquatting",detail:"Impersonates "+leg+" (hyphen injection)",weight:25});break}
    if(nm.startsWith(b)&&nm.length>b.length){var sf=nm.slice(b.length).replace(/^-/,"");if(_SUS_WORDS.indexOf(sf)!==-1){s+=25;R.push({signal:"combosquatting",detail:"Impersonates "+leg+"-"+sf,weight:25});break}}
    if(nm.length===b.length&&nm.length>=4){var df=0;for(var i=0;i<nm.length;i++)if(nm[i]!==b[i])df++;if(df<=2){s+=25;R.push({signal:"typosquatting",detail:"Similar to "+leg,weight:25});break}}
  }

  // Brand in subdomain
  if(P.length>2)for(var k=0;k<P.length-2;k++){var cl=P[k].replace(/-/g,"");if(_BRANDS[cl]&&base!==_BRANDS[cl]){s+=30;R.push({signal:"brand_subdomain",detail:"Uses '"+cl+"' brand as subdomain",weight:30});break}}

  // Fake TLD
  if(P.length>2){var rTLD=["com","org","net","gov","edu","co"];for(var j=0;j<P.length-2;j++)if(rTLD.indexOf(P[j])!==-1){s+=35;R.push({signal:"fake_tld",detail:"Fake TLD '."+P[j]+"' in subdomain",weight:35});break}}

  // TLD risk
  if(_HR_TLDS.indexOf(tld)!==-1){s+=20;R.push({signal:"risky_tld",detail:"High-risk TLD "+tld,weight:20})}
  else if(_MR_TLDS.indexOf(tld)!==-1){s+=10;R.push({signal:"risky_tld",detail:"Suspicious TLD "+tld,weight:10})}

  // Keywords
  for(var w of _SUS_WORDS)if(domain.indexOf(w)!==-1){s+=10;R.push({signal:"keyword",detail:"Contains '"+w+"'",weight:10});break}

  // @
  if(domain.indexOf("@")!==-1){s+=40;R.push({signal:"at_symbol",detail:"@ symbol — phishing trick",weight:40})}

  // Structure
  if(nm.length>25){s+=10;R.push({signal:"long_name",detail:"Long domain ("+nm.length+" chars)",weight:10})}
  var hy=(domain.match(/-/g)||[]).length;if(hy>=3){s+=15;R.push({signal:"hyphens",detail:hy+" hyphens",weight:15})}
  if(P.length>3){s+=15;R.push({signal:"subdomains",detail:P.length+" levels deep",weight:15})}

  // Entropy
  var freq={};for(var i2=0;i2<nm.length;i2++)freq[nm[i2]]=(freq[nm[i2]]||0)+1;
  var ent=0;for(var ch in freq){var p=freq[ch]/nm.length;if(p>0)ent-=p*Math.log2(p)}
  if(ent>4.0&&nm.length>8){s+=20;R.push({signal:"dga",detail:"Auto-generated domain (entropy="+ent.toFixed(1)+")",weight:20})}

  // Digits
  var digs=(nm.match(/\d/g)||[]).length;if(digs/nm.length>0.4&&nm.length>5){s+=15;R.push({signal:"digits",detail:Math.round(digs/nm.length*100)+"% digits",weight:15})}

  // Hosting
  if(_HOSTING.indexOf(base)!==-1&&domain!==base){s+=10;R.push({signal:"hosting",detail:"Shared hosting platform",weight:10})}

  s=Math.min(s,100);
  return{domain:domain,score:s,level:s<=20?"safe":s<=50?"caution":"dangerous",confidence:R.length>=3?"medium":"low",reasons:R,source:"local"};
}

// Keyboard shortcut handler
chrome.commands.onCommand.addListener(async (command) => {
  if (command === "check-page") {
    var tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs[0] && tabs[0].url) {
      try {
        var domain = new URL(tabs[0].url).hostname;
        var resp = await handleCheckDomains([domain]);
        if (resp.results && resp.results[0]) {
          chrome.tabs.sendMessage(tabs[0].id, { type: "SHOW_CHECK_RESULT", result: resp.results[0] });
        }
      } catch (e) {}
    }
  }
});

// Load bloom on startup
loadBloomFilter();

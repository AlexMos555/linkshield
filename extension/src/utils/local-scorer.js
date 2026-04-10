/**
 * Local Scoring Engine — runs 100% in extension, no API needed.
 *
 * Mirrors the server-side scoring logic for offline/standalone use.
 * When API is available, results are enriched with external blocklists.
 * When API is unavailable, this provides full protection locally.
 *
 * Signals:
 *   - Typosquatting (50+ brands, char substitution, hyphen, TLD confusion)
 *   - Risky TLDs (.tk, .xyz, .click, etc.)
 *   - Suspicious keywords (login, verify, account, etc.)
 *   - Domain structure (length, hyphens, subdomains, @ symbol)
 *   - Entropy (DGA detection)
 *   - Hosting platform detection
 *   - Fake TLD in subdomain (paypal.com.evil.xyz)
 */

// ── Brand targets for typosquatting ──
var BRANDS = {
  paypal:"paypal.com",apple:"apple.com",google:"google.com",amazon:"amazon.com",
  microsoft:"microsoft.com",netflix:"netflix.com",facebook:"facebook.com",
  instagram:"instagram.com",whatsapp:"whatsapp.com",linkedin:"linkedin.com",
  twitter:"twitter.com",github:"github.com",dropbox:"dropbox.com",spotify:"spotify.com",
  adobe:"adobe.com",slack:"slack.com",discord:"discord.com",ebay:"ebay.com",
  walmart:"walmart.com",chase:"chase.com",wellsfargo:"wellsfargo.com",
  bankofamerica:"bankofamerica.com",coinbase:"coinbase.com",binance:"binance.com",
  steam:"store.steampowered.com",youtube:"youtube.com",yahoo:"yahoo.com",
  tiktok:"tiktok.com",reddit:"reddit.com",zoom:"zoom.us",stripe:"stripe.com",
  shopify:"shopify.com",fedex:"fedex.com",ups:"ups.com",usps:"usps.com",
  dhl:"dhl.com",citi:"citi.com",hsbc:"hsbc.com",metamask:"metamask.io",
  telegram:"telegram.org",docusign:"docusign.com",icloud:"icloud.com",
  outlook:"outlook.com",gmail:"gmail.com",roblox:"roblox.com",
};

var HIGH_RISK_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".buzz",".icu",".cam",".live",".online",".site",".loan",".racing",".win",".download",".rest",".surf"];
var MEDIUM_RISK_TLDS = [".info",".biz",".cc",".pw",".ws",".club",".space",".fun",".monster",".store",".stream"];

var SUSPICIOUS_WORDS = ["login","signin","sign-in","verify","verification","update","confirm","secure","account","banking","password","reset","suspend","locked","unlock","validate","wallet","payment","invoice","billing","refund","recovery","alert","urgent","expired","reactivate"];

var HOSTING_PLATFORMS = ["pages.dev","workers.dev","r2.dev","netlify.app","vercel.app","herokuapp.com","github.io","gitlab.io","web.app","firebaseapp.com","appspot.com","azurewebsites.net","cloudfront.net","onrender.com","fly.dev","railway.app","blogspot.com","wordpress.com","wixsite.com","wixstudio.com","weebly.com","webflow.io","framer.app","framer.website","carrd.co","notion.site","myshopify.com","lovable.app","replit.app","webcindario.com","contaboserver.net"];

var CHAR_SUBS = {"1":"l","0":"o","3":"e","@":"a","5":"s","!":"i"};

// ── Main scoring function ──
function localScore(domain) {
  var score = 0;
  var reasons = [];
  var parts = domain.split(".");
  var tld = "." + parts[parts.length - 1];
  var base = parts.length >= 2 ? parts.slice(-2).join(".") : domain;
  var name = parts.length >= 2 ? parts[parts.length - 2] : domain;

  // 1. Hosting platform subdomain
  var isHosting = HOSTING_PLATFORMS.indexOf(base) !== -1 && domain !== base;

  // 2. Typosquatting
  var typo = checkTyposquat(name, domain, base, tld);
  if (typo) {
    score += 30;
    reasons.push({signal:"typosquatting", detail:"Impersonates " + typo.brand + " (" + typo.method + ")", weight:30});
  }

  // 3. Brand in subdomain (paypal.evil.com)
  if (parts.length > 2) {
    for (var i = 0; i < parts.length - 2; i++) {
      var clean = parts[i].replace(/-/g, "");
      if (BRANDS[clean] && base !== BRANDS[clean]) {
        score += 30;
        reasons.push({signal:"brand_subdomain", detail:"Uses '" + clean + "' brand as subdomain", weight:30});
        break;
      }
    }
  }

  // 4. Fake TLD in subdomain (paypal.com.evil.xyz)
  if (parts.length > 2) {
    var realTLDs = ["com","org","net","gov","edu","co","io"];
    for (var j = 0; j < parts.length - 2; j++) {
      if (realTLDs.indexOf(parts[j]) !== -1) {
        score += 35;
        reasons.push({signal:"fake_tld", detail:"Contains real TLD '" + parts[j] + "' in subdomain (deception)", weight:35});
        break;
      }
    }
  }

  // 5. Risky TLD
  if (HIGH_RISK_TLDS.indexOf(tld) !== -1) {
    score += 20;
    reasons.push({signal:"risky_tld", detail:"High-risk TLD " + tld, weight:20});
  } else if (MEDIUM_RISK_TLDS.indexOf(tld) !== -1) {
    score += 10;
    reasons.push({signal:"risky_tld", detail:"Suspicious TLD " + tld, weight:10});
  }

  // 6. Suspicious keywords
  for (var w of SUSPICIOUS_WORDS) {
    if (domain.indexOf(w) !== -1) {
      score += 10;
      reasons.push({signal:"suspicious_keyword", detail:"Contains '" + w + "'", weight:10});
      break;
    }
  }

  // 7. @ symbol in URL
  if (domain.indexOf("@") !== -1) {
    score += 40;
    reasons.push({signal:"at_symbol", detail:"@ symbol — browser ignores everything before it", weight:40});
  }

  // 8. Long domain
  if (name.length > 25) {
    score += 10;
    reasons.push({signal:"long_domain", detail:"Unusually long domain name (" + name.length + " chars)", weight:10});
  }

  // 9. Many hyphens
  var hyphens = (domain.match(/-/g) || []).length;
  if (hyphens >= 3) {
    score += 15;
    reasons.push({signal:"many_hyphens", detail:"Excessive hyphens (" + hyphens + ")", weight:15});
  }

  // 10. Deep subdomains
  if (parts.length > 3) {
    score += 15;
    reasons.push({signal:"deep_subdomains", detail:"Deep subdomain nesting (" + parts.length + " levels)", weight:15});
  }

  // 11. Entropy (DGA detection)
  var entropy = shannonEntropy(name);
  if (entropy > 4.0 && name.length > 8) {
    score += 20;
    reasons.push({signal:"high_entropy", detail:"Auto-generated domain (entropy=" + entropy.toFixed(2) + ")", weight:20});
  } else if (entropy > 3.5 && name.length > 10) {
    score += 10;
    reasons.push({signal:"medium_entropy", detail:"Unusual randomness (entropy=" + entropy.toFixed(2) + ")", weight:10});
  }

  // 12. High digit ratio
  var digits = (name.match(/\d/g) || []).length;
  if (digits / name.length > 0.4 && name.length > 5) {
    score += 15;
    reasons.push({signal:"high_digits", detail:Math.round(digits/name.length*100) + "% digits in domain", weight:15});
  }

  // 13. Hosting platform
  if (isHosting) {
    score += 10;
    reasons.push({signal:"hosting_platform", detail:"Subdomain on shared hosting platform", weight:10});
  }

  score = Math.min(score, 100);
  var level = score <= 20 ? "safe" : score <= 50 ? "caution" : "dangerous";

  return {
    domain: domain,
    score: score,
    level: level,
    confidence: reasons.length >= 3 ? "medium" : "low",
    reasons: reasons,
    source: "local",
  };
}

function checkTyposquat(name, domain, base, tld) {
  for (var brand in BRANDS) {
    var legit = BRANDS[brand];
    if (domain === legit || base === legit) continue;

    // TLD confusion
    if (name === brand && "." + legit.split(".").pop() !== tld) {
      return {brand: legit, method: "TLD confusion"};
    }
    if (name === brand) continue;

    // Char substitution
    var normalized = name;
    for (var c in CHAR_SUBS) normalized = normalized.split(c).join(CHAR_SUBS[c]);
    if (normalized === brand) return {brand: legit, method: "character substitution"};

    // Hyphen injection
    if (name.replace(/-/g, "") === brand && name.indexOf("-") !== -1) {
      return {brand: legit, method: "hyphen injection"};
    }

    // Combosquatting
    if (name.startsWith(brand) && name.length > brand.length) {
      var suffix = name.slice(brand.length).replace(/^-/, "");
      if (SUSPICIOUS_WORDS.indexOf(suffix) !== -1) return {brand: legit, method: "combosquatting"};
    }

    // Similarity
    if (name.length === brand.length && name.length >= 4) {
      var diffs = 0;
      for (var i = 0; i < name.length; i++) if (name[i] !== brand[i]) diffs++;
      if (diffs <= 2) return {brand: legit, method: "high similarity"};
    }
  }
  return null;
}

function shannonEntropy(s) {
  if (!s) return 0;
  var freq = {};
  for (var i = 0; i < s.length; i++) freq[s[i]] = (freq[s[i]] || 0) + 1;
  var e = 0;
  for (var c in freq) {
    var p = freq[c] / s.length;
    if (p > 0) e -= p * Math.log2(p);
  }
  return e;
}

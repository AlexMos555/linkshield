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

var HIGH_RISK_TLDS = [".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",".buzz",".icu",".cam",".live",".online",".site",".loan",".racing",".win",".download",".rest",".surf",".zip",".mov",".sbs",".cfd"];
var MEDIUM_RISK_TLDS = [".info",".biz",".cc",".pw",".ws",".club",".space",".fun",".monster",".store",".stream"];

var SUSPICIOUS_WORDS = ["login","signin","sign-in","verify","verification","update","confirm","secure","account","banking","password","reset","suspend","locked","unlock","validate","wallet","payment","invoice","billing","refund","recovery","alert","urgent","expired","reactivate"];

var HOSTING_PLATFORMS = ["pages.dev","workers.dev","r2.dev","netlify.app","vercel.app","herokuapp.com","github.io","gitlab.io","web.app","firebaseapp.com","appspot.com","azurewebsites.net","cloudfront.net","onrender.com","fly.dev","railway.app","blogspot.com","wordpress.com","wixsite.com","wixstudio.com","weebly.com","webflow.io","framer.app","framer.website","carrd.co","notion.site","myshopify.com","lovable.app","replit.app","webcindario.com","contaboserver.net"];

var CHAR_SUBS = {"1":"l","0":"o","3":"e","@":"a","5":"s","!":"i"};

// ═══════════════════════════════════════════════════════════════
// IDN / PUNYCODE NORMALISATION
//
// An internationalised domain reaches us in its ASCII-compatible (punycode)
// form, because that is what DNS carries and what `location.hostname` hands
// back. Punycode is an ENCODING, not a name: `экзамен-пдд.рф` has one hyphen
// and eleven characters, while its wire form `xn----7sbnackuskv0m.xn--p1ai`
// "has" six hyphens and a 19-character label. Every heuristic below that
// judges the SHAPE of a name — hyphen count, label length, entropy, digit
// ratio — was reading the encoder's artefacts, so every .рф site got a yellow
// badge. (Measured 2026-09-20 over the 1,503 punycode domains in
// data/top-1m.csv: 87.9% tripped a shape heuristic, 42.4% were badged
// non-safe; over the 529 .рф domains alone, 99.8% and 57.7%.)
//
// NO BROWSER API DOES THIS FOR US — verified in Chrome on 2026-09-20 rather
// than assumed:
//     new URL("http://xn----7sbnackuskv0m.xn--p1ai/").hostname
//       === "xn----7sbnackuskv0m.xn--p1ai"
// and an <a> element's .hostname behaves identically. The WHATWG URL host
// serializer returns the ASCII form by design, and `punycode` is not a
// browser global. Node's punycode module is not reachable from a content
// script either. Hence the RFC 3492 decoder below.
//
// This mirrors _decode_idn in api/services/scoring.py, deliberately including
// its fallback behaviour, so the offline badge and the backend verdict cannot
// disagree about what a name even IS. scripts/test-local-scorer.mjs pins the
// two together with a table generated from the Python implementation.
// ═══════════════════════════════════════════════════════════════

var PUNY_BASE = 36, PUNY_TMIN = 1, PUNY_TMAX = 26;
var PUNY_SKEW = 38, PUNY_DAMP = 700;
var PUNY_INITIAL_BIAS = 72, PUNY_INITIAL_N = 128;
// RFC 1035 §2.3.4: a DNS label is at most 63 octets. The decoder below is
// permissive (it has to be — see punyDecodeLabel), and punycode is expansive,
// so a longer label "decodes" into a run of control characters. That is not a
// name and no heuristic should be handed one, so anything longer keeps its
// ASCII spelling.
var PUNY_MAX_LABEL = 63;
var PUNY_MAX_CODE_POINT = 0x10FFFF;
var PUNY_ASCII_RE = /^[\x00-\x7F]*$/;

function punyDigit(ch) {
  var cc = ch.charCodeAt(0);
  // RFC 3492 §5: decoders MUST accept both cases, and Python's punycode codec
  // does (b"80ABAP1ARSF" decodes to "сбербанк"), so this does too.
  if (cc >= 97 && cc <= 122) return cc - 97;   // a-z => 0..25
  if (cc >= 65 && cc <= 90) return cc - 65;    // A-Z => 0..25
  if (cc >= 48 && cc <= 57) return cc - 22;    // 0-9 => 26..35
  return -1;
}

function punyAdapt(delta, numPoints, firstTime) {
  delta = firstTime ? Math.floor(delta / PUNY_DAMP) : Math.floor(delta / 2);
  delta += Math.floor(delta / numPoints);
  var k = 0;
  while (delta > ((PUNY_BASE - PUNY_TMIN) * PUNY_TMAX) / 2) {
    delta = Math.floor(delta / (PUNY_BASE - PUNY_TMIN));
    k += PUNY_BASE;
  }
  return Math.floor(k + ((PUNY_BASE - PUNY_TMIN + 1) * delta) / (delta + PUNY_SKEW));
}

/**
 * RFC 3492 decode of ONE label's payload (everything after the "xn--").
 * Returns the decoded string, or null when the input is not valid punycode.
 *
 * Deliberately permissive: it does NOT apply IDNA validation. A homograph
 * label is often not valid IDNA, and refusing to decode it is exactly how
 * `xn--pypal-4ve.com` used to be waved through as an unremarkable ASCII
 * string. We want the characters it encodes so the brand comparison can see
 * them. This matches the backend, which falls back to Python's raw `punycode`
 * codec for the same reason.
 */
function punyDecodeLabel(input) {
  var output = [];
  // Basic (already-ASCII) code points sit before the LAST hyphen; the
  // extended part follows it. Mirrors Python's rfind-based split, which is
  // why "-a" decodes (empty basic part) while "a-" yields "a".
  var split = input.lastIndexOf("-");
  var extended = input;
  if (split !== -1) {
    var basic = input.slice(0, split);
    for (var b = 0; b < basic.length; b++) output.push(basic.charCodeAt(b));
    extended = input.slice(split + 1);
  }

  var n = PUNY_INITIAL_N, i = 0, bias = PUNY_INITIAL_BIAS;
  var index = 0;
  while (index < extended.length) {
    var oldi = i, w = 1;
    for (var k = PUNY_BASE; ; k += PUNY_BASE) {
      if (index >= extended.length) return null;      // truncated
      var digit = punyDigit(extended.charAt(index++));
      if (digit < 0) return null;                     // not a base-36 digit
      i += digit * w;
      // Doubles lose integer precision past 2^53; rather than silently
      // diverge from the backend's bignums, refuse. Such a label always
      // overflows the code-point range anyway, which both sides reject.
      if (!Number.isSafeInteger(i)) return null;
      var t = k <= bias ? PUNY_TMIN : (k >= bias + PUNY_TMAX ? PUNY_TMAX : k - bias);
      if (digit < t) break;
      w *= PUNY_BASE - t;
      if (!Number.isSafeInteger(w)) return null;
    }
    var outLen = output.length + 1;
    bias = punyAdapt(i - oldi, outLen, oldi === 0);
    n += Math.floor(i / outLen);
    i %= outLen;
    if (n > PUNY_MAX_CODE_POINT) return null;         // not a character
    output.splice(i, 0, n);
    i++;
  }

  try {
    return String.fromCodePoint.apply(String, output);
  } catch (e) {
    return null;                                      // lone surrogate, etc.
  }
}

/**
 * Decode every xn-- label in a domain. `xn----7sbnackuskv0m.xn--p1ai`
 * becomes `экзамен-пдд.рф`; `xn--80abap1arsf.ru` becomes `сбербанк.ru`.
 *
 * Never throws, and never invents a name: a label that is not valid punycode
 * keeps its ASCII spelling, so malformed input degrades to exactly the
 * behaviour this scorer had before decoding existed.
 */
function decodeIDN(domain) {
  var s = String(domain == null ? "" : domain);
  if (s.toLowerCase().indexOf("xn--") === -1) return s;

  var labels = s.split(".");
  var out = [];
  for (var i = 0; i < labels.length; i++) {
    var label = labels[i];
    var decoded = null;
    // The ACE prefix is matched case-SENSITIVELY, mirroring Python's idna
    // codec (encodings.idna.ToUnicode tests `label.startswith(b"xn--")`), so
    // "XN--a" is left alone on both sides while "xn--A" decodes on both.
    // Unreachable in practice — the extension lowercases in content/index.js
    // (url.hostname.toLowerCase()) and the API lowercases in
    // domain_validator.py — but pinned so the two scorers cannot disagree
    // even here. Verified by differential fuzz against _decode_idn.
    if (label.slice(0, 4) === "xn--" &&
        label.length <= PUNY_MAX_LABEL &&
        PUNY_ASCII_RE.test(label)) {
      decoded = punyDecodeLabel(label.slice(4));
    }
    out.push(decoded || label);
  }
  return out.join(".");
}

// ── Which language model, if any, may judge a name's shape ──
//
// Mirrors name_script() in api/services/url_features.py. Entropy is bounded
// by log2(alphabet size), so the same "ordinariness" reads hotter on a bigger
// alphabet; applying the Latin thresholds to another script measures "not
// Latin", not "random". A script we have no calibration for must stand down
// rather than guess — guessing with the wrong table is what produced the
// original false positives.
//
// A MIXED-script name is "other" on purpose. It is not a name in one
// language, it is the signature of a homograph attack, and the typosquat
// check (which compares the decoded name against the brand table) is the tool
// for it — a mixed name must never be waved through on the strength of
// whichever alphabet happened to win a majority vote.
var CYRILLIC_VOWELS = "аеёиоуыэюя";
var CYRILLIC_CONSONANTS = "бвгджзйклмнпрстфхцчшщ";
// ъ and ь are signs, not spoken letters, but they are still Cyrillic letters
// for the purpose of deciding WHICH alphabet a name is written in.
var CYRILLIC_SIGNS = "ъь";
var LETTER_RE = /\p{L}/u;

function nameScript(s) {
  var letters = [];
  // for...of iterates by code point, so an astral letter is one item rather
  // than two surrogate halves.
  for (var ch of String(s)) {
    if (LETTER_RE.test(ch)) letters.push(ch.toLowerCase());
  }
  // No letters at all: the ASCII-only digit/length heuristics already assume
  // this case, so keep them switched on.
  if (letters.length === 0) return "ascii";

  var allAscii = true;
  for (var i = 0; i < letters.length; i++) {
    if (letters[i].codePointAt(0) > 127) { allAscii = false; break; }
  }
  if (allAscii) return "ascii";

  for (var j = 0; j < letters.length; j++) {
    var c = letters[j];
    if (CYRILLIC_VOWELS.indexOf(c) === -1 &&
        CYRILLIC_CONSONANTS.indexOf(c) === -1 &&
        CYRILLIC_SIGNS.indexOf(c) === -1) return "other";
  }
  return "cyrillic";
}

// PSL-aware registrable domain (mirrors backend doh_gateway._registrable_domain):
// a 2-letter ccTLD preceded by a generic second-level label (com.cn/co.uk/com.mx...)
// means the eTLD+1 is the last THREE labels, so a brand's own apex is not a subdomain.
var CCTLD_SLD = ["com","co","org","net","gov","edu","ac","gob","or","ne","go","in","id","biz","info"];
function registrableDomain(d) {
  var p = String(d).toLowerCase().replace(/^\.+|\.+$/g, "").split(".");
  if (p.length <= 2) return p.join(".");
  var tld = p[p.length - 1], sld = p[p.length - 2];
  if (tld.length === 2 && CCTLD_SLD.indexOf(sld) !== -1) return p.slice(-3).join(".");
  return p.slice(-2).join(".");
}

// ── Main scoring function ──
function localScore(domain) {
  var score = 0;
  var reasons = [];

  // ── IDN normalisation, done ONCE, up front ──
  //
  // Two different questions get asked about the name below, and they need
  // different forms. Each heuristic states which one it takes and why.
  //
  //   asciiDomain   — the wire form. Everything that LOOKS THE NAME UP speaks
  //                   punycode: the TLD tables, the hosting-platform list, the
  //                   brand table and the PSL helper, all of which are spelled
  //                   in ASCII. It is also the key the popup, the cache and
  //                   the background merge in content/index.js are keyed on.
  //   unicodeDomain — the name a human reads. Everything that judges the SHAPE
  //                   of the name (hyphens, length, entropy, digits) must use
  //                   this, or it scores the encoder's artefacts.
  var asciiDomain = domain;
  var unicodeDomain = decodeIDN(domain);

  var parts = asciiDomain.split(".");
  var tld = "." + parts[parts.length - 1];
  var base = parts.length >= 2 ? parts.slice(-2).join(".") : asciiDomain;

  // Decoding is per-label, so uParts lines up with parts one for one.
  var uParts = unicodeDomain.split(".");
  var uTld = "." + uParts[uParts.length - 1];
  var uBase = uParts.length >= 2 ? uParts.slice(-2).join(".") : unicodeDomain;
  var name = uParts.length >= 2 ? uParts[uParts.length - 2] : unicodeDomain;

  // 1. Hosting platform subdomain — ASCII: HOSTING_PLATFORMS is an ASCII table.
  var isHosting = HOSTING_PLATFORMS.indexOf(base) !== -1 && asciiDomain !== base;

  // 2. Typosquatting — UNICODE: brand comparison against punycode gibberish is
  //    meaningless ("xn--pypal-4ve" resembles no brand), while on the decoded
  //    name a Cyrillic look-alike sits one edit from its target. Decoding is
  //    what lets this catch the homograph instead of missing it.
  var typo = checkTyposquat(name, unicodeDomain, uBase, uTld);
  if (typo) {
    score += 30;
    reasons.push({signal:"typosquatting", detail:"Impersonates " + typo.brand + " (" + typo.method + ")", weight:30});
  }

  // 3. Brand in subdomain (paypal.evil.com) — PSL-aware so a brand's own apex on a
  //    compound ccTLD (apple.com.cn, hsbc.co.uk) is NOT mistaken for a spoof subdomain.
  //    ASCII: this walks the registrable-domain boundary with the PSL helper,
  //    whose compound-suffix table is ASCII. Decoding would change nothing
  //    anyway — BRANDS is Latin, so a decoded Cyrillic label can never match it.
  var reg = registrableDomain(asciiDomain);
  if (asciiDomain !== reg) {
    var subLabels = asciiDomain.slice(0, asciiDomain.length - reg.length - 1).split(".");
    for (var i = 0; i < subLabels.length; i++) {
      var clean = subLabels[i].replace(/-/g, "");
      if (BRANDS[clean] && reg !== BRANDS[clean]) {
        score += 30;
        reasons.push({signal:"brand_subdomain", detail:"Uses '" + clean + "' brand as subdomain", weight:30});
        break;
      }
    }
  }

  // 4. Fake TLD in subdomain (paypal.com.evil.xyz) — ASCII: looks for literal
  //    'com'/'org'/… labels; decoding never creates or removes one.
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

  // 5. Risky TLD — ASCII: the lists are spelled in ASCII, so '.xn--p1ai' must
  //    stay encoded here rather than decode to '.рф'. (Neither form is on the
  //    lists, which is correct: .рф is a national registry, not a risky TLD.)
  if (HIGH_RISK_TLDS.indexOf(tld) !== -1) {
    score += 20;
    reasons.push({signal:"risky_tld", detail:"High-risk TLD " + tld, weight:20});
  } else if (MEDIUM_RISK_TLDS.indexOf(tld) !== -1) {
    score += 10;
    reasons.push({signal:"risky_tld", detail:"Suspicious TLD " + tld, weight:10});
  }

  // 6. Suspicious keywords — UNICODE: the list is words a human would read in
  //    the name. The punycode tail is base-36 filler and must not be searched
  //    for them.
  for (var w of SUSPICIOUS_WORDS) {
    if (unicodeDomain.indexOf(w) !== -1) {
      score += 10;
      reasons.push({signal:"suspicious_keyword", detail:"Contains '" + w + "'", weight:10});
      break;
    }
  }

  // 7. @ symbol in URL — ASCII: this is a property of the wire form the
  //    browser parses, not of the name a human reads.
  if (asciiDomain.indexOf("@") !== -1) {
    score += 40;
    reasons.push({signal:"at_symbol", detail:"@ symbol — browser ignores everything before it", weight:40});
  }

  // 8. Long domain — UNICODE (via `name`): punycode inflates length, e.g.
  //    перемышльский-район is 19 characters and its encoding is 28.
  if (name.length > 25) {
    score += 10;
    reasons.push({signal:"long_domain", detail:"Unusually long domain name (" + name.length + " chars)", weight:10});
  }

  // 9. Many hyphens — UNICODE. This is the single biggest source of the RU
  //    false positives: the '----' in xn----7sb… is the ACE delimiter plus the
  //    name's own hyphen, not four hyphens that anybody typed.
  var hyphens = (unicodeDomain.match(/-/g) || []).length;
  if (hyphens >= 3) {
    score += 15;
    reasons.push({signal:"many_hyphens", detail:"Excessive hyphens (" + hyphens + ")", weight:15});
  }

  // 10. Deep subdomains — either form works; decoding never adds or removes a
  //     label separator.
  if (parts.length > 3) {
    score += 15;
    reasons.push({signal:"deep_subdomains", detail:"Deep subdomain nesting (" + parts.length + " levels)", weight:15});
  }

  // 11. Entropy (DGA detection) — UNICODE (via `name`) and SCRIPT-GATED.
  //
  //     Mirrors the SCRIPT GATE in api/services/scoring.py §3.13. Entropy is
  //     bounded by log2(alphabet size), so the same "ordinariness" reads
  //     hotter on Russian's 33 letters than on English's 26. Asking the Latin
  //     thresholds about a Cyrillic name does not measure "random", it
  //     measures "not Latin".
  //
  //     Cyrillic gets its own tier rather than being skipped: gating on ASCII
  //     alone would leave an all-Cyrillic generated name with ZERO lexical
  //     scrutiny, which is the worse failure for an RU-first product. Its
  //     threshold is the backend's calibrated one (> 4.0 with len > 10 —
  //     measured there at 0.00% false positives on legitimate Cyrillic names);
  //     the weaker "medium" tier is dropped on Cyrillic because at 3.5 the
  //     measured false-positive rate is 10.26%.
  //
  //     A script we have no calibration for — Greek, Arabic, accented Latin —
  //     and any MIXED-script name stand down entirely. Guessing with the wrong
  //     table is what caused the false positives in the first place, and a
  //     mixed-script name is a homograph, which #2 above now catches on the
  //     decoded form.
  //
  //     Honest limitation: the backend also runs a Russian bigram model, a
  //     vowel-ratio band and a consonant-run check (scoring.py §3.30-§3.32)
  //     that this fork deliberately does not carry — a content script should
  //     not ship a language model to every page load. So a low-entropy
  //     Russian keyboard mash (жкшнвыапролдэъ.рф, entropy 3.81) is a known
  //     local miss that the backend catches; content/index.js upgrades to the
  //     backend verdict whenever one arrives.
  var script = nameScript(name);
  var entropy = shannonEntropy(name);
  if (script === "ascii" && entropy > 4.0 && name.length > 8) {
    score += 20;
    reasons.push({signal:"high_entropy", detail:"Auto-generated domain (entropy=" + entropy.toFixed(2) + ")", weight:20});
  } else if (script === "ascii" && entropy > 3.5 && name.length > 10) {
    score += 10;
    reasons.push({signal:"medium_entropy", detail:"Unusual randomness (entropy=" + entropy.toFixed(2) + ")", weight:10});
  } else if (script === "cyrillic" && entropy > 4.0 && name.length > 10) {
    score += 20;
    reasons.push({signal:"high_entropy", detail:"Auto-generated domain (entropy=" + entropy.toFixed(2) + ")", weight:20});
  }

  // 12. High digit ratio — UNICODE (via `name`): punycode encodes non-ASCII
  //     letters into a base-36 tail full of digits, inventing a digit ratio
  //     the real name does not have.
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

    // Char substitution (also try with common suffixes stripped)
    var nameClean = name.replace(/[-_](verify|login|secure|update|account|confirm|alert|support|help|app|web|mail)$/, "");
    var normalized = nameClean;
    for (var c in CHAR_SUBS) normalized = normalized.split(c).join(CHAR_SUBS[c]);
    if (normalized === brand) return {brand: legit, method: "character substitution"};
    // Try full name too
    var normFull = name;
    for (var c in CHAR_SUBS) normFull = normFull.split(c).join(CHAR_SUBS[c]);
    if (normFull === brand) return {brand: legit, method: "character substitution"};

    // Multi-char ASCII glyph homoglyph (rn->m, vv->w, cl->d) — mirrors backend.
    if (brand.length >= 5) {
      var skel = nameClean.split("rn").join("m").split("vv").join("w").split("cl").join("d");
      if (skel !== nameClean && skel === brand) return {brand: legit, method: "glyph homoglyph"};
    }

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

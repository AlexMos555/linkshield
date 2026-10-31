// The server's name rules, ported for the offline scorer.
//
// What a host's NAME alone says: does it imitate a brand (typosquat), carry a
// brand as a subdomain of someone else's site, dress a TLD up as a subdomain
// (paypal.com.evil.xyz), or nest deeper than a site needs? The server answers
// these in api/services/scoring.py; this is a line-by-line port of
//   registrable_domain (public_suffix.py)          → registrableDomain
//   legacy_registrable_domain                      → legacyRegistrable
//   _check_typosquatting_v2 and _imitation        → typosquat
//   _check_brand_in_subdomain                      → brandInSubdomain
//   _check_brand_under_open_zone                   → brandUnderOpenZone
//   _has_fake_tld_in_subdomain                     → hasFakeTldInSubdomain
//   _apparent_subdomain_levels                     → apparentSubdomainLevels
// with the data (brands, official domains, exemptions, Russian public
// suffixes, the Public Suffix List's ICANN rules, constants) generated from
// the server into scorer-data.js.
//
// It used to be a hand-written fork with 50 brands, no Russian brand and no
// Russian zone: sberbamk.ru and t1nkoff.ru scored 0, and kvs.gov.spb.ru (the
// St Petersburg government) was "caution" for a fake 'gov' TLD and three
// subdomain levels it does not have. The comments on the server functions
// say why each rule is the way it is (PRs #61 and #62); they are not
// repeated here. scripts/test-local-scorer.mjs holds this file to the
// server's answers on ~6,000 hosts (tests/data/extension_name_rules_parity.tsv),
// so a server rule change that is not ported here fails CI.
//
// Not ported: the homograph check against the Tranco top-100k (the list is
// megabytes); a confusable-letter brand name is still caught here, as a
// character substitution.
//
// A classic script, like link-target.js: a content script gets the global,
// the background module imports it for its side effect, Node tests load it
// in a vm context. Pure functions — no DOM, no chrome.*. Besides the scorer,
// content/credential-guardian.js reads registrableDomain and isRestrictedZone
// from it: where one site ends.
(function (root, factory) {
  root.cleanwayNameRules = factory(root.cleanwayScorerData);
})(typeof self !== "undefined" ? self : globalThis, function (D) {
  "use strict";

  // A missing data file is a packaging bug, but throwing here would take the
  // background module (and every listener in it) down with it. Degrade to
  // "no name rule fires", which is what the scorer did before it had data.
  if (!D || !Array.isArray(D.targets)) {
    try { console.warn("[Cleanway] scorer-data.js not loaded; name rules are off"); } catch (e) { /* no console */ }
    D = null;
  }

  function set(list) { return new Set(list || []); }
  var RULE_FIELDS = D ? D.ruleFields : [];
  function ruleFrom(flags) {
    var rule = {};
    for (var i = 0; i < RULE_FIELDS.length; i++) rule[RULE_FIELDS[i]] = flags.charAt(i) === "1";
    return rule;
  }

  var TARGETS = D ? D.targets : [];                  // [name, legit domain], server order
  var GLOBAL_TARGETS = new Map(TARGETS.slice(0, D ? D.globalCount : 0));
  var RULES_AWAY = new Map(), RULES_HOME = new Map();
  if (D) {
    for (var name in D.rules) {
      RULES_AWAY.set(name, ruleFrom(D.rules[name][0]));
      RULES_HOME.set(name, ruleFrom(D.rules[name][1]));
    }
  }
  // _DEFAULT_NAME_RULE: never used for a listed name, kept for parity.
  var DEFAULT_RULE = { fuzzy: true, slips_only: false, generic_combos: true, hyphen_combos_only: false, country_combos: false, lure_words: false };
  // _ZONE_NAME_RULE: a brand under an open zone (mts-bonus.spb.ru) takes the
  // Russian lure words too.
  var ZONE_RULE = { fuzzy: true, slips_only: false, generic_combos: true, hyphen_combos_only: false, country_combos: false, lure_words: true };

  var OFFICIAL = set(D && D.officialDomains);
  var LEGIT = set(D && D.officialDomains.concat(D.unrelatedDomains));
  var NOT_TYPOS = new Map();
  if (D) for (var brand in D.notTypos) NOT_TYPOS.set(brand, set(D.notTypos[brand]));
  var SHARED = set(D && D.sharedNames);
  var RU_PSL = set(D && D.ruPublicSuffixes);
  var RU_WILDCARD = set(D && D.ruWildcardSuffixes);
  var RU_RESTRICTED = set(D && D.ruRestrictedZones);
  var RESTRICTED_LABELS = set(D && D.restrictedZoneLabels);
  var REGIONAL_GOV = D ? D.regionalGovernmentDomains : [];
  var CCTLD_SLD = set(D && D.cctldSecondLevels);
  var FAKE_TLD_LABELS = set(D && D.fakeTldLabels);
  var REGISTERED_FAKE_TLD_LABELS = set(D && D.registeredFakeTldLabels);
  var ZONE_BRANDS = D ? D.ruZoneBrands : [];         // longest first
  var ZONE_BRAND_SET = set(ZONE_BRANDS);
  var ZONE_BRAND_PART_MIN = D ? D.ruZoneBrandPartMin : 4;
  var LURE_TLDS = set(D && D.lureTlds);
  var RU_TLDS = set(D && D.ruTlds);
  var RU_LOOKALIKE_ZONES = set(D && D.ruLookalikeZones);
  var CHAR_SUBS = new Map(D ? Object.entries(D.charSubs) : []);
  var CONFUSABLES = new Map(D ? Object.entries(D.confusables) : []);
  var GLYPH_SUBS = D ? D.glyphSubs : [];
  var SIMILAR = set(D && D.similarLetters);
  var VOWELS = D ? D.vowels : "";
  var GENERIC_TAILS = D ? D.genericTails : [];
  var COMBO_KEYWORDS = set(D && D.comboKeywords);
  var TENANT_EXTRA_LURES = set(D && D.tenantExtraLures);
  var TENANT_GLUED_LURES = (D && D.tenantGluedLures) || [];
  var COMBO_SUFFIXES = set(D && D.comboGenericSuffixes);
  var COMBO_PREFIXES = set(D && D.comboGenericPrefixes);
  var COMBO_COUNTRY = set(D && D.comboCountrySuffixes);
  // ru_lures: Russian lure words matched on a spelling skeleton.
  // _check_brand_on_hosting_tenant
  var TENANT_SUFFIXES = set(D && D.hostingTenantSuffixes);
  var OPERATOR_HOSTS = set(D && D.operatorHosts);
  var REGISTRY_ONLY_ZONES = set(D && D.registryOnlyZones);
  var TENANT_BRANDS = D && D.hostingTenantBrands ? D.hostingTenantBrands : [];
  var LURE_WORDS = set(D && D.lureWords);
  var LURE_STEMS = D && D.lureStems ? D.lureStems : [];
  var BRAND_LURE_WORDS = new Map();
  // _NOT_LURE_NEXT_TO: 'secure' is no lure next to 'booking' in the
  // several-word and glued combos (booking engines' checkout).
  var NOT_LURE_NEXT_TO = new Map();
  if (D && D.notLureNextTo) {
    Object.keys(D.notLureNextTo).forEach(function (b) { NOT_LURE_NEXT_TO.set(b, new Set(D.notLureNextTo[b])); });
  }
  if (D && D.brandLureWords) for (var lb in D.brandLureWords) BRAND_LURE_WORDS.set(lb, set(D.brandLureWords[lb]));
  var SKEL_CYRILLIC = new Map(D && D.skeletonCyrillic ? Object.entries(D.skeletonCyrillic) : []);
  var SKEL_FOLDS = D && D.skeletonFolds ? D.skeletonFolds : [];
  var SKEL_DIGITS = new Map(D && D.skeletonDigits ? Object.entries(D.skeletonDigits) : []);
  var TYPOSQUAT_MIN = D ? D.typosquatMinLabel : 3;
  var SHAPE_MIN = D ? D.shapeMinLabel : 4;
  var FUZZY_MIN = D ? D.fuzzyMinLabel : 5;
  var TWO_EDIT_MIN = D ? D.twoEditMinLabel : 8;
  var LOOKALIKE_COMBO_MIN = D && D.lookalikeComboMinLabel ? D.lookalikeComboMinLabel : 4;
  // Literals inside the server's _imitation().
  var GLYPH_BRAND_MIN = 5, GLYPH_RATIO = 0.9, SIMILAR_RATIO = 0.82;

  var KEY_POSITIONS = new Map();
  if (D) {
    D.keyboardRows.forEach(function (rows, layout) {
      rows.forEach(function (keys, row) {
        for (var col = 0; col < keys.length; col++) KEY_POSITIONS.set(keys.charAt(col), [layout, row, col]);
      });
    });
  }

  function clean(domain) { return String(domain == null ? "" : domain).toLowerCase().replace(/^\.+|\.+$/g, ""); }
  function lastTwo(labels) { return labels.slice(-2).join("."); }
  function tldOf(domain) { var p = domain.toLowerCase().replace(/^\.+|\.+$/g, "").split("."); return "." + p[p.length - 1]; }
  function isAscii(s) { return /^[\x00-\x7F]*$/.test(s); }

  // ── Registrable domain ──

  // _ru_suffix_length: trailing labels forming the longest Russian PSL
  // suffix (an exact rule, or one label under a wildcard base); 0 if none.
  function ruSuffixLength(asciiLabels) {
    for (var k = asciiLabels.length; k > 1; k--) {
      var tail = asciiLabels.slice(-k);
      if (RU_PSL.has(tail.join(".")) || RU_WILDCARD.has(tail.slice(1).join("."))) return k;
    }
    return 0;
  }

  // public_suffix.heuristic_registrable_domain (the reading before
  // 2026-10-28): a 2-letter ccTLD under a generic second-level label
  // (co.uk, com.cn) takes three labels, else two.
  function heuristicRegistrable(domain) {
    var p = clean(domain).split(".");
    if (p.length <= 2) return p.join(".");
    if (p[p.length - 1].length === 2 && CCTLD_SLD.has(p[p.length - 2])) return p.slice(-3).join(".");
    return lastTwo(p);
  }

  // _ru_registrable_domain on an ASCII host: the suffix plus one label.
  function ruRegistrable(asciiDomain) {
    var parts = clean(asciiDomain).split(".");
    var k = ruSuffixLength(parts);
    return k ? parts.slice(-(k + 1)).join(".") : null;
  }

  // legacy_registrable_domain: the Russian zones, else the heuristic. What
  // the server's model features and the shape rules that share them read
  // (subdomain levels, fake TLDs), so the ports of those stay on it too.
  function legacyRegistrable(asciiDomain) {
    return ruRegistrable(asciiDomain) || heuristicRegistrable(asciiDomain);
  }

  // The Public Suffix List's ICANN rules (public_suffix.py): scorer-data.js
  // carries them as {TLD: trie of the labels below it}, and a TLD's trie is
  // decoded the first time a host under it is asked about. No ICANN rule
  // has two labels under .com, .net or .org, so most pages decode nothing;
  // .jp, the largest (1,776 rules), about a millisecond.
  var PSL_TRIES = D && D.icannSuffixes && typeof D.icannSuffixes === "object" ? D.icannSuffixes : null;
  var PSL_BY_TLD = new Map();
  var NO_RULES = { exact: new Set(), wildcards: new Set(), exceptions: new Set(), depth: 1, icann: 0 };

  // The server's ccTLD default (public_suffix.SuffixRules.cc_second_levels):
  // each generic second level of a 2-letter TLD (cctldSecondLevels: co, com,
  // net, gov, web …) is a suffix whether the PSL lists it or not — co.ua,
  // com.de, co.vu, ne.pw — but for the zones named as one owner's
  // (cctldNames: web.de, id.me, com.be …). Exact 2-label rules joined to
  // their TLD's ICANN rules, as the server reads them in one table. An open
  // zone read as one name makes its strangers one site; one owner's read as
  // a registry only costs what it did before 2026-10-28.
  var CCTLD_NAMES = set(D && D.cctldNames);

  // One TLD's rules: Sets of its exact rules, wildcards' bases and
  // exceptions, and its longest rule in labels (a wildcard's '*' counts).
  function pslRulesOf(tld) {
    var R = PSL_BY_TLD.get(tld);
    if (R) return R;
    // Own keys only: a host under '.constructor' must not read Object's.
    var text = PSL_TRIES && Object.prototype.hasOwnProperty.call(PSL_TRIES, tld) ? PSL_TRIES[tld] : "";
    var ccDefault = tld.length === 2 && isAscii(tld) && CCTLD_SLD.size > 0;
    R = text || ccDefault ? { exact: new Set(), wildcards: new Set(), exceptions: new Set(), depth: 1, icann: 0 } : NO_RULES;
    if (ccDefault) {
      CCTLD_SLD.forEach(function (label) {
        var zone = label + "." + tld;
        if (!CCTLD_NAMES.has(zone)) R.exact.add(zone);
      });
      R.depth = 2;
    }
    var pos = 0;
    // `suffix` has `level` labels; a rule found under it has level + 1.
    function list(suffix, level) {
      for (;;) {
        var terminal = text.charCodeAt(pos) === 43; // '+'
        if (terminal) pos++;
        var start = pos;
        for (var c = text.charCodeAt(pos); pos < text.length && c !== 44 && c !== 40 && c !== 41; c = text.charCodeAt(++pos)) { /* label */ }
        var label = text.slice(start, pos);
        var name = label + "." + suffix;
        var kids = text.charCodeAt(pos) === 40; // '('
        var rule = true;
        if (label === "*") R.wildcards.add(suffix);
        else if (label.charCodeAt(0) === 33) R.exceptions.add(label.slice(1) + "." + suffix); // '!'
        else if (terminal || !kids) { R.exact.add(name); R.icann++; }
        else rule = false;
        if (rule && level + 1 > R.depth) R.depth = level + 1;
        if (kids) { pos++; list(name, level + 1); pos++; } // past ')'
        if (text.charCodeAt(pos) === 44) { pos++; continue; } // ','
        return;
      }
    }
    if (text) list(tld, 1);
    PSL_BY_TLD.set(tld, R);
    return R;
  }

  // SuffixRules.suffix_length: the prevailing rule's labels — an
  // exception's minus one, else the longest match — or 1 (the default rule).
  function pslSuffixLength(labels) {
    var n = labels.length;
    var R = pslRulesOf(labels[n - 1]);
    if (R.depth < 2 || n < 2) return 1;
    var top = Math.min(R.depth, n), k;
    if (R.exceptions.size) {
      for (k = top; k > 1; k--) if (R.exceptions.has(labels.slice(-k).join("."))) return k - 1;
    }
    for (k = top; k > 1; k--) {
      if (R.exact.has(labels.slice(-k).join(".")) || R.wildcards.has(labels.slice(1 - k).join("."))) return k;
    }
    return 1;
  }

  // An IP literal is its own site: IPv6 (two or more colons, hex digits and
  // dots only, [::1]) or a numeric TLD; one colon is a port. public_suffix.
  // is_ip_literal: any colon counted until 2026-10-31.
  function isIpLiteral(dom) {
    var colons = dom.split(":").length - 1;
    if (colons > 1) return /^\[?[0-9a-f:.]+\]?$/.test(dom);
    if (colons === 1) dom = dom.slice(0, dom.indexOf(":"));
    return /^[0-9]+$/.test(dom.slice(dom.lastIndexOf(".") + 1));
  }

  // registrable_domain: the Russian zones, else the PSL's ICANN rules with
  // the ccTLD default (the server merges all three into one table;
  // tests/test_public_suffix.py holds that to "the Russian rule first"). A
  // suffix by itself, one label and an IP literal answer themselves.
  // Without the rules (an old data file) the legacy reading, as the server
  // falls back when its list does not load; it splits the named zones too.
  function registrableDomain(asciiDomain) {
    var dom = clean(asciiDomain);
    if (!dom || isIpLiteral(dom)) return dom;
    var ru = ruRegistrable(dom);
    if (ru) return ru;
    if (!PSL_TRIES) return heuristicRegistrable(dom);
    var parts = dom.split(".");
    if (parts.length === 1) return dom;
    var k = pslSuffixLength(parts);
    return parts.length <= k ? dom : parts.slice(-(k + 1)).join(".");
  }

  // _subdomain_labels: left of the LEGACY registrable domain.
  function subdomainLabels(asciiDomain) {
    var dom = clean(asciiDomain);
    var reg = legacyRegistrable(dom);
    if (dom === reg || dom.slice(-(reg.length + 1)) !== "." + reg) return [];
    return dom.slice(0, dom.length - reg.length - 1).split(".");
  }

  // ── Fake TLDs and nesting ──

  function isRestrictedZone(suffix) {
    return RU_RESTRICTED.has(suffix) || RESTRICTED_LABELS.has(suffix.split(".")[0]);
  }

  function registeredTldLookalike(asciiDomain) {
    var reg = legacyRegistrable(asciiDomain);
    var dot = reg.indexOf(".");
    var label = dot === -1 ? reg : reg.slice(0, dot);
    var suffix = dot === -1 ? "" : reg.slice(dot + 1);
    if (suffix.indexOf(".") === -1 || !REGISTERED_FAKE_TLD_LABELS.has(label)) return null;
    if (REGIONAL_GOV.indexOf(reg) !== -1 || isRestrictedZone(suffix)) return null;
    return label;
  }

  function apparentSubdomainLevels(asciiDomain) {
    var levels = subdomainLabels(asciiDomain).length;
    return levels && registeredTldLookalike(asciiDomain) ? levels + 1 : levels;
  }

  function hasFakeTldInSubdomain(asciiDomain) {
    var sub = subdomainLabels(asciiDomain);
    for (var i = 0; i < sub.length; i++) if (FAKE_TLD_LABELS.has(sub[i])) return true;
    return sub.length > 0 && registeredTldLookalike(asciiDomain) !== null;
  }

  // ── Brand as a subdomain ──

  function brandInSubdomain(asciiDomain) {
    var dom = clean(asciiDomain);
    var reg = heuristicRegistrable(dom);
    if (!reg || dom === reg) return null;
    var sub = dom.slice(0, dom.length - reg.length - 1).split(".");
    for (var i = 0; i < sub.length; i++) {
      var part = sub[i].replace(/-/g, "");
      if (GLOBAL_TARGETS.has(part) && reg !== GLOBAL_TARGETS.get(part)) return part;
    }
    return null;
  }

  function isRegionalGovernmentDomain(domain) {
    var name = clean(domain);
    for (var i = 0; i < REGIONAL_GOV.length; i++) {
      var g = REGIONAL_GOV[i];
      if (name === g || name.slice(-(g.length + 1)) === "." + g) return true;
    }
    return false;
  }

  function brandUnderOpenZone(asciiDomain) {
    var parts = clean(asciiDomain).split(".");
    var k = ruSuffixLength(parts);
    if (!k || k === parts.length || RU_RESTRICTED.has(parts.slice(-k).join("."))) return null;
    if (isRegionalGovernmentDomain(asciiDomain)) return null;
    if (LEGIT.has(parts.slice(-(k + 1)).join("."))) return null;
    var labels = parts.slice(0, parts.length - k);
    for (var i = 0; i < labels.length; i++) {
      var label = labels[i];
      var whole = label.replace(/-/g, "");
      if (ZONE_BRAND_SET.has(whole)) return whole;
      var pieces = label.split("-");
      for (var j = 0; j < ZONE_BRANDS.length; j++) {
        var b = ZONE_BRANDS[j];
        if (b.length >= ZONE_BRAND_PART_MIN) {
          if (pieces.indexOf(b) !== -1 || checkCombosquat(label, b, ZONE_RULE)) return b;
        } else if (pieces.indexOf(b) !== -1 && checkCombosquat(label, b, ZONE_RULE)) {
          return b;
        }
      }
    }
    return null;
  }

  // hosting_platforms.tenant_suffix_of(domain, _SCORER_SHARED_SUFFIXES)
  function tenantSuffixOf(d) {
    var parts = d.split(".");
    for (var k = parts.length - 1; k > 1; k--) {
      var suffix = parts.slice(-k).join(".");
      if (TENANT_SUFFIXES.has(suffix)) {
        return d === "www." + suffix || OPERATOR_HOSTS.has(d) ? null : suffix;
      }
    }
    return null;
  }

  // _check_brand_on_hosting_tenant: a brand with a lure word (or a Russian
  // brand as the whole name) as a customer's site on a hosting platform;
  // the brand may be in look-alike characters (paypa1-login.ngrok-free.app).
  function brandOnHostingTenant(asciiDomain) {
    var d = clean(asciiDomain);
    var suffix = tenantSuffixOf(d);
    if (!suffix || RU_PSL.has(suffix) || RU_RESTRICTED.has(suffix)) return null;
    if (RU_LOOKALIKE_ZONES.has(suffix) || REGISTRY_ONLY_ZONES.has(suffix)) return null;
    var base = lastTwo(d.split("."));
    if (!(suffix === base || endsWith(suffix, "." + base))) return null;
    if (LEGIT.has(d)) return null;
    var labels = d.slice(0, d.length - suffix.length - 1).split(".");
    for (var i = 0; i < labels.length; i++) {
      var label = labels[i];
      var whole = label.replace(/-/g, "");
      if (whole.length >= ZONE_BRAND_PART_MIN && ZONE_BRAND_SET.has(whole)) return whole;
      var words = label.split("-");
      var pairs = [];
      for (var p = 0; p + 1 < words.length; p++) pairs.push(words[p] + words[p + 1]);
      var candidates = words.concat(pairs);
      for (var b = 0; b < TENANT_BRANDS.length; b++) {
        var brand = TENANT_BRANDS[b];
        var named = [];
        for (var n = 0; n < words.length; n++) {
          if (words[n] === brand || spellsBrand(words[n], brand)) named.push(words[n]);
        }
        if (named.length) {
          for (var c = 0; c < candidates.length; c++) {
            if (named.indexOf(candidates[c]) === -1 && isTenantLure(candidates[c], brand)) return brand;
          }
        } else if (brand.length >= ZONE_BRAND_PART_MIN) {
          for (var w = 0; w < words.length; w++) {
            var word = withBrandSpelledOut(words[w], brand) || words[w];
            var glued = startsWith(word, brand) ? word.slice(brand.length)
              : endsWith(word, brand) ? word.slice(0, word.length - brand.length) : "";
            if (glued && glued !== word && isTenantLure(glued, brand)) return brand;
          }
        }
      }
    }
    return null;
  }

  // ── Typosquatting ──

  // _imitates: ch is the letter, or a digit / Unicode look-alike of it.
  function imitates(ch, letter) {
    if (ch === letter) return true;
    var subs = CHAR_SUBS.get(ch);
    return (subs !== undefined && subs.indexOf(letter) !== -1) || CONFUSABLES.get(ch) === letter;
  }

  function keyboardNeighbours(a, b) {
    var pa = KEY_POSITIONS.get(a), pb = KEY_POSITIONS.get(b);
    if (!pa || !pb || pa[0] !== pb[0]) return false;
    if (pa[1] === pb[1]) return Math.abs(pa[2] - pb[2]) === 1;
    if (Math.abs(pa[1] - pb[1]) !== 1) return false;
    var upper = pa[1] < pb[1] ? pa[2] : pb[2];
    var lower = pa[1] < pb[1] ? pb[2] : pa[2];
    return lower === upper - 1 || lower === upper;
  }

  function isSlip(typed, letter) {
    return imitates(typed, letter) ||
      SIMILAR.has([typed, letter].sort().join("")) ||
      (VOWELS.indexOf(typed) !== -1 && VOWELS.indexOf(letter) !== -1) ||
      keyboardNeighbours(typed, letter);
  }

  function diffPairs(a, b, same) {
    var out = [];
    for (var i = 0; i < a.length; i++) if (!same(a.charAt(i), b.charAt(i))) out.push([a.charAt(i), b.charAt(i)]);
    return out;
  }
  function equal(x, y) { return x === y; }

  function oneOddSubstitution(name, brand) {
    if (name.length !== brand.length) return false;
    var diffs = diffPairs(name, brand, equal);
    return diffs.length === 1 && !isSlip(diffs[0][0], diffs[0][1]);
  }

  function checkCharSubstitution(s1, s2, fuzzy, slipsOnly) {
    if (s1.length !== s2.length) return false;
    var diffs = diffPairs(s1, s2, imitates);
    if (s1.length < FUZZY_MIN || !fuzzy) return diffs.length === 0;
    if (s1.length >= TWO_EDIT_MIN) return diffs.length <= 2;
    return diffs.length === 0 || (diffs.length === 1 && (!slipsOnly || isSlip(diffs[0][0], diffs[0][1])));
  }

  function checkDoubledLetter(s1, s2) {
    if (s1.length !== s2.length + 1) return false;
    for (var i = 0; i < s1.length - 1; i++) {
      if (s1.charAt(i) === s1.charAt(i + 1) && s1.slice(0, i) + s1.slice(i + 1) === s2) return true;
    }
    return false;
  }

  function checkTransposition(s1, s2) {
    if (s1.length !== s2.length) return false;
    for (var i = 0; i < s2.length - 1; i++) {
      if (s1 === s2.slice(0, i) + s2.charAt(i + 1) + s2.charAt(i) + s2.slice(i + 2)) return true;
    }
    return false;
  }

  // _edit_distance_at_most: optimal string alignment distance <= limit.
  function editDistanceAtMost(a, b, limit) {
    if (Math.abs(a.length - b.length) > limit) return false;
    var prev2 = [];
    var prev = [];
    for (var j0 = 0; j0 <= b.length; j0++) prev.push(j0);
    for (var i = 1; i <= a.length; i++) {
      var cur = [i];
      var rowMin = i;
      for (var j = 1; j <= b.length; j++) {
        var cost = a.charAt(i - 1) === b.charAt(j - 1) ? 0 : 1;
        var v = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
        if (i > 1 && j > 1 && a.charAt(i - 1) === b.charAt(j - 2) && a.charAt(i - 2) === b.charAt(j - 1)) {
          v = Math.min(v, prev2[j - 2] + 1);
        }
        cur.push(v);
        if (v < rowMin) rowMin = v;
      }
      if (rowMin > limit) return false;
      prev2 = prev;
      prev = cur;
    }
    return prev[prev.length - 1] <= limit;
  }

  // difflib.SequenceMatcher(None, a, b).ratio() for names this short (no
  // junk, and autojunk only starts at 200 characters): twice the characters
  // in the recursively found longest matching blocks, over both lengths.
  function longestMatch(a, b, b2j, alo, ahi, blo, bhi) {
    var besti = alo, bestj = blo, bestsize = 0;
    var j2len = new Map();
    for (var i = alo; i < ahi; i++) {
      var newj2len = new Map();
      var js = b2j.get(a.charAt(i)) || [];
      for (var n = 0; n < js.length; n++) {
        var j = js[n];
        if (j < blo) continue;
        if (j >= bhi) break;
        var k = (j2len.get(j - 1) || 0) + 1;
        newj2len.set(j, k);
        if (k > bestsize) { besti = i - k + 1; bestj = j - k + 1; bestsize = k; }
      }
      j2len = newj2len;
    }
    while (besti > alo && bestj > blo && a.charAt(besti - 1) === b.charAt(bestj - 1)) {
      besti--; bestj--; bestsize++;
    }
    while (besti + bestsize < ahi && bestj + bestsize < bhi && a.charAt(besti + bestsize) === b.charAt(bestj + bestsize)) {
      bestsize++;
    }
    return [besti, bestj, bestsize];
  }

  // Per-string facts the brand loop asks for again and again (the name's
  // letter counts and glyph skeleton, each brand's letter counts). Pure
  // functions of the string; typosquat() clears the name side per host.
  var memo = new Map();
  var brandCounts = new Map();
  function letterCounts(s) {
    var counts = new Map();
    for (var i = 0; i < s.length; i++) counts.set(s.charAt(i), (counts.get(s.charAt(i)) || 0) + 1);
    return counts;
  }
  function memoized(table, key, compute) {
    var hit = table.get(key);
    if (hit === undefined) { hit = compute(key); table.set(key, hit); }
    return hit;
  }

  // An upper bound on similarityRatio, difflib's quick_ratio(): matching
  // blocks pair equal letters, so they can never pair more than the two
  // strings have in common. The same denominator makes the bound exact to
  // compare: when it is under a threshold, so is the ratio.
  function ratioCanReach(a, b, threshold) {
    var ca = memoized(memo, "#" + a, function () { return letterCounts(a); });
    var cb = memoized(brandCounts, b, letterCounts);
    var common = 0;
    ca.forEach(function (n, ch) { common += Math.min(n, cb.get(ch) || 0); });
    return 2 * common / (a.length + b.length) >= threshold;
  }

  function similarityRatio(a, b) {
    var total = a.length + b.length;
    if (!total) return 1;
    var b2j = new Map();
    for (var j = 0; j < b.length; j++) {
      var ch = b.charAt(j);
      if (!b2j.has(ch)) b2j.set(ch, []);
      b2j.get(ch).push(j);
    }
    var matched = 0;
    var queue = [[0, a.length, 0, b.length]];
    while (queue.length) {
      var q = queue.pop();
      var m = longestMatch(a, b, b2j, q[0], q[1], q[2], q[3]);
      if (!m[2]) continue;
      matched += m[2];
      if (q[0] < m[0] && q[2] < m[1]) queue.push([q[0], m[0], q[2], m[1]]);
      if (m[0] + m[2] < q[1] && m[1] + m[2] < q[3]) queue.push([m[0] + m[2], q[1], m[1] + m[2], q[3]]);
    }
    return 2 * matched / total;
  }

  function glyphSkeleton(name) {
    var out = name;
    for (var i = 0; i < GLYPH_SUBS.length; i++) out = out.split(GLYPH_SUBS[i][0]).join(GLYPH_SUBS[i][1]);
    return out;
  }

  function genericTail(name, brand) {
    for (var i = 0; i < GENERIC_TAILS.length; i++) {
      var tail = GENERIC_TAILS[i];
      if (endsWith(name, tail) && endsWith(brand, tail) && name.length > tail.length && brand.length > tail.length) {
        return tail.length;
      }
    }
    return 0;
  }
  function endsWith(s, tail) { return s.length >= tail.length && s.slice(s.length - tail.length) === tail; }
  function startsWith(s, head) { return s.slice(0, head.length) === head; }

  // _combo_parts: (word, hyphenated, word is after the brand) per reading.
  function comboParts(name, brand) {
    var parts = [];
    if (name.length > brand.length && startsWith(name, brand)) {
      var rest = name.slice(brand.length);
      parts.push([rest.replace(/^-+/, ""), startsWith(rest, "-"), true]);
    }
    if (name.length > brand.length && endsWith(name, brand)) {
      var head = name.slice(0, name.length - brand.length);
      parts.push([head.replace(/-+$/, ""), endsWith(head, "-"), false]);
    }
    return parts;
  }

  // ru_lures.skeleton: Cyrillic transliterated, Latin spellings of one sound
  // folded, 0/3 read as o/e, doubled letters collapsed.
  function lureSkeleton(word) {
    var lower = String(word).toLowerCase(), s = "";
    for (var i = 0; i < lower.length; i++) {
      var ch = lower.charAt(i);
      s += SKEL_CYRILLIC.has(ch) ? SKEL_CYRILLIC.get(ch) : ch;
    }
    var digits = "";
    for (var k = 0; k < s.length; k++) {
      var c = s.charAt(k);
      digits += SKEL_DIGITS.has(c) ? SKEL_DIGITS.get(c) : c;
    }
    s = digits;
    for (var f = 0; f < SKEL_FOLDS.length; f++) s = s.split(SKEL_FOLDS[f][0]).join(SKEL_FOLDS[f][1]);
    return s.replace(/(.)\1+/g, "$1");
  }

  // ru_lures.is_lure
  function isRuLure(word) {
    if (!word) return false;
    var s = lureSkeleton(word);
    if (LURE_WORDS.has(s)) return true;
    for (var i = 0; i < LURE_STEMS.length; i++) if (startsWith(s, LURE_STEMS[i])) return true;
    return false;
  }

  // _is_lure_word
  function isLureWord(word, brand) {
    if (COMBO_KEYWORDS.has(word) || isRuLure(word)) return true;
    var own = BRAND_LURE_WORDS.get(brand);
    return !!own && own.has(lureSkeleton(word));
  }

  // _is_tenant_lure: a lure word with a counter on the end (login17), glued
  // to more letters after it (loginuser), or one of the extra tenant lures.
  function isTenantLure(word, brand) {
    var w = word.replace(/[0-9]+$/, "");
    if (!w) return false;
    if (isLureWord(w, brand) || TENANT_EXTRA_LURES.has(w)) return true;
    for (var i = 0; i < TENANT_GLUED_LURES.length; i++) if (startsWith(w, TENANT_GLUED_LURES[i])) return true;
    return false;
  }

  // _spells_brand: the brand in look-alike characters (g00gle, micr0soft).
  function spellsBrand(word, brand) {
    if (word.length !== brand.length || brand.length < LOOKALIKE_COMBO_MIN || word === brand) return false;
    for (var i = 0; i < word.length; i++) if (!imitates(word.charAt(i), brand.charAt(i))) return false;
    return true;
  }

  // _with_brand_spelled_out: g00glemail → googlemail, secure-paypa1 → secure-paypal.
  function withBrandSpelledOut(name, brand) {
    var n = brand.length;
    if (name.length > n) {
      if (spellsBrand(name.slice(0, n), brand)) return brand + name.slice(n);
      if (spellsBrand(name.slice(name.length - n), brand)) return name.slice(0, name.length - n) + brand;
    }
    return null;
  }

  // _is_brand_word: the brand, its look-alike spelling, or (where the rule
  // allows glued generic combos) the brand glued to a generic word.
  function isBrandWord(word, brand, rule) {
    if (word === brand || spellsBrand(word, brand)) return true;
    if (!rule || !rule.generic_combos || rule.hyphen_combos_only) return false;
    var parts = comboParts(word, brand);
    for (var i = 0; i < parts.length; i++) {
      if ((parts[i][2] ? COMBO_SUFFIXES : COMBO_PREFIXES).has(parts[i][0])) return true;
    }
    return false;
  }

  // _check_lure_combo: the brand as one whole word plus a lure word, glued
  // to it or among the hyphenated words around it. Russian and English lure
  // words under a rule with lure_words (or no rule), the English keywords
  // alone otherwise; a hyphenated keyword (sign-in) counts as one word.
  function checkLureCombo(name, brand, rule) {
    var russian = !rule || !!rule.lure_words;
    var notLures = NOT_LURE_NEXT_TO.get(brand);
    function isLure(w) {
      if (notLures && notLures.has(w)) return false;
      return russian ? isLureWord(w, brand) : COMBO_KEYWORDS.has(w);
    }
    var words = name.split("-");
    for (var i = 0; i < words.length; i++) {
      var word = words[i];
      if (isBrandWord(word, brand, rule)) {
        for (var j = 0; j < words.length; j++) if (j !== i && isLure(words[j])) return true;
        for (var k = 0; k + 1 < words.length; k++) {
          if (k !== i && k + 1 !== i && isLure(words[k] + "-" + words[k + 1])) return true;
        }
      }
      if (word.length > brand.length) {
        var spelled = withBrandSpelledOut(word, brand) || word;
        var glued = startsWith(spelled, brand) ? spelled.slice(brand.length)
          : endsWith(spelled, brand) ? spelled.slice(0, spelled.length - brand.length) : "";
        if (glued && isLure(glued)) return true;
      }
    }
    return false;
  }

  function checkCombosquat(name, brand, rule) {
    var parts = comboParts(name, brand);
    for (var i = 0; i < parts.length; i++) {
      var word = parts[i][0], hyphenated = parts[i][1], after = parts[i][2];
      if (COMBO_KEYWORDS.has(word)) return true;
      if (rule.hyphen_combos_only && !hyphenated) continue;
      if (rule.generic_combos && (after ? COMBO_SUFFIXES : COMBO_PREFIXES).has(word)) return true;
      if (rule.country_combos && after && COMBO_COUNTRY.has(word)) return true;
    }
    return checkLureCombo(name, brand, rule);
  }

  function withRule(rule, changes) {
    var out = {};
    for (var key in rule) out[key] = rule[key];
    for (var c in changes) out[c] = changes[c];
    return out;
  }

  // _imitation: how `name` imitates `brand` (a different string), or null.
  function imitation(name, brand, rule) {
    var tail = genericTail(name, brand);
    if (tail) {
      if (name.indexOf("-") !== -1 && name.replace(/-/g, "") === brand) return "hyphen injection";
      if (checkCombosquat(name, brand, rule)) return "combosquatting";
      if (Math.min(name.length, brand.length) >= TWO_EDIT_MIN) rule = withRule(rule, { slips_only: false });
      return imitation(name.slice(0, name.length - tail).replace(/-+$/, ""), brand.slice(0, brand.length - tail), rule);
    }

    if (checkCharSubstitution(name, brand, rule.fuzzy, rule.slips_only)) return "character substitution";
    if (name.length < SHAPE_MIN) return null;

    var skel = memoized(memo, "~" + name, function () { return glyphSkeleton(name); });
    if (skel !== name) {
      if (skel === brand) return "glyph homoglyph";
      if (brand.length >= GLYPH_BRAND_MIN && (
        skel.split(/[-.]/).indexOf(brand) !== -1 ||
        checkCombosquat(skel, brand, rule) ||
        (ratioCanReach(skel, brand, GLYPH_RATIO) && similarityRatio(skel, brand) >= GLYPH_RATIO)
      )) return "glyph homoglyph";
    }

    if (checkTransposition(name, brand)) return "character swap";
    if (name.replace(/-/g, "") === brand && name.indexOf("-") !== -1) return "hyphen injection";
    if (checkCombosquat(name, brand, rule)) return "combosquatting";
    var spelled = withBrandSpelledOut(name, brand);
    if (spelled && checkCombosquat(spelled, brand, rule)) return "combosquatting";

    // The same conjunction as the server's, cheapest test first: the edit
    // budget can only pass when the lengths differ by at most the budget, so
    // the ratio (the slow part) is computed only for names that could pass.
    var twoEdits = Math.min(name.length, brand.length) >= TWO_EDIT_MIN;
    var budget = twoEdits ? 2 : 1;
    if (rule.fuzzy && name.length >= FUZZY_MIN && Math.abs(name.length - brand.length) <= budget &&
        ratioCanReach(name, brand, SIMILAR_RATIO) && similarityRatio(name, brand) >= SIMILAR_RATIO &&
        editDistanceAtMost(name, brand, budget) &&
        !(rule.slips_only && !twoEdits && oneOddSubstitution(name, brand))) {
      return "high similarity";
    }

    if (checkDoubledLetter(name, brand)) return "doubled letter";
    return null;
  }

  // Python strings index by code point, JavaScript's by UTF-16 unit, so an
  // astral-plane letter (𝐚, an emoji) would be one character there and two
  // here. Every comparison below is by equality or by table lookup, and no
  // brand or table holds such a letter, so each distinct one is swapped for
  // its own private-use character: lengths and matches then agree with the
  // server.
  function codePointSafe(s) {
    if (!/[\uD800-\uDFFF]/.test(s)) return s;
    var seen = new Map();
    var out = "";
    for (var ch of s) {
      if (ch.length === 1) { out += ch; continue; }
      if (!seen.has(ch)) seen.set(ch, String.fromCharCode(0xE000 + seen.size));
      out += seen.get(ch);
    }
    return out;
  }

  // _check_typosquatting_v2 on the decoded host. `asciiDomain` is the same
  // host in its wire form, label for label: the Russian suffix table is
  // spelled in ASCII (the .рус zones as xn--), which is how the server's
  // _ascii_label looks them up.
  function typosquat(asciiDomain, unicodeDomain) {
    var domain = clean(unicodeDomain == null ? asciiDomain : unicodeDomain);
    var uParts = domain.split(".");
    var aParts = clean(asciiDomain).split(".");
    var keys = uParts.length === aParts.length
      ? uParts.map(function (label, i) { return isAscii(label) ? label : aParts[i]; })
      : uParts;

    var zoneName = uParts.length >= 3 && RU_LOOKALIKE_ZONES.has(lastTwo(uParts)) ? uParts.slice(-3).join(".") : null;
    var k = ruSuffixLength(keys);
    var base = zoneName || (k ? uParts.slice(-(k + 1)).join(".") : lastTwo(uParts));
    if (LEGIT.has(base)) return null;
    var name = codePointSafe(base.split(".")[0]);
    memo.clear();
    var zoneSite = zoneName && OFFICIAL.has(name + ".ru") ? { brand: name + ".ru", method: "TLD confusion" } : null;
    if (name.length < TYPOSQUAT_MIN) return zoneSite;
    var tld = tldOf(domain);
    var directlyUnderTld = base.split(".").length === 2;
    var rules = RU_TLDS.has(tld) ? RULES_HOME : RULES_AWAY;

    for (var t = 0; t < TARGETS.length; t++) {
      var brand = TARGETS[t][0], legit = TARGETS[t][1];
      if (domain === legit || base === legit) continue;
      var notTypos = NOT_TYPOS.get(brand);
      if (notTypos && notTypos.has(name)) continue;
      if (name === brand) {
        if (directlyUnderTld && tld !== tldOf(legit) && (!SHARED.has(brand) || LURE_TLDS.has(tld))) {
          return { brand: legit, method: "TLD confusion" };
        }
        continue;
      }
      var method = imitation(name, brand, rules.get(brand) || DEFAULT_RULE);
      if (method) return { brand: legit, method: method };
    }
    return zoneSite;
  }

  return {
    available: D !== null,
    registrableDomain: registrableDomain,
    // For the table tests: the reading the shape rules keep, and the
    // decoded ICANN rules' sizes (scorer-data.js icannSuffixCounts; the
    // ccTLD default's zones not counted).
    legacyRegistrable: legacyRegistrable,
    icannRuleCounts: function () {
      var counts = [0, 0, 0];
      Object.keys(PSL_TRIES || {}).forEach(function (tld) {
        var R = pslRulesOf(tld);
        counts[0] += R.icann; counts[1] += R.wildcards.size; counts[2] += R.exceptions.size;
      });
      return counts;
    },
    // _is_restricted_zone: a public suffix whose names its owner hands out
    // (gov.uk, ac.uk, go.jp, gov.ru). The credential guard reads both.
    isRestrictedZone: isRestrictedZone,
    subdomainLabels: subdomainLabels,
    typosquat: typosquat,
    brandInSubdomain: brandInSubdomain,
    brandUnderOpenZone: brandUnderOpenZone,
    brandOnHostingTenant: brandOnHostingTenant,
    hasFakeTldInSubdomain: hasFakeTldInSubdomain,
    apparentSubdomainLevels: apparentSubdomainLevels,
    // Exposed for the table tests.
    similarityRatio: similarityRatio,
    editDistanceAtMost: editDistanceAtMost,
    isSlip: isSlip,
  };
});

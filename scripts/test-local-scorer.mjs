#!/usr/bin/env node
/**
 * Table tests for the extension's offline scorer — packages/extension-core/src/utils/local-scorer.js.
 *
 * Run with: node scripts/test-local-scorer.mjs
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The local scorer is a deliberate fork of the Python rules in
 * api/services/scoring.py: it runs with no network, so the badge is drawn
 * before (and sometimes instead of) any backend verdict. A fork drifts, and
 * this one already has — see the 2026-07-20 QA finding, where the badge showed
 * a weak local verdict with brand-subdomain and glyph bugs the backend had
 * already fixed. So the cases below are not decoration; each group pins a
 * decision that the two scorers have to agree on.
 *
 * The specific bug this table was written for: the scorer had NO punycode
 * handling. An internationalised domain arrives in its ASCII (xn--) wire form,
 * and every heuristic that judges the SHAPE of a name — hyphen count, label
 * length, entropy, digit ratio — was reading the encoder's output instead of
 * the name. `экзамен-пдд.рф` has one hyphen and eleven characters; its wire
 * form `xn----7sbnackuskv0m.xn--p1ai` "has" six hyphens and a 19-character
 * label. Measured against the 1,503 punycode domains in data/top-1m.csv on
 * 2026-09-20, before the fix: 87.9% tripped at least one shape heuristic and
 * 42.4% were badged non-safe. Restricted to the 529 .рф domains — Cleanway is
 * RU-first — it was 99.8% and 57.7%.
 *
 * VERIFIED, NOT ASSUMED
 * ---------------------
 * The obvious shortcut — build a URL and read `.hostname` — does not work.
 * Checked in real Chrome on 2026-09-20 at https://example.com:
 *     new URL("http://xn----7sbnackuskv0m.xn--p1ai/").hostname
 *       === "xn----7sbnackuskv0m.xn--p1ai"
 * and the same for an <a> element's .hostname. The WHATWG URL host serializer
 * returns the ASCII form by design, and `punycode` is not a browser global
 * (typeof punycode === "undefined"). Hence the hand-rolled RFC 3492 decoder.
 *
 * Every expected decoding below was generated from the backend's own
 * `api.services.scoring._decode_idn`, so the JS decoder is pinned to the
 * Python one rather than to my reading of the RFC. The Unicode -> punycode
 * direction was independently confirmed with Chrome's own IDN encoder.
 */
import assert from "node:assert";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, "..");

// packages/extension-core/ is the single source of truth; the three browser
// trees are generated from it by scripts/build-extensions.sh. Running the same
// table against all four is a second drift guard: if someone hand-edits a
// generated copy, or edits the source and forgets to rebuild, this fails.
const TREES = [
  ["extension-core (source)", "packages/extension-core/src/utils/local-scorer.js"],
  ["extension (chrome)", "extension/src/utils/local-scorer.js"],
  ["extension-firefox", "extension-firefox/src/utils/local-scorer.js"],
  ["extension-safari", "extension-safari/src/utils/local-scorer.js"],
];

/**
 * The scorer is a CLASSIC content script, not a module: the manifest lists it
 * under content_scripts.js, and it declares `localScore` and friends as plain
 * globals. A bare vm context is the closest honest model of how the browser
 * actually loads it — no module wrapper, no injected globals, no DOM. That
 * also proves the file does not secretly depend on `window` or `chrome`.
 */
function loadScorer(relPath) {
  const src = readFileSync(join(ROOT, relPath), "utf8");
  const ctx = vm.createContext({});
  vm.runInContext(src, ctx);
  return ctx;
}

let passed = 0;
let failed = 0;
function check(name, fn) {
  try {
    fn();
    passed++;
  } catch (err) {
    failed++;
    console.error(`  FAIL  ${name}\n        ${err && err.message}`);
  }
}

// ── Group 1: the punycode decoder itself ──
// Left column is the wire form, right column is what
// api.services.scoring._decode_idn returns for it (generated 2026-09-20).
const DECODE_CASES = [
  // Real .рф names from the Tranco tail.
  ["xn----7sbnackuskv0m.xn--p1ai", "экзамен-пдд.рф"],
  ["xn--80abap1arsf.xn--p1ai", "сбербанк.рф"],
  ["xn--d1abbgf6aiiy.xn--p1ai", "президент.рф"],
  ["xn--80adxhks.xn--p1ai", "москва.рф"],
  ["xn--c1aapkosapc.xn--p1ai", "госуслуги.рф"],
  ["xn----8sbnapgcdijslcphl1j5bv.xn--p1ai", "перемышльский-район.рф"],
  // Per-label: a decoded label next to an ASCII one, and a bare TLD.
  ["www.xn--80abap1arsf.xn--p1ai", "www.сбербанк.рф"],
  ["xn--80abap1arsf.ru", "сбербанк.ru"],
  ["xn--p1ai", "рф"],
  // Homographs — the reason the decoder must be permissive rather than
  // IDNA-strict: these have to decode to the characters they encode.
  ["xn--pypal-4ve.com", "pаypal.com"],
  ["xn--80ak6aa92e.com", "аррӏе.com"],
  // Untouched: no xn-- label anywhere.
  ["example.com", "example.com"],
  ["", ""],
  // Malformed: keep the ASCII spelling rather than throw or invent a name.
  ["xn--notvalid!!.com", "xn--notvalid!!.com"], // '!' is not a base-36 digit
  ["xn---.com", "xn---.com"], // decodes to empty
  ["xn--0.com", "xn--0.com"], // truncated generalized number
  ["xn--zz.com", "xn--zz.com"], // ditto
  // Valid punycode that spells something odd. Still decoded, because
  // pretending it is ASCII is how a homograph slips past.
  ["xn--a.com", ".com"],
  ["xn--a-.com", "a.com"],
  ["sub.xn--notreal-xyz.com", "sub.࿠notreal.com"],
  // Over the RFC 1035 63-octet label limit: not a name, keep it ASCII.
  [`xn--${"a".repeat(120)}.com`, `xn--${"a".repeat(120)}.com`],
  // Case handling, pinned to the backend's exact quirks. Unreachable in
  // practice — the extension lowercases at both call sites (content/index.js
  // uses url.hostname.toLowerCase()) and the API lowercases in
  // domain_validator.py — but a differential fuzz against _decode_idn found
  // these two, and "the scorers cannot disagree" has to mean even here.
  // The ACE PREFIX is matched case-sensitively (Python's idna codec tests
  // startswith(b"xn--")), so an uppercase prefix is never decoded...
  ["XN--80ABAP1ARSF.XN--P1AI", "XN--80ABAP1ARSF.XN--P1AI"],
  ["XN--a.com", "XN--a.com"],
  // ...while the base-36 DIGITS after a lowercase prefix accept either case,
  // as RFC 3492 §5 requires and Python's punycode codec does.
  ["xn--A.com", ".com"],
  ["xn--80ABAP1ARSF.ru", "сбербанк.ru"],
];

// ── Group 2: .рф names must stop tripping shape heuristics ──
// Expected score is 0 with an EMPTY reason list: not merely "safe", but
// carrying no bogus explanation into the popup either. Before the fix these
// scored 15-45 with many_hyphens / medium_entropy / long_domain attached.
const RF_CLEAN = [
  "xn----7sbnackuskv0m.xn--p1ai", // экзамен-пдд.рф        — was 25 caution
  "xn--80abap1arsf.xn--p1ai", // сбербанк.рф           — was 15 safe + many_hyphens
  "xn--d1abbgf6aiiy.xn--p1ai", // президент.рф          — was 15 safe + many_hyphens
  "xn--80adxhks.xn--p1ai", // москва.рф             — was 15 safe + many_hyphens
  "xn--c1aapkosapc.xn--p1ai", // госуслуги.рф          — was 15 safe + many_hyphens
  "xn----8sbnapgcdijslcphl1j5bv.xn--p1ai", // перемышльский-район.рф — was 45 caution
];

// ── Group 3: Latin domains must score EXACTLY as before ──
// Captured from the pre-fix scorer on 2026-09-20. None contain "xn--", so the
// decoder returns early and nothing about their scoring may move. This is the
// regression net for the whole change.
const LATIN_UNCHANGED = [
  ["google.com", 0, "safe", ""],
  ["example.com", 0, "safe", ""],
  ["paypal.com", 0, "safe", ""],
  ["github.io", 30, "caution", "typosquatting"],
  ["my-cool-site.com", 0, "safe", ""],
  ["a-b-c-d.com", 15, "safe", "many_hyphens"],
  ["secure-login-paypal-verify.tk", 65, "dangerous", "risky_tld|suspicious_keyword|long_domain|many_hyphens|medium_entropy"],
  ["xyzqwkjhdfgkjhsdf.xyz", 20, "safe", "risky_tld"],
  ["paypa1.com", 30, "caution", "typosquatting"],
  ["paypal.evil.com", 30, "caution", "brand_subdomain"],
  ["paypal.com.evil.xyz", 100, "dangerous", "brand_subdomain|fake_tld|risky_tld|deep_subdomains"],
  ["bit.ly", 0, "safe", ""],
  ["wellsfargo-secure.com", 40, "caution", "typosquatting|suspicious_keyword"],
  ["1234567890abc.com", 25, "caution", "medium_entropy|high_digits"],
  ["metamask.github.io", 70, "dangerous", "typosquatting|brand_subdomain|hosting_platform"],
  ["store.steampowered.com", 0, "safe", ""],
  ["apple.com.cn", 0, "safe", ""],
  ["hsbc.co.uk", 0, "safe", ""],
  ["barclays.co.uk", 0, "safe", ""],
  ["rnetamask.io", 30, "caution", "typosquatting"],
  ["login.microsoftonline.com.evil.tk", 80, "dangerous", "fake_tld|risky_tld|suspicious_keyword|deep_subdomains"],
  ["cdn.jsdelivr.net", 0, "safe", ""],
  ["sub.domain.example.co.uk", 15, "safe", "deep_subdomains"],
  ["verylongdomainnamethatiswaytoolong.com", 20, "safe", "long_domain|medium_entropy"],
];

// ── Group 4: malformed xn-- must degrade to the OLD behaviour, never throw ──
// "Falls back safely" means the ASCII spelling is scored exactly as an
// undecodable ASCII string always was — no crash, no silently-empty name.
const MALFORMED_UNCHANGED = [
  ["xn--notvalid!!.com", 0, "safe", ""],
  ["xn---.com", 15, "safe", "many_hyphens"], // still 3 hyphens, because it IS still that string
  ["xn--a.com", 0, "safe", ""],
  [`xn--${"a".repeat(120)}.com`, 10, "safe", "long_domain"],
];

for (const [treeName, relPath] of TREES) {
  console.log(`\n${treeName}  (${relPath})`);
  const ctx = loadScorer(relPath);

  check("exposes localScore and decodeIDN as content-script globals", () => {
    assert.strictEqual(typeof ctx.localScore, "function");
    assert.strictEqual(typeof ctx.decodeIDN, "function", "decodeIDN must be reachable for testing");
  });

  for (const [input, want] of DECODE_CASES) {
    check(`decodeIDN(${JSON.stringify(input)}) -> ${JSON.stringify(want)}`, () => {
      assert.strictEqual(ctx.decodeIDN(input), want);
    });
  }

  for (const d of RF_CLEAN) {
    check(`${d} scores clean (no punycode artefacts)`, () => {
      const r = ctx.localScore(d);
      // Compared as a joined string, not with deepStrictEqual: `r.reasons`
      // is built inside the vm realm, so its Array prototype is not the
      // host's and a structural compare fails on identity alone.
      const sigs = r.reasons.map((x) => x.signal).join("|");
      assert.strictEqual(sigs, "", `expected no reasons, got ${sigs}`);
      assert.strictEqual(r.score, 0);
      assert.strictEqual(r.level, "safe");
      // The result still reports the ASCII domain: it is the key the popup,
      // the cache and the background merge are all keyed on.
      assert.strictEqual(r.domain, d);
    });
  }

  for (const [d, score, level, sigs] of [...LATIN_UNCHANGED, ...MALFORMED_UNCHANGED]) {
    check(`${d} -> ${score}/${level} [${sigs}]`, () => {
      const r = ctx.localScore(d);
      assert.strictEqual(r.score, score, `score ${r.score} != ${score}`);
      assert.strictEqual(r.level, level);
      assert.strictEqual(r.reasons.map((x) => x.signal).join("|"), sigs);
    });
  }

  // ── Group 5: the homograph that used to be waved through ──
  // Decoding does more than remove false positives. Scoring the real name is
  // also what lets the Latin brand table see a Cyrillic look-alike at all.
  check("pаypal.com (Cyrillic а) is caught as a typosquat — was 15/safe", () => {
    const r = ctx.localScore("xn--pypal-4ve.com");
    const sigs = r.reasons.map((x) => x.signal);
    assert.ok(sigs.includes("typosquatting"), `expected typosquatting, got ${sigs.join("|")}`);
    assert.ok(!sigs.includes("many_hyphens"), "the '-4ve' hyphen is the encoder's, not the name's");
    assert.strictEqual(r.level, "caution");
  });

  // ── Group 6: the script gate on the name-shape heuristics ──
  // Mirrors the backend's SCRIPT GATE (api/services/scoring.py §3.13).
  // Entropy is bounded by log2(alphabet size), so the same "ordinariness"
  // reads hotter on a bigger alphabet. A script we have no calibration for
  // must stand down rather than guess with the wrong table.
  check("Greek name is not judged by the Latin entropy table", () => {
    // αβγδεζηθικλμνξοπρ — 17 distinct letters, entropy 4.09, length 17.
    // Under the ASCII thresholds (> 4.0, len > 8) that is a high_entropy hit
    // on a perfectly ordinary Greek word-shape. Unknown script => no verdict.
    const r = ctx.localScore("xn--mxacdefghijklmnopqr.com");
    const sigs = r.reasons.map((x) => x.signal);
    assert.ok(!sigs.includes("high_entropy") && !sigs.includes("medium_entropy"),
      `no entropy verdict without a model for the script, got ${sigs.join("|")}`);
  });

  check("Cyrillic is still scrutinised, not merely skipped", () => {
    // абвгдежзиклмнопрст — 18 distinct Cyrillic letters, entropy 4.17,
    // length 18. Gating these heuristics on isascii() alone would give an
    // all-Cyrillic generated name ZERO lexical scrutiny, which is the
    // opposite failure and the one that matters most for an RU-first
    // product. Cyrillic gets the high tier at the backend's threshold
    // (> 4.0 with len > 10).
    const r = ctx.localScore("xn--80acdefghijulmnopqrs.com");
    const sigs = r.reasons.map((x) => x.signal);
    assert.ok(sigs.includes("high_entropy"), `expected high_entropy, got ${sigs.join("|")}`);
  });

  check("a Russian keyboard mash is a KNOWN local miss, not a silent one", () => {
    // жкшнвыапролдэъ.рф — entropy 3.81, under the > 4.0 Cyrillic tier, so
    // the local fork clears it. The backend catches it with the Russian
    // bigram model and the consonant-run check (scoring.py §3.30/§3.32),
    // which this fork deliberately does not carry — a content script should
    // not ship a language model to every page load, and content/index.js
    // upgrades to the backend verdict when one arrives. Pinned so the gap
    // is a recorded decision instead of something rediscovered in QA.
    const r = ctx.localScore("xn--80adhfuilkik7f6ag8a.xn--p1ai");
    assert.strictEqual(r.level, "safe");
  });

  // ── Group 7: the decoded name must not leak into ASCII lookups ──
  check("risky-TLD / hosting lookups still use the ASCII form", () => {
    // .рф is not a risky TLD and must not be compared against the ASCII
    // list as ".рф"; the list is spelled in ASCII, so ".xn--p1ai" is the
    // only form that could ever match one. Neither does, which is correct.
    const r = ctx.localScore("xn--80abap1arsf.xn--p1ai");
    assert.ok(!r.reasons.some((x) => x.signal === "risky_tld"));
    // An IDN label on a genuinely risky ASCII TLD must still be flagged.
    const risky = ctx.localScore("xn--80abap1arsf.tk");
    assert.ok(risky.reasons.some((x) => x.signal === "risky_tld"),
      "decoding the label must not blind the TLD check");
  });

  check("brand-in-subdomain still works under an IDN registrable domain", () => {
    const r = ctx.localScore("paypal.xn--80abap1arsf.xn--p1ai");
    const sigs = r.reasons.map((x) => x.signal);
    assert.ok(sigs.includes("brand_subdomain"), `got ${sigs.join("|")}`);
  });

  check("never throws, whatever it is handed", () => {
    for (const junk of ["", ".", "..", "xn--", "xn--.", "-", "a", "xn-- .com",
      "xn--" + "9".repeat(59), "....xn--p1ai", "xn--p1ai.xn--p1ai.xn--p1ai"]) {
      const r = ctx.localScore(junk);
      assert.ok(typeof r.score === "number" && Number.isFinite(r.score), `bad score for ${JSON.stringify(junk)}`);
      assert.ok(Array.isArray(r.reasons));
    }
  });
}

console.log(
  failed === 0
    ? `\n${passed} assertions passed across ${TREES.length} extension trees`
    : `\n${failed} FAILED, ${passed} passed`,
);
process.exit(failed === 0 ? 0 : 1);

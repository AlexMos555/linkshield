#!/usr/bin/env node
/**
 * Table test for the landing helpers that decide what the site is allowed to
 * claim (report items #11, #12, #13, #15 of the 2026-09-25 service check).
 *
 * Run: node --experimental-strip-types scripts/test-landing-honesty.mjs
 *
 * Pinned here:
 *   1. No accuracy number from a benchmark sample too small to mean anything —
 *      including the committed latest.json (n=24), which must stay hidden.
 *   2. Russian visitors never get paid plans they cannot buy.
 *   3. The support address is only advertised once the mailbox is switched on.
 *   4. Install screenshots render only when the file really exists.
 *   5. The /check form sends a site's name and nothing else of a pasted link.
 *   6. A scorecard lists each plain-language reason once.
 *   7. No false-positive rate from a legitimate sample our server auto-trusts.
 *   8. Every client component's messages reach the browser — and only those.
 *   9. Legal documents attach links by section id, the same in every locale.
 *  10. Sentry never receives the site name from a /check or /audit page URL.
 */
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  MIN_PHISHING_CLASSIFIED,
  MIN_PHISHING_SAMPLE,
  falsePositiveRateIsPublishable,
  recallIsPublishable,
} from "../landing/lib/benchmark.ts";
import { hostFromSegment, toCheckHost } from "../landing/lib/check-host.ts";
import { CLIENT_NAMESPACES, pickClientMessages } from "../landing/lib/client-messages.ts";
import { displayHost } from "../landing/lib/display-host.ts";
import { installScreenshotSrc } from "../landing/lib/install-screenshots.ts";
import { paidPlansOffered } from "../landing/lib/paid-plans.ts";
import { REASON_CODE_TO_KEY, reasonLabelKey, reasonLines } from "../landing/lib/reason-label.ts";
import { scrubSitePaths } from "../landing/lib/sentry-scrub.ts";
import { isFlagOn } from "../landing/lib/support.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, "..");
const LATEST = path.join(ROOT, "docs", "benchmarks", "latest.json");
const SOURCE_DIR = path.join(ROOT, "packages", "i18n-strings", "src");
const LOCALES = ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"];

function landingSource(locale) {
  return JSON.parse(fs.readFileSync(path.join(SOURCE_DIR, `${locale}.json`), "utf-8")).landing;
}

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (err) {
    failures += 1;
    console.log(`  FAIL ${name}\n       ${err.message}`);
  }
}

function stats(overrides) {
  return { tp: 0, fp: 0, tn: 0, fn: 0, unknown: 0, recall: null, fpr: null, precision: null, f1: null, latency_p50_ms: null, ...overrides };
}

function snapshot({ nPhishing = 200, phishing = {}, safe = {}, legitOutsideAllowlist = true } = {}) {
  return {
    ts: "2026-09-21T11:53:00Z",
    n_phishing: nPhishing,
    n_safe: 200,
    sources: { legit_outside_allowlist: legitOutsideAllowlist },
    phishing: { cleanway: stats(phishing) },
    safe: { cleanway: stats(safe) },
  };
}

console.log("recallIsPublishable");
check("healthy sample → publishable", () => {
  assert.equal(recallIsPublishable(snapshot({ phishing: { tp: 150, fn: 30, unknown: 20, recall: 150 / 180 } })), true);
});
check("null snapshot → hidden", () => assert.equal(recallIsPublishable(null), false));
check(`n_phishing below ${MIN_PHISHING_SAMPLE} → hidden`, () => {
  assert.equal(recallIsPublishable(snapshot({ nPhishing: 60, phishing: { tp: 50, fn: 5, unknown: 5, recall: 0.9 } })), false);
});
check(`fewer than ${MIN_PHISHING_CLASSIFIED} classified → hidden`, () => {
  assert.equal(recallIsPublishable(snapshot({ phishing: { tp: 30, fn: 5, unknown: 10, recall: 0.86 } })), false);
});
check("mostly rate-limited (unknown > 30%) → hidden", () => {
  assert.equal(recallIsPublishable(snapshot({ phishing: { tp: 60, fn: 5, unknown: 135, recall: 0.92 } })), false);
});
check("zero or null recall → hidden", () => {
  assert.equal(recallIsPublishable(snapshot({ phishing: { tp: 0, fn: 90, unknown: 10, recall: 0 } })), false);
  assert.equal(recallIsPublishable(snapshot({ phishing: { tp: 80, fn: 20, recall: null } })), false);
});
check("committed latest.json (n=24) stays hidden", () => {
  const committed = JSON.parse(fs.readFileSync(LATEST, "utf-8"));
  assert.equal(recallIsPublishable(committed), false);
});

console.log("falsePositiveRateIsPublishable");
check("never measured (all unknown) → hidden", () => {
  assert.equal(falsePositiveRateIsPublishable(snapshot({ safe: { unknown: 60, fpr: null } })), false);
});
check("too few answered → hidden", () => {
  assert.equal(falsePositiveRateIsPublishable(snapshot({ safe: { tn: 10, fp: 0, unknown: 40, fpr: 0 } })), false);
});
check("enough answered → publishable, even at 0%", () => {
  assert.equal(falsePositiveRateIsPublishable(snapshot({ safe: { tn: 120, fp: 0, unknown: 5, fpr: 0 } })), true);
});
check("legit sample our server auto-trusts (Tranco top 100k) → hidden, however large", () => {
  const allowlisted = { safe: { tn: 120, fp: 0, unknown: 5, fpr: 0 }, legitOutsideAllowlist: false };
  assert.equal(falsePositiveRateIsPublishable(snapshot(allowlisted)), false);
  const unstated = snapshot({ safe: { tn: 120, fp: 0, unknown: 5, fpr: 0 } });
  delete unstated.sources;
  assert.equal(falsePositiveRateIsPublishable(unstated), false);
});
check("committed latest.json never measured false positives", () => {
  const committed = JSON.parse(fs.readFileSync(LATEST, "utf-8"));
  assert.equal(falsePositiveRateIsPublishable(committed), false);
});

console.log("paidPlansOffered");
check("Russian page → free only", () => assert.equal(paidPlansOffered({ locale: "ru" }), false));
check("Russian page abroad → still free only", () => assert.equal(paidPlansOffered({ locale: "ru", country: "DE" }), false));
check("English page from Russia → free only", () => assert.equal(paidPlansOffered({ locale: "en", country: "ru" }), false));
check("English page, unknown country → paid plans shown", () => assert.equal(paidPlansOffered({ locale: "en", country: null }), true));
check("German page from Germany → paid plans shown", () => assert.equal(paidPlansOffered({ locale: "de", country: "DE" }), true));

console.log("isFlagOn (NEXT_PUBLIC_SUPPORT_EMAIL_LIVE)");
check("unset / empty / 0 → off", () => {
  assert.equal(isFlagOn(undefined), false);
  assert.equal(isFlagOn(""), false);
  assert.equal(isFlagOn("0"), false);
  assert.equal(isFlagOn("false"), false);
});
check("1 / true / yes (any case, padded) → on", () => {
  assert.equal(isFlagOn("1"), true);
  assert.equal(isFlagOn(" TRUE "), true);
  assert.equal(isFlagOn("yes"), true);
});

function withPublicDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cw-shots-"));
  try {
    fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

console.log("installScreenshotSrc");
check("no file → null (no broken image, no placeholder box)", () => {
  withPublicDir((dir) => assert.equal(installScreenshotSrc("ru", "samsung-auto-blocker", dir), null));
});
check("file present → public URL, any supported extension", () => {
  withPublicDir((dir) => {
    fs.mkdirSync(path.join(dir, "install", "ru"), { recursive: true });
    fs.writeFileSync(path.join(dir, "install", "ru", "play-protect-warning.webp"), "x");
    assert.equal(installScreenshotSrc("ru", "play-protect-warning", dir), "/install/ru/play-protect-warning.webp");
    assert.equal(installScreenshotSrc("en", "play-protect-warning", dir), null);
  });
});
check("locale that is not a plain 2-letter code → null (no path tricks)", () => {
  assert.equal(installScreenshotSrc("../ru", "samsung-auto-blocker", os.tmpdir()), null);
});

console.log("reason labels (landing twin of mobile/src/utils/reason-label.ts)");
check("landing map matches the app's map exactly", () => {
  const mobileSource = fs.readFileSync(path.join(HERE, "..", "mobile", "src", "utils", "reason-label.ts"), "utf-8");
  const block = mobileSource.match(/const CODE_TO_KEY[^{]*\{([\s\S]*?)\n\};/);
  assert.ok(block, "CODE_TO_KEY not found in the mobile file");
  const mobileMap = Object.fromEntries(
    [...block[1].matchAll(/^\s*([a-z0-9_]+):\s*"([a-z0-9_]+)",/gm)].map((m) => [m[1], m[2]]),
  );
  assert.deepEqual({ ...REASON_CODE_TO_KEY }, mobileMap);
});
check("every label key exists in the Reasons strings", () => {
  const en = JSON.parse(fs.readFileSync(path.join(HERE, "..", "packages", "i18n-strings", "src", "en.json"), "utf-8"));
  for (const key of new Set(Object.values(REASON_CODE_TO_KEY))) {
    assert.equal(typeof en.mobile.reason[key], "string", `mobile.reason.${key} missing`);
  }
});
check("unknown or missing code → null (caller falls back to the API detail)", () => {
  assert.equal(reasonLabelKey("no_https"), "no_https");
  assert.equal(reasonLabelKey("something_new"), null);
  assert.equal(reasonLabelKey(undefined), null);
  assert.equal(reasonLabelKey("toString"), null);
});

console.log("toCheckHost (the /check form sends a site name, never the rest of a link)");
check("bare name → itself, lowercased", () => {
  assert.equal(toCheckHost("Example.RU"), "example.ru");
  assert.equal(toCheckHost("  sberbank.ru  "), "sberbank.ru");
});
check("scheme-less link → host only (path, query and email gone)", () => {
  assert.equal(toCheckHost("bank-verify.ru/confirm?email=me@x.ru"), "bank-verify.ru");
  assert.equal(toCheckHost("Sberbank-bonus.ru/pay/123#top"), "sberbank-bonus.ru");
});
check("full link, credentials and port → host only", () => {
  assert.equal(toCheckHost("https://bank.ru/login?token=abc"), "bank.ru");
  assert.equal(toCheckHost("http://user:pass@bank.ru:8443/x"), "bank.ru");
  assert.equal(toCheckHost("example.com."), "example.com");
});
check("Cyrillic name → punycode, the form the API checks", () => {
  assert.equal(toCheckHost("президент.рф"), "xn--d1abbgf6aiiy.xn--p1ai");
});
check("not a site name → null (nothing is sent)", () => {
  for (const bad of ["", "   ", "hello", "две фразы", "javascript:alert(1)", "-bad-.com", "bank.ru%2Fconfirm", "[::1]", null, undefined]) {
    assert.equal(toCheckHost(bad), null, `accepted ${JSON.stringify(bad)}`);
  }
});
check("route segment: encoded link → host; broken encoding → null, not a crash", () => {
  assert.equal(hostFromSegment(encodeURIComponent("bank-verify.ru/confirm?email=me@x.ru")), "bank-verify.ru");
  assert.equal(hostFromSegment("example.com"), "example.com");
  assert.equal(hostFromSegment("%E0%A4%A"), null);
});

console.log("displayHost (what the scorecard shows)");
check("Cyrillic name under .рф → shown as people type it", () => {
  assert.equal(displayHost("xn--d1abbgf6aiiy.xn--p1ai"), "президент.рф");
  assert.equal(displayHost("www.xn--d1abbgf6aiiy.xn--p1ai"), "www.президент.рф");
});
check("ASCII names untouched", () => {
  assert.equal(displayHost("sberbank.ru"), "sberbank.ru");
});
check("look-alikes keep their punycode (Latin zone, or mixed letters)", () => {
  // "аррӏе.com" in Cyrillic letters reads as apple.com.
  assert.equal(displayHost(toCheckHost("аррӏе.com")), toCheckHost("аррӏе.com"));
  assert.match(displayHost(toCheckHost("sberbank-онлайн.рф")), /^xn--/);
});

console.log("reasonLines (each plain-language reason once)");
check("codes sharing a label print one line, first one wins", () => {
  const details = ["Domain is new", "Certificate is new", "No HTTPS", "Free SSL on new domain"];
  const codes = ["domain_new", "new_certificate", "no_https", "free_ssl_new_domain"];
  assert.deepEqual(reasonLines(details, codes, (key) => `<${key}>`), ["<very_new_site>", "<no_https>"]);
});
check("three blocklist codes → one 'on blocklists' line", () => {
  const codes = ["spamhaus_dbl", "surbl", "multi_blocklist"];
  assert.deepEqual(reasonLines(["a", "b", "c"], codes, (key) => key), ["on_blocklists"]);
});
check("unmapped codes keep the API text, deduplicated by that text", () => {
  assert.deepEqual(reasonLines(["Odd", "Odd", "Other"], ["x_new", "x_new", undefined], (k) => k), ["Odd", "Other"]);
  assert.deepEqual(reasonLines(["A", "B"], undefined, (k) => k), ["A", "B"]);
});

console.log("client messages (next-intl provider)");
function clientNamespacesInUse() {
  const found = new Set();
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name !== "node_modules" && !entry.name.startsWith(".")) walk(full);
      } else if (/\.tsx?$/.test(entry.name)) {
        const text = fs.readFileSync(full, "utf-8");
        if (!/^\s*["']use client["']/m.test(text)) continue;
        for (const m of text.matchAll(/useTranslations\(\s*["']([A-Za-z]+)/g)) found.add(m[1]);
        assert.ok(!/useTranslations\(\s*\)/.test(text), `${full}: useTranslations() without a namespace`);
      }
    }
  };
  for (const dir of ["app", "components", "lib"]) walk(path.join(ROOT, "landing", dir));
  return found;
}
check("every namespace a client component reads is sent to the browser", () => {
  for (const ns of clientNamespacesInUse()) {
    assert.ok(CLIENT_NAMESPACES.includes(ns), `client component uses "${ns}" — add it to CLIENT_NAMESPACES`);
  }
});
check("legal text, methodology and the rest stay on the server", () => {
  const messages = JSON.parse(fs.readFileSync(path.join(ROOT, "landing", "messages", "ru.json"), "utf-8"));
  const picked = pickClientMessages(messages);
  assert.deepEqual(Object.keys(picked).sort(), [...CLIENT_NAMESPACES].filter((ns) => ns in messages).sort());
  for (const heavy of ["PrivacyPolicy", "Terms", "Methodology", "Transparency", "Support", "Android"]) {
    assert.ok(!(heavy in picked), `${heavy} would ride on every page`);
  }
  assert.ok(JSON.stringify(picked).length < JSON.stringify(messages).length / 3);
});

console.log("legal documents (links attach by section id)");
const LEGAL_IDS = { privacy_policy: ["contact"], terms: ["privacy", "contact"] };
check("every locale has the same sections, and the ids the pages attach links to", () => {
  const reference = landingSource("en");
  for (const [doc, required] of Object.entries(LEGAL_IDS)) {
    const refIds = reference[doc].sections.map((section) => section.id ?? null);
    for (const id of required) assert.ok(refIds.includes(id), `en ${doc}: no section with id "${id}"`);
    for (const locale of LOCALES) {
      const ids = landingSource(locale)[doc].sections.map((section) => section.id ?? null);
      assert.deepEqual(ids, refIds, `${locale} ${doc}: sections differ from en (count or ids)`);
    }
  }
});

console.log("scrubSitePaths (Sentry)");
check("/check and /audit pages lose the site name, any locale prefix", () => {
  assert.equal(scrubSitePaths("https://cleanway.ai/ru/check/bank-verify.ru"), "https://cleanway.ai/ru/check/[site]");
  assert.equal(scrubSitePaths("/check/example.com?x=1"), "/check/[site]?x=1");
  assert.equal(scrubSitePaths("/de/audit/example.com/grade/F"), "/de/audit/[site]/grade/F");
  assert.equal(scrubSitePaths("GET /api/v1/public/check/example.com"), "GET /api/v1/public/check/[site]");
});
check("other paths are left alone", () => {
  assert.equal(scrubSitePaths("/ru/android"), "/ru/android");
  assert.equal(scrubSitePaths("/ru/check"), "/ru/check");
});

if (failures > 0) {
  console.log(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall checks passed");

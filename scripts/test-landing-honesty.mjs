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
import { installScreenshotSrc } from "../landing/lib/install-screenshots.ts";
import { paidPlansOffered } from "../landing/lib/paid-plans.ts";
import { REASON_CODE_TO_KEY, reasonLabelKey } from "../landing/lib/reason-label.ts";
import { isFlagOn } from "../landing/lib/support.ts";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LATEST = path.join(HERE, "..", "docs", "benchmarks", "latest.json");

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

function snapshot({ nPhishing = 200, phishing = {}, safe = {} } = {}) {
  return {
    ts: "2026-09-21T11:53:00Z",
    n_phishing: nPhishing,
    n_safe: 200,
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

if (failures > 0) {
  console.log(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall checks passed");

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
 *  11. The operator-billed subscription (Russia) is sold only behind its flag,
 *      at prices that come from settings, with the same ICU arguments in every
 *      language — and the legal pages swap their payment section by id.
 *  12. The world's /pricing shows the device plan the API serves, falls back to
 *      the base tier for anything else, and never hand-writes a price.
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
  MIN_SAFE_CLASSIFIED,
  MAX_UNKNOWN_RATE,
} from "../landing/lib/benchmark.ts";
import { hostFromSegment, toCheckHost } from "../landing/lib/check-host.ts";
import { CLIENT_NAMESPACES, pickClientMessages } from "../landing/lib/client-messages.ts";
import { displayHost } from "../landing/lib/display-host.ts";
import { installScreenshotSrc } from "../landing/lib/install-screenshots.ts";
import {
  DEFAULT_EXTRA_DEVICE_RUB,
  DEFAULT_FREE_CHECKS_PER_DAY,
  DEFAULT_GRACE_DAYS,
  DEFAULT_INCLUDED_DEVICES,
  DEFAULT_PRICE_RUB,
  DEFAULT_TRIAL_DAYS,
  billingMessageArgs,
  billingTermsFromEnv,
  formatPhone,
  monthlyPriceFor,
  parseLapsePolicy,
  parsePositiveInt,
  pricingVariant,
  replaceSection,
  sellerFromEnv,
  sellerIsComplete,
  stopNumberFromEnv,
  supportPhoneFromEnv,
} from "../landing/lib/billing.ts";
import { paidPlansOffered } from "../landing/lib/paid-plans.ts";
import { REASON_CODE_TO_KEY, reasonLabelKey, reasonLines } from "../landing/lib/reason-label.ts";
import { scrubSitePaths } from "../landing/lib/sentry-scrub.ts";
import { isFlagOn } from "../landing/lib/support.ts";
import {
  DEFAULT_PRICING,
  checkoutPlanKey,
  intervalFrom,
  monthsFree,
  normalizePricing,
  usd,
} from "../landing/lib/world-pricing.ts";

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
check("committed latest.json: recall is shown only by its own numbers", () => {
  // The weekly benchmark rewrites latest.json; pin the gate, not one snapshot.
  const committed = JSON.parse(fs.readFileSync(LATEST, "utf-8"));
  const ours = committed.phishing?.cleanway ?? {};
  const answered = (ours.tp ?? 0) + (ours.fn ?? 0);
  const unknown = ours.unknown ?? 0;
  const expected =
    typeof ours.recall === "number" && ours.recall > 0 &&
    (committed.n_phishing ?? 0) >= MIN_PHISHING_SAMPLE &&
    answered >= MIN_PHISHING_CLASSIFIED &&
    unknown / (answered + unknown) <= MAX_UNKNOWN_RATE;
  assert.equal(recallIsPublishable(committed), expected);
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
check("committed latest.json: false-positive rate is shown only by its own numbers", () => {
  const committed = JSON.parse(fs.readFileSync(LATEST, "utf-8"));
  const ours = committed.safe?.cleanway ?? {};
  const expected =
    committed.sources?.legit_outside_allowlist === true &&
    typeof ours.fpr === "number" &&
    (ours.tn ?? 0) + (ours.fp ?? 0) >= MIN_SAFE_CLASSIFIED;
  assert.equal(falsePositiveRateIsPublishable(committed), expected);
  if (expected) {
    // A shown rate rests on a stated, allowlist-free sample.
    assert.equal(typeof committed.sources.legit, "string");
  }
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
  for (const heavy of ["PrivacyPolicy", "Terms", "Methodology", "Transparency", "Support", "Android", "Billing", "Cancel"]) {
    assert.ok(!(heavy in picked), `${heavy} would ride on every page`);
  }
  assert.ok(JSON.stringify(picked).length < JSON.stringify(messages).length / 3);
});

console.log("legal documents (links attach by section id)");
const LEGAL_IDS = { privacy_policy: ["payments", "contact"], terms: ["payments", "privacy", "contact"] };
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

console.log("operator-billed subscription (lib/billing.ts)");
check("defaults are the founder's numbers: 99 ₽ for 3 devices, +29 ₽ each more, 3 checks a day, 7 days unlimited, 7-day grace, basic lapse", () => {
  const terms = billingTermsFromEnv({});
  assert.deepEqual(
    [terms.priceRub, terms.includedDevices, terms.extraDeviceRub, terms.freeChecksPerDay],
    [99, 3, 29, 3],
  );
  assert.deepEqual(
    [DEFAULT_PRICE_RUB, DEFAULT_INCLUDED_DEVICES, DEFAULT_EXTRA_DEVICE_RUB, DEFAULT_FREE_CHECKS_PER_DAY],
    [99, 3, 29, 3],
  );
  assert.equal(terms.trialDays, DEFAULT_TRIAL_DAYS);
  assert.equal(terms.trialDays, 7);
  assert.equal(terms.graceDays, DEFAULT_GRACE_DAYS);
  assert.equal(terms.graceDays, 7);
  assert.equal(terms.lapsePolicy, "basic");
});
check("every number comes from its env setting; a malformed value falls back instead of selling a typo", () => {
  const terms = billingTermsFromEnv({
    NEXT_PUBLIC_BILLING_PRICE_RUB: "149",
    NEXT_PUBLIC_BILLING_INCLUDED_DEVICES: " 4 ",
    NEXT_PUBLIC_BILLING_EXTRA_DEVICE_RUB: "4.99",
    NEXT_PUBLIC_BILLING_FREE_CHECKS_PER_DAY: "5",
    NEXT_PUBLIC_BILLING_TRIAL_DAYS: "30",
    NEXT_PUBLIC_BILLING_GRACE_DAYS: "-3",
    NEXT_PUBLIC_BILLING_LAPSE_POLICY: "OFF",
  });
  assert.deepEqual([terms.priceRub, terms.includedDevices, terms.extraDeviceRub, terms.freeChecksPerDay], [149, 4, 29, 5]);
  assert.equal(terms.trialDays, 30);
  assert.equal(terms.graceDays, 7);
  assert.equal(terms.lapsePolicy, "off");
});
check("parsePositiveInt / parseLapsePolicy edge cases", () => {
  for (const bad of [undefined, null, "", "0", "abc", "1e3", "1234567", "12 3"]) {
    assert.equal(parsePositiveInt(bad, 5), 5, `accepted ${JSON.stringify(bad)}`);
  }
  assert.equal(parsePositiveInt("007", 5), 7);
  assert.equal(parseLapsePolicy(undefined), "basic");
  assert.equal(parseLapsePolicy("basic"), "basic");
  assert.equal(parseLapsePolicy("anything-else"), "basic");
  assert.equal(parseLapsePolicy(" off "), "off");
});
check("price for N devices: the plan covers the included ones, each more adds the extra price; message arguments carry prices as text and counts as numbers", () => {
  const terms = billingTermsFromEnv({});
  assert.deepEqual([1, 3, 4, 5].map((n) => monthlyPriceFor(terms, n)), [99, 99, 128, 157]);
  assert.deepEqual(billingMessageArgs(terms), { price: "99", extra: "29", devices: 3, days: 7, checks: 3, grace: 7 });
});
check("pricingVariant: Russian visitors get the free page today and the operator page only with the flag on", () => {
  const stripe = (visitor) => paidPlansOffered(visitor);
  assert.equal(pricingVariant(stripe({ locale: "ru" }), false), "free");
  assert.equal(pricingVariant(stripe({ locale: "ru" }), true), "operator");
  assert.equal(pricingVariant(stripe({ locale: "en", country: "RU" }), false), "free");
  assert.equal(pricingVariant(stripe({ locale: "en", country: "RU" }), true), "operator");
  // Stripe where it is sold — the flag does not touch those visitors.
  assert.equal(pricingVariant(stripe({ locale: "en", country: null }), true), "stripe");
  assert.equal(pricingVariant(stripe({ locale: "de", country: "DE" }), false), "stripe");
});
check("seller requisites: present only when every field is well-formed", () => {
  const complete = sellerFromEnv({
    NEXT_PUBLIC_BILLING_SELLER_NAME: "ИП Иванов Иван Иванович",
    NEXT_PUBLIC_BILLING_SELLER_INN: "123456789012",
    NEXT_PUBLIC_BILLING_SELLER_OGRNIP: "123456789012345",
  });
  assert.equal(sellerIsComplete(complete), true);
  const typo = sellerFromEnv({
    NEXT_PUBLIC_BILLING_SELLER_NAME: "ИП Иванов",
    NEXT_PUBLIC_BILLING_SELLER_INN: "1234567890",
    NEXT_PUBLIC_BILLING_SELLER_OGRNIP: "123456789012345",
  });
  assert.equal(typo.inn, null);
  assert.equal(sellerIsComplete(typo), false);
  assert.deepEqual(sellerFromEnv({}), { name: null, inn: null, ogrnip: null });
  assert.equal(sellerIsComplete(sellerFromEnv({})), false);
});
check("STOP short number and support phone are shown only when set and well-formed", () => {
  assert.equal(stopNumberFromEnv({}), null);
  assert.equal(stopNumberFromEnv({ NEXT_PUBLIC_BILLING_STOP_NUMBER: "1234" }), "1234");
  assert.equal(stopNumberFromEnv({ NEXT_PUBLIC_BILLING_STOP_NUMBER: "+79991234567" }), null);
  assert.equal(supportPhoneFromEnv({}), null);
  assert.equal(supportPhoneFromEnv({ NEXT_PUBLIC_SUPPORT_PHONE: "+79991234567" }), "+79991234567");
  assert.equal(supportPhoneFromEnv({ NEXT_PUBLIC_SUPPORT_PHONE: "8 999 123 45 67" }), null);
  assert.equal(formatPhone("+79991234567"), "+7 999 123-45-67");
  assert.equal(formatPhone("+442071234567"), "+442071234567");
});
check("replaceSection swaps exactly the section with that id and returns a new array", () => {
  const sections = [{ id: "a", title: "A" }, { id: "payments", title: "P" }, { title: "no id" }];
  const swapped = replaceSection(sections, "payments", { id: "billing", title: "B" });
  assert.deepEqual(swapped.map((s) => s.title), ["A", "B", "no id"]);
  assert.notEqual(swapped, sections);
  assert.equal(sections[1].title, "P");
  assert.deepEqual(replaceSection(sections, "missing", { id: "x", title: "X" }), sections);
});

console.log("billing strings (behind NEXT_PUBLIC_BILLING_ENABLED, all 10 languages)");
// The strings the flag reveals. Each key must exist in every language with
// the same ICU arguments as English: a dropped {days} or {solo} renders a
// sentence about a trial with no length, or a price with no number.
const BILLING_STRING_PATHS = [
  ["billing"],
  ["cancel"],
  ["terms", "billing"],
  ["privacy_policy", "billing"],
  ["pricing_teaser", "operator"],
];
function stringLeaves(node, prefix = "") {
  if (typeof node === "string") return [[prefix, node]];
  if (Array.isArray(node)) return node.flatMap((v, i) => stringLeaves(v, `${prefix}[${i}]`));
  if (node && typeof node === "object") return Object.entries(node).flatMap(([k, v]) => stringLeaves(v, prefix ? `${prefix}.${k}` : k));
  return [];
}
function icuArgs(text) {
  return [...text.matchAll(/\{([a-z][a-z0-9_]*)/g)].map((m) => m[1]).sort();
}
function pick(root, pathParts) {
  return pathParts.reduce((node, part) => (node == null ? undefined : node[part]), root);
}
check("every billing key exists in every language, with English's ICU arguments", () => {
  const en = landingSource("en");
  for (const pathParts of BILLING_STRING_PATHS) {
    const reference = pick(en, pathParts);
    assert.ok(reference && typeof reference === "object", `en: landing.${pathParts.join(".")} missing`);
    const refLeaves = new Map(stringLeaves(reference));
    assert.ok(refLeaves.size > 0, `en: landing.${pathParts.join(".")} is empty`);
    for (const locale of LOCALES) {
      const leaves = new Map(stringLeaves(pick(landingSource(locale), pathParts)));
      assert.deepEqual([...leaves.keys()], [...refLeaves.keys()], `${locale}: landing.${pathParts.join(".")} keys differ from en`);
      for (const [key, text] of refLeaves) {
        assert.deepEqual(icuArgs(leaves.get(key)), icuArgs(text), `${locale}: landing.${pathParts.join(".")}.${key} ICU arguments differ`);
        assert.ok(leaves.get(key).trim().length > 0, `${locale}: landing.${pathParts.join(".")}.${key} is blank`);
      }
    }
  }
});
check("the billing sections of the terms and the policy carry id 'billing', the ones they replace 'payments'", () => {
  for (const locale of LOCALES) {
    const landing = landingSource(locale);
    for (const doc of ["terms", "privacy_policy"]) {
      assert.equal(landing[doc].billing.section.id, "billing", `${locale} ${doc}.billing.section.id`);
      assert.equal(landing[doc].sections.filter((s) => s.id === "payments").length, 1, `${locale} ${doc}: exactly one 'payments' section`);
    }
  }
});
check("both lapse policies have their sentence, and prices are never written into a billing string", () => {
  for (const locale of LOCALES) {
    const landing = landingSource(locale);
    for (const policy of ["basic", "off"]) {
      assert.equal(typeof landing.billing[`lapse_${policy}`], "string", `${locale}: billing.lapse_${policy}`);
      assert.equal(typeof landing.terms.billing[`lapse_${policy}`], "string", `${locale}: terms.billing.lapse_${policy}`);
    }
    for (const pathParts of BILLING_STRING_PATHS) {
      for (const [key, text] of stringLeaves(pick(landing, pathParts))) {
        assert.doesNotMatch(text, /\b(99|270|399)\s?(₽|руб|RUB)/i, `${locale}: landing.${pathParts.join(".")}.${key} hard-codes a price`);
      }
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

console.log("world pricing (lib/world-pricing.ts)");
const DEVICE_PLAN_RESPONSE = {
  country: "IN",
  tier: 4,
  currency: "USD",
  plan: {
    id: "devices",
    included_devices: 3,
    price: {
      monthly: { amount: 0.99, monthly_equivalent: 0.99, interval: "monthly", stripe_price_id: "p1" },
      yearly: { amount: 4.99, monthly_equivalent: 0.42, interval: "yearly", stripe_price_id: "p2" },
    },
    extra_device: {
      monthly: { amount: 0.49, monthly_equivalent: 0.49, interval: "monthly", stripe_price_id: "p3" },
      yearly: { amount: 2.49, monthly_equivalent: 0.21, interval: "yearly", stripe_price_id: "p4" },
    },
    trial_days: 14,
  },
  free: { list_blocking_unlimited: true, detailed_checks_per_day: 3, unlimited_days_after_install: 7 },
  messaging: { blocking_is_free_forever: true, what_paid_unlocks: [] },
};
check("the base tier fallback is the founder's world price: $0.99 / $9.99, +$0.49 per device, 3 devices", () => {
  assert.equal(DEFAULT_PRICING.price.monthly.amount, 0.99);
  assert.equal(DEFAULT_PRICING.price.yearly.amount, 9.99);
  assert.equal(DEFAULT_PRICING.extraDevice.monthly.amount, 0.49);
  assert.equal(DEFAULT_PRICING.includedDevices, 3);
  assert.equal(DEFAULT_PRICING.country, null);
  assert.equal(monthsFree(DEFAULT_PRICING), 2);
});
check("normalizePricing reads the device plan and refuses anything else (an API from before it, partial bodies)", () => {
  const pricing = normalizePricing(DEVICE_PLAN_RESPONSE);
  assert.ok(pricing);
  assert.equal(pricing.country, "IN");
  assert.equal(pricing.tier, 4);
  assert.equal(pricing.price.yearly.amount, 4.99);
  assert.equal(pricing.extraDevice.yearly.amount, 2.49);
  assert.equal(pricing.freeChecksPerDay, 3);
  assert.equal(monthsFree(pricing), 7);
  // The pre-device-plan response: personal / family / business.
  const legacy = {
    country: null, tier: 2, currency: "USD",
    plans: { personal: { monthly: { amount: 4.99 }, yearly: { amount: 49.9 } } },
    messaging: { blocking_is_free_forever: true, free_threat_threshold: 50, what_paid_unlocks: [] },
  };
  assert.equal(normalizePricing(legacy), null);
  assert.equal(normalizePricing(null), null);
  assert.equal(normalizePricing("oops"), null);
  const noYearly = structuredClone(DEVICE_PLAN_RESPONSE);
  delete noYearly.plan.price.yearly;
  assert.equal(normalizePricing(noYearly), null);
  const zeroPrice = structuredClone(DEVICE_PLAN_RESPONSE);
  zeroPrice.plan.price.monthly.amount = 0;
  assert.equal(normalizePricing(zeroPrice), null);
  const badTier = structuredClone(DEVICE_PLAN_RESPONSE);
  badTier.tier = 7;
  assert.equal(normalizePricing(badTier), null);
  const oddCountry = structuredClone(DEVICE_PLAN_RESPONSE);
  oddCountry.country = "<script>";
  assert.equal(normalizePricing(oddCountry).country, null);
});
check("usd, intervals and the checkout key", () => {
  assert.equal(usd(0.99), "$0.99");
  assert.equal(usd(9.99), "$9.99");
  assert.equal(usd(4.9), "$4.90");
  assert.equal(intervalFrom(undefined), "yearly");
  assert.equal(intervalFrom("monthly"), "monthly");
  assert.equal(intervalFrom("weekly"), "yearly");
  assert.equal(checkoutPlanKey("yearly"), "devices_yearly");
  assert.equal(checkoutPlanKey("monthly"), "devices_monthly");
});
check("monthsFree says nothing when yearly is not cheaper", () => {
  const flat = { ...DEFAULT_PRICING, price: { monthly: { amount: 1, monthlyEquivalent: 1 }, yearly: { amount: 12, monthlyEquivalent: 1 } } };
  assert.equal(monthsFree(flat), 0);
});
check("every world pricing key exists in every language, with English's ICU arguments", () => {
  const refLeaves = new Map(stringLeaves(landingSource("en").pricing));
  for (const locale of LOCALES) {
    const leaves = new Map(stringLeaves(landingSource(locale).pricing));
    assert.deepEqual([...leaves.keys()].sort(), [...refLeaves.keys()].sort(), `${locale}: landing.pricing keys differ from en`);
    for (const [key, text] of refLeaves) {
      assert.deepEqual(icuArgs(leaves.get(key)), icuArgs(text), `${locale}: landing.pricing.${key} ICU arguments differ`);
    }
  }
});
check("the world pricing strings carry no hand-written dollar price, in any locale", () => {
  for (const locale of LOCALES) {
    for (const [key, value] of Object.entries(landingSource(locale).pricing)) {
      const text = Array.isArray(value) ? value.join(" ") : String(value);
      assert.ok(!/\$\s?\d/.test(text), `${locale} landing.pricing.${key}: hand-written price "${text}"`);
    }
  }
});

if (failures > 0) {
  console.log(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall checks passed");

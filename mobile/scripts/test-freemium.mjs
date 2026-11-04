#!/usr/bin/env node
/**
 * Table test for src/utils/freemium.ts — the free plan's daily limit — and
 * the list-only message verdict it falls back to (message-verdict.ts).
 *
 * Run: node --experimental-strip-types mobile/scripts/test-freemium.mjs
 *
 * No jest in mobile/ (see test-host-parser.mjs); both modules import nothing
 * from react-native, so node's TS stripper loads them as-is.
 *
 * Pinned (docs/ACCOUNTS_BILLING_PLAN.md §5):
 *   • the switch is OFF unless EXPO_PUBLIC_FREEMIUM_ENABLED says so, and off
 *     means every check is detailed — current users see no change;
 *   • the limit and the trial come from the server (GET
 *     /api/v1/pricing/for-country `free`: 5 manual checks a MONTH after 7
 *     days unlocked, founder 2026-11-04) — nothing is typed into the app;
 *     a malformed answer is ignored, and with no answer ever the app does
 *     not limit (a counter must never hide an analysis);
 *   • the counter resets on the 1st, local time; a clock moved back before
 *     the install does not count as the trial;
 *   • a paid account is unlimited; a paid answer survives 7 days offline,
 *     never for another account;
 *   • re-opening the same site the same day is not a second check; a message
 *     (never stored, not even hashed) always counts;
 *   • the paywall opens by itself at most once a day (the card stays);
 *   • after the limit a message keeps the scam list's verdict: a listed link
 *     is still "dangerous", and nothing else is claimed;
 *   • a store build never links out to the web checkout; Russia shows
 *     "coming soon"; signed out → sign in first;
 *   • a build that cannot take a payment (RuStore: no billing built; a
 *     store build without its billing SDK) says "coming soon" up front —
 *     the button off, no sign-in first for a purchase that cannot happen;
 *   • "Upgrade" / the Plan row are hidden exactly where the paywall would say
 *     "coming soon" — by the phone's region, like the paywall's prices, not
 *     by the app's language (a Ukrainian phone with Russian second opens in
 *     Russian, and in Ukraine it can pay), and in a build that cannot sell;
 *   • no world price is typed into the app: a store build shows the store's
 *     own price (StorePlans), the site APK the server's (GET
 *     /api/v1/pricing/for-country), and nothing when neither answered.
 */
import assert from "node:assert/strict";
import { createRequire } from "node:module";

import {
  ENTITLEMENT_FRESH_MS,
  TERMS_FRESH_MS,
  ENTITLEMENT_GRACE_MS,
  WEB_CHECKOUT_URL,
  accessFor,
  emptyQuota,
  entitlementFresh,
  gateCheck,
  inTrial,
  installedAtOr,
  isPaidEntitlement,
  localDayKey,
  localMonthKey,
  marketFor,
  paidFromCache,
  paidPlansVisible,
  parseEntitlementCache,
  parseFreeTerms,
  parseTermsCache,
  paywallBenefits,
  paywallSaleOff,
  priceDisplay,
  purchaseAction,
  webPlanPrice,
  quotaForPeriod,
  readFreemiumConfig,
  termsFresh,
  trialDaysLeft,
  webCheckoutAllowed,
  withPaywallShown,
} from "../src/utils/freemium.ts";
import { listOnlyVerdict } from "../src/utils/message-verdict.ts";
import { firstSupportedLocale } from "../src/utils/device-locale.ts";

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

const DAY = 24 * 60 * 60 * 1000;
const ON = readFreemiumConfig({ EXPO_PUBLIC_FREEMIUM_ENABLED: "1" });
const OFF = readFreemiumConfig({});
// Local noon on 2026-10-08, so ±hours never cross midnight by accident.
const NOON = new Date(2026, 9, 8, 12, 0, 0).getTime();
const TODAY = localDayKey(NOON);
const MONTH = localMonthKey(NOON);
const LONG_AGO = NOON - 30 * DAY;
/** What the server sends today (api/routers/pricing.py `free`). */
const SERVER = { list_blocking_unlimited: true, manual_checks: 5, manual_checks_period: "month", unlimited_days_after_install: 7 };
const TERMS = parseFreeTerms({ free: SERVER });

/** Run [n] link checks of distinct sites through the gate, as the service does. */
function spend(n, config = ON, installedAt = LONG_AGO, paid = false, terms = TERMS) {
  let quota = emptyQuota(MONTH);
  const gates = [];
  for (let i = 0; i < n; i += 1) {
    const access = accessFor({ config, terms, paid, installedAt, quota, nowMs: NOON });
    const gate = gateCheck(access, quota, `site-${i}.ru`, TODAY);
    gates.push(gate.detailed);
    quota = gate.quota;
  }
  return { gates, quota };
}
const accessNow = (quota, extra = {}) =>
  accessFor({ config: ON, terms: TERMS, paid: false, installedAt: LONG_AGO, quota, nowMs: NOON, ...extra });

console.log("config");
check("off by default, site build; the limit is not a build setting", () => {
  assert.deepEqual(OFF, { enabled: false, distribution: "site" });
  // The old build-time knobs are gone: the server decides the numbers.
  assert.deepEqual(readFreemiumConfig({ EXPO_PUBLIC_FREE_CHECKS_PER_DAY: "3", EXPO_PUBLIC_FREE_TRIAL_DAYS: "1" }), OFF);
});
for (const [flag, enabled] of [["1", true], ["true", true], ["TRUE", true], ["0", false], ["false", false], ["yes", false], ["", false]]) {
  check(`EXPO_PUBLIC_FREEMIUM_ENABLED=${JSON.stringify(flag)} → ${enabled}`, () => {
    assert.equal(readFreemiumConfig({ EXPO_PUBLIC_FREEMIUM_ENABLED: flag }).enabled, enabled);
  });
}

console.log("the server's terms");
check("today's answer: 5 a month after 7 days", () => {
  assert.deepEqual(TERMS, { limit: 5, trialDays: 7 });
});
check("whatever the server says — a change there needs no new build", () => {
  assert.deepEqual(parseFreeTerms({ free: { ...SERVER, manual_checks: 20, unlimited_days_after_install: 0 } }), { limit: 20, trialDays: 0 });
  assert.deepEqual(parseFreeTerms({ free: { ...SERVER, manual_checks: 0 } }), { limit: 0, trialDays: 7 });
});
check("a malformed or older answer is no terms (the stored ones stay)", () => {
  for (const junk of [null, undefined, "x", {}, { free: null },
    { free: { detailed_checks_per_day: 3, unlimited_days_after_install: 7 } }, // the API before 2026-11-04
    { free: { ...SERVER, manual_checks_period: "day" } },
    { free: { ...SERVER, manual_checks: -1 } }, { free: { ...SERVER, manual_checks: 2.5 } },
    { free: { ...SERVER, manual_checks: "5" } }, { free: { ...SERVER, unlimited_days_after_install: -3 } },
    { free: { ...SERVER, manual_checks: 100000 } }]) {
    assert.equal(parseFreeTerms(junk), null, JSON.stringify(junk));
  }
});
check("the stored terms are re-asked after 6 h; a stamp from the future is stale", () => {
  const cache = { terms: TERMS, fetchedAt: NOON };
  assert.equal(termsFresh(cache, NOON + TERMS_FRESH_MS - 1), true);
  assert.equal(termsFresh(cache, NOON + TERMS_FRESH_MS), false);
  assert.equal(termsFresh({ terms: TERMS, fetchedAt: NOON + DAY }, NOON), false);
  assert.equal(termsFresh(null, NOON), false);
});
check("a broken stored copy reads as none", () => {
  assert.deepEqual(parseTermsCache(JSON.parse(JSON.stringify({ terms: TERMS, fetchedAt: 1 }))), { terms: TERMS, fetchedAt: 1 });
  for (const junk of [null, "x", { terms: { limit: -1, trialDays: 7 }, fetchedAt: 1 }, { terms: TERMS }, { terms: TERMS, fetchedAt: "1" }]) {
    assert.equal(parseTermsCache(junk), null, JSON.stringify(junk));
  }
});
check("no terms ever (the server never answered): no limit — a counter never hides an analysis", () => {
  const { gates, quota } = spend(9, ON, LONG_AGO, false, null);
  assert.deepEqual(gates, Array(9).fill(true));
  assert.equal(quota.used, 0);
  assert.deepEqual(accessNow(emptyQuota(MONTH), { terms: null }), { kind: "unlimited", why: "no_terms" });
});
for (const [value, dist] of [["play", "play"], ["rustore", "rustore"], ["site", "site"], ["PLAY", "play"], ["appstore", "site"], ["", "site"]]) {
  check(`EXPO_PUBLIC_DISTRIBUTION=${JSON.stringify(value)} → ${dist}`, () => {
    assert.equal(readFreemiumConfig({ EXPO_PUBLIC_DISTRIBUTION: value }).distribution, dist);
    assert.equal(readFreemiumConfig({ EXPO_PUBLIC_DISTRIBUTION: value }, "android").distribution, dist);
  });
}
check("the Android release guard accepts a store exactly when the app and autolinking read that store", () => {
  // plugins/distribution.js stops a release whose EXPO_PUBLIC_DISTRIBUTION the
  // app would read as the site build; it must never let one through as play.
  const require = createRequire(import.meta.url);
  const { STORES, distributionOf, releaseCheck } = require("../plugins/distribution.js");
  const { storeBillingLinked } = require("../plugins/store-billing-linking.js");
  for (const value of ["play", " PLAY ", "rustore", "site", "", "appstore", "play;", "'play'", "pl.ay", "p lay", "pl'ay${x}"]) {
    const env = { EXPO_PUBLIC_DISTRIBUTION: value };
    const store = distributionOf(env);
    const accepted = releaseCheck({ distribution: store, prebuild: store, artifact: "apk", revenueCatKey: true }).ok;
    const app = readFreemiumConfig(env, "android").distribution;
    assert.equal(accepted, STORES.includes(store), JSON.stringify(value));
    assert.equal(accepted, app === store, JSON.stringify(value));
    assert.equal(storeBillingLinked(env), accepted && store === "play", JSON.stringify(value));
  }
});
check("iOS: always the App Store build, whatever EXPO_PUBLIC_DISTRIBUTION says", () => {
  for (const value of ["play", "site", "rustore", "appstore", "", undefined]) {
    assert.equal(readFreemiumConfig({ EXPO_PUBLIC_DISTRIBUTION: value }, "ios").distribution, "appstore", String(value));
  }
});
check("no paid plans in this build (iPhone without App Store billing): no limit, no paywall", () => {
  // Nothing to buy means nothing to limit: a hard stop with no way out would
  // be worse than no limit at all (store-billing.ts paidPlansOffered).
  const env = { EXPO_PUBLIC_FREEMIUM_ENABLED: "1" };
  const cfg = readFreemiumConfig(env, "ios", false);
  assert.equal(cfg.enabled, false);
  const spent = { ...emptyQuota(MONTH), used: 99 };
  const access = accessFor({ config: cfg, terms: TERMS, paid: false, installedAt: LONG_AGO, quota: spent, nowMs: NOON });
  assert.deepEqual(access, { kind: "unlimited", why: "off" });
  const gate = gateCheck(access, spent, "a.ru", TODAY);
  assert.equal(gate.detailed, true);
  assert.equal(gate.autoPaywall, false);
  assert.equal(gate.quota, spent); // nothing counted
  // The same iPhone build with App Store billing: limited as before.
  const sold = readFreemiumConfig(env, "ios", true);
  assert.equal(sold.enabled, true);
  assert.equal(accessFor({ config: sold, terms: TERMS, paid: false, installedAt: LONG_AGO, quota: spent, nowMs: NOON }).kind, "free");
  // Android (and any caller that does not say): the flag alone decides, as before.
  assert.equal(readFreemiumConfig(env, "android").enabled, true);
  assert.equal(readFreemiumConfig(env).enabled, true);
  assert.equal(readFreemiumConfig({}, "android").enabled, false);
});
check("paywall benefits: only what the build can do, and only what the plan adds", () => {
  assert.deepEqual(paywallBenefits("appstore"), ["unlimited", "devices"]);
  // No build reads SMS by itself yet (feat/sms-auto-rustore is not merged), and
  // the call guard is free for everyone — neither is sold as a plan benefit.
  for (const dist of ["site", "play", "rustore"]) {
    assert.deepEqual(paywallBenefits(dist), ["unlimited", "text_model", "devices"], dist);
  }
});

console.log("the monthly counter");
check("limit off: every check is detailed, nothing is counted", () => {
  const { gates, quota } = spend(10, OFF);
  assert.deepEqual(gates, Array(10).fill(true));
  assert.equal(quota.used, 0);
});
check("free: 5 detailed, then the list's verdict only", () => {
  const { gates, quota } = spend(7);
  assert.deepEqual(gates, [true, true, true, true, true, false, false]);
  assert.equal(quota.used, 5);
});
check("remaining counts down 5 → 0 and never below", () => {
  let quota = emptyQuota(MONTH);
  const left = [];
  for (let i = 0; i < 7; i += 1) {
    const access = accessNow(quota);
    left.push(access.remaining);
    quota = gateCheck(access, quota, `s${i}.ru`, TODAY).quota;
  }
  assert.deepEqual(left, [5, 4, 3, 2, 1, 0, 0]);
});
check("the same site again this month is free (\"Full details\" after the shared screen)", () => {
  let quota = emptyQuota(MONTH);
  quota = gateCheck(accessNow(quota), quota, "pochta-dostavka.ru", TODAY).quota;
  const again = gateCheck(accessNow(quota), quota, "pochta-dostavka.ru", TODAY);
  assert.equal(again.detailed, true);
  assert.equal(again.quota.used, 1);
});
check("a site checked before the limit stays detailed after it", () => {
  const { quota } = spend(5);
  assert.equal(gateCheck(accessNow(quota), quota, "site-0.ru", TODAY).detailed, true);
  assert.equal(gateCheck(accessNow(quota), quota, "new-site.ru", TODAY).detailed, false);
});
check("a message (key null) always counts — its text is never kept", () => {
  let quota = emptyQuota(MONTH);
  const results = [];
  for (let i = 0; i < 6; i += 1) {
    const gate = gateCheck(accessNow(quota), quota, null, TODAY);
    results.push(gate.detailed);
    quota = gate.quota;
  }
  assert.deepEqual(results, [true, true, true, true, true, false]);
  assert.deepEqual(quota.keys, []);
});
check("a stopped check does not spend anything", () => {
  const { quota } = spend(5);
  assert.equal(gateCheck(accessNow(quota), quota, "x.ru", TODAY).quota.used, 5);
});
check("the server lowering the limit mid-month: what is spent stays spent, never below 0", () => {
  const { quota } = spend(4);
  const access = accessNow(quota, { terms: { limit: 2, trialDays: 7 } });
  assert.deepEqual(access, { kind: "free", limit: 2, remaining: 0 });
  assert.equal(gateCheck(access, quota, "new.ru", TODAY).detailed, false);
});
check("limit 0 from the server: no detailed checks after the trial", () => {
  assert.deepEqual(spend(2, ON, LONG_AGO, false, { limit: 0, trialDays: 7 }).gates, [false, false]);
});

console.log("reset on the 1st, local time");
check("the month key is the phone's local calendar month", () => {
  assert.equal(localMonthKey(new Date(2026, 9, 1, 0, 0, 0).getTime()), "2026-10");
  assert.equal(localMonthKey(new Date(2026, 9, 31, 23, 59, 59).getTime()), "2026-10");
  assert.equal(localMonthKey(new Date(2026, 10, 1, 0, 0, 0).getTime()), "2026-11");
  assert.equal(localMonthKey(new Date(2027, 0, 5, 9, 0, 0).getTime()), "2027-01");
});
check("last month's spent counter starts over on the 1st", () => {
  const { quota } = spend(5);
  const next = localMonthKey(new Date(2026, 10, 1, 0, 0, 1).getTime());
  assert.deepEqual(quotaForPeriod(quota, next), emptyQuota(next));
});
check("tomorrow, same month: the counter is kept (it is not a daily limit)", () => {
  const { quota } = spend(5);
  const tomorrow = new Date(2026, 9, 9, 9, 0, 0).getTime();
  const kept = quotaForPeriod(JSON.parse(JSON.stringify(quota)), localMonthKey(tomorrow));
  assert.deepEqual(kept, quota);
  assert.equal(accessNow(kept, { nowMs: tomorrow }).remaining, 0);
});
check("a counter stored by the old daily build reads as a fresh month, never as a crash", () => {
  for (const junk of [null, undefined, "x", 5, [], { day: TODAY, used: 3, keys: [] }, { period: MONTH, used: "lots" },
    { period: MONTH, used: -4, keys: [1, "a.ru"] }]) {
    const q = quotaForPeriod(junk, MONTH);
    assert.equal(q.period, MONTH);
    assert.ok(q.used >= 0);
    assert.ok(q.keys.every((k) => typeof k === "string"));
  }
});

console.log("the trial: everything unlocked first");
check("day 0 and day 6 are in the trial, day 7 is not", () => {
  assert.equal(inTrial(NOON, NOON, 7), true);
  assert.equal(inTrial(NOON - 6 * DAY - 1, NOON, 7), true);
  assert.equal(inTrial(NOON - 7 * DAY, NOON, 7), false);
});
check("a clock set before the install is not the trial", () => {
  assert.equal(inTrial(NOON + DAY, NOON, 7), false);
});
check("trial 0 days from the server: none", () => {
  assert.equal(inTrial(NOON, NOON, 0), false);
  assert.deepEqual(spend(6, ON, NOON, false, { limit: 5, trialDays: 0 }).gates, [true, true, true, true, true, false]);
});
check("in the trial every check is detailed and nothing is counted", () => {
  const { gates, quota } = spend(9, ON, NOON - 2 * DAY);
  assert.deepEqual(gates, Array(9).fill(true));
  assert.equal(quota.used, 0);
});
check("days left: 7 on install day, 1 on the last day, 0 after", () => {
  assert.equal(trialDaysLeft(NOON, NOON, 7), 7);
  assert.equal(trialDaysLeft(NOON - 6.5 * DAY, NOON, 7), 1);
  assert.equal(trialDaysLeft(NOON - 8 * DAY, NOON, 7), 0);
});
check("install time: a stored number is kept; nothing / junk is now", () => {
  assert.equal(installedAtOr(String(LONG_AGO), NOON), LONG_AGO);
  assert.equal(installedAtOr("", NOON), NOON);
  assert.equal(installedAtOr("abc", NOON), NOON);
  assert.equal(installedAtOr("-5", NOON), NOON);
});

console.log("paid status");
for (const [ent, paid] of [
  [{ plan: "personal", status: "active" }, true],
  [{ plan: "family", status: "trialing" }, true],
  [{ plan: "personal", status: "past_due" }, true],
  [{ plan: "free", status: "free" }, false],
  [null, false],
]) {
  check(`entitlement ${JSON.stringify(ent)} → paid=${paid}`, () => assert.equal(isPaidEntitlement(ent), paid));
}
check("paid: unlimited, nothing counted", () => {
  const { gates, quota } = spend(8, ON, LONG_AGO, true);
  assert.deepEqual(gates, Array(8).fill(true));
  assert.equal(quota.used, 0);
});
check("the cached answer is fresh for 6 h, for its own account only", () => {
  const cache = { account: "a@x.ru", paid: true, fetchedAt: NOON };
  assert.equal(entitlementFresh(cache, "a@x.ru", NOON + ENTITLEMENT_FRESH_MS - 1), true);
  assert.equal(entitlementFresh(cache, "a@x.ru", NOON + ENTITLEMENT_FRESH_MS), false);
  assert.equal(entitlementFresh(cache, "b@x.ru", NOON), false);
});
check("offline grace: a paid answer counts for 7 days, then not", () => {
  const cache = { account: "a@x.ru", paid: true, fetchedAt: NOON };
  assert.equal(ENTITLEMENT_GRACE_MS, 7 * DAY);
  assert.equal(paidFromCache(cache, "a@x.ru", NOON + 6 * DAY), true);
  assert.equal(paidFromCache(cache, "a@x.ru", NOON + 7 * DAY), false);
});
check("offline grace never carries a plan to another account, or a free answer to paid", () => {
  assert.equal(paidFromCache({ account: "a@x.ru", paid: true, fetchedAt: NOON }, "b@x.ru", NOON), false);
  assert.equal(paidFromCache({ account: "a@x.ru", paid: false, fetchedAt: NOON }, "a@x.ru", NOON), false);
  assert.equal(paidFromCache(null, "a@x.ru", NOON), false);
});
check("a cache from the future (clock moved back) is not trusted", () => {
  assert.equal(paidFromCache({ account: "a@x.ru", paid: true, fetchedAt: NOON + DAY }, "a@x.ru", NOON), false);
});
check("a broken cache reads as none", () => {
  assert.equal(parseEntitlementCache({ account: "a", paid: "yes", fetchedAt: 1 }), null);
  assert.equal(parseEntitlementCache("x"), null);
  assert.deepEqual(parseEntitlementCache({ account: "a", paid: true, fetchedAt: 1, extra: 2 }), { account: "a", paid: true, fetchedAt: 1 });
});

console.log("the paywall opens by itself once a day");
check("first stop today → open; after it opened → card only", () => {
  const { quota } = spend(5);
  const first = gateCheck(accessNow(quota), quota, "a.ru", TODAY);
  assert.equal(first.autoPaywall, true);
  const shown = withPaywallShown(first.quota, TODAY);
  assert.equal(gateCheck(accessNow(shown), shown, "b.ru", TODAY).autoPaywall, false);
});
check("not marked unless the screen opened it (never over a dangerous verdict)", () => {
  const { quota } = spend(5);
  const stopped = gateCheck(accessNow(quota), quota, "a.ru", TODAY);
  assert.equal(gateCheck(accessNow(stopped.quota), stopped.quota, "b.ru", TODAY).autoPaywall, true);
});
check("the next day (same month, still no checks left) it may open once again", () => {
  const shown = withPaywallShown(spend(5).quota, TODAY);
  assert.equal(gateCheck(accessNow(shown), shown, "c.ru", "2026-10-09").autoPaywall, true);
});
check("an allowed check never opens it", () => {
  assert.equal(gateCheck(accessNow(emptyQuota(MONTH)), emptyQuota(MONTH), "a.ru", TODAY).autoPaywall, false);
});

console.log("message after the limit: the scam list only");
const link = (host, status = "unknown") => ({ text: `https://${host}/x`, host, status, shortener: false, messenger: false });
check("a listed link: dangerous, with the list's reason", () => {
  assert.deepEqual(listOnlyVerdict([link("ok.ru"), link("scam-pochta.ru", "blocked")]), { verdict: "dangerous", reasons: ["link_blocklisted"] });
});
check("no listed link: no verdict claimed (no_signals, no reasons)", () => {
  assert.deepEqual(listOnlyVerdict([link("ok.ru"), link("docs.google.com", "system")]), { verdict: "no_signals", reasons: [] });
  assert.deepEqual(listOnlyVerdict([]), { verdict: "no_signals", reasons: [] });
});

console.log("paying");
check("Russia: \"coming soon\" — phone-balance billing is not merged yet", () => {
  for (const signedIn of [true, false]) {
    for (const distribution of ["site", "play", "rustore", "appstore"]) {
      assert.equal(purchaseAction({ signedIn, market: "ru", distribution }), "soon");
    }
  }
});
check("signed out: sign in first, on every build", () => {
  for (const distribution of ["site", "play", "rustore", "appstore"]) {
    assert.equal(purchaseAction({ signedIn: false, market: "world", distribution }), "sign_in");
  }
});
check("signed in: site APK → web checkout; store builds → store billing, never the web", () => {
  assert.equal(purchaseAction({ signedIn: true, market: "world", distribution: "site" }), "web_checkout");
  assert.equal(purchaseAction({ signedIn: true, market: "world", distribution: "play" }), "store");
  assert.equal(purchaseAction({ signedIn: true, market: "world", distribution: "rustore" }), "store");
  assert.equal(purchaseAction({ signedIn: true, market: "world", distribution: "appstore" }), "store");
  assert.equal(webCheckoutAllowed("appstore"), false);
  assert.equal(webCheckoutAllowed("play"), false);
  assert.equal(webCheckoutAllowed("rustore"), false);
  assert.equal(webCheckoutAllowed("site"), true);
});
check("the web checkout is the site's monthly plan, over https", () => {
  const url = new URL(WEB_CHECKOUT_URL);
  assert.equal(url.protocol, "https:");
  assert.equal(url.hostname, "cleanway.ai");
  assert.equal(url.searchParams.get("interval"), "monthly");
});
check("market: the region decides, else the language", () => {
  assert.equal(marketFor("en", "RU"), "ru");
  assert.equal(marketFor("ru", "AE"), "world");
  assert.equal(marketFor("ru-RU", null), "ru");
  assert.equal(marketFor("de", undefined), "world");
});
const DISTRIBUTIONS = ["site", "play", "rustore", "appstore"];
check("RuStore: no billing built — \"coming soon\" up front, no sign-in first", () => {
  for (const signedIn of [false, true]) {
    const action = purchaseAction({ signedIn, market: "world", distribution: "rustore" });
    for (const storeBillingOn of [false, true]) {
      assert.equal(paywallSaleOff({ action, distribution: "rustore", storeBillingOn }), true, `${action} / ${storeBillingOn}`);
    }
  }
});
check("a store build without its billing SDK (no RevenueCat key): \"coming soon\" up front", () => {
  for (const distribution of ["play", "appstore"]) {
    for (const signedIn of [false, true]) {
      const action = purchaseAction({ signedIn, market: "world", distribution });
      assert.equal(paywallSaleOff({ action, distribution, storeBillingOn: false }), true, `${distribution} / ${action}`);
      assert.equal(paywallSaleOff({ action, distribution, storeBillingOn: true }), false, `${distribution} / ${action}`);
    }
  }
});
check("the site APK sells on the web: its button stays on, store billing or not", () => {
  for (const signedIn of [false, true]) {
    const action = purchaseAction({ signedIn, market: "world", distribution: "site" });
    assert.equal(paywallSaleOff({ action, distribution: "site", storeBillingOn: false }), false, action);
  }
});
check("Russia keeps its own \"coming soon\" (action soon), not the store one", () => {
  for (const distribution of DISTRIBUTIONS) {
    const action = purchaseAction({ signedIn: true, market: "ru", distribution });
    assert.equal(paywallSaleOff({ action, distribution, storeBillingOn: false }), false, distribution);
  }
});
check("upgrade entry points: hidden where the paywall says \"coming soon\", by the same signal", () => {
  const pairs = [
    ["ru", "RU"], ["ru-RU", null], ["en", "RU"], ["ru", undefined],
    ["ru", "UA"], ["ru", "KZ"], ["ru", "AE"], ["en", "US"], ["de", undefined], ["en", ""],
  ];
  for (const [language, region] of pairs) {
    const market = marketFor(language, region);
    for (const distribution of DISTRIBUTIONS) {
      for (const storeBillingOn of [false, true]) {
        // What the paywall's button would do for a signed-in person: a real
        // purchase, or "coming soon" (Russia, or a build that cannot sell).
        const action = purchaseAction({ signedIn: true, market, distribution });
        const sells = action !== "soon" && !paywallSaleOff({ action, distribution, storeBillingOn });
        assert.equal(
          paidPlansVisible({ language, region, distribution, storeBillingOn }), sells,
          `${language} / ${region} / ${distribution} / ${storeBillingOn}`,
        );
      }
    }
  }
  const play = { distribution: "play", storeBillingOn: true };
  assert.equal(paidPlansVisible({ language: "ru", region: "RU", ...play }), false);
  assert.equal(paidPlansVisible({ language: "ru", region: null, ...play }), false, "no region: the language decides");
  assert.equal(paidPlansVisible({ language: "en", region: "RU", ...play }), false, "an English phone in Russia cannot pay either");
  assert.equal(paidPlansVisible({ language: "en", region: "US", ...play }), true);
});
check("RuStore hides \"Upgrade\" everywhere: its paywall can only say \"coming soon\"", () => {
  for (const [language, region] of [["ru", "KZ"], ["ru", "BY"], ["ru", "UA"], ["en", "US"], ["ru", null], ["ru", "RU"]]) {
    for (const storeBillingOn of [false, true]) {
      assert.equal(paidPlansVisible({ language, region, distribution: "rustore", storeBillingOn }), false, `${language} / ${region}`);
    }
  }
});
check("\"Upgrade\" outside Russia: the site APK always; a store build only with its billing SDK", () => {
  const world = { language: "en", region: "US" };
  assert.equal(paidPlansVisible({ ...world, distribution: "site", storeBillingOn: false }), true);
  assert.equal(paidPlansVisible({ ...world, distribution: "play", storeBillingOn: true }), true);
  assert.equal(paidPlansVisible({ ...world, distribution: "play", storeBillingOn: false }), false);
  assert.equal(paidPlansVisible({ ...world, distribution: "appstore", storeBillingOn: true }), true);
  assert.equal(paidPlansVisible({ ...world, distribution: "appstore", storeBillingOn: false }), false);
});
check("a Ukrainian phone with Russian second opens in Russian and keeps \"Upgrade\" in Ukraine", () => {
  // The app starts in the first language it has (utils/device-locale.ts); the
  // region is the first preferred locale's, as on the paywall.
  const SUPPORTED = ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"];
  for (const region of ["UA", "KZ", "BY"]) {
    const phone = [{ languageCode: region === "KZ" ? "kk" : region === "BY" ? "be" : "uk", regionCode: region },
                   { languageCode: "ru", regionCode: region }];
    const language = firstSupportedLocale(phone, SUPPORTED);
    assert.equal(language, "ru");
    assert.equal(paidPlansVisible({ language, region: phone[0].regionCode, distribution: "site", storeBillingOn: false }), true, region);
    assert.equal(marketFor(language, phone[0].regionCode), "world", region);
  }
});
// What GET /api/v1/pricing/for-country answers (api/routers/pricing.py), trimmed.
const PRICING = {
  plan: { price: { monthly: { amount: 1.99 }, yearly: { amount: 19.99 } } },
};
check("prices: RU 99 ₽ a month (phone balance, not merged); no world price typed into the app", () => {
  assert.deepEqual(priceDisplay("ru", "site"), { price: "99 ₽", period: "month", alt: null });
  // Store builds: only the store's own quote (StorePlans) — nothing here.
  for (const dist of ["play", "appstore"]) {
    assert.equal(priceDisplay("world", dist, PRICING), null, dist);
  }
  // RuStore cannot sell yet ("coming soon"): no price for what cannot be bought.
  assert.equal(priceDisplay("world", "rustore", PRICING), null);
  // The site APK before the server answered (or when it could not): no price, never a guess.
  assert.equal(priceDisplay("world", "site"), null);
  assert.equal(priceDisplay("world", "site", null), null);
});
check("site APK: the server's price, monthly large (what its button buys), yearly under it", () => {
  assert.deepEqual(priceDisplay("world", "site", PRICING), {
    price: "$1.99", period: "month", alt: { price: "$19.99", period: "year" },
  });
});
check("the server's price is formatted as US dollars; junk is no price", () => {
  assert.deepEqual(webPlanPrice({ plan: { price: { monthly: { amount: 2 } } } }), { month: "$2.00", year: null });
  assert.deepEqual(webPlanPrice({ plan: { price: { monthly: { amount: 1.99 }, yearly: { amount: 0 } } } }), { month: "$1.99", year: null });
  for (const junk of [null, undefined, {}, { plan: null }, { plan: { price: { monthly: { amount: "1.99" } } } },
    { plan: { price: { monthly: { amount: -1 } } } }, { plan: { price: { monthly: { amount: Number.NaN } } } }]) {
    assert.equal(webPlanPrice(junk), null, JSON.stringify(junk));
  }
});
check("no world dollar amount is typed into the app's freemium rules", () => {
  const require = createRequire(import.meta.url);
  const fs = require("node:fs");
  const src = fs.readFileSync(new URL("../src/utils/freemium.ts", import.meta.url), "utf8");
  // Comments may name prices; code may not.
  const code = src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");
  assert.doesNotMatch(code, /\$\s?\d/);
});

if (failures) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall freemium checks passed");

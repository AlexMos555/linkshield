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
 *   • 3 detailed checks a day, reset at the phone's local midnight; a bad
 *     configured number falls back to the default, never to "unlimited";
 *   • the first 7 days after install are unlimited; a clock moved back
 *     before the install does not count as the trial;
 *   • a paid account is unlimited; a paid answer survives 7 days offline,
 *     never for another account;
 *   • re-opening the same site the same day is not a second check; a message
 *     (never stored, not even hashed) always counts;
 *   • the paywall opens by itself at most once a day;
 *   • after the limit a message keeps the scam list's verdict: a listed link
 *     is still "dangerous", and nothing else is claimed;
 *   • a store build never links out to the web checkout; Russia shows
 *     "coming soon"; signed out → sign in first.
 */
import assert from "node:assert/strict";

import {
  DEFAULT_DAILY_LIMIT,
  DEFAULT_TRIAL_DAYS,
  ENTITLEMENT_FRESH_MS,
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
  marketFor,
  paidFromCache,
  parseEntitlementCache,
  priceDisplay,
  purchaseAction,
  quotaForDay,
  readFreemiumConfig,
  trialDaysLeft,
  webCheckoutAllowed,
  withPaywallShown,
} from "../src/utils/freemium.ts";
import { listOnlyVerdict } from "../src/utils/message-verdict.ts";

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
const LONG_AGO = NOON - 30 * DAY;

/** Run [n] link checks of distinct sites through the gate, as the service does. */
function spend(n, config = ON, installedAt = LONG_AGO, paid = false) {
  let quota = emptyQuota(TODAY);
  const gates = [];
  for (let i = 0; i < n; i += 1) {
    const access = accessFor({ config, paid, installedAt, quota, nowMs: NOON });
    const gate = gateCheck(access, quota, `site-${i}.ru`);
    gates.push(gate.detailed);
    quota = gate.quota;
  }
  return { gates, quota };
}

console.log("config");
check("off by default; defaults 3 a day, 7 days, site build", () => {
  assert.deepEqual(OFF, { enabled: false, dailyLimit: 3, trialDays: 7, distribution: "site" });
  assert.equal(DEFAULT_DAILY_LIMIT, 3);
  assert.equal(DEFAULT_TRIAL_DAYS, 7);
});
for (const [flag, enabled] of [["1", true], ["true", true], ["TRUE", true], ["0", false], ["false", false], ["yes", false], ["", false]]) {
  check(`EXPO_PUBLIC_FREEMIUM_ENABLED=${JSON.stringify(flag)} → ${enabled}`, () => {
    assert.equal(readFreemiumConfig({ EXPO_PUBLIC_FREEMIUM_ENABLED: flag }).enabled, enabled);
  });
}
for (const [value, limit] of [["5", 5], ["0", 0], ["-1", 3], ["2.5", 3], ["abc", 3], ["", 3], ["100000", 3]]) {
  check(`EXPO_PUBLIC_FREE_CHECKS_PER_DAY=${JSON.stringify(value)} → ${limit}`, () => {
    assert.equal(readFreemiumConfig({ EXPO_PUBLIC_FREE_CHECKS_PER_DAY: value }).dailyLimit, limit);
  });
}
check("EXPO_PUBLIC_FREE_TRIAL_DAYS is read; a bad value keeps 7", () => {
  assert.equal(readFreemiumConfig({ EXPO_PUBLIC_FREE_TRIAL_DAYS: "14" }).trialDays, 14);
  assert.equal(readFreemiumConfig({ EXPO_PUBLIC_FREE_TRIAL_DAYS: "x" }).trialDays, 7);
});
for (const [value, dist] of [["play", "play"], ["rustore", "rustore"], ["site", "site"], ["PLAY", "play"], ["appstore", "site"], ["", "site"]]) {
  check(`EXPO_PUBLIC_DISTRIBUTION=${JSON.stringify(value)} → ${dist}`, () => {
    assert.equal(readFreemiumConfig({ EXPO_PUBLIC_DISTRIBUTION: value }).distribution, dist);
  });
}

console.log("the daily counter");
check("limit off: every check is detailed, nothing is counted", () => {
  const { gates, quota } = spend(10, OFF);
  assert.deepEqual(gates, Array(10).fill(true));
  assert.equal(quota.used, 0);
});
check("free: 3 detailed, then the list's verdict only", () => {
  const { gates, quota } = spend(5);
  assert.deepEqual(gates, [true, true, true, false, false]);
  assert.equal(quota.used, 3);
});
check("remaining counts down 3 → 0 and never below", () => {
  let quota = emptyQuota(TODAY);
  const left = [];
  for (let i = 0; i < 5; i += 1) {
    const access = accessFor({ config: ON, paid: false, installedAt: LONG_AGO, quota, nowMs: NOON });
    left.push(access.remaining);
    quota = gateCheck(access, quota, `s${i}.ru`).quota;
  }
  assert.deepEqual(left, [3, 2, 1, 0, 0]);
});
check("the same site again today is free (\"Full details\" after the shared screen)", () => {
  let quota = emptyQuota(TODAY);
  const access = () => accessFor({ config: ON, paid: false, installedAt: LONG_AGO, quota, nowMs: NOON });
  quota = gateCheck(access(), quota, "pochta-dostavka.ru").quota;
  const again = gateCheck(access(), quota, "pochta-dostavka.ru");
  assert.equal(again.detailed, true);
  assert.equal(again.quota.used, 1);
});
check("a site checked before the limit stays detailed after it", () => {
  const { quota } = spend(3);
  const access = accessFor({ config: ON, paid: false, installedAt: LONG_AGO, quota, nowMs: NOON });
  assert.equal(gateCheck(access, quota, "site-0.ru").detailed, true);
  assert.equal(gateCheck(access, quota, "new-site.ru").detailed, false);
});
check("a message (key null) always counts — its text is never kept", () => {
  let quota = emptyQuota(TODAY);
  const results = [];
  for (let i = 0; i < 4; i += 1) {
    const access = accessFor({ config: ON, paid: false, installedAt: LONG_AGO, quota, nowMs: NOON });
    const gate = gateCheck(access, quota, null);
    results.push(gate.detailed);
    quota = gate.quota;
  }
  assert.deepEqual(results, [true, true, true, false]);
  assert.deepEqual(quota.keys, []);
});
check("a stopped check does not spend anything", () => {
  const { quota } = spend(3);
  const access = accessFor({ config: ON, paid: false, installedAt: LONG_AGO, quota, nowMs: NOON });
  assert.equal(gateCheck(access, quota, "x.ru").quota.used, 3);
});
check("limit 0 configured: no detailed checks after the trial", () => {
  const zero = readFreemiumConfig({ EXPO_PUBLIC_FREEMIUM_ENABLED: "1", EXPO_PUBLIC_FREE_CHECKS_PER_DAY: "0" });
  assert.deepEqual(spend(2, zero).gates, [false, false]);
});

console.log("reset at local midnight");
check("the day key is the phone's local calendar day", () => {
  assert.equal(localDayKey(new Date(2026, 9, 8, 0, 0, 0).getTime()), "2026-10-08");
  assert.equal(localDayKey(new Date(2026, 9, 8, 23, 59, 59).getTime()), "2026-10-08");
  assert.equal(localDayKey(new Date(2026, 9, 9, 0, 0, 0).getTime()), "2026-10-09");
  assert.equal(localDayKey(new Date(2026, 0, 5, 9, 0, 0).getTime()), "2026-01-05");
});
check("yesterday's spent counter starts over today", () => {
  const { quota } = spend(3);
  const tomorrow = localDayKey(new Date(2026, 9, 9, 0, 0, 1).getTime());
  assert.deepEqual(quotaForDay(quota, tomorrow), emptyQuota(tomorrow));
});
check("same day: the stored counter is kept", () => {
  const { quota } = spend(2);
  assert.deepEqual(quotaForDay(JSON.parse(JSON.stringify(quota)), TODAY), quota);
});
check("junk in storage reads as a fresh day, never as a crash", () => {
  for (const junk of [null, undefined, "x", 5, [], { day: TODAY, used: "lots" }, { day: TODAY, used: -4, keys: [1, "a.ru"] }]) {
    const q = quotaForDay(junk, TODAY);
    assert.equal(q.day, TODAY);
    assert.ok(q.used >= 0);
    assert.ok(q.keys.every((k) => typeof k === "string"));
  }
});

console.log("first days unlimited");
check("day 0 and day 6 are in the trial, day 7 is not", () => {
  assert.equal(inTrial(NOON, NOON, 7), true);
  assert.equal(inTrial(NOON - 6 * DAY - 1, NOON, 7), true);
  assert.equal(inTrial(NOON - 7 * DAY, NOON, 7), false);
});
check("a clock set before the install is not the trial", () => {
  assert.equal(inTrial(NOON + DAY, NOON, 7), false);
});
check("trial 0 days: none", () => {
  assert.equal(inTrial(NOON, NOON, 0), false);
});
check("in the trial every check is detailed and nothing is counted", () => {
  const { gates, quota } = spend(6, ON, NOON - 2 * DAY);
  assert.deepEqual(gates, Array(6).fill(true));
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
  const { quota } = spend(3);
  const access = accessFor({ config: ON, paid: false, installedAt: LONG_AGO, quota, nowMs: NOON });
  const first = gateCheck(access, quota, "a.ru");
  assert.equal(first.autoPaywall, true);
  const shown = withPaywallShown(first.quota);
  assert.equal(gateCheck(access, shown, "b.ru").autoPaywall, false);
});
check("not marked unless the screen opened it (never over a dangerous verdict)", () => {
  const { quota } = spend(3);
  const access = accessFor({ config: ON, paid: false, installedAt: LONG_AGO, quota, nowMs: NOON });
  const stopped = gateCheck(access, quota, "a.ru");
  assert.equal(gateCheck(access, stopped.quota, "b.ru").autoPaywall, true);
});
check("a new day may open it again", () => {
  const shown = withPaywallShown(spend(3).quota);
  assert.equal(quotaForDay(shown, "2026-10-09").paywallShown, false);
});
check("an allowed check never opens it", () => {
  assert.equal(gateCheck(accessFor({ config: ON, paid: false, installedAt: LONG_AGO, quota: emptyQuota(TODAY), nowMs: NOON }), emptyQuota(TODAY), "a.ru").autoPaywall, false);
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
    for (const distribution of ["site", "play", "rustore"]) {
      assert.equal(purchaseAction({ signedIn, market: "ru", distribution }), "soon");
    }
  }
});
check("signed out: sign in first, on every build", () => {
  for (const distribution of ["site", "play", "rustore"]) {
    assert.equal(purchaseAction({ signedIn: false, market: "world", distribution }), "sign_in");
  }
});
check("signed in: site APK → web checkout; store builds → store billing, never the web", () => {
  assert.equal(purchaseAction({ signedIn: true, market: "world", distribution: "site" }), "web_checkout");
  assert.equal(purchaseAction({ signedIn: true, market: "world", distribution: "play" }), "store");
  assert.equal(purchaseAction({ signedIn: true, market: "world", distribution: "rustore" }), "store");
  assert.equal(webCheckoutAllowed("play"), false);
  assert.equal(webCheckoutAllowed("rustore"), false);
  assert.equal(webCheckoutAllowed("site"), true);
});
check("the web checkout is the site's yearly plan, over https", () => {
  const url = new URL(WEB_CHECKOUT_URL);
  assert.equal(url.protocol, "https:");
  assert.equal(url.hostname, "cleanway.ai");
  assert.equal(url.searchParams.get("interval"), "yearly");
});
check("market: the region decides, else the language", () => {
  assert.equal(marketFor("en", "RU"), "ru");
  assert.equal(marketFor("ru", "AE"), "world");
  assert.equal(marketFor("ru-RU", null), "ru");
  assert.equal(marketFor("de", undefined), "world");
});
check("prices: RU 99 ₽ a month; site sells $9.99 a year; stores $0.99 a month", () => {
  assert.deepEqual(priceDisplay("ru", "site"), { price: "99 ₽", period: "month", alt: null });
  assert.deepEqual(priceDisplay("world", "site"), { price: "$9.99", period: "year", alt: { price: "$0.99", period: "month" } });
  assert.deepEqual(priceDisplay("world", "play"), { price: "$0.99", period: "month", alt: { price: "$9.99", period: "year" } });
});

if (failures) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall freemium checks passed");

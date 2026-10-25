#!/usr/bin/env node
/**
 * Table test for paying in the app through Google Play (RevenueCat):
 * src/utils/store-billing.ts, the store-policy switches in
 * src/utils/freemium.ts, and the native-linking gate in
 * plugins/store-billing-linking.js.
 *
 * Run: node --experimental-strip-types mobile/scripts/test-store-billing.mjs
 *
 * No jest in mobile/ (see test-host-parser.mjs); the modules import nothing
 * from react-native, so node's TS stripper loads them as-is.
 *
 * Pinned (docs/runbooks/revenuecat.md, docs/ACCOUNTS_BILLING_PLAN.md §11):
 *   • only the Google Play build on Android with a public goog_ key pays in
 *     the app; a secret sk_ key or an App Store key never configures it;
 *   • the iPhone app is always the App Store build and pays with a public
 *     appl_ key, in App Store words; it opens only Apple's subscriptions page
 *     and never the web checkout (App Review 3.1.1);
 *   • the plan sold is cleanway.devices monthly / yearly from the `default`
 *     offering, at the store's own price — never the "+1 device" add-on;
 *   • store errors map to a few kinds, each with a sentence in every locale;
 *     a cancel says nothing; a slow card is "pending", not a failure;
 *   • RevenueCat knows the person by the Supabase account id (JWT `sub`);
 *     signed out, the iPhone app buys and restores under RevenueCat's
 *     anonymous id (App Review 5.1.1) and the phone honours its own App
 *     Store plan; Google Play still asks to sign in first;
 *   • a store build opens only a store's subscriptions page, never our site;
 *   • deleting the account sends a Google Play subscriber to cancel in Play;
 *   • the site and Play APKs never promise automatic SMS checks; only the
 *     site APK offers a self-update; only the Play build links the SDK, and
 *     the SDK's require stays behind a literal env comparison so other
 *     release bundles drop it.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  APP_STORE_SUBSCRIPTIONS_URL,
  OFFERING_ID,
  PLAN_PRODUCT_ID,
  STORE_PLAN_FRESH_MS,
  STORE_PLAN_GRACE_MS,
  accountIdFromAccessToken,
  billingStoreFor,
  configureAtStart,
  manageSubscriptionUrl,
  manageUrlFor,
  paidPlansOffered,
  parseStorePlanCache,
  payingAs,
  planOptions,
  playSubscriptionsUrl,
  readStoreBillingConfig,
  restoreSuggested,
  storeCopyKeys,
  storeErrorKind,
  storeErrorNoteKey,
  storeHasPlan,
  storePlanActive,
  storePlanFromInfo,
  storePlanStale,
  storeSubscriptionToCancel,
} from "../src/utils/store-billing.ts";
import {
  ENTITLEMENT_FRESH_MS,
  ENTITLEMENT_GRACE_MS,
  distributionFor,
  purchaseAction,
  revenueCatStore,
  selfUpdateAllowed,
  smsBenefitShown,
  storePurchaseWithoutAccount,
  webCheckoutAllowed,
} from "../src/utils/freemium.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const MOBILE = join(HERE, "..");
const require = createRequire(import.meta.url);

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

// A made-up key of the public Play shape, assembled so secret scanners do not
// mistake a test fixture for a committed credential.
const KEY = ["goog", "x".repeat(8) + "TEST" + "0".repeat(8)].join("_");

// ── Gating by distribution ──────────────────────────────────────────

check("Play build on Android with a public Play key: on", () => {
  assert.deepEqual(
    readStoreBillingConfig({ EXPO_PUBLIC_DISTRIBUTION: "play", EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: KEY }, "android"),
    { kind: "on", apiKey: KEY, store: "google_play" },
  );
  assert.equal(
    readStoreBillingConfig({ EXPO_PUBLIC_DISTRIBUTION: " Play ", EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: ` ${KEY} ` }, "android").kind,
    "on",
  );
});

check("site APK, RuStore, unset distribution, 'appstore' on Android: off (not_play), whatever the key", () => {
  for (const dist of ["site", "rustore", "", undefined, "google", "appstore"]) {
    assert.deepEqual(
      readStoreBillingConfig({ EXPO_PUBLIC_DISTRIBUTION: dist, EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: KEY }, "android"),
      { kind: "off", why: "not_play" },
      String(dist),
    );
  }
});

// A made-up key of the public App Store shape (assembled, as KEY above).
const IOS_KEY = ["appl", "y".repeat(8) + "TEST" + "1".repeat(8)].join("_");
// A secret-key shape the app must refuse; built at runtime so secret scanners
// do not take a test literal for a leaked key.
const SECRET_SHAPED = ["sk", "live", "abc123"].join("_");

check("iPhone app with a public App Store key: on, through the App Store — whatever EXPO_PUBLIC_DISTRIBUTION says", () => {
  // An EAS profile's EXPO_PUBLIC_DISTRIBUTION=play reaches the iOS build of the
  // same profile too; it must not switch the iPhone app off.
  for (const dist of ["appstore", "play", "site", "", undefined]) {
    assert.deepEqual(
      readStoreBillingConfig({ EXPO_PUBLIC_DISTRIBUTION: dist, EXPO_PUBLIC_REVENUECAT_IOS_KEY: IOS_KEY }, "ios"),
      { kind: "on", apiKey: IOS_KEY, store: "app_store" },
      String(dist),
    );
  }
  assert.equal(
    readStoreBillingConfig({ EXPO_PUBLIC_REVENUECAT_IOS_KEY: ` ${IOS_KEY} ` }, "ios").kind,
    "on",
  );
});

check("iPhone app without its key: off (no_key) — the Play key is never used on iOS", () => {
  for (const key of [undefined, "", "  "]) {
    assert.deepEqual(
      readStoreBillingConfig({ EXPO_PUBLIC_REVENUECAT_IOS_KEY: key, EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: KEY }, "ios"),
      { kind: "off", why: "no_key" },
    );
  }
});

check("iPhone app: a secret key, a Play key or junk never configures the SDK (bad_key)", () => {
  for (const key of [SECRET_SHAPED, KEY, "appl_", "appl_abc def", "appl_abc;drop", "rcb_abc"]) {
    assert.deepEqual(
      readStoreBillingConfig({ EXPO_PUBLIC_REVENUECAT_IOS_KEY: key }, "ios"),
      { kind: "off", why: "bad_key" },
      key,
    );
  }
  // …and the App Store key never turns on the Android build.
  assert.deepEqual(
    readStoreBillingConfig({ EXPO_PUBLIC_DISTRIBUTION: "play", EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: IOS_KEY }, "android"),
    { kind: "off", why: "bad_key" },
  );
});

check("paid plans at all: an iPhone build that cannot sell in the app shows none (App Review: no IAP)", () => {
  // Without its appl_ key (or with a wrong one) the iPhone app was submitted
  // as having no in-app purchases: no plan row, no paywall, no prices.
  for (const key of [undefined, "", "  ", SECRET_SHAPED, KEY]) {
    const billing = readStoreBillingConfig({ EXPO_PUBLIC_REVENUECAT_IOS_KEY: key }, "ios");
    assert.equal(paidPlansOffered(billing, "ios"), false, String(key));
  }
  // With the key: as before.
  assert.equal(paidPlansOffered(readStoreBillingConfig({ EXPO_PUBLIC_REVENUECAT_IOS_KEY: IOS_KEY }, "ios"), "ios"), true);
});

check("paid plans at all: every Android build unchanged, with or without in-app billing", () => {
  for (const env of [
    { EXPO_PUBLIC_DISTRIBUTION: "play", EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: KEY },
    { EXPO_PUBLIC_DISTRIBUTION: "play" }, // the Play build keeps its "coming soon" paywall
    { EXPO_PUBLIC_DISTRIBUTION: "play", EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: SECRET_SHAPED },
    { EXPO_PUBLIC_DISTRIBUTION: "rustore" },
    { EXPO_PUBLIC_DISTRIBUTION: "site" },
    {},
  ]) {
    assert.equal(paidPlansOffered(readStoreBillingConfig(env, "android"), "android"), true, JSON.stringify(env));
    assert.equal(paidPlansOffered(readStoreBillingConfig(env, "web"), "web"), true, JSON.stringify(env));
  }
});

check("the store this build pays through, by distribution", () => {
  assert.equal(billingStoreFor("appstore"), "app_store");
  assert.equal(billingStoreFor("play"), "google_play");
  for (const d of ["site", "rustore", ""]) assert.equal(billingStoreFor(d), null);
});

check("Play build without a key: off (no_key) — a clear state, not a crash", () => {
  for (const key of [undefined, "", "   "]) {
    assert.deepEqual(
      readStoreBillingConfig({ EXPO_PUBLIC_DISTRIBUTION: "play", EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: key }, "android"),
      { kind: "off", why: "no_key" },
    );
  }
});

check("a secret key, an App Store key or junk never configures the SDK (bad_key)", () => {
  for (const key of [SECRET_SHAPED, "appl_abc123", "goog_", "goog_abc def", "rcb_abc", "goog_abc;drop"]) {
    assert.deepEqual(
      readStoreBillingConfig({ EXPO_PUBLIC_DISTRIBUTION: "play", EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: key }, "android"),
      { kind: "off", why: "bad_key" },
      key,
    );
  }
});

check("the SDK starts with the app only for a signed-in person who started a purchase here", () => {
  const on = { kind: "on", apiKey: KEY };
  assert.equal(configureAtStart({ billing: on, signedIn: true, purchaseStarted: true }), true);
  assert.equal(configureAtStart({ billing: on, signedIn: true, purchaseStarted: false }), false);
  assert.equal(configureAtStart({ billing: on, signedIn: false, purchaseStarted: true }), false);
  assert.equal(configureAtStart({ billing: on, signedIn: false, purchaseStarted: true, withoutAccount: false }), false);
  assert.equal(configureAtStart({ billing: { kind: "off", why: "no_key" }, signedIn: true, purchaseStarted: true }), false);
});

check("the iPhone app also starts it for a phone that bought or restored without an account", () => {
  // A pending (Ask to Buy) purchase must finish, and the phone must learn of
  // a renewal or an end — it has no account the server could answer for.
  const on = { kind: "on", apiKey: IOS_KEY, store: "app_store" };
  assert.equal(configureAtStart({ billing: on, signedIn: false, purchaseStarted: true, withoutAccount: true }), true);
  assert.equal(configureAtStart({ billing: on, signedIn: false, purchaseStarted: false, withoutAccount: true }), false);
  assert.equal(
    configureAtStart({ billing: { kind: "off", why: "no_key" }, signedIn: false, purchaseStarted: true, withoutAccount: true }),
    false,
  );
});

check("store policy: only the site APK links to the web checkout or offers a self-update", () => {
  assert.equal(webCheckoutAllowed("site"), true);
  assert.equal(webCheckoutAllowed("play"), false);
  assert.equal(webCheckoutAllowed("rustore"), false);
  assert.equal(selfUpdateAllowed("site"), true);
  assert.equal(selfUpdateAllowed("play"), false);
  assert.equal(selfUpdateAllowed("rustore"), false);
  assert.equal(purchaseAction({ signedIn: true, market: "world", distribution: "play" }), "store");
  assert.equal(purchaseAction({ signedIn: false, market: "world", distribution: "play" }), "sign_in");
});

check("store policy: the iPhone app never links to the web checkout, never self-updates, pays in the App Store", () => {
  assert.equal(webCheckoutAllowed("appstore"), false);
  assert.equal(selfUpdateAllowed("appstore"), false);
  assert.equal(smsBenefitShown("appstore"), false);
  assert.equal(revenueCatStore("appstore"), true);
  assert.equal(revenueCatStore("play"), true);
  assert.equal(revenueCatStore("site"), false);
  assert.equal(revenueCatStore("rustore"), false);
  assert.equal(purchaseAction({ signedIn: true, market: "world", distribution: "appstore" }), "store");
  // No account needed to buy on the iPhone (App Review 5.1.1; STORE_DECISIONS §3, option Б).
  assert.equal(purchaseAction({ signedIn: false, market: "world", distribution: "appstore" }), "store");
  assert.equal(storePurchaseWithoutAccount("appstore"), true);
  assert.equal(storePurchaseWithoutAccount("play"), false);
  // An iOS build is the App Store build whatever the env says (no "site" on iOS).
  for (const raw of ["site", "play", "rustore", "", undefined]) {
    assert.equal(distributionFor(raw, "ios"), "appstore", String(raw));
  }
});

check("'automatic SMS check' is promised by no build until one reads SMS", () => {
  // Automatic SMS checking lives only on the unmerged feat/sms-auto-rustore
  // branch, and check-android-permissions.mjs forbids every SMS permission.
  for (const dist of ["rustore", "site", "play", "appstore"]) {
    assert.equal(smsBenefitShown(dist), false, dist);
  }
});

check("native SDK (Play Billing + BILLING permission) is linked only into the Play build", () => {
  const { storeBillingLinked } = require("../plugins/store-billing-linking.js");
  assert.equal(storeBillingLinked({ EXPO_PUBLIC_DISTRIBUTION: "play" }), true);
  assert.equal(storeBillingLinked({ EXPO_PUBLIC_DISTRIBUTION: " PLAY " }), true);
  for (const dist of ["site", "rustore", "", undefined]) {
    assert.equal(storeBillingLinked({ EXPO_PUBLIC_DISTRIBUTION: dist }), false, String(dist));
  }
});

check("react-native.config.js turns the Android link off outside the Play build", () => {
  const configPath = require.resolve("../react-native.config.js");
  const load = (dist) => {
    const before = process.env.EXPO_PUBLIC_DISTRIBUTION;
    process.env.EXPO_PUBLIC_DISTRIBUTION = dist;
    try {
      delete require.cache[configPath];
      return require(configPath);
    } finally {
      if (before === undefined) delete process.env.EXPO_PUBLIC_DISTRIBUTION;
      else process.env.EXPO_PUBLIC_DISTRIBUTION = before;
      delete require.cache[configPath];
    }
  };
  assert.deepEqual(load("site").dependencies["react-native-purchases"], { platforms: { android: null } });
  assert.deepEqual(load("rustore").dependencies["react-native-purchases"], { platforms: { android: null } });
  assert.equal(load("play").dependencies["react-native-purchases"], undefined);
});

check("the SDK's require sits behind a literal EXPO_PUBLIC_DISTRIBUTION === \"play\" || Platform.OS === \"ios\" (dropped from other Android bundles)", () => {
  const src = readFileSync(join(MOBILE, "src/services/store-billing.ts"), "utf8");
  const requires = [...src.matchAll(/require\("react-native-purchases"\)/g)];
  assert.equal(requires.length, 1, "exactly one require of the SDK");
  const guard = src.indexOf('if (process.env.EXPO_PUBLIC_DISTRIBUTION === "play" || Platform.OS === "ios") {');
  assert.ok(guard >= 0, "literal guard present");
  assert.ok(guard < requires[0].index, "guard comes before the require");
  // No static import of the SDK's runtime anywhere in the app (types only).
  for (const file of ["src/services/store-billing.ts", "src/components/paywall/StorePlans.tsx", "app/paywall.tsx", "app/account.tsx"]) {
    const text = readFileSync(join(MOBILE, file), "utf8");
    assert.ok(!/^import (?!type )[^;]*from "react-native-purchases"/m.test(text), `${file}: runtime import of the SDK`);
  }
});

check("services/store-billing.ts: buying and restoring go through payingAs; only the iPhone app with its key goes anonymous", () => {
  const src = readFileSync(join(MOBILE, "src/services/store-billing.ts"), "utf8");
  assert.ok(
    src.includes('STORE_BILLING.kind === "on" && storePurchaseWithoutAccount(FREEMIUM.distribution)'),
    "STORE_PURCHASE_WITHOUT_ACCOUNT needs App Store billing on and the iPhone distribution",
  );
  assert.equal([...src.matchAll(/payingAs\(payer, STORE_PURCHASE_WITHOUT_ACCOUNT\)/g)].length, 2, "purchase + restore");
  // A signed-in session that could not be refreshed (offline) never buys anonymously.
  assert.equal([...src.matchAll(/if \(payer === undefined\)/g)].length, 2, "purchase + restore");
  // The signed-out path logs the SDK out of an account it kept before buying.
  assert.ok(src.includes("ready(null, true)"), "anonymous purchase / restore asks ready() for an anonymous SDK");
  // The phone's own plan is kept only by the iPhone app (services/freemium.ts DEVICE_PLAN too).
  const freemium = readFileSync(join(MOBILE, "src/services/freemium.ts"), "utf8");
  assert.ok(freemium.includes("PAID_PLANS_OFFERED && storePurchaseWithoutAccount(FREEMIUM.distribution)"));
});

// ── Who is paying ───────────────────────────────────────────────────

function jwt(payload) {
  const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${enc({ alg: "HS256", typ: "JWT" })}.${enc(payload)}.sig`;
}
const UID = "3f1c2a9e-5b7d-4e21-9a0b-1c2d3e4f5a6b";

check("the Supabase account id is the access token's sub", () => {
  assert.equal(accountIdFromAccessToken(jwt({ sub: UID, email: "anna@example.com", role: "authenticated" })), UID);
  // Non-ASCII elsewhere in the claims does not get in the way.
  assert.equal(accountIdFromAccessToken(jwt({ sub: UID, email: "аня@пример.рф" })), UID);
});

check("no account id from a token without a UUID sub, or from junk", () => {
  assert.equal(accountIdFromAccessToken(jwt({ sub: "$RCAnonymousID:abc" })), null);
  assert.equal(accountIdFromAccessToken(jwt({ email: "x@y.z" })), null);
  assert.equal(accountIdFromAccessToken(jwt({ sub: 42 })), null);
  for (const junk of [null, undefined, "", "abc", "a.b", "a.!!!.c", "a.e30.c.d"]) {
    assert.equal(accountIdFromAccessToken(junk), null, String(junk));
  }
});

check("who a purchase or a restore goes under: the account; signed out, anonymous on the iPhone only", () => {
  assert.deepEqual(payingAs(UID, false), { kind: "account", id: UID });
  assert.deepEqual(payingAs(UID, true), { kind: "account", id: UID });
  // Google Play: a plan belongs to an account — sign in first, as before.
  assert.deepEqual(payingAs(null, false), { kind: "sign_in_first" });
  // The App Store: RevenueCat's anonymous id; signing in later aliases it.
  assert.deepEqual(payingAs(null, true), { kind: "anonymous" });
});

// ── This phone's own plan (the iPhone app) ──────────────────────────

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
const NOW = Date.UTC(2026, 9, 25, 12, 0, 0);

function info(active) {
  return { entitlements: { active } };
}

check("this phone's plan from RevenueCat: the `unlimited` entitlement and its end date", () => {
  const ends = new Date(NOW + 30 * DAY).toISOString();
  assert.deepEqual(storePlanFromInfo(info({ unlimited: { isActive: true, expirationDate: ends } }), NOW), {
    paid: true, expiresAt: NOW + 30 * DAY, checkedAt: NOW,
  });
  // No end date (or an unreadable one): paid, the end unknown.
  assert.deepEqual(storePlanFromInfo(info({ unlimited: { isActive: true, expirationDate: null } }), NOW), {
    paid: true, expiresAt: null, checkedAt: NOW,
  });
  assert.equal(storePlanFromInfo(info({ unlimited: { isActive: true, expirationDate: "soon" } }), NOW).expiresAt, null);
  // An end date already past is not paid, whatever a cached isActive says
  // (in a billing grace period RevenueCat moves the end date to the grace end).
  const past = new Date(NOW - HOUR).toISOString();
  assert.deepEqual(storePlanFromInfo(info({ unlimited: { isActive: true, expirationDate: past } }), NOW), {
    paid: false, expiresAt: null, checkedAt: NOW,
  });
  // Nothing, the add-on alone, an inactive one, junk: not paid.
  for (const x of [info({}), info({ extra_device: { isActive: true } }), info({ unlimited: { isActive: false } }), null, undefined, {}]) {
    assert.deepEqual(storePlanFromInfo(x, NOW), { paid: false, expiresAt: null, checkedAt: NOW }, JSON.stringify(x));
  }
});

check("this phone's plan counts until the store's end date", () => {
  const plan = { paid: true, expiresAt: NOW + 30 * DAY, checkedAt: NOW };
  assert.equal(storePlanActive(plan, NOW), true);
  assert.equal(storePlanActive(plan, NOW + 29 * DAY), true);
  assert.equal(storePlanActive({ ...plan, paid: false }, NOW), false);
  assert.equal(storePlanActive(null, NOW), false);
});

check("past the end date (a renewal not seen yet) or with no end date: STORE_PLAN_GRACE_MS after the last answer", () => {
  // Same 7 days as a paid account answer offline (freemium.ts).
  assert.equal(STORE_PLAN_GRACE_MS, ENTITLEMENT_GRACE_MS);
  const ended = { paid: true, expiresAt: NOW + DAY, checkedAt: NOW };
  assert.equal(storePlanActive(ended, NOW + 2 * DAY), true);
  assert.equal(storePlanActive(ended, NOW + 7 * DAY), false);
  const open = { paid: true, expiresAt: null, checkedAt: NOW };
  assert.equal(storePlanActive(open, NOW + 6 * DAY), true);
  assert.equal(storePlanActive(open, NOW + 7 * DAY), false);
  // An answer from the future (clock moved back) earns no grace.
  assert.equal(storePlanActive({ paid: true, expiresAt: null, checkedAt: NOW + DAY }, NOW), false);
});

check("ask RevenueCat again after STORE_PLAN_FRESH_MS, or once the end date has passed", () => {
  assert.equal(STORE_PLAN_FRESH_MS, ENTITLEMENT_FRESH_MS);
  const plan = { paid: true, expiresAt: NOW + 30 * DAY, checkedAt: NOW };
  assert.equal(storePlanStale(plan, NOW + HOUR), false);
  assert.equal(storePlanStale(plan, NOW + 6 * HOUR), true);
  assert.equal(storePlanStale({ ...plan, expiresAt: NOW + 2 * HOUR }, NOW + 3 * HOUR), true);
  // Already asked after the end: wait the usual 6 hours.
  assert.equal(storePlanStale({ paid: false, expiresAt: null, checkedAt: NOW }, NOW + HOUR), false);
  assert.equal(storePlanStale(null, NOW), true);
  assert.equal(storePlanStale({ ...plan, checkedAt: NOW + HOUR }, NOW), true); // from the future
});

check("this phone's plan read back from storage; junk reads as none", () => {
  const plan = { paid: true, expiresAt: NOW, checkedAt: NOW };
  assert.deepEqual(parseStorePlanCache(plan), plan);
  assert.deepEqual(parseStorePlanCache({ paid: false, expiresAt: null, checkedAt: NOW }), { paid: false, expiresAt: null, checkedAt: NOW });
  for (const junk of [null, "x", 1, {}, { paid: "yes", expiresAt: null, checkedAt: NOW }, { paid: true, expiresAt: "x", checkedAt: NOW }, { paid: true, expiresAt: null }]) {
    assert.equal(parseStorePlanCache(junk), null, JSON.stringify(junk));
  }
});

check("signed in, the plan bought here did not follow the account: suggest Restore", () => {
  // RevenueCat merges the anonymous buyer into the account on logIn — unless
  // the account already has an anonymous alias of its own. Then only
  // "Restore purchases" moves it (docs/runbooks/revenuecat.md §9).
  const before = { paid: true, expiresAt: NOW + 30 * DAY, checkedAt: NOW - HOUR };
  const after = { paid: false, expiresAt: null, checkedAt: NOW };
  assert.equal(restoreSuggested(before, after, NOW), true);
  assert.equal(restoreSuggested(before, { ...after, paid: true, expiresAt: NOW + 30 * DAY }, NOW), false); // merged
  assert.equal(restoreSuggested(null, after, NOW), false);
  assert.equal(restoreSuggested({ ...before, paid: false }, after, NOW), false);
  assert.equal(restoreSuggested({ ...before, expiresAt: NOW - 8 * DAY, checkedAt: NOW - 8 * DAY }, after, NOW), false); // long over
});

check("'nothing to restore' names the Apple ID in the iPhone app, the account on Android", () => {
  assert.equal(storeCopyKeys("app_store").restoreNone, "mobile.paywall.note_restore_none_appstore");
  assert.equal(storeCopyKeys("google_play").restoreNone, "mobile.paywall.note_restore_none");
  const en = JSON.parse(readFileSync(join(MOBILE, "i18n", "en.json"), "utf8"));
  assert.match(en["mobile.paywall.note_restore_none_appstore"], /Apple ID/);
});

check("the after-purchase sign-in offer and the Restore hint exist in all 10 locales", () => {
  for (const loc of ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"]) {
    const strings = JSON.parse(readFileSync(join(MOBILE, "i18n", `${loc}.json`), "utf8"));
    for (const key of ["mobile.paywall.sync_offer", "mobile.paywall.note_restore_here_appstore"]) {
      assert.ok(typeof strings[key] === "string" && strings[key].length > 0, `${loc}: ${key}`);
    }
    // The offer is optional and says what signing in adds, with the device count.
    assert.match(strings["mobile.paywall.sync_offer"], /\{\{n\}\}/, `${loc}: sync_offer {{n}}`);
  }
});

// ── What is on sale ─────────────────────────────────────────────────

function pkg(identifier, packageType, productId, priceString, price, currencyCode = "USD") {
  return { identifier, packageType, product: { identifier: productId, priceString, price, currencyCode } };
}
const MONTH = pkg("$rc_monthly", "MONTHLY", "cleanway.devices:monthly", "$0.99", 0.99);
const YEAR = pkg("$rc_annual", "ANNUAL", "cleanway.devices:yearly", "$9.99", 9.99);
const EXTRA = pkg("$rc_monthly", "MONTHLY", "cleanway.extra_device:monthly", "$0.49", 0.49);
function offering(id, packages, shortcuts = {}) {
  return { identifier: id, availablePackages: packages, monthly: null, annual: null, ...shortcuts };
}

check("offering `default`: monthly first, then yearly with its saving, at the store's own prices", () => {
  const opts = planOptions({
    current: null,
    all: { [OFFERING_ID]: offering(OFFERING_ID, [YEAR, MONTH], { monthly: MONTH, annual: YEAR }) },
  });
  assert.deepEqual(opts.map((o) => [o.period, o.priceString, o.savePercent]), [
    ["month", "$0.99", null],
    ["year", "$9.99", 15],
  ]);
  assert.equal(opts[0].pkg, MONTH);
  assert.equal(opts[1].pkg, YEAR);
});

check("localised prices pass through untouched; the saving needs one currency", () => {
  const m = pkg("$rc_monthly", "MONTHLY", "cleanway.devices:monthly", "89,00 ₽", 89, "RUB");
  const y = pkg("$rc_annual", "ANNUAL", "cleanway.devices:yearly", "₹799.00", 799, "INR");
  const opts = planOptions({ current: null, all: { default: offering("default", [m, y]) } });
  assert.deepEqual(opts.map((o) => o.priceString), ["89,00 ₽", "₹799.00"]);
  assert.equal(opts[1].savePercent, null);
});

check("a tiny saving is not advertised (< 5%)", () => {
  const y = pkg("$rc_annual", "ANNUAL", "cleanway.devices:yearly", "$11.50", 11.5);
  const opts = planOptions({ current: null, all: { default: offering("default", [MONTH, y]) } });
  assert.equal(opts[1].savePercent, null);
});

check("packages are found by type, then by base plan id, when the shortcuts are empty", () => {
  const custom = pkg("plan_m", "CUSTOM", "cleanway.devices:monthly", "$0.99", 0.99);
  const opts = planOptions({ current: null, all: { default: offering("default", [custom, YEAR]) } });
  assert.deepEqual(opts.map((o) => o.period), ["month", "year"]);
  assert.equal(opts[0].pkg, custom);
});

check("the '+1 device' add-on is never sold as the plan, even if attached as $rc_monthly", () => {
  const opts = planOptions({ current: null, all: { default: offering("default", [EXTRA, YEAR], { monthly: EXTRA }) } });
  assert.deepEqual(opts.map((o) => o.period), ["year"]);
  assert.equal(opts[0].savePercent, null);
  assert.ok(opts.every((o) => o.pkg.product.identifier.startsWith(PLAN_PRODUCT_ID)));
});

check("a package without a price is not shown", () => {
  const noPrice = pkg("$rc_monthly", "MONTHLY", "cleanway.devices:monthly", " ", 0);
  const opts = planOptions({ current: null, all: { default: offering("default", [noPrice, YEAR]) } });
  assert.deepEqual(opts.map((o) => o.period), ["year"]);
});

check("no `default` offering: the current one; nothing at all: an empty list", () => {
  const cur = offering("experiment", [MONTH]);
  assert.deepEqual(planOptions({ current: cur, all: { experiment: cur } }).map((o) => o.period), ["month"]);
  assert.deepEqual(planOptions({ current: null, all: {} }), []);
  assert.deepEqual(planOptions(null), []);
  assert.deepEqual(planOptions({ current: null, all: { default: offering("default", []) } }), []);
});

check("an App Store style product id is the plan too (cleanway.devices.yearly)", () => {
  const y = pkg("$rc_annual", "ANNUAL", "cleanway.devices.yearly", "$9.99", 9.99);
  assert.deepEqual(planOptions({ current: null, all: { default: offering("default", [y]) } }).map((o) => o.period), ["year"]);
});

check("Google Play has the plan: the `unlimited` entitlement is active", () => {
  assert.equal(storeHasPlan({ entitlements: { active: { unlimited: { isActive: true } } } }), true);
  assert.equal(storeHasPlan({ entitlements: { active: { extra_device: { isActive: true } } } }), false);
  assert.equal(storeHasPlan({ entitlements: { active: {} } }), false);
  assert.equal(storeHasPlan(null), false);
});

// ── When it goes wrong ──────────────────────────────────────────────

check("store errors map to what the person is told", () => {
  const cases = [
    [{ code: "1", userCancelled: true }, "cancelled"],
    [{ code: "0", userCancelled: true }, "cancelled"],
    [{ code: "1" }, "cancelled"],
    [{ code: "20" }, "pending"],
    [{ code: "6" }, "already_owned"],
    [{ code: "7" }, "already_owned"],
    [{ code: "13" }, "already_owned"],
    [{ code: "10" }, "network"],
    [{ code: "35" }, "network"],
    [{ code: 10 }, "network"],
    [{ code: "3" }, "not_allowed"],
    [{ code: "5" }, "unavailable"],
    [{ code: "23" }, "unavailable"],
    [{ code: "2" }, "store_problem"],
    [{ code: "15" }, "busy"],
    [{ code: "16" }, "unknown"],
    [{ code: "999" }, "unknown"],
    [new Error("boom"), "unknown"],
    [null, "unknown"],
    ["1", "unknown"],
  ];
  for (const [err, kind] of cases) assert.equal(storeErrorKind(err), kind, JSON.stringify(err));
});

check("every error kind has its sentence in all 10 locales, for both stores; a cancel says nothing", () => {
  assert.equal(storeErrorNoteKey("cancelled"), null);
  assert.equal(storeErrorNoteKey("cancelled", "app_store"), null);
  const kinds = ["pending", "already_owned", "network", "not_allowed", "unavailable", "store_problem", "busy", "unknown"];
  for (const loc of ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"]) {
    const strings = JSON.parse(readFileSync(join(MOBILE, "i18n", `${loc}.json`), "utf8"));
    for (const store of ["google_play", "app_store"]) {
      for (const kind of kinds) {
        const key = storeErrorNoteKey(kind, store);
        assert.ok(key && typeof strings[key] === "string" && strings[key].length > 0, `${loc}: ${store} ${kind} → ${key}`);
      }
      for (const key of Object.values(storeCopyKeys(store))) {
        assert.ok(typeof strings[key] === "string" && strings[key].length > 0, `${loc}: ${store} copy ${key}`);
      }
    }
  }
});

check("the App Store sentences never mention Google; the Google Play ones keep theirs", () => {
  const en = JSON.parse(readFileSync(join(MOBILE, "i18n", "en.json"), "utf8"));
  const kinds = ["pending", "already_owned", "network", "not_allowed", "store_problem"];
  for (const kind of kinds) {
    assert.ok(!/Google/.test(en[storeErrorNoteKey(kind, "app_store")]), `app_store ${kind}`);
  }
  for (const key of Object.values(storeCopyKeys("app_store"))) assert.ok(!/Google/.test(en[key]), key);
  assert.equal(storeErrorNoteKey("network"), "mobile.paywall.err_network");
  assert.equal(storeErrorNoteKey("network", "google_play"), "mobile.paywall.err_network");
  // The App Store fine print says who bills, that it renews, and where to cancel (3.1.2).
  assert.match(en["mobile.paywall.fine_store_appstore"], /Apple ID/);
  assert.match(en["mobile.paywall.fine_store_appstore"], /24 hours/);
  assert.match(en["mobile.paywall.fine_store_appstore"], /Subscriptions/);
});

// ── Managing and cancelling ─────────────────────────────────────────

const PLAY_URL = "https://play.google.com/store/account/subscriptions?sku=cleanway.devices&package=ai.cleanway.app";
const playEnt = { plan: "personal", status: "active", source: "google_play", manage_url: PLAY_URL };
const stripeEnt = { plan: "personal", status: "active", source: "stripe", manage_url: "https://cleanway.ai/account" };

check("Manage subscription: the store's page in any build; our site only in the site APK", () => {
  assert.equal(manageUrlFor(playEnt, "play"), PLAY_URL);
  assert.equal(manageUrlFor(playEnt, "site"), PLAY_URL);
  assert.equal(manageUrlFor(stripeEnt, "site"), "https://cleanway.ai/account");
  assert.equal(manageUrlFor(stripeEnt, "play"), null);
  assert.equal(manageUrlFor(stripeEnt, "rustore"), null);
});

check("Manage subscription: never for the free plan, never a non-https or look-alike URL", () => {
  assert.equal(manageUrlFor({ ...playEnt, plan: "free", status: "free" }, "play"), null);
  assert.equal(manageUrlFor({ ...playEnt, manage_url: null }, "play"), null);
  assert.equal(manageUrlFor({ ...playEnt, manage_url: "http://play.google.com/store" }, "play"), null);
  assert.equal(manageUrlFor({ ...playEnt, manage_url: "https://play.google.com.evil.tk/x" }, "play"), null);
  assert.equal(manageUrlFor({ ...playEnt, manage_url: "https://evil.tk@play.google.com/x" }, "play"), null);
  assert.equal(manageUrlFor({ ...playEnt, manage_url: "intent://x" }, "site"), null);
  assert.equal(manageUrlFor(null, "play"), null);
});

const APPLE_URL = "https://apps.apple.com/account/subscriptions";
const appleEnt = { plan: "personal", status: "active", source: "app_store", manage_url: APPLE_URL };

check("the iPhone app opens only Apple's subscriptions page — never Google Play, never our site", () => {
  assert.equal(manageUrlFor(appleEnt, "appstore"), APPLE_URL);
  assert.equal(manageUrlFor(playEnt, "appstore"), null);
  assert.equal(manageUrlFor(stripeEnt, "appstore"), null);
  assert.equal(manageUrlFor({ ...appleEnt, manage_url: "https://apps.apple.com.evil.tk/x" }, "appstore"), null);
});

check("Manage subscription falls back to the store's own page for a plan bought in this build's store", () => {
  const PKG = "ai.cleanway.app";
  assert.equal(APP_STORE_SUBSCRIPTIONS_URL, APPLE_URL);
  assert.equal(manageSubscriptionUrl({ ...appleEnt, manage_url: null }, "appstore", PKG), APPLE_URL);
  assert.equal(manageSubscriptionUrl(appleEnt, "appstore", PKG), APPLE_URL);
  assert.equal(manageSubscriptionUrl({ ...playEnt, manage_url: null }, "play", PKG), playSubscriptionsUrl(PKG));
  assert.equal(manageSubscriptionUrl(playEnt, "play", PKG), PLAY_URL);
  // Bought elsewhere: the iPhone app links nowhere (the account screen says where it was paid).
  assert.equal(manageSubscriptionUrl({ ...playEnt, manage_url: null }, "appstore", PKG), null);
  assert.equal(manageSubscriptionUrl(stripeEnt, "appstore", PKG), null);
  assert.equal(manageSubscriptionUrl({ ...appleEnt, plan: "free", status: "free", manage_url: null }, "appstore", PKG), null);
  assert.equal(manageSubscriptionUrl(null, "appstore", PKG), null);
});

check("Play's subscriptions page for this app, when the server sent none", () => {
  assert.equal(
    playSubscriptionsUrl("ai.cleanway.app"),
    "https://play.google.com/store/account/subscriptions?package=ai.cleanway.app",
  );
});

check("deleting the account: a paid store plan must be cancelled in the store first", () => {
  assert.equal(storeSubscriptionToCancel(playEnt), "google_play");
  assert.equal(storeSubscriptionToCancel({ ...playEnt, source: "app_store" }), "app_store");
  assert.equal(storeSubscriptionToCancel({ ...playEnt, status: "past_due" }), "google_play");
  assert.equal(storeSubscriptionToCancel(stripeEnt), null); // the server cancels Stripe itself
  assert.equal(storeSubscriptionToCancel({ ...playEnt, plan: "free", status: "free" }), null);
  assert.equal(storeSubscriptionToCancel({ plan: "personal", status: "active", source: "promo" }), null);
  assert.equal(storeSubscriptionToCancel(null), null);
});

if (failures > 0) {
  console.log(`\n${failures} failing`);
  process.exit(1);
}
console.log("\nstore billing: all passed");

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
 *   • the plan sold is cleanway.devices monthly / yearly from the `default`
 *     offering, at the store's own price — never the "+1 device" add-on;
 *   • store errors map to a few kinds, each with a sentence in every locale;
 *     a cancel says nothing; a slow card is "pending", not a failure;
 *   • RevenueCat knows the person by the Supabase account id (JWT `sub`);
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
  OFFERING_ID,
  PLAN_PRODUCT_ID,
  accountIdFromAccessToken,
  configureAtStart,
  manageUrlFor,
  planOptions,
  playSubscriptionsUrl,
  readStoreBillingConfig,
  storeErrorKind,
  storeErrorNoteKey,
  storeHasPlan,
  storeSubscriptionToCancel,
} from "../src/utils/store-billing.ts";
import {
  purchaseAction,
  selfUpdateAllowed,
  smsBenefitShown,
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
    { kind: "on", apiKey: KEY },
  );
  assert.equal(
    readStoreBillingConfig({ EXPO_PUBLIC_DISTRIBUTION: " Play ", EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: ` ${KEY} ` }, "android").kind,
    "on",
  );
});

check("site APK, RuStore, unset distribution, iOS: off (not_play), whatever the key", () => {
  for (const dist of ["site", "rustore", "", undefined, "google"]) {
    assert.deepEqual(
      readStoreBillingConfig({ EXPO_PUBLIC_DISTRIBUTION: dist, EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: KEY }, "android"),
      { kind: "off", why: "not_play" },
      String(dist),
    );
  }
  assert.deepEqual(
    readStoreBillingConfig({ EXPO_PUBLIC_DISTRIBUTION: "play", EXPO_PUBLIC_REVENUECAT_ANDROID_KEY: KEY }, "ios"),
    { kind: "off", why: "not_play" },
  );
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
  for (const key of ["sk_live_abc123", "appl_abc123", "goog_", "goog_abc def", "rcb_abc", "goog_abc;drop"]) {
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
  assert.equal(configureAtStart({ billing: { kind: "off", why: "no_key" }, signedIn: true, purchaseStarted: true }), false);
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

check("'automatic SMS check' is promised only in the RuStore build", () => {
  assert.equal(smsBenefitShown("rustore"), true);
  assert.equal(smsBenefitShown("site"), false);
  assert.equal(smsBenefitShown("play"), false);
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

check("the SDK's require sits behind a literal EXPO_PUBLIC_DISTRIBUTION === \"play\" (dropped from other bundles)", () => {
  const src = readFileSync(join(MOBILE, "src/services/store-billing.ts"), "utf8");
  const requires = [...src.matchAll(/require\("react-native-purchases"\)/g)];
  assert.equal(requires.length, 1, "exactly one require of the SDK");
  const guard = src.indexOf('if (process.env.EXPO_PUBLIC_DISTRIBUTION === "play") {');
  assert.ok(guard >= 0, "literal guard present");
  assert.ok(guard < requires[0].index, "guard comes before the require");
  // No static import of the SDK's runtime anywhere in the app (types only).
  for (const file of ["src/services/store-billing.ts", "src/components/paywall/StorePlans.tsx", "app/paywall.tsx", "app/account.tsx"]) {
    const text = readFileSync(join(MOBILE, file), "utf8");
    assert.ok(!/^import (?!type )[^;]*from "react-native-purchases"/m.test(text), `${file}: runtime import of the SDK`);
  }
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

check("every error kind has its sentence in all 10 locales; a cancel says nothing", () => {
  assert.equal(storeErrorNoteKey("cancelled"), null);
  const kinds = ["pending", "already_owned", "network", "not_allowed", "unavailable", "store_problem", "busy", "unknown"];
  for (const loc of ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"]) {
    const strings = JSON.parse(readFileSync(join(MOBILE, "i18n", `${loc}.json`), "utf8"));
    for (const kind of kinds) {
      const key = storeErrorNoteKey(kind);
      assert.ok(key && typeof strings[key] === "string" && strings[key].length > 0, `${loc}: ${kind} → ${key}`);
    }
  }
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

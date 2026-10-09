#!/usr/bin/env node
/**
 * Table test for what the app shows on each platform
 * (src/utils/platform-features.ts) and for the iOS build's App Store shape
 * (app.json, the iOS config plugin, the native module's podspec). docs/IOS.md.
 *
 * Run: node --experimental-strip-types mobile/scripts/test-platform-gating.mjs
 *
 * Pinned:
 *   • Android-only protection (the VPN shield, keep-alive, link guard, call
 *     guard, Private DNS, permission steps) is never shown on an iPhone; the
 *     iPhone gets its own card listing its three layers, "coming soon" until
 *     a later build reports one;
 *   • the onboarding, the share how-to, the home privacy line and the hero
 *     say iPhone things on iOS — every such key exists in all 10 locales;
 *   • the screens really use those switches (a source check: an ungated
 *     Android card would otherwise come back unnoticed — nothing here can
 *     render React Native);
 *   • the iOS app is App Store-shaped: no VPN entitlement, no push
 *     entitlement, no microphone or Face ID string, a camera string,
 *     ITSAppUsesNonExemptEncryption=false, a privacy manifest with reasons,
 *     iPhone only, and the native module's pod not above the app's iOS
 *     deployment target (it was, and the app died at launch).
 */
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  androidProtectionShown,
  heroWithoutShieldsKeys,
  homePrivacyKey,
  iosProtectionLayers,
  iosProtectionShown,
  linkGuardSettingShown,
  onboardingSlides,
  shareHowToKey,
} from "../src/utils/platform-features.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const MOBILE = join(HERE, "..");
const require = createRequire(import.meta.url);
const LOCALES = ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"];
const STRINGS = Object.fromEntries(
  LOCALES.map((loc) => [loc, JSON.parse(readFileSync(join(MOBILE, "i18n", `${loc}.json`), "utf8"))]),
);
const read = (rel) => readFileSync(join(MOBILE, rel), "utf8");

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

function assertKeys(keys) {
  for (const loc of LOCALES) {
    for (const key of keys) {
      assert.ok(typeof STRINGS[loc][key] === "string" && STRINGS[loc][key].length > 0, `${loc}: ${key}`);
    }
  }
}

// ── What each platform shows ─────────────────────────────────────────

check("Android-only protection: shown on Android, never on iOS (or web)", () => {
  assert.equal(androidProtectionShown("android"), true);
  assert.equal(linkGuardSettingShown("android"), true);
  for (const os of ["ios", "web"]) {
    assert.equal(androidProtectionShown(os), false, os);
    assert.equal(linkGuardSettingShown(os), false, os);
  }
});

check("the iPhone protection card: iOS only", () => {
  assert.equal(iosProtectionShown("ios"), true);
  assert.equal(iosProtectionShown("android"), false);
  assert.equal(iosProtectionShown("web"), false);
});

check("the iPhone's layers: Safari, scam texts, DNS — all 'coming' until a build reports one", () => {
  const layers = iosProtectionLayers();
  assert.deepEqual(layers.map((l) => l.id), ["safari", "sms_filter", "dns"]);
  assert.ok(layers.every((l) => l.status === "coming"));
  assertKeys(layers.flatMap((l) => [l.titleKey, l.lineKey]));
  assertKeys(["mobile.ios.header", "mobile.ios.lead", "mobile.ios.coming", "mobile.ios.set_up", "mobile.ios.on"]);
});

check("a later step reports its layer; a nonsense status stays 'coming'", () => {
  const layers = iosProtectionLayers({ dns: "setup", safari: "on", sms_filter: "maybe" });
  assert.deepEqual(layers.map((l) => [l.id, l.status]), [["safari", "on"], ["sms_filter", "coming"], ["dns", "setup"]]);
});

check("onboarding: the third slide is the iPhone one on iOS, the shield one elsewhere", () => {
  const ios = onboardingSlides("ios");
  const android = onboardingSlides("android");
  assert.equal(ios.length, 3);
  assert.equal(android.length, 3);
  assert.deepEqual(ios.slice(0, 2), android.slice(0, 2));
  assert.equal(ios[2].titleKey, "mobile.onboarding.s3_title_ios");
  assert.equal(android[2].titleKey, "mobile.onboarding.s3_title");
  assertKeys([...ios, ...android].flatMap((s) => [s.titleKey, s.descKey]));
  // The iPhone slide never promises the Android shield.
  for (const loc of LOCALES) assert.ok(!/Android/.test(STRINGS[loc][ios[2].descKey]), loc);
});

check("share how-to, home privacy line, hero: iPhone copy on iOS, in every locale", () => {
  assert.equal(shareHowToKey("ios"), "mobile.home.check.share_sheet_body_ios");
  assert.equal(shareHowToKey("android"), "mobile.home.check.share_sheet_body");
  assert.equal(homePrivacyKey("ios"), "mobile.home.privacy_ios");
  assert.equal(homePrivacyKey("android"), "mobile.home.privacy");
  assertKeys([shareHowToKey("ios"), homePrivacyKey("ios")]);
  // The iPhone privacy line names no Android shield.
  for (const loc of LOCALES) assert.ok(!/All apps|Every app/.test(STRINGS[loc][homePrivacyKey("ios")]), loc);
  const hero = heroWithoutShieldsKeys("ios", 0);
  assert.deepEqual(hero, { title: "mobile.home.hero.title_ios", sub: "mobile.home.hero.sub_ios" });
  assertKeys([hero.title, hero.sub]);
  assert.equal(heroWithoutShieldsKeys("ios", 1), null);
  assert.equal(heroWithoutShieldsKeys("android", 0), null);
});

// ── The screens use the switches ─────────────────────────────────────

check("home: the iPhone card and the Android-only cards sit behind their switches", () => {
  const home = read("app/(tabs)/index.tsx");
  assert.match(home, /iosProtectionShown\(Platform\.OS\)/);
  assert.match(home, /<IosProtectionCard /);
  assert.match(home, /heroWithoutShieldsKeys\(Platform\.OS, totalCount\)/);
  assert.match(home, /shareHowToKey\(Platform\.OS\)/);
  assert.match(home, /homePrivacyKey\(Platform\.OS\)/);
  // Android cards render only where their native half exists (false on iOS).
  assert.match(home, /\{network\.available && \(/);
  assert.match(home, /\{linkGuard\.available && \(/);
  assert.match(home, /\{showKeepAlive && \(/);
  assert.match(home, /\{callHelp && \(/);
  assert.match(home, /\{selfUpdateAllowed\(FREEMIUM\.distribution\) && <UpdateBanner/);
  // The old iOS "rolling out" rows are gone (the card replaces them).
  assert.ok(!/rollout\.network_ios|rollout\.browser_ios|rollout\.messages_ios/.test(home));
});

check("settings: the link-checking section is Android only", () => {
  const settings = read("app/(tabs)/settings.tsx");
  const gate = settings.indexOf("{linkGuardSettingShown(Platform.OS) && (");
  const section = settings.indexOf('t("mobile.settings.linkguard")');
  assert.ok(gate >= 0, "gate present");
  assert.ok(section > gate, "section inside the gate");
});

check("onboarding uses the per-platform slides", () => {
  assert.match(read("app/onboarding.tsx"), /onboardingSlides\(Platform\.OS\)/);
});

check("the native checks the iPhone lacks report 'not here', not a guess", () => {
  const vpn = read("modules/cleanway-vpn/index.ts");
  assert.match(vpn, /return Platform\.OS === 'android' && typeof CleanwayVpn\.analyzeMessage === 'function'/);
  assert.match(read("src/hooks/useProtectionActive.ts"), /useState\(\(\) => Platform\.OS === "android"\)/);
});

// ── The iOS build's App Store shape ──────────────────────────────────

const app = JSON.parse(read("app.json")).expo;

check("app.json: iPhone only, bundle id, no VPN entitlement, export compliance", () => {
  assert.equal(app.ios.bundleIdentifier, "ai.cleanway.app");
  assert.equal(app.ios.supportsTablet, false);
  assert.equal(app.ios.config.usesNonExemptEncryption, false);
  assert.ok(!JSON.stringify(app.ios).includes("packet-tunnel-provider"), "no packet-tunnel-provider");
  assert.equal(app.ios.entitlements, undefined);
});

check("app.json: usage strings only for what is used (camera yes; microphone, Face ID no)", () => {
  const plugin = (name) => app.plugins.find((p) => (Array.isArray(p) ? p[0] : p) === name);
  const camera = plugin("expo-camera");
  assert.ok(Array.isArray(camera));
  assert.match(camera[1].cameraPermission, /QR/);
  assert.equal(camera[1].microphonePermission, false);
  const secureStore = plugin("expo-secure-store");
  assert.ok(Array.isArray(secureStore) && secureStore[1].faceIDPermission === false);
  const plist = app.ios.infoPlist ?? {};
  for (const key of ["NSMicrophoneUsageDescription", "NSFaceIDUsageDescription", "NSLocationWhenInUseUsageDescription", "NSUserTrackingUsageDescription"]) {
    assert.equal(plist[key], undefined, key);
  }
});

check("app.json: privacy manifest — no tracking, a reason for each required-reason API", () => {
  const pm = app.ios.privacyManifests;
  assert.equal(pm.NSPrivacyTracking, false);
  const reasons = Object.fromEntries(pm.NSPrivacyAccessedAPITypes.map((t) => [t.NSPrivacyAccessedAPIType, t.NSPrivacyAccessedAPITypeReasons]));
  assert.deepEqual(reasons.NSPrivacyAccessedAPICategoryUserDefaults, ["CA92.1"]);
  assert.deepEqual(reasons.NSPrivacyAccessedAPICategoryFileTimestamp, ["C617.1"]);
  assert.deepEqual(reasons.NSPrivacyAccessedAPICategorySystemBootTime, ["35F9.1"]);
  assert.deepEqual(reasons.NSPrivacyAccessedAPICategoryDiskSpace, ["E174.1"]);
});

check("the iOS entitlements plugin runs first and strips push and VPN entitlements, keeping the app group", () => {
  const first = app.plugins[0];
  assert.equal(first, "./plugins/withIosAppStore");
  const patch = require("../plugins/withIosAppStore.js")._patch;
  const out = patch({
    "aps-environment": "development",
    "com.apple.security.application-groups": ["group.ai.cleanway.app"],
    "com.apple.developer.networking.networkextension": ["packet-tunnel-provider"],
  });
  assert.deepEqual(out, { "com.apple.security.application-groups": ["group.ai.cleanway.app"] });
  // The DNS-settings step will add `dns-settings`; that one stays.
  assert.deepEqual(
    patch({ "com.apple.developer.networking.networkextension": ["dns-settings", "packet-tunnel-provider"] }),
    { "com.apple.developer.networking.networkextension": ["dns-settings"] },
  );
});

check("expo-notifications is kept out of the iOS build (no push on iPhone yet)", () => {
  const pkg = JSON.parse(read("package.json"));
  assert.ok(pkg.expo.autolinking.ios.exclude.includes("expo-notifications"));
  // Nothing in the app may import it while it is excluded: the import would
  // fail on iOS. Lift the exclude (and the entitlement strip) together.
  const files = ["app", "src"].flatMap((dir) =>
    readdirSync(join(MOBILE, dir), { recursive: true })
      .map(String)
      .filter((f) => /\.(ts|tsx)$/.test(f))
      .map((f) => `${dir}/${f}`),
  );
  assert.ok(files.length > 20, "scanned the app's sources");
  for (const file of files) assert.ok(!/from ["']expo-notifications["']/.test(read(file)), file);
});

check("the native module's pod is not above the app's iOS deployment target (Expo SDK 54: 15.1)", () => {
  const podspec = read("modules/cleanway-vpn/ios/CleanwayVpn.podspec");
  const m = /:ios => '(\d+)\.(\d+)'/.exec(podspec);
  assert.ok(m, "ios platform declared");
  assert.ok(Number(m[1]) * 100 + Number(m[2]) <= 1501, `pod needs iOS ${m[1]}.${m[2]}`);
});

check("the share extension: links and text, one at a time — the URL itself, not the web page", () => {
  const share = app.plugins.find((p) => Array.isArray(p) && p[0] === "expo-share-intent")[1];
  assert.equal(share.iosActivationRules.NSExtensionActivationSupportsWebURLWithMaxCount, 1);
  assert.equal(share.iosActivationRules.NSExtensionActivationSupportsText, true);
  // With "web page" support Safari hands over its JavaScript preprocessing
  // result instead of the URL, and a page that failed to load (a scam site
  // already taken down) came through without a checkable link.
  assert.equal(share.iosActivationRules.NSExtensionActivationSupportsWebPageWithMaxCount, undefined);
  assert.equal(app.scheme, "cleanway");
});

check("the share extension's hand-off URL lands on home, not on 'Unmatched Route'", () => {
  const intent = read("app/+native-intent.tsx");
  assert.match(intent, /export function redirectSystemPath/);
  assert.match(intent, /dataUrl=\$\{getShareExtensionKey\(\)\}/);
  assert.match(intent, /return "\/"/);
});

if (failures > 0) {
  console.log(`\n${failures} failing`);
  process.exit(1);
}
console.log("\nplatform gating: all passed");

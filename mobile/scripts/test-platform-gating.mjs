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
 *     deployment target (it was, and the app died at launch);
 *   • the Safari Web Extension inside the app: the home card's Safari layer
 *     follows what iOS and the extension report (safariLayerState), the
 *     setup steps exist in all 10 locales, and the target the config plugin
 *     adds (plugins/withSafariExtension.js) bundles the built
 *     extension-safari/ tree with the right bundle id, app group, iOS 16.4
 *     floor and Safari extension point.
 */
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  androidProtectionShown,
  heroWithoutShieldsKeys,
  homePrivacyKey,
  iosProtectionLayers,
  iosProtectionShown,
  linkGuardSettingShown,
  NO_SAFARI_EXTENSION,
  onboardingSlides,
  parseSafariFacts,
  SAFARI_SEEN_FRESH_MS,
  SAFARI_SETUP_STEP_KEYS,
  SAFARI_TEST_URL,
  SAFARI_TEST_URL_FALLBACK,
  safariLayerState,
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
  // DNS protection on: the line also says site names go to Cleanway's DNS server.
  assert.equal(homePrivacyKey("ios", true), "mobile.home.privacy_ios_dns");
  assert.equal(homePrivacyKey("android", true), "mobile.home.privacy");
  assertKeys([shareHowToKey("ios"), homePrivacyKey("ios"), homePrivacyKey("ios", true)]);
  // The iPhone privacy lines name no Android shield.
  for (const loc of LOCALES) {
    for (const key of [homePrivacyKey("ios"), homePrivacyKey("ios", true)]) {
      assert.ok(!/All apps|Every app/.test(STRINGS[loc][key]), `${loc} ${key}`);
    }
  }
  const hero = heroWithoutShieldsKeys("ios", 0);
  assert.deepEqual(hero, { title: "mobile.home.hero.title_ios", sub: "mobile.home.hero.sub_ios" });
  assertKeys([hero.title, hero.sub]);
  // Once a layer can be set up, "on its way" is no longer the whole truth.
  assert.deepEqual(heroWithoutShieldsKeys("ios", 0, iosProtectionLayers({ dns: "setup" })),
    { title: "mobile.home.hero.title_ios", sub: "mobile.home.hero.sub_ios_ready" });
  assert.equal(heroWithoutShieldsKeys("ios", 0, iosProtectionLayers()).sub, "mobile.home.hero.sub_ios");
  assertKeys(["mobile.home.hero.sub_ios_ready"]);
  assert.equal(heroWithoutShieldsKeys("ios", 1), null);
  assert.equal(heroWithoutShieldsKeys("android", 0), null);
});

// ── The screens use the switches ─────────────────────────────────────

check("home: the iPhone card and the Android-only cards sit behind their switches", () => {
  const home = read("app/(tabs)/index.tsx");
  assert.match(home, /iosProtectionShown\(Platform\.OS\)/);
  assert.match(home, /<IosProtectionCard\s/);
  assert.match(home, /heroWithoutShieldsKeys\(Platform\.OS, totalCount, iosLayers \?\? \[\]\)/);
  assert.match(home, /shareHowToKey\(Platform\.OS\)/);
  assert.match(home, /homePrivacyKey\(Platform\.OS, iosDns\.phase === "on"\)/);
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
  // CA92.1 the app's own defaults; 1C8F.1 the app group shared with the Safari extension.
  assert.deepEqual(reasons.NSPrivacyAccessedAPICategoryUserDefaults, ["CA92.1", "1C8F.1"]);
  assert.deepEqual(reasons.NSPrivacyAccessedAPICategoryFileTimestamp, ["C617.1"]);
  assert.deepEqual(reasons.NSPrivacyAccessedAPICategorySystemBootTime, ["35F9.1"]);
  assert.deepEqual(reasons.NSPrivacyAccessedAPICategoryDiskSpace, ["E174.1"]);
});

check("the iOS entitlements plugin runs first: strips push and VPN, keeps the app group, adds dns-settings", () => {
  const first = app.plugins[0];
  assert.equal(first, "./plugins/withIosAppStore");
  const patch = require("../plugins/withIosAppStore.js")._patch;
  const NE = "com.apple.developer.networking.networkextension";
  const out = patch({
    "aps-environment": "development",
    "com.apple.security.application-groups": ["group.ai.cleanway.app"],
    [NE]: ["packet-tunnel-provider"],
  });
  // DNS protection (NEDNSSettingsManager) needs exactly `dns-settings` — never a VPN value.
  assert.deepEqual(out, { "com.apple.security.application-groups": ["group.ai.cleanway.app"], [NE]: ["dns-settings"] });
  assert.deepEqual(patch({}), { [NE]: ["dns-settings"] });
  assert.deepEqual(patch({ [NE]: ["dns-settings", "packet-tunnel-provider", "app-proxy-provider"] }), { [NE]: ["dns-settings"] });
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


// ── The Safari Web Extension inside the iPhone app ──────────────────

check("Safari layer: status and line from what iOS and the extension report", () => {
  const now = Date.UTC(2026, 9, 9);
  const day = 24 * 3600_000;
  const facts = (o) => ({ bundled: true, stateKnown: false, enabled: false, lastSeenMs: null, settingsApi: false, ...o });
  const table = [
    // An older build without the extension: still "coming".
    [NO_SAFARI_EXTENSION, "coming", "mobile.ios.safari_line"],
    // iOS 26.2+: switched off — whatever the extension said before.
    [facts({ stateKnown: true, enabled: false, lastSeenMs: now - day }), "setup", "mobile.ios.safari_line_off"],
    // Switched on but never ran on a page: "All Websites" is the missing step.
    [facts({ stateKnown: true, enabled: true }), "setup", "mobile.ios.safari_line_allow"],
    [facts({ stateKnown: true, enabled: true, lastSeenMs: now - 15 * day }), "setup", "mobile.ios.safari_line_allow"],
    [facts({ stateKnown: true, enabled: true, lastSeenMs: now - 2 * day }), "on", "mobile.ios.safari_line_on"],
    // iOS < 26.2: only the extension's own report can say "on".
    [facts({}), "setup", "mobile.ios.safari_line_setup"],
    [facts({ lastSeenMs: now - 3600_000 }), "on", "mobile.ios.safari_line_on"],
    [facts({ lastSeenMs: now - SAFARI_SEEN_FRESH_MS }), "setup", "mobile.ios.safari_line_setup"],
    [facts({ lastSeenMs: now + 3 * day }), "setup", "mobile.ios.safari_line_setup"], // a time from the future
  ];
  for (const [f, status, lineKey] of table) {
    assert.deepEqual(safariLayerState(f, now), { status, lineKey }, JSON.stringify(f));
  }
  assert.equal(SAFARI_SEEN_FRESH_MS, 14 * day);
  assertKeys([...new Set(table.map((row) => row[2]))]);
});

check("Safari layer: the native answer is validated (odd values read as 'not known')", () => {
  assert.deepEqual(parseSafariFacts(null), NO_SAFARI_EXTENSION);
  assert.deepEqual(parseSafariFacts("yes"), NO_SAFARI_EXTENSION);
  assert.deepEqual(
    parseSafariFacts({ bundled: true, stateKnown: true, enabled: true, lastSeenMs: 1_700_000_000_000 }),
    { bundled: true, stateKnown: true, enabled: true, lastSeenMs: 1_700_000_000_000, settingsApi: false },
  );
  assert.equal(parseSafariFacts({ bundled: true, settingsApi: true }).settingsApi, true);
  // "enabled" means nothing unless iOS answered; NaN / negative / strings are no time.
  assert.deepEqual(
    parseSafariFacts({ bundled: 1, stateKnown: false, enabled: true, lastSeenMs: Number.NaN }),
    { bundled: false, stateKnown: false, enabled: false, lastSeenMs: null, settingsApi: false },
  );
  assert.equal(parseSafariFacts({ bundled: true, lastSeenMs: -5 }).lastSeenMs, null);
  assert.equal(parseSafariFacts({ bundled: true, lastSeenMs: "1700000000000" }).lastSeenMs, null);
});

check("the card shows the Safari layer's own line once it is built; 'coming' keeps the default", () => {
  const built = iosProtectionLayers({ safari: "setup" }, { safari: "mobile.ios.safari_line_allow" });
  assert.equal(built[0].lineKey, "mobile.ios.safari_line_allow");
  assert.equal(built[1].lineKey, "mobile.ios.sms_line");
  const coming = iosProtectionLayers({}, { safari: "mobile.ios.safari_line_allow" });
  assert.equal(coming[0].lineKey, "mobile.ios.safari_line");
});

check("Safari setup sheet: four steps naming the real switches, in every locale", () => {
  assert.equal(SAFARI_SETUP_STEP_KEYS.length, 4);
  assertKeys([
    ...SAFARI_SETUP_STEP_KEYS,
    "mobile.ios.safari_setup_title",
    "mobile.ios.safari_setup_why",
    "mobile.ios.safari_setup_open_settings",
    "mobile.ios.safari_setup_test",
    "mobile.ios.safari_setup_close",
  ]);
  for (const loc of LOCALES) {
    assert.match(STRINGS[loc][SAFARI_SETUP_STEP_KEYS[0]], /Safari/, `${loc}: step 1 names Safari`);
    assert.match(STRINGS[loc][SAFARI_SETUP_STEP_KEYS[0]], /Cleanway/, `${loc}: step 1 names the extension`);
    // The scam-text and DNS layers are not promised by the Safari steps.
    assert.ok(!/VPN/.test(SAFARI_SETUP_STEP_KEYS.map((k) => STRINGS[loc][k]).join(" ")), loc);
  }
  assert.equal(STRINGS.en["mobile.ios.safari_setup_step2"], "Turn on Allow Extension.");
  // iOS 26 Settings: Permissions → "Other Websites" (seen on the 26.2 simulator).
  assert.match(STRINGS.en["mobile.ios.safari_setup_step3"], /Other Websites/);
  // Opens Safari itself (the extension lives nowhere else), on a page the
  // extension reports from (content/index.js EXTENSION_SEEN on cleanway.ai).
  assert.equal(SAFARI_TEST_URL, "x-safari-https://cleanway.ai/");
  assert.equal(SAFARI_TEST_URL_FALLBACK, "https://cleanway.ai/");
});

check("home wires the Safari layer: status from the hook, Set up opens the sheet", () => {
  const home = read("app/(tabs)/index.tsx");
  assert.match(home, /const safari = useSafariExtension\(\);/);
  assert.match(home, /iosProtectionLayers\(\{[^}]*\bsafari: safari\.layer\.status \}, \{\s*safari: safari\.layer\.lineKey,?\s*\}\)/);
  assert.match(home, /if \(id === "safari"\) setSafariSheetVisible\(true\);/);
  // The Safari layer's own line wins; the SMS filter keeps its ready line.
  const merged = iosProtectionLayers({ safari: "setup", sms_filter: "setup" }, { safari: "mobile.ios.safari_line_allow" });
  assert.equal(merged[0].lineKey, "mobile.ios.safari_line_allow");
  assert.equal(merged[1].lineKey, "mobile.ios_sms.line_ready");
  assert.match(home, /<SafariSetupSheet/);
  const hook = read("src/hooks/useSafariExtension.ts");
  assert.match(hook, /AppState\.addEventListener\("change"/, "re-read when the person comes back from Settings / Safari");
  assert.match(hook, /canOpenSettings: facts\.bundled && facts\.settingsApi/);
});

const safariPlugin = require("../plugins/withSafariExtension.js")._internals;

check("app.json: the Safari extension plugin is on; the app group reason is in the privacy manifest", () => {
  assert.ok(app.plugins.includes("./plugins/withSafariExtension"));
  const ud = app.ios.privacyManifests.NSPrivacyAccessedAPITypes.find((t) => t.NSPrivacyAccessedAPIType === "NSPrivacyAccessedAPICategoryUserDefaults");
  assert.ok(ud.NSPrivacyAccessedAPITypeReasons.includes("1C8F.1"), "reading the app group's defaults needs 1C8F.1");
});

check("Safari extension target: bundle id, app group, iOS 16.4, Safari web-extension point", () => {
  assert.equal(safariPlugin.TARGET, "CleanwaySafariExtension");
  assert.equal(safariPlugin.extensionBundleId("ai.cleanway.app"), "ai.cleanway.app.safari-extension");
  assert.equal(safariPlugin.appGroupOf("ai.cleanway.app"), "group.ai.cleanway.app");
  // Module service workers arrived in Safari 16.4; the app itself stays at 15.1.
  assert.equal(safariPlugin.DEPLOYMENT_TARGET, "16.4");
  const info = safariPlugin.infoPlistContent("group.ai.cleanway.app");
  assert.match(info, /<key>NSExtensionPointIdentifier<\/key>\s*<string>com\.apple\.Safari\.web-extension<\/string>/);
  assert.match(info, /<string>\$\(PRODUCT_MODULE_NAME\)\.SafariWebExtensionHandler<\/string>/);
  assert.match(info, /<key>CleanwayAppGroup<\/key>\s*<string>group\.ai\.cleanway\.app<\/string>/);
  assert.match(safariPlugin.entitlementsContent("group.ai.cleanway.app"), /<string>group\.ai\.cleanway\.app<\/string>/);
  const privacy = safariPlugin.privacyInfoContent();
  assert.match(privacy, /NSPrivacyAccessedAPICategoryUserDefaults/);
  assert.match(privacy, /1C8F\.1/);
  assert.match(privacy, /<key>NSPrivacyTracking<\/key>\s*<false\/>/);
  // Not "PrivacyInfo.xcprivacy" at the group root: expo-share-intent looks that
  // path up for its own target and would share our file reference.
  assert.equal(safariPlugin.PRIVACY_PATH, "Privacy/PrivacyInfo.xcprivacy");
  const settings = safariPlugin.targetBuildSettings({ bundleId: "ai.cleanway.app.safari-extension", version: "1.0.4", buildNumber: "7", devTeam: null, debug: false });
  assert.equal(settings.IPHONEOS_DEPLOYMENT_TARGET, "16.4");
  assert.equal(settings.TARGETED_DEVICE_FAMILY, "1");
  assert.equal(settings.APPLICATION_EXTENSION_API_ONLY, "YES");
  assert.equal(settings.MARKETING_VERSION, '"1.0.4"');
  assert.equal(settings.CURRENT_PROJECT_VERSION, '"7"');
  // The handler stores a time and nothing from the page.
  assert.match(safariPlugin.HANDLER_SWIFT, /body\["type"\] as\? String == "seen"/);
  assert.ok(!/url|host|tab/i.test(safariPlugin.HANDLER_SWIFT.replace(/\/\/.*$/gm, "")), "the handler reads nothing about the page");
});

check("Safari extension target: EAS gets its own profile with the app group", () => {
  const cfg = safariPlugin.addEasAppExtension({}, { bundleId: "ai.cleanway.app.safari-extension", appGroup: "group.ai.cleanway.app" });
  assert.deepEqual(cfg.extra.eas.build.experimental.ios.appExtensions, [{
    targetName: "CleanwaySafariExtension",
    bundleIdentifier: "ai.cleanway.app.safari-extension",
    entitlements: { "com.apple.security.application-groups": ["group.ai.cleanway.app"] },
  }]);
  // Next to the share extension's entry, and not twice on a second run.
  const share = { targetName: "CleanwayCheckLink", bundleIdentifier: "ai.cleanway.app.share-extension" };
  const both = { extra: { eas: { build: { experimental: { ios: { appExtensions: [share] } } } } } };
  safariPlugin.addEasAppExtension(both, { bundleId: "x.safari-extension", appGroup: "group.x" });
  safariPlugin.addEasAppExtension(both, { bundleId: "x.safari-extension", appGroup: "group.x" });
  assert.deepEqual(both.extra.eas.build.experimental.ios.appExtensions.map((e) => e.targetName), ["CleanwayCheckLink", "CleanwaySafariExtension"]);
});

check("Safari extension target: bundles the built extension-safari/ tree, copied, not a second source", () => {
  const repoTree = join(MOBILE, "..", "extension-safari");
  assert.equal(safariPlugin.resolveExtensionSource(MOBILE, {}), repoTree);
  assert.equal(safariPlugin.resolveExtensionSource(MOBILE, { CLEANWAY_SAFARI_EXTENSION_DIR: "/x/ext " }), "/x/ext");
  const manifest = safariPlugin.assertExtensionTree(repoTree);
  assert.equal(manifest.manifest_version, 3);
  assert.ok(manifest.permissions.includes("nativeMessaging"), "the extension cannot report to the app");
  assert.throws(() => safariPlugin.assertExtensionTree(join(MOBILE, "plugins")), /No Safari extension/);

  const dest = mkdtempSync(join(tmpdir(), "cw-safari-"));
  try {
    const copied = safariPlugin.copyExtensionResources(repoTree, join(dest, "Resources"));
    assert.deepEqual(copied, ["manifest.json", "_locales", "src", "public", "styles"]);
    for (const rel of [manifest.background.service_worker, "_locales/ru/messages.json", "src/content/index.js", "src/popup/popup.html"]) {
      assert.equal(readFileSync(join(dest, "Resources", rel), "utf8"), readFileSync(join(repoTree, rel), "utf8"), rel);
    }
  } finally {
    rmSync(dest, { recursive: true, force: true });
  }
  // No committed copy of the extension anywhere under mobile/.
  const stray = readdirSync(MOBILE)
    .filter((top) => !["node_modules", "ios", "android", "dist", ".expo"].includes(top))
    .flatMap((top) => (statSync(join(MOBILE, top)).isDirectory()
      ? readdirSync(join(MOBILE, top), { recursive: true }).map((f) => `${top}/${f}`)
      : [top]))
    .filter((f) => !f.includes("node_modules") && f.endsWith("manifest.json"));
  assert.deepEqual(stray, []);
});

check("the Safari status module's pod is not above the app's iOS deployment target", () => {
  const podspec = read("modules/cleanway-safari/ios/CleanwaySafari.podspec");
  const m = /:ios => '(\d+)\.(\d+)'/.exec(podspec);
  assert.ok(m && Number(m[1]) * 100 + Number(m[2]) <= 1501, "pod above iOS 15.1");
  const swift = read("modules/cleanway-safari/ios/CleanwaySafariModule.swift");
  // The iOS 26.2 calls stay behind a runtime check (and a compiler check for older Xcode).
  const guarded = (call) => new RegExp(String.raw`#if compiler\(>=6\.2\.3\)\s*if #available\(iOS 26\.2, \*\) \{[\s\S]*?` + call);
  assert.match(swift, guarded(String.raw`SFSafariExtensionManager\.getStateOfExtension`));
  assert.match(swift, guarded(String.raw`SFSafariSettings\.openExtensionsSettings`));
  // Both answer once, with a timeout: a call iOS never completes must not leave the card waiting.
  assert.equal((swift.match(/ResolveOnce\(promise\)/g) || []).length, 2);
});
if (failures > 0) {
  console.log(`\n${failures} failing`);
  process.exit(1);
}
console.log("\nplatform gating: all passed");

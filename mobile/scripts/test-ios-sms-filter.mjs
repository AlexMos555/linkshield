#!/usr/bin/env node
/**
 * Table test for the iPhone scam-text filter's app side and build shape
 * (docs/IOS.md §5): the home card's SMS row, its setup sheet, the server's
 * switches reaching the extension, and the Expo plugin that adds the
 * ILMessageFilterExtension target. The engine's verdicts are pinned by the
 * Swift parity tests and check-ios-parity-fixture.mjs.
 *
 * Run: node --experimental-strip-types mobile/scripts/test-ios-sms-filter.mjs
 *
 * Pinned:
 *   • the row is "setup" when the build carries the extension and NEVER "on"
 *     (Apple gives the app no way to know the filter is enabled), "coming"
 *     without it; its line then says it works once turned on in Settings;
 *   • the setup sheet's steps and notes exist in all 10 locales and name the
 *     real path (Apps → Messages → Unknown & Spam → SMS Filtering → Cleanway);
 *   • home and the update check really use those switches (a source check);
 *   • the plugin: target, bundle id, app group, EAS appExtensions entry,
 *     entitlements limited to the app group, the shared Android assets, and
 *     a native module pod not above iOS 15.1.
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  iosProtectionLayers,
  remoteConfigFetched,
  SMS_FILTER_SETUP,
  smsFilterLayerStatus,
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
      const v = STRINGS[loc][key];
      assert.ok(typeof v === "string" && v.trim().length > 0, `${loc}: ${key} missing`);
    }
  }
}

check("the row: 'setup' with the extension, 'coming' without — never 'on'", () => {
  assert.equal(smsFilterLayerStatus(true), "setup");
  assert.equal(smsFilterLayerStatus(false), "coming");
  const ready = iosProtectionLayers({ sms_filter: smsFilterLayerStatus(true) }).find((l) => l.id === "sms_filter");
  assert.equal(ready.status, "setup");
  assert.equal(ready.lineKey, "mobile.ios_sms.line_ready");
  const coming = iosProtectionLayers({ sms_filter: smsFilterLayerStatus(false) }).find((l) => l.id === "sms_filter");
  assert.equal(coming.status, "coming");
  assert.equal(coming.lineKey, "mobile.ios.sms_line");
  // The other layers are untouched by the filter's status.
  assert.deepEqual(
    iosProtectionLayers({ sms_filter: "setup" }).filter((l) => l.id !== "sms_filter").map((l) => l.status),
    ["coming", "coming"],
  );
  assertKeys([ready.lineKey, coming.lineKey]);
});

check("the setup sheet: every string in all 10 locales, the real Settings path", () => {
  const keys = [
    SMS_FILTER_SETUP.titleKey, SMS_FILTER_SETUP.leadKey, ...SMS_FILTER_SETUP.stepKeys, SMS_FILTER_SETUP.olderKey,
    ...SMS_FILTER_SETUP.noteKeys, SMS_FILTER_SETUP.openSettingsKey, SMS_FILTER_SETUP.doneKey,
  ];
  assertKeys(keys);
  const en = STRINGS.en;
  assert.match(en["mobile.ios_sms.step_messages"], /Apps → Messages/);
  assert.match(en["mobile.ios_sms.step_filtering"], /Unknown & Spam.*SMS Filtering/);
  assert.match(en["mobile.ios_sms.step_choose"], /Cleanway/);
  for (const loc of LOCALES) {
    // Every locale names Cleanway in the last step, and promises nothing about iMessage.
    assert.match(STRINGS[loc]["mobile.ios_sms.step_choose"], /Cleanway/, loc);
    assert.match(STRINGS[loc]["mobile.ios_sms.note_limits"], /iMessage/, loc);
    // No "it's on" claim: the app cannot know.
    assert.ok(!/✓|is on\b/i.test(STRINGS[loc]["mobile.ios_sms.line_ready"]), loc);
  }
});

check("home: the row's status comes from the build, 'Set up' opens the sheet", () => {
  const home = read("app/(tabs)/index.tsx");
  assert.match(home, /sms_filter: smsFilterLayerStatus\(smsFilterInstalled\(\)\)/);
  assert.match(home, /if \(id === "sms_filter"\) setSmsSetupVisible\(true\)/);
  assert.match(home, /<IosProtectionCard layers=\{iosLayers\} onSetUp=\{onIosSetUp\} \/>/);
  assert.match(home, /<SmsFilterSetupSheet visible=\{smsSetupVisible\}/);
  const sheet = read("src/components/shield/SmsFilterSetupSheet.tsx");
  assert.match(sheet, /Linking\.openSettings\(\)/);
  // A private settings URL is an App Review rejection.
  assert.ok(!/App-[Pp]refs:|prefs:root/.test(sheet));
});

check("the server's switches reach the filter: fetched on an iPhone with it, stored in the app group", () => {
  assert.equal(remoteConfigFetched("android", false), true);
  assert.equal(remoteConfigFetched("ios", true), true);
  assert.equal(remoteConfigFetched("ios", false), false);
  assert.equal(remoteConfigFetched("web", true), false);
  const hook = read("src/hooks/useUpdateCheck.ts");
  assert.match(hook, /if \(!remoteConfigFetched\(Platform\.OS, smsFilterInstalled\(\)\)\) return;/);
  assert.match(hook, /setSmsFilterRemoteConfig\(wire\)/);
  // The update decision itself stays Android-only.
  assert.match(hook, /if \(!ready \|\| Platform\.OS !== "android" \|\| !info\) return NONE;/);
  const native = read("modules/cleanway-sms-filter/ios/CleanwaySmsFilterModule.swift");
  assert.match(native, /Function\("setRemoteConfig"\) \{ \(json: String\) -> Bool in/);
  assert.match(native, /remote_config\.json/);
  // The same keys as RemoteConfig.kt and the extension's reader.
  const engine = readFileSync(join(MOBILE, "targets/sms-filter/Sources/CleanwayMessageEngine/RemoteConfig.swift"), "utf8");
  for (const key of ["sms_text_model_enabled", "sms_text_model_caution_threshold_override", "sms_text_model_danger_threshold_override"]) {
    assert.ok(native.includes(key) && engine.includes(key), key);
  }
  assert.ok(readFileSync(join(MOBILE, "targets/sms-filter/Sources/CleanwayMessageEngine/SmsFilterEngine.swift"), "utf8")
    .includes('remoteConfigFile = "remote_config.json"'));
});

// ── The build shape ──────────────────────────────────────────────────

const app = JSON.parse(read("app.json")).expo;
const plugin = require("../plugins/withSmsFilter.js");

check("app.json registers the filter plugin after the App Store entitlement plugin", () => {
  const i = app.plugins.indexOf("./plugins/withSmsFilter");
  assert.ok(i > 0, "registered");
  assert.equal(app.plugins[0], "./plugins/withIosAppStore");
});

check("EAS knows the target: its bundle id and the app group", () => {
  const extra = plugin._easExtra({ eas: { projectId: "x" } }, "ai.cleanway.app");
  assert.equal(extra.eas.projectId, "x");
  const ext = extra.eas.build.experimental.ios.appExtensions;
  assert.deepEqual(ext, [{
    targetName: "CleanwaySmsFilter",
    bundleIdentifier: "ai.cleanway.app.sms-filter",
    entitlements: { "com.apple.security.application-groups": ["group.ai.cleanway.app"] },
  }]);
  // Idempotent, and leaves other extensions (the share extension) alone.
  const twice = plugin._easExtra({ eas: { build: { experimental: { ios: { appExtensions: [{ targetName: "ShareExtension" }, ext[0]] } } } } }, "ai.cleanway.app");
  assert.deepEqual(twice.eas.build.experimental.ios.appExtensions.map((e) => e.targetName), ["ShareExtension", "CleanwaySmsFilter"]);
});

check("the extension's entitlements: the app group, nothing else", () => {
  const ent = plugin._entitlements("group.ai.cleanway.app");
  assert.match(ent, /com\.apple\.security\.application-groups/);
  assert.equal((ent.match(/<key>/g) || []).length, 1);
});

check("the target compiles the engine and the entry point, and bundles the shared Android assets", () => {
  const files = plugin._targetFiles(MOBILE);
  assert.ok(files.sources.includes("MessageFilterExtension.swift"));
  for (const f of ["MessageAnalyzer.swift", "MessageModel.swift", "MessageSignals.swift", "SmsFilterEngine.swift", "IDN.swift"]) {
    assert.ok(files.sources.includes(f), f);
  }
  assert.deepEqual(plugin.ASSETS, ["message_rules.json", "root_zone_tlds.txt", "message_model.json", "message_model.bin"]);
  for (const a of plugin.ASSETS) {
    assert.ok(files.resources.includes(a), a);
    assert.ok(existsSync(join(MOBILE, "modules/cleanway-vpn/android/src/main/assets", a)), a);
  }
  assert.ok(files.resources.includes("PrivacyInfo.xcprivacy"));
});

check("the module's pod is not above the app's iOS deployment target (15.1)", () => {
  const podspec = read("modules/cleanway-sms-filter/ios/CleanwaySmsFilter.podspec");
  const m = /:ios => '(\d+)\.(\d+)'/.exec(podspec);
  assert.ok(m, "ios platform declared");
  assert.ok(Number(m[1]) * 100 + Number(m[2]) <= 1501, `pod needs iOS ${m[1]}.${m[2]}`);
  const config = JSON.parse(read("modules/cleanway-sms-filter/expo-module.config.json"));
  assert.deepEqual(config.platforms, ["apple"]);
  // The extension's Swift module must not share the pod's name: its swiftmodule
  // in the products dir shadowed the pod and the app failed to compile.
  const pod = /s\.name\s*=\s*'([^']+)'/.exec(podspec)[1];
  const src = read("plugins/withSmsFilter.js");
  assert.match(src, /PRODUCT_MODULE_NAME: MODULE_NAME/);
  const moduleName = /const MODULE_NAME = "([^"]+)"/.exec(src)[1];
  assert.notEqual(moduleName, pod);
  assert.notEqual(moduleName, plugin.TARGET);
});

if (failures > 0) {
  console.log(`\n${failures} failing`);
  process.exit(1);
}
console.log("\niOS scam-text filter: all passed");

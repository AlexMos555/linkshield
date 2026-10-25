#!/usr/bin/env node
/**
 * Tests for the Expo config plugins that shape the Android release build.
 *
 * These plugins rewrite `android/app/build.gradle` on every `expo prebuild`, and
 * the generated tree is not in git — so a silent regression here means a build
 * that is debug-signed or 40 MB fatter, with a green BUILD SUCCESSFUL either
 * way. That is exactly the kind of failure nobody notices until a store rejects
 * the artifact, hence real, committed assertions rather than ad-hoc checking.
 *
 * Plain node (no jest in mobile/): `node mobile/plugins/__tests__/plugins.test.js`
 */
const assert = require("node:assert");
const { _patch: patchSigning } = require("../withReleaseSigning.js");
const { _patch: patchAbi, DEFAULT_ABIS } = require("../withAbiFilters.js");
const { _patch: patchSeed } = require("../withSeedGuard.js");
const { _patch: patchDarkBars } = require("../withDarkSystemBars.js");

// A trimmed but structurally faithful app/build.gradle (Expo SDK 52 / RN 0.76;
// the anchors are unchanged in the SDK 54 / RN 0.81 and SDK 58 / RN 0.88
// prebuild output — scripts/check-prebuild-gradle.mjs, 2026-10-24).
const TEMPLATE = `
apply plugin: "com.android.application"
def enableProguardInReleaseBuilds = false

android {
    namespace "ai.cleanway.app"
    defaultConfig {
        applicationId "ai.cleanway.app"
        versionCode 100
        versionName "1.0.0"
    }
    signingConfigs {
        debug {
            storeFile file('debug.keystore')
            storePassword 'android'
            keyAlias 'androiddebugkey'
            keyPassword 'android'
        }
    }
    buildTypes {
        debug {
            signingConfig signingConfigs.debug
        }
        release {
            // Caution! In production, you need to generate your own keystore file.
            signingConfig signingConfigs.debug
            shrinkResources (findProperty('x')?.toBoolean() ?: false)
            minifyEnabled enableProguardInReleaseBuilds
        }
    }
}
`;

let passed = 0;
function check(name, fn) {
  fn();
  passed++;
  console.log("  ok  " + name);
}

console.log("withReleaseSigning:");
{
  const out = patchSigning(TEMPLATE);
  check("loads keystore.properties before the android block", () => {
    assert.ok(out.includes("def cleanwayKeystoreProps = new Properties()"));
    assert.ok(out.indexOf("cleanwayKeystoreProps") < out.indexOf("android {"));
  });
  check("adds a release signingConfig", () => {
    assert.match(out, /signingConfigs\s*\{\s*\n\s*release \{/);
  });
  check("release buildType selects the release key when one exists", () => {
    assert.ok(out.includes(
      "signingConfig (cleanwayKeystoreProps['storeFile'] ? signingConfigs.release : signingConfigs.debug)"));
  });
  check("falls back to the debug key when no keystore is configured", () => {
    // The ternary is the fallback: absent properties => signingConfigs.debug.
    assert.ok(out.includes("? signingConfigs.release : signingConfigs.debug"));
  });
  check("leaves the debug buildType debug-signed", () => {
    assert.match(out, /debug \{\s*\n\s*signingConfig signingConfigs\.debug\s*\n\s*\}/);
  });
  check("does not disturb the rest of the release block", () => {
    assert.match(out, /signingConfigs\.debug\)\s*\n\s*shrinkResources/);
  });
  check("warns loudly instead of silently debug-signing", () => {
    // A silent fallback is how a debug-signed APK reaches a store submission:
    // the build still says BUILD SUCCESSFUL either way.
    assert.ok(out.includes("NO RELEASE KEYSTORE"));
    assert.ok(out.includes("if (!cleanwayKeystoreProps['storeFile'])"));
  });
  check("is idempotent across repeated prebuilds", () => {
    assert.strictEqual(patchSigning(out), out);
  });
  check("leaves unrecognised gradle untouched (fail-safe, never a broken build)", () => {
    assert.strictEqual(patchSigning("something { unrelated }"), "something { unrelated }");
  });
}

console.log("withAbiFilters:");
{
  const out = patchAbi(TEMPLATE, DEFAULT_ABIS);
  check("filters ABIs in the release build type", () => {
    const release = out.slice(out.indexOf("release {"));
    assert.ok(release.includes('abiFilters "armeabi-v7a", "arm64-v8a"'));
  });
  check("does NOT touch debug — emulators need x86_64 to install the dev APK", () => {
    const debugBlock = out.slice(out.indexOf("debug {"), out.indexOf("release {"));
    assert.ok(!debugBlock.includes("abiFilters"));
  });
  check("does not put abiFilters in defaultConfig (that would hit every variant)", () => {
    // Slice the actual defaultConfig block rather than pattern-match across it.
    const defaultConfig = out.slice(
      out.indexOf("defaultConfig {"),
      out.indexOf("signingConfigs {"),
    );
    assert.ok(!defaultConfig.includes("abiFilters"));
  });
  // New Architecture (Expo SDK 55+): the RN gradle plugin adds every
  // reactNativeArchitectures ABI to defaultConfig.ndk.abiFilters and AGP merges
  // it with the build type's, so the first SDK 58 release APK still had x86.
  check("New Architecture: moves React Native's defaultConfig ABIs to debug, after RN's finalizeDsl", () => {
    assert.ok(out.includes("androidComponents {\n    finalizeDsl { ext ->"));
    assert.ok(out.includes("def cleanwayAllAbis = new ArrayList(ext.defaultConfig.ndk.abiFilters)"));
    assert.ok(out.includes("ext.defaultConfig.ndk.abiFilters.clear()"));
    assert.ok(out.includes('ext.buildTypes.getByName("debug").ndk.abiFilters.addAll(cleanwayAllAbis)'));
    assert.ok(!out.includes('getByName("release")'), "release keeps only its own filter");
    // At file scope after the android { … } block (and after `apply plugin: "com.facebook.react"`).
    assert.ok(out.indexOf("\nandroidComponents {") > out.indexOf("minifyEnabled enableProguardInReleaseBuilds\n        }\n    }\n}"));
  });
  check("honours a CLEANWAY_ABIS override", () => {
    const only64 = patchAbi(TEMPLATE, "arm64-v8a");
    assert.ok(only64.includes('abiFilters "arm64-v8a"'));
    assert.ok(!only64.includes("armeabi-v7a"));
  });
  check("is idempotent across repeated prebuilds", () => {
    assert.strictEqual(patchAbi(out, DEFAULT_ABIS), out);
  });
  check("leaves unrecognised gradle untouched", () => {
    assert.strictEqual(patchAbi("no build types here", DEFAULT_ABIS), "no build types here");
  });
}

console.log("withSeedGuard:");
{
  const out = patchSeed(TEMPLATE);
  check("fails a non-debug build that has no starter blocklist", () => {
    assert.ok(out.includes('file("../../modules/cleanway-vpn/android/src/main/assets/dns-blocklist-v2.seed.bin")'));
    assert.ok(out.includes("throw new GradleException("));
    assert.ok(out.includes("!cleanwaySeed.isFile()"));
  });
  check("hooks every pre<Variant>Build except debug ones, before compiling", () => {
    assert.ok(out.includes("it.name ==~ /pre\\w+Build/ && !(it.name ==~ /(?i).*debug.*/)"));
  });
  check("says how to fix it, and how to skip it on purpose", () => {
    assert.ok(out.includes("fetch-seed-blocklist.sh"));
    assert.ok(out.includes('!project.hasProperty("cleanwayNoSeed")'));
  });
  check("leaves the android block untouched (appended after it)", () => {
    assert.ok(out.startsWith(TEMPLATE.trimEnd()));
  });
  check("is idempotent across repeated prebuilds", () => {
    assert.strictEqual(patchSeed(out), out);
  });
}

console.log("withDistributionGuard:");
{
  // Which store a release is for decides the paywall (web checkout or not),
  // the self-update banner and whether Play Billing is linked. Unset means
  // the site APK, so a forgotten export turned the Play AAB and the RuStore
  // APK into the site build with a green BUILD SUCCESSFUL (backlog rank 2).
  const { releaseCheck, distributionOf } = require("../distribution.js");
  const { _patch: patchDist } = require("../withDistributionGuard.js");

  // Values the app (freemium.ts distributionFor) and autolinking
  // (store-billing-linking.js) read as the site build, though they look like
  // play: the guard must refuse them, not tidy them into "play".
  const LOOKALIKES = ["play;", "'play'", "pl.ay", "p lay", "pl'ay${x}"];
  check("reads the store the same way the app does (trimmed, lower-case, nothing else)", () => {
    assert.strictEqual(distributionOf({ EXPO_PUBLIC_DISTRIBUTION: " PLAY " }), "play");
    assert.strictEqual(distributionOf({ EXPO_PUBLIC_DISTRIBUTION: "rustore" }), "rustore");
    assert.strictEqual(distributionOf({}), "");
    for (const v of LOOKALIKES) assert.notStrictEqual(distributionOf({ EXPO_PUBLIC_DISTRIBUTION: v }), "play", v);
  });
  check("a value the app reads as the site build fails, even when it looks like play", () => {
    for (const v of LOOKALIKES) {
      const r = releaseCheck({ distribution: distributionOf({ EXPO_PUBLIC_DISTRIBUTION: v }), prebuild: "play", artifact: "aab" });
      assert.strictEqual(r.ok, false, v);
      assert.ok(!r.message.includes("Google Play build"), r.message);
    }
  });
  check("the CLI gradle runs refuses them too (exit 1), and passes play (exit 0)", () => {
    const { spawnSync } = require("node:child_process");
    const fs = require("node:fs");
    const os = require("node:os");
    const path = require("node:path");
    // An empty cwd: no project .env file can change the answer.
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "cleanway-dist-"));
    const cli = (value) =>
      spawnSync(process.execPath, [path.join(__dirname, "..", "distribution.js"), "check", "--prebuild=play", "--artifact=aab"], {
        cwd, encoding: "utf8", env: { PATH: process.env.PATH, EXPO_PUBLIC_DISTRIBUTION: value },
      });
    try {
      for (const v of LOOKALIKES) {
        const r = cli(v);
        assert.strictEqual(r.status, 1, `${v}: ${r.stdout}${r.stderr}`);
        assert.ok(!r.stdout.includes("Google Play build"), r.stdout);
        assert.ok(r.stderr.includes("EXPO_PUBLIC_DISTRIBUTION"), r.stderr);
      }
      const ok = cli("play");
      assert.strictEqual(ok.status, 0, ok.stderr);
      assert.ok(ok.stdout.includes("Google Play build"), ok.stdout);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });
  check("a release build must name its store — unset or unknown fails", () => {
    for (const distribution of ["", "googleplay", "appstore"]) {
      for (const artifact of ["apk", "aab"]) {
        const r = releaseCheck({ distribution, prebuild: distribution, artifact });
        assert.strictEqual(r.ok, false, `${distribution || "unset"} ${artifact}`);
        assert.ok(r.message.includes("EXPO_PUBLIC_DISTRIBUTION"), r.message);
        assert.ok(/site.*rustore.*play/s.test(r.message), "names the three stores");
      }
    }
  });
  check("an App Bundle is never the site build", () => {
    const r = releaseCheck({ distribution: "site", prebuild: "site", artifact: "aab" });
    assert.strictEqual(r.ok, false);
    assert.ok(r.message.includes("EXPO_PUBLIC_DISTRIBUTION=play"), r.message);
  });
  check("site APK, RuStore APK/AAB and Play AAB/APK pass", () => {
    for (const [distribution, artifact] of [
      ["site", "apk"], ["rustore", "apk"], ["rustore", "aab"], ["play", "aab"], ["play", "apk"],
    ]) {
      const r = releaseCheck({ distribution, prebuild: distribution, artifact, revenueCatKey: true });
      assert.strictEqual(r.ok, true, `${distribution} ${artifact}: ${r.message}`);
      assert.ok(r.message.includes(distribution), r.message);
    }
  });
  check("android/ generated for another store fails (stale autolinking)", () => {
    const r = releaseCheck({ distribution: "play", prebuild: "site", artifact: "aab", revenueCatKey: true });
    assert.strictEqual(r.ok, false);
    assert.ok(r.message.includes("expo prebuild -p android --clean"), r.message);
  });
  check("a Play build without the RevenueCat key passes with a warning", () => {
    const r = releaseCheck({ distribution: "play", prebuild: "play", artifact: "aab", revenueCatKey: false });
    assert.strictEqual(r.ok, true);
    assert.ok(r.message.includes("EXPO_PUBLIC_REVENUECAT_ANDROID_KEY"), r.message);
  });

  const out = patchDist(TEMPLATE, "play");
  check("bakes the prebuild's store into the gradle file", () => {
    assert.ok(out.includes("def cleanwayPrebuildDistribution = 'play'"));
    assert.ok(patchDist(TEMPLATE, " Play ").includes("def cleanwayPrebuildDistribution = 'play'"));
    assert.ok(patchDist(TEMPLATE, "").includes("def cleanwayPrebuildDistribution = ''"));
  });
  check("a prebuild for an unknown value bakes a marker no build matches, never the text", () => {
    for (const v of [...LOOKALIKES, "googleplay"]) {
      const baked = /def cleanwayPrebuildDistribution = '([^']*)'/.exec(patchDist(TEMPLATE, v));
      assert.ok(baked, v);
      assert.strictEqual(baked[1], "invalid", v);
      // Built afterwards with a correct EXPO_PUBLIC_DISTRIBUTION: still refused.
      const r = releaseCheck({ distribution: "play", prebuild: distributionOf({ EXPO_PUBLIC_DISTRIBUTION: baked[1] }), artifact: "aab", revenueCatKey: true });
      assert.strictEqual(r.ok, false, v);
      assert.ok(r.message.includes("expo prebuild -p android --clean"), r.message);
    }
    assert.ok(!patchDist(TEMPLATE, "pl'ay${x}").includes("${x}"));
    assert.strictEqual(patchDist(patchDist(TEMPLATE, "play"), "p lay"), patchDist(TEMPLATE, "invalid"));
  });
  check("checks APK and AAB release packaging, before any task runs", () => {
    assert.ok(out.includes("gradle.taskGraph.whenReady"));
    assert.ok(out.includes("it.name ==~ /bundle\\w*Release/"));
    assert.ok(out.includes("it.name ==~ /package\\w*Release/"));
  });
  check("asks plugins/distribution.js and fails the build on a refusal", () => {
    assert.ok(out.includes('"plugins/distribution.js", "check"'));
    assert.ok(out.includes("throw new GradleException("));
  });
  check("leaves the android block untouched (appended after it)", () => {
    assert.ok(out.startsWith(TEMPLATE.trimEnd()));
  });
  check("re-prebuilding for another store re-bakes the value, once", () => {
    const again = patchDist(out, "rustore");
    assert.ok(again.includes("def cleanwayPrebuildDistribution = 'rustore'"));
    assert.ok(!again.includes("'play'"));
    assert.strictEqual(again.split("cleanway-distribution-guard:").length, 2);
    assert.strictEqual(patchDist(again, "rustore"), again);
  });
}

console.log("withDarkSystemBars:");
{
  // The Expo SDK 54 prebuild MainActivity.kt onCreate, verbatim (SDK 58 keeps
  // the `super.onCreate(null)` anchor).
  const MAIN_ACTIVITY = `package ai.cleanway.app

import android.os.Build
import android.os.Bundle

import com.facebook.react.ReactActivity

class MainActivity : ReactActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    // Set the theme to AppTheme BEFORE onCreate to support
    // coloring the background, status bar, and navigation bar.
    // This is required for expo-splash-screen.
    setTheme(R.style.AppTheme);
    super.onCreate(null)
  }

  override fun getMainComponentName(): String = "main"
}
`;
  const out = patchDarkBars(MAIN_ACTIVITY);
  check("sets night mode in MainActivity.onCreate, before super.onCreate", () => {
    const night = out.indexOf("AppCompatDelegate.setDefaultNightMode(androidx.appcompat.app.AppCompatDelegate.MODE_NIGHT_YES)");
    assert.ok(night > 0, "night-mode line present");
    assert.ok(night > out.indexOf("setTheme(R.style.AppTheme)"));
    assert.ok(night < out.indexOf("super.onCreate(null)"));
  });
  check("is idempotent across repeated prebuilds", () => {
    assert.strictEqual(patchDarkBars(out), out);
  });
  check("leaves an unrecognised file alone", () => {
    const odd = "class MainActivity : ReactActivity()\n";
    assert.strictEqual(patchDarkBars(odd), odd);
  });
}

// Guard the RuStore-facing app.json config: the four Expo-template
// permissions the app never uses must stay blocked, and expo-camera must
// not pull RECORD_AUDIO back in. (RuStore asks to justify each sensitive
// permission; docs/RUSTORE_SUBMISSION.md §3 declares mic/photos "No".)
{
  const fs = require("fs");
  const path = require("path");
  const appJson = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "app.json"), "utf8")).expo;
  check("app.json blocks the four unused Android permissions", () => {
    const blocked = (appJson.android && appJson.android.blockedPermissions) || [];
    for (const perm of [
      "android.permission.RECORD_AUDIO",
      "android.permission.SYSTEM_ALERT_WINDOW",
      "android.permission.READ_EXTERNAL_STORAGE",
      "android.permission.WRITE_EXTERNAL_STORAGE",
    ]) assert.ok(blocked.includes(perm), `${perm} must be in android.blockedPermissions`);
    assert.ok(!blocked.includes("android.permission.CAMERA"), "CAMERA is used by the QR scanner and must stay");
  });
  // Google Play target API 36: RN still relies on onBackPressed, which
  // Android 16 stops calling for targetSdk 36 apps unless predictive back is
  // opted out. Since Expo SDK 55 the New Architecture is the only one, and the
  // app.json schema rejects `newArchEnabled`, so it must stay out.
  check("app.json keeps predictive back off and has no newArchEnabled", () => {
    assert.strictEqual(appJson.android.predictiveBackGestureEnabled, false);
    assert.ok(!("newArchEnabled" in appJson), "newArchEnabled was removed in Expo SDK 55");
  });
  // Expo SDK 58: the root `splash` is no longer in the app.json schema; the
  // launch screen comes from the expo-splash-screen plugin entry instead.
  check("app.json: the launch screen is the expo-splash-screen plugin's, no root splash", () => {
    assert.ok(!("splash" in appJson), "root splash is rejected by the SDK 58 schema");
    const entry = (appJson.plugins || []).find((p) => Array.isArray(p) && p[0] === "expo-splash-screen");
    assert.ok(entry, "expo-splash-screen plugin entry present");
    assert.deepStrictEqual(entry[1], { image: "./assets/splash.png", resizeMode: "contain", backgroundColor: "#0f172a" });
  });
  check("app.json registers the dark-system-bars plugin", () => {
    assert.ok((appJson.plugins || []).includes("./plugins/withDarkSystemBars"));
  });
  check("app.json registers the distribution guard", () => {
    assert.ok((appJson.plugins || []).includes("./plugins/withDistributionGuard"));
  });
  // EAS release profiles carry their store in eas.json, so an EAS Android
  // build passes the guard by itself: production is the Play AAB.
  check("eas.json: every release profile names its store, production is Google Play", () => {
    const eas = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "eas.json"), "utf8")).build;
    assert.strictEqual(eas.production.env.EXPO_PUBLIC_DISTRIBUTION, "play");
    assert.strictEqual(eas.production.android.buildType, "app-bundle");
    for (const [name, profile] of Object.entries(eas)) {
      if (name.startsWith("//") || profile.developmentClient) continue;
      assert.ok(["site", "rustore", "play"].includes(profile.env && profile.env.EXPO_PUBLIC_DISTRIBUTION), name);
    }
  });
  check("expo-camera plugin disables Android audio recording", () => {
    const cam = (appJson.plugins || []).find((p) => Array.isArray(p) && p[0] === "expo-camera");
    assert.ok(cam, "expo-camera plugin entry present");
    assert.strictEqual(cam[1].recordAudioAndroid, false);
  });
  // iOS shows NSCameraUsageDescription in the camera prompt, in the phone's
  // language only if the app ships <lang>.lproj/InfoPlist.strings — Expo
  // writes those from `locales` (generated by scripts/build-i18n.py from
  // packages/i18n-strings, mobile.ios_info_plist.*).
  check("app.json localises the iOS camera prompt in every app language", () => {
    const cam = (appJson.plugins || []).find((p) => Array.isArray(p) && p[0] === "expo-camera");
    const locales = appJson.locales || {};
    const APP_LANGS = ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"];
    assert.deepStrictEqual(Object.keys(locales).sort(), [...APP_LANGS].sort());
    for (const lang of APP_LANGS) {
      assert.strictEqual(locales[lang], `./i18n/ios/${lang}.json`, lang);
      const file = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", locales[lang]), "utf8"));
      assert.deepStrictEqual(Object.keys(file), ["ios"], `${lang}: iOS-only keys (Android gets nothing)`);
      const text = file.ios.NSCameraUsageDescription;
      assert.ok(typeof text === "string" && text.trim().length > 20, lang);
      // Expo writes `KEY = "value";` without escaping.
      assert.ok(!/["\\\n]/.test(text), `${lang}: no quote, backslash or newline`);
    }
    // The base Info.plist (expo-camera) and en.lproj say the same thing.
    assert.strictEqual(
      JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "i18n", "ios", "en.json"), "utf8")).ios.NSCameraUsageDescription,
      cam[1].cameraPermission,
    );
  });

  // --- Android backup rules (withBackupRules) ------------------------------
  // The block log is a browsing trail and the allow list is the person's own;
  // neither may reach a Google Drive backup or a new phone. The rule files are
  // committed resources of the native module; the manifest is prebuild output,
  // so its two attributes are asserted through the plugin's transform.
  const backup = require("../withBackupRules.js");
  const resXml = path.join(__dirname, "..", "..", "modules", "cleanway-vpn", "android", "src", "main", "res", "xml");
  const ktDir = path.join(__dirname, "..", "..", "modules", "cleanway-vpn", "android", "src", "main", "java", "ai", "cleanway", "app");
  // Read the pref names from the Kotlin source, so a rename there cannot
  // silently put the data back into backups.
  const prefsName = (file) => {
    const m = fs.readFileSync(path.join(ktDir, file), "utf8").match(/private const val PREFS = "([^"]+)"/);
    assert.ok(m, `${file} declares PREFS`);
    return m[1];
  };
  const PRIVATE_PREFS = [prefsName("BlockLog.kt"), prefsName("UserAllow.kt")];
  check("private prefs are the block log and the allow list", () => {
    assert.deepStrictEqual(PRIVATE_PREFS, ["cleanway_block_log", "cleanway_user_allow"]);
  });
  const excludes = (xml, section) => {
    const body = section ? (xml.match(new RegExp(`<${section}>([\\s\\S]*?)</${section}>`)) || [])[1] : xml;
    assert.ok(body, `<${section}> present`);
    // Comments mention the names too; only real elements count. Keep the text
    // outside <!-- … --> (an unterminated comment swallows the rest).
    const live = body
      .split("<!--")
      .map((seg, i) => {
        if (i === 0) return seg;
        const end = seg.indexOf("-->");
        return end < 0 ? "" : seg.slice(end + 3);
      })
      .join("");
    return [...live.matchAll(/<exclude\s+domain="sharedpref"\s+path="([^"]+)"\s*\/>/g)].map((m) => m[1]);
  };
  const extraction = fs.readFileSync(path.join(resXml, "cleanway_data_extraction_rules.xml"), "utf8");
  const legacy = fs.readFileSync(path.join(resXml, "cleanway_backup_rules.xml"), "utf8");
  for (const [label, xml, section] of [
    ["Android 12+ cloud backup", extraction, "cloud-backup"],
    ["Android 12+ device transfer", extraction, "device-transfer"],
    ["Android 11- full backup", legacy, null],
  ]) {
    check(`${label} excludes the block log, the allow list and SecureStore`, () => {
      const ex = excludes(xml, section);
      for (const name of PRIVATE_PREFS) assert.ok(ex.includes(`${name}.xml`), `${name}.xml excluded`);
      assert.ok(ex.includes("SecureStore"), "keeps expo-secure-store's exclusion");
    });
  }
  check("withBackupRules points the manifest at Cleanway's rule files", () => {
    // Shaped like a manifest that expo-secure-store's plugin already touched.
    const manifest = {
      manifest: {
        application: [{
          $: {
            "android:name": ".MainApplication",
            "android:allowBackup": "true",
            "android:fullBackupContent": "@xml/secure_store_backup_rules",
            "android:dataExtractionRules": "@xml/secure_store_data_extraction_rules",
          },
        }],
      },
    };
    const app = backup._apply(manifest).manifest.application[0].$;
    assert.strictEqual(app["android:fullBackupContent"], "@xml/cleanway_backup_rules");
    assert.strictEqual(app["android:dataExtractionRules"], "@xml/cleanway_data_extraction_rules");
  });
  check("app.json registers withBackupRules and turns off expo-secure-store's backup rules", () => {
    assert.ok((appJson.plugins || []).includes("./plugins/withBackupRules"));
    const ss = (appJson.plugins || []).find((p) => Array.isArray(p) && p[0] === "expo-secure-store");
    assert.ok(ss, "expo-secure-store plugin entry present");
    // Otherwise it warns on every prebuild that other backup rules exist, and
    // a reorder of plugins would be one step from its rules (SecureStore
    // only) being the ones in force.
    assert.strictEqual(ss[1].configureAndroidBackup, false);
  });
}

// --- expo-share-intent: a shared file stays in the cache (Android) ---------
// 2.0.0–8.0.0 copied a shared file to cacheDir/<the sender's _display_name>,
// so any app on the phone could send "../shared_prefs/…" and overwrite
// Cleanway's private data (docs/EXPO_UPGRADE_PLAN.md §1.2). 1.0.6 patched 5.1.1;
// since Expo SDK 58 the app takes ^9.0.0, which has upstream's 8.0.1 fix, and
// the patch is gone. scripts/check-share-intent.mjs proves the fix is in the
// installed module, that no patch is left behind and that the share sheet
// takes text/plain only. Here: it passes, and it fails when it should.
console.log("expo-share-intent (Android shared-file path traversal):");
{
  const { spawnSync } = require("node:child_process");
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");
  const mobileDir = path.join(__dirname, "..", "..");
  const script = path.join(mobileDir, "scripts", "check-share-intent.mjs");
  const run = (...args) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8" });
  const KT = path.join("android", "src", "main", "java", "expo", "modules", "shareintent", "ExpoShareIntentModule.kt");
  const installed = path.dirname(require.resolve("expo-share-intent/package.json", { paths: [mobileDir] }));
  const fixed = fs.readFileSync(path.join(installed, KT), "utf8");
  // Upstream's fix (#221, 8.0.1), both ways: the line 2.0.0–8.0.0 had in
  // getDataColumn, and the lines 8.0.1 and 9.0.0 have instead.
  const HOLE = [
    "                    targetFile = File(context.cacheDir, fileName)",
    "                }",
  ].join("\n");
  const FIX = [
    "                    val safeName = fileName?.let { File(it).name }.orEmpty()",
    "                    if (safeName.isNotEmpty()) {",
    "                        val candidate = File(context.cacheDir, safeName)",
    "                        val cacheRoot = context.cacheDir.canonicalPath + File.separator",
    "                        if (candidate.canonicalPath.startsWith(cacheRoot)) {",
    "                            targetFile = candidate",
    "                        }",
    "                    }                }",
  ].join("\n");
  const withFakePackage = (version, source, fn, patches = []) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cleanway-share-intent-"));
    try {
      fs.mkdirSync(path.join(dir, "pkg", path.dirname(KT)), { recursive: true });
      fs.mkdirSync(path.join(dir, "patches"));
      fs.writeFileSync(path.join(dir, "pkg", "package.json"), JSON.stringify({ name: "expo-share-intent", version }));
      fs.writeFileSync(path.join(dir, "pkg", KT), source);
      for (const name of patches) fs.writeFileSync(path.join(dir, "patches", name), "--- a/x\n+++ b/x\n");
      fn(run(`--package-dir=${path.join(dir, "pkg")}`, `--patches-dir=${path.join(dir, "patches")}`));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };
  check("package.json takes expo-share-intent ^9.0.0, and 9.x is what is installed", () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(mobileDir, "package.json"), "utf8"));
    assert.strictEqual(pkg.dependencies["expo-share-intent"], "^9.0.0");
    const version = JSON.parse(fs.readFileSync(path.join(installed, "package.json"), "utf8")).version;
    assert.match(version, /^9\./);
  });
  check("the installed module carries the fix, no patch is left, and the share sheet takes text/plain only", () => {
    const r = run();
    assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    assert.ok(r.stdout.includes("carries the fix itself"), r.stdout);
    assert.ok(r.stdout.includes("no expo-share-intent patch in mobile/patches/"), r.stdout);
    assert.ok(fixed.includes(FIX), "the installed file holds upstream's fix, as 8.0.1 wrote it");
  });
  check("fails on the file 2.0.0–8.0.0 shipped, i.e. a module without the fix", () => {
    withFakePackage("8.0.0", fixed.replace(FIX, HOLE), (r) => {
      assert.strictEqual(r.status, 1, r.stdout + r.stderr);
      assert.ok(r.stdout.includes("File(context.cacheDir, fileName)"), r.stdout);
      assert.ok(r.stdout.includes("expo-share-intent 8.0.0 has the hole"), r.stdout);
    });
  });
  check("fails when the fixed module still has a patch next to it (the 5.1.1 one, forgotten)", () => {
    withFakePackage("9.0.0", fixed, (r) => {
      assert.strictEqual(r.status, 1, r.stdout + r.stderr);
      assert.ok(r.stdout.includes("expo-share-intent+5.1.1.patch is left behind"), r.stdout);
      assert.ok(r.stdout.includes("only if its canonical path is inside cacheDir"), "its own code passes");
    }, ["expo-share-intent+5.1.1.patch"]);
  });

  // --manifest: the AndroidManifest.xml a release build actually uses. An
  // android/ generated before app.json narrowed the filter still says text/*.
  const manifestWith = (types, fn) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cleanway-share-manifest-"));
    const file = path.join(dir, "AndroidManifest.xml");
    const data = types.map((t) => `<data android:mimeType="${t}"/>`).join("");
    fs.writeFileSync(file, `<manifest xmlns:android="http://schemas.android.com/apk/res/android">
  <application android:name=".MainApplication">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter><action android:name="android.intent.action.MAIN"/><category android:name="android.intent.category.LAUNCHER"/></intent-filter>
      <intent-filter><action android:name="android.intent.action.VIEW"/><data android:scheme="cleanway"/></intent-filter>
      <intent-filter><action android:name="android.intent.action.SEND"/><category android:name="android.intent.category.DEFAULT"/>${data}</intent-filter>
    </activity>
  </application>
</manifest>
`);
    try {
      fn(run(`--manifest=${file}`), file);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };
  check("--manifest passes a built manifest whose share filter is text/plain only", () => {
    manifestWith(["text/plain"], (r, file) => {
      assert.strictEqual(r.status, 0, r.stdout + r.stderr);
      assert.ok(r.stdout.includes(`ok: ${file}: MainActivity takes SEND for text/plain only`), r.stdout);
    });
  });
  check("--manifest fails an android/ generated with the old text/* filter, and a missing manifest", () => {
    manifestWith(["text/*"], (r) => {
      assert.strictEqual(r.status, 1, r.stdout + r.stderr);
      assert.ok(r.stdout.includes('"types":["text/*"]'), r.stdout);
      assert.ok(r.stdout.includes("expo prebuild -p android --clean"), r.stdout);
    });
    manifestWith(["text/plain", "text/html"], (r) => assert.strictEqual(r.status, 1, r.stdout + r.stderr));
    const missing = run(`--manifest=${path.join(os.tmpdir(), "cleanway-no-such-dir", "AndroidManifest.xml")}`);
    assert.strictEqual(missing.status, 1, missing.stdout + missing.stderr);
    assert.ok(missing.stdout.includes("no such file"), missing.stdout);
  });

  // The release build runs that check itself: a failed or skipped postinstall
  // leaves the mirror's old node_modules in place, and gradle never looks at
  // the Kotlin source, so without this a signed release with the hole builds.
  const { _patch: patchShare, SENTINEL: SHARE_SENTINEL } = require("../withShareIntentGuard.js");
  const out = patchShare(TEMPLATE);
  check("withShareIntentGuard: every non-debug pre<Variant>Build runs the check, before compiling", () => {
    assert.ok(out.includes("tasks.matching { it.name ==~ /pre\\w+Build/ && !(it.name ==~ /(?i).*debug.*/) }"));
    assert.ok(out.includes("task.doFirst {"));
  });
  check("withShareIntentGuard: runs scripts/check-share-intent.mjs from mobile/ on this android/'s manifest", () => {
    assert.ok(out.includes('["node", "scripts/check-share-intent.mjs",'));
    assert.ok(out.includes('"--manifest=" + cleanwayShareManifest'));
    assert.ok(out.includes('def cleanwayShareManifest = file("src/main/AndroidManifest.xml").getAbsolutePath()'));
    assert.ok(out.includes("def cleanwayShareCheckDir = rootDir.getAbsoluteFile().getParentFile()"));
    assert.ok(out.includes(".execute(null, cleanwayShareCheckDir)"));
    assert.ok(fs.existsSync(path.join(mobileDir, "scripts", "check-share-intent.mjs")));
  });
  check("withShareIntentGuard: a failed check fails the build, with no switch to skip it", () => {
    assert.ok(out.includes("if (cleanwayShareCheck.exitValue() != 0) {"));
    assert.ok(out.includes("throw new GradleException("));
    assert.ok(!out.includes("hasProperty"), "no -P switch");
  });
  check("withShareIntentGuard: appended after the android block, idempotent", () => {
    assert.ok(out.startsWith(TEMPLATE.trimEnd()));
    assert.strictEqual(patchShare(out), out);
    assert.strictEqual(out.split(`${SHARE_SENTINEL}:`).length, 2);
  });
  check("app.json registers withShareIntentGuard", () => {
    const plugins = JSON.parse(fs.readFileSync(path.join(mobileDir, "app.json"), "utf8")).expo.plugins || [];
    assert.ok(plugins.includes("./plugins/withShareIntentGuard"));
  });
}

// --- After prebuild: every plugin above landed in the generated android/ ------
// Each plugin does nothing when a new Expo template moves its anchor, so a
// template change shows up only as a release signed with the debug key, or
// one without its checks. scripts/check-prebuild-gradle.mjs reads the real
// prebuild output in the build mirror (docs/EXPO_UPGRADE_PLAN.md §3.2); here it
// is shown to pass on the plugins' own output and to fail without any one of them.
console.log("check-prebuild-gradle (plugins landed after expo prebuild):");
{
  const { spawnSync } = require("node:child_process");
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");
  const { _patch: patchDist } = require("../withDistributionGuard.js");
  const { _patch: patchShare } = require("../withShareIntentGuard.js");
  const script = path.join(__dirname, "..", "..", "scripts", "check-prebuild-gradle.mjs");
  const ACTIVITY = "class MainActivity : ReactActivity() {\n  override fun onCreate(savedInstanceState: Bundle?) {\n    setTheme(R.style.AppTheme);\n    super.onCreate(null)\n  }\n}\n";
  const steps = {
    withReleaseSigning: patchSigning,
    withAbiFilters: (g) => patchAbi(g, DEFAULT_ABIS),
    withSeedGuard: patchSeed,
    withDistributionGuard: (g) => patchDist(g, "rustore"),
    withShareIntentGuard: patchShare,
  };
  const prebuild = ({ skip = "" } = {}, ...args) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cleanway-prebuild-"));
    try {
      let gradle = TEMPLATE;
      for (const [name, step] of Object.entries(steps)) if (name !== skip) gradle = step(gradle);
      const javaDir = path.join(dir, "app", "src", "main", "java", "ai", "cleanway", "app");
      fs.mkdirSync(javaDir, { recursive: true });
      fs.writeFileSync(path.join(dir, "app", "build.gradle"), gradle);
      fs.writeFileSync(path.join(javaDir, "MainActivity.kt"), skip === "withDarkSystemBars" ? ACTIVITY : patchDarkBars(ACTIVITY));
      return spawnSync(process.execPath, [script, `--android=${dir}`, ...args], { encoding: "utf8" });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };
  check("passes when every plugin landed, and on the store it was generated for", () => {
    const r = prebuild({}, "--distribution=rustore");
    assert.strictEqual(r.status, 0, r.stdout + r.stderr);
    for (const m of ["release-signing", "abi-filters", "seed-guard", "distribution-guard", "share-intent-guard", "dark-system-bars"]) {
      assert.ok(r.stdout.includes(`cleanway-${m}`), m);
    }
  });
  check("fails when any one plugin found no anchor", () => {
    for (const name of [...Object.keys(steps), "withDarkSystemBars"]) {
      const r = prebuild({ skip: name });
      assert.strictEqual(r.status, 1, `${name}: ${r.stdout}${r.stderr}`);
      assert.ok(r.stdout.includes(`plugins/${name}.js found no anchor`), r.stdout);
    }
  });
  check("fails on an android/ generated for another store", () => {
    const r = prebuild({}, "--distribution=play");
    assert.strictEqual(r.status, 1, r.stdout + r.stderr);
    assert.ok(r.stdout.includes("generated for 'rustore', not 'play'"), r.stdout);
  });
}

// --- Expo SDK 58: native modules that are installed but never linked ---------
// expo-router 58 depends on react-native-drawer-layout, whose required peers
// (gesture-handler, reanimated, + worklets for reanimated 4) npm installs with
// it. react-native.config.js keeps their native code out of both apps; that
// holds only while nothing the app ships imports them.
console.log("not-linked native modules (react-native.config.js):");
{
  const fs = require("node:fs");
  const path = require("node:path");
  const mobileDir = path.join(__dirname, "..", "..");
  const NOT_LINKED = ["react-native-gesture-handler", "react-native-reanimated", "react-native-worklets"];
  const { dependencies } = require(path.join(mobileDir, "react-native.config.js"));
  check("gesture-handler, reanimated and worklets are linked on neither platform", () => {
    for (const name of NOT_LINKED) assert.deepStrictEqual(dependencies[name], { platforms: { android: null, ios: null } }, name);
  });
  check("package.json does not depend on them, nor on expo-router's drawer", () => {
    const pkg = JSON.parse(fs.readFileSync(path.join(mobileDir, "package.json"), "utf8"));
    for (const name of [...NOT_LINKED, "react-native-drawer-layout"]) {
      assert.ok(!(name in pkg.dependencies), `${name} is a direct dependency: link it (react-native.config.js) or drop it`);
    }
  });
  check("no app code imports them (or expo-router/drawer, expo-router/js-stack)", () => {
    const banned = [...NOT_LINKED, "react-native-drawer-layout", "expo-router/drawer", "expo-router/js-stack"];
    // Every module specifier a file names: import … from "x", import "x", require("x"), import("x").
    const specifierRe = /(?:from\s+|require\(\s*|import\(\s*|import\s+)["']([^"']+)["']/g;
    const isBanned = (spec) => banned.some((b) => spec === b || spec.startsWith(`${b}/`));
    const offenders = [];
    const walk = (dir) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.name === "node_modules" || entry.name === "android" || entry.name === "ios" || entry.name.startsWith(".")) continue;
        const p = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(p);
        else if (/\.(ts|tsx|js|jsx|mjs|cjs)$/.test(entry.name)) {
          const specs = [...fs.readFileSync(p, "utf8").matchAll(specifierRe)].map((m) => m[1]);
          if (specs.some(isBanned)) offenders.push(path.relative(mobileDir, p));
        }
      }
    };
    for (const dir of ["app", "src", "modules"]) walk(path.join(mobileDir, dir));
    assert.deepStrictEqual(offenders, []);
  });
}

console.log(`\n${passed} assertions passed`);

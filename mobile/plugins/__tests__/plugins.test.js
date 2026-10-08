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
// the anchors are unchanged in the SDK 54 / RN 0.81 prebuild output).
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

console.log("withDarkSystemBars:");
{
  // The Expo SDK 54 prebuild MainActivity.kt onCreate, verbatim.
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
  // Google Play target API 36 (Expo SDK 54): RN still relies on onBackPressed,
  // which Android 16 stops calling for targetSdk 36 apps unless predictive back
  // is opted out; and the legacy architecture is what reanimated 3 needs.
  check("app.json keeps predictive back off and the legacy architecture", () => {
    assert.strictEqual(appJson.android.predictiveBackGestureEnabled, false);
    assert.strictEqual(appJson.newArchEnabled, false);
  });
  check("app.json registers the dark-system-bars plugin", () => {
    assert.ok((appJson.plugins || []).includes("./plugins/withDarkSystemBars"));
  });
  check("expo-camera plugin disables Android audio recording", () => {
    const cam = (appJson.plugins || []).find((p) => Array.isArray(p) && p[0] === "expo-camera");
    assert.ok(cam, "expo-camera plugin entry present");
    assert.strictEqual(cam[1].recordAudioAndroid, false);
  });
}

console.log(`\n${passed} assertions passed`);

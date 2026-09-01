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

// A trimmed but structurally faithful Expo SDK 52 / RN 0.76 app/build.gradle.
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

console.log(`\n${passed} assertions passed`);

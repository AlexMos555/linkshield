#!/usr/bin/env node
/**
 * Tests for the Expo config plugins that shape the Android release build.
 *
 * These plugins rewrite `android/app/build.gradle` on every `expo prebuild`, and
 * the generated tree is not in git — so a silent regression here means a build
 * that is debug-signed or 40 MB fatter, with a green BUILD SUCCESSFUL either
 * way. That is exactly the kind of failure nobody notices until a store rejects
 * the artifact, hence real, committed assertions rather than ad-hoc checking.
 * The worst one is SMS access leaking into the browser-downloaded APK: Play
 * Protect then hard-blocks every sideloaded install.
 *
 * Plain node (no jest in mobile/): `node mobile/plugins/__tests__/plugins.test.js`
 */
const assert = require("node:assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { _patch: patchSigning } = require("../withReleaseSigning.js");
const { _patch: patchAbi, DEFAULT_ABIS } = require("../withAbiFilters.js");
const withRustoreVariant = require("../withRustoreVariant.js");
const {
  _patch: patchRustore,
  _writeManifest: writeRustoreManifest,
  RUSTORE_MANIFEST,
  MANIFEST_PATH,
  RECEIVER_CLASS,
  JOB_CLASS,
} = withRustoreVariant;

const MOBILE = path.join(__dirname, "..", "..");

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

console.log("withRustoreVariant (build type):");
{
  const out = patchRustore(TEMPLATE);
  const rustore = out.slice(out.indexOf("rustore {"));
  check("adds a rustore build type that copies release", () => {
    assert.match(rustore, /^rustore \{\s*\n\s*initWith release\n/);
    assert.ok(rustore.includes("matchingFallbacks = ['release']"));
  });
  check("puts it at the end of buildTypes, after release — initWith copies what release has then", () => {
    assert.match(out, /release \{[\s\S]*?\n        \}\n\n        \/\/ cleanway-rustore-variant[\s\S]*?rustore \{[\s\S]*?\n        \}\n    \}\n\}\n$/);
  });
  check("only inserts: everything else is byte-for-byte the template", () => {
    const start = out.indexOf("\n        // cleanway-rustore-variant");
    const end = out.indexOf("}\n", out.indexOf("rustore {")) + 2;
    assert.strictEqual(out.slice(0, start) + out.slice(end), TEMPLATE);
  });
  check("signing and ABI edits land in release in either plugin order; rustore inherits them", () => {
    const rustoreLast = patchRustore(patchAbi(patchSigning(TEMPLATE), DEFAULT_ABIS));
    const rustoreFirst = patchSigning(patchAbi(patchRustore(TEMPLATE), DEFAULT_ABIS));
    assert.strictEqual(rustoreFirst, rustoreLast);
    const release = rustoreLast.slice(rustoreLast.indexOf("release {"), rustoreLast.indexOf("rustore {"));
    assert.ok(release.includes("? signingConfigs.release : signingConfigs.debug"));
    assert.ok(release.includes('abiFilters "armeabi-v7a", "arm64-v8a"'));
    const own = rustoreLast.slice(rustoreLast.indexOf("rustore {"));
    assert.ok(!own.includes("signingConfig") && !own.includes("abiFilters"), "copied by initWith, not restated");
  });
  check("a brace inside a comment or a string does not move the insertion point", () => {
    const tricky = TEMPLATE.replace(
      "minifyEnabled enableProguardInReleaseBuilds",
      "minifyEnabled enableProguardInReleaseBuilds // }\n            resValue 'string', 'brace', '}'",
    );
    assert.match(patchRustore(tricky), /'\}'\n        \}\n\n        \/\/ cleanway-rustore-variant[\s\S]*?\n        \}\n    \}\n\}\n$/);
  });
  check("is idempotent across repeated prebuilds", () => {
    assert.strictEqual(patchRustore(out), out);
  });
  check("leaves unrecognised gradle untouched (fail-safe, never a broken build)", () => {
    assert.strictEqual(patchRustore("something { unrelated }"), "something { unrelated }");
    // No release to copy: `initWith release` would break configuration.
    const noRelease = "android {\n    buildTypes {\n        debug {\n        }\n    }\n}\n";
    assert.strictEqual(patchRustore(noRelease), noRelease);
    const unbalanced = "android {\n    buildTypes {\n        release {\n";
    assert.strictEqual(patchRustore(unbalanced), unbalanced);
  });
}

console.log("withRustoreVariant (manifest):");
{
  check("registers no main-manifest mod: SMS access can only come from the overlay", () => {
    const cfg = withRustoreVariant({ name: "t", slug: "t", android: {} });
    assert.deepStrictEqual(Object.keys(cfg.mods.android).sort(), ["appBuildGradle", "dangerous"]);
  });
  check("the overlay asks for RECEIVE_SMS only — never READ_SMS or SEND_SMS", () => {
    const perms = [...RUSTORE_MANIFEST.matchAll(/<uses-permission android:name="([^"]+)"/g)].map((m) => m[1]);
    assert.deepStrictEqual(perms, ["android.permission.RECEIVE_SMS"]);
  });
  check("the receiver is exported, BROADCAST_SMS-protected and listens for SMS_RECEIVED only", () => {
    const receiver = RUSTORE_MANIFEST.slice(RUSTORE_MANIFEST.indexOf("<receiver"), RUSTORE_MANIFEST.indexOf("</receiver>"));
    assert.ok(receiver.includes(`android:name="${RECEIVER_CLASS}"`));
    assert.ok(receiver.includes('android:exported="true"'));
    assert.ok(receiver.includes('android:permission="android.permission.BROADCAST_SMS"'));
    const actions = [...receiver.matchAll(/<action android:name="([^"]+)"/g)].map((m) => m[1]);
    assert.deepStrictEqual(actions, ["android.provider.Telephony.SMS_RECEIVED"]);
  });
  check("the receiver is declared off: nothing is checked until the person turns it on", () => {
    const receiver = RUSTORE_MANIFEST.slice(RUSTORE_MANIFEST.indexOf("<receiver"), RUSTORE_MANIFEST.indexOf("</receiver>"));
    assert.ok(receiver.includes('android:enabled="false"'));
  });
  check("the list refresh job is a private job service in the main process", () => {
    const service = RUSTORE_MANIFEST.slice(RUSTORE_MANIFEST.indexOf("<service"));
    const tag = service.slice(0, service.indexOf("/>"));
    assert.ok(tag.includes(`android:name="${JOB_CLASS}"`));
    assert.ok(tag.includes('android:exported="false"'));
    assert.ok(tag.includes('android:permission="android.permission.BIND_JOB_SERVICE"'));
    // The shield's write lock on the list is per process.
    assert.ok(!tag.includes("android:process"));
    assert.strictEqual([...RUSTORE_MANIFEST.matchAll(/<service\b/g)].length, 1);
  });
  check("the receiver and job classes exist in the module", () => {
    const src = path.join(MOBILE, "modules/cleanway-vpn/android/src/main/java", "ai", "cleanway", "app");
    assert.match(fs.readFileSync(path.join(src, "SmsReceiver.kt"), "utf8"), /class SmsReceiver\b/);
    assert.match(fs.readFileSync(path.join(src, "BlocklistRefreshJob.kt"), "utf8"), /class BlocklistRefreshJob\b/);
    assert.strictEqual(RECEIVER_CLASS, "ai.cleanway.app.SmsReceiver");
    assert.strictEqual(JOB_CLASS, "ai.cleanway.app.BlocklistRefreshJob");
  });
  check("the module manifest, merged into BOTH APKs, declares no SMS permission or receiver", () => {
    const manifest = fs.readFileSync(path.join(MOBILE, "modules/cleanway-vpn/android/src/main/AndroidManifest.xml"), "utf8");
    assert.ok(!/_SMS|_MMS|WAP_PUSH|Telephony\.|SmsReceiver/.test(manifest));
  });

  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cleanway-rustore-"));
  try {
    const main = path.join(root, "app", "src", "main", "AndroidManifest.xml");
    const overlay = path.join(root, MANIFEST_PATH);
    const MAIN = '<manifest xmlns:android="http://schemas.android.com/apk/res/android">\n  <uses-permission android:name="android.permission.INTERNET"/>\n</manifest>\n';
    fs.mkdirSync(path.dirname(main), { recursive: true });
    fs.writeFileSync(main, MAIN);

    check("writes the overlay into the rustore source set only", () => {
      assert.strictEqual(MANIFEST_PATH, path.join("app", "src", "rustore", "AndroidManifest.xml"));
      assert.strictEqual(writeRustoreManifest(root), "written");
      assert.strictEqual(fs.readFileSync(overlay, "utf8"), RUSTORE_MANIFEST);
    });
    check("never touches the main manifest", () => {
      assert.strictEqual(fs.readFileSync(main, "utf8"), MAIN);
      assert.deepStrictEqual(fs.readdirSync(path.join(root, "app", "src")).sort(), ["main", "rustore"]);
    });
    check("re-applying is a no-op", () => {
      assert.strictEqual(writeRustoreManifest(root), "unchanged");
      assert.strictEqual(fs.readFileSync(overlay, "utf8"), RUSTORE_MANIFEST);
    });
    check("an outdated generated overlay is brought up to date", () => {
      fs.writeFileSync(overlay, RUSTORE_MANIFEST.replace(":sms", ":old"));
      assert.strictEqual(writeRustoreManifest(root), "written");
      assert.strictEqual(fs.readFileSync(overlay, "utf8"), RUSTORE_MANIFEST);
    });
    check("a hand-written overlay is left alone", () => {
      const own = "<manifest/>\n";
      fs.writeFileSync(overlay, own);
      assert.strictEqual(writeRustoreManifest(root), "foreign");
      assert.strictEqual(fs.readFileSync(overlay, "utf8"), own);
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
}

// Guard the RuStore-facing app.json config: the four Expo-template
// permissions the app never uses must stay blocked, and expo-camera must
// not pull RECORD_AUDIO back in. (RuStore asks to justify each sensitive
// permission; docs/RUSTORE_SUBMISSION.md §3 declares mic/photos "No".)
{
  const appJson = JSON.parse(fs.readFileSync(path.join(MOBILE, "app.json"), "utf8")).expo;
  check("app.json requests no SMS access for every build — only the RuStore overlay may", () => {
    for (const perm of (appJson.android && appJson.android.permissions) || []) {
      assert.ok(!/SMS|MMS|WAP_PUSH/.test(perm), `${perm} would reach the browser-downloaded APK`);
    }
    assert.ok((appJson.plugins || []).includes("./plugins/withRustoreVariant"));
  });
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
  check("expo-camera plugin disables Android audio recording", () => {
    const cam = (appJson.plugins || []).find((p) => Array.isArray(p) && p[0] === "expo-camera");
    assert.ok(cam, "expo-camera plugin entry present");
    assert.strictEqual(cam[1].recordAudioAndroid, false);
  });
}

// The prebuild wiring itself, not just the helper: the registered mod must
// resolve the overlay under android/ from the mod request. Async, so last.
(async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cleanway-rustore-mod-"));
  try {
    const cfg = withRustoreVariant({ name: "t", slug: "t", android: {} });
    await cfg.mods.android.dangerous({
      ...cfg,
      modResults: null,
      modRequest: {
        platform: "android", modName: "dangerous", introspect: false,
        projectRoot: path.dirname(root), platformProjectRoot: root, nextMod: async (c) => c,
      },
    });
    check("the prebuild mod writes the overlay under android/", () => {
      assert.strictEqual(fs.readFileSync(path.join(root, MANIFEST_PATH), "utf8"), RUSTORE_MANIFEST);
    });
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
  console.log(`\n${passed} assertions passed`);
})().catch((e) => {
  console.error(e);
  process.exit(1);
});

/**
 * Expo config plugin: wire a real RELEASE signing config into android/app/build.gradle.
 *
 * Why this exists (docs/TELE2_LAUNCH_PLAN.md B1): `android/` is the managed
 * workflow — `expo prebuild` regenerates it, and Expo's template signs the
 * release build with the *debug* key ("signingConfig signingConfigs.debug").
 * A debug-signed APK installs fine by sideload, but no store (RuStore, Google
 * Play) will accept it. Any hand-edit to build.gradle is wiped on the next
 * prebuild, so the wiring has to be reapplied by a plugin every time.
 *
 * Security contract — the founder holds the keystore, this repo never does:
 *  - Credentials are read at build time from android/keystore.properties, which
 *    lives inside the git-ignored android/ tree and is NEVER committed.
 *  - If that file is absent, the release build falls back to debug signing —
 *    exactly today's behaviour — so a dev/CI build without the keystore still
 *    works and this plugin can never *break* the build, only upgrade it.
 *  - Losing the keystore means every user must uninstall/reinstall forever, so
 *    the founder generates it once and backs it up; see docs/RUSTORE_SUBMISSION.md.
 *
 * Robustness: each edit is idempotent (a sentinel guards re-application) and
 * anchored on substrings Expo/RN have kept stable for years. If an anchor ever
 * moves, the edit is skipped rather than mis-applied — the build stays
 * debug-signed (a clear, safe failure) instead of breaking.
 *
 * android/keystore.properties (founder creates, git-ignored):
 *   storeFile=cleanway-release.jks      # path relative to android/
 *   storePassword=********
 *   keyAlias=cleanway
 *   keyPassword=********
 */
const { withAppBuildGradle } = require("@expo/config-plugins");

const SENTINEL = "cleanway-release-signing";

// Loaded at file scope, before the `android {}` block, so both the signing
// config and the buildType selector can see it.
const KEYSTORE_LOADER = `// ${SENTINEL}: load release credentials from the git-ignored keystore.properties
def cleanwayKeystoreProps = new Properties()
def cleanwayKeystoreFile = rootProject.file("keystore.properties")
if (cleanwayKeystoreFile.exists()) {
    cleanwayKeystoreFile.withInputStream { cleanwayKeystoreProps.load(it) }
}
`;

// The release signing config — only populated when the properties file supplied
// a storeFile; otherwise it stays empty and we never select it.
const RELEASE_SIGNING_BLOCK = `{
            // ${SENTINEL}
            if (cleanwayKeystoreProps['storeFile']) {
                storeFile rootProject.file(cleanwayKeystoreProps['storeFile'])
                storePassword cleanwayKeystoreProps['storePassword']
                keyAlias cleanwayKeystoreProps['keyAlias']
                keyPassword cleanwayKeystoreProps['keyPassword']
            }
        }`;

// Pick the real release key when we have one, else debug (today's behaviour).
const SIGNING_SELECTOR =
  "signingConfig (cleanwayKeystoreProps['storeFile'] ? signingConfigs.release : signingConfigs.debug)";

function patch(contents) {
  if (contents.includes(SENTINEL)) return contents; // already applied

  let out = contents;

  // 1. Load the keystore properties at file scope, just before `android {`.
  const androidBlock = /\nandroid\s*\{/;
  if (androidBlock.test(out)) {
    out = out.replace(androidBlock, `\n${KEYSTORE_LOADER}\nandroid {`);
  } else {
    return contents; // unrecognised gradle — leave it entirely alone
  }

  // 2. Add a `release {}` signing config next to the existing `debug {}` one.
  const signingConfigs = /signingConfigs\s*\{/;
  if (!signingConfigs.test(out)) return contents;
  out = out.replace(signingConfigs, `signingConfigs {\n        release ${RELEASE_SIGNING_BLOCK}\n`);

  // 3. Point the RELEASE buildType at that config (not the debug key). The
  //    non-greedy spans require the literal `release {` first, so the debug
  //    buildType's identical line above it is never the one matched.
  const releaseSigning =
    /(buildTypes\s*\{[\s\S]*?release\s*\{[\s\S]*?)signingConfig\s+signingConfigs\.debug/;
  if (!releaseSigning.test(out)) return contents; // don't half-apply
  out = out.replace(releaseSigning, `$1${SIGNING_SELECTOR}`);

  return out;
}

module.exports = function withReleaseSigning(config) {
  return withAppBuildGradle(config, (cfg) => {
    if (cfg.modResults.language !== "groovy") return cfg; // .kts unsupported
    cfg.modResults.contents = patch(cfg.modResults.contents);
    return cfg;
  });
};

// Test seam: the pure gradle transform, so its behaviour (idempotent,
// fail-safe, correct anchors) can be verified without running `expo prebuild`.
module.exports._patch = patch;

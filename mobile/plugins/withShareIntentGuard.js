/**
 * Expo config plugin: an Android release build fails unless expo-share-intent
 * keeps a shared file inside the cache.
 *
 * Why (docs/EXPO_UPGRADE_PLAN.md §1.2, #318): expo-share-intent 2.0.0–8.0.0
 * copied a shared file to cacheDir/<the sender's file name>, so any app on the
 * phone could write "../shared_prefs/…" into Cleanway's private data. 1.0.6
 * (Expo SDK 54, 5.1.1) fixed it with a patch; since Expo SDK 58 the app
 * installs ^9.0.0, which has upstream's fix (8.0.1+). That is still not
 * enough on its own: the build mirror keeps its node_modules between runs,
 * so after a failed or partial install an old, unfixed copy can still be
 * there. Nothing in `expo prebuild` or gradle looks at that Kotlin source, so
 * the release would say BUILD SUCCESSFUL, signed, with the hole.
 *
 * What it adds to android/app/build.gradle: every non-debug
 * `pre<Variant>Build` task (release, and any other non-debug build type) runs
 * `node scripts/check-share-intent.mjs` from mobile/ before anything is
 * compiled, and the build fails when the check does. The check is the one CI
 * runs (the installed Kotlin keeps a shared file inside the cache, a fixed
 * version, no patch left behind, text/plain-only share filter), plus the
 * AndroidManifest.xml this android/ actually builds from, so an android/
 * generated before the filter was narrowed fails too. There is no switch to
 * skip it: a release without the fix is never what we want. Debug builds are
 * not checked.
 *
 * Fail-safe: groovy build files only; idempotent across prebuilds.
 */
const { withAppBuildGradle } = require("@expo/config-plugins");

const SENTINEL = "cleanway-share-intent-guard";

const GUARD = `
// ${SENTINEL}: no release with the shared-file path hole (plugins/withShareIntentGuard.js)
def cleanwayShareCheckDir = rootDir.getAbsoluteFile().getParentFile()
def cleanwayShareManifest = file("src/main/AndroidManifest.xml").getAbsolutePath()
tasks.matching { it.name ==~ /pre\\w+Build/ && !(it.name ==~ /(?i).*debug.*/) }.configureEach { task ->
    task.doFirst {
        def cleanwayShareCheck = ["node", "scripts/check-share-intent.mjs",
            "--manifest=" + cleanwayShareManifest].execute(null, cleanwayShareCheckDir)
        def cleanwayShareOut = new StringBuilder()
        def cleanwayShareErr = new StringBuilder()
        cleanwayShareCheck.waitForProcessOutput(cleanwayShareOut, cleanwayShareErr)
        if (cleanwayShareCheck.exitValue() != 0) {
            throw new GradleException(
                (cleanwayShareOut.toString() + cleanwayShareErr.toString()).trim() +
                "\\nThis release would let any app on the phone write into Cleanway's private files. " +
                "Run npm install in mobile/ (expo-share-intent ^9.0.0 has the fix), " +
                "then expo prebuild -p android --clean.")
        }
        logger.lifecycle(cleanwayShareOut.toString().trim())
    }
}
`;

function patch(contents) {
  if (contents.includes(SENTINEL)) return contents;
  return `${contents.trimEnd()}\n${GUARD}`;
}

module.exports = function withShareIntentGuard(config) {
  return withAppBuildGradle(config, (cfg) => {
    if (cfg.modResults.language !== "groovy") return cfg;
    cfg.modResults.contents = patch(cfg.modResults.contents);
    return cfg;
  });
};

module.exports._patch = patch;
module.exports.SENTINEL = SENTINEL;

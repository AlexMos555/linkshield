/**
 * Expo config plugin: an Android release build fails unless it says which
 * store it is for.
 *
 * Why (backlog rank 2): with EXPO_PUBLIC_DISTRIBUTION unset the app is the
 * site APK — a link to the web checkout, the "download the new version"
 * banner, no Play Billing. The documented Play AAB and RuStore APK were
 * built without the variable, so they came out as that build, and Google
 * Play's Payments and Device-and-Network-Abuse policies forbid exactly those
 * two things. Nothing failed: BUILD SUCCESSFUL either way.
 *
 * What it adds to android/app/build.gradle: before any task runs, if the
 * build packages a release APK (package*Release) or AAB (bundle*Release), it
 * runs `node plugins/distribution.js check` from mobile/, which fails the
 * build when the store is unset or unknown, when an AAB would be the site
 * build, or when android/ was generated for another store than this build
 * runs with (the value is baked in here, at prebuild). The rules and their
 * messages live in plugins/distribution.js, next to its tests.
 *
 * Debug builds and unit-test tasks are not checked. Fail-safe: groovy build
 * files only; re-running prebuild without --clean re-bakes the value.
 */
const { withAppBuildGradle } = require("@expo/config-plugins");
const { STORES, distributionOf } = require("./distribution");
const { buildEnv } = require("./store-billing-linking");

const SENTINEL = "cleanway-distribution-guard";
const BAKED_RE = /def cleanwayPrebuildDistribution = '[a-z0-9_-]*'/;

function guard(prebuild) {
  return `
// ${SENTINEL}: a release names its store (plugins/withDistributionGuard.js)
def cleanwayPrebuildDistribution = '${prebuild}'
gradle.taskGraph.whenReady { graph ->
    def cleanwayTasks = graph.allTasks.findAll { it.project == project }
    def cleanwayAab = cleanwayTasks.any { it.name ==~ /bundle\\w*Release/ }
    def cleanwayApk = cleanwayTasks.any { it.name ==~ /package\\w*Release/ }
    if (!cleanwayAab && !cleanwayApk) return
    def cleanwayCheck = ["node", "plugins/distribution.js", "check",
        "--prebuild=" + cleanwayPrebuildDistribution,
        "--artifact=" + (cleanwayAab ? "aab" : "apk")].execute(null, rootDir.getAbsoluteFile().getParentFile())
    def cleanwayOut = new StringBuilder()
    def cleanwayErr = new StringBuilder()
    cleanwayCheck.waitForProcessOutput(cleanwayOut, cleanwayErr)
    if (cleanwayCheck.exitValue() != 0) {
        throw new GradleException((cleanwayErr.toString() + cleanwayOut.toString()).trim())
    }
    logger.lifecycle(cleanwayOut.toString().trim())
}
`;
}

/**
 * Bakes the prebuild's store: one of STORES, "" when unset, or "invalid" for
 * anything else — so the env's own text never lands in build.gradle, and a
 * release from that android/ fails the "generated for another store" check
 * whatever it is built with.
 */
function bakedValue(prebuild) {
  const value = distributionOf({ EXPO_PUBLIC_DISTRIBUTION: prebuild });
  if (value === "" || STORES.includes(value)) return value;
  return "invalid";
}

function patch(contents, prebuild) {
  const value = bakedValue(prebuild);
  if (contents.includes(SENTINEL)) {
    return contents.replace(BAKED_RE, `def cleanwayPrebuildDistribution = '${value}'`);
  }
  return `${contents.trimEnd()}\n${guard(value)}`;
}

module.exports = function withDistributionGuard(config) {
  return withAppBuildGradle(config, (cfg) => {
    if (cfg.modResults.language !== "groovy") return cfg;
    const env = buildEnv(cfg.modRequest.projectRoot);
    cfg.modResults.contents = patch(cfg.modResults.contents, env.EXPO_PUBLIC_DISTRIBUTION ?? "");
    return cfg;
  });
};

module.exports._patch = patch;
module.exports.SENTINEL = SENTINEL;

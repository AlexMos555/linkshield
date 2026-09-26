/**
 * Expo config plugin: a release build fails when the APK would ship without
 * its starter blocklist.
 *
 * Why: the seed (modules/cleanway-vpn/android/src/main/assets/
 * dns-blocklist-v2.seed.bin, SeedBlocklist.kt) is what lets a fresh install
 * block known scam sites before its first 2.6 MB download from our US server
 * — the download most likely to be slow or cut in Russia. It is not in git
 * (2.6 MB, changes daily): mobile/scripts/fetch-seed-blocklist.sh downloads
 * and verifies it at release time, and the build mirror's `sync.sh`
 * (`rsync --delete`) removes it whenever the checkout has none. Without this
 * guard such a release still says BUILD SUCCESSFUL, the app logs
 * `seed_absent`, and nobody learns that new installs are unprotected until
 * their first sync.
 *
 * Scope: every non-debug variant's `pre<Variant>Build` task (release, and the
 * RuStore build type) — it fails before anything is compiled. Debug builds
 * never need a seed. To build a release without one on purpose (a local
 * test APK), pass `-PcleanwayNoSeed`.
 *
 * Fail-safe: groovy build files only; idempotent across prebuilds.
 */
const { withAppBuildGradle } = require("@expo/config-plugins");

const SENTINEL = "cleanway-seed-guard";

const GUARD = `
// ${SENTINEL}: no release without the starter blocklist (plugins/withSeedGuard.js)
def cleanwaySeed = file("../../modules/cleanway-vpn/android/src/main/assets/dns-blocklist-v2.seed.bin")
tasks.matching { it.name ==~ /pre\\w+Build/ && !(it.name ==~ /(?i).*debug.*/) }.configureEach { task ->
    task.doFirst {
        if (!cleanwaySeed.isFile() && !project.hasProperty("cleanwayNoSeed")) {
            throw new GradleException(
                "No starter blocklist at \${cleanwaySeed}: fresh installs of this build would block nothing " +
                "until their first sync. Run scripts/fetch-seed-blocklist.sh (after sync.sh), " +
                "or pass -PcleanwayNoSeed to build without one on purpose.")
        }
    }
}
`;

function patch(contents) {
  if (contents.includes(SENTINEL)) return contents;
  return `${contents.trimEnd()}\n${GUARD}`;
}

module.exports = function withSeedGuard(config) {
  return withAppBuildGradle(config, (cfg) => {
    if (cfg.modResults.language !== "groovy") return cfg;
    cfg.modResults.contents = patch(cfg.modResults.contents);
    return cfg;
  });
};

module.exports._patch = patch;
module.exports.SENTINEL = SENTINEL;

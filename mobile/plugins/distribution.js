/**
 * Which store an Android release is for — and the check that every release
 * build says so (plugins/withDistributionGuard.js runs it from gradle).
 *
 * EXPO_PUBLIC_DISTRIBUTION decides three things that store review checks:
 *   • the paywall: `site` links to the web checkout, a store build never does
 *     (Google Play Payments policy; src/utils/freemium.ts webCheckoutAllowed);
 *   • the "new version — download" banner from our server: `site` only (Play's
 *     Device and Network Abuse policy; selfUpdateAllowed);
 *   • Play Billing and the com.android.vending.BILLING permission: `play`
 *     only (react-native.config.js, plugins/store-billing-linking.js).
 * The app treats an unset value as `site`, so a forgotten export used to make
 * the Play AAB and the RuStore APK the site build, with BUILD SUCCESSFUL.
 * Now a release (any APK or AAB packaging task) must name its store, an AAB
 * is never the site build, and android/ must have been generated for the same
 * store (Gradle caches autolinking keyed on package.json, not on the env).
 *
 * The value is read like Expo reads it for the JS bundle: the environment
 * over the project's .env files (store-billing-linking.js buildEnv).
 *
 * CLI (from mobile/, what gradle runs):
 *   node plugins/distribution.js check --prebuild=<store> --artifact=apk|aab
 * exit 0 + a one-line summary, or exit 1 + what to do.
 */
"use strict";

const { buildEnv } = require("./store-billing-linking");

const STORES = ["site", "rustore", "play"];

const WHAT = {
  site: "the APK from cleanway.ai (web checkout, self-update)",
  rustore: "the RuStore build (no web checkout, no self-update, no Play Billing)",
  play: "the Google Play build (Play Billing only, no web checkout, no self-update)",
};

/**
 * The store named by the env, read exactly like the app (freemium.ts
 * distributionFor) and autolinking (store-billing-linking.js) read it:
 * trimmed and lower-cased, nothing else; "" when unset. Not cleaned up: the
 * app reads "play;" or "pl.ay" as the site build, so releaseCheck must see
 * it as it is and refuse it, never tidy it into "play".
 */
function distributionOf(env) {
  return String(env.EXPO_PUBLIC_DISTRIBUTION ?? "").trim().toLowerCase();
}

const HOW =
  "Export it for the WHOLE build, then regenerate android/ and build:\n" +
  "  export EXPO_PUBLIC_DISTRIBUTION=site     # APK for cleanway.ai/android  (assembleRelease)\n" +
  "  export EXPO_PUBLIC_DISTRIBUTION=rustore  # APK for RuStore              (assembleRelease)\n" +
  "  export EXPO_PUBLIC_DISTRIBUTION=play     # AAB for Google Play          (bundleRelease)\n" +
  "  CI=1 npx expo prebuild -p android --clean\n" +
  "docs/RUSTORE_SUBMISSION.md §2.";

/**
 * Decide whether a release build may go ahead.
 * @param {{distribution: string, prebuild: string, artifact: "apk"|"aab", revenueCatKey?: boolean}} input
 * @returns {{ok: boolean, message: string}}
 */
function releaseCheck({ distribution, prebuild, artifact, revenueCatKey = false }) {
  if (!STORES.includes(distribution)) {
    const seen = distribution ? `is ${JSON.stringify(distribution)}` : "is not set";
    return {
      ok: false,
      message:
        `Cleanway: EXPO_PUBLIC_DISTRIBUTION ${seen}. A release build must say which store it is for — ` +
        `site, rustore or play — or it comes out as the site build (web-checkout link, self-update ` +
        `banner, no Play Billing), which Google Play and RuStore reject.\n${HOW}`,
    };
  }
  if (distribution !== prebuild) {
    return {
      ok: false,
      message:
        `Cleanway: android/ was generated for ${prebuild ? JSON.stringify(prebuild) : "unset"} but this build runs with ` +
        `EXPO_PUBLIC_DISTRIBUTION=${distribution}. Gradle's autolinking (Play Billing or not) follows ` +
        `the prebuild, so the two halves would disagree. Regenerate with the same value:\n` +
        `  CI=1 npx expo prebuild -p android --clean`,
    };
  }
  if (artifact === "aab" && distribution === "site") {
    return {
      ok: false,
      message:
        "Cleanway: an App Bundle (AAB) is for a store, but EXPO_PUBLIC_DISTRIBUTION=site is the " +
        "APK from cleanway.ai — uploaded to Google Play it would link to the web checkout and offer " +
        "its own updates. For Google Play: EXPO_PUBLIC_DISTRIBUTION=play (RuStore: rustore), then " +
        "CI=1 npx expo prebuild -p android --clean and bundleRelease again.",
    };
  }
  let message = `Cleanway: building ${WHAT[distribution]} (EXPO_PUBLIC_DISTRIBUTION=${distribution}, ${artifact.toUpperCase()}).`;
  if (distribution === "play" && !revenueCatKey) {
    message +=
      "\nwarning: EXPO_PUBLIC_REVENUECAT_ANDROID_KEY is not set — the paywall will say that paying " +
      "in the app is coming soon (docs/runbooks/revenuecat.md §5).";
  }
  return { ok: true, message };
}

function argValue(args, name) {
  const hit = args.find((a) => a.startsWith(`--${name}=`));
  return hit === undefined ? "" : hit.slice(name.length + 3);
}

function main(argv) {
  const [command, ...args] = argv;
  if (command !== "check") {
    process.stderr.write("usage: node plugins/distribution.js check --prebuild=<store> --artifact=apk|aab\n");
    return 2;
  }
  const env = buildEnv(process.cwd());
  const result = releaseCheck({
    distribution: distributionOf(env),
    prebuild: distributionOf({ EXPO_PUBLIC_DISTRIBUTION: argValue(args, "prebuild") }),
    artifact: argValue(args, "artifact") === "aab" ? "aab" : "apk",
    // Presence only — the key itself is never printed.
    revenueCatKey: String(env.EXPO_PUBLIC_REVENUECAT_ANDROID_KEY ?? "").trim() !== "",
  });
  (result.ok ? process.stdout : process.stderr).write(result.message + "\n");
  return result.ok ? 0 : 1;
}

if (require.main === module) process.exitCode = main(process.argv.slice(2));

module.exports = { STORES, distributionOf, releaseCheck };

#!/usr/bin/env node
/**
 * After `expo prebuild -p android`: did every one of our Gradle / Kotlin
 * plugins actually land in the generated android/? Run from mobile/:
 *
 *   node scripts/check-prebuild-gradle.mjs [--android=android] [--distribution=site|rustore|play]
 *
 * Why (docs/EXPO_UPGRADE_PLAN.md §3.2, risk 3): the plugins below edit
 * android/app/build.gradle and MainActivity.kt, and when a new Expo template
 * moves the anchor they look for (or the file stops being Groovy), they do
 * nothing on purpose, so a plugin can never break a build. Gradle then says
 * BUILD SUCCESSFUL for a release that is signed with the debug key, ships
 * without its starter blocklist, skips the store or share-intent checks, or
 * has a white navigation bar. The plugin tests (plugins/__tests__) pin each
 * plugin against a copy of the template; this checks the real prebuild output
 * of the template in use. The build mirror runs it after every prebuild
 * (docs/RUSTORE_SUBMISSION.md §2); CI does not run prebuild.
 *
 * With --distribution, the store baked into build.gradle at prebuild
 * (plugins/withDistributionGuard.js) must be that one.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const mobile = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const arg = (name) => {
  const a = process.argv.find((x) => x.startsWith(`--${name}=`));
  return a === undefined ? undefined : a.slice(name.length + 3);
};
const android = resolve(mobile, arg("android") ?? "android");
const distribution = arg("distribution");

/** Marker → the plugin that writes it, in android/app/build.gradle. */
const GRADLE_MARKERS = {
  "cleanway-release-signing": "withReleaseSigning",
  "cleanway-abi-filters": "withAbiFilters",
  "cleanway-seed-guard": "withSeedGuard",
  "cleanway-distribution-guard": "withDistributionGuard",
  "cleanway-share-intent-guard": "withShareIntentGuard",
};
/** Marker → plugin, in MainActivity.kt. */
const ACTIVITY_MARKERS = { "cleanway-dark-system-bars": "withDarkSystemBars" };

function findMainActivity(dir) {
  if (!existsSync(dir)) return undefined;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) {
      const found = findMainActivity(p);
      if (found) return found;
    } else if (entry.name === "MainActivity.kt") {
      return p;
    }
  }
  return undefined;
}

const failures = [];
const ok = [];
const show = (p) => relative(mobile, p) || p;

const gradlePath = join(android, "app", "build.gradle");
if (!existsSync(gradlePath)) {
  failures.push(`${show(gradlePath)}: no such file (Kotlin DSL? the plugins only edit Groovy). Run expo prebuild -p android --clean`);
} else {
  const gradle = readFileSync(gradlePath, "utf8");
  for (const [marker, plugin] of Object.entries(GRADLE_MARKERS)) {
    if (gradle.includes(marker)) ok.push(`${show(gradlePath)}: ${marker} (${plugin})`);
    else failures.push(`${show(gradlePath)}: no ${marker}: plugins/${plugin}.js found no anchor in this template`);
  }
  if (distribution !== undefined) {
    const baked = gradle.match(/def cleanwayPrebuildDistribution = '([a-z0-9_-]*)'/);
    if (!baked) failures.push(`${show(gradlePath)}: no baked store (withDistributionGuard)`);
    else if (baked[1] !== distribution) {
      failures.push(`${show(gradlePath)}: generated for '${baked[1]}', not '${distribution}': EXPO_PUBLIC_DISTRIBUTION=${distribution} expo prebuild -p android --clean`);
    } else ok.push(`${show(gradlePath)}: generated for '${distribution}'`);
  }
}

const activity = findMainActivity(join(android, "app", "src", "main", "java"));
if (!activity) {
  failures.push(`${show(join(android, "app", "src", "main", "java"))}: no MainActivity.kt`);
} else {
  const kt = readFileSync(activity, "utf8");
  for (const [marker, plugin] of Object.entries(ACTIVITY_MARKERS)) {
    if (kt.includes(marker)) ok.push(`${show(activity)}: ${marker} (${plugin})`);
    else failures.push(`${show(activity)}: no ${marker}: plugins/${plugin}.js found no anchor in this template`);
  }
}

for (const line of ok) console.log(`ok: ${line}`);
if (failures.length > 0) {
  console.log("PREBUILD CHECK FAILED (docs/EXPO_UPGRADE_PLAN.md §3.2):");
  for (const f of failures) console.log(`  ${f}`);
  process.exit(1);
}

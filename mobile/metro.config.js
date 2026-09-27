/**
 * Metro config: Expo's defaults plus one fix.
 *
 * babel-preset-expo inlines every `process.env.EXPO_PUBLIC_*` into the code
 * at transform time, but Metro's transform cache is not keyed on those
 * values. A bundle built after one with a different value can reuse the old
 * inlined code: on 2026-09-27 a normal export made after a review export
 * (EXPO_PUBLIC_REVIEW_LINKS=1) still had the review switch on, which would
 * put unverified official links in a release APK. Folding the values into
 * `cacheVersion` gives each set of values its own cache entries.
 */
const { createHash } = require("crypto");
const { getDefaultConfig } = require("expo/metro-config");

const config = getDefaultConfig(__dirname);

const publicEnv = Object.keys(process.env)
  .filter((key) => key.startsWith("EXPO_PUBLIC_"))
  .sort()
  .map((key) => `${key}=${process.env[key]}`)
  .join("\n");

module.exports = {
  ...config,
  cacheVersion: `${config.cacheVersion ?? ""}+env:${createHash("sha256").update(publicEnv).digest("hex").slice(0, 16)}`,
};

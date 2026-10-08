/**
 * Which builds carry the Google Play purchase SDK's native half
 * (react-native-purchases → Play Billing Library, which adds the
 * com.android.vending.BILLING permission). Read by react-native.config.js
 * when Gradle autolinks native modules.
 *
 * Only the Google Play build (EXPO_PUBLIC_DISTRIBUTION=play) links it. The
 * APK from our site and the RuStore build never pay through Google Play, so
 * they carry neither the library nor the permission; their JS bundle drops
 * the SDK too (src/services/store-billing.ts).
 *
 * The value comes from the environment Gradle runs in, then the project's
 * .env files (as Expo's own bundling reads them) — the same source the JS
 * bundle is built from, so the two halves always agree.
 */
"use strict";

/** @param {Record<string, string | undefined>} env */
function storeBillingLinked(env) {
  return String(env.EXPO_PUBLIC_DISTRIBUTION ?? "").trim().toLowerCase() === "play";
}

/** process.env over the project's .env files (system env wins, as in Expo). */
function buildEnv(projectRoot) {
  let fromFiles = {};
  try {
    // A dependency of expo itself; absent only in odd installs — then
    // process.env alone decides.
    fromFiles = require("@expo/env").parseProjectEnv(projectRoot, { silent: true }).env || {};
  } catch {
    fromFiles = {};
  }
  return { ...fromFiles, ...process.env };
}

module.exports = { storeBillingLinked, buildEnv };

/**
 * Expo config plugin: keep only the ABIs real phones need in the APK.
 *
 * Why: `-PreactNativeArchitectures=…` does NOT slim the APK. In the RN template
 * that property only feeds `splits.abi.include`, and splits are disabled by
 * default (`enableSeparateBuildPerCPUArchitecture=false`), so every prebuilt
 * `.so` from every AAR still gets packaged. Measured on the first signed build:
 * 92 MB with arm64-v8a + armeabi-v7a + x86 + x86_64.
 *
 * `x86`/`x86_64` exist for EMULATORS — no retail Android phone ships them — so
 * dropping them costs zero real users and removes ~25 MB. That matters on the
 * Tele2 funnel, where people download over metered mobile data.
 *
 * Default keeps BOTH 32-bit and 64-bit ARM: `armeabi-v7a` covers the old budget
 * phones still common in RF, which are exactly the users most likely to be
 * phished. Going arm64-only would save ~20 MB more but silently exclude them —
 * not a trade we make by default. Override deliberately with
 * `CLEANWAY_ABIS=arm64-v8a` at prebuild time.
 *
 * Store builds are unaffected: the AAB carries every ABI and RuStore/Play split
 * per-device automatically.
 *
 * Fail-safe: if the `defaultConfig {` anchor is missing, the file is left
 * untouched (a fat APK, never a broken build). Idempotent across prebuilds.
 */
const { withAppBuildGradle } = require("@expo/config-plugins");

const SENTINEL = "cleanway-abi-filters";
const DEFAULT_ABIS = "armeabi-v7a,arm64-v8a";

function patch(contents, abis) {
  if (contents.includes(SENTINEL)) return contents;
  const anchor = /defaultConfig\s*\{/;
  if (!anchor.test(contents)) return contents;
  const list = abis.split(",").map((a) => `"${a.trim()}"`).join(", ");
  return contents.replace(
    anchor,
    `defaultConfig {\n        // ${SENTINEL}: emulator ABIs (x86*) are dead weight on a phone download\n        ndk {\n            abiFilters ${list}\n        }\n`,
  );
}

module.exports = function withAbiFilters(config) {
  return withAppBuildGradle(config, (cfg) => {
    if (cfg.modResults.language !== "groovy") return cfg;
    const abis = process.env.CLEANWAY_ABIS || DEFAULT_ABIS;
    cfg.modResults.contents = patch(cfg.modResults.contents, abis);
    return cfg;
  });
};

module.exports._patch = patch;
module.exports.DEFAULT_ABIS = DEFAULT_ABIS;

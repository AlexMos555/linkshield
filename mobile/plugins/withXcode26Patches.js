/**
 * Expo config plugin: make the Cleanway iOS build survive Xcode 26 / newer clang.
 *
 * Expo SDK 52 / RN 0.76.9 shipped for Xcode 15–16. On Xcode 26, three third-party
 * sources fail to compile. None are Cleanway code; each patch mirrors what the
 * upstream projects already do for newer toolchains. `expo prebuild` regenerates
 * ios/ and reinstalls Pods, wiping any hand-edits — so these patches must be
 * reapplied by a plugin on every prebuild. See
 * memory finding_2026-07-23_xcode26_expo52_toolchain_gap for the full analysis.
 *
 *   1. fmt 11.0.2         — `consteval FMT_STRING` rejected by Xcode 26 clang.
 *                           fmt has no #ifndef guard on FMT_USE_CONSTEVAL, so a -D
 *                           flag can't win; the header itself must flip it to 0
 *                           (which fmt already does for "Apple clang < 14").
 *   2. sentry-cocoa 8.41  — `std::vector<const T>`; libc++ in Xcode 26 dropped
 *                           `std::allocator<const T>` (never legal C++).
 *   3. expo-localization  — non-exhaustive `switch` over Calendar.Identifier;
 *                           iOS 26 added cases the module predates.
 *
 * Patches 1 & 2 touch Pods/ (which exist only after `pod install`), so they run
 * from the Podfile `post_install` hook. Patch 3 touches node_modules and is
 * applied directly at prebuild time.
 */
const { withDangerousMod } = require("@expo/config-plugins");
const fs = require("fs");
const path = require("path");

const POST_INSTALL_RUBY = `
    # --- Cleanway: Xcode 26 toolchain patches (see mobile/plugins/withXcode26Patches.js) ---
    fmt_base = File.join(installer.sandbox.root, 'fmt', 'include', 'fmt', 'base.h')
    if File.exist?(fmt_base)
      src = File.read(fmt_base)
      if src.include?("\#  define FMT_USE_CONSTEVAL 1")
        File.chmod(0644, fmt_base)
        File.write(fmt_base, src.gsub("\#  define FMT_USE_CONSTEVAL 1",
          "\#  define FMT_USE_CONSTEVAL 0  // Cleanway: consteval broken in Xcode 26 clang"))
        Pod::UI.puts "[Cleanway] patched fmt/base.h: FMT_USE_CONSTEVAL -> 0"
      end
    end
    sentry_hpp = File.join(installer.sandbox.root, 'Sentry', 'Sources', 'Sentry',
                           'include', 'SentryThreadMetadataCache.hpp')
    if File.exist?(sentry_hpp)
      src = File.read(sentry_hpp)
      if src.include?('std::vector<const ThreadHandleMetadataPair>')
        File.chmod(0644, sentry_hpp)
        File.write(sentry_hpp, src.gsub('std::vector<const ThreadHandleMetadataPair>',
                                        'std::vector<ThreadHandleMetadataPair>'))
        Pod::UI.puts "[Cleanway] patched SentryThreadMetadataCache.hpp: dropped const element type"
      end
    end
    # --- end Cleanway Xcode 26 patches ---
`;

function patchPodfile(podfilePath) {
  let src = fs.readFileSync(podfilePath, "utf8");
  if (src.includes("Cleanway: Xcode 26 toolchain patches")) return; // idempotent
  const marker = "post_install do |installer|";
  if (!src.includes(marker)) {
    throw new Error("withXcode26Patches: no post_install hook found in Podfile");
  }
  src = src.replace(marker, marker + "\n" + POST_INSTALL_RUBY);
  fs.writeFileSync(podfilePath, src);
}

function patchExpoLocalization(projectRoot) {
  const swift = path.join(
    projectRoot,
    "node_modules",
    "expo-localization",
    "ios",
    "LocalizationModule.swift"
  );
  if (!fs.existsSync(swift)) return;
  let src = fs.readFileSync(swift, "utf8");
  if (src.includes("Cleanway: iOS 26 added Calendar.Identifier")) return; // idempotent
  const anchor = `    case .iso8601:\n      return "iso8601"\n    }`;
  if (!src.includes(anchor)) return; // upstream changed; skip rather than mis-patch
  const replacement =
    `    case .iso8601:\n      return "iso8601"\n` +
    `    // Cleanway: iOS 26 added Calendar.Identifier cases this module predates;\n` +
    `    // BCP 47 "gregory" is the correct fallback for an unrecognised calendar.\n` +
    `    default:\n      return "gregory"\n    }`;
  fs.writeFileSync(swift, src.replace(anchor, replacement));
}

module.exports = function withXcode26Patches(config) {
  return withDangerousMod(config, [
    "ios",
    (cfg) => {
      patchExpoLocalization(cfg.modRequest.projectRoot);
      patchPodfile(path.join(cfg.modRequest.platformProjectRoot, "Podfile"));
      return cfg;
    },
  ]);
};

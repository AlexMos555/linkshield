/**
 * Expo config plugin: the iPhone's scam-text filter — an ILMessageFilterExtension
 * target ("CleanwaySmsFilter", ai.cleanway.app.sms-filter) embedded in the app.
 * docs/IOS.md §4.
 *
 * What it does on every `expo prebuild -p ios`:
 *   1. copies the engine (mobile/targets/sms-filter/Sources/CleanwayMessageEngine,
 *      the Swift twin of the Android message check) and the extension's entry
 *      point (mobile/targets/sms-filter/Extension) into ios/CleanwaySmsFilter/;
 *   2. copies the SAME assets the Android build ships — message_rules.json,
 *      root_zone_tlds.txt, message_model.json/.bin — from
 *      modules/cleanway-vpn/android/src/main/assets, so there is one vocabulary
 *      and one model for both platforms, never a fork;
 *   3. writes the extension's Info.plist, entitlements (the app group only) and
 *      privacy manifest, and adds the target, its build phases and the embed
 *      phase to the Xcode project;
 *   4. declares the target for EAS (extra.eas.build.experimental.ios.appExtensions)
 *      so EAS creates its bundle id and provisioning profile with the app group.
 *
 * OFFLINE ONLY. The Info.plist has no ILMessageFilterExtensionNetworkURL and
 * the code never calls deferQueryRequestToNetwork: server-assisted filtering
 * would send every message from an unknown sender to a server, and the
 * promise is that message text never leaves the phone.
 *
 * Why a hand-written plugin and not @bacons/apple-targets: one more build-time
 * dependency (and its own `targets/` layout and Xcode-project rewriting) for one
 * target that needs four copied files; expo-share-intent, already in the app,
 * adds its target with the same `xcode` API used here.
 */
const { withXcodeProject, withEntitlementsPlist, withDangerousMod } = require("@expo/config-plugins");
const fs = require("fs");
const path = require("path");

const TARGET = "CleanwaySmsFilter";
/** The extension's Swift module (Info.plist: $(PRODUCT_MODULE_NAME).MessageFilterExtension). */
const MODULE_NAME = "CleanwaySmsFilterExtension";
const ENGINE_DIR = path.join("targets", "sms-filter", "Sources", "CleanwayMessageEngine");
const EXTENSION_DIR = path.join("targets", "sms-filter", "Extension");
const ASSETS_DIR = path.join("modules", "cleanway-vpn", "android", "src", "main", "assets");
/** Shared with Android: one vocabulary, one root zone, one model. */
const ASSETS = ["message_rules.json", "root_zone_tlds.txt", "message_model.json", "message_model.bin"];
const DEPLOYMENT_TARGET = "15.1";

function bundleIdFor(appId) {
  return `${appId}.sms-filter`;
}

/** The app group the app and its extensions share (the one expo-share-intent also uses). */
function appGroupFor(appId) {
  return `group.${appId}`;
}

/** The extension's Info.plist. No network URL: the filter is offline-only. Pure. */
function infoPlist(appGroup) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>$(DEVELOPMENT_LANGUAGE)</string>
	<key>CFBundleDisplayName</key>
	<string>Cleanway</string>
	<key>CFBundleExecutable</key>
	<string>$(EXECUTABLE_NAME)</string>
	<key>CFBundleIdentifier</key>
	<string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>$(PRODUCT_NAME)</string>
	<key>CFBundlePackageType</key>
	<string>$(PRODUCT_BUNDLE_PACKAGE_TYPE)</string>
	<key>CFBundleShortVersionString</key>
	<string>$(MARKETING_VERSION)</string>
	<key>CFBundleVersion</key>
	<string>$(CURRENT_PROJECT_VERSION)</string>
	<key>CleanwayAppGroup</key>
	<string>${appGroup}</string>
	<key>NSExtension</key>
	<dict>
		<key>NSExtensionPointIdentifier</key>
		<string>com.apple.identitylookup.message-filter</string>
		<key>NSExtensionPrincipalClass</key>
		<string>$(PRODUCT_MODULE_NAME).MessageFilterExtension</string>
	</dict>
</dict>
</plist>
`;
}

/** The app group only: the extension reads the server's switches the app stored there. Pure. */
function entitlementsPlist(appGroup) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.application-groups</key>
	<array>
		<string>${appGroup}</string>
	</array>
</dict>
</plist>
`;
}

/** Collects nothing, tracks nothing, and reads no required-reason API. */
const PRIVACY_INFO = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>NSPrivacyTracking</key>
	<false/>
	<key>NSPrivacyTrackingDomains</key>
	<array/>
	<key>NSPrivacyCollectedDataTypes</key>
	<array/>
	<key>NSPrivacyAccessedAPITypes</key>
	<array/>
</dict>
</plist>
`;

/** extra.eas.build.experimental.ios.appExtensions with this target, once. Pure: returns new extra. */
function withEasAppExtension(extra, appId) {
  const out = JSON.parse(JSON.stringify(extra || {}));
  out.eas = out.eas || {};
  out.eas.build = out.eas.build || {};
  out.eas.build.experimental = out.eas.build.experimental || {};
  out.eas.build.experimental.ios = out.eas.build.experimental.ios || {};
  const list = out.eas.build.experimental.ios.appExtensions || [];
  const entry = {
    targetName: TARGET,
    bundleIdentifier: bundleIdFor(appId),
    entitlements: { "com.apple.security.application-groups": [appGroupFor(appId)] },
  };
  const at = list.findIndex((e) => e && e.targetName === TARGET);
  if (at >= 0) list[at] = entry;
  else list.push(entry);
  out.eas.build.experimental.ios.appExtensions = list;
  return out;
}

/** The files the target compiles and bundles, by build phase. */
function targetFiles(projectRoot) {
  const swift = (dir) => fs.readdirSync(path.join(projectRoot, dir)).filter((f) => f.endsWith(".swift")).sort();
  return {
    sources: [...swift(EXTENSION_DIR), ...swift(ENGINE_DIR)],
    resources: [...ASSETS, "PrivacyInfo.xcprivacy"],
    config: ["Info.plist", `${TARGET}.entitlements`],
  };
}

function writeFiles(projectRoot, platformRoot, appGroup) {
  const dir = path.join(platformRoot, TARGET);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  for (const src of [ENGINE_DIR, EXTENSION_DIR]) {
    for (const f of fs.readdirSync(path.join(projectRoot, src)).filter((n) => n.endsWith(".swift"))) {
      fs.copyFileSync(path.join(projectRoot, src, f), path.join(dir, f));
    }
  }
  for (const a of ASSETS) {
    const from = path.join(projectRoot, ASSETS_DIR, a);
    if (!fs.existsSync(from)) throw new Error(`[withSmsFilter] missing shared asset ${from}`);
    fs.copyFileSync(from, path.join(dir, a));
  }
  fs.writeFileSync(path.join(dir, "Info.plist"), infoPlist(appGroup));
  fs.writeFileSync(path.join(dir, `${TARGET}.entitlements`), entitlementsPlist(appGroup));
  fs.writeFileSync(path.join(dir, "PrivacyInfo.xcprivacy"), PRIVACY_INFO);
}

function mainDevelopmentTeam(project) {
  const configs = project.pbxXCBuildConfigurationSection();
  for (const key of Object.keys(configs)) {
    const bs = configs[key] && configs[key].buildSettings;
    if (bs && bs.DEVELOPMENT_TEAM && bs.PRODUCT_NAME && !String(bs.PRODUCT_NAME).includes("Extension")) {
      return String(bs.DEVELOPMENT_TEAM).replace(/"/g, "");
    }
  }
  return null;
}

function addTarget(project, files, { bundleId, version, buildNumber }) {
  if (project.pbxTargetByName(TARGET)) return;
  // Every file is referenced by its path from ios/ ("CleanwaySmsFilter/Info.plist"),
  // like the app's own "Cleanway/PrivacyInfo.xcprivacy". The xcode library
  // reuses any existing reference with the same path: with bare names, our
  // PrivacyInfo.xcprivacy and Info.plist were picked up by the next
  // extension's group (the share extension shipped OUR privacy manifest).
  const p = (f) => `${TARGET}/${f}`;
  const all = [...files.sources, ...files.resources, ...files.config].map(p);
  const group = project.addPbxGroup(all, TARGET);
  const groups = project.hash.project.objects.PBXGroup;
  // A group without a path of its own (the files carry it); the writer would print "path = undefined".
  delete groups[group.uuid].path;
  for (const key of Object.keys(groups)) {
    const g = groups[key];
    if (typeof g === "object" && g.name === undefined && g.path === undefined) project.addToPbxGroup(group.uuid, key);
  }
  // The xcode library assumes these sections exist; a project with one target has none.
  const objects = project.hash.project.objects;
  objects.PBXTargetDependency = objects.PBXTargetDependency || {};
  objects.PBXContainerItemProxy = objects.PBXContainerItemProxy || {};

  // app_extension: the library also embeds the product in the app ("Copy Files", PlugIns).
  const target = project.addTarget(TARGET, "app_extension", TARGET);
  project.addBuildPhase(files.sources.map(p), "PBXSourcesBuildPhase", "Sources", target.uuid);
  project.addBuildPhase(files.resources.map(p), "PBXResourcesBuildPhase", "Resources", target.uuid);
  project.addBuildPhase([], "PBXFrameworksBuildPhase", "Frameworks", target.uuid);

  const team = mainDevelopmentTeam(project);
  const configs = project.pbxXCBuildConfigurationSection();
  for (const key of Object.keys(configs)) {
    const bs = configs[key] && configs[key].buildSettings;
    if (!bs || bs.PRODUCT_NAME !== `"${TARGET}"`) continue;
    Object.assign(bs, {
      INFOPLIST_FILE: `"${TARGET}/Info.plist"`,
      CODE_SIGN_ENTITLEMENTS: `"${TARGET}/${TARGET}.entitlements"`,
      CODE_SIGN_STYLE: "Automatic",
      PRODUCT_BUNDLE_IDENTIFIER: `"${bundleId}"`,
      // Not "CleanwaySmsFilter": that is the app-side module's pod
      // (modules/cleanway-sms-filter), and the extension's swiftmodule in the
      // shared products dir shadowed it ("cannot find 'CleanwaySmsFilterModule'").
      PRODUCT_MODULE_NAME: MODULE_NAME,
      MARKETING_VERSION: `"${version}"`,
      CURRENT_PROJECT_VERSION: `"${buildNumber}"`,
      IPHONEOS_DEPLOYMENT_TARGET: DEPLOYMENT_TARGET,
      TARGETED_DEVICE_FAMILY: `"1"`,
      SWIFT_VERSION: "5.0",
      CLANG_ENABLE_MODULES: "YES",
      APPLICATION_EXTENSION_API_ONLY: "YES",
      GENERATE_INFOPLIST_FILE: "NO",
      // The engine runs per incoming SMS: unoptimised Swift is ~40× slower, so even a Debug build compiles it with -O.
      SWIFT_OPTIMIZATION_LEVEL: `"-O"`,
      SWIFT_COMPILATION_MODE: "wholemodule",
    });
    if (team) bs.DEVELOPMENT_TEAM = team;
  }
  if (team) project.addTargetAttribute("DevelopmentTeam", team, project.pbxTargetByName(TARGET));
}

function withSmsFilter(config) {
  const appId = config.ios && config.ios.bundleIdentifier;
  if (!appId) throw new Error("[withSmsFilter] ios.bundleIdentifier is required");
  const appGroup = appGroupFor(appId);
  config.extra = withEasAppExtension(config.extra, appId);

  // The app reads nothing from the extension (Apple does not let a filter write
  // anything back), but it must be in the same group to leave the switches there.
  config = withEntitlementsPlist(config, (cfg) => {
    const key = "com.apple.security.application-groups";
    const groups = Array.isArray(cfg.modResults[key]) ? cfg.modResults[key] : [];
    if (!groups.includes(appGroup)) cfg.modResults[key] = [...groups, appGroup];
    return cfg;
  });

  config = withDangerousMod(config, [
    "ios",
    (cfg) => {
      writeFiles(cfg.modRequest.projectRoot, cfg.modRequest.platformProjectRoot, appGroup);
      return cfg;
    },
  ]);

  return withXcodeProject(config, (cfg) => {
    addTarget(cfg.modResults, targetFiles(cfg.modRequest.projectRoot), {
      bundleId: bundleIdFor(appId),
      version: cfg.version,
      buildNumber: (cfg.ios && cfg.ios.buildNumber) || "1",
    });
    return cfg;
  });
}

module.exports = withSmsFilter;
module.exports._infoPlist = infoPlist;
module.exports._entitlements = entitlementsPlist;
module.exports._easExtra = withEasAppExtension;
module.exports._targetFiles = targetFiles;
module.exports.TARGET = TARGET;
module.exports.ASSETS = ASSETS;

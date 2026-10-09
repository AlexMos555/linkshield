/**
 * Expo config plugin: the Cleanway Safari Web Extension inside the iPhone
 * app. docs/IOS.md §2.5.
 *
 * Adds an app-extension target, `CleanwaySafariExtension`
 * (bundle id `<app>.safari-extension`, iOS 16.4+), embedded in the app. Its
 * web resources are COPIED at prebuild from the built extension-safari/ tree
 * (bash scripts/build-extensions.sh makes it from packages/extension-core) —
 * there is no second copy of the extension in git. EAS runs prebuild on
 * every build, so a build always carries the extension as it is in the repo;
 * locally, re-run prebuild after changing the extension.
 *
 * Where the extension comes from: `CLEANWAY_SAFARI_EXTENSION_DIR` if set
 * (the out-of-repo build mirror of docs/IOS.md §1.1 sets it), otherwise
 * `<mobile>/../extension-safari` (EAS uploads the whole repository). A
 * missing tree fails the prebuild — an app without its extension must not
 * build green.
 *
 * Why our own plugin and not @bacons/apple-targets: one target with a fixed
 * shape does not need a new dependency or its `targets/` convention, the six
 * other plugins here are our own too, and expo-share-intent already adds the
 * share-extension target the same way (the `xcode` project API Expo ships).
 *
 * The extension's native half (SafariWebExtensionHandler.swift, written
 * below) answers one message from the extension's background,
 * {type: "seen"} (packages/extension-core/src/background/safari-native.js):
 * it stores the time in the app group, and the app's "Protection on iPhone"
 * card reads it (modules/cleanway-safari) to say the extension really runs
 * on websites.
 *
 * iOS 16.4: the background is an ES-module service worker, which Safari
 * supports from 16.4 ("Added support for modules in background service
 * workers", Safari 16.4 release notes). The app itself stays at 15.1;
 * on older iOS the extension simply does not appear in Safari.
 */
const fs = require("fs");
const path = require("path");
const { withXcodeProject, withEntitlementsPlist, withInfoPlist } = require("@expo/config-plugins");
const plist = require("@expo/plist").default;

const pbxFile = require(
  require.resolve("xcode/lib/pbxFile", { paths: [path.dirname(require.resolve("@expo/config-plugins"))] }),
);

const TARGET = "CleanwaySafariExtension";
const DEPLOYMENT_TARGET = "16.4";
const DISPLAY_NAME = "Cleanway";
// What the extension needs at run time: everything the manifest references.
// The tree's own files (README, overrides/) stay out.
const RESOURCE_ENTRIES = ["manifest.json", "_locales", "src", "public", "styles"];
const RESOURCE_FOLDERS = ["_locales", "src", "public", "styles"];
const APP_GROUP_KEY = "com.apple.security.application-groups";
// The key the handler reads its app group from (Info.plist of the extension).
const INFO_APP_GROUP = "CleanwayAppGroup";
// The key the app reads the extension's bundle id from (its own Info.plist).
const INFO_EXTENSION_ID = "CleanwaySafariExtensionBundleId";
// Copied to the .appex root as PrivacyInfo.xcprivacy (see addFile below for the folder).
const PRIVACY_PATH = "Privacy/PrivacyInfo.xcprivacy";

function extensionBundleId(appId) {
  return `${appId}.safari-extension`;
}

function appGroupOf(appId) {
  return `group.${appId}`;
}

/** The built extension tree to bundle. Pure apart from the env default. */
function resolveExtensionSource(projectRoot, env = process.env) {
  const fromEnv = env.CLEANWAY_SAFARI_EXTENSION_DIR;
  return path.resolve(fromEnv && fromEnv.trim() ? fromEnv.trim() : path.join(projectRoot, "..", "extension-safari"));
}

/** Throws unless `dir` looks like the built Safari extension. */
function assertExtensionTree(dir) {
  const manifestPath = path.join(dir, "manifest.json");
  if (!fs.existsSync(manifestPath)) {
    throw new Error(
      `[withSafariExtension] No Safari extension at ${dir} (manifest.json missing). ` +
      "Run `bash scripts/build-extensions.sh` in the repo, or set CLEANWAY_SAFARI_EXTENSION_DIR to the repo's extension-safari/.",
    );
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (manifest.manifest_version !== 3) throw new Error("[withSafariExtension] extension-safari must be Manifest V3");
  const worker = manifest.background && manifest.background.service_worker;
  if (!worker || !fs.existsSync(path.join(dir, worker))) {
    throw new Error(`[withSafariExtension] background service worker ${worker} missing in ${dir}`);
  }
  for (const entry of RESOURCE_ENTRIES) {
    if (!fs.existsSync(path.join(dir, entry))) throw new Error(`[withSafariExtension] ${entry} missing in ${dir}`);
  }
  assertLocalizedNamesFit(dir, manifest);
  return manifest;
}

// App Store Connect rejects the upload when a Safari extension's localized
// name is over 40 characters (it refused the first TestFlight build for de,
// es, fr, id, pt and ru). Fail at prebuild instead of after a 20-minute archive.
const SAFARI_NAME_MAX = 40;

function assertLocalizedNamesFit(dir, manifest) {
  const key = /^__MSG_(\w+)__$/.exec(manifest.name || "");
  if (!key) return;
  const localesDir = path.join(dir, "_locales");
  for (const locale of fs.readdirSync(localesDir)) {
    const file = path.join(localesDir, locale, "messages.json");
    if (!fs.existsSync(file)) continue;
    const entry = JSON.parse(fs.readFileSync(file, "utf8"))[key[1]];
    const name = entry && entry.message;
    // Code points, as App Store Connect counts them (a 40-character Hindi name passes).
    if (typeof name !== "string" || [...name].length > SAFARI_NAME_MAX) {
      throw new Error(
        `[withSafariExtension] _locales/${locale}: "${key[1]}" must be a string of at most ${SAFARI_NAME_MAX} characters ` +
        `(App Store Connect rule for Safari extensions); got ${JSON.stringify(name)}. Edit packages/i18n-strings/src/${locale}.json.`,
      );
    }
  }
}

/** Copies the extension's resources into `<ios>/<TARGET>/Resources`, replacing what was there. */
function copyExtensionResources(srcDir, destDir) {
  fs.rmSync(destDir, { recursive: true, force: true });
  fs.mkdirSync(destDir, { recursive: true });
  for (const entry of RESOURCE_ENTRIES) {
    fs.cpSync(path.join(srcDir, entry), path.join(destDir, entry), {
      recursive: true,
      filter: (src) => path.basename(src) !== ".DS_Store",
    });
  }
  return RESOURCE_ENTRIES.slice();
}

function infoPlistContent(appGroup) {
  return plist.build({
    CFBundleDevelopmentRegion: "$(DEVELOPMENT_LANGUAGE)",
    CFBundleDisplayName: DISPLAY_NAME,
    CFBundleExecutable: "$(EXECUTABLE_NAME)",
    CFBundleIdentifier: "$(PRODUCT_BUNDLE_IDENTIFIER)",
    CFBundleInfoDictionaryVersion: "6.0",
    CFBundleName: "$(PRODUCT_NAME)",
    CFBundlePackageType: "$(PRODUCT_BUNDLE_PACKAGE_TYPE)",
    CFBundleShortVersionString: "$(MARKETING_VERSION)",
    CFBundleVersion: "$(CURRENT_PROJECT_VERSION)",
    [INFO_APP_GROUP]: appGroup,
    NSExtension: {
      NSExtensionPointIdentifier: "com.apple.Safari.web-extension",
      NSExtensionPrincipalClass: "$(PRODUCT_MODULE_NAME).SafariWebExtensionHandler",
    },
  });
}

function entitlementsContent(appGroup) {
  return plist.build({ [APP_GROUP_KEY]: [appGroup] });
}

// The handler reads and writes the app group's UserDefaults (required-reason
// API: 1C8F.1, "app group shared with the containing app"). Nothing collected,
// no tracking.
function privacyInfoContent() {
  return plist.build({
    NSPrivacyTracking: false,
    NSPrivacyTrackingDomains: [],
    NSPrivacyCollectedDataTypes: [],
    NSPrivacyAccessedAPITypes: [
      {
        NSPrivacyAccessedAPIType: "NSPrivacyAccessedAPICategoryUserDefaults",
        NSPrivacyAccessedAPITypeReasons: ["1C8F.1"],
      },
    ],
  });
}

const HANDLER_SWIFT = `import Foundation
import SafariServices

// Generated by mobile/plugins/withSafariExtension.js — edit it there.
//
// The native half of the Cleanway Safari extension. The extension's
// background sends {type: "seen"} (at most every 6 hours) after a content
// script reached it from a real web page; this stores the time in the app
// group, where the Cleanway app reads it to show that the extension works.
// Nothing about the page is sent or stored.
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    static let lastSeenKey = "safariExtensionLastSeenMs"

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let message: Any?
        if #available(iOS 17.0, *) {
            message = item?.userInfo?[SFExtensionMessageKey]
        } else {
            message = item?.userInfo?["message"]
        }

        var ok = false
        if let body = message as? [String: Any], body["type"] as? String == "seen",
           let group = Bundle.main.object(forInfoDictionaryKey: "${INFO_APP_GROUP}") as? String,
           let defaults = UserDefaults(suiteName: group) {
            defaults.set(Date().timeIntervalSince1970 * 1000, forKey: Self.lastSeenKey)
            ok = true
        }

        let response = NSExtensionItem()
        let reply: [String: Any] = ["ok": ok]
        if #available(iOS 17.0, *) {
            response.userInfo = [SFExtensionMessageKey: reply]
        } else {
            response.userInfo = ["message": reply]
        }
        context.completeRequest(returningItems: [response], completionHandler: nil)
    }
}
`;

/** Writes the target's own files into `<ios>/<TARGET>/`. */
function writeTargetFiles(targetDir, appGroup) {
  fs.mkdirSync(targetDir, { recursive: true });
  fs.writeFileSync(path.join(targetDir, "SafariWebExtensionHandler.swift"), HANDLER_SWIFT);
  fs.writeFileSync(path.join(targetDir, `${TARGET}-Info.plist`), infoPlistContent(appGroup));
  fs.writeFileSync(path.join(targetDir, `${TARGET}.entitlements`), entitlementsContent(appGroup));
  fs.mkdirSync(path.join(targetDir, "Privacy"), { recursive: true });
  fs.writeFileSync(path.join(targetDir, PRIVACY_PATH), privacyInfoContent());
}

/** Build settings of the extension target. Pure. */
function targetBuildSettings({ bundleId, version, buildNumber, devTeam, debug }) {
  const s = {
    APPLICATION_EXTENSION_API_ONLY: "YES",
    CLANG_ENABLE_MODULES: "YES",
    CODE_SIGN_ENTITLEMENTS: `"${TARGET}/${TARGET}.entitlements"`,
    CODE_SIGN_STYLE: "Automatic",
    CURRENT_PROJECT_VERSION: `"${buildNumber}"`,
    GENERATE_INFOPLIST_FILE: "NO",
    INFOPLIST_FILE: `"${TARGET}/${TARGET}-Info.plist"`,
    IPHONEOS_DEPLOYMENT_TARGET: DEPLOYMENT_TARGET,
    LD_RUNPATH_SEARCH_PATHS: '"$(inherited) @executable_path/Frameworks @executable_path/../../Frameworks"',
    MARKETING_VERSION: `"${version}"`,
    PRODUCT_BUNDLE_IDENTIFIER: `"${bundleId}"`,
    PRODUCT_NAME: `"${TARGET}"`,
    SDKROOT: "iphoneos",
    SKIP_INSTALL: "YES",
    SWIFT_VERSION: "5.0",
    TARGETED_DEVICE_FAMILY: "1", // iPhone only, like the app (app.json supportsTablet: false)
  };
  if (debug) {
    s.SWIFT_ACTIVE_COMPILATION_CONDITIONS = "DEBUG";
    s.SWIFT_OPTIMIZATION_LEVEL = '"-Onone"';
  }
  if (devTeam) s.DEVELOPMENT_TEAM = devTeam;
  return s;
}

function mainAppDevelopmentTeam(project) {
  const first = project.getFirstTarget();
  const list = project.pbxXCConfigurationList()[first.firstTarget.buildConfigurationList];
  const configs = project.pbxXCBuildConfigurationSection();
  for (const ref of (list && list.buildConfigurations) || []) {
    const team = configs[ref.value] && configs[ref.value].buildSettings.DEVELOPMENT_TEAM;
    if (team) return String(team).replace(/"/g, "");
  }
  return null;
}

// A file reference of our own. Not addPbxGroup()/addBuildPhase() with paths:
// those reuse ANY existing reference with the same path. For the same reason
// our privacy manifest sits in Privacy/: expo-share-intent looks up the path
// "PrivacyInfo.xcprivacy" for its own target and, whichever plugin runs first,
// would otherwise share one file reference between the two extensions.
function addFile(project, relPath, opts) {
  const file = new pbxFile(relPath, opts);
  file.uuid = project.generateUuid();
  file.fileRef = project.generateUuid();
  project.addToPbxFileReferenceSection(file);
  return file;
}

function addToPhase(project, phase, file, phaseName) {
  project.addToPbxBuildFileSection(file);
  phase.files.push({ value: file.uuid, comment: `${file.basename} in ${phaseName}` });
}

function addTargetToProject(project, { bundleId, version, buildNumber }) {
  const devTeam = mainAppDevelopmentTeam(project);
  const objects = project.hash.project.objects;
  // Missing in a project with a single target (xcode lib's addTarget assumes them).
  objects.PBXTargetDependency = objects.PBXTargetDependency || {};
  objects.PBXContainerItemProxy = objects.PBXContainerItemProxy || {};

  // The target, its product embedded in the app ("Copy Files" → PlugIns),
  // and the app's dependency on it.
  const target = project.addTarget(TARGET, "app_extension", TARGET, bundleId);

  // Files: the handler, the privacy manifest, the web resources (the four
  // directories as folder references, so their layout lands unchanged at
  // the root of the .appex where Safari looks for manifest.json).
  const handler = addFile(project, "SafariWebExtensionHandler.swift");
  const info = addFile(project, `${TARGET}-Info.plist`);
  const entitlements = addFile(project, `${TARGET}.entitlements`, { lastKnownFileType: "text.plist.entitlements" });
  const privacy = addFile(project, PRIVACY_PATH, { lastKnownFileType: "text.xml" });
  const manifest = addFile(project, "Resources/manifest.json", { lastKnownFileType: "text.json" });
  const folders = RESOURCE_FOLDERS.map((dir) => addFile(project, `Resources/${dir}`, { lastKnownFileType: "folder" }));

  const group = project.addPbxGroup([], TARGET, TARGET);
  for (const f of [handler, info, entitlements, privacy, manifest, ...folders]) {
    group.pbxGroup.children.push({ value: f.fileRef, comment: f.basename });
  }
  const mainGroupId = project.getFirstProject().firstProject.mainGroup;
  objects.PBXGroup[mainGroupId].children.push({ value: group.uuid, comment: TARGET });

  const sources = project.addBuildPhase([], "PBXSourcesBuildPhase", "Sources", target.uuid).buildPhase;
  addToPhase(project, sources, handler, "Sources");
  const resources = project.addBuildPhase([], "PBXResourcesBuildPhase", "Resources", target.uuid).buildPhase;
  for (const f of [privacy, manifest, ...folders]) addToPhase(project, resources, f, "Resources");
  project.addBuildPhase([], "PBXFrameworksBuildPhase", "Frameworks", target.uuid);

  const list = project.pbxXCConfigurationList()[target.pbxNativeTarget.buildConfigurationList];
  const configs = project.pbxXCBuildConfigurationSection();
  for (const ref of list.buildConfigurations) {
    const cfg = configs[ref.value];
    cfg.buildSettings = targetBuildSettings({ bundleId, version, buildNumber, devTeam, debug: cfg.name === "Debug" });
  }
  if (devTeam) {
    project.addTargetAttribute("DevelopmentTeam", devTeam, target);
  }
  return target;
}

/** EAS credentials: the extension needs its own provisioning profile with the app group. */
function addEasAppExtension(config, { bundleId, appGroup }) {
  config.extra = config.extra || {};
  const eas = (config.extra.eas = config.extra.eas || {});
  const build = (eas.build = eas.build || {});
  const experimental = (build.experimental = build.experimental || {});
  const ios = (experimental.ios = experimental.ios || {});
  const list = (ios.appExtensions = ios.appExtensions || []);
  const entry = { targetName: TARGET, bundleIdentifier: bundleId, entitlements: { [APP_GROUP_KEY]: [appGroup] } };
  const at = list.findIndex((e) => e && e.targetName === TARGET);
  if (at >= 0) list[at] = entry;
  else list.push(entry);
  return config;
}

function withSafariExtension(config) {
  const appId = config.ios && config.ios.bundleIdentifier;
  if (!appId) throw new Error("[withSafariExtension] ios.bundleIdentifier is required");
  const bundleId = extensionBundleId(appId);
  const appGroup = appGroupOf(appId);

  config = addEasAppExtension(config, { bundleId, appGroup });

  // The app reads the extension's state and the "seen" time from the same group.
  config = withEntitlementsPlist(config, (cfg) => {
    const groups = new Set(cfg.modResults[APP_GROUP_KEY] || []);
    groups.add(appGroup);
    cfg.modResults[APP_GROUP_KEY] = [...groups];
    return cfg;
  });
  config = withInfoPlist(config, (cfg) => {
    cfg.modResults[INFO_EXTENSION_ID] = bundleId;
    cfg.modResults[INFO_APP_GROUP] = appGroup;
    return cfg;
  });

  return withXcodeProject(config, (cfg) => {
    const { projectRoot, platformProjectRoot } = cfg.modRequest;
    const source = resolveExtensionSource(projectRoot);
    assertExtensionTree(source);
    const targetDir = path.join(platformProjectRoot, TARGET);
    writeTargetFiles(targetDir, appGroup);
    copyExtensionResources(source, path.join(targetDir, "Resources"));

    const project = cfg.modResults;
    if (!project.pbxTargetByName(TARGET)) {
      addTargetToProject(project, {
        bundleId,
        version: cfg.version,
        buildNumber: (cfg.ios && cfg.ios.buildNumber) || "1",
      });
    }
    return cfg;
  });
}

module.exports = withSafariExtension;
module.exports._internals = {
  TARGET,
  DEPLOYMENT_TARGET,
  RESOURCE_ENTRIES,
  INFO_APP_GROUP,
  INFO_EXTENSION_ID,
  PRIVACY_PATH,
  extensionBundleId,
  appGroupOf,
  resolveExtensionSource,
  assertExtensionTree,
  assertLocalizedNamesFit,
  SAFARI_NAME_MAX,
  copyExtensionResources,
  infoPlistContent,
  entitlementsContent,
  privacyInfoContent,
  targetBuildSettings,
  addEasAppExtension,
  HANDLER_SWIFT,
};

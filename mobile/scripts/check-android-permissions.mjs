#!/usr/bin/env node
/**
 * Permission guard for the browser-downloaded Android APK — run with
 * `node mobile/scripts/check-android-permissions.mjs` (CI: the mobile job).
 *
 * What this build promises never to ask for, pinned so that no "small"
 * change can slip it in:
 *  - no SMS permissions: message text is checked only when the person
 *    hands it over, and never leaves the phone;
 *  - no phone-state, call-log or call-answering permissions and no
 *    call-screening role: call awareness comes from the audio mode alone
 *    (CallState.kt), which needs nothing;
 *  - no notification listener, no accessibility service, no overlay
 *    (SYSTEM_ALERT_WINDOW stays blocked), no microphone;
 *  - none of the other permissions Play reviews as special access (exact
 *    alarms, all-packages visibility, installing packages, all-files
 *    access, background location, usage stats) — the shield needs none;
 *  - exactly one special-access permission, on purpose:
 *    REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, declared once, in the native
 *    module's manifest, next to its justification (SPECIAL_ALLOWED below).
 *
 * And what it does ask for: the permissions our own config puts in the
 * merged manifest are pinned (DECLARED below), with BIND_VPN_SERVICE in the
 * native module's manifest only, never in app.json (MODULE_ONLY below).
 *
 * Checked: app.json's android.permissions (expo prebuild merges it into the
 * manifest), the native module's manifest and Kotlin sources, and the config
 * plugins. The Kotlin suite has the same list (PolicyGuardTest) but does not
 * run in CI. app.json's blockedPermissions must keep the phone permissions
 * listed, so that a library cannot bring one in at manifest-merge time.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const mobile = resolve(here, "..");

const FORBIDDEN = [
  "RECEIVE_SMS", "READ_SMS", "SEND_SMS", "RECEIVE_MMS",
  "READ_PHONE_STATE", "READ_PHONE_NUMBERS", "READ_CALL_LOG", "WRITE_CALL_LOG",
  "ANSWER_PHONE_CALLS", "CALL_PHONE", "PROCESS_OUTGOING_CALLS",
  "ROLE_CALL_SCREENING", "CallScreeningService", "InCallService",
  "BIND_NOTIFICATION_LISTENER_SERVICE", "NotificationListenerService",
  "BIND_ACCESSIBILITY_SERVICE", "AccessibilityService",
  "SYSTEM_ALERT_WINDOW", "RECORD_AUDIO",
];

/**
 * Play special-access permissions this app does not use. Listed so that a
 * library or a "quick fix" cannot add one without this file changing too.
 */
const FORBIDDEN_SPECIAL = [
  "SCHEDULE_EXACT_ALARM", "USE_EXACT_ALARM", "QUERY_ALL_PACKAGES", "REQUEST_INSTALL_PACKAGES",
  "MANAGE_EXTERNAL_STORAGE", "ACCESS_BACKGROUND_LOCATION", "PACKAGE_USAGE_STATS",
];

/**
 * The special-access permissions this app DOES declare, each allowed in one
 * file only and only with its justification beside it. Adding one here is a
 * product decision, not a build fix: it changes what the Play listing must
 * justify.
 *
 *  - REQUEST_IGNORE_BATTERY_OPTIMIZATIONS (2026-10, "Keep protection on"):
 *    shows Android's one-question battery dialog for this app instead of a
 *    list of every app. Play permits it for a "safety app" whose core
 *    function battery optimisation breaks — OEM battery managers kill the
 *    always-on scam shield overnight. docs/MOBILE_AUTO_PROTECTION.md
 *    "Keeping the shield alive" holds the justification for the listing.
 */
const SPECIAL_ALLOWED = [
  {
    permission: "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
    file: join("modules", "cleanway-vpn", "android", "src", "main", "AndroidManifest.xml"),
    justification: "MOBILE_AUTO_PROTECTION.md",
  },
];

const MODULE_MANIFEST = join("modules", "cleanway-vpn", "android", "src", "main", "AndroidManifest.xml");

/**
 * Every permission our own config adds to the merged manifest: app.json's
 * android.permissions plus the module manifests' <uses-permission> entries.
 * Config plugins and libraries add the rest (CAMERA, VIBRATE, INTERNET…;
 * docs/STORES.md §6.4 lists the whole APK). Pinned so that moving one
 * between app.json and a manifest cannot drop it from the APK.
 */
const DECLARED = [
  "android.permission.ACCESS_NETWORK_STATE",
  "android.permission.BIND_VPN_SERVICE",
  "android.permission.FOREGROUND_SERVICE",
  "android.permission.FOREGROUND_SERVICE_SPECIAL_USE",
  "android.permission.POST_NOTIFICATIONS",
  "android.permission.RECEIVE_BOOT_COMPLETED",
  "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
];

/**
 * Declared in the native module's manifest, never in app.json. expo-constants
 * embeds the public app config, android.permissions included, in the iOS app
 * (EXConstants.bundle/app.config), and App Review's scan flagged the iOS
 * build as "contains VPN functionality" (2026-10-30). The module manifest
 * reaches the Android build only; the merged manifest is the same. Not via a
 * config plugin either: AndroidConfig.Permissions.withPermissions writes the
 * permission back into config.android.permissions, i.e. the public config.
 */
const MODULE_ONLY = ["android.permission.BIND_VPN_SERVICE"];

/** Phone permissions the app config must actively strip at manifest merge. */
const MUST_BLOCK = [
  "android.permission.SYSTEM_ALERT_WINDOW",
  "android.permission.RECORD_AUDIO",
  "android.permission.READ_PHONE_STATE",
  "android.permission.READ_CALL_LOG",
  "android.permission.ANSWER_PHONE_CALLS",
  "android.permission.CALL_PHONE",
];

/** A declaration, a string constant or a class reference — not a mention in a comment. */
function declares(text, needle) {
  const re = new RegExp(
    `(uses-permission[^>]*${needle}|permission\\.${needle}|"[A-Z_.]*${needle}"|extends\\s+${needle}|:\\s*${needle}\\(|import\\s+[\\w.]*${needle})`,
  );
  return re.test(text);
}

/** The permission names a manifest requests: comments and tools:node="remove" entries left out. */
function usesPermissions(xml) {
  return [...xml.replace(/<!--[\s\S]*?-->/g, "").matchAll(/<uses-permission\b([^>]*)>/g)]
    .filter((m) => !/tools:node\s*=\s*"remove"/.test(m[1]))
    .map((m) => /android:name\s*=\s*"([^"]+)"/.exec(m[1])?.[1])
    .filter(Boolean);
}

/** Expo prefixes a bare name the same way (prefixAndroidPermissionsIfNecessary). */
const fullName = (p) => (p.includes(".") ? p : `android.permission.${p}`);

function walk(dir, exts, acc = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (name === "node_modules" || name === "__tests__") continue;
    if (statSync(p).isDirectory()) walk(p, exts, acc);
    else if (exts.some((e) => name.endsWith(e))) acc.push(p);
  }
  return acc;
}

const failures = [];

// 1. app.json: permissions asked for, and the block list kept.
const app = JSON.parse(readFileSync(join(mobile, "app.json"), "utf8"));
const asked = app.expo?.android?.permissions ?? [];
for (const p of asked) {
  if (FORBIDDEN.some((f) => p.endsWith(f))) failures.push(`app.json android.permissions asks for ${p}`);
}
const blocked = new Set(app.expo?.android?.blockedPermissions ?? []);
for (const p of MUST_BLOCK) {
  if (!blocked.has(p)) failures.push(`app.json android.blockedPermissions no longer strips ${p}`);
}

// 2. The native module (manifest + Kotlin) and the config plugins.
const files = [
  ...walk(join(mobile, "modules"), [".kt", ".xml"]),
  ...walk(join(mobile, "plugins"), [".js"]),
].filter((f) => !f.includes(`${join("src", "test")}${"/"}`));
for (const f of files) {
  const text = readFileSync(f, "utf8");
  for (const needle of [...FORBIDDEN, ...FORBIDDEN_SPECIAL]) {
    if (declares(text, needle)) failures.push(`${relative(mobile, f)}: ${needle}`);
  }
}
for (const p of asked) {
  if (FORBIDDEN_SPECIAL.some((f) => p.endsWith(f))) failures.push(`app.json android.permissions asks for ${p}`);
}

// 3. The deliberate special-access permissions: declared exactly where
// allowed, with the justification next to them, and nowhere else.
for (const { permission, file, justification } of SPECIAL_ALLOWED) {
  const where = files.filter((f) => declares(readFileSync(f, "utf8"), permission)).map((f) => relative(mobile, f));
  if (asked.some((p) => p.endsWith(permission))) where.push("app.json");
  if (where.length !== 1 || where[0] !== file) {
    failures.push(`${permission} must be declared only in ${file}; found in: ${where.join(", ") || "nowhere"}`);
    continue;
  }
  const manifest = readFileSync(join(mobile, file), "utf8");
  const at = manifest.indexOf(`android.permission.${permission}`);
  if (at < 0 || !manifest.slice(Math.max(0, at - 800), at).includes(justification)) {
    failures.push(`${permission} in ${file} lost its justification comment (must cite ${justification})`);
  }
}

// 4. What our config asks for: the pinned set, and the VPN permission in the
// module manifest rather than app.json.
const manifests = files.filter((f) => f.endsWith("AndroidManifest.xml"));
const fromManifests = new Map(manifests.map((f) => [relative(mobile, f), usesPermissions(readFileSync(f, "utf8"))]));
const fromApp = asked.map(fullName);
const declared = new Set([...fromApp, ...[...fromManifests.values()].flat()]);
for (const p of DECLARED) {
  if (!declared.has(p)) failures.push(`${p} is no longer declared (app.json or ${MODULE_MANIFEST}): the APK would lose it`);
}
for (const p of declared) {
  if (!DECLARED.includes(p)) failures.push(`${p} is declared but not in DECLARED: add it there and to the store permission tables`);
}
for (const p of MODULE_ONLY) {
  if (fromApp.includes(p)) failures.push(`app.json android.permissions asks for ${p}: it ships in the iOS app; declare it in ${MODULE_MANIFEST}`);
  if (!(fromManifests.get(MODULE_MANIFEST) ?? []).includes(p)) failures.push(`${MODULE_MANIFEST} does not declare <uses-permission> ${p}`);
}

if (failures.length > 0) {
  console.log("ANDROID PERMISSION GUARD FAILED:");
  for (const f of failures) console.log("  " + f);
  process.exit(1);
}
console.log(
  `ok: ${declared.size} permissions declared (${asked.length} in app.json, ${[...fromManifests.values()].flat().length} in ` +
  `${manifests.length} module manifest${manifests.length === 1 ? "" : "s"}), ` +
  `${FORBIDDEN.length + FORBIDDEN_SPECIAL.length} forbidden ones absent from ${files.length} files, ` +
  `${SPECIAL_ALLOWED.length} special-access declared where allowed, ${MUST_BLOCK.length} stripped at merge`,
);

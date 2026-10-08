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

if (failures.length > 0) {
  console.log("ANDROID PERMISSION GUARD FAILED:");
  for (const f of failures) console.log("  " + f);
  process.exit(1);
}
console.log(
  `ok: ${asked.length} permissions asked, ${FORBIDDEN.length + FORBIDDEN_SPECIAL.length} forbidden ones absent from ${files.length} files, ` +
  `${SPECIAL_ALLOWED.length} special-access declared where allowed, ${MUST_BLOCK.length} stripped at merge`,
);

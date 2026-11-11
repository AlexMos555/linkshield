#!/usr/bin/env node
/**
 * Table test for scripts/check-android-permissions.mjs — run with
 * `node mobile/scripts/test-check-android-permissions.mjs`.
 *
 * Each case writes an edited copy of mobile/app.json into a temp dir, next to
 * links to the real modules/ and plugins/, and runs the guard on it with
 * --dir. The rows are ways the permissions our config declares (DECLARED in
 * the guard) can leave the APK while the store permission tables stay as
 * they are:
 *   - a declared permission listed in android.blockedPermissions: expo
 *     prebuild drops it from android.permissions and writes
 *     tools:node="remove" into the app manifest, which also strips the module
 *     manifest's entry at manifest merge. The guard's first version missed
 *     this (review, 2026-11-02);
 *   - BIND_VPN_SERVICE back in app.json, whose public config ships in the
 *     iOS app;
 *   - a declared permission dropped from app.json.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const mobile = resolve(here, "..");
const script = join(here, "check-android-permissions.mjs");
const app = JSON.parse(readFileSync(join(mobile, "app.json"), "utf8"));
const tmp = mkdtempSync(join(tmpdir(), "cleanway-android-permissions-"));
for (const d of ["modules", "plugins"]) symlinkSync(join(mobile, d), join(tmp, d), "dir");

/** The committed app.json with its android section changed by `edit`. */
function appWith(edit) {
  const copy = structuredClone(app);
  edit(copy.expo.android);
  return copy;
}
const blocking = (name) => appWith((a) => a.blockedPermissions.push(name));

const CASES = [
  ["app.json as committed", app, 0, [/^ok: /m]],
  ["a permission nobody declares blocked: still fine", blocking("android.permission.READ_CONTACTS"), 0, [/^ok: /m]],
  [
    "RECEIVE_BOOT_COMPLETED (app.json and the module manifest) blocked",
    blocking("android.permission.RECEIVE_BOOT_COMPLETED"),
    1,
    [/blockedPermissions strips android\.permission\.RECEIVE_BOOT_COMPLETED: the APK would lose it/],
  ],
  [
    "POST_NOTIFICATIONS (app.json only) blocked by its bare name: Expo prefixes it",
    blocking("POST_NOTIFICATIONS"),
    1,
    [/blockedPermissions strips android\.permission\.POST_NOTIFICATIONS/],
  ],
  [
    "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS (module manifest only) blocked",
    blocking("android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"),
    1,
    [/blockedPermissions strips android\.permission\.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS/],
  ],
  [
    "BIND_VPN_SERVICE blocked",
    blocking("android.permission.BIND_VPN_SERVICE"),
    1,
    [/blockedPermissions strips android\.permission\.BIND_VPN_SERVICE/],
  ],
  [
    "BIND_VPN_SERVICE back in app.json",
    appWith((a) => a.permissions.push("android.permission.BIND_VPN_SERVICE")),
    1,
    [/asks for android\.permission\.BIND_VPN_SERVICE: it ships in the iOS app/],
  ],
  [
    "POST_NOTIFICATIONS (app.json only) dropped from app.json",
    appWith((a) => { a.permissions = a.permissions.filter((p) => !p.endsWith("POST_NOTIFICATIONS")); }),
    1,
    [/POST_NOTIFICATIONS is no longer declared/],
  ],
];

let failed = 0;
try {
  for (const [name, appJson, wantCode, patterns] of CASES) {
    writeFileSync(join(tmp, "app.json"), JSON.stringify(appJson, null, 2));
    const r = spawnSync(process.execPath, [script, "--dir", tmp], { encoding: "utf8" });
    const out = `${r.stdout}${r.stderr}`;
    const missing = patterns.filter((p) => !p.test(out));
    const ok = r.status === wantCode && missing.length === 0;
    if (!ok) failed++;
    console.log(`${ok ? "  ok  " : "  FAIL"}  ${name}`);
    if (!ok) {
      console.log(`        exit ${r.status} (want ${wantCode}); missing ${missing.map(String).join(", ") || "nothing"}`);
      console.log(out.replace(/^/gm, "        | "));
    }
  }
} finally {
  // Removes the two links, not what they point to.
  rmSync(tmp, { recursive: true, force: true });
}

console.log(failed === 0 ? `\nall ${CASES.length} cases pass` : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);

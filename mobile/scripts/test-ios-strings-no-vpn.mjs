#!/usr/bin/env node
/**
 * The strings the iPhone's JS bundle carries say "VPN" only where they name
 * Apple's own Settings page. App Review's automated check read 1.0.4 as
 * "contains VPN functionality" (2026-10-30, docs/IOS.md §3.6), and the
 * bundle then carried 15 such strings per locale, none of them shown on an
 * iPhone except those two.
 *
 * Run: node mobile/scripts/test-ios-strings-no-vpn.mjs
 *
 * Pinned:
 *   • in the base files every platform ships (mobile/i18n/<locale>.json),
 *     /vpn/i matches only mobile.ios.dns.step_on_body and
 *     mobile.ios.dns.error_remove — the path Settings → General → VPN &
 *     Device Management → DNS;
 *   • the landing site's and the emails' strings are not in them: the app
 *     reads neither, and the support FAQ talks about the Android VPN;
 *   • the strings only Android shows (the VpnService disclosure, the
 *     "permission taken back" notice, the Always-on VPN rows) are in
 *     mobile/i18n/android/<locale>.json for all 10 locales, only there, and
 *     still say VPN (Google Play's disclosure must name it);
 *   • only src/i18n/resources.android.ts imports i18n/android/ (Metro picks
 *     it on Android, resources.ts on iOS and web), and src/i18n/index.ts
 *     takes RESOURCES from ./resources instead of importing the files.
 *
 * Generated files: edit packages/i18n-strings/src, then run
 * python3 scripts/build-i18n.py (scripts/i18n_mobile.py decides which key
 * goes where).
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const MOBILE = join(dirname(fileURLToPath(import.meta.url)), "..");
const LOCALES = ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"];
const SETTINGS_PATH_KEYS = ["mobile.ios.dns.error_remove", "mobile.ios.dns.step_on_body"];
const ANDROID_ONLY_KEYS = [
  "mobile.home.interrupted_revoked",
  "mobile.keep_alive.always_on_ok",
  "mobile.keep_alive.always_on_optional",
  "mobile.shield.disclosure.body",
];
const read = (rel) => readFileSync(join(MOBILE, rel), "utf8");
const readJson = (rel) => (existsSync(join(MOBILE, rel)) ? JSON.parse(read(rel)) : {});
const BASE = Object.fromEntries(LOCALES.map((loc) => [loc, readJson(`i18n/${loc}.json`)]));
const ANDROID = Object.fromEntries(LOCALES.map((loc) => [loc, readJson(`i18n/android/${loc}.json`)]));

let failures = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`  ok   ${name}`);
  } catch (err) {
    failures += 1;
    console.log(`  FAIL ${name}\n       ${err.message}`);
  }
}

// ── What the iPhone's bundle carries ─────────────────────────────────

check("base files: 'VPN' only in the two Settings-path strings, in every locale", () => {
  for (const loc of LOCALES) {
    assert.ok(Object.keys(BASE[loc]).length > 500, `${loc}: base file read`);
    const vpn = Object.keys(BASE[loc]).filter((k) => /vpn/i.test(BASE[loc][k])).sort();
    assert.deepEqual(vpn, SETTINGS_PATH_KEYS, loc);
    for (const key of SETTINGS_PATH_KEYS) assert.match(BASE[loc][key], /DNS/, `${loc}: ${key} names the DNS page`);
  }
  assert.match(BASE.en["mobile.ios.dns.step_on_body"], /General → VPN & Device Management → DNS/);
});

check("base files: no landing.* or email.* strings (the app reads neither)", () => {
  for (const loc of LOCALES) {
    const foreign = Object.keys(BASE[loc]).filter((k) => /^(landing|email)\./.test(k));
    assert.deepEqual(foreign.slice(0, 5), [], loc);
  }
});

// ── What only Android gets ───────────────────────────────────────────

check("android/: exactly the Android-only strings, for all 10 locales, and none in the base", () => {
  const files = existsSync(join(MOBILE, "i18n/android")) ? readdirSync(join(MOBILE, "i18n/android")).sort() : [];
  assert.deepEqual(files, LOCALES.map((loc) => `${loc}.json`).sort());
  for (const loc of LOCALES) {
    assert.deepEqual(Object.keys(ANDROID[loc]).sort(), ANDROID_ONLY_KEYS, loc);
    for (const key of ANDROID_ONLY_KEYS) {
      assert.ok(typeof ANDROID[loc][key] === "string" && ANDROID[loc][key].trim(), `${loc}: ${key}`);
      assert.equal(BASE[loc][key], undefined, `${loc}: ${key} is in the base file`);
    }
  }
});

check("Android still says VPN where it means it (Play's VpnService disclosure, Always-on VPN)", () => {
  for (const loc of LOCALES) {
    for (const key of ANDROID_ONLY_KEYS) assert.match(ANDROID[loc][key] ?? "", /VPN/, `${loc}: ${key}`);
  }
});

// ── Which file imports what (Metro resolves by platform) ─────────────

const importsOf = (src) => [...src.matchAll(/from\s+["']([^"']+)["']/g)].map((m) => m[1]);

check("resources.ts: the 10 base files, nothing from i18n/android/", () => {
  const imports = importsOf(read("src/i18n/resources.ts"));
  assert.deepEqual(imports.sort(), LOCALES.map((loc) => `../../i18n/${loc}.json`).sort());
});

check("resources.android.ts: the 10 base files and the 10 Android ones", () => {
  const imports = importsOf(read("src/i18n/resources.android.ts"));
  const want = LOCALES.flatMap((loc) => [`../../i18n/${loc}.json`, `../../i18n/android/${loc}.json`]);
  assert.deepEqual(imports.sort(), want.sort());
});

check("index.ts takes RESOURCES from ./resources and imports no strings file itself", () => {
  const index = read("src/i18n/index.ts");
  assert.ok(/^import \{ RESOURCES \} from "\.\/resources";$/m.test(index), "no RESOURCES import from ./resources");
  assert.ok(!importsOf(index).some((p) => p.endsWith(".json")), "a .json import in index.ts");
});

check("nothing else in the app imports i18n/android/ or a strings file", () => {
  const files = ["app", "src", "modules"].flatMap((dir) =>
    readdirSync(join(MOBILE, dir), { recursive: true })
      .map(String)
      .filter((f) => /\.(ts|tsx|js|jsx)$/.test(f) && !f.includes("node_modules"))
      .map((f) => `${dir}/${f}`),
  );
  assert.ok(files.length > 50, "scanned the app's sources");
  const own = new Set(["src/i18n/resources.ts", "src/i18n/resources.android.ts"]);
  for (const file of files) {
    if (own.has(file)) continue;
    const bad = importsOf(read(file)).filter((p) => /(^|\/)i18n\/(android\/)?[a-z]{2}\.json$|i18n\/android\//.test(p));
    assert.deepEqual(bad, [], file);
  }
});

if (failures > 0) {
  console.log(`${failures} iOS strings check(s) failed`);
  process.exit(1);
}
console.log("ok: the iPhone's strings say VPN only for Apple's Settings page; Android keeps its own");

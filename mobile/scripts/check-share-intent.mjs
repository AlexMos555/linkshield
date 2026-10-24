#!/usr/bin/env node
/**
 * expo-share-intent on Android: a shared file can no longer be written
 * outside the cache. Run with `node mobile/scripts/check-share-intent.mjs` —
 * CI runs it in the mobile job (through plugins/__tests__/plugins.test.js),
 * the build mirror right after `npm install` (docs/RUSTORE_SUBMISSION.md §2),
 * and every Android release build before it compiles anything
 * (plugins/withShareIntentGuard.js; a failure here fails the build).
 *
 * The hole (docs/EXPO_UPGRADE_PLAN.md §1.2; CWE-22, "Dirty Stream"): for a
 * shared file, getDataColumn in ExpoShareIntentModule.kt copied it to
 * File(context.cacheDir, _display_name), a name the SENDING app's
 * ContentProvider picks. "../shared_prefs/…" lands outside the cache, in
 * Cleanway's private data (settings, the allow list). MainActivity is
 * exported, and an explicit intent skips intent filters, so any app on the
 * phone could do it: no permission, nothing for the person to tap.
 *
 * Upstream fixed it in 8.0.1 (achorein/expo-share-intent#221). SDK 54 keeps
 * us on 5.1.1, so mobile/patches/expo-share-intent+5.1.1.patch is that fix,
 * byte for byte, and scripts/apply-patches.js applies it on every install
 * (the monorepo's and the mirror's).
 *
 * Checked:
 *  1. the installed Kotlin copies into the cache only under the name cut to
 *     its last path component, and only once its canonical path is inside
 *     cacheDir; File(context.cacheDir, fileName) is gone;
 *  2. below 8.0.1, the patch for the installed version is there and applied
 *     cleanly: the installed file is exactly the patch's result, which is
 *     upstream 8.0.1's file. From 8.0.1 on, no expo-share-intent patch is left;
 *  3. defence in depth: the share sheet offers Cleanway for text/plain only,
 *     the one type 5.1.1 reads as text without copying a file. Checked on
 *     the manifest the plugin itself generates from app.json. Not enough on
 *     its own (an explicit intent ignores filters), hence 1 and 2.
 *  4. with --manifest=<android/app/src/main/AndroidManifest.xml>: the same
 *     filter in the manifest a build actually uses. Release builds run the
 *     check this way before compiling (plugins/withShareIntentGuard.js), so
 *     an android/ generated before the filter was narrowed fails as well.
 *
 * --package-dir=<dir> points checks 1 and 2 at another copy of the package;
 * plugins.test.js uses it to show that this check fails when it should.
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual } from "node:util";

const mobile = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const require = createRequire(join(mobile, "package.json"));

const PKG = "expo-share-intent";
const KT = "android/src/main/java/expo/modules/shareintent/ExpoShareIntentModule.kt";
const FIXED_IN = [8, 0, 1];
/**
 * Git blob ids (`git hash-object`) of upstream's ExpoShareIntentModule.kt.
 * UNPATCHED: npm 5.1.1; the file stayed the same up to 8.0.0. FIXED: npm
 * 8.0.1, i.e. #221's single hunk; 9.0.0 has the same file. To re-check one:
 *   gh api "repos/achorein/expo-share-intent/contents/<KT>?ref=v8.0.1" \
 *     --jq .content | base64 -d | git hash-object --stdin
 */
const UPSTREAM_UNPATCHED = "0153c89c7e2ce4fa20351bc2d5e7b1c6cd341dbe";
const UPSTREAM_FIXED = "ff5b1001e7bb3443482727cec48c22579465c73b";
/** The share types Cleanway reads: ShareIntentRouter (app/_layout.tsx) uses `text` and `webUrl` only. */
const SHARE_TYPES = ["text/plain"];
const SEND = "android.intent.action.SEND";
const SEND_MULTIPLE = "android.intent.action.SEND_MULTIPLE";

const arg = (name) => {
  const a = process.argv.find((x) => x.startsWith(`--${name}=`));
  return a === undefined ? undefined : resolve(a.slice(name.length + 3));
};
const pkgDir = arg("package-dir") ?? dirname(require.resolve(`${PKG}/package.json`));
const manifestPath = arg("manifest");
const patchesDir = join(mobile, "patches");

const ok = [];
const failures = [];
const gitBlobId = (buf) => createHash("sha1").update(`blob ${buf.length}\0`).update(buf).digest("hex");
/** MainActivity's SEND / SEND_MULTIPLE filters in a manifest (xml2js shape): [{ actions, types }]. */
const shareFiltersOf = (manifest) => {
  const activities = manifest.manifest?.application?.[0]?.activity ?? [];
  const main = activities.find((a) => a.$?.["android:name"] === ".MainActivity");
  if (!main) return undefined;
  const actions = (f) => (f.action ?? []).map((a) => a.$["android:name"]);
  return (main["intent-filter"] ?? [])
    .filter((f) => actions(f).some((a) => a === SEND || a === SEND_MULTIPLE))
    .map((f) => ({ actions: actions(f), types: (f.data ?? []).map((d) => d.$["android:mimeType"]) }));
};
const EXPECTED_SHARES = [{ actions: [SEND], types: SHARE_TYPES }];
const olderThan = (version, floor) => {
  const v = version.split("-")[0].split(".").map(Number);
  for (let i = 0; i < 3; i++) if (v[i] !== floor[i]) return v[i] < floor[i];
  return false;
};

const version = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8")).version;
const bytes = readFileSync(join(pkgDir, KT));
const src = bytes.toString("utf8");
const where = `${PKG} ${version} ${KT}`;

// 1. The copy itself.
{
  const before = failures.length;
  if (/File\(\s*context\.cacheDir\s*,\s*fileName\s*\)/.test(src)) {
    failures.push(`${where}: still copies a shared file to File(context.cacheDir, fileName), the sender's _display_name, "../" and all`);
  }
  if (!/val\s+safeName\s*=\s*fileName\?\.let\s*\{\s*File\(it\)\.name\s*\}\.orEmpty\(\)/.test(src)) {
    failures.push(`${where}: does not cut the name to its last path component (no safeName = File(it).name)`);
  }
  if (
    !/val\s+candidate\s*=\s*File\(\s*context\.cacheDir\s*,\s*safeName\s*\)/.test(src) ||
    !/val\s+cacheRoot\s*=\s*context\.cacheDir\.canonicalPath\s*\+\s*File\.separator/.test(src) ||
    !/if\s*\(\s*candidate\.canonicalPath\.startsWith\(\s*cacheRoot\s*\)\s*\)\s*\{\s*targetFile\s*=\s*candidate\s*\}/.test(src)
  ) {
    failures.push(`${where}: does not keep the copy inside cacheDir (no candidate.canonicalPath.startsWith(cacheDir.canonicalPath + File.separator))`);
  }
  // Nothing else may decide where a shared file goes: every name under
  // cacheDir is the sanitised one or the module's own generated one, every
  // assignment of targetFile is one of the two, and it is the only file written.
  const GENERATED = '"${prefix}_${Date().time}.$type"';
  const names = [...src.matchAll(/File\(\s*context\.cacheDir\s*,\s*(.+?)\)\s*$/gm)].map((m) => m[1]);
  const targets = [...src.matchAll(/\btargetFile\s*=(?!=)\s*(.+?)\s*$/gm)].map((m) => m[1]);
  const outputs = [...src.matchAll(/FileOutputStream\(([^)]*)\)/g)].map((m) => m[1].trim());
  const strayNames = names.filter((n) => n !== "safeName" && n !== GENERATED);
  const strayTargets = targets.filter((t) => t !== "candidate" && t !== `File(context.cacheDir, ${GENERATED})`);
  if (strayNames.length) failures.push(`${where}: writes into cacheDir under ${strayNames.join(", ")}`);
  if (strayTargets.length) failures.push(`${where}: targetFile is also set to ${strayTargets.join(", ")}`);
  if (!isDeepStrictEqual(outputs, ["targetFile"])) failures.push(`${where}: writes files other than targetFile (${outputs.join(", ")})`);
  if (failures.length === before) {
    ok.push(`${where}: a shared file is copied as cacheDir/<last path component>, only if its canonical path is inside cacheDir`);
  }
}

// 2. The patch: there below 8.0.1, applied cleanly, gone from 8.0.1 on.
{
  const patches = existsSync(patchesDir)
    ? readdirSync(patchesDir).filter((f) => f.startsWith(`${PKG}+`) && f.endsWith(".patch"))
    : [];
  if (!olderThan(version, FIXED_IN)) {
    if (patches.length) {
      failures.push(`${PKG} ${version} carries the fix itself (8.0.1+): delete ${patches.map((p) => `mobile/patches/${p}`).join(", ")}`);
    } else {
      ok.push(`${PKG} ${version} carries the fix itself; no patch left behind`);
    }
  } else {
    const want = `${PKG}+${version}.patch`;
    for (const p of patches.filter((p) => p !== want)) {
      failures.push(`mobile/patches/${p} is for another version than the installed ${version} (patch-package only warns about that)`);
    }
    if (!patches.includes(want)) {
      failures.push(`${PKG} ${version} has the hole and mobile/patches/${want} is missing`);
    } else {
      const text = readFileSync(join(patchesDir, want), "utf8");
      const files = [...text.matchAll(/^diff --git a\/\S+ b\/(\S+)$/gm)].map((m) => m[1]);
      const index = text.match(/^index ([0-9a-f]{40})\.\.([0-9a-f]{40}) /m);
      const got = gitBlobId(bytes);
      if (!isDeepStrictEqual(files, [`node_modules/${PKG}/${KT}`])) {
        failures.push(`mobile/patches/${want} must change ${KT} and nothing else; it changes ${files.join(", ") || "nothing"}`);
      } else if (!index) {
        failures.push(`mobile/patches/${want} lost its full "index <before>..<after>" line (git diff --full-index)`);
      } else if (index[1] !== UPSTREAM_UNPATCHED || index[2] !== UPSTREAM_FIXED) {
        failures.push(
          `mobile/patches/${want} is not upstream's fix: it maps ${index[1]} -> ${index[2]}, ` +
            `expected ${UPSTREAM_UNPATCHED} (5.1.1) -> ${UPSTREAM_FIXED} (8.0.1)`,
        );
      } else if (got === UPSTREAM_UNPATCHED) {
        failures.push(`mobile/patches/${want} did not apply: ${KT} is still upstream ${version}'s (npm install --ignore-scripts skips postinstall)`);
      } else if (got !== UPSTREAM_FIXED) {
        failures.push(`${where} is neither upstream 5.1.1's nor the patched file (git blob ${got}): edited by hand, or patched twice`);
      } else {
        ok.push(`mobile/patches/${want} applied cleanly: ${KT} is byte for byte upstream 8.0.1's (git blob ${got.slice(0, 7)})`);
      }
    }
  }
}

// 3. The share filter Android gets, as the plugin itself writes it from app.json.
{
  const app = JSON.parse(readFileSync(join(mobile, "app.json"), "utf8")).expo;
  const entry = (app.plugins ?? []).find((p) => (Array.isArray(p) ? p[0] : p) === PKG);
  if (!entry) {
    failures.push(`app.json no longer configures the ${PKG} plugin`);
  } else {
    const params = (Array.isArray(entry) && entry[1]) || {};
    const { withAndroidIntentFilters } = require(`${PKG}/plugin/build/android/withAndroidIntentFilters.js`);
    const manifest = {
      manifest: {
        application: [{
          $: { "android:name": ".MainApplication" },
          activity: [{
            $: { "android:name": ".MainActivity", "android:exported": "true" },
            "intent-filter": [{
              action: [{ $: { "android:name": "android.intent.action.MAIN" } }],
              category: [{ $: { "android:name": "android.intent.category.LAUNCHER" } }],
            }],
          }],
        }],
      },
    };
    const config = withAndroidIntentFilters({ ...app, mods: undefined }, params);
    const warn = console.warn;
    console.warn = () => {}; // the plugin announces its filters on every run
    let result;
    try {
      result = await config.mods.android.manifest({
        ...config,
        modResults: manifest,
        modRequest: { platform: "android", modName: "manifest", projectRoot: mobile, platformProjectRoot: join(mobile, "android"), introspect: true },
      });
    } finally {
      console.warn = warn;
    }
    const shares = shareFiltersOf(result.modResults);
    if (!isDeepStrictEqual(shares, EXPECTED_SHARES)) {
      failures.push(
        `the share filters MainActivity gets are ${JSON.stringify(shares)}; expected one SEND for ${SHARE_TYPES.join(", ")} ` +
          `(app.json: androidIntentFilters ${JSON.stringify(SHARE_TYPES)}, no androidMultiIntentFilters)`,
      );
    } else {
      ok.push(`share sheet: MainActivity takes SEND for ${SHARE_TYPES.join(", ")} only (plugin output from app.json)`);
    }
  }
}

// 4. The manifest this android/ builds from (release builds pass --manifest).
if (manifestPath !== undefined) {
  const { AndroidConfig } = require("@expo/config-plugins");
  let manifest;
  if (!existsSync(manifestPath)) {
    failures.push(`${manifestPath}: no such file`);
  } else {
    try {
      manifest = await AndroidConfig.Manifest.readAndroidManifestAsync(manifestPath);
    } catch (e) {
      failures.push(`${manifestPath}: cannot read it (${e.message})`);
    }
  }
  if (manifest) {
    const shares = shareFiltersOf(manifest);
    if (shares === undefined) {
      failures.push(`${manifestPath}: no .MainActivity in it`);
    } else if (!isDeepStrictEqual(shares, EXPECTED_SHARES)) {
      failures.push(
        `${manifestPath}: MainActivity's share filters are ${JSON.stringify(shares)}; expected one SEND for ` +
          `${SHARE_TYPES.join(", ")}. This android/ was generated from an older app.json: expo prebuild -p android --clean`,
      );
    } else {
      ok.push(`${manifestPath}: MainActivity takes SEND for ${SHARE_TYPES.join(", ")} only`);
    }
  }
}

for (const line of ok) console.log(`ok: ${line}`);
if (failures.length > 0) {
  console.log("EXPO-SHARE-INTENT CHECK FAILED (docs/EXPO_UPGRADE_PLAN.md §1.2):");
  for (const f of failures) console.log(`  ${f}`);
  process.exit(1);
}

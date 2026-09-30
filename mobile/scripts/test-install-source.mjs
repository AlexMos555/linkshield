#!/usr/bin/env node
/**
 * Table test for modules/cleanway-vpn/src/InstallSource.ts — run with
 * `node scripts/test-install-source.mjs`.
 *
 * Where the app came from decides which SMS set-up path the person is sent
 * down: a browser download on Android 15+ must go through "Allow restricted
 * settings", a store install may not. The JS bundle and the native build ship
 * separately, so parseInstallSource() must turn anything odd into "not
 * reported" — never into a made-up source. Same approach as
 * test-message-analysis.mjs: compile the one file with the tree's TypeScript,
 * run the table for real, exit non-zero on failure.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, "../modules/cleanway-vpn/src/InstallSource.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-install-"));

const NONE = { installer: null, initiator: null, packageSource: null };

try {
  execFileSync(
    "npx",
    ["tsc", src, "--outDir", out, "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck"],
    { cwd: resolve(here, ".."), stdio: "inherit" },
  );

  const { parseInstallSource, PACKAGE_SOURCE, RUSTORE_INSTALLER } = await import(
    pathToFileURL(join(out, "InstallSource.js")).href
  );

  const CASES = [
    [
      "a RuStore install passes through unchanged",
      { installer: "ru.vk.store", initiator: "ru.vk.store", packageSource: 2 },
      { installer: "ru.vk.store", initiator: "ru.vk.store", packageSource: 2 },
    ],
    [
      "a browser download (package source 4) passes through",
      { installer: "com.google.android.packageinstaller", initiator: "com.android.chrome", packageSource: 4 },
      { installer: "com.google.android.packageinstaller", initiator: "com.android.chrome", packageSource: 4 },
    ],
    ["an adb install on an older phone: nothing reported", { installer: null, initiator: null, packageSource: null }, NONE],
    ["not an object", "ru.vk.store", null],
    ["null", null, null],
    ["an array is not a source", ["ru.vk.store"], null],
    ["an empty map from an older native build", {}, NONE],
    ["a blank package name is not a package", { installer: "  ", initiator: "" }, NONE],
    ["a package name that is not a string is dropped", { installer: 42, initiator: true }, NONE],
    ["a package source outside 0..4 is dropped", { packageSource: 7 }, NONE],
    ["a fractional package source is dropped", { packageSource: 2.5 }, NONE],
    ["a string package source is dropped", { packageSource: "4" }, NONE],
    ["package source 0 (unspecified) is a real answer", { packageSource: 0 }, { ...NONE, packageSource: 0 }],
  ];

  let failed = 0;
  for (const [name, input, want] of CASES) {
    const got = parseInstallSource(input);
    let ok = true;
    try {
      deepStrictEqual(got, want);
    } catch {
      ok = false;
      failed++;
    }
    console.log(`${ok ? "  ok  " : "  FAIL"}  ${name}` + (ok ? "" : `\n        got ${JSON.stringify(got)}`));
  }

  // Must match PackageInstaller.PACKAGE_SOURCE_* and AppInstallInfo's range.
  const pinned = { UNSPECIFIED: 0, OTHER: 1, STORE: 2, LOCAL_FILE: 3, DOWNLOADED_FILE: 4 };
  try {
    deepStrictEqual({ ...PACKAGE_SOURCE }, pinned);
    deepStrictEqual(RUSTORE_INSTALLER, "ru.vk.store");
  } catch {
    failed++;
    console.log("  FAIL  PACKAGE_SOURCE / RUSTORE_INSTALLER drifted from the platform values");
  }

  console.log(failed === 0 ? `\nall ${CASES.length} cases pass` : `\n${failed} FAILED`);
  process.exit(failed === 0 ? 0 : 1);
} finally {
  rmSync(out, { recursive: true, force: true });
}

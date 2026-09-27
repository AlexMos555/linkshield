#!/usr/bin/env node
/**
 * Table test for modules/cleanway-vpn/src/BypassApps.ts — run with
 * `node scripts/test-bypass-apps.mjs`.
 *
 * "Apps without the filter" shows native rows the JS never made (the bundle
 * and the APK ship separately). Pinned here: a row without a package or a
 * name is dropped rather than shown as a blank the person could pick blindly;
 * an unknown browser flag reads as "browser" so the stronger warning is the
 * default; a non-image icon is not rendered; and the picker lists apps known
 * to ask for the VPN to be turned off first — but never a browser there.
 * Same approach as test-message-analysis.mjs: compile the one file with the
 * tree's TypeScript and run the table for real.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, "../modules/cleanway-vpn/src/BypassApps.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-bypass-"));

const icon = "data:image/png;base64,iVBORw0KGgo=";
const max = { package: "ru.oneme.app", label: "МАКС", icon, suggested: true, isDefault: true, isBrowser: false };

try {
  execFileSync(
    "npx",
    ["tsc", src, "--outDir", out, "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck"],
    { cwd: resolve(here, ".."), stdio: "inherit" },
  );

  const { parseBypassApps, groupPickable } = await import(pathToFileURL(join(out, "BypassApps.js")).href);

  const PARSE = [
    ["a complete row passes through", [max], [max]],
    ["not an array", { package: "ru.oneme.app" }, []],
    ["null", null, []],
    ["a row without a package is dropped", [{ ...max, package: "" }], []],
    ["a row without a name is dropped", [{ ...max, label: "   " }], []],
    ["a repeated package appears once", [max, { ...max, label: "MAX copy" }], [max]],
    ["a non-image icon is not rendered", [{ ...max, icon: "https://evil.example/x.png" }], [{ ...max, icon: null }]],
    [
      "an unknown browser flag reads as a browser (the stronger warning)",
      [{ package: "com.example.app", label: "App" }],
      [{ package: "com.example.app", label: "App", icon: null, suggested: false, isDefault: false, isBrowser: true }],
    ],
    [
      "booleans must be true to count",
      [{ ...max, suggested: "yes", isDefault: 1, isBrowser: false }],
      [{ ...max, suggested: false, isDefault: false }],
    ],
  ];

  const app = (pkg, label, extra = {}) => ({
    package: pkg, label, icon: null, suggested: false, isDefault: false, isBrowser: false, ...extra,
  });
  const ozon = app("ru.ozon.app.android", "Ozon", { suggested: true });
  const avito = app("com.avito.android", "Авито", { suggested: true });
  const chrome = app("com.android.chrome", "Chrome", { isBrowser: true });
  const yabro = app("com.yandex.browser", "Яндекс Браузер", { suggested: true, isBrowser: true });
  const calc = app("com.android.calculator2", "Калькулятор");
  const bank = app("ru.example.bank", "банк");

  const GROUP = [
    [
      "known apps first, then the rest, each by name in the person's language",
      [calc, ozon, chrome, bank, avito],
      "ru",
      { suggested: [avito, ozon], others: [bank, calc, chrome] },
    ],
    ["a browser is never suggested, even if listed", [yabro, ozon], "ru", { suggested: [ozon], others: [yabro] }],
    ["nothing known installed: one plain list", [calc, bank], "ru", { suggested: [], others: [bank, calc] }],
  ];

  let failed = 0;
  const check = (name, got, want) => {
    let ok = true;
    try {
      deepStrictEqual(got, want);
    } catch {
      ok = false;
      failed++;
    }
    console.log(`${ok ? "  ok  " : "  FAIL"}  ${name}` + (ok ? "" : `\n        got ${JSON.stringify(got)}`));
  };
  for (const [name, input, want] of PARSE) check(name, parseBypassApps(input), want);
  for (const [name, input, locale, want] of GROUP) check(name, groupPickable(input, locale), want);

  // The shipped list (a hand-edited asset) and the manifest's <queries> must
  // name the same packages: a package the shield cannot see reads as "not
  // installed" and is never kept out. AppExclusionsTest pins this too, but
  // the Kotlin tests do not run in CI.
  const moduleDir = resolve(here, "../modules/cleanway-vpn/android/src/main");
  const list = JSON.parse(readFileSync(join(moduleDir, "assets/vpn_exclusions.json"), "utf8")).apps;
  const manifest = readFileSync(join(moduleDir, "AndroidManifest.xml"), "utf8");
  const queried = [...manifest.matchAll(/<package\s+android:name="([^"]+)"/g)].map((m) => m[1]).sort();
  const listed = list.map((a) => a.package).sort();
  const PKG = /^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/;
  const defaults = list.filter((a) => a.default === true).map((a) => a.package);
  const DATA = [
    ["the shipped list and the manifest <queries> name the same packages", queried, listed],
    ["every shipped package name is well-formed", listed.filter((p) => !PKG.test(p)), []],
    ["no package is listed twice", listed.length - new Set(listed).size, 0],
    ["MAX and Gosuslugi are kept out by default", ["ru.oneme.app", "ru.rostel"].every((p) => defaults.includes(p)), true],
    ["no browser and never Cleanway in the list", listed.filter((p) => /browser|chrome|firefox|cleanway/i.test(p)), []],
    [
      "every entry says where its package name comes from and whether it is certain",
      list.filter((a) => !a.name || !a.package_source || typeof a.certain !== "boolean" || typeof a.default !== "boolean").map((a) => a.package),
      [],
    ],
  ];
  for (const [name, got, want] of DATA) check(name, got, want);

  const total = PARSE.length + GROUP.length + DATA.length;
  console.log(failed === 0 ? `\nall ${total} cases pass` : `\n${failed} FAILED`);
  process.exit(failed === 0 ? 0 : 1);
} finally {
  rmSync(out, { recursive: true, force: true });
}

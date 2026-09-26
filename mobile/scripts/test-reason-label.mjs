#!/usr/bin/env node
/**
 * Table test for src/utils/reason-label.ts — run with
 * `node scripts/test-reason-label.mjs`.
 *
 * The server sends each reason as an English `detail` plus a `code`; the app
 * shows the label for the code in the person's language and falls back to
 * the English detail only for a code it does not know. Review of 1.0.2 found
 * the codes the API's verdict_basis release adds — among them
 * unreachable_from_scanner, which fires on exactly the Russian bank and
 * government sites the release is for — unmapped, so a Russian screen would
 * have shown English sentences under a Russian verdict. Pinned here:
 *  - those codes (and the phone's own on_device_list) read in Russian;
 *  - every mapped code has its label in every locale, so no mapping can
 *    quietly point at a key that does not exist.
 * Same approach as test-host-parser.mjs: compile the one file with the tree's
 * TypeScript and run it against the generated mobile/i18n/*.json.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const src = resolve(root, "src/utils/reason-label.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-reason-label-"));

const locales = Object.fromEntries(
  readdirSync(join(root, "i18n"))
    .filter((f) => f.endsWith(".json"))
    .map((f) => [f.slice(0, -5), JSON.parse(readFileSync(join(root, "i18n", f), "utf8"))]),
);

/** i18next's t() as reasonLabel uses it: the key's value, else defaultValue. */
const tFor = (locale) => (key, options) => locales[locale][key] ?? options?.defaultValue ?? key;

// The codes the API's verdict_basis release adds, and the one the phone adds.
const NEW_CODES = [
  "domain_not_found", "cleanway_blocklist", "unreachable_from_scanner",
  "checks_incomplete", "partial_analysis", "user_content_platform", "on_device_list",
];

try {
  execFileSync(
    "npx",
    [
      "tsc", src, "--outDir", out, "--rootDir", root,
      "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck",
    ],
    { cwd: root, stdio: "inherit" },
  );
  const m = await import(pathToFileURL(join(out, "src/utils/reason-label.js")).href);
  const ru = tFor("ru");
  const english = "English detail from the server";

  const CASES = [
    [
      "the new API codes and the phone's list code read in Russian, never the English detail",
      () => NEW_CODES.filter((code) => m.reasonLabel({ code, detail: english }, ru) === english),
      [],
    ],
    [
      "the scanner-abroad reason says it is not a sign of danger, in Russian",
      () => m.reasonLabel({ code: "unreachable_from_scanner", detail: english }, ru).includes("не признак опасности"),
      true,
    ],
    [
      "every mapped code has its label in every locale",
      () => Object.entries(locales).flatMap(([locale, strings]) =>
        Object.values(m.CODE_TO_KEY)
          .filter((key) => !(`mobile.reason.${key}` in strings))
          .map((key) => `${locale}: mobile.reason.${key}`)),
      [],
    ],
    [
      "an unknown code still falls back to the server's own words",
      () => m.reasonLabel({ code: "some_future_code", detail: english }, ru),
      english,
    ],
    [
      "no code at all (older API builds): the detail as sent",
      () => m.reasonLabel({ detail: english }, ru),
      english,
    ],
  ];

  let failed = 0;
  for (const [name, run, expected] of CASES) {
    try {
      deepStrictEqual(await run(), expected);
      console.log(`  ok    ${name}`);
    } catch (e) {
      failed += 1;
      console.log(`  FAIL  ${name}\n        ${String(e.message).split("\n").join("\n        ")}`);
    }
  }
  if (failed > 0) {
    console.error(`\n${failed} of ${CASES.length} cases failed`);
    process.exitCode = 1;
  } else {
    console.log(`\nall ${CASES.length} cases pass`);
  }
} finally {
  rmSync(out, { recursive: true, force: true });
}

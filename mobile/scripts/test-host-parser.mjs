#!/usr/bin/env node
/**
 * Table test for src/utils/host.ts — run with `node scripts/test-host-parser.mjs`.
 *
 * There is no test runner in mobile/ yet, so rather than leave an unrunnable
 * *.test.ts sitting there looking like coverage, this compiles the one file it
 * cares about with the TypeScript already in the tree and runs the table for
 * real. Exits non-zero on failure, so CI can call it as-is.
 *
 * The table is not decoration. Two of these cases are bugs that shipped:
 * "evil.com?token=…" used to be forwarded to the server whole, under a privacy
 * line promising only the website name is sent; and an earlier version of this
 * very parser turned "пaypal.com" into "aypal.com" — a different, real domain —
 * because \b in a non-unicode regex does not treat Cyrillic as a word
 * character. Silently rewriting a homograph into the brand it imitates is
 * worse than not handling it at all.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, "../src/utils/host.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-host-"));

try {
  execFileSync(
    "npx",
    ["tsc", src, "--outDir", out, "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck"],
    { cwd: resolve(here, ".."), stdio: "inherit" },
  );

  const { toCheckableHost } = await import(pathToFileURL(join(out, "host.js")).href);

  const CASES = [
    ["evil.com?token=SECRET123", "evil.com"],
    ["evil.com#access_token=SECRET", "evil.com"],
    ["user:hunter2@evil.com/path", "evil.com"],
    ["https://Example.COM:8443/a/b?c=d", "example.com"],
    ["пaypal.com", "xn--aypal-oye.com"],
    ["https://пaypal.com/login", "xn--aypal-oye.com"],
    ["look at this https://bad.tld/x?s=1 please", "bad.tld"],
    ["WIFI:S=home;T=WPA;P=secret;;", null],
    ["not a link", null],
    ["", null],
    ["google.com.", "google.com"],
    ["localhost", null],
    ["   spaced.example.org  ", "spaced.example.org"],
  ];

  let failed = 0;
  for (const [input, want] of CASES) {
    const got = toCheckableHost(input);
    const ok = got === want;
    if (!ok) failed++;
    console.log(
      `${ok ? "  ok  " : "  FAIL"}  ${JSON.stringify(input)} -> ${JSON.stringify(got)}` +
      (ok ? "" : `  (want ${JSON.stringify(want)})`),
    );
  }

  console.log(failed === 0 ? `\nall ${CASES.length} cases pass` : `\n${failed} FAILED`);
  process.exit(failed === 0 ? 0 : 1);
} finally {
  rmSync(out, { recursive: true, force: true });
}

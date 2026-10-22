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
 *
 * The deep-link rows pin a crash: expo-router turns a repeated query param
 * (cleanway:///shared?url=a&url=b — any app or web page can open one) into an
 * array, and the parser called .trim() on it during render. With no error
 * boundary that killed the app, and the Android shield in the same process
 * went down with it. A non-string is now "no link", and the screen reads the
 * first value (src/utils/route-params.ts).
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, "../src/utils/host.ts");
const params = resolve(here, "../src/utils/route-params.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-host-"));

try {
  execFileSync(
    "npx",
    ["tsc", src, params, "--outDir", out, "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck"],
    { cwd: resolve(here, ".."), stdio: "inherit" },
  );

  const { toCheckableHost } = await import(pathToFileURL(join(out, "host.js")).href);
  const { firstValue } = await import(pathToFileURL(join(out, "route-params.js")).href);

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
    // Scheme-priority: the explicit link outranks an earlier dot-token.
    ["check file.pdf from https://evil.tld/x", "evil.tld"],
    // Trailing/wrapping punctuation must not turn a link into "not a link".
    ["look: evil.com,", "evil.com"],
    ["(see https://bad.example.org/x).", "bad.example.org"],
    // Non-web payloads answer the wrong question — refuse, never extract.
    ["mailto:granny@example.com", null],
    ["BEGIN:VCARD\nEMAIL:a@corp.example\nEND:VCARD", null],
    ["tel:+1-555-0100", null],
    // Not a string at all — a repeated deep-link param arrives as an array.
    // "No link", never a TypeError thrown during render.
    [["evil.com", "x.com"], null],
    [undefined, null],
    [null, null],
    [42, null],
    [{ toString: () => "evil.com" }, null],
  ];

  // What app/shared.tsx and app/result.tsx do with a route param: the first
  // value of a repeated one, "" for anything that is not a string.
  const PARAM_CASES = [
    [["evil.com", "x.com"], "evil.com"],
    [["", "x.com"], ""],
    [[], ""],
    [[42, "x.com"], ""],
    ["evil.com", "evil.com"],
    [undefined, ""],
    [null, ""],
    [42, ""],
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

  for (const [input, want] of PARAM_CASES) {
    const got = firstValue(input);
    const ok = got === want;
    if (!ok) failed++;
    console.log(
      `${ok ? "  ok  " : "  FAIL"}  firstValue(${JSON.stringify(input)}) -> ${JSON.stringify(got)}` +
      (ok ? "" : `  (want ${JSON.stringify(want)})`),
    );
  }
  // The /shared deep link end to end: ?url=evil.com&url=x.com checks evil.com.
  {
    const got = toCheckableHost(firstValue(["https://evil.com/login", "https://x.com/"]));
    const ok = got === "evil.com";
    if (!ok) failed++;
    console.log(`${ok ? "  ok  " : "  FAIL"}  repeated ?url= -> ${JSON.stringify(got)}${ok ? "" : '  (want "evil.com")'}`);
  }

  const total = CASES.length + PARAM_CASES.length + 1;
  console.log(failed === 0 ? `\nall ${total} cases pass` : `\n${failed} FAILED`);
  process.exit(failed === 0 ? 0 : 1);
} finally {
  rmSync(out, { recursive: true, force: true });
}

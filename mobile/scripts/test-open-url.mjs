#!/usr/bin/env node
/**
 * Table test for src/utils/open-url.ts — run with `node scripts/test-open-url.mjs`.
 *
 * The link-guard screen (app/shared.tsx, via=guard) checks ONE host and then
 * offers "Open in browser" / "Open anyway". It used to hand the raw shared
 * string to the native openInBrowser, so the thing opened was not the thing
 * checked: "intent://evil.tld/#Intent;…;end https://google.com" was checked
 * as google.com and launched as an intent:// URL, and
 * "https://google.com https://evil.tld/x" was checked as google.com and opened
 * whatever Uri.parse made of the whole string. The cleanway:///shared deep
 * link is reachable by any app or web page, so the string is attacker-shaped.
 *
 * Pinned here: whatever goes in, what comes out is null or an http(s) URL
 * whose host — as a browser (WHATWG URL) reads it — is exactly the checked
 * host, with no userinfo. Same approach as test-host-parser.mjs: compile with
 * the tree's TypeScript, run the table for real, exit non-zero on failure.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const out = mkdtempSync(join(tmpdir(), "cleanway-open-url-"));

try {
  execFileSync(
    "npx",
    [
      "tsc", resolve(root, "src/utils/open-url.ts"), resolve(root, "src/utils/host.ts"),
      "--outDir", out, "--rootDir", root,
      "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck",
    ],
    { cwd: root, stdio: "inherit" },
  );

  const { browserUrlFor } = await import(pathToFileURL(join(out, "src/utils/open-url.js")).href);
  const { toCheckableHost } = await import(pathToFileURL(join(out, "src/utils/host.js")).href);

  // [raw shared string, checked host passed in, expected URL to open]
  // A checked host of undefined means "what shared.tsx computes":
  // toCheckableHost(raw).
  const CASES = [
    // --- the audit's inputs --------------------------------------------------
    ["intent://evil.tld/#Intent;scheme=https;package=com.evil;end https://google.com", undefined, "https://google.com/"],
    ["https://google.com https://evil.tld/x", undefined, "https://google.com/"],
    ["javascript:alert(1)//https://google.com", undefined, null],
    ["javascript:alert(1)//https://google.com", "google.com", "https://google.com/"],
    ["https://google.com@evil.tld/", undefined, "https://evil.tld/"],
    ["https://google.com@evil.tld/", "google.com", "https://google.com/"],
    ["https://evil.tld/?u=https://google.com", undefined, "https://evil.tld/?u=https://google.com"],
    ["https://evil.tld/?u=https://google.com", "google.com", "https://google.com/"],
    // --- case and whitespace -------------------------------------------------
    ["  HTTPS://Google.COM/Path?q=1#Frag  ", undefined, "https://google.com/Path?q=1#Frag"],
    ["HTTP://GOOGLE.COM", undefined, "http://google.com/"],
    ["https://google.com\t/x", "google.com", "https://google.com/"],
    ["https://google.com/x\nhttps://evil.tld", "google.com", "https://google.com/"],
    ["https://google.com/x https://evil.tld", "google.com", "https://google.com/"],
    ["https://google.com/\u0000x", "google.com", "https://google.com/"],
    ["INTENT://google.com/#Intent;scheme=https;package=com.evil;end", "google.com", "https://google.com/"],
    // --- authority tricks ----------------------------------------------------
    ["https://google.com\\@evil.tld/", "google.com", "https://google.com/"],
    ["https://google.com%2F@evil.tld/", "google.com", "https://google.com/"],
    ["https://google.com%00.evil.tld/", "google.com", "https://google.com/"],
    ["https://user:pw@google.com/", "google.com", "https://google.com/"],
    ["https://google.com:8443/a", undefined, "https://google.com:8443/a"],
    ["https://google.com:99999/a", "google.com", "https://google.com/"],
    ["https://google.com:/a", "google.com", "https://google.com/"],
    ["https://google.com./x", undefined, "https://google.com/x"],
    ["https://evil.tld#@google.com", undefined, "https://evil.tld/#@google.com"],
    ["//google.com/x", "google.com", "https://google.com/"],
    ["google.com/x", "google.com", "https://google.com/"],
    ["ftp://google.com/", "google.com", "https://google.com/"],
    ["data:text/html,<script>alert(1)</script>", "google.com", "https://google.com/"],
    // --- path / query / fragment are rebuilt, not passed through --------------
    ["https://google.com", undefined, "https://google.com/"],
    ["https://google.com?q=1", undefined, "https://google.com/?q=1"],
    ["https://google.com#top", undefined, "https://google.com/#top"],
    ["https://google.com/путь", undefined, "https://google.com/%D0%BF%D1%83%D1%82%D1%8C"],
    ["https://google.com/a%2Fb%zz", undefined, "https://google.com/a%2Fb%25zz"],
    ["https://google.com/<script>\"x\"", undefined, "https://google.com/%3Cscript%3E%22x%22"],
    ["https://google.com/a#b#c", undefined, "https://google.com/a#b%23c"],
    // --- no checked host, nothing to open ------------------------------------
    ["https://google.com/", null, null],
    ["https://google.com/", "", null],
    ["https://google.com/", "evil.tld/x", null],
    ["https://google.com/", "google.com@evil.tld", null],
    ["https://google.com/", "localhost", null],
    // --- not strings (a repeated deep-link param is an array) ----------------
    // Must answer, never throw during render: the screen reads the first
    // value (src/utils/route-params.ts), these are the backstop.
    [["https://google.com/x", "https://evil.tld/"], undefined, null],
    [["https://evil.tld/"], "google.com", "https://google.com/"],
    [42, "google.com", "https://google.com/"],
    [undefined, "google.com", "https://google.com/"],
    ["https://google.com/", ["google.com"], null],
    ["https://google.com/", 42, null],
  ];

  let failed = 0;
  for (const [raw, given, expected] of CASES) {
    const checked = given === undefined ? toCheckableHost(raw) : given;
    const got = browserUrlFor(raw, checked);
    let ok = got === expected;
    let why = "";
    // Whatever the table says, an answer must be a URL a browser reads as
    // exactly the checked host over http(s), with no userinfo.
    if (got !== null) {
      try {
        const u = new URL(got);
        if (!/^https?:$/.test(u.protocol)) { ok = false; why = `scheme ${u.protocol}`; }
        else if (u.hostname !== checked) { ok = false; why = `browser host ${u.hostname} != ${checked}`; }
        else if (u.username || u.password) { ok = false; why = "userinfo survived"; }
      } catch (e) {
        ok = false;
        why = `not a URL: ${e.message}`;
      }
    }
    if (ok) {
      console.log(`  ok    ${JSON.stringify(raw) ?? String(raw)} -> ${JSON.stringify(got)}`);
    } else {
      failed++;
      console.error(`  FAIL  ${JSON.stringify(raw)} [checked ${JSON.stringify(checked)}] -> ${JSON.stringify(got)}, expected ${JSON.stringify(expected)} ${why}`);
    }
  }

  if (failed) {
    console.error(`\n${failed}/${CASES.length} failed`);
    process.exitCode = 1;
  } else {
    console.log(`\nall ${CASES.length} passed`);
  }
} finally {
  rmSync(out, { recursive: true, force: true });
}

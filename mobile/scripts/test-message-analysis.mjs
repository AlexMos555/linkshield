#!/usr/bin/env node
/**
 * Table test for modules/cleanway-vpn/src/MessageAnalysis.ts — run with
 * `node scripts/test-message-analysis.mjs`.
 *
 * The JS bundle and the native build ship separately, so the typed result the
 * UI renders is whatever parseMessageAnalysis() makes of the native map. The
 * cases pin the degradation contract: an unknown verdict rejects the whole
 * result (the UI then says "could not check"), while an unknown reason, shape,
 * link status or a missing field only drops that one piece. Same approach as
 * test-host-parser.mjs: compile the one file with the tree's TypeScript, run
 * the table for real, exit non-zero on failure.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, "../modules/cleanway-vpn/src/MessageAnalysis.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-msg-"));

const full = {
  verdict: "dangerous",
  reasons: ["claims_organisation", "threat_or_urgency", "call_unknown_number"],
  links: [{ text: "clck.ru/3Abc", host: "clck.ru", status: "unknown", shortener: true, messenger: false }],
  phones: ["+79164821537"],
  legitShape: null,
  organisations: ["gosuslugi"],
  truncated: false,
  listAvailable: true,
  listStale: false,
};

try {
  execFileSync(
    "npx",
    ["tsc", src, "--outDir", out, "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck"],
    { cwd: resolve(here, ".."), stdio: "inherit" },
  );

  const { parseMessageAnalysis, MESSAGE_REASONS } = await import(pathToFileURL(join(out, "MessageAnalysis.js")).href);

  const CASES = [
    ["a complete native result passes through unchanged", full, full],
    ["not an object", "dangerous", null],
    ["null", null, null],
    ["an unknown verdict rejects the whole result", { ...full, verdict: "safe" }, null],
    ["a missing verdict rejects the whole result", { ...full, verdict: undefined }, null],
    [
      "an unknown reason is dropped, the verdict stays",
      { ...full, reasons: ["claims_organisation", "brand_new_reason"] },
      { ...full, reasons: ["claims_organisation"] },
    ],
    [
      "a link with an unknown status is dropped",
      { ...full, links: [{ text: "a.ru", host: "a.ru", status: "safe" }, full.links[0]] },
      full,
    ],
    ["an unknown legit shape becomes null", { ...full, legitShape: "newsletter" }, full],
    [
      "missing optional fields default to empty/false",
      { verdict: "no_signals" },
      {
        verdict: "no_signals", reasons: [], links: [], phones: [], legitShape: null, organisations: [],
        truncated: false, listAvailable: false, listStale: false,
      },
    ],
    [
      "non-string list entries are ignored, booleans must be true to count",
      { ...full, phones: ["+79164821537", 42], listAvailable: "yes" },
      { ...full, listAvailable: false },
    ],
  ];

  let failed = 0;
  for (const [name, input, want] of CASES) {
    const got = parseMessageAnalysis(input);
    let ok = true;
    try {
      deepStrictEqual(got, want);
    } catch {
      ok = false;
      failed++;
    }
    console.log(`${ok ? "  ok  " : "  FAIL"}  ${name}` + (ok ? "" : `\n        got ${JSON.stringify(got)}`));
  }

  const unique = new Set(MESSAGE_REASONS);
  if (unique.size !== MESSAGE_REASONS.length) {
    failed++;
    console.log("  FAIL  MESSAGE_REASONS has duplicates");
  }

  console.log(failed === 0 ? `\nall ${CASES.length} cases pass` : `\n${failed} FAILED`);
  process.exit(failed === 0 ? 0 : 1);
} finally {
  rmSync(out, { recursive: true, force: true });
}

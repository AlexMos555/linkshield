#!/usr/bin/env node
/**
 * Table test for src/utils/check-verdict.ts — run with
 * `node scripts/test-check-verdict.mjs`.
 *
 * The link-check screens fold two answers into one: the on-device list (in
 * milliseconds) and the server (up to ten seconds). Pinned here:
 *  - a listed site is dangerous at once, and no server answer — late, calm,
 *    or failed — can downgrade it (report #4);
 *  - a name that does not exist is said to not exist, never scored as a scam
 *    (report #18), on old and new servers alike;
 *  - a slow first check is retried once, anything else is not (report #6).
 * Same approach as test-host-parser.mjs: compile the one file with the tree's
 * TypeScript, run the table for real, exit non-zero on failure.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const src = resolve(root, "src/utils/check-verdict.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-check-verdict-"));

const answer = (level, extra = {}) => ({ domain: "x.tld", score: 40, level, reasons: [], ...extra });
const reason = (code, detail = code) => ({ code, detail });

try {
  execFileSync(
    "npx",
    [
      "tsc", src, "--outDir", out, "--rootDir", root,
      "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck",
    ],
    { cwd: root, stdio: "inherit" },
  );

  const m = await import(pathToFileURL(join(out, "src/utils/check-verdict.js")).href);

  // Fake attempts for the retry rule: each call returns the next outcome.
  const attempts = (...outcomes) => {
    let calls = 0;
    const run = async () => outcomes[Math.min(calls++, outcomes.length - 1)];
    return { run, calls: () => calls };
  };
  const retried = async (...outcomes) => {
    const a = attempts(...outcomes);
    const result = await m.retryOnceOnTimeout(a.run);
    return { result, calls: a.calls() };
  };
  const ok = { data: { level: "safe" }, error: null };
  const timeout = { data: null, error: { kind: "timeout" } };
  const limited = { data: null, error: { kind: "rate_limited" } };

  const CASES = [
    // ── the list outranks the server ────────────────────────────────
    ["listed, server not answered yet: dangerous at once", () => m.shownLevel("evil.tld", null), "dangerous"],
    ["listed, server says safe: still dangerous", () => m.shownLevel("evil.tld", answer("safe")), "dangerous"],
    ["listed, server says caution: still dangerous", () => m.shownLevel("evil.tld", answer("caution")), "dangerous"],
    ["not listed: the server decides", () => m.shownLevel(null, answer("caution")), "caution"],
    ["not listed, no answer yet: nothing to show", () => m.shownLevel(null, null), null],
    ["an unknown server level is caution, never safe", () => m.shownLevel(null, answer("unknown")), "caution"],

    // ── what the verdict card carries ───────────────────────────────
    ["the score shows when the server agrees", () => m.showScore("evil.tld", answer("dangerous")), true],
    ["no '25/100' next to 'Dangerous'", () => m.showScore("evil.tld", answer("caution")), false],
    ["unlisted: the server's score as always", () => m.showScore(null, answer("safe")), true],
    [
      "a calm server's reassurance is not a red 'why' under a listed verdict",
      () => m.reasonsToShow("evil.tld", answer("safe", { reasons: [reason("known_legitimate")] })),
      [],
    ],
    [
      "a worried server's reasons do show under a listed verdict",
      () => m.reasonsToShow("evil.tld", answer("caution", { reasons: [reason("no_https")] })),
      [reason("no_https")],
    ],

    // ── a name that does not exist ──────────────────────────────────
    ["exists=false: not found", () => m.isNotFound(answer("dangerous", { exists: false })), true],
    ["domain_not_found reason: not found", () => m.isNotFound(answer("caution", { reasons: [reason("domain_not_found")] })), true],
    ["an older server's answer is not guessed to be 'not found'", () => m.isNotFound(answer("dangerous", { reasons: [reason("no_https")] })), false],
    ["no score ring for a name that does not exist", () => m.showScore(null, answer("dangerous", { exists: false })), false],
    ["a name that does not exist is not kept in History", () => m.historyRecord("x.tld", null, answer("dangerous", { exists: false })), null],

    // ── what History keeps ──────────────────────────────────────────
    [
      "listed with no server answer: dangerous, from the list, no invented score",
      () => m.historyRecord("evil.tld", "evil.tld", null),
      {
        domain: "evil.tld", score: 0, level: "dangerous", source: "list",
        reasons: [{ code: "on_device_list", detail: "On the list of scam sites on this phone" }],
      },
    ],
    [
      "listed and the server agrees: its score and reasons join the list's",
      () => m.historyRecord("evil.tld", "evil.tld", answer("dangerous", { score: 95, reasons: [reason("phishtank")] })),
      {
        domain: "evil.tld", score: 95, level: "dangerous", source: "list",
        reasons: [{ code: "on_device_list", detail: "On the list of scam sites on this phone" }, reason("phishtank")],
      },
    ],
    [
      "unlisted: the server's answer as it came",
      () => m.historyRecord("x.tld", null, answer("caution", { score: 45, confidence: "high", reasons: [reason("no_https")] })),
      { domain: "x.tld", score: 45, level: "caution", reasons: [reason("no_https")], confidence: "high" },
    ],
    ["nothing known: nothing kept", () => m.historyRecord("x.tld", null, null), null],

    // ── when History is written (the screen may close before the server answers) ──
    ["the list not read yet: nothing written", () => m.historyStep("evil.tld", undefined, answer("dangerous"), "nothing").write, "none"],
    [
      "listed: saved the moment the list answers, before the server",
      () => {
        const step = m.historyStep("evil.tld", "evil.tld", undefined, "nothing");
        return [step.write, step.saved, step.row.level, step.row.source];
      },
      ["insert", "list", "dangerous", "list"],
    ],
    [
      "listed, the server answers later: the same row gets its score",
      () => {
        const step = m.historyStep("evil.tld", "evil.tld", answer("dangerous", { score: 95 }), "list");
        return [step.write, step.saved, step.row.score];
      },
      ["update", "final", 95],
    ],
    ["listed, the server failed: the list's row stays as it is", () => m.historyStep("evil.tld", "evil.tld", null, "list").write, "none"],
    [
      "listed, the server answered before the list: one complete row",
      () => {
        const step = m.historyStep("evil.tld", "evil.tld", answer("dangerous", { score: 90 }), "nothing");
        return [step.write, step.saved, step.row.score];
      },
      ["insert", "final", 90],
    ],
    ["unlisted, the server has not answered: nothing yet", () => m.historyStep("x.tld", null, undefined, "nothing").write, "none"],
    [
      "unlisted, the server answered: saved once",
      () => {
        const step = m.historyStep("x.tld", null, answer("caution", { score: 45 }), "nothing");
        return [step.write, step.saved, step.row.level];
      },
      ["insert", "final", "caution"],
    ],
    ["a complete row is never written again", () => m.historyStep("x.tld", null, answer("safe"), "final").write, "none"],
    ["a name that does not exist is never written", () => m.historyStep("x.tld", null, answer("dangerous", { exists: false }), "nothing").write, "none"],

    // ── one retry, on a timeout only ────────────────────────────────
    ["an answer first time is not asked twice", () => retried(ok), { result: ok, calls: 1 }],
    ["a timeout is retried once and the late answer used", () => retried(timeout, ok), { result: ok, calls: 2 }],
    ["two timeouts give up", () => retried(timeout, timeout, ok), { result: timeout, calls: 2 }],
    ["a rate limit is not retried", () => retried(limited, ok), { result: limited, calls: 1 }],
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

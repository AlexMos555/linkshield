#!/usr/bin/env node
/**
 * Table test for src/utils/call-guard.ts — run with
 * `node scripts/test-call-guard.mjs`.
 *
 * The stop screen steps in front of "pause protection", "not a scam — allow"
 * and "open anyway" while the person is on the phone and for 30 minutes
 * after a call. Each way of getting that wrong is quiet: a screen that never
 * shows because the native flag went stale, one that shows on a phone that
 * cannot see calls at all, a countdown a fast hand can skip, a clock stepped
 * backwards that shortens the wait. Same approach as test-history-model.mjs:
 * compile the one file with the tree's TypeScript, run the table for real,
 * exit non-zero on failure.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const src = resolve(root, "src/utils/call-guard.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-call-"));

const MINUTE = 60_000;
const T0 = Date.UTC(2026, 8, 29, 12, 0, 0);

const idle = { inCall: false, ringing: false, callStartedAt: 0, callEndedAt: 0, windowEndsAt: 0, guardActive: false };
const inCall = { ...idle, inCall: true, callStartedAt: T0 - 2 * MINUTE, guardActive: true };
const ringing = { ...idle, ringing: true };
const ended = (at) => ({ ...idle, callStartedAt: at - 3 * MINUTE, callEndedAt: at, windowEndsAt: at + 30 * MINUTE, guardActive: true });

try {
  execFileSync(
    "npx",
    [
      "tsc", src, "--outDir", out, "--rootDir", root,
      "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck",
    ],
    { cwd: root, stdio: "inherit" },
  );

  const m = await import(pathToFileURL(join(out, "src/utils/call-guard.js")).href);

  const CASES = [
    // ── when the screen applies ───────────────────────────────────────
    ["no snapshot (iOS, an older native build): never", () => m.guardReason(null, T0), null],
    ["idle phone: never", () => m.guardReason(idle, T0), null],
    ["ringing is not yet a call", () => m.guardReason(ringing, T0), null],
    ["in a call", () => m.guardReason(inCall, T0), "in_call"],
    ["a minute after a call", () => m.guardReason(ended(T0 - MINUTE), T0), "after_call"],
    ["29 minutes after a call", () => m.guardReason(ended(T0 - 29 * MINUTE), T0), "after_call"],
    ["30 minutes after a call: the window has closed", () => m.guardReason(ended(T0 - 30 * MINUTE), T0), null],
    [
      "the native flag is not trusted once it is stale",
      // Taken 20 minutes ago with guardActive=true; the call ended 40 minutes ago by now.
      () => m.guardReason({ ...ended(T0 - 40 * MINUTE), guardActive: true }, T0),
      null,
    ],
    ["a clock stepped back below the call's end is not 'after a call'", () => m.guardReason(ended(T0 + 5 * MINUTE), T0), null],
    ["in a call again inside the old window: in_call wins", () => m.guardReason({ ...inCall, callEndedAt: T0 - 10 * MINUTE }, T0), "in_call"],

    // ── when to re-check by itself ────────────────────────────────────
    ["no snapshot: nothing to wait for", () => m.windowEndsAt(null), 0],
    ["no call yet: nothing to wait for", () => m.windowEndsAt(idle), 0],
    ["in a call: wait for the end, not a window", () => m.windowEndsAt(inCall), 0],
    ["after a call: 30 minutes past its end", () => m.windowEndsAt(ended(T0)), T0 + 30 * MINUTE],
    ["the window constant matches the native one (30 min)", () => m.AFTER_CALL_WINDOW_MS, 30 * MINUTE],

    // ── the slow path ─────────────────────────────────────────────────
    ["the countdown starts at 5", () => m.countdownLeft(T0, T0), 5],
    ["2.9 s in: 3 left", () => m.countdownLeft(T0, T0 + 2_900), 3],
    ["5 s in: unlocked", () => m.countdownLeft(T0, T0 + 5_000), 0],
    ["long after: stays unlocked", () => m.countdownLeft(T0, T0 + 60_000), 0],
    ["a clock stepped backwards never shortens the wait", () => m.countdownLeft(T0, T0 - 10_000), 5],
    ["garbage times wait the full count", () => m.countdownLeft(NaN, T0), 5],
    ["the default is the exported constant", () => m.COUNTDOWN_SECONDS, 5],

    // ── merging native events ─────────────────────────────────────────
    ["an event on an empty state fills every field", () => m.applyCallEvent(null, inCall), inCall],
    [
      "an absent field keeps the held value, a present one wins",
      () => m.applyCallEvent(inCall, { inCall: false, callEndedAt: T0 }),
      { ...inCall, inCall: false, callEndedAt: T0 },
    ],
    [
      "a wrongly typed field is ignored",
      () => m.applyCallEvent(idle, { inCall: "yes", callEndedAt: "now" }),
      idle,
    ],
  ];

  let failed = 0;
  for (const [name, run, expected] of CASES) {
    try {
      deepStrictEqual(run(), expected);
      console.log(`  ok  ${name}`);
    } catch (e) {
      failed += 1;
      console.log(`FAIL  ${name}\n      ${String(e.message).split("\n").join("\n      ")}`);
    }
  }
  console.log(`\n${CASES.length - failed}/${CASES.length} passed`);
  if (failed > 0) process.exit(1);
} finally {
  rmSync(out, { recursive: true, force: true });
}

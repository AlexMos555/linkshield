#!/usr/bin/env node
/**
 * Table test for modules/cleanway-vpn/src/SmsShield.ts — run with
 * `node scripts/test-sms-shield.mjs`.
 *
 * The SMS screen shows what smsShieldStatus() says, and History shows what
 * recentSmsEvents() read from a file the ":sms" process wrote. Both cross a
 * boundary where the JS bundle and the native build can differ, so each way
 * of getting it wrong is quiet:
 *  - a malformed status read as "the check is on" when nothing proves it;
 *  - a notification-permission field that is missing read as "warnings will
 *    reach you";
 *  - an event with a bad id opening from a crafted deep link, or a reason
 *    this build has no words for shown as a dotted i18n key.
 * Same approach as test-install-source.mjs: compile the one file with the
 * tree's TypeScript, run the table for real, exit non-zero on failure.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const src = resolve(here, "../modules/cleanway-vpn/src/SmsShield.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-sms-shield-"));

const KNOWN = ["link_blocklisted", "claims_organisation", "asks_for_code", "call_unknown_number"];
const ID = "0123456789abcdef";

const FULL = {
  supported: true,
  permission: "granted",
  canAskAgain: false,
  enabled: true,
  notificationsEnabled: true,
  backgroundRestricted: false,
  checkedCount: 42,
  flaggedCount: 3,
  lastCheckedAt: 1_758_800_000_000,
  listAgeMs: 3_600_000,
};

try {
  execFileSync(
    "npx",
    ["tsc", src, "--outDir", out, "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck"],
    { cwd: resolve(here, ".."), stdio: "inherit" },
  );

  const m = await import(pathToFileURL(join(out, "SmsShield.js")).href);
  const NONE = m.SMS_SHIELD_UNSUPPORTED;
  const event = (over = {}) => ({
    id: ID, ts: 1_758_800_000_000, sender: "900", verdict: "dangerous",
    reasons: ["claims_organisation", "asks_for_code"], hosts: ["gosuslugi-help.ru"], ...over,
  });

  const CASES = [
    // ── status ──────────────────────────────────────────────────────
    ["a full status passes through", () => m.parseSmsShieldStatus(FULL), FULL],
    ["not an object: unsupported", () => m.parseSmsShieldStatus("yes"), NONE],
    ["an array: unsupported", () => m.parseSmsShieldStatus([FULL]), NONE],
    ["null: unsupported", () => m.parseSmsShieldStatus(null), NONE],
    ["supported must be exactly true", () => m.parseSmsShieldStatus({ ...FULL, supported: "true" }), NONE],
    [
      "the browser APK's own answer stays unsupported whatever else it says",
      () => m.parseSmsShieldStatus({ ...FULL, supported: false }),
      NONE,
    ],
    [
      "an unknown permission state reads as never asked, not as granted",
      () => m.parseSmsShieldStatus({ ...FULL, permission: "maybe_later" }).permission,
      "not_requested",
    ],
    [
      "each known permission state is kept",
      () => ["granted", "denied", "restricted_maybe", "not_requested"].map((p) => m.parseSmsShieldStatus({ ...FULL, permission: p }).permission),
      ["granted", "denied", "restricted_maybe", "not_requested"],
    ],
    [
      "missing switches read as off: never 'on', never 'warnings will reach you'",
      () => {
        const s = m.parseSmsShieldStatus({ supported: true });
        return [s.enabled, s.notificationsEnabled, s.backgroundRestricted];
      },
      [false, false, false],
    ],
    [
      "\"Android will ask again\" only when it says so exactly: else the screen shows the App-info way",
      () => [true, "true", 1, undefined].map((v) => m.parseSmsShieldStatus({ ...FULL, canAskAgain: v }).canAskAgain),
      [true, false, false, false],
    ],
    ["a truthy non-boolean is not on", () => m.parseSmsShieldStatus({ ...FULL, enabled: 1 }).enabled, false],
    [
      "counts are whole and never negative",
      () => {
        const s = m.parseSmsShieldStatus({ ...FULL, checkedCount: -5, flaggedCount: 2.9 });
        return [s.checkedCount, s.flaggedCount];
      },
      [0, 2],
    ],
    [
      "unreadable times are not known, not zero",
      () => {
        const s = m.parseSmsShieldStatus({ ...FULL, lastCheckedAt: "yesterday", listAgeMs: Number.NaN });
        return [s.lastCheckedAt, s.listAgeMs];
      },
      [null, null],
    ],
    ["a list with no age (none synced) stays null", () => m.parseSmsShieldStatus({ ...FULL, listAgeMs: null }).listAgeMs, null],

    // ── events ──────────────────────────────────────────────────────
    ["a stored event passes through", () => m.parseSmsAlertEvents([event()], KNOWN), [event()]],
    ["not an array: no events", () => m.parseSmsAlertEvents({ 0: event() }, KNOWN), []],
    [
      "an id that is not 16 hex characters drops the event: a deep link can only name a real one",
      () => m.parseSmsAlertEvents([event({ id: "0123456789ABCDEF" }), event({ id: "../../x" }), event({ id: 7 })], KNOWN),
      [],
    ],
    [
      "only dangerous and caution are events",
      () => m.parseSmsAlertEvents([event({ verdict: "no_signals" }), event({ verdict: "safe" })], KNOWN),
      [],
    ],
    ["an event without a time is dropped", () => m.parseSmsAlertEvents([event({ ts: "now" })], KNOWN), []],
    [
      "a reason this build cannot explain is dropped, the event stays",
      () => m.parseSmsAlertEvents([event({ reasons: ["asks_for_code", "future_code", 3] })], KNOWN)[0].reasons,
      ["asks_for_code"],
    ],
    ["a blank sender reads as none", () => m.parseSmsAlertEvents([event({ sender: "  " })], KNOWN)[0].sender, null],
    ["a missing sender reads as none", () => m.parseSmsAlertEvents([event({ sender: undefined })], KNOWN)[0].sender, null],
    [
      "an over-long sender is capped by characters, never inside an emoji",
      () => m.parseSmsAlertEvents([event({ sender: "😀".repeat(50) })], KNOWN)[0].sender,
      "😀".repeat(33),
    ],
    [
      "hosts must look like hosts: no paths, no uppercase tricks",
      () => m.parseSmsAlertEvents([event({ hosts: ["a.ru", "evil.example/login", "EVIL.RU", "1.2.3.4", 5] })], KNOWN)[0].hosts,
      ["a.ru", "1.2.3.4"],
    ],
    [
      "duplicate ids keep the first (newest) one",
      () => m.parseSmsAlertEvents([event({ sender: "first" }), event({ sender: "second" })], KNOWN).map((e) => e.sender),
      ["first"],
    ],
    [
      "one bad event does not take the others down",
      () => m.parseSmsAlertEvents([null, "x", event({ id: "fedcba9876543210" }), event()], KNOWN).map((e) => e.id),
      ["fedcba9876543210", ID],
    ],

    // ── ids ─────────────────────────────────────────────────────────
    ["a stored id is an id", () => m.isSmsEventId(ID), true],
    ["an array is not an id", () => m.isSmsEventId([ID]), false],
    ["a longer string is not an id", () => m.isSmsEventId(`${ID}0`), false],
  ];

  let failed = 0;
  for (const [name, run, expected] of CASES) {
    try {
      deepStrictEqual(run(), expected);
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

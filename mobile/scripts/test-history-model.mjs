#!/usr/bin/env node
/**
 * Table test for src/utils/history-model.ts — run with
 * `node scripts/test-history-model.mjs`.
 *
 * History has to answer "Blocked 3 — which three?" with exactly the rows the
 * home counter added up, and each way of getting that wrong is quiet:
 *  - a filter that disagrees with its counter (a manual "dangerous" check is
 *    counted as Blocked, so it must be listed under Blocked too);
 *  - a block-log entry from before the `source` field, or a row this build
 *    does not know, crashing the list or being shown as something it is not;
 *  - the notification deep link opening a site that is not in the log — the
 *    cleanway:// scheme is public, so any app can craft one;
 *  - an automatic SMS warning missing from Warned, whose home counter adds
 *    it up (flaggedCount), or listed under a chip whose counter never counts
 *    it; or an SMS warning's deep link opening an id the log lacks.
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
const src = resolve(root, "src/utils/history-model.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-history-"));

const HOUR = 3_600_000;
const T0 = Date.UTC(2026, 8, 24, 12, 0, 0);

// SQLite rows as getRecentChecks returns them; native rows as recentBlocks does.
const CHECKS = [
  { id: 1, domain: "bad-check.example", score: 91, level: "dangerous", source: "api", checked_at: new Date(T0 - 1 * HOUR).toISOString() },
  { id: 2, domain: "meh.example", score: 45, level: "caution", source: "api", checked_at: new Date(T0 - 2 * HOUR).toISOString() },
  { id: 3, domain: "fine.example", score: 3, level: "safe", source: "api", checked_at: new Date(T0 - 3 * HOUR).toISOString() },
  { id: 4, domain: "a.example b.example", score: 0, level: "dangerous", source: "sms", checked_at: new Date(T0 - 4 * HOUR).toISOString() },
  { id: 5, domain: "", score: 0, level: "no_signals", source: "sms", checked_at: new Date(T0 - 5 * HOUR).toISOString() },
  // The legacy datetime('now') shape: UTC with no zone marker.
  { id: 6, domain: "old.example", score: 10, level: "safe", checked_at: "2026-09-24 06:00:00" },
];
const SHIELD = [
  { domain: "dns-blocked.example", ts: T0 - 0.5 * HOUR, kind: "blocked", source: "dns" },
  { domain: "link-blocked.example", ts: T0 - 1.5 * HOUR, kind: "blocked", source: "link" },
  { domain: "warned.example", ts: T0 - 2.5 * HOUR, kind: "warned", source: "link" },
  { domain: "dns-blocked.example", ts: T0 - 3.5 * HOUR, kind: "allowed", source: null },
  // An older native build: no source at all.
  { domain: "legacy.example", ts: T0 - 7 * HOUR, kind: "blocked" },
  // Garbage the list must survive without showing it.
  { domain: "", ts: T0, kind: "blocked" },
  { domain: "x.example", ts: T0, kind: "exploded" },
];

// SMS the automatic check flagged, as recentSmsEvents() returns them (validated).
const ALERTS = [
  { id: "00000000000000a1", ts: T0 - 0.25 * HOUR, sender: "900", verdict: "dangerous", reasons: ["asks_for_code"], hosts: ["gosuslugi-help.ru"] },
  { id: "00000000000000a2", ts: T0 - 6 * HOUR, sender: null, verdict: "caution", reasons: [], hosts: [] },
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

  const m = await import(pathToFileURL(join(out, "src/utils/history-model.js")).href);
  const items = m.mergeHistory(CHECKS, SHIELD);
  const withAlerts = m.mergeHistory(CHECKS, SHIELD, ALERTS);
  const names = (list) => list.map((i) =>
    i.type === "sms" ? `sms:${i.hosts.join("+") || "-"}` : i.type === "sms_alert" ? `alert:${i.id}` : `${i.type}:${i.domain}`);

  const CASES = [
    // ── merge ────────────────────────────────────────────────────────
    [
      "both stores merge newest first; garbage shield rows are dropped",
      () => names(items),
      [
        "shield:dns-blocked.example", "check:bad-check.example", "shield:link-blocked.example",
        "check:meh.example", "shield:warned.example", "check:fine.example",
        "shield:dns-blocked.example", "sms:a.example+b.example", "sms:-",
        "check:old.example", "shield:legacy.example",
      ],
    ],
    ["the legacy SQLite time reads as UTC", () => items.find((i) => i.domain === "old.example").ts, Date.UTC(2026, 8, 24, 6, 0, 0)],
    ["an entry without source keeps a null source, not a guess", () => items.find((i) => i.domain === "legacy.example").source, null],
    ["keys are unique", () => new Set(items.map((i) => i.key)).size === items.length, true],
    [
      "a key survives a refresh that prepends a newer row",
      () => {
        const before = items.find((i) => i.domain === "warned.example").key;
        const after = m.mergeHistory(CHECKS, [{ domain: "new.example", ts: T0, kind: "blocked", source: "dns" }, ...SHIELD])
          .find((i) => i.domain === "warned.example").key;
        return before === after;
      },
      true,
    ],
    [
      "unknown check level and sms verdict are kept as null (shown as unknown), never as safe",
      () => {
        const [c, s] = m.mergeHistory(
          [
            { id: 9, domain: "q.example", score: 5, level: "weird", checked_at: new Date(T0).toISOString() },
            { id: 10, domain: "", score: 0, level: "safe", source: "sms", checked_at: new Date(T0 - 1).toISOString() },
          ],
          [],
        );
        return [c.level, s.verdict];
      },
      [null, null],
    ],

    // ── filters match the home counters ─────────────────────────────
    [
      "blocked = shield blocked + dangerous checked links — never an SMS the person asked about",
      () => names(m.filterHistory(items, "blocked")),
      ["shield:dns-blocked.example", "check:bad-check.example", "shield:link-blocked.example", "shield:legacy.example"],
    ],
    [
      "warned = shield warned + caution checked links",
      () => names(m.filterHistory(items, "warned")),
      ["check:meh.example", "shield:warned.example"],
    ],
    [
      "checked = every SQLite row, links and SMS — the Checked counter",
      () => m.filterHistory(items, "checked").length,
      CHECKS.length,
    ],
    ["sms = message checks only", () => names(m.filterHistory(items, "sms")), ["sms:a.example+b.example", "sms:-"]],
    ["all = everything, including allows", () => m.filterHistory(items, "all").length, items.length],
    ["allows are never counted as blocked or warned", () => m.filterHistory(items, "blocked").some((i) => i.kind === "allowed"), false],

    // ── "only the latest events are shown" ──────────────────────────
    [
      "a lifetime counter above the listed events is a gap for that kind only",
      () => m.shieldGaps([{ kind: "blocked" }, { kind: "blocked" }, { kind: "warned" }], { blocked: 3400, warned: 1 }),
      { shieldBlocked: true, shieldWarned: false },
    ],
    [
      "a counter that matches the log is no gap",
      () => m.shieldGaps([{ kind: "blocked" }, { kind: "allowed" }], { blocked: 1, warned: 0 }),
      { shieldBlocked: false, shieldWarned: false },
    ],
    [
      "the note follows the filter: a blocked gap shows under Blocked and All, not under Warned or SMS",
      () => ["all", "blocked", "warned", "checked", "sms"].map((f) =>
        m.isTruncated(f, { checksFull: false, shieldBlocked: true, shieldWarned: false, smsAlerts: false })),
      [true, true, false, false, false],
    ],
    [
      "a full page of checks shows the note everywhere",
      () => ["all", "blocked", "warned", "checked", "sms"].every((f) =>
        m.isTruncated(f, { checksFull: true, shieldBlocked: false, shieldWarned: false, smsAlerts: false })),
      true,
    ],

    // ── route params ────────────────────────────────────────────────
    ["a known filter param is kept", () => m.parseHistoryFilter("warned"), "warned"],
    ["an array param takes its first value", () => m.parseHistoryFilter(["sms", "all"]), "sms"],
    ["an unknown filter shows everything", () => m.parseHistoryFilter("drop table"), "all"],
    ["a missing filter shows everything", () => m.parseHistoryFilter(undefined), "all"],
    ["a host param is normalised", () => m.parseDeepLinkDomain(" Evil.Example. "), "evil.example"],
    ["punycode is a host", () => m.parseDeepLinkDomain("xn--80ak6aa92e.com"), "xn--80ak6aa92e.com"],
    ["a URL is not a host", () => m.parseDeepLinkDomain("https://evil.example/x"), null],
    ["a single label is not a host", () => m.parseDeepLinkDomain("localhost"), null],
    ["an over-long name is not a host", () => m.parseDeepLinkDomain(`${"a".repeat(250)}.com`), null],
    ["no param, no host", () => m.parseDeepLinkDomain(undefined), null],

    // ── the notification deep link ──────────────────────────────────
    [
      "a notification opens the newest entry of its kind for the site",
      () => {
        const e = m.findShieldEvent(items, "dns-blocked.example", "blocked");
        return [e.kind, e.ts];
      },
      ["blocked", T0 - 0.5 * HOUR],
    ],
    [
      "without a matching kind it falls back to the newest entry for the site",
      () => m.findShieldEvent(items, "dns-blocked.example", "warned").kind,
      "blocked",
    ],
    [
      "a site that is not in the block log opens nothing — even if it was checked by hand",
      () => [m.findShieldEvent(items, "bad-check.example", "blocked"), m.findShieldEvent(items, "never.example", "blocked")],
      [null, null],
    ],

    // ── the automatic SMS check (RuStore build) ─────────────────────
    [
      "without SMS warnings the list is what it always was",
      () => names(m.mergeHistory(CHECKS, SHIELD, [])),
      names(items),
    ],
    [
      "SMS warnings merge in by time",
      () => names(withAlerts).slice(0, 3),
      ["alert:00000000000000a1", "shield:dns-blocked.example", "check:bad-check.example"],
    ],
    ["keys stay unique with SMS warnings", () => new Set(withAlerts.map((i) => i.key)).size === withAlerts.length, true],
    [
      "a warning keeps sender, verdict, reasons and hosts — and nothing else",
      () => {
        const a = withAlerts.find((i) => i.type === "sms_alert");
        return Object.keys(a).sort();
      },
      ["hosts", "id", "key", "reasons", "sender", "ts", "type", "verdict"],
    ],
    [
      "the SMS chip lists warnings and messages checked by hand",
      () => names(m.filterHistory(withAlerts, "sms")),
      ["alert:00000000000000a1", "sms:a.example+b.example", "sms:-", "alert:00000000000000a2"],
    ],
    [
      "Warned lists every SMS warning, whatever its verdict: the home counter adds flaggedCount",
      () => names(m.filterHistory(withAlerts, "warned")),
      ["alert:00000000000000a1", "check:meh.example", "shield:warned.example", "alert:00000000000000a2"],
    ],
    [
      "a warning is never under Blocked or Checked: the phone showed the SMS, and no one checked it by hand",
      () => ["blocked", "checked"].map((f) => m.filterHistory(withAlerts, f).some((i) => i.type === "sms_alert")),
      [false, false],
    ],
    [
      "Warned is exactly its counter's parts: shield warned + caution checks + flagged SMS",
      () => m.filterHistory(withAlerts, "warned").length,
      SHIELD.filter((r) => r.kind === "warned").length + CHECKS.filter((c) => c.level === "caution" && c.source !== "sms").length + ALERTS.length,
    ],
    ["Checked is still exactly the SQLite rows", () => m.filterHistory(withAlerts, "checked").length, CHECKS.length],
    ["All lists the warnings too", () => m.filterHistory(withAlerts, "all").length, items.length + ALERTS.length],
    ["more flagged than listed is a gap", () => m.smsAlertGap(2, 5), true],
    ["as many flagged as listed is no gap", () => m.smsAlertGap(2, 2), false],
    [
      "an SMS gap shows the note under All, Warned and SMS — the chips that list warnings",
      () => ["all", "blocked", "warned", "checked", "sms"].map((f) =>
        m.isTruncated(f, { checksFull: false, shieldBlocked: false, shieldWarned: false, smsAlerts: true })),
      [true, false, true, false, true],
    ],
    ["a stored SMS id is kept", () => m.parseDeepLinkSmsId("00000000000000a1"), "00000000000000a1"],
    ["an array SMS param takes its first value", () => m.parseDeepLinkSmsId(["00000000000000a1", "x"]), "00000000000000a1"],
    [
      "anything but a stored id's shape is ignored",
      () => ["00000000000000A1", "0a1", "../../etc", "00000000000000a1&filter=all", 12, undefined].map((v) => m.parseDeepLinkSmsId(v)),
      [null, null, null, null, null, null],
    ],
    [
      "a warning's link opens that warning",
      () => {
        const a = m.findSmsAlert(withAlerts, "00000000000000a1");
        return [a.sender, a.verdict, a.hosts];
      },
      ["900", "dangerous", ["gosuslugi-help.ru"]],
    ],
    [
      "an id the log does not hold opens nothing — a crafted link cannot show a made-up warning",
      () => [m.findSmsAlert(withAlerts, "ffffffffffffffff"), m.findSmsAlert(items, "00000000000000a1")],
      [null, null],
    ],

    // ── helpers ─────────────────────────────────────────────────────
    ["message hosts split on spaces", () => m.splitHosts("a.example  b.example"), ["a.example", "b.example"]],
    ["no hosts from a non-string", () => m.splitHosts(null), []],
    ["an unreadable time is NaN, not now", () => Number.isNaN(m.parseCheckedAt("yesterday-ish")), true],
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

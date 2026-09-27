#!/usr/bin/env node
/**
 * Table test for "Проверка защиты" — run with `node scripts/test-checkup.mjs`.
 *
 * Pinned here:
 *  - Part 1 says only what the phone actually read: a state it cannot read
 *    has no row, a probe in flight says "checking", and every wrong row
 *    carries the one fix it has;
 *  - Part 2 counts the person's own marks ("done N of M", never a score),
 *    counts the call step only by a saved number, and shows the Russian
 *    steps only where they apply;
 *  - the saved number is a plain dialable one — the same table as
 *    ProtectionCheckupTest.kt, so the JS and native rules cannot drift;
 *  - no official link shows its button until a person verified it, and
 *    every one points at https://www.gosuslugi.ru.
 * Same approach as test-check-verdict.mjs: compile with the tree's
 * TypeScript, run the table for real, exit non-zero on failure. CommonJS
 * output, because checkup.ts imports phone-number.ts at run time and an
 * ES module import would need the ".js" the sources do not write.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const files = ["src/utils/checkup.ts", "src/config/official-links.ts", "src/config/market.ts"];
const out = mkdtempSync(join(tmpdir(), "cleanway-checkup-"));

const HOUR = 3_600_000;
const shield = (state, extra = {}) => ({
  state, probing: false, interrupted: false, pausedTime: "14:35", privateDnsHost: null,
  list: { count: 430_000, stale: false, ageMs: 3 * HOUR }, ...extra,
});
const input = (extra = {}) => ({
  shield: shield("on"), linkGuard: { on: true }, alertsOn: true, backgroundRestricted: false, ...extra,
});
const brief = (rows) => rows.map((r) => [r.id, r.status, r.key.replace("mobile.checkup.device.", ""), r.fix ?? null]);
const rowOf = (rows, id) => rows.find((r) => r.id === id);

try {
  execFileSync(
    "npx",
    [
      "tsc", ...files.map((f) => resolve(root, f)), "--outDir", out, "--rootDir", root,
      "--module", "commonjs", "--target", "es2020", "--moduleResolution", "node", "--skipLibCheck",
    ],
    { cwd: root, stdio: "inherit" },
  );

  const load = createRequire(join(out, "index.js"));
  const m = load("./src/utils/checkup.js");
  const phone = load("./src/utils/phone-number.js");
  const links = load("./src/config/official-links.js");
  const market = load("./src/config/market.js");

  const steps = (russia, android) => m.familySteps({ russia, android }).map((s) => s.id);
  const ALL = m.FAMILY_STEPS;

  const CASES = [
    // ── Part 1: only what the phone can tell ─────────────────────────
    [
      "a phone that can tell nothing gets no rows (iOS, an old build)",
      () => m.deviceChecks({ shield: null, linkGuard: null, alertsOn: null, backgroundRestricted: null }),
      [],
    ],
    [
      "all fine: every row ok, in screen order, nothing to fix",
      () => {
        const rows = m.deviceChecks(input());
        return [brief(rows), m.fixCount(rows), rowOf(rows, "list").params];
      },
      [
        [
          ["shield", "ok", "shield_on", null],
          ["links", "ok", "links_on", null],
          ["alerts", "ok", "alerts_on", null],
          ["battery", "ok", "battery_ok", null],
          ["list", "ok", "list_fresh", null],
        ],
        0,
        { hours: 3 },
      ],
    ],
    [
      "shield never set up: fix turns it on; the list waits on it instead of a second fix",
      () => brief(m.deviceChecks(input({ shield: shield("setup") }))).filter(([id]) => id === "shield" || id === "list"),
      [["shield", "fix", "shield_off", "shield_on"], ["list", "wait", "list_needs_shield", null]],
    ],
    [
      "shield was on and stopped: says it stopped, same fix",
      () => brief([rowOf(m.deviceChecks(input({ shield: shield("setup", { interrupted: true }) })), "shield")]),
      [["shield", "fix", "shield_stopped", "shield_on"]],
    ],
    [
      "strict Private DNS: the fix is that setting, and the host is named",
      () => {
        const row = rowOf(m.deviceChecks(input({ shield: shield("conflict", { privateDnsHost: "dns.google" }) })), "shield");
        return [row.status, row.fix, row.params];
      },
      ["fix", "private_dns", { host: "dns.google" }],
    ],
    [
      "paused: not protected, the fix resumes, the end time is shown",
      () => {
        const rows = m.deviceChecks(input({ shield: shield("paused") }));
        return [rowOf(rows, "shield").fix, rowOf(rows, "shield").params, rowOf(rows, "list").status];
      },
      ["shield_resume", { time: "14:35" }, "ok"],
    ],
    [
      "probe in flight: 'checking', never the negative state, no fix",
      () => brief([rowOf(m.deviceChecks(input({ shield: shield("unverified", { probing: true }) })), "shield")]),
      [["shield", "wait", "shield_checking", null]],
    ],
    [
      "offline and unverified: said as they are, with no fix that could not help",
      () => [
        brief([rowOf(m.deviceChecks(input({ shield: shield("offline") })), "shield")]),
        brief([rowOf(m.deviceChecks(input({ shield: shield("unverified") })), "shield")]),
      ],
      [[["shield", "wait", "shield_offline", null]], [["shield", "wait", "shield_unverified", null]]],
    ],
    [
      "the list: missing and stale each get a refresh; under an hour reads 'just now'",
      () => [
        brief([rowOf(m.deviceChecks(input({ shield: shield("on", { list: { count: 0, stale: true, ageMs: null } }) })), "list")]),
        brief([rowOf(m.deviceChecks(input({ shield: shield("on", { list: { count: 9, stale: true, ageMs: 30 * HOUR } }) })), "list")]),
        brief([rowOf(m.deviceChecks(input({ shield: shield("on", { list: { count: 9, stale: false, ageMs: 10 * 60_000 } }) })), "list")]),
      ],
      [
        [["list", "fix", "list_missing", "list_refresh"]],
        [["list", "fix", "list_stale", "list_refresh"]],
        [["list", "ok", "list_fresh_now", null]],
      ],
    ],
    [
      "link guard off, alerts off, battery restricted: each with its own fix",
      () => {
        const rows = m.deviceChecks(input({ linkGuard: { on: false }, alertsOn: false, backgroundRestricted: true }));
        return [brief(rows).slice(1, 4), m.fixCount(rows)];
      },
      [
        [
          ["links", "fix", "links_off", "links_on"],
          ["alerts", "fix", "alerts_off", "alerts_on"],
          ["battery", "fix", "battery_restricted", "battery"],
        ],
        3,
      ],
    ],
    [
      "unknown notification and battery state: no row, never a guessed 'fine'",
      () => m.deviceChecks(input({ alertsOn: null, backgroundRestricted: null })).map((r) => r.id),
      ["shield", "links", "list"],
    ],

    // ── Part 2: the family steps ──────────────────────────────────────
    [
      "Russia on Android: all seven, in the roadmap's order",
      () => steps(true, true),
      ["credit_ban", "sim_ban", "second_hand", "caller_id", "install_block", "code_word", "call_close_one"],
    ],
    ["Russia on an iPhone: no Android setting", () => steps(true, false).length, 6],
    ["elsewhere on Android: no Госуслуги, no Russian banks", () => steps(false, true), ["install_block", "code_word", "call_close_one"]],
    ["elsewhere on an iPhone", () => steps(false, false), ["code_word", "call_close_one"]],
    ["every official-link step has its link", () => ALL.filter((s) => s.link).every((s) => links.OFFICIAL_LINKS[s.link] !== undefined), true],
    [
      "progress counts marks, and the call step only by a saved number",
      () => {
        const all = m.familySteps({ russia: true, android: true });
        const marks = new Set(["credit_ban", "code_word", "call_close_one"]);
        return [m.familyProgress(all, marks, false), m.familyProgress(all, marks, true)];
      },
      [{ done: 2, total: 7 }, { done: 3, total: 7 }],
    ],
    [
      "a mark for a step not shown here does not count",
      () => m.familyProgress(m.familySteps({ russia: false, android: false }), new Set(["credit_ban"]), false),
      { done: 0, total: 2 },
    ],
    [
      "stored marks are re-validated: known ids once, never the call step",
      () => [
        m.parseMarks(null),
        m.parseMarks("not json"),
        m.parseMarks('{"credit_ban":true}'),
        m.parseMarks('["credit_ban","credit_ban","evil",7,"call_close_one","sim_ban"]'),
      ],
      [[], [], [], ["credit_ban", "sim_ban"]],
    ],
    [
      "toggling returns a new list and leaves the old one as it was",
      () => {
        const before = ["credit_ban"];
        const on = m.toggleMark(before, "sim_ban");
        const off = m.toggleMark(on, "credit_ban");
        return [before, on, off];
      },
      [["credit_ban"], ["credit_ban", "sim_ban"], ["sim_ban"]],
    ],
    ["Russian steps: Russian UI", () => market.russianStepsVisible("ru", null), true],
    ["Russian steps: a regional Russian tag", () => market.russianStepsVisible("ru-RU", "KZ"), true],
    ["Russian steps: another language on a phone set to Russia", () => market.russianStepsVisible("en", "ru"), true],
    ["Russian steps: not for Spanish in Spain", () => market.russianStepsVisible("es", "ES"), false],
    ["Russian steps: not when the region is unknown", () => market.russianStepsVisible("de", undefined), false],

    // ── the saved number (mirror of ProtectionCheckupTest.kt) ────────
    [
      "numbers in the shapes people write them",
      () => ["+7 916 123-45-67", "+7 (916) 123-45-67", "8 916 123 45 67", "  8-916-123-45-67  "].map(phone.normalizePhone),
      ["+79161234567", "+79161234567", "89161234567", "89161234567"],
    ],
    ["address-book separators", () => phone.normalizePhone("+7 916‑123.45.67"), "+79161234567"],
    ["short service numbers", () => ["112", "900"].map(phone.normalizePhone), ["112", "900"]],
    [
      "USSD codes, extensions and pauses are refused",
      () => ["*#06#", "*100#", "+79161234567;ext=12", "+79161234567,1", "89161234567p12"].map(phone.normalizePhone),
      [null, null, null, null, null],
    ],
    [
      "letters, a second plus and non-ASCII digits are refused",
      () => ["Саша", "++79161234567", "7+9161234567", "٨٩١٦١٢٣٤٥٦٧"].map(phone.normalizePhone),
      [null, null, null, null],
    ],
    [
      "empty, too short and too long are refused",
      () => [null, undefined, "", "  ", "+", "12", "1234567890123456"].map(phone.normalizePhone),
      [null, null, null, null, null, null, null],
    ],
    [
      "read back the way it is spoken",
      () => ["+79161234567", "89161234567", "112", "+442071234567"].map(phone.formatPhone),
      ["+7 916 123-45-67", "8 916 123-45-67", "112", "+442071234567"],
    ],
    [
      "a contact: number normalised, name trimmed and capped, blank name dropped",
      () => [
        m.makeCloseOne("  Саша ", "+7 916 123-45-67"),
        m.makeCloseOne("   ", "8 916 123 45 67"),
        m.makeCloseOne("Я".repeat(60), "112").name.length,
        m.makeCloseOne("Саша", "*100#"),
      ],
      [
        { name: "Саша", number: "+79161234567" },
        { name: null, number: "89161234567" },
        m.MAX_NAME_LENGTH,
        null,
      ],
    ],
    [
      "a stored contact is re-validated; a broken one reads as none",
      () => [
        m.parseCloseOne('{"name":"Мама","number":"+79161234567"}'),
        m.parseCloseOne('{"name":"Мама","number":"*#06#"}'),
        m.parseCloseOne('{"number":79161234567}'),
        m.parseCloseOne("{"),
        m.parseCloseOne(null),
      ],
      [{ name: "Мама", number: "+79161234567" }, null, null, null, null],
    ],

    // ── official links ────────────────────────────────────────────────
    [
      "every official link is https on www.gosuslugi.ru",
      () => Object.values(links.OFFICIAL_LINKS).every((l) => /^https:\/\/www\.gosuslugi\.ru\/[^\s]*$/.test(l.url)),
      true,
    ],
    [
      "verified_on is empty or a real date not in the future",
      () => Object.values(links.OFFICIAL_LINKS).every(
        (l) => l.verified_on === "" || (links.isVerified(l) && Date.parse(l.verified_on) <= Date.now()),
      ),
      true,
    ],
    [
      "an unverified link has no button outside a review build",
      () => {
        const link = { url: "https://www.gosuslugi.ru/x", expect: "", source: "", verified_on: "" };
        return [links.linkButtonVisible(link, false), links.linkButtonVisible(link, true)];
      },
      [false, true],
    ],
    [
      "a verified link shows its button in any build; a malformed date does not count",
      () => {
        const at = (verified_on) => ({ url: "https://www.gosuslugi.ru/x", expect: "", source: "", verified_on });
        return [links.linkButtonVisible(at("2026-10-01"), false), links.linkButtonVisible(at("01.10.2026"), false)];
      },
      [true, false],
    ],
    ["the button names the host it opens", () => links.linkHost(links.OFFICIAL_LINKS.credit_ban), "gosuslugi.ru"],
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
  const unverified = Object.entries(links.OFFICIAL_LINKS).filter(([, l]) => !links.isVerified(l)).map(([id]) => id);
  if (links.REVIEW_SHOWS_UNVERIFIED_LINKS && unverified.length > 0) {
    // Not a failure — the draft needs it — but never a silent one.
    console.log(`\n  NOTE  REVIEW_SHOWS_UNVERIFIED_LINKS is on; unverified links visible: ${unverified.join(", ")}`);
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

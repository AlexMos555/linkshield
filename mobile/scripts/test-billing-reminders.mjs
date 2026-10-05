#!/usr/bin/env node
/**
 * Table test for src/utils/billing-reminders.ts — run with `node scripts/test-billing-reminders.mjs`.
 *
 * Reminders for an elderly person who already gets scam SMS all day: few,
 * spaced, and NEVER with a link. The last point is checked against the
 * generated locale files, every language: a reminder body that carried a
 * URL would teach the person that tapping links in notifications is normal.
 */
import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const appRequire = createRequire(join(root, "package.json"));
const ts = appRequire("typescript");

function loadTs(file) {
  const { outputText } = ts.transpileModule(readFileSync(file, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
    fileName: file,
  });
  const module = { exports: {} };
  const requireHere = (spec) => (spec.startsWith(".") ? loadTs(resolve(dirname(file), `${spec}.ts`)) : appRequire(spec));
  new Function("require", "module", "exports", outputText)(requireHere, module, module.exports);
  return module.exports;
}

const { remindersFor, reminderCopyKeys, looksLikeLink, spaced, MIN_GAP_SEC, MAX_PER_PERIOD } =
  loadTs(join(root, "src/utils/billing-reminders.ts"));

const NOW = 1_800_000_000;
const DAY = 86_400;
const END = NOW + 14 * DAY;
const GRACE_UNTIL = NOW + 7 * DAY;

const kinds = (rs) => rs.map((r) => r.kind);
const offsets = (rs, from) => rs.map((r) => (r.atSec - from) / DAY);

const CASES = [
  ["a fresh trial: one reminder at 3 days left, one on the last day", () => {
    const rs = remindersFor({ kind: "trial", endsAt: END, daysLeft: 14, ending: false }, NOW);
    return { kinds: kinds(rs), days: offsets(rs, END), ids: rs.map((r) => r.id) };
  }, { kinds: ["trial_ending", "trial_last_day"], days: [-3, -1], ids: [`billing:trial:${END}:3`, `billing:trial:${END}:1`] }],
  ["two days before the end only the last-day reminder is still ahead", () =>
    kinds(remindersFor({ kind: "trial", endsAt: END, daysLeft: 2, ending: true }, END - 2 * DAY)), ["trial_last_day"]],
  ["on the last day nothing more is scheduled", () => remindersFor({ kind: "trial", endsAt: END, daysLeft: 0, ending: true }, END - 3600), []],
  ["grace: days 1, 3, 5 and 7 after the failed charge, none after the window", () => {
    const rs = remindersFor({ kind: "grace", plan: "solo", graceUntil: GRACE_UNTIL, daysLeft: 7, isPayer: true, priceRub: 99 }, NOW);
    return { days: offsets(rs, NOW), count: rs.length, max: MAX_PER_PERIOD };
  }, { days: [1, 3, 5, 7], count: 4, max: 4 }],
  ["grace, learned about on day 4: only days 5 and 7 remain", () =>
    offsets(remindersFor({ kind: "grace", plan: "solo", graceUntil: GRACE_UNTIL, daysLeft: 3, isPayer: true, priceRub: 99 }, NOW + 4 * DAY), NOW), [5, 7]],
  ["grace reminders a relative's phone sees are the same (the server decides who pays)", () =>
    offsets(remindersFor({ kind: "grace", plan: "solo", graceUntil: GRACE_UNTIL, daysLeft: 7, isPayer: false, priceRub: 99 }, NOW), NOW), [1, 3, 5, 7]],
  ["lapsed to basic: one reminder now, never again once shown", () => {
    const view = { kind: "lapsed", after: "subscription", mode: "basic" };
    const first = remindersFor(view, NOW);
    const again = remindersFor(view, NOW + DAY, new Set(first.map((r) => r.id)));
    return { first: kinds(first), at: first[0].atSec === NOW, again };
  }, { first: ["lapsed_basic"], at: true, again: [] }],
  ["lapsed to off says so", () => kinds(remindersFor({ kind: "lapsed", after: "trial", mode: "off" }, NOW)), ["lapsed_off"]],
  ["nothing for an active, cancelled, legacy, pending or hidden state", () => [
    { kind: "active", source: "subscription", plan: "solo", seatsUsed: 1, seatsTotal: 1, priceRub: 99, nextChargeAt: NOW + DAY, periodEnd: NOW + DAY, isPayer: true },
    { kind: "cancelled", plan: "solo", periodEnd: NOW + DAY, isPayer: true }, { kind: "legacy" }, { kind: "pending", plan: "solo" }, { kind: "hidden" }, { kind: "unknown" },
  ].map((v) => remindersFor(v, NOW).length), [0, 0, 0, 0, 0, 0]],
  ["never two reminders closer than the gap", () => {
    const rs = spaced([
      { id: "a", kind: "grace", atSec: NOW }, { id: "b", kind: "grace", atSec: NOW + 3600 },
      { id: "c", kind: "grace", atSec: NOW + MIN_GAP_SEC }, { id: "d", kind: "grace", atSec: NOW + MIN_GAP_SEC + 10 },
    ]);
    return rs.map((r) => r.id);
  }, ["a", "c"]],
  ["copy keys follow the kind", () => reminderCopyKeys("grace"), { title: "mobile.billing.reminder_grace_title", body: "mobile.billing.reminder_grace_body" }],
  ["what counts as a link", () => ["https://cleanway.ai", "cleanway.ai/ru", "www.x.com", "Откройте приложение Cleanway", "в разделе «Подписка»"].map(looksLikeLink),
    [true, true, true, false, false]],
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

// ── no link in any reminder, any language ──
const i18nDir = join(root, "i18n");
const KINDS = ["trial_ending", "trial_last_day", "grace", "lapsed_basic", "lapsed_off"];
for (const file of readdirSync(i18nDir).filter((f) => f.endsWith(".json")).sort()) {
  const strings = JSON.parse(readFileSync(join(i18nDir, file), "utf8"));
  const problems = [];
  for (const kind of KINDS) {
    for (const key of Object.values(reminderCopyKeys(kind))) {
      const text = strings[key];
      if (typeof text !== "string" || !text.trim()) problems.push(`${key} missing`);
      else if (looksLikeLink(text)) problems.push(`${key} carries a link: ${text}`);
    }
  }
  if (problems.length === 0) {
    console.log(`  ok    ${file}: every reminder exists and none carries a link`);
  } else {
    failed += 1;
    console.log(`  FAIL  ${file}:\n        ${problems.join("\n        ")}`);
  }
}

if (failed > 0) {
  console.error(`\n${failed} failures`);
  process.exitCode = 1;
} else {
  console.log(`\nall ${CASES.length} cases pass, reminders carry no link in any locale`);
}

#!/usr/bin/env node
/**
 * Table test for what the app says and offers about the automatic SMS check
 * (RuStore build) — run with `node scripts/test-sms-shield-ui.mjs`.
 *
 *  - src/utils/sms-shield-view.ts: the card's state. A card that reads "On"
 *    while warnings cannot reach the person, or while Android no longer
 *    delivers SMS, is the placebo this app refuses to ship; a restricted
 *    install left without the App-info steps — or without a way to ask again
 *    once they are done — is a dead end for a grandma.
 *  - src/config/stores.ts: the RuStore line appears only for a live listing
 *    with a real rustore.ru https page — never a dead link, never another host.
 *  - src/lib/update-check.ts planUpdate: a RuStore install is never sent to the
 *    website APK, which would silently remove its SMS check.
 *
 * Same approach as test-history-model.mjs: compile the files with the tree's
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
const FILES = ["src/utils/sms-shield-view.ts", "src/config/stores.ts", "src/lib/update-check.ts"];
const out = mkdtempSync(join(tmpdir(), "cleanway-sms-ui-"));

/** A status where every link of the chain holds; each case breaks one. */
const ON = {
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
const HOUR = 3_600_000;
const STORE = "https://www.rustore.ru/catalog/app/ai.cleanway.app";
const INFO = { latestVersionName: "1.0.2", minSupportedVersionName: null, apkUrl: "https://cleanway.ai/cleanway-1.0.2.apk", releaseNotes: null };

try {
  execFileSync(
    "npx",
    [
      "tsc", ...FILES.map((f) => resolve(root, f)), "--outDir", out, "--rootDir", root,
      "--module", "esnext", "--target", "es2020", "--moduleResolution", "bundler", "--skipLibCheck",
    ],
    { cwd: root, stdio: "inherit" },
  );
  const load = (f) => import(pathToFileURL(join(out, f.replace(/\.ts$/, ".js"))).href);
  const v = await load(FILES[0]);
  const stores = await load(FILES[1]);
  const upd = await load(FILES[2]);

  const view = (over = {}) => v.smsShieldView({ ...ON, ...over });
  const kind = (over) => view(over).kind;

  const CASES = [
    // ── the card's state ────────────────────────────────────────────
    ["every link holds: on, with the count", () => view(), { kind: "on", checked: 42 }],
    ["on is the only verified state", () => v.isSmsShieldVerified(view()), true],
    ["the website APK and iOS: no card at all", () => kind({ supported: false }), "unsupported"],
    ["unsupported wins over anything else it might report", () => kind({ supported: false, enabled: true }), "unsupported"],
    ["never asked, switch off: first set-up", () => view({ enabled: false, permission: "not_requested" }), { kind: "setup", why: "first" }],
    ["allowed, switch off: paused — one tap back", () => view({ enabled: false, permission: "granted" }), { kind: "setup", why: "paused" }],
    [
      "refused once in a real dialog (Android will ask again): set-up that says so",
      () => view({ enabled: false, permission: "denied", canAskAgain: true }),
      { kind: "setup", why: "refused" },
    ],
    [
      "refused and Android will not ask again (second no, \"don't ask again\", an installer that never allowed SMS): App info",
      () => [kind({ enabled: false, permission: "denied" }), kind({ permission: "denied" })],
      ["blocked", "blocked"],
    ],
    ["restricted, switch off: the restricted-settings steps come first", () => kind({ enabled: false, permission: "restricted_maybe" }), "restricted"],
    ["restricted while on: still the steps", () => kind({ permission: "restricted_maybe" }), "restricted"],
    ["on, but access revoked and Android can ask again: not working, said so", () => kind({ permission: "denied", canAskAgain: true }), "permission_off"],
    ["on, never asked (access granted elsewhere then revoked): not working", () => kind({ permission: "not_requested" }), "permission_off"],
    ["checking but warnings cannot show: not on", () => kind({ notificationsEnabled: false }), "notifications"],
    ["battery restricted: not on", () => kind({ backgroundRestricted: true }), "battery"],
    ["the permission problem is named before the notification one", () => kind({ permission: "denied", canAskAgain: true, notificationsEnabled: false }), "permission_off"],
    ["notifications before battery", () => kind({ notificationsEnabled: false, backgroundRestricted: true }), "notifications"],
    [
      "nothing short of every link is verified",
      () => [
        { enabled: false }, { permission: "denied", canAskAgain: true }, { notificationsEnabled: false },
        { backgroundRestricted: true }, { supported: false }, { permission: "restricted_maybe" },
      ].map((over) => v.isSmsShieldVerified(view(over))),
      [false, false, false, false, false, false],
    ],
    [
      "listening: on, and the states where SMS are still read — never a switched-off one",
      () => [{}, { notificationsEnabled: false }, { backgroundRestricted: true }, { permission: "denied" }, { enabled: false }]
        .map((over) => v.isSmsShieldListening(view(over))),
      [true, true, true, false, false],
    ],

    // ── one action each ─────────────────────────────────────────────
    [
      "each state's one fix",
      () => [
        view({ enabled: false, permission: "not_requested" }),
        view({ permission: "restricted_maybe" }),
        view({ permission: "denied" }),
        view({ permission: "denied", canAskAgain: true }),
        view({ notificationsEnabled: false }),
        view({ backgroundRestricted: true }),
        view(),
        view({ supported: false }),
      ].map(v.smsShieldAction),
      ["enable", "open_app_settings", "open_app_settings", "request_sms", "open_notifications", "open_app_settings", null, null],
    ],

    [
      "\"Turn on\" stays offered while restricted or blocked: after the App-info steps, asking again is the only way on",
      () => [
        view({ enabled: false, permission: "not_requested" }), view({ permission: "restricted_maybe" }), view({ permission: "denied" }),
        view(), view({ permission: "denied", canAskAgain: true }), view({ notificationsEnabled: false }), view({ backgroundRestricted: true }),
      ].map(v.offersTurnOn),
      [true, true, true, false, false, false, false],
    ],

    // ── the list line ───────────────────────────────────────────────
    ["a fresh list says nothing", () => v.smsListNote(view(), HOUR), null],
    ["no list while listening: say so", () => v.smsListNote(view(), null), "missing"],
    ["a day-old list: say so", () => v.smsListNote(view(), 25 * HOUR), "stale"],
    ["exactly a day is still fresh", () => v.smsListNote(view(), 24 * HOUR), null],
    ["switched off: no list line — nothing is checked with it", () => v.smsListNote(view({ enabled: false }), null), null],

    // ── the RuStore listing ─────────────────────────────────────────
    ["not live: no line", () => stores.rustoreListingUrl({ available: false, url: STORE }), null],
    ["the shipped config is not live yet", () => stores.rustoreListingUrl(), null],
    ["live with a rustore.ru page: that page", () => stores.rustoreListingUrl({ available: true, url: ` ${STORE} ` }), STORE],
    ["the bare domain is a page", () => stores.rustoreListingUrl({ available: true, url: "https://rustore.ru" }), "https://rustore.ru"],
    [
      "anything but an https rustore.ru page hides the line",
      () => [
        "", "http://www.rustore.ru/catalog/app/ai.cleanway.app", "https://rustore.ru.evil.example/app",
        "https://evilrustore.ru/app", "https://evil.example/rustore.ru", "rustore://app/ai.cleanway.app",
        "https://www.rustore.ru/catalog app", "javascript:alert(1)",
      ].map((url) => stores.rustoreListingUrl({ available: true, url })),
      [null, null, null, null, null, null, null, null],
    ],

    // ── where "Update" leads ────────────────────────────────────────
    [
      "the website APK: unchanged — the signed APK",
      () => upd.planUpdate("1.0.1", INFO, "direct", INFO.apkUrl, STORE),
      { decision: "optional", url: INFO.apkUrl, viaStore: false },
    ],
    [
      "a RuStore install is never sent to the website APK: the listing when live",
      () => upd.planUpdate("1.0.1", INFO, "rustore", INFO.apkUrl, STORE),
      { decision: "optional", url: STORE, viaStore: true },
    ],
    [
      "a RuStore install with no live listing hears nothing — RuStore updates it",
      () => upd.planUpdate("1.0.1", { ...INFO, minSupportedVersionName: "1.0.2" }, "rustore", INFO.apkUrl, null),
      { decision: "none", url: "", viaStore: true },
    ],
    [
      "a security floor still insists, through the store",
      () => upd.planUpdate("1.0.0", { ...INFO, minSupportedVersionName: "1.0.1" }, "rustore", INFO.apkUrl, STORE).decision,
      "required",
    ],
    [
      "the website APK without a signed file cannot be forced",
      () => upd.planUpdate("1.0.0", { ...INFO, apkUrl: null, minSupportedVersionName: "1.0.1" }, "direct", "https://cleanway.ai/android", null).decision,
      "optional",
    ],
    ["up to date: nothing, on either channel", () => ["direct", "rustore"].map((c) => upd.planUpdate("1.0.2", INFO, c, INFO.apkUrl, STORE).decision), ["none", "none"]],
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

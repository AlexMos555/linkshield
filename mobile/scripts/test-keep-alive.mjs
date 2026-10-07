#!/usr/bin/env node
/**
 * Table test for the "Keep protection on" list — run with
 * `node scripts/test-keep-alive.mjs`.
 *
 * Pins three things, each a way to lie quietly:
 *  - modules/cleanway-vpn/src/KeepAliveStatus.ts: the native map degrades
 *    field by field — a missing or odd value is "cannot tell" (null), never a
 *    tick, and an unknown phone maker gets no steps rather than wrong ones;
 *  - src/utils/keep-alive.ts: a row is "done" only when the phone reports it
 *    (the phone maker's own manager is never ticked; Always-on is offered,
 *    never shown as missing);
 *  - the card's dynamic keys (`running_${shield}`, `state_${state}`,
 *    `oem_*_${family}`) exist in all 10 generated locales — the i18n contract
 *    check cannot see template-literal keys.
 * Same approach as test-history-model.mjs: compile with the tree's
 * TypeScript, run the table for real, exit non-zero on failure.
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const statusSrc = resolve(root, "modules/cleanway-vpn/src/KeepAliveStatus.ts");
const rowsSrc = resolve(root, "src/utils/keep-alive.ts");
const out = mkdtempSync(join(tmpdir(), "cleanway-keepalive-"));

let failed = 0;
function check(name, got, want) {
  try {
    deepStrictEqual(got, want);
  } catch {
    failed += 1;
    console.log(`FAIL ${name}\n  got:  ${JSON.stringify(got)}\n  want: ${JSON.stringify(want)}`);
  }
}

try {
  execFileSync(
    "npx",
    ["tsc", statusSrc, rowsSrc, "--outDir", out, "--rootDir", root, "--module", "esnext", "--target", "es2020",
      "--moduleResolution", "bundler", "--skipLibCheck"],
    { cwd: root, stdio: "inherit" },
  );
  const { parseKeepAliveStatus, parseRearmDecision, OEM_FAMILIES, UNKNOWN_KEEP_ALIVE } = await import(
    pathToFileURL(join(out, "modules/cleanway-vpn/src/KeepAliveStatus.js")).href
  );
  const { keepAliveRows, keepAliveTodo, shieldForKeepAlive } = await import(
    pathToFileURL(join(out, "src/utils/keep-alive.js")).href
  );

  // ── The native map ──────────────────────────────────────────────────────
  const unknown = { batteryUnrestricted: null, alwaysOn: null, oem: null };
  check("unknown constant", UNKNOWN_KEEP_ALIVE, unknown);
  check("full map passes", parseKeepAliveStatus({ batteryUnrestricted: true, alwaysOn: false, oem: "xiaomi" }),
    { batteryUnrestricted: true, alwaysOn: false, oem: "xiaomi" });
  check("older build: no map", parseKeepAliveStatus(undefined), unknown);
  check("null", parseKeepAliveStatus(null), unknown);
  check("array", parseKeepAliveStatus([true]), unknown);
  check("string", parseKeepAliveStatus("samsung"), unknown);
  check("non-boolean values are cannot-tell, never a tick",
    parseKeepAliveStatus({ batteryUnrestricted: "true", alwaysOn: 1, oem: "samsung" }),
    { batteryUnrestricted: null, alwaysOn: null, oem: "samsung" });
  check("Always-on unreadable while the shield is off",
    parseKeepAliveStatus({ batteryUnrestricted: false, alwaysOn: null, oem: null }),
    { batteryUnrestricted: false, alwaysOn: null, oem: null });
  check("unknown phone maker: no steps", parseKeepAliveStatus({ batteryUnrestricted: true, oem: "nokia" }).oem, null);
  check("phone maker is case-exact (the native wire name)", parseKeepAliveStatus({ oem: "Samsung" }).oem, null);
  check("phone makers match KeepAlivePolicy.OemFamily.wire", [...OEM_FAMILIES],
    ["samsung", "xiaomi", "huawei", "oppo", "vivo"]);

  for (const d of ["start", "running", "not_wanted", "taken_away", "private_dns", "other_vpn", "budget", "no_consent"]) {
    check(`rearm decision ${d}`, parseRearmDecision(d), d);
  }
  check("unknown rearm decision", parseRearmDecision("START"), null);
  check("no rearm decision", parseRearmDecision(undefined), null);

  // ── The shield, folded ──────────────────────────────────────────────────
  check("on + verified", shieldForKeepAlive("on", true), "on");
  check("on, not verified (paused hides verified)", shieldForKeepAlive("on", false), "unproven");
  check("unverified", shieldForKeepAlive("unverified", false), "unproven");
  check("offline", shieldForKeepAlive("offline", false), "unproven");
  check("paused", shieldForKeepAlive("paused", false), "paused");
  check("setup (stopped by something else)", shieldForKeepAlive("setup", false), "off");
  check("conflict", shieldForKeepAlive("conflict", false), "off");

  // ── The rows ────────────────────────────────────────────────────────────
  const rows = (shield, status, notifications) => keepAliveRows({ shield, status, notifications });
  const ids = (r) => r.map((x) => `${x.id}:${x.state}`);

  check("everything reported set, stock Android",
    ids(rows("on", { batteryUnrestricted: true, alwaysOn: true, oem: null }, true)),
    ["running:ok", "battery:ok", "notifications:ok", "always_on:ok"]);
  check("Samsung killed it overnight: the steps that matter come first",
    ids(rows("off", { batteryUnrestricted: false, alwaysOn: null, oem: "samsung" }, true)),
    ["running:todo", "battery:todo", "oem:manual", "notifications:ok", "always_on:optional"]);
  check("alerts off is a step",
    ids(rows("on", { batteryUnrestricted: true, alwaysOn: false, oem: null }, false)),
    ["running:ok", "battery:ok", "notifications:todo", "always_on:optional"]);
  check("unreadable values are left out, never guessed",
    ids(rows("unproven", unknown, null)),
    ["running:unknown", "always_on:optional"]);
  check("paused is the person's choice, not a fault",
    ids(rows("paused", { batteryUnrestricted: true, alwaysOn: null, oem: null }, true)),
    ["running:unknown", "battery:ok", "notifications:ok", "always_on:optional"]);
  check("Always-on off is offered, never a step",
    rows("on", { batteryUnrestricted: true, alwaysOn: false, oem: null }, true).find((r) => r.id === "always_on").state,
    "optional");
  check("the phone maker's manager is never ticked",
    rows("on", { batteryUnrestricted: true, alwaysOn: true, oem: "vivo" }, true).find((r) => r.id === "oem").state,
    "manual");

  check("todo count: battery + alerts + the shield",
    keepAliveTodo(rows("off", { batteryUnrestricted: false, alwaysOn: null, oem: "xiaomi" }, false)), 3);
  check("todo count: optional, manual and unknown do not count",
    keepAliveTodo(rows("unproven", { batteryUnrestricted: true, alwaysOn: false, oem: "oppo" }, true)), 0);

  // ── Dynamic keys the card builds, in every generated locale ─────────────
  const dynamic = [
    ...["on", "unproven", "paused", "off"].map((s) => `mobile.keep_alive.running_${s}`),
    ...["ok", "todo", "optional", "manual", "unknown"].map((s) => `mobile.keep_alive.state_${s}`),
    ...OEM_FAMILIES.flatMap((f) => ["row", "title", "steps"].map((k) => `mobile.keep_alive.oem_${k}_${f}`)),
  ];
  const i18nDir = resolve(root, "i18n");
  const locales = readdirSync(i18nDir).filter((f) => f.endsWith(".json"));
  check("10 generated locales", locales.length, 10);
  for (const file of locales) {
    const flat = JSON.parse(readFileSync(join(i18nDir, file), "utf8"));
    const missing = dynamic.filter((k) => typeof flat[k] !== "string" || flat[k].length === 0);
    check(`${file}: every dynamic keep-alive key`, missing, []);
  }
} finally {
  rmSync(out, { recursive: true, force: true });
}

if (failed > 0) {
  console.log(`${failed} keep-alive case(s) failed`);
  process.exit(1);
}
console.log("ok: keep-alive status parser, rows and dynamic keys");

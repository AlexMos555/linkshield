#!/usr/bin/env node
/**
 * Table test for src/lib/remote-config.ts — the server's switches for the
 * on-phone checks (the SMS text model's kill switch).
 *
 * Run: node --experimental-strip-types mobile/scripts/test-remote-config.mjs
 *
 * Pinned:
 *   • an answer without a valid block is null, so the phone keeps the
 *     switches it stored — an outage or an older API never flips one;
 *   • a bad threshold is dropped on its own, the on/off switch still counts;
 *   • the JSON handed to the native module uses the keys RemoteConfig.kt
 *     reads and the API sends (the Kotlin tests do not run in CI, so the
 *     three files are cross-checked here);
 *   • the app asks on start, about daily while open, never twice an hour, and
 *     a clock that was ahead never switches the check off.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  DEFAULT_REMOTE_CONFIG,
  MIN_GAP_MS,
  REFRESH_INTERVAL_MS,
  parseRemoteConfig,
  readStamp,
  refreshDue,
  remoteConfigWire,
} from "../src/lib/remote-config.ts";

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`  ok   ${name}`);
  } catch (err) {
    failures += 1;
    console.log(`  FAIL ${name}\n       ${err.message}`);
  }
}

const KEYS = [
  "sms_text_model_enabled",
  "sms_text_model_caution_threshold_override",
  "sms_text_model_danger_threshold_override",
];

console.log("parsing the server's block");
await check("defaults: model on, shipped thresholds", () => {
  assert.deepEqual(DEFAULT_REMOTE_CONFIG, {
    smsTextModelEnabled: true,
    smsTextModelCautionThresholdOverride: null,
    smsTextModelDangerThresholdOverride: null,
  });
});
await check("a full answer is read", () => {
  assert.deepEqual(
    parseRemoteConfig({
      sms_text_model_enabled: false,
      sms_text_model_caution_threshold_override: 0.9,
      sms_text_model_danger_threshold_override: null,
    }),
    { smsTextModelEnabled: false, smsTextModelCautionThresholdOverride: 0.9, smsTextModelDangerThresholdOverride: null },
  );
});
await check("no block, or not a config → null (keep what is stored)", () => {
  for (const raw of [undefined, null, "", "x", 1, [], {}, { sms_text_model_enabled: "false" }, { sms_text_model_enabled: 0 }]) {
    assert.equal(parseRemoteConfig(raw), null, JSON.stringify(raw));
  }
});
await check("a threshold outside (0, 1) is dropped, the switch still counts", () => {
  for (const bad of [0, 1, 1.5, -0.1, NaN, Infinity, "0.9", true]) {
    const c = parseRemoteConfig({ sms_text_model_enabled: true, sms_text_model_danger_threshold_override: bad });
    assert.equal(c?.smsTextModelEnabled, true, String(bad));
    assert.equal(c?.smsTextModelDangerThresholdOverride, null, String(bad));
  }
});

console.log("the native hand-off");
await check("the wire JSON round-trips through the parser", () => {
  for (const c of [
    DEFAULT_REMOTE_CONFIG,
    { smsTextModelEnabled: false, smsTextModelCautionThresholdOverride: 0.91, smsTextModelDangerThresholdOverride: 0.97 },
  ]) {
    const wire = JSON.parse(remoteConfigWire(c));
    assert.deepEqual(Object.keys(wire).sort(), [...KEYS].sort());
    assert.deepEqual(parseRemoteConfig(wire), c);
  }
});
await check("RemoteConfig.kt reads the same keys", () => {
  const kt = readFileSync(
    new URL("../modules/cleanway-vpn/android/src/main/java/ai/cleanway/app/RemoteConfig.kt", import.meta.url),
    "utf8",
  );
  for (const key of KEYS) assert.ok(kt.includes(`"${key}"`), `RemoteConfig.kt lacks ${key}`);
  assert.ok(/fun save\(context: Context, raw: String\)/.test(kt), "RemoteConfigStore.save(context, raw) changed");
});
await check("the native module exposes setRemoteConfig(json)", () => {
  const module = readFileSync(
    new URL("../modules/cleanway-vpn/android/src/main/java/expo/modules/cleanwayvpn/CleanwayVpnModule.kt", import.meta.url),
    "utf8",
  );
  assert.ok(/Function\("setRemoteConfig"\)\s*\{\s*json: String ->/.test(module));
});
await check("the API sends the same keys", () => {
  const py = readFileSync(new URL("../../api/routers/mobile.py", import.meta.url), "utf8");
  assert.ok(py.includes('"remote_config"'), "mobile.py has no remote_config");
  for (const key of KEYS) assert.ok(py.includes(`"${key}"`), `mobile.py lacks ${key}`);
});

console.log("when to ask");
const NOW = 1_800_000_000_000;
const H = 60 * 60 * 1000;
await check("first ever start: ask", () => {
  assert.equal(refreshDue("start", NOW, 0, 0), true);
});
await check("every start asks once the last attempt is an hour old", () => {
  assert.equal(refreshDue("start", NOW, NOW - MIN_GAP_MS, NOW - MIN_GAP_MS), true);
  assert.equal(refreshDue("start", NOW, NOW - 2 * H, NOW - 2 * H), true);
});
await check("never twice within the hour — a launch loop or a failing endpoint", () => {
  assert.equal(refreshDue("start", NOW, NOW - 5 * 60 * 1000, 0), false);
  assert.equal(refreshDue("resume", NOW, NOW - 59 * 60 * 1000, NOW - 30 * H), false);
});
await check("back in front: only once the last success is ~a day old", () => {
  assert.equal(refreshDue("resume", NOW, NOW - 2 * H, NOW - 2 * H), false);
  assert.equal(refreshDue("resume", NOW, NOW - 2 * H, NOW - REFRESH_INTERVAL_MS), true);
  assert.equal(refreshDue("resume", NOW, NOW - 2 * H, 0), true, "never succeeded");
});
await check("a stamp in the future (clock was ahead) is stale, not recent", () => {
  assert.equal(refreshDue("start", NOW, NOW + 10 * H, NOW + 10 * H), true);
  assert.equal(refreshDue("resume", NOW, NOW + 10 * H, NOW + 10 * H), true);
});
await check("stored stamps: junk reads as never", () => {
  assert.equal(readStamp(null), 0);
  assert.equal(readStamp(""), 0);
  assert.equal(readStamp("abc"), 0);
  assert.equal(readStamp("-5"), 0);
  assert.equal(readStamp(String(NOW)), NOW);
});

if (failures) {
  console.log(`\n${failures} failed`);
  process.exit(1);
}
console.log("\nall passed");

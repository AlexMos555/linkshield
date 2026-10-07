#!/usr/bin/env node
/**
 * Table test for src/utils/account-session.ts — the rules behind staying
 * signed in and the Account screen.
 *
 * Run: node --experimental-strip-types mobile/scripts/test-account-session.mjs
 *
 * Pinned:
 *   • the token is refreshed BEFORE it expires (2-minute window), and an
 *     unknown expiry counts as expired;
 *   • concurrent refreshes share one run — GoTrue rotates the refresh token,
 *     a second parallel refresh would spend it twice and sign the person out;
 *     a failed run doesn't poison the next one;
 *   • device heartbeat at most every 6 hours, and again after a clock jump;
 *   • 403 device_revoked → sign out here; 409 device_limit_reached → offer
 *     "unlink one"; 401 → signed out; anything else → keep state, retry;
 *   • every plan / source / status / platform the API sends has a label key,
 *     and an unknown one falls back instead of rendering a raw key;
 *   • the device id is a well-formed v4 UUID the API accepts.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  HEARTBEAT_INTERVAL_MS,
  accountFailure,
  defaultDeviceName,
  heartbeatDue,
  needsRefresh,
  planKey,
  platformKey,
  refreshDelayMs,
  singleFlight,
  sourceKey,
  statusKey,
  uuidFromBytes,
} from "../src/utils/account-session.ts";

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

const en = JSON.parse(readFileSync(new URL("../i18n/en.json", import.meta.url), "utf8"));

console.log("token refresh timing");
await check("fresh token is not refreshed", () => {
  assert.equal(needsRefresh(10_000, 9_000), false);
});
await check("refreshed inside the 2-minute window and after expiry", () => {
  assert.equal(needsRefresh(10_000, 9_880), true);
  assert.equal(needsRefresh(10_000, 10_500), true);
});
await check("unknown / zero expiry counts as expired", () => {
  assert.equal(needsRefresh(0, 1), true);
  assert.equal(needsRefresh(Number.NaN, 1), true);
});
await check("proactive refresh is scheduled 2 minutes before expiry", () => {
  assert.equal(refreshDelayMs(10_000, 6_400), (10_000 - 120 - 6_400) * 1000);
  assert.equal(refreshDelayMs(10_000, 9_990), 0);
});

console.log("single-flight refresh");
await check("parallel callers share one run", async () => {
  let runs = 0;
  let release;
  const gate = new Promise((r) => { release = r; });
  const refresh = singleFlight(async () => { runs += 1; await gate; return `token-${runs}`; });
  const all = Promise.all([refresh(), refresh(), refresh()]);
  release();
  assert.deepEqual(await all, ["token-1", "token-1", "token-1"]);
  assert.equal(runs, 1);
  assert.equal(await refresh(), "token-2");
});
await check("a failed run doesn't block the next one", async () => {
  let n = 0;
  const refresh = singleFlight(async () => { n += 1; if (n === 1) throw new Error("offline"); return "ok"; });
  await assert.rejects(refresh());
  assert.equal(await refresh(), "ok");
});

console.log("device heartbeat");
await check("first heartbeat is due, then every 6 hours", () => {
  const now = 1_000_000_000;
  assert.equal(heartbeatDue(null, now), true);
  assert.equal(heartbeatDue(now - 60_000, now), false);
  assert.equal(heartbeatDue(now - HEARTBEAT_INTERVAL_MS, now), true);
  assert.equal(heartbeatDue(now + 60_000, now), true); // clock went backwards
});

console.log("account call failures");
for (const [error, expected] of [
  [{ kind: "forbidden", status: 403, code: "device_revoked" }, "revoked"],
  [{ kind: "http_4xx", status: 409, code: "device_limit_reached" }, "limit"],
  [{ kind: "unauthorized", status: 401 }, "signed_out"],
  [{ kind: "forbidden", status: 403 }, "retry"],
  [{ kind: "network" }, "retry"],
  [{ kind: "http_5xx", status: 503, code: "account_unavailable" }, "retry"],
  [null, "retry"],
]) {
  await check(`${JSON.stringify(error)} → ${expected}`, () => {
    assert.equal(accountFailure(error), expected);
  });
}

console.log("labels resolve in en.json");
const has = (key) => assert.ok(typeof en[key] === "string" && en[key], `missing ${key}`);
await check("every plan the API sends, plus the fallback", () => {
  for (const plan of ["free", "personal", "family", "business"]) has(planKey(plan));
  assert.equal(planKey("enterprise"), "mobile.account.plan_paid");
  assert.equal(planKey(null), "mobile.account.plan_paid");
  has("mobile.account.plan_paid");
});
await check("every entitlement source, plus the fallback", () => {
  for (const source of ["stripe", "google_play", "app_store", "rustore", "operator_ru", "promo", "partner"]) {
    has(sourceKey(source));
  }
  assert.equal(sourceKey(null), null);
  assert.equal(sourceKey("paypal"), "mobile.account.source_other");
  has("mobile.account.source_other");
});
await check("status lines, with and without an end date", () => {
  for (const status of ["active", "trialing", "past_due"]) {
    has(statusKey(status, true));
    has(statusKey(status, false));
  }
  assert.equal(statusKey("free", false), null);
  assert.ok(en[statusKey("active", true)].includes("{{date}}"));
  assert.ok(!en[statusKey("active", false)].includes("{{date}}"));
});
await check("every platform, plus the fallback", () => {
  for (const p of ["android", "ios", "extension", "web"]) has(platformKey(p));
  assert.equal(platformKey("toaster"), "mobile.account.platform_web");
});

console.log("device identity");
await check("device name: model first, then the phone's name, trimmed", () => {
  assert.equal(defaultDeviceName("  Pixel 8\n", "Anna's phone"), "Pixel 8");
  assert.equal(defaultDeviceName(undefined, "Anna's phone"), "Anna's phone");
  assert.equal(defaultDeviceName("", "   "), null);
  assert.equal(defaultDeviceName("x".repeat(200), null).length, 80);
});
await check("device id is a v4 UUID the API's pattern accepts", () => {
  const id = uuidFromBytes(new Uint8Array(16).fill(255));
  assert.match(id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
  assert.match(id, /^[A-Za-z0-9_-]{16,128}$/);
  assert.throws(() => uuidFromBytes(new Uint8Array(4)));
});

if (failures) {
  console.log(`\n${failures} failed`);
  process.exit(1);
}
console.log("\nall passed");

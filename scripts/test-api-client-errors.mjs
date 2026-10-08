#!/usr/bin/env node
/**
 * Runtime verification for packages/api-client error mapping.
 *
 * We don't have a TS test runner in the monorepo, but the api-client
 * is plain TypeScript that the workspace publishes via "main": "src/index.ts"
 * with tsx-compatible resolution. This script imports it via tsx and
 * exercises each error-kind branch with a stubbed fetchImpl.
 *
 * Run: node --experimental-strip-types scripts/test-api-client-errors.mjs
 * (Node 22+. Stripping TS types is built-in, no extra runtime needed.)
 *
 * Exits non-zero on any failed assertion so it can wire into CI.
 */
import assert from "node:assert/strict";

import { createClient, errorDetail, normalizePublicCheck } from "../packages/api-client/src/index.ts";

/**
 * Build a client whose `fetchImpl` returns whatever the test fixture says.
 * Lets us pin exact wire shapes (status, body, headers) without spinning
 * up a real HTTP server.
 */
function makeClient(fixtureResponse) {
  return createClient({
    baseUrl: "https://api.test",
    timeoutMs: 1000,
    fetchImpl: async () => fixtureResponse,
  });
}

/** Helper: build a Response-like object the client's `await resp.text()` etc. can consume. */
function makeResponse({ status, body, headers = {} }) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: {
      get(name) {
        return headers[name.toLowerCase()] ?? headers[name] ?? null;
      },
    },
    text: async () => text,
  };
}

let failed = 0;
async function test(name, fn) {
  try {
    await fn();
    console.log(`  ok  ${name}`);
  } catch (e) {
    failed += 1;
    console.error(`  FAIL ${name}`);
    console.error(`    ${e.message}`);
  }
}

console.log("api-client error mapping");

await test("401 → unauthorized", async () => {
  const client = makeClient(
    makeResponse({ status: 401, body: { detail: "Invalid token" } }),
  );
  const { data, error } = await client.health();
  assert.equal(data, null);
  assert.equal(error?.kind, "unauthorized");
  assert.equal(error?.status, 401);
  assert.equal(error?.message, "Invalid token");
});

await test("403 → forbidden", async () => {
  const client = makeClient(
    makeResponse({ status: 403, body: { detail: "Not your family" } }),
  );
  const { error } = await client.health();
  assert.equal(error?.kind, "forbidden");
  assert.equal(error?.status, 403);
});

await test("410 → account_locked + restoreUrl extracted from detail", async () => {
  const client = makeClient(
    makeResponse({
      status: 410,
      body: {
        detail: {
          error: "Account is scheduled for deletion.",
          restore_url: "/api/v1/user/account/restore",
        },
      },
    }),
  );
  const { error } = await client.health();
  assert.equal(error?.kind, "account_locked");
  assert.equal(error?.status, 410);
  assert.equal(error?.restoreUrl, "/api/v1/user/account/restore");
});

await test("410 with top-level restore_url also works", async () => {
  const client = makeClient(
    makeResponse({
      status: 410,
      body: { error: "gone", restore_url: "/elsewhere" },
    }),
  );
  const { error } = await client.health();
  assert.equal(error?.kind, "account_locked");
  assert.equal(error?.restoreUrl, "/elsewhere");
});

await test("429 with Retry-After in seconds", async () => {
  const client = makeClient(
    makeResponse({
      status: 429,
      body: { detail: "Too many" },
      headers: { "retry-after": "60" },
    }),
  );
  const { error } = await client.health();
  assert.equal(error?.kind, "rate_limited");
  assert.equal(error?.retryAfterSeconds, 60);
});

await test("429 without Retry-After header", async () => {
  const client = makeClient(
    makeResponse({ status: 429, body: { detail: "Too many" } }),
  );
  const { error } = await client.health();
  assert.equal(error?.kind, "rate_limited");
  assert.equal(error?.retryAfterSeconds, undefined);
});

await test("404 → generic http_4xx (not a special case)", async () => {
  const client = makeClient(
    makeResponse({ status: 404, body: { detail: "Not Found" } }),
  );
  const { error } = await client.health();
  assert.equal(error?.kind, "http_4xx");
  assert.equal(error?.status, 404);
});

await test("503 → http_5xx", async () => {
  const client = makeClient(
    makeResponse({ status: 503, body: "Service down" }),
  );
  const { error } = await client.health();
  assert.equal(error?.kind, "http_5xx");
  assert.equal(error?.status, 503);
});

await test("200 → success path still works", async () => {
  const client = makeClient(
    makeResponse({
      status: 200,
      body: { ok: true, version: "1.0.0", checks: {} },
    }),
  );
  const { data, error } = await client.health();
  assert.equal(error, null);
  assert.ok(data);
});

await test("403 device_revoked → forbidden with code + the server's sentence", async () => {
  const c = makeClient(
    makeResponse({
      status: 403,
      body: { detail: { code: "device_revoked", error: "This device was removed from your account." } },
    }),
  );
  const { error } = await c.account.entitlement();
  assert.equal(error.kind, "forbidden");
  assert.equal(error.code, "device_revoked");
  assert.equal(error.message, "This device was removed from your account.");
});

await test("409 device_limit_reached → code + linked devices via errorDetail", async () => {
  const devices = [{ id: "d1", platform: "android", name: "Pixel", is_current: false }];
  const c = makeClient(
    makeResponse({
      status: 409,
      body: { detail: { code: "device_limit_reached", device_limit: 2, devices_used: 2, devices } },
    }),
  );
  const { error } = await c.account.registerDevice({ device_id: "x".repeat(20), platform: "android" });
  assert.equal(error.kind, "http_4xx");
  assert.equal(error.code, "device_limit_reached");
  assert.deepEqual(errorDetail(error).devices, devices);
  assert.equal(errorDetail(error).device_limit, 2);
});

await test("plain string detail carries no code", async () => {
  const c = makeClient(makeResponse({ status: 404, body: { detail: "Not Found" } }));
  const { error } = await c.account.devices();
  assert.equal(error.code, undefined);
  assert.equal(errorDetail(error), undefined);
});

await test("account calls hit the right method + path", async () => {
  const calls = [];
  const c = createClient({
    baseUrl: "https://api.test",
    fetchImpl: async (url, init) => {
      calls.push([init.method, url.replace("https://api.test", ""), init.body ?? null]);
      return makeResponse({ status: 200, body: {} });
    },
  });
  await c.account.unlinkDevice("abc/def");
  await c.account.renameDevice("d-1", "Mum's phone");
  assert.deepEqual(calls, [
    ["DELETE", "/api/v1/me/devices/abc%2Fdef", null],
    ["PATCH", "/api/v1/me/devices/d-1", JSON.stringify({ name: "Mum's phone" })],
  ]);
});

await test("public check: reason_codes map onto reasons[].code, aligned with detail", () => {
  const norm = normalizePublicCheck({
    domain: "evil.tk",
    score: 90,
    level: "dangerous",
    safe: false,
    signals: ["Site does not use HTTPS", "Reported as phishing"],
    reason_codes: ["no_https", "phishtank"],
  });
  assert.equal(norm.reasons.length, 2);
  assert.deepEqual(norm.reasons[0], { detail: "Site does not use HTTPS", code: "no_https" });
  assert.deepEqual(norm.reasons[1], { detail: "Reported as phishing", code: "phishtank" });
});

await test("public check: missing reason_codes leaves code undefined (older API)", () => {
  const norm = normalizePublicCheck({
    domain: "evil.tk", score: 90, level: "dangerous", safe: false,
    signals: ["Something"],
  });
  assert.equal(norm.reasons[0].detail, "Something");
  assert.equal(norm.reasons[0].code, undefined);
});

await test("public check: exists=false and verdict_basis pass through, as a list", () => {
  const norm = normalizePublicCheck({
    domain: "sbertank.ru", score: 53, level: "dangerous", safe: false,
    signals: [], exists: false, verdict_basis: "heuristics",
  });
  assert.equal(norm.exists, false);
  assert.deepEqual(norm.verdict_basis, ["heuristics"]);
  const listed = normalizePublicCheck({
    domain: "evil.tk", score: 90, level: "dangerous", safe: false, verdict_basis: ["threat_intel", 7, ""],
  });
  assert.deepEqual(listed.verdict_basis, ["threat_intel"]);
});

await test("public check: an older server's answer gains no invented exists/verdict_basis", () => {
  const norm = normalizePublicCheck({ domain: "evil.tk", score: 90, level: "dangerous", safe: false });
  assert.equal("exists" in norm, false);
  assert.equal("verdict_basis" in norm, false);
});

await test("public check: never carries the account token", async () => {
  const seen = [];
  const client = createClient({
    baseUrl: "https://api.test",
    timeoutMs: 1000,
    getAuthToken: () => "jwt-of-a-signed-in-person",
    fetchImpl: async (url, init) => {
      seen.push({ url, headers: init.headers });
      return makeResponse({ status: 200, body: { domain: "evil.tk", score: 90, level: "dangerous", safe: false } });
    },
  });
  await client.check.publicDomain("https://evil.tk/login?token=1");
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, "https://api.test/api/v1/public/check/evil.tk");
  assert.equal(seen[0].headers.Authorization, undefined);
  // …while an account route still sends it.
  await client.health();
  assert.equal(seen[1].headers.Authorization, "Bearer jwt-of-a-signed-in-person");
});

await test("restore purchases: POST /me/entitlement/refresh, with the token; a 503 keeps its code", async () => {
  const seen = [];
  const client = createClient({
    baseUrl: "https://api.test",
    timeoutMs: 1000,
    getAuthToken: () => "jwt",
    fetchImpl: async (url, init) => {
      seen.push({ url, method: init.method, headers: init.headers });
      return makeResponse({
        status: 503,
        body: { detail: { code: "store_sync_unavailable", error: "Restoring store purchases isn't available yet." } },
      });
    },
  });
  const { data, error } = await client.account.refreshEntitlement();
  assert.equal(data, null);
  assert.equal(seen[0].url, "https://api.test/api/v1/me/entitlement/refresh");
  assert.equal(seen[0].method, "POST");
  assert.equal(seen[0].headers.Authorization, "Bearer jwt");
  assert.equal(error.kind, "http_5xx");
  assert.equal(error.code, "store_sync_unavailable");
});

if (failed > 0) {
  console.error(`\n${failed} test(s) failed`);
  process.exit(1);
}
console.log("\nall passed");

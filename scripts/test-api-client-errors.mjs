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

import { createClient } from "../packages/api-client/src/index.ts";

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

if (failed > 0) {
  console.error(`\n${failed} test(s) failed`);
  process.exit(1);
}
console.log("\nall passed");

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
 *
 * And src/services/auth.ts itself, against a fake GoTrue (SecureStore is a
 * Map, fetch a function — loaded the way test-domain-check-hook.mjs loads a
 * hook, with the tree's TypeScript and stubs for the expo modules):
 *   • a call its own 10-second timer aborts is a "timeout", however fetch
 *     names the rejection (expo/fetch, the global fetch since Expo SDK 56,
 *     says plain Error); a failure on its own is a "network_error";
 *   • sign-out ends only THIS phone's session (/logout?scope=local) — without
 *     the scope GoTrue's default is global, and signing out on the phone
 *     signed the account out on the website, the extension and other phones;
 *   • a refresh token GoTrue refuses (400 refresh_token_not_found /
 *     invalid_grant, 401, 403 session_expired) ends the session here, once
 *     and for all; it used to count only 401 as final, so a dead session was
 *     kept as "offline" forever (the email stayed in Settings, Family stuck
 *     on an error, a refresh on every foreground);
 *   • no answer, a timeout, 429, 5xx or an unusable 200 keep the session
 *     for a retry (the same table as the extension: scripts/test-extension-auth.mjs);
 *   • so does a 400 / 403 that GoTrue did not write — an HTML page or an
 *     empty body with no error code in it: *.supabase.co sits behind
 *     Cloudflare, whose block / challenge page reaches a phone on a VPN or
 *     Tor exit with a bad name, and a proxy answers 400 with its own page.
 *     Taking those as "refused" signed the person out for good on a network
 *     where signing back in fails too.
 */
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import {
  HEARTBEAT_INTERVAL_MS,
  accountFailure,
  defaultDeviceName,
  heartbeatDue,
  needsRefresh,
  planKey,
  platformKey,
  refreshDelayMs,
  refreshFailure,
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

console.log("refresh failures");
// [HTTP status, AuthError code (services/auth.ts goTrue()), expected].
// goTrue() names an error by the body's error_code, else its error, else the
// bare HTTP status it carries, else "auth_error" (a body it could not read).
for (const [status, code, expected] of [
  [400, "refresh_token_not_found", "signed_out"],
  [400, "refresh_token_already_used", "signed_out"],
  [400, "invalid_grant", "signed_out"],
  [403, "session_expired", "signed_out"],
  [403, "session_not_found", "signed_out"],
  [401, "auth_error", "signed_out"],
  [401, undefined, "signed_out"],
  // A 400 / 403 GoTrue did not write: an HTML page, an empty body, a JSON
  // body with no error name in it.
  [400, "auth_error", "offline"],
  [403, "auth_error", "offline"],
  [403, "403", "offline"],
  [400, undefined, "offline"],
  [403, "", "offline"],
  [0, "network_error", "offline"], [0, "timeout", "offline"],
  [404, "auth_error", "offline"], [408, "auth_error", "offline"],
  [429, "over_request_rate_limit", "offline"],
  [500, "unexpected_failure", "offline"], [502, "auth_error", "offline"], [503, "auth_error", "offline"],
]) {
  await check(`refresh answered ${status} ${code === undefined ? "(no code)" : JSON.stringify(code)} → ${expected}`, () => {
    assert.equal(refreshFailure(status, code), expected);
  });
}

// ── services/auth.ts against a fake GoTrue ─────────────────────────────

const mobileRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const appRequire = createRequire(join(mobileRoot, "package.json"));
const ts = appRequire("typescript");

/** CommonJS-load an app .ts file: its relative imports from source, `stubs` for the rest. */
function loadTs(file, stubs) {
  const { outputText } = ts.transpileModule(readFileSync(file, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
    fileName: file,
  });
  const module = { exports: {} };
  const requireHere = (spec) => {
    if (spec in stubs) return stubs[spec];
    if (spec.startsWith(".")) return loadTs(resolve(dirname(file), `${spec}.ts`), stubs);
    throw new Error(`${file} imports ${spec}, which this test does not stub`);
  };
  new Function("require", "module", "exports", outputText)(requireHere, module, module.exports);
  return module.exports;
}

const SUPABASE = "https://project.supabase.example";
const ANON = "anon-public-key";
const NOW_S = Math.floor(Date.now() / 1000);
/** What sign-in leaves in SecureStore; the access token expired by default, so the next call refreshes. */
const signedIn = (expiresAt = NOW_S - 10) => ({
  auth_token: "access-old",
  refresh_token: "refresh-old",
  user_email: "anna@example.com",
  token_expires_at: String(expiresAt),
});
const json = (status, body) =>
  new Response(body === null ? null : JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const html = (status, body) => new Response(body, { status, headers: { "Content-Type": "text/html; charset=UTF-8" } });

/** A fresh copy of services/auth.ts (its module state included) talking to `answer`. */
function authWith({ stored, answer }) {
  const store = new Map(Object.entries(stored));
  const calls = [];
  const events = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return answer(url, init);
  };
  const auth = loadTs(join(mobileRoot, "src/services/auth.ts"), {
    "expo-secure-store": {
      getItemAsync: async (k) => store.get(k) ?? null,
      setItemAsync: async (k, v) => { store.set(k, v); },
      deleteItemAsync: async (k) => { store.delete(k); },
    },
    "react-native": { AppState: { addEventListener: () => ({ remove() {} }) } },
    events: { EventEmitter },
    "./api": { setAuthToken() {}, setTokenProvider() {} },
    "./supabase": {
      SUPABASE_URL: SUPABASE,
      SUPABASE_ANON_KEY: ANON,
      isSupabaseConfigured: () => true,
      SupabaseNotConfiguredError: class extends Error {},
    },
  });
  auth.authEvents.on("signed_out", () => events.push("signed_out"));
  return { auth, store, calls, events };
}

console.log("timeouts (services/auth.ts)");
// Since Expo SDK 56 the app's global fetch is expo/fetch, and a request
// aborted before its answer arrives rejects with expo's FetchError
// ("fetch failed: The operation was aborted.", name "Error"), not an
// AbortError (expo@58.0.19 src/winter/fetch/fetch.ts). auth.ts must tell a
// timeout by its own timer, not by the error's name.
await check("a request auth.ts's own timer aborts is a timeout, though expo/fetch calls it a plain Error", async () => {
  const realSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (fn) => realSetTimeout(fn, 0); // the 10 s timer, at once
  try {
    const { auth } = authWith({
      stored: {},
      answer: (url, init) =>
        new Promise((_, reject) => {
          init.signal.addEventListener("abort", () => reject(new Error("fetch failed: The operation was aborted.")));
        }),
    });
    await assert.rejects(auth.signIn("anna@example.com", "correct horse battery"), (e) => {
      assert.equal(e.name, "AuthError");
      assert.equal(e.code, "timeout");
      return true;
    });
  } finally {
    globalThis.setTimeout = realSetTimeout;
  }
});
await check("a connection that fails on its own is a network error, not a timeout", async () => {
  const { auth } = authWith({
    stored: {},
    answer: () => { throw new Error("fetch failed: The Internet connection appears to be offline."); },
  });
  await assert.rejects(auth.signIn("anna@example.com", "correct horse battery"), (e) => {
    assert.equal(e.code, "network_error");
    return true;
  });
});

console.log("sign-out (services/auth.ts)");
await check("ends only this phone's session: POST /auth/v1/logout?scope=local", async () => {
  const { auth, store, calls, events } = authWith({ stored: signedIn(NOW_S + 3000), answer: () => json(204, null) });
  await auth.signOut();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, `${SUPABASE}/auth/v1/logout?scope=local`);
  assert.equal(calls[0].init.method, "POST");
  assert.equal(calls[0].init.headers.Authorization, "Bearer access-old");
  assert.equal(calls[0].init.headers.apikey, ANON);
  assert.equal(store.size, 0, "every token forgotten");
  assert.deepEqual(events, ["signed_out"]);
});
await check("offline: still signed out here", async () => {
  const { auth, store, events } = authWith({
    stored: signedIn(NOW_S + 3000),
    answer: () => { throw new TypeError("Network request failed"); },
  });
  await auth.signOut();
  assert.equal(store.size, 0);
  assert.deepEqual(events, ["signed_out"]);
});
await check("no other code calls GoTrue's logout without scope=local", () => {
  const files = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (/\.tsx?$/.test(entry.name)) files.push(p);
    }
  };
  walk(join(mobileRoot, "src"));
  walk(join(mobileRoot, "app"));
  const unscoped = files.filter((f) => /\/auth\/v1\/logout(?!\?scope=local)/.test(readFileSync(f, "utf8")));
  assert.deepEqual(unscoped, []);
});

console.log("refresh (services/auth.ts)");
for (const [status, body] of [
  [400, { code: 400, error_code: "refresh_token_not_found", msg: "Invalid Refresh Token: Refresh Token Not Found" }],
  [400, { error: "invalid_grant", error_description: "Invalid Refresh Token: Already Used" }],
  [401, { message: "Invalid API key" }],
  [403, { code: 403, error_code: "session_expired", msg: "Session Expired" }],
]) {
  const what = [status, body.error_code ?? body.error].filter(Boolean).join(" ");
  await check(`refused with ${what} → signed out, no retry`, async () => {
    const { auth, store, calls, events } = authWith({ stored: signedIn(), answer: () => json(status, body) });
    assert.equal(await auth.refreshAccessToken(), null);
    assert.equal(store.size, 0, "the dead session is gone");
    assert.deepEqual(events, ["signed_out"]);
    assert.equal(calls.length, 1, "no logout call with a dead token");
    assert.equal(calls[0].url, `${SUPABASE}/auth/v1/token?grant_type=refresh_token`);
    assert.deepEqual(JSON.parse(calls[0].init.body), { refresh_token: "refresh-old" });
    // Settings and Family now read "signed out", and nothing asks again.
    assert.deepEqual(await auth.getSessionState(), { kind: "none" });
    assert.equal(await auth.ensureFreshToken(), null);
    assert.equal(calls.length, 1);
  });
}
for (const [name, answer] of [
  ["no connection", () => { throw new TypeError("Network request failed"); }],
  ["timeout", () => { const e = new Error("Aborted"); e.name = "AbortError"; throw e; }],
  ["429", () => json(429, { msg: "Too many requests" })],
  ["500", () => json(500, {})],
  ["503", () => json(503, {})],
  ["an unusable 200", () => json(200, { unexpected: true })],
  ["Cloudflare's 403 block page", () => html(403, "<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head><body>Sorry, you have been blocked</body></html>")],
  ["a proxy's 400 page", () => html(400, "<html><body><h1>400 Bad Request</h1></body></html>")],
  ["an empty 403", () => new Response(null, { status: 403 })],
  ["a 403 JSON body with no GoTrue error in it", () => json(403, { message: "Forbidden" })],
]) {
  await check(`${name} → session kept, refresh tried again later`, async () => {
    const { auth, store, calls, events } = authWith({ stored: signedIn(), answer });
    assert.equal(await auth.ensureFreshToken(), "access-old", "the stored token is still sent");
    assert.equal(store.get("refresh_token"), "refresh-old");
    assert.deepEqual(await auth.getSessionState(), { kind: "offline", email: "anna@example.com" });
    assert.deepEqual(events, []);
    assert.equal(calls.length, 2, "each call tried the refresh again");
  });
}
await check("a refresh that works stores the rotated tokens", async () => {
  const { auth, store, events } = authWith({
    stored: signedIn(),
    answer: () => json(200, { access_token: "access-new", refresh_token: "refresh-new", expires_in: 3600, user: {} }),
  });
  assert.equal(await auth.ensureFreshToken(), "access-new");
  assert.equal(store.get("refresh_token"), "refresh-new");
  assert.equal(store.get("user_email"), "anna@example.com");
  assert.deepEqual(events, []);
});

if (failures) {
  console.log(`\n${failures} failed`);
  process.exit(1);
}
console.log("\nall passed");

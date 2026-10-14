#!/usr/bin/env node
/**
 * Table test for src/utils/local-store.ts — how the app reads its on-device
 * SQLite store (src/services/database.ts) and what it does when a read fails.
 *
 * Run: node --experimental-strip-types mobile/scripts/test-local-store.mjs
 *
 * No jest in mobile/ (see test-host-parser.mjs); the module imports nothing
 * from react-native, so node's TS stripper loads it as-is.
 *
 * The bug this pins (Galaxy A16, release 1.0.4, process alive for days under
 * the VPN service): every query failed with
 *   "Call to function 'NativeDatabase.prepareAsync' has been rejected.
 *    → Caused by: java.lang.NullPointerException"
 * Home read "Checked: 0" and the intro tour came back mid-session.
 *
 * Root cause: several screens asked for the database at once on start, so
 * openDatabaseAsync("cleanway.db") ran several times. expo-sqlite hands every
 * such open the SAME native connection, but each JS wrapper owns it: when
 * Hermes later garbage-collects one of the discarded wrappers, Android's
 * NativeDatabase.sharedObjectDidRelease() closes the shared connection under
 * the one still in use, and the next JNI call throws the NPE. The cached
 * native object stays in expo-sqlite's open-database cache, so reopening by
 * name returns the same dead connection.
 *
 * Pinned:
 *   • the handle is opened once, however many callers race for it;
 *   • a dead-handle error (NPE, closed resource, released shared object)
 *     reopens once and retries the query; a second failure rejects — no loop;
 *   • an ordinary SQL error does not throw the connection away;
 *   • a failed open is retried on the next call, never latched;
 *   • a read failure is never "first run": the tour is shown only when the
 *     store answered and the flag is not set;
 *   • a failed stats read never shows 0 over counts that were read before.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  ONBOARDING_DONE_KEY,
  isDeadHandleError,
  onboardingNeeded,
  sharedHandle,
  statsWhenUnreadable,
} from "../src/utils/local-store.ts";

const HERE = dirname(fileURLToPath(import.meta.url));
const MOBILE = join(HERE, "..");

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

// The exact rejection seen in logcat.
const NPE = new Error(
  "Call to function 'NativeDatabase.prepareAsync' has been rejected.\n→ Caused by: java.lang.NullPointerException",
);

/** A fake expo-sqlite connection whose queries fail `failures` times (Infinity = dead for good). */
function fakeDb(id, { failures = 0, error = NPE } = {}) {
  let left = failures;
  return {
    id,
    async getFirstAsync() {
      if (left > 0) {
        left -= 1;
        throw error;
      }
      return { count: 3, db: id };
    },
  };
}

/** An opener that yields the given connections in order and counts its calls. */
function opener(dbs) {
  const fn = async () => {
    fn.calls += 1;
    await new Promise((r) => setTimeout(r, 5)); // ensureDatabasePathExistsAsync + new NativeDatabase
    const next = dbs.shift();
    if (next instanceof Error) throw next;
    return next;
  };
  fn.calls = 0;
  return fn;
}

console.log("local-store");

await check("dead-handle errors are recognised; ordinary SQL errors are not", () => {
  assert.equal(isDeadHandleError(NPE), true);
  assert.equal(isDeadHandleError(new Error("Access to closed resource")), true);
  assert.equal(isDeadHandleError(new Error("Cannot use shared object that was already released")), true);
  assert.equal(
    isDeadHandleError(new Error("Cannot convert provided JavaScriptObject to the SharedObject, because it doesn't contain valid id")),
    true,
  );
  assert.equal(isDeadHandleError(new Error("Error code 1: no such table: checks")), false);
  assert.equal(isDeadHandleError(new Error("database is locked")), false);
  assert.equal(isDeadHandleError(undefined), false);
});

await check("concurrent callers share ONE open (the duplicate wrappers were the root cause)", async () => {
  const open = opener([fakeDb("a")]);
  const handle = sharedHandle(open);
  const rows = await Promise.all(
    Array.from({ length: 6 }, () => handle.use((db) => db.getFirstAsync())),
  );
  assert.equal(open.calls, 1);
  assert.ok(rows.every((r) => r.db === "a"));
  await handle.use((db) => db.getFirstAsync());
  assert.equal(open.calls, 1, "a later call reuses the handle");
});

await check("a query rejected with the NPE once reopens and retries", async () => {
  const open = opener([fakeDb("dead", { failures: Infinity }), fakeDb("fresh")]);
  const handle = sharedHandle(open);
  const row = await handle.use((db) => db.getFirstAsync());
  assert.equal(row.db, "fresh");
  assert.equal(open.calls, 2);
  const again = await handle.use((db) => db.getFirstAsync());
  assert.equal(again.db, "fresh", "the fresh handle is kept");
  assert.equal(open.calls, 2);
});

await check("a handle that stays dead rejects after ONE reopen, and the next call tries again", async () => {
  const open = opener([
    fakeDb("dead1", { failures: Infinity }),
    fakeDb("dead2", { failures: Infinity }),
    fakeDb("fresh"),
  ]);
  const handle = sharedHandle(open);
  await assert.rejects(handle.use((db) => db.getFirstAsync()), /NullPointerException/);
  assert.equal(open.calls, 2, "one reopen, no loop");
  const row = await handle.use((db) => db.getFirstAsync());
  assert.equal(row.db, "fresh", "a later call is not latched onto the dead handle");
});

await check("many callers failing on the same dead handle reopen it once", async () => {
  const open = opener([fakeDb("dead", { failures: Infinity }), fakeDb("fresh")]);
  const handle = sharedHandle(open);
  const rows = await Promise.all(
    Array.from({ length: 4 }, () => handle.use((db) => db.getFirstAsync())),
  );
  assert.ok(rows.every((r) => r.db === "fresh"));
  assert.equal(open.calls, 2);
});

await check("an ordinary SQL error keeps the connection and is not retried", async () => {
  const sqlError = new Error("Error code 1: no such column: nope");
  const open = opener([fakeDb("a", { failures: 1, error: sqlError })]);
  const handle = sharedHandle(open);
  await assert.rejects(handle.use((db) => db.getFirstAsync()), /no such column/);
  assert.equal(open.calls, 1);
  const row = await handle.use((db) => db.getFirstAsync());
  assert.equal(row.db, "a");
});

await check("a failed open (or a failed CREATE TABLE) is retried on the next call, never latched", async () => {
  const open = opener([new Error("unable to open database file"), fakeDb("b")]);
  const handle = sharedHandle(open);
  await assert.rejects(handle.use((db) => db.getFirstAsync()), /unable to open/);
  const row = await handle.use((db) => db.getFirstAsync());
  assert.equal(row.db, "b");
  assert.equal(open.calls, 2);
});

await check("onboarding: shown only when storage answered and the flag is not set", async () => {
  assert.equal(ONBOARDING_DONE_KEY, "onboarding_done");
  assert.equal(await onboardingNeeded(async () => null), true, "first run");
  assert.equal(await onboardingNeeded(async () => ""), true, "first run (empty value)");
  assert.equal(await onboardingNeeded(async () => "true"), false);
  assert.equal(await onboardingNeeded(async () => { throw NPE; }), false, "a read failure is not first run");
  let asked = null;
  await onboardingNeeded(async (key) => { asked = key; return "true"; });
  assert.equal(asked, ONBOARDING_DONE_KEY);
});

await check("stats: a failed read keeps the last counts read, plus checks only held in memory", () => {
  const zero = { total_checks: 0, threats_blocked: 0, threats_warned: 0 };
  const last = { total_checks: 3, threats_blocked: 1, threats_warned: 1 };
  assert.deepEqual(statsWhenUnreadable(last, zero), last, "never 0 over 3");
  assert.deepEqual(
    statsWhenUnreadable(last, { total_checks: 2, threats_blocked: 1, threats_warned: 0 }),
    { total_checks: 5, threats_blocked: 2, threats_warned: 1 },
  );
  assert.deepEqual(statsWhenUnreadable(null, { total_checks: 1, threats_blocked: 0, threats_warned: 0 }),
    { total_checks: 1, threats_blocked: 0, threats_warned: 0 });
});

await check("database.ts opens through the shared handle on a connection of its own", () => {
  const src = readFileSync(join(MOBILE, "src/services/database.ts"), "utf8");
  assert.ok(/sharedHandle(<[^>]*>)?\(/.test(src), "the connection comes from sharedHandle()");
  assert.ok(
    /openDatabaseAsync\("cleanway\.db",\s*\{\s*useNewConnection:\s*true\s*\}\)/.test(src),
    "a reopen must not get expo-sqlite's cached (dead) connection back",
  );
  assert.equal((src.match(/openDatabaseAsync\(/g) || []).length, 1, "one place opens the database");
  assert.ok(/statsWhenUnreadable\(/.test(src), "getStats falls back through statsWhenUnreadable");
});

await check("the onboarding gate reads through onboardingNeeded and readSetting", () => {
  const src = readFileSync(join(MOBILE, "app/_layout.tsx"), "utf8");
  assert.ok(/onboardingNeeded\(readSetting\)/.test(src), "gate uses onboardingNeeded(readSetting)");
  assert.ok(!/getSetting\("onboarding_done"\)/.test(src), "getSetting turns a read failure into \"\" = first run");
});

if (failures) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nall ok");

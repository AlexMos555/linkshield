#!/usr/bin/env node
/**
 * Sign-in for the browser extension: the cleanway.ai → extension token
 * handoff and the session's refresh (no browser needed).
 *
 * Run with: node scripts/test-extension-auth.mjs
 *
 * WHAT THIS PINS
 * --------------
 * 1. The connect URL: exact origin, the browser's language as the site's
 *    locale (English at the apex), the state as the only query parameter.
 * 2. Who may hand over tokens: only our content script, in the top frame of
 *    https://cleanway.ai/<locale>/extension/connect. Look-alike hosts,
 *    subdomains, other paths, other extensions and extension pages are refused.
 * 3. The state: 32 random bytes, kept by this install, compared in constant
 *    time, used once, dead after 30 minutes.
 * 4. What is stored: a live user token of OUR Supabase project, a well-formed
 *    refresh token and a public anon key (never a service-role key).
 * 5. Refresh: before expiry, to the pinned project, one request at a time,
 *    tokens only in the body; signed out only when Supabase REFUSES the
 *    refresh token, kept (and retried) when the network is down.
 * 6. Sign-out forgets every token and ends the extension's own session.
 * 7. The relay content script reads only same-window messages from the exact
 *    origin, forwards only the known fields, and answers only that origin.
 * 8. Every manifest injects the relay on the connect path alone, and none
 *    declares externally_connectable.
 *
 * Every group runs against packages/extension-core/ AND the three generated
 * trees, so a hand-edit to a generated copy (or a forgotten rebuild) fails too.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import vm from "node:vm";

process.removeAllListeners("warning");
process.on("warning", (w) => {
  if (w.code !== "MODULE_TYPELESS_PACKAGE_JSON") console.warn(w);
});

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, "..");
const SOURCE_TREE = "packages/extension-core";
const BROWSER_TREES = ["extension", "extension-firefox", "extension-safari"];

let passed = 0;
let failed = 0;
async function check(name, fn) {
  try {
    await fn();
    passed++;
  } catch (err) {
    failed++;
    console.error(`  FAIL  ${name}\n        ${err && err.stack ? err.stack.split("\n").slice(0, 3).join("\n        ") : err}`);
  }
}

// ── Fixtures ─────────────────────────────────────────────────────────

const PROJECT = "https://bpyqgzzclsbfvxthyfsf.supabase.co";
const RUNTIME_ID = "abcdefghijklmnopabcdefghijklmnop";
const EXT_BASE = `chrome-extension://${RUNTIME_ID}/`;
const NOW_MS = 1_800_000_000_000;
const NOW_S = NOW_MS / 1000;

const b64url = (obj) => Buffer.from(JSON.stringify(obj)).toString("base64url");
function jwt(claims) {
  return `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url(claims)}.c2lnbmF0dXJl`;
}
function accessToken(over = {}) {
  return jwt({
    iss: `${PROJECT}/auth/v1`, aud: "authenticated", sub: "user-1", email: "ann@example.com",
    role: "authenticated", exp: NOW_S + 3600, ...over,
  });
}
const ANON = jwt({ iss: "supabase", ref: "bpyqgzzclsbfvxthyfsf", role: "anon", exp: NOW_S + 10 * 365 * 86400 });
const SERVICE = jwt({ iss: "supabase", ref: "bpyqgzzclsbfvxthyfsf", role: "service_role", exp: NOW_S + 86400 });
const REFRESH = "v1refresh-token_ABC123";

function session(over = {}) {
  return { access_token: accessToken(), refresh_token: REFRESH, expires_at: NOW_S + 3600, anon_key: ANON, ...over };
}

const connectSender = (over = {}) => ({
  id: RUNTIME_ID,
  tab: { id: 3, url: "https://cleanway.ai/ru/extension/connect?state=x" },
  frameId: 0,
  url: "https://cleanway.ai/ru/extension/connect?state=x",
  origin: "https://cleanway.ai",
  ...over,
});

function memoryStorage(initial = {}) {
  const data = { ...initial };
  return {
    data,
    get: async (keys) => Object.fromEntries([].concat(keys).filter((k) => k in data).map((k) => [k, data[k]])),
    set: async (obj) => { Object.assign(data, structuredClone(obj)); },
    remove: async (keys) => { for (const k of [].concat(keys)) delete data[k]; },
  };
}

function jsonResponse(status, body) {
  return { status, ok: status >= 200 && status < 300, json: async () => body };
}

function harness(tree, { stored = {}, fetchImpl, clock = { ms: NOW_MS } } = {}) {
  return import(pathToFileURL(join(ROOT, tree, "src/utils/auth-session.js")).href).then((mod) => {
    const storage = memoryStorage(stored);
    const calls = { fetch: [], tabs: [], alarms: [], signedIn: [] };
    const auth = mod.createAuthSession({
      storage,
      fetchImpl: async (url, init) => {
        calls.fetch.push({ url, init });
        return fetchImpl ? fetchImpl(url, init) : jsonResponse(500, {});
      },
      now: () => clock.ms,
      openTab: (url) => calls.tabs.push(url),
      uiLanguage: () => "ru-RU",
      scheduleRefresh: (when) => calls.alarms.push(when),
      onSignedIn: async (token) => calls.signedIn.push(token),
    });
    return { mod, auth, storage, calls, clock };
  });
}

const SESSION_KEYS = ["auth_token", "auth_refresh_token", "auth_expires_at", "auth_email", "auth_user_id", "auth_anon_key"];

// ── 1–4: pure helpers ────────────────────────────────────────────────

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  const load = () => import(pathToFileURL(join(ROOT, tree, "src/utils/auth-session.js")).href);

  await check(`[${tree}] connect URL: exact origin, the site's locale, only the state`, async () => {
    const m = await load();
    const state = m.generateState();
    assert.equal(m.connectUrl(state, "en-US"), `https://cleanway.ai/extension/connect?state=${state}`);
    assert.equal(m.connectUrl(state, "ru"), `https://cleanway.ai/ru/extension/connect?state=${state}`);
    assert.equal(m.connectUrl(state, "pt-BR"), `https://cleanway.ai/pt/extension/connect?state=${state}`);
    assert.equal(m.connectUrl(state, "zh-CN"), `https://cleanway.ai/extension/connect?state=${state}`);
    for (const lang of ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"]) {
      assert.ok(m.isConnectPageUrl(m.connectUrl(state, lang)), lang);
    }
  });

  await check(`[${tree}] the state is 32 random bytes, compared in full`, async () => {
    const m = await load();
    const seen = new Set(Array.from({ length: 200 }, () => m.generateState()));
    assert.equal(seen.size, 200);
    for (const s of seen) assert.ok(m.isValidState(s) && s.length === 43, s);
    const [a] = seen;
    assert.ok(m.statesMatch(a, a));
    assert.ok(!m.statesMatch(a, a.slice(0, -1) + (a.endsWith("A") ? "B" : "A")));
    assert.ok(!m.statesMatch(a, a.slice(0, 20)));
    assert.ok(!m.statesMatch(a, undefined));
    assert.ok(!m.isValidState("short") && !m.isValidState(a + "x") && !m.isValidState(a.slice(0, 42) + "!"));
  });

  await check(`[${tree}] only the connect page of https://cleanway.ai counts`, async () => {
    const m = await load();
    for (const ok of [
      "https://cleanway.ai/extension/connect", "https://cleanway.ai/extension/connect?state=a",
      "https://cleanway.ai/ar/extension/connect/?state=a", "https://CLEANWAY.ai/de/extension/connect",
    ]) assert.ok(m.isConnectPageUrl(ok), ok);
    for (const bad of [
      "http://cleanway.ai/extension/connect", "https://www.cleanway.ai/extension/connect",
      "https://cleanway.ai.evil.example/extension/connect", "https://evil.example/extension/connect",
      "https://cleanway.ai@evil.example/extension/connect", "https://cleanway.ai:8443/extension/connect",
      "https://cleanway.ai/extension/connect/x", "https://cleanway.ai/xx/extension/connect",
      "https://cleanway.ai/ru/ru/extension/connect", "https://cleanway.ai/signup?next=/extension/connect",
      "https://api.cleanway.ai/extension/connect", "chrome-extension://x/extension/connect", "", null,
    ]) assert.ok(!m.isConnectPageUrl(bad), String(bad));
  });

  await check(`[${tree}] AUTH_CONNECT only from our content script on the connect page's top frame`, async () => {
    const m = await load();
    assert.ok(m.isConnectSender(connectSender(), RUNTIME_ID));
    // Firefox and Safari: no `origin`, the URL decides.
    assert.ok(m.isConnectSender(connectSender({ origin: undefined }), RUNTIME_ID));
    assert.ok(m.isConnectSender(connectSender({ url: undefined }), RUNTIME_ID), "falls back to the tab URL");
    for (const [why, sender] of [
      ["another extension", connectSender({ id: "other" })],
      ["an extension page (no tab)", { id: RUNTIME_ID, url: `${EXT_BASE}src/popup/popup.html` }],
      ["a frame", connectSender({ frameId: 2 })],
      ["another page of the site", connectSender({ url: "https://cleanway.ai/pricing", tab: { id: 3, url: "https://cleanway.ai/pricing" } })],
      ["another site", connectSender({ url: "https://evil.example/extension/connect", origin: "https://evil.example" })],
      ["origin disagrees with url", connectSender({ origin: "https://evil.example" })],
      ["nothing", null],
    ]) assert.ok(!m.isConnectSender(sender, RUNTIME_ID), why);
  });

  await check(`[${tree}] sign in / out / status only from the extension's own pages`, async () => {
    const m = await load();
    assert.ok(m.isExtensionPageSender({ id: RUNTIME_ID, url: `${EXT_BASE}src/popup/popup.html` }, RUNTIME_ID, EXT_BASE));
    assert.ok(m.isExtensionPageSender({ id: RUNTIME_ID, url: `${EXT_BASE}src/options/options.html` }, RUNTIME_ID, EXT_BASE));
    assert.ok(!m.isExtensionPageSender(connectSender(), RUNTIME_ID, EXT_BASE), "a content script");
    assert.ok(!m.isExtensionPageSender({ id: "other", url: `${EXT_BASE}x.html` }, RUNTIME_ID, EXT_BASE));
    assert.ok(!m.isExtensionPageSender({ id: RUNTIME_ID, url: `${EXT_BASE}x.html` }, RUNTIME_ID, ""));
  });

  await check(`[${tree}] the handed-over session must be a live user token of our project`, async () => {
    const m = await load();
    const ok = m.parseHandoffSession(session(), { nowS: NOW_S });
    assert.ok(ok.ok);
    assert.deepEqual(ok.session, {
      auth_token: session().access_token, auth_refresh_token: REFRESH, auth_expires_at: NOW_S + 3600,
      auth_email: "ann@example.com", auth_user_id: "user-1", auth_anon_key: ANON,
    });
    assert.ok(m.parseHandoffSession(session({ anon_key: "sb_publishable_AbCdEf123456" }), { nowS: NOW_S }).ok);
    const refused = {
      "another project": session({ access_token: accessToken({ iss: "https://evil.supabase.co/auth/v1" }) }),
      "expired": session({ access_token: accessToken({ exp: NOW_S - 1 }) }),
      "not a user token": session({ access_token: accessToken({ aud: "anon" }) }),
      "no subject": session({ access_token: accessToken({ sub: "" }) }),
      "not a JWT": session({ access_token: "abc.def" }),
      "refresh token with odd characters": session({ refresh_token: "abc def<script>" }),
      "service-role key as the anon key": session({ anon_key: SERVICE }),
      "no anon key": session({ anon_key: "" }),
      "missing": null,
    };
    for (const [why, raw] of Object.entries(refused)) {
      assert.equal(m.parseHandoffSession(raw, { nowS: NOW_S }).ok, false, why);
    }
    // expires_at never outlives the token itself
    const capped = m.parseHandoffSession(session({ expires_at: NOW_S + 99_999 }), { nowS: NOW_S });
    assert.equal(capped.session.auth_expires_at, NOW_S + 3600);
  });
}

// ── 3–6: the stateful flow ───────────────────────────────────────────

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] sign in: state kept, tab opened, tokens stored once, device registered`, async () => {
    const { auth, storage, calls } = await harness(tree);
    const url = await auth.startSignIn();
    assert.deepEqual(calls.tabs, [url]);
    const state = storage.data.auth_connect_state.value;
    assert.equal(url, `https://cleanway.ai/ru/extension/connect?state=${state}`);
    assert.equal((await auth.status()).pending, true);

    const result = await auth.acceptHandoff({ type: "AUTH_CONNECT", state, session: session() }, connectSender(), RUNTIME_ID);
    assert.deepEqual(result, { ok: true, email: "ann@example.com" });
    for (const k of SESSION_KEYS) assert.ok(storage.data[k] !== undefined, k);
    assert.equal(storage.data.auth_connect_state, undefined, "state not spent");
    assert.deepEqual(calls.signedIn, [session().access_token]);
    assert.equal(calls.alarms.at(-1), (NOW_S + 3600 - 300) * 1000, "refresh alarm 5 min before expiry");
    assert.deepEqual(await auth.status(), { signedIn: true, email: "ann@example.com", pending: false, signedOutReason: null });

    // The same handoff again (a replay) finds no state.
    const replay = await auth.acceptHandoff({ type: "AUTH_CONNECT", state, session: session({ refresh_token: "otherrefresh" }) }, connectSender(), RUNTIME_ID);
    assert.deepEqual(replay, { ok: false, error: "state_mismatch" });
    assert.equal(storage.data.auth_refresh_token, REFRESH);
  });

  await check(`[${tree}] a wrong, missing or stale state is refused and nothing is stored`, async () => {
    const { auth, storage, clock } = await harness(tree);
    await auth.startSignIn();
    const state = storage.data.auth_connect_state.value;
    const other = state.slice(0, -1) + (state.endsWith("A") ? "B" : "A");
    assert.deepEqual(await auth.acceptHandoff({ state: other, session: session() }, connectSender(), RUNTIME_ID),
      { ok: false, error: "state_mismatch" });
    assert.ok(storage.data.auth_connect_state, "a wrong guess must not burn the real state");
    assert.deepEqual(await auth.acceptHandoff({ session: session() }, connectSender(), RUNTIME_ID),
      { ok: false, error: "state_mismatch" });
    // Right state, wrong sender: refused before the state is even read.
    assert.deepEqual(await auth.acceptHandoff({ state, session: session() }, connectSender({ frameId: 1 }), RUNTIME_ID),
      { ok: false, error: "bad_sender" });
    assert.ok(storage.data.auth_connect_state);
    clock.ms += 31 * 60 * 1000;
    assert.deepEqual(await auth.acceptHandoff({ state, session: session({ access_token: accessToken({ exp: clock.ms / 1000 + 3600 }) }) }, connectSender(), RUNTIME_ID),
      { ok: false, error: "state_expired" });
    assert.equal(storage.data.auth_connect_state, undefined);
    for (const k of SESSION_KEYS) assert.equal(storage.data[k], undefined, k);
  });

  await check(`[${tree}] a bad session with the right state stores nothing and spends the state`, async () => {
    const { auth, storage } = await harness(tree);
    await auth.startSignIn();
    const state = storage.data.auth_connect_state.value;
    const r = await auth.acceptHandoff({ state, session: session({ anon_key: SERVICE }) }, connectSender(), RUNTIME_ID);
    assert.equal(r.ok, false);
    for (const k of SESSION_KEYS) assert.equal(storage.data[k], undefined, k);
    assert.equal(storage.data.auth_connect_state, undefined);
  });

  const signedIn = (over = {}) => ({
    auth_token: accessToken({ exp: NOW_S + 200 }), auth_refresh_token: REFRESH, auth_expires_at: NOW_S + 200,
    auth_email: "ann@example.com", auth_user_id: "user-1", auth_anon_key: ANON, ...over,
  });

  await check(`[${tree}] refresh: before expiry, to our project, token only in the body, once at a time`, async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    const fresh = accessToken({ exp: NOW_S + 3600 });
    const { auth, storage, calls } = await harness(tree, {
      stored: signedIn(),
      fetchImpl: async () => {
        await gate;
        return jsonResponse(200, { access_token: fresh, refresh_token: "rotated_refresh_2", expires_at: NOW_S + 3600, user: {} });
      },
    });
    const a = auth.ensureFresh();
    const b = auth.ensureFresh();
    release();
    await Promise.all([a, b]);
    assert.equal(calls.fetch.length, 1, "two refreshes with one rotating token");
    const { url, init } = calls.fetch[0];
    assert.equal(url, `${PROJECT}/auth/v1/token?grant_type=refresh_token`);
    assert.ok(!url.includes(REFRESH));
    assert.equal(init.method, "POST");
    assert.equal(init.headers.apikey, ANON);
    assert.deepEqual(JSON.parse(init.body), { refresh_token: REFRESH });
    assert.equal(storage.data.auth_token, fresh);
    assert.equal(storage.data.auth_refresh_token, "rotated_refresh_2");
    assert.equal(storage.data.auth_expires_at, NOW_S + 3600);
  });

  await check(`[${tree}] refresh: nothing to do while the token has time left`, async () => {
    const { auth, calls } = await harness(tree, { stored: signedIn({ auth_expires_at: NOW_S + 3000 }) });
    const r = await auth.ensureFresh();
    assert.deepEqual(r, { signedIn: true, refreshed: false });
    assert.equal(calls.fetch.length, 0);
    assert.equal(calls.alarms.at(-1), (NOW_S + 3000 - 300) * 1000);
  });

  await check(`[${tree}] refresh refused by Supabase → signed out, reason kept for the UI`, async () => {
    for (const status of [400, 401, 403]) {
      const { auth, storage, calls } = await harness(tree, {
        stored: signedIn(),
        fetchImpl: async () => jsonResponse(status, { error: "invalid_grant", error_description: "Invalid Refresh Token: Already Used" }),
      });
      const r = await auth.ensureFresh();
      assert.equal(r.signedIn, false, String(status));
      for (const k of SESSION_KEYS) assert.equal(storage.data[k], undefined, `${status} ${k}`);
      assert.equal(storage.data.auth_signed_out_reason, "expired");
      assert.equal(calls.alarms.at(-1), null, "refresh alarm cleared");
      assert.equal(calls.fetch.length, 1, "no logout call with a dead token");
      assert.deepEqual(await auth.status(), { signedIn: false, email: "", pending: false, signedOutReason: "expired" });
    }
  });

  await check(`[${tree}] refresh that can't reach Supabase keeps the session and retries`, async () => {
    for (const fetchImpl of [
      async () => { throw new TypeError("Failed to fetch"); },
      async () => jsonResponse(503, {}),
      async () => jsonResponse(429, {}),
      async () => jsonResponse(200, { unexpected: true }),
    ]) {
      const { auth, storage, calls } = await harness(tree, { stored: signedIn(), fetchImpl });
      const r = await auth.ensureFresh();
      assert.equal(r.signedIn, true);
      assert.equal(storage.data.auth_refresh_token, REFRESH);
      assert.equal(calls.alarms.at(-1), NOW_MS + 120_000, "retry in 2 minutes");
    }
  });

  await check(`[${tree}] sign-out forgets every token and ends the extension's session`, async () => {
    const { auth, storage, calls } = await harness(tree, {
      stored: { ...signedIn({ auth_expires_at: NOW_S + 3000 }), auth_connect_state: { value: "x", created_at: NOW_MS } },
      fetchImpl: async () => jsonResponse(204, {}),
    });
    const token = storage.data.auth_token;
    await auth.signOut();
    for (const k of [...SESSION_KEYS, "auth_connect_state", "auth_signed_out_reason"]) assert.equal(storage.data[k], undefined, k);
    assert.equal(calls.fetch.length, 1);
    assert.equal(calls.fetch[0].url, `${PROJECT}/auth/v1/logout?scope=local`);
    assert.equal(calls.fetch[0].init.headers.Authorization, `Bearer ${token}`);
    assert.equal(calls.alarms.at(-1), null);
    assert.deepEqual(await auth.status(), { signedIn: false, email: "", pending: false, signedOutReason: null });
  });

  await check(`[${tree}] sign-out works offline`, async () => {
    const { auth, storage } = await harness(tree, {
      stored: signedIn({ auth_expires_at: NOW_S + 3000 }),
      fetchImpl: async () => { throw new TypeError("offline"); },
    });
    await auth.signOut();
    for (const k of SESSION_KEYS) assert.equal(storage.data[k], undefined, k);
  });
}

// ── 7: the relay content script ──────────────────────────────────────

function loadRelay(tree, { href = "https://cleanway.ai/ru/extension/connect?state=s", top = true, reply = { ok: true } } = {}) {
  const url = new URL(href);
  const listeners = [];
  const posted = [];
  const sent = [];
  const window = {
    addEventListener: (type, fn) => { if (type === "message") listeners.push(fn); },
    postMessage: (data, targetOrigin) => posted.push({ data: structuredClone(data), targetOrigin }),
  };
  window.top = top ? window : {};
  const chrome = {
    runtime: {
      lastError: undefined,
      sendMessage: (msg, cb) => { sent.push(structuredClone(msg)); Promise.resolve().then(() => cb(reply)); },
    },
  };
  const ctx = vm.createContext({ window, location: url, chrome });
  vm.runInContext(readFileSync(join(ROOT, tree, "src/content/connect-relay.js"), "utf8"), ctx);
  const dispatch = (data, { origin = "https://cleanway.ai", source = window } = {}) => {
    for (const fn of listeners) fn({ data, origin, source });
  };
  return { listeners, posted, sent, dispatch, window };
}
const tick = () => new Promise((r) => setTimeout(r, 0));

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] relay stays silent anywhere but the connect page's top frame`, () => {
    for (const href of [
      "https://cleanway.ai/pricing", "https://evil.example/extension/connect",
      "https://www.cleanway.ai/extension/connect", "http://cleanway.ai/extension/connect",
    ]) {
      const r = loadRelay(tree, { href });
      assert.equal(r.listeners.length, 0, href);
      assert.equal(r.posted.length, 0, href);
    }
    assert.equal(loadRelay(tree, { top: false }).listeners.length, 0, "inside a frame");
  });

  await check(`[${tree}] relay answers hello, forwards only known fields, replies to the exact origin`, async () => {
    const r = loadRelay(tree);
    assert.deepEqual(r.posted[0], { data: { type: "cleanway:extension-ready", source: "cleanway-extension" }, targetOrigin: "https://cleanway.ai" });
    r.dispatch({ source: "cleanway-web", type: "cleanway:hello" });
    assert.equal(r.posted.length, 2);

    const s = session();
    r.dispatch({ source: "cleanway-web", type: "cleanway:connect", state: "st", session: { ...s, password: "x", extra: 1 }, evil: true });
    await tick();
    assert.deepEqual(r.sent, [{
      type: "AUTH_CONNECT", state: "st",
      session: { access_token: s.access_token, refresh_token: s.refresh_token, expires_at: s.expires_at, anon_key: s.anon_key },
    }]);
    assert.deepEqual(r.posted.at(-1), {
      data: { type: "cleanway:connect-result", ok: true, error: null, source: "cleanway-extension" },
      targetOrigin: "https://cleanway.ai",
    });
  });

  await check(`[${tree}] relay ignores other windows, other origins and other senders`, async () => {
    const r = loadRelay(tree);
    const msg = { source: "cleanway-web", type: "cleanway:connect", state: "st", session: session() };
    r.dispatch(msg, { origin: "https://evil.example" });
    r.dispatch(msg, { source: {} }); // an iframe or another window
    r.dispatch({ ...msg, source: "someone-else" });
    r.dispatch("cleanway:connect");
    await tick();
    assert.equal(r.sent.length, 0);
  });

  await check(`[${tree}] relay reports a refusal as a short error code`, async () => {
    const r = loadRelay(tree, { reply: { ok: false, error: "state_mismatch" } });
    r.dispatch({ source: "cleanway-web", type: "cleanway:connect", state: "st", session: session() });
    await tick();
    assert.deepEqual(r.posted.at(-1).data, { type: "cleanway:connect-result", ok: false, error: "state_mismatch", source: "cleanway-extension" });
    const dead = loadRelay(tree, { reply: null }); // background gone or crashed
    dead.dispatch({ source: "cleanway-web", type: "cleanway:connect", state: "st", session: session() });
    await tick();
    assert.equal(dead.posted.at(-1).data.error, "extension_error");
  });
}

// ── 8: manifests and logs ────────────────────────────────────────────

for (const tree of BROWSER_TREES) {
  await check(`[${tree}] manifest: relay on the connect path only, no externally_connectable`, () => {
    const manifest = JSON.parse(readFileSync(join(ROOT, tree, "manifest.json"), "utf8"));
    assert.equal(manifest.externally_connectable, undefined);
    const withRelay = manifest.content_scripts.filter((cs) => cs.js.includes("src/content/connect-relay.js"));
    assert.equal(withRelay.length, 1);
    assert.deepEqual(withRelay[0].matches, ["https://cleanway.ai/extension/connect*", "https://cleanway.ai/*/extension/connect*"]);
    assert.deepEqual(withRelay[0].js, ["src/content/connect-relay.js"]);
    assert.ok(!withRelay[0].all_frames, "top frame only");
  });
}

await check("the connect page and the relay speak the same message names", () => {
  const page = readFileSync(join(ROOT, "landing/lib/extension-connect.ts"), "utf8");
  const relay = readFileSync(join(ROOT, SOURCE_TREE, "src/content/connect-relay.js"), "utf8");
  for (const name of ["MSG_FROM_PAGE", "MSG_FROM_EXTENSION", "MSG_HELLO", "MSG_READY", "MSG_CONNECT", "MSG_RESULT"]) {
    const m = page.match(new RegExp(`export const ${name} = "([^"]+)"`));
    assert.ok(m, `${name} missing from landing/lib/extension-connect.ts`);
    assert.ok(relay.includes(`"${m[1]}"`), `connect-relay.js does not use "${m[1]}" (${name})`);
  }
  // The state the page accepts is the state the extension makes.
  assert.ok(page.includes("/^[A-Za-z0-9_-]{43}$/"), "landing state pattern drifted");
});

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] sign-in code never logs`, () => {
    for (const rel of ["src/utils/auth-session.js", "src/background/auth.js", "src/content/connect-relay.js"]) {
      const code = readFileSync(join(ROOT, tree, rel), "utf8").replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, "");
      assert.ok(!/\bconsole\.|_log\(/.test(code), `${rel} logs`);
    }
  });
}

console.log(
  failed === 0
    ? `\n${passed} checks passed (source + ${BROWSER_TREES.length} browser trees)`
    : `\n${failed} FAILED, ${passed} passed`,
);
process.exit(failed === 0 ? 0 : 1);

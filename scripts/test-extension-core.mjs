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
 *    it off mid-scan aborts the request, and it sends a message's links
 *    instead of its HTML.
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
  const data = { api_url: "https://api.test", ...stored };
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
  const window = {};
  const ctx = vm.createContext({
    window, chrome, document: page.document, location: { hostname: "mail.google.com" },
    MutationObserver, AbortController, console: { warn() {}, log() {} },
    setTimeout: (fn) => { timers.push(fn); return timers.length; },
    clearTimeout: () => {},
    fetch: (url, init) => {
      requests.push({ url, body: JSON.parse(init.body), signal: init.signal });
      if (hang) {
        // A slow API: answers only by failing when the request is aborted.
        return new Promise((_, reject) => init.signal.addEventListener("abort", () => reject(new Error("aborted"))));
      }
      return Promise.resolve({ ok: true, status: 200, json: async () => ({ level: "dangerous", score: 80, findings: [], links: [] }) });
    },
  });
  vm.runInContext(readFileSync(join(ROOT, tree, "src/content/webmail.js"), "utf8"), ctx);
  const settle = () => new Promise((r) => setTimeout(r, 0));
  return {
    page, requests, observers, window,
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
    assert.equal(req.url, "https://api.test/api/v1/email/analyze");
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

  await check(`[${tree}] webmail scanner: switching off mid-request aborts it and draws nothing`, async () => {
    const tab = runWebmailOnMailPage(tree, { webmailScannerEnabled: true }, { hang: true });
    await tab.tick();
    // The request is in flight once the scan reaches fetch.
    await tab.tick();
    assert.equal(tab.requests.length, 1);
    await tab.setSwitch(false);
    assert.equal(tab.requests[0].signal.aborted, true, "the request in flight was not aborted");
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

console.log(
  failed === 0
    ? `\n${passed} checks passed (source + ${BROWSER_TREES.length} browser trees)`
    : `\n${failed} FAILED, ${passed} passed`,
);
process.exit(failed === 0 ? 0 : 1);

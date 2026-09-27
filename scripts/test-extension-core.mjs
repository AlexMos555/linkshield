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
  "evidence_", "weekly_", "score_", "breach_", "pwned_", "webmail_", "options_",
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

// The webmail banner names the analyzer's first finding by its category.
await check("every email-analyzer finding category has a webmail line", () => {
  const analyzer = readFileSync(join(ROOT, "api/services/email_analyzer.py"), "utf8");
  const categories = new Set([...analyzer.matchAll(/\bcategory\s*=\s*["']([a-z_]+)["']/g)].map((m) => m[1]));
  assert.ok(categories.size >= 4, `only ${categories.size} categories found — did the scan break?`);
  const webmail = readFileSync(join(ROOT, SOURCE_TREE, "src/content/webmail.js"), "utf8");
  const en = readJson("extension/_locales/en/messages.json");
  for (const category of categories) {
    const key = `webmail_finding_${category}`;
    assert.ok(webmail.includes(`${category}: "${key}"`), `webmail.js does not map ${category}`);
    assert.ok(en[key], `${key} missing from the catalog`);
  }
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

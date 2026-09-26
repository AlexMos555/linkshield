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
// content scripts, the context menu, the manifest and the family notifier.
const NEW_KEY_PREFIXES = [
  "badge_", "audit_", "credguard_", "mpg_", "menu_", "command_", "family_notify_",
];

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

function fakeChrome({ optional }) {
  const calls = { alarmsCreated: [] };
  const api = {
    runtime: { onMessage: fakeEvent(), onInstalled: fakeEvent(), getURL: (p) => `chrome-extension://test/${p}`, lastError: undefined },
    storage: { local: { get: async () => ({}), set: async () => {}, remove: async () => {} }, onChanged: fakeEvent() },
    i18n: { getMessage: (key) => `[${key}]` },
    tabs: { create() {}, query: async () => [], sendMessage: async () => {}, remove() {} },
  };
  if (optional) {
    Object.assign(api, {
      alarms: { create: (name) => calls.alarmsCreated.push(name), get: async () => undefined, onAlarm: fakeEvent() },
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
    assert.ok(calls.alarmsCreated.includes("cleanway_family_poll"), "family poll alarm not armed");
    await new Promise((r) => setTimeout(r, 0)); // alarms.get() resolves, prune alarm is created
    assert.ok(calls.alarmsCreated.includes("cleanway_history_prune"), "history prune alarm not armed");
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

// ── Group 3: every i18n key used exists in every locale of every tree ──

const KEY_USE_RES = [
  /chrome\.i18n\.getMessage\(\s*["']([A-Za-z0-9_]+)["']/g,
  /\b_t\(\s*["']([A-Za-z0-9_]+)["']/g,
  /\b_tHtml\(\s*["']([A-Za-z0-9_]+)["']/g,
];

function usedKeys(tree) {
  const keys = new Set();
  for (const rel of listJs(join(tree, "src"))) {
    const code = stripComments(readFileSync(join(ROOT, rel), "utf8"));
    for (const re of KEY_USE_RES) for (const m of code.matchAll(re)) keys.add(m[1]);
  }
  const manifest = join(ROOT, tree, "manifest.json");
  if (existsSync(manifest)) {
    for (const m of readFileSync(manifest, "utf8").matchAll(/__MSG_(\w+)__/g)) keys.add(m[1]);
  }
  return keys;
}

await check("extension-core uses the new keys (sanity: the scan finds them)", () => {
  const keys = [...usedKeys(SOURCE_TREE)];
  for (const prefix of ["credguard_", "mpg_", "badge_", "menu_", "family_notify_"]) {
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

console.log(
  failed === 0
    ? `\n${passed} checks passed (source + ${BROWSER_TREES.length} browser trees)`
    : `\n${failed} FAILED, ${passed} passed`,
);
process.exit(failed === 0 ? 0 : 1);

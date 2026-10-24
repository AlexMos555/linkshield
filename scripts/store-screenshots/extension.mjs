#!/usr/bin/env node
/**
 * Store screenshots of the Cleanway browser extension, reproducibly.
 *
 *   NODE_PATH=<dir>/node_modules node scripts/store-screenshots/extension.mjs [en] [ru] [--ext <dir>] [--out <dir>]
 *
 * Needs playwright (+ `playwright install chromium`) resolvable through
 * NODE_PATH, like scripts/test-extension-sw.mjs; nothing is added to the
 * repository's dependencies. Writes store-assets/extension/<lang>/0N-*.png
 * (1280x800, RGB, no alpha) and, after a run in both languages, the README
 * there, which says what each picture shows, how it was made and which to
 * upload per language (readme.mjs, HOLD_BACK).
 *
 * The extension is the real unpacked build (extension/ by default), loaded
 * the way a person loads it. Around it:
 *   - Pages: the demo pages of fixtures.mjs, served by this script.
 *   - Server and network (network.mjs): every host name resolves to nowhere;
 *     a stub answers each site check with the verdict the extension's OWN
 *     offline rules give that host, and /health with 200; everything else is
 *     answered or refused by the script. No verdict is invented.
 *   - Popup: opened with Extensions.triggerAction, i.e. a toolbar click
 *     (with the activeTab grant that comes with it), captured from its own
 *     DevTools target and placed at the top right of a shot of the same tab.
 *
 * The run stops instead of saving a wrong picture: a demo host whose offline
 * verdict changed, a missing or wrong badge, a tooltip over another badge, a
 * popup in the wrong state or taller than Chrome's 600 px popup limit, a block
 * page that never came, a service worker the stub cannot reach.
 */
import { createRequire } from "node:module";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildInfo, scorerFrom } from "./build-info.mjs";
import { connectBrowser } from "./cdp.mjs";
import { EXPECTED, HOSTS, URLS, WHERE } from "./fixtures.mjs";
import { interceptAll } from "./network.mjs";
import { decodePng, encodeRgbPng } from "./png.mjs";
import { HOLD_BACK, SHOTS, heldBack, writeReadme } from "./readme.mjs";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const PLAYWRIGHT_VERSION = require("playwright/package.json").version;

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const W = 1280, H = 800;
const POPUP_MAX_H = 600; // Chrome never makes an extension popup taller
const LANG_ENV = { en: "en_US", ru: "ru_RU" };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const withTimeout = (promise, ms) =>
  Promise.race([promise, sleep(ms).then(() => { throw new Error(`no answer in ${ms} ms`); })]);

// ── arguments ──
const argv = process.argv.slice(2);
const opt = (name, fallback) => {
  const i = argv.indexOf(name);
  return i >= 0 ? resolve(argv[i + 1]) : fallback;
};
const EXT = opt("--ext", join(ROOT, "extension"));
const OUT = opt("--out", join(ROOT, "store-assets", "extension"));
const LANGS = argv.filter((a, i) => !a.startsWith("--") && !argv[i - 1]?.startsWith("--"));
for (const l of LANGS) if (!LANG_ENV[l]) throw new Error(`unknown language ${l}: use en and/or ru`);

async function until(what, fn, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const v = await fn();
    if (v) return v;
    await sleep(150);
  }
  throw new Error(`timed out waiting for ${what}`);
}

// ── the browser ──

// A service worker keeps the network setup it started with, and the
// extension's started before interception was switched on, so its requests
// would miss the stub (and fail on the dead resolver). Stopping it is what
// Chrome does to every idle MV3 worker; the next message starts a fresh one,
// whose requests are intercepted. Proven before any shot: a request from
// the new worker must reach the stub.
async function restartWorker(context, browser, oldWorker, extId) {
  const { targetInfos } = await browser.send("Target.getTargets");
  const target = targetInfos.find((t) => t.type === "service_worker" && t.url === oldWorker.url());
  if (!target) throw new Error("the extension's service worker target is missing");
  await browser.send("Target.closeTarget", { targetId: target.targetId });
  await sleep(500);
  // Playwright keeps one Worker handle across the restart; ask through it
  // until the answer comes from the stub.
  return until("the restarted service worker to reach the stub", async () => {
    const w = context.serviceWorkers().filter((x) => new URL(x.url()).host === extId).pop();
    // A handle on a stopped worker can wait forever: give each try 3 s.
    const status = w ? await withTimeout(w.evaluate(() =>
      fetch("https://api.cleanway.ai/health?from=screenshot-script").then((r) => r.status, () => 0)), 3000).catch(() => -1) : -1;
    if (status === 200) return w;
    // Wake it the way any extension page does: a message to the background.
    const ext = context.pages().find((p) => p.url().startsWith(`chrome-extension://${extId}/`));
    if (ext) {
      await withTimeout(ext.evaluate(() => chrome.runtime.sendMessage({ type: "AUTH_STATUS" }).catch(() => null)), 3000)
        .catch(() => {});
    }
    await sleep(500);
    return null;
  }, 60000);
}

async function launch(lang, score, log) {
  const dir = mkdtempSync(join(tmpdir(), "cleanway-shots-"));
  const profile = join(dir, "profile");
  let executablePath;
  if (process.platform === "darwin") {
    // macOS Chromium takes its UI language from -AppleLanguages, not --lang.
    // Headless Chromium also reads one start URL, and would take "(ru)" for
    // it, so the wrapper drops Playwright's about:blank and the value stands in.
    executablePath = join(dir, "chromium.sh");
    writeFileSync(executablePath, `#!/bin/sh\nfor a; do shift; [ "$a" = about:blank ] || set -- "$@" "$a"; done\n` +
      `exec "${chromium.executablePath()}" "$@" -AppleLanguages "(${lang})"\n`);
    chmodSync(executablePath, 0o755);
  }
  const context = await chromium.launchPersistentContext(profile, {
    ...(executablePath ? { executablePath } : { channel: "chromium" }),
    headless: true,
    timeout: 0, // a cold first start on a busy Mac can take minutes
    viewport: { width: W, height: H },
    deviceScaleFactor: 1,
    locale: lang,
    env: { ...process.env, LANGUAGE: lang, LANG: `${LANG_ENV[lang]}.UTF-8` },
    args: [
      `--disable-extensions-except=${EXT}`,
      `--load-extension=${EXT}`,
      `--lang=${lang}`,
      "--headless=new",
      "--remote-debugging-port=0",
      "--host-resolver-rules=MAP * ~NOTFOUND",
    ],
  });
  try {
    const browser = await connectBrowser(profile);
    await interceptAll(browser, lang, score, log);
    let [sw] = context.serviceWorkers();
    if (!sw) sw = await context.waitForEvent("serviceworker", { timeout: 120000 });
    const extId = new URL(sw.url()).host;
    const uiLocale = await sw.evaluate(() => chrome.i18n.getMessage("@@ui_locale"));
    if (!uiLocale.toLowerCase().startsWith(lang)) throw new Error(`the extension's UI is ${uiLocale}, wanted ${lang}`);
    console.log(`[${lang}] ${browser.version}, extension ${extId}, UI locale ${uiLocale}`);
    await sleep(1500); // the first-install welcome tab
    sw = await restartWorker(context, browser, sw, extId);
    console.log(`[${lang}] service worker restarted inside the interception; the stub answers it`);
    for (const p of context.pages().slice(1)) await p.close();
    const page = context.pages()[0] || (await context.newPage());
    return { context, browser, extId, uiLocale, page, dir };
  } catch (err) {
    await context.close();
    rmSync(dir, { recursive: true, force: true });
    throw err;
  }
}

// ── pictures ──
function save(png, file) {
  const { width, height, rgba } = decodePng(png);
  if (width !== W || height !== H) throw new Error(`${file}: ${width}x${height}, expected ${W}x${H}`);
  writeFileSync(file, encodeRgbPng(width, height, rgba));
  console.log(`  ${relative(ROOT, file)}  ${Math.round(readFileSync(file).length / 1024)} KB`);
}

const tabShot = (page) => page.screenshot({ type: "png", animations: "disabled", caret: "hide" });

/** The badge right after the link to `href`: "safe" | "caution" | "dangerous" | null. */
const badgeLevel = (page, href) => page.evaluate((h) => {
  const a = [...document.querySelectorAll("a")].find((x) => x.href === h);
  const b = a && a.nextElementSibling;
  if (!b || !b.classList.contains("ls-badge")) return null;
  return ["safe", "caution", "dangerous"].find((l) => b.classList.contains(`ls-${l}`)) || "other";
}, href);

async function expectBadges(page, expected) {
  await until("every badge", async () => {
    for (const [href] of expected) if (!(await badgeLevel(page, href))) return false;
    return true;
  });
  for (const [href, level] of expected) {
    const got = await badgeLevel(page, href);
    if (got !== level) throw new Error(`badge for ${href}: ${got}, expected ${level}`);
  }
}

/** The tab target (not the page target) of the only tab: what triggerAction takes. */
async function onlyTab(browser) {
  const { targetInfos } = await browser.send("Target.getTargets", { filter: [{ type: "tab" }] });
  if (targetInfos.length !== 1) throw new Error(`expected one tab, found ${targetInfos.length}`);
  return targetInfos[0].targetId;
}

/** Click the toolbar icon over the current tab and capture the popup at its full height. */
async function popupShot(s, { expectState, dismissTip = false }) {
  const { browser, extId } = s;
  const popupUrl = `chrome-extension://${extId}/src/popup/popup.html`;
  await browser.send("Extensions.triggerAction", { id: extId, targetId: await onlyTab(browser) });
  const target = await until("the popup", async () => {
    const { targetInfos } = await browser.send("Target.getTargets");
    return targetInfos.find((t) => t.type === "page" && t.url === popupUrl);
  });
  const { sessionId } = await browser.send("Target.attachToTarget", { targetId: target.targetId, flatten: true });
  try {
    const ev = (expr) => browser.evaluate(sessionId, expr);
    await until("the popup's verdict", () => ev("(() => { const c = document.getElementById('status-card'); " +
      "return document.readyState === 'complete' && !!c && c.dataset.state !== 'scanning'; })()"));
    if (dismissTip) {
      await ev("(() => { const tip = document.getElementById('onboarding-tip'); " +
        "if (!tip.hidden) document.getElementById('dismiss-tip').click(); return true; })()");
    }
    await sleep(1200); // the server check (/health) and the account row
    const ui = await ev("({ state: document.getElementById('status-card').dataset.state, " +
      "title: document.getElementById('status-title').textContent, sub: document.getElementById('status-subtitle').textContent, " +
      "offline: !document.getElementById('offline-banner').hidden, tip: !document.getElementById('onboarding-tip').hidden })");
    console.log(`  popup: ${ui.state} — ${ui.title} — ${ui.sub}`);
    if (ui.state !== expectState) throw new Error(`popup state ${ui.state}, expected ${expectState}`);
    if (ui.offline) throw new Error("the popup shows its offline banner: the /health stub did not answer");
    if (ui.tip) throw new Error("the welcome tip is still open");
    const { cssContentSize } = await browser.send("Page.getLayoutMetrics", {}, sessionId);
    const h = Math.ceil(cssContentSize.height), w = Math.ceil(cssContentSize.width);
    if (h > POPUP_MAX_H) throw new Error(`popup is ${h}px tall: Chrome would cut it at ${POPUP_MAX_H}px with a scrollbar`);
    const shot = await browser.send("Page.captureScreenshot",
      { format: "png", captureBeyondViewport: true, clip: { x: 0, y: 0, width: w, height: h, scale: 1 } }, sessionId);
    return { png: Buffer.from(shot.data, "base64"), width: w, height: h, line: ui.sub };
  } finally {
    await browser.send("Target.closeTarget", { targetId: target.targetId }).catch(() => {});
    await sleep(300);
  }
}

/** The popup at the top right of the tab it was opened over, where Chrome puts it under the toolbar. */
async function withPopup(context, tabPng, popup) {
  const canvas = await context.newPage();
  const src = (b) => `data:image/png;base64,${b.toString("base64")}`;
  await canvas.setContent(
    `<body style="margin:0;width:${W}px;height:${H}px;overflow:hidden;position:relative;background:#fff">` +
    `<img src="${src(tabPng)}" style="position:absolute;left:0;top:0;width:${W}px;height:${H}px">` +
    `<img src="${src(popup.png)}" style="position:absolute;top:10px;right:18px;width:${popup.width}px;height:${popup.height}px;` +
    "border-radius:10px;box-shadow:0 0 0 1px rgba(15,23,42,.18),0 16px 48px rgba(15,23,42,.45)\"></body>");
  await canvas.waitForFunction(() => [...document.images].every((i) => i.complete && i.naturalWidth > 0));
  const png = await canvas.screenshot({ type: "png" });
  await canvas.close();
  return png;
}

// ── one language ──
async function captureLocale(lang, score, log) {
  const s = await launch(lang, score, log);
  const { context, page, extId } = s;
  const out = join(OUT, lang);
  mkdirSync(out, { recursive: true });
  const file = (n) => join(out, SHOTS[n - 1][0]);
  try {
    // 04 — badges on a search-results page, the red one hovered.
    await page.goto(URLS.search);
    const results = await page.$$eval("main a", (as) => as.map((a) => a.href));
    await expectBadges(page, results.map((href) => [href, EXPECTED[new URL(href).hostname] || "safe"]));
    await sleep(600);
    await page.hover(`a[href="${URLS.scam}"] + .ls-badge`);
    await page.waitForSelector(`a[href="${URLS.scam}"] + .ls-badge .ls-tooltip`, { state: "visible" });
    await sleep(400);
    const hidden = await page.evaluate((scam) => {
      const own = document.querySelector(`a[href="${scam}"] + .ls-badge`);
      const tip = own.querySelector(".ls-tooltip-inner").getBoundingClientRect();
      return [...document.querySelectorAll(".ls-badge")].filter((b) => b !== own).filter((b) => {
        const r = b.getBoundingClientRect();
        return r.left < tip.right && r.right > tip.left && r.top < tip.bottom && r.bottom > tip.top;
      }).map((b) => b.previousElementSibling.href);
    }, URLS.scam);
    if (hidden.length) throw new Error(`the tooltip covers the badge of ${hidden.join(", ")}: shorten that title`);
    save(await tabShot(page), file(4));
    await page.mouse.move(0, 0);

    // 02 — the popup on an ordinary page.
    await page.goto(URLS.recipe);
    const links = await page.$$eval("main a", (as) => as.map((a) => a.href));
    await expectBadges(page, links.map((href) => [href, "safe"]));
    await sleep(600);
    const recipeTab = await tabShot(page);
    const safePopup = await popupShot(s, { expectState: "safe", dismissTip: true });
    save(await withPopup(context, recipeTab, safePopup), file(2));
    const worker = context.serviceWorkers().find((w) => new URL(w.url()).host === extId);
    const tipDone = worker && await worker.evaluate(() =>
      chrome.storage.local.get("onboarding_done").then((d) => d.onboarding_done === true));
    if (!tipDone) throw new Error("closing the welcome tip was not stored");

    // 03 — the popup on a caution page (not blocked).
    await page.goto(URLS.caution);
    await sleep(1500); // the page check
    if (new URL(page.url()).hostname !== HOSTS.caution) throw new Error(`caution page left for ${page.url()}`);
    const cautionTab = await tabShot(page);
    const cautionPopup = await popupShot(s, { expectState: "warning" });
    save(await withPopup(context, cautionTab, cautionPopup), file(3));

    // 01 — opening the scam page: the tab is taken to the extension's block page.
    await page.goto(URLS.scam, { waitUntil: "commit" }); // it does not stay long enough to "load"
    await page.waitForURL(/^chrome-extension:\/\/[a-p]{32}\/src\/blocked\/blocked\.html\?/, { timeout: 30000 });
    await page.waitForSelector("#ls-block-overlay", { timeout: 30000 });
    const shownDomain = (await page.innerText(".ls-block-domain")).trim();
    if (shownDomain !== HOSTS.scam) throw new Error(`block page names ${shownDomain}`);
    await page.waitForSelector("#ls-block-proceed:not([disabled])", { timeout: 15000 }); // the 5-second countdown
    await sleep(800);
    save(await tabShot(page), file(1));

    // 05 — Settings, top of the page.
    await page.goto(`chrome-extension://${extId}/src/options/options.html`);
    await sleep(1500); // the account row and the saved settings
    save(await tabShot(page), file(5));
    // The popups' second lines, for the README's upload order (HOLD_BACK).
    const popupLines = { [SHOTS[1][0]]: safePopup.line, [SHOTS[2][0]]: cautionPopup.line };
    return { lang, uiLocale: s.uiLocale, browser: s.browser.version, popupLines };
  } finally {
    s.browser.close();
    await context.close();
    rmSync(s.dir, { recursive: true, force: true });
  }
}

// ── main ──
const info = buildInfo(ROOT, EXT);
const score = scorerFrom((rel) => readFileSync(join(EXT, rel), "utf8"));
const verdicts = [];
for (const [host, level] of Object.entries(EXPECTED)) {
  const v = score(host);
  if (v.level !== level) throw new Error(`the offline rules now call ${host} ${v.level}, not ${level}: pick another demo host`);
  if (info.zipScore && info.zipScore(host).level !== level) {
    throw new Error(`${info.zip} calls ${host} ${info.zipScore(host).level}, the source tree ${level}`);
  }
  verdicts.push({ host, level: v.level, reasons: v.reasons.map((r) => r.signal), where: WHERE[host] });
}
console.log(`extension ${info.version} from ${relative(ROOT, EXT) || EXT}${info.commit ? ` @ ${info.commit}` : ""}` +
  (info.zip ? `; differs from ${info.zip} in: ${info.zipDiff.join(", ") || "nothing"}` : ""));

const log = { api: new Set(), refused: new Set() };
const runs = [];
for (const lang of LANGS.length ? LANGS : ["en", "ru"]) runs.push(await captureLocale(lang, score, log));

for (const h of HOLD_BACK) {
  const run = runs.find((r) => r.lang === h.lang);
  if (run && !heldBack([run]).includes(h)) {
    console.log(`  note: ${h.lang}/${h.file} no longer shows what kept it out of the upload order ` +
      `(${JSON.stringify(run.popupLines[h.file])}); it is back in the README's order: update the docs that list it ` +
      "(docs/CWS_SUBMISSION.md §6, docs/STORES.md, docs/STORE_SUBMISSION_KIT.md §2.3) and drop its HOLD_BACK entry");
  }
}

if (new Set(runs.map((r) => r.lang)).size === 2) {
  writeReadme(OUT, {
    date: new Date().toISOString().slice(0, 10),
    extRel: relative(ROOT, EXT).startsWith("..") ? EXT : `${relative(ROOT, EXT)}/`,
    ...info,
    browser: runs[0].browser,
    playwright: PLAYWRIGHT_VERSION,
    platform: process.platform === "darwin" ? "macOS" : process.platform,
    locales: runs,
    verdicts,
    apiPaths: [...log.api].sort(),
    refused: [...log.refused].sort(),
  });
  console.log(`  ${relative(ROOT, join(OUT, "README.md"))}`);
}
console.log("done");

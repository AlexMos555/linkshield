#!/usr/bin/env node
/**
 * Store screenshots of the Cleanway browser extension (1280x800, no alpha).
 *
 *   NODE_PATH=<repo>/node_modules node store-assets/browser-extension/screenshots/capture.mjs [en] [ru] [--popup-only]
 *
 * Loads the unpacked extension/ into Playwright's Chromium, exactly as a user
 * would, against the PRODUCTION API (https://api.cleanway.ai, read-only GET
 * /api/v1/public/check/<host>). No sign-in, no webmail scanning, no form is
 * ever submitted. Only the demo pages are served locally (context.route on
 * hosts we control the content of); every badge, verdict, warning and the
 * block page (the extension's own blocked.html) come from the extension itself.
 *
 * The public check allows ~60 requests/hour per IP; one language costs ~8.
 *
 * The popup (02) is the real popup.html opened in a tab. A toolbar click
 * gives the popup the current tab's address through activeTab, which a script
 * cannot click; so that one shot runs from a temporary copy of the extension
 * whose manifest also lists "tabs" (nothing else differs), and the popup is
 * laid over a screenshot of the same tab.
 *
 * macOS Chromium ignores --lang, so Chromium is started through a tiny
 * wrapper that adds `-AppleLanguages (<lang>)`. Needs Playwright + its
 * Chromium (`npx playwright install chromium`) and macOS `sips` for the
 * final alpha-free PNG (on Linux, --lang + LANGUAGE are enough and the
 * flattening step can be replaced by any JPEG/PNG round-trip).
 */
import { createRequire } from "node:module";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const HERE = dirname(fileURLToPath(import.meta.url));
const EXT = resolve(HERE, "../../../extension");
const W = 1280, H = 800;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Hosts. Verdicts come from the live API at capture time (checked 2026-10-21):
const DEMO = "news.example"; // our demo page; reserved TLD, nobody's brand
const DANGEROUS = "account-verify-login-secure.netlify.app"; // API: dangerous
const LINKS = ["en.wikipedia.org", "github.com", "parcel-fee-redelivery.top", "prize-claim-now.xyz", DANGEROUS];
const LOGIN = "secure-login-update.xyz"; // API: caution; hosts the demo login form
const COLLECTOR = "collector-endpoint.example"; // where that form would post (never submitted)

const TEXT = {
  en: {
    title: "Weekend links from the neighbourhood group",
    intro: "Links people shared in the group chat this week.",
    items: [
      ["Wikipedia: How to recognise phishing", "https://en.wikipedia.org/wiki/Phishing"],
      ["Open-source photo organiser on GitHub", "https://github.com/topics/photo-management"],
      ["“Your parcel is waiting — pay the redelivery fee”", "https://parcel-fee-redelivery.top/pay"],
      ["“You won! Claim your prize now”", "https://prize-claim-now.xyz/claim"],
    ],
    fwd: "Forwarded from an unknown number",
    fwdText: "Security notice: unusual activity was detected on your account. Confirm your details within 24 hours to avoid suspension.",
    fwdLink: "Verify your account now",
    loginTitle: "Members area", loginUser: "Email", loginPass: "Password", loginBtn: "Sign in",
    blank: "Loading…",
  },
  ru: {
    title: "Ссылки за неделю из чата соседей",
    intro: "Что прислали в общий чат на этой неделе.",
    items: [
      ["Википедия: как распознать фишинг", "https://en.wikipedia.org/wiki/Phishing"],
      ["Фотоорганайзер с открытым кодом на GitHub", "https://github.com/topics/photo-management"],
      ["«Ваша посылка ждёт — оплатите повторную доставку»", "https://parcel-fee-redelivery.top/pay"],
      ["«Вы выиграли! Заберите приз»", "https://prize-claim-now.xyz/claim"],
    ],
    fwd: "Переслано с неизвестного номера",
    fwdText: "Уведомление безопасности: в вашем аккаунте замечена необычная активность. Подтвердите данные в течение 24 часов, иначе доступ будет закрыт.",
    fwdLink: "Подтвердить аккаунт",
    loginTitle: "Личный кабинет", loginUser: "Эл. почта", loginPass: "Пароль", loginBtn: "Войти",
    blank: "Загрузка…",
  },
};

const PAGE_CSS = "body{margin:0;font:16px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" +
  "background:#f8fafc;color:#0f172a}main{max-width:760px;margin:40px auto;background:#fff;border:1px solid #e2e8f0;" +
  "border-radius:14px;padding:32px 44px}h1{font-size:28px;margin:0 0 6px}p{color:#475569;margin:0 0 20px}" +
  "li{margin:12px 0;font-size:18px}a{color:#1d4ed8}label{display:block;margin:14px 0 6px;color:#334155}" +
  "input{width:100%;box-sizing:border-box;padding:10px 12px;font-size:16px;border:1px solid #cbd5e1;border-radius:8px}" +
  "button{margin-top:20px;padding:11px 22px;font-size:16px;border:0;border-radius:8px;background:#1d4ed8;color:#fff}";
const html = (lang, title, body) =>
  `<!doctype html><html lang="${lang}"><meta charset="utf-8"><title>${title}</title><style>${PAGE_CSS}</style><main>${body}</main>`;

function demoPage(lang) {
  const t = TEXT[lang];
  const items = t.items.map(([label, href]) => `<li><a href="${href}">${label}</a></li>`).join("");
  // The scam link sits well below the list, so its open tooltip (it opens
  // upwards) covers the forwarded text, not the other badges.
  return html(lang, t.title, `<h1>${t.title}</h1><p>${t.intro}</p><ul>${items}</ul>` +
    `<div style="margin-top:28px;padding:16px 22px;border-left:4px solid #cbd5e1;background:#f8fafc;border-radius:8px">` +
    `<div style="font-size:13px;color:#64748b;margin-bottom:6px">${t.fwd}</div><p style="margin:0 0 90px">${t.fwdText}</p>` +
    `<a style="font-size:18px" href="https://${DANGEROUS}/verify">${t.fwdLink}</a></div>`);
}
function loginPage(lang) {
  const t = TEXT[lang];
  return html(lang, t.loginTitle, `<h1>${t.loginTitle}</h1><form action="https://${COLLECTOR}/submit" method="post">` +
    `<label>${t.loginUser}</label><input type="email" name="u"><label>${t.loginPass}</label>` +
    `<input type="password" name="p"><button type="button">${t.loginBtn}</button></form>`);
}

// Playwright PNGs carry an alpha channel; the stores want plain 24-bit RGB.
function savePng(buf, file) {
  const jpg = file.replace(/\.png$/, ".tmp.jpg");
  writeFileSync(jpg, buf);
  execFileSync("sips", ["-s", "format", "png", jpg, "--out", file], { stdio: "ignore" });
  rmSync(jpg);
}
const shot = async (page, file) => savePng(await page.screenshot({ type: "jpeg", quality: 100 }), file);

async function launch(lang, ext = EXT) {
  const dir = mkdtempSync(join(tmpdir(), "cw-shots-"));
  const wrapper = join(dir, "chromium.sh");
  // Headless Chromium takes one start URL, and it would read "(ru)" as one;
  // so the wrapper drops Playwright's about:blank and the value stands in.
  writeFileSync(wrapper, `#!/bin/sh\nfor a; do shift; [ "$a" = about:blank ] || set -- "$@" "$a"; done\n` +
    `exec "${chromium.executablePath()}" "$@" -AppleLanguages "(${lang})"\n`);
  chmodSync(wrapper, 0o755);
  const context = await chromium.launchPersistentContext(join(dir, "profile"), {
    executablePath: process.platform === "darwin" ? wrapper : undefined,
    headless: true,
    timeout: 0, // a cold first start on a busy Mac can take minutes
    viewport: { width: W, height: H },
    deviceScaleFactor: 1,
    locale: lang,
    env: { ...process.env, LANGUAGE: lang, LANG: `${lang}_${lang.toUpperCase()}.UTF-8` },
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, `--lang=${lang}`, "--headless=new"],
  });
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent("serviceworker", { timeout: 120000 });
  const extId = new URL(sw.url()).host;
  const uiLocale = await sw.evaluate(() => chrome.i18n.getMessage("@@ui_locale"));
  if (!uiLocale.startsWith(lang)) throw new Error(`extension UI is ${uiLocale}, wanted ${lang}`);
  console.log(`[${lang}] extension ${extId} from ${ext}, UI locale ${uiLocale}`);

  // Every verdict the background got from the live API, for the log.
  context.on("response", async (r) => {
    if (!r.url().includes("api.cleanway.ai/api/v1/public/check/")) return;
    const j = await r.json().catch(() => ({}));
    console.log(`[${lang}] API ${r.status()} ${decodeURIComponent(r.url().split("/check/")[1])} -> ${j.level} ${j.score ?? ""}`);
  });
  await context.route(`https://${DEMO}/**`, (r) => r.fulfill({ contentType: "text/html", body: demoPage(lang) }));
  await context.route(`https://${LOGIN}/**`, (r) => r.fulfill({ contentType: "text/html", body: loginPage(lang) }));
  await context.route(`https://${DANGEROUS}/**`, (r) =>
    r.fulfill({ contentType: "text/html", body: html(lang, "", `<p>${TEXT[lang].blank}</p>`) }));
  await sleep(1500); // the first-install welcome tab
  for (const p of context.pages().slice(1)) await p.close();
  const page = context.pages()[0] || (await context.newPage());
  return { context, sw, extId, dir, page };
}

// Since 0.2.1 the tab is taken to the extension's own blocked.html
// (background/block-redirect.js) instead of an overlay inside the scam page.
async function openBlockPage(page) {
  await page.goto(`https://${DANGEROUS}/verify`);
  await page.waitForURL(/^chrome-extension:\/\/[a-p]{32}\/src\/blocked\/blocked\.html\?/, { timeout: 60000 });
  await page.waitForSelector("#ls-block-overlay", { timeout: 60000 });
  await sleep(6500); // let the 5-second "continue anyway" countdown finish
}

async function capture(lang, out) {
  const { context, extId, dir, page } = await launch(lang);
  try {
    // 1. Link badges on an ordinary page, with the red badge's tooltip open.
    await page.goto(`https://${DEMO}/`);
    await page.waitForFunction((n) => document.querySelectorAll(".ls-badge").length >= n, LINKS.length, { timeout: 90000 });
    await sleep(800);
    await page.hover(".ls-badge.ls-dangerous");
    await sleep(500);
    await shot(page, join(out, "01-link-badges.png"));

    // 3. The block page the extension puts over a dangerous site on its own.
    await openBlockPage(page);
    await shot(page, join(out, "03-block-page.png"));

    // 4. Credential warning: a password form that posts to another site.
    await page.goto(`https://${LOGIN}/`);
    await page.waitForSelector("#ls-credguard-banner", { timeout: 30000 });
    await sleep(1000);
    await shot(page, join(out, "04-credential-warning.png"));

    // 5. Settings, top of the page.
    await page.goto(`chrome-extension://${extId}/src/options/options.html`);
    await sleep(2000);
    await shot(page, join(out, "05-settings.png"));
  } finally {
    await context.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

// 2. The popup for the blocked scam tab (see the header for the "tabs" copy).
async function capturePopup(lang, out) {
  const copy = mkdtempSync(join(tmpdir(), "cw-ext-"));
  cpSync(EXT, copy, { recursive: true });
  const manifest = JSON.parse(readFileSync(join(copy, "manifest.json"), "utf8"));
  manifest.permissions.push("tabs");
  writeFileSync(join(copy, "manifest.json"), JSON.stringify(manifest, null, 2));
  const { context, sw, extId, dir, page } = await launch(lang, copy);
  try {
    await openBlockPage(page);
    const bg = await page.screenshot({ type: "png" });
    // A background tab in the same window: the popup's "active tab" query
    // still returns the scam page, as it would from the toolbar.
    const [popup] = await Promise.all([
      context.waitForEvent("page"),
      sw.evaluate((url) => chrome.tabs.create({ url, active: false }), `chrome-extension://${extId}/src/popup/popup.html`),
    ]);
    await popup.setViewportSize({ width: 380, height: H });
    await popup.waitForFunction(() => document.getElementById("status-card").dataset.state !== "scanning", null, { timeout: 60000 });
    await sleep(800);
    const fg = await popup.locator("#popup").screenshot({ type: "png" });
    await popup.close();
    const canvas = await context.newPage();
    const src = (b) => `data:image/png;base64,${b.toString("base64")}`;
    await canvas.setContent(`<body style="margin:0;width:${W}px;height:${H}px;overflow:hidden;position:relative">` +
      `<img src="${src(bg)}" style="position:absolute;inset:0">` +
      `<img src="${src(fg)}" style="position:absolute;top:8px;right:16px;border-radius:10px;` +
      `box-shadow:0 12px 40px rgba(0,0,0,.55)"></body>`);
    await sleep(300);
    await shot(canvas, join(out, "02-popup-verdict.png"));
  } finally {
    await context.close();
    rmSync(dir, { recursive: true, force: true });
    rmSync(copy, { recursive: true, force: true });
  }
}

// The extension waits 3 s for the API and otherwise falls back to its offline
// scorer. A host the server has not analysed lately can take longer than that,
// so ask once first: the server caches the verdict and the extension then
// gets the same answer in time.
for (const host of [DEMO, ...LINKS, LOGIN]) {
  const r = await fetch(`https://api.cleanway.ai/api/v1/public/check/${host}`).catch(() => null);
  const j = r ? await r.json().catch(() => ({})) : {};
  console.log(`warm-up ${host}: ${r ? r.status : "offline"} ${j.level ?? ""}`);
}

const args = process.argv.slice(2);
const popupOnly = args.includes("--popup-only");
const langs = args.filter((a) => !a.startsWith("--"));
for (const lang of langs.length ? langs : ["en", "ru"]) {
  const out = join(HERE, lang);
  mkdirSync(out, { recursive: true });
  if (!popupOnly) await capture(lang, out);
  await capturePopup(lang, out);
}
console.log("done");

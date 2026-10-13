#!/usr/bin/env node
/**
 * Renders the store graphics that are not screenshots — the Google Play
 * feature graphic and the browser-store promo tiles — from the app icon and
 * the wordmark, in the app's colours (mobile/src/utils/theme.ts). No UI is
 * drawn here: screenshots are always real frames of the app or the extension.
 *
 * Run:   NODE_PATH=<repo>/node_modules node store-assets/render-graphics.mjs
 * Needs: playwright + its Chromium (`npx playwright install chromium`).
 * Output is opaque PNG (Play rejects alpha in the feature graphic); check with
 * `sips -g pixelWidth -g pixelHeight -g hasAlpha <file>`. The Edge store logo is
 * just the icon resized: `sips -z 300 300 mobile/assets/store/icon-512.png
 * --out store-assets/browser-extension/edge-store-logo-300.png`.
 */
import { createRequire } from "node:module";
import { readFileSync, mkdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ICON = `data:image/png;base64,${readFileSync(join(ROOT, "mobile/assets/store/icon-512.png")).toString("base64")}`;

// theme.ts: bg #0B1220, textPrimary #F1F5F9, textSecondary #94A3B8, green #34D399
const C = { bg: "#0B1220", text: "#F1F5F9", sub: "#94A3B8", green: "#34D399" };

const page = ({ w, h, icon, word, tag, gap, pad }) => `<!doctype html><html><head><meta charset="utf-8"><style>
  html,body{margin:0;width:${w}px;height:${h}px;background:${C.bg};overflow:hidden}
  body{display:flex;align-items:center;justify-content:flex-start;
       padding:0 ${pad}px;box-sizing:border-box;gap:${gap}px;
       font-family:-apple-system,BlinkMacSystemFont,"SF Pro Display","Helvetica Neue",Arial,sans-serif;
       background:radial-gradient(circle at 18% 50%, #13213a 0%, ${C.bg} 60%)}
  img{width:${icon}px;height:${icon}px;border-radius:${Math.round(icon * 0.22)}px;flex:none;
      box-shadow:0 0 0 1px #FFFFFF14}
  .t{display:flex;flex-direction:column;gap:${Math.round(word * 0.28)}px}
  .w{color:${C.text};font-size:${word}px;font-weight:700;letter-spacing:-0.02em;line-height:1}
  .g{color:${C.sub};font-size:${Math.round(word * 0.42)}px;font-weight:500;line-height:1.25;max-width:${w - icon - gap - pad * 2}px}
  .g b{color:${C.green};font-weight:600}
</style></head><body><img src="${ICON}"><div class="t"><div class="w">Cleanway</div><div class="g">${tag}</div></div></body></html>`;

const JOBS = [
  // Google Play feature graphic, 1024×500, per listing language.
  { out: "mobile/assets/store/google-play/en/feature-graphic.png", w: 1024, h: 500, icon: 220, word: 88, gap: 56, pad: 88,
    tag: "Blocks known <b>scam sites</b> in every app and checks texts and links" },
  { out: "mobile/assets/store/google-play/ru/feature-graphic.png", w: 1024, h: 500, icon: 220, word: 88, gap: 56, pad: 88,
    tag: "Блокирует <b>сайты мошенников</b> во всех приложениях, проверяет СМС и ссылки" },
  // Chrome Web Store / Edge small promo tile, 440×280.
  { out: "store-assets/browser-extension/en/promo-small-440x280.png", w: 440, h: 280, icon: 104, word: 40, gap: 22, pad: 30,
    tag: "Warns you about <b>scam sites</b> before you type a password" },
  { out: "store-assets/browser-extension/ru/promo-small-440x280.png", w: 440, h: 280, icon: 104, word: 40, gap: 22, pad: 30,
    tag: "Предупредит о <b>сайтах мошенников</b>, пока вы не ввели пароль" },
  // Marquee / large promo tile, 1400×560 (optional in CWS and Edge).
  { out: "store-assets/browser-extension/en/promo-marquee-1400x560.png", w: 1400, h: 560, icon: 260, word: 110, gap: 72, pad: 150,
    tag: "Warns you about <b>scam and phishing sites</b> before you type a password or card number" },
  { out: "store-assets/browser-extension/ru/promo-marquee-1400x560.png", w: 1400, h: 560, icon: 260, word: 110, gap: 72, pad: 150,
    tag: "Предупредит о <b>сайтах мошенников и фишинге</b>, пока вы не ввели пароль или номер карты" },
];

const browser = await chromium.launch({ timeout: 0 });
for (const job of JOBS) {
  const tab = await browser.newPage({ viewport: { width: job.w, height: job.h }, deviceScaleFactor: 1 });
  await tab.setContent(page(job));
  const out = join(ROOT, job.out);
  mkdirSync(dirname(out), { recursive: true });
  await tab.screenshot({ path: out, omitBackground: false, type: "png" });
  await tab.close();
  console.log(`${job.w}x${job.h}  ${job.out}`);
}
await browser.close();

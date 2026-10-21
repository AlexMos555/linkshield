#!/usr/bin/env node
/**
 * Colour-contrast table for the mobile theme — run with
 * `node mobile/scripts/test-theme-contrast.mjs`.
 *
 * Reads the colour tokens straight from mobile/src/utils/theme.ts and checks
 * the text/background pairs the screens actually use against WCAG 2.x AA:
 * 4.5:1 for body text, 3:1 for large text (>= 18pt, or >= 14pt bold —
 * 24 / 18.67 px; RN font sizes are density-independent px, so a 17px
 * semibold button label is NOT large). Translucent surfaces and washes are
 * composited over the app background first, the way they render.
 *
 * Many of our users are older people; small grey captions are the first
 * thing that stops being readable. Add a row here when a screen introduces a
 * new text/background pair.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const themeSrc = readFileSync(resolve(here, "../src/utils/theme.ts"), "utf8");
const block = themeSrc.match(/export const colors = \{([\s\S]*?)\n\};/);
if (!block) throw new Error("could not find `export const colors` in theme.ts");
const colors = Object.fromEntries(
  [...block[1].matchAll(/^\s*(\w+):\s*"(#[0-9A-Fa-f]{6}(?:[0-9A-Fa-f]{2})?)"/gm)].map((m) => [m[1], m[2]]),
);

function rgba(hex) {
  const h = hex.replace("#", "");
  const a = h.length === 8 ? parseInt(h.slice(6), 16) / 255 : 1;
  return [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16)).concat(a);
}
/** Composite a (possibly translucent) colour over an opaque one. */
function over(fg, bg) {
  const [r, g, b, a] = rgba(fg);
  const [R, G, B] = rgba(bg);
  return "#" + [r * a + R * (1 - a), g * a + G * (1 - a), b * a + B * (1 - a)]
    .map((v) => Math.round(v).toString(16).padStart(2, "0")).join("");
}
function luminance(hex) {
  const lin = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
  const [r, g, b] = rgba(hex);
  return 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
}
export function ratio(a, b) {
  const x = luminance(a), y = luminance(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

const c = (name) => {
  if (!(name in colors)) throw new Error(`theme.ts has no colour "${name}"`);
  return colors[name];
};
const BG = c("bg");
const SURFACES = {
  bg: BG,
  surface: over(c("surface"), BG),
  surfaceRaised: over(c("surfaceRaised"), BG),
  bgCard: c("bgCard"),
  bgInput: c("bgInput"),
  greenWash: over(c("greenWash"), BG),
  amberWash: over(c("amberWash"), BG),
  dangerWash: over(c("dangerWash"), BG),
  blueWash: over(c("blueWash"), BG),
};
const BODY = 4.5;
const LARGE = 3;

// [foreground, background, required ratio, where it is used]
const PAIRS = [
  // Body copy and captions on every surface the app draws.
  ...["bg", "surface", "surfaceRaised", "bgCard", "bgInput"].flatMap((bg) => [
    ["textPrimary", bg, BODY, "titles and body text"],
    ["textSecondary", bg, BODY, "secondary body text"],
    ["textMuted", bg, BODY, "captions, privacy lines, section headers"],
  ]),
  // Verdict words and status lines in their own hue.
  ...["bg", "surface"].flatMap((bg) => [
    ["green", bg, BODY, "safe / protected status text"],
    ["amber", bg, BODY, "caution text, low-confidence note"],
    ["danger", bg, BODY, "dangerous verdict, error text"],
    ["blue", bg, BODY, "text buttons and links"],
  ]),
  ["green", "greenWash", BODY, "status text on a green wash"],
  ["amber", "amberWash", BODY, "status text on an amber wash"],
  ["danger", "dangerWash", BODY, "status text on a red wash"],
  ["blue", "blueWash", BODY, "chip text on a blue wash"],
  ["textPrimary", "dangerWash", BODY, "body text inside a red verdict card"],
  ["textSecondary", "dangerWash", BODY, "sub text inside a red verdict card"],
  ["textSecondary", "amberWash", BODY, "sub text inside an amber verdict card"],
  // Filled buttons: 17px semibold white labels (not "large" text).
  ["#FFFFFF", "blueFill", BODY, "primary button / selected chip label"],
  ["#FFFFFF", "bluePressed", BODY, "primary button label, pressed"],
  ["bg", "danger", BODY, "required-update button label"],
  ["#0B1220", "green", BODY, "dark label on a green button (auth, onboarding, family)"],
  // Non-text: the filled button must still stand out from the page (3:1).
  ["blueFill", "bg", LARGE, "filled button against the background"],
];

const resolveColor = (v) => (v.startsWith("#") ? v : SURFACES[v] ?? c(v));
const failures = [];
const rows = [];
for (const [fg, bg, need, where] of PAIRS) {
  const r = ratio(resolveColor(fg), resolveColor(bg));
  const ok = r >= need;
  rows.push(`${ok ? "ok  " : "FAIL"} ${r.toFixed(2).padStart(5)}:1 (needs ${need}) ${fg} on ${bg} — ${where}`);
  if (!ok) failures.push(rows[rows.length - 1]);
}
if (process.argv.includes("--table")) console.log(rows.join("\n"));
if (failures.length) {
  console.error(`Contrast check failed (${failures.length}):\n  ${failures.join("\n  ")}`);
  process.exit(1);
}
console.log(`theme contrast: OK (${PAIRS.length} text/background pairs meet WCAG AA)`);

#!/usr/bin/env node
/**
 * Accessibility guard for the mobile app — run with
 * `node mobile/scripts/check-a11y-labels.mjs`.
 *
 * Many of our users are older people, some with a screen reader or large
 * system text. This static check pins the basics so a new screen cannot
 * quietly regress them:
 *  - every Pressable / TouchableOpacity / TouchableHighlight /
 *    TouchableWithoutFeedback opening tag declares accessibilityRole, so
 *    VoiceOver / TalkBack say "button" (or "link", "switch", "tab", ...)
 *    instead of reading a bare text;
 *  - nothing turns off system font scaling (allowFontScaling={false}), and
 *    nothing caps it below 1.3x (maxFontSizeMultiplier) — large text must
 *    actually get large;
 *  - an icon-only touchable (no <Text> child and no accessibilityLabel)
 *    is reported too, since a screen reader would have nothing to say;
 *  - a touchable inside another accessible touchable is reported: iOS
 *    merges the outer one into a single element and the inner button
 *    becomes unreachable with VoiceOver;
 *  - icon glyphs are hidden from screen readers app-wide
 *    (src/utils/decorative-icons.ts, imported by app/_layout.tsx); an
 *    <Ionicons> that carries its own accessibilityLabel must opt back in.
 *
 * Scans every .tsx under mobile/app and mobile/src.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname, resolve, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const mobile = resolve(here, "..");
const ROOTS = ["app", "src"].map((d) => join(mobile, d));
const TOUCHABLES = ["Pressable", "TouchableOpacity", "TouchableHighlight", "TouchableWithoutFeedback"];
const MIN_FONT_MULTIPLIER = 1.3;

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) {
      if (name === "node_modules" || name === "__tests__") continue;
      walk(p, out);
    } else if (name.endsWith(".tsx")) {
      out.push(p);
    }
  }
  return out;
}

/**
 * Return the index just past the end of the JSX opening tag starting at
 * `start` (which points at "<"). Braces and string literals are skipped so
 * that `=>` inside a prop expression does not end the tag early.
 */
function endOfOpeningTag(src, start) {
  let depth = 0;
  let quote = null;
  for (let i = start + 1; i < src.length; i++) {
    const c = src[i];
    if (quote) {
      if (c === "\\") { i++; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === "`") { quote = c; continue; }
    if (c === "{") depth++;
    else if (c === "}") depth--;
    else if (c === ">" && depth === 0) return i + 1;
  }
  return src.length;
}

/** Find the matching closing tag of a non-self-closing element. */
function bodyOf(src, tagName, from) {
  const open = new RegExp(`<${tagName}\\b`, "g");
  const close = new RegExp(`</${tagName}\\s*>`, "g");
  let depth = 1;
  let i = from;
  while (depth > 0) {
    open.lastIndex = i;
    close.lastIndex = i;
    const o = open.exec(src);
    const c = close.exec(src);
    if (!c) return src.slice(from);
    if (o && o.index < c.index) {
      const end = endOfOpeningTag(src, o.index);
      if (src[end - 2] !== "/") depth++;
      i = end;
    } else {
      depth--;
      if (depth === 0) return src.slice(from, c.index);
      i = c.index + c[0].length;
    }
  }
  return "";
}

const lineOf = (src, idx) => src.slice(0, idx).split("\n").length;

export function checkSource(src, file = "<inline>") {
  const problems = [];
  const tagRe = new RegExp(`<(${TOUCHABLES.join("|")})\\b`, "g");
  let m;
  while ((m = tagRe.exec(src))) {
    const end = endOfOpeningTag(src, m.index);
    const tag = src.slice(m.index, end);
    const where = `${file}:${lineOf(src, m.index)}`;
    // A backdrop the screen reader must skip (accessible={false}) needs no
    // role; neither does a tag whose props come from a spread we cannot see.
    if (/\baccessible\s*=\s*\{\s*false\s*\}/.test(tag) || /\{\s*\.\.\./.test(tag)) continue;
    if (!/\baccessibilityRole\s*=/.test(tag)) {
      problems.push(`${where} <${m[1]}> has no accessibilityRole`);
    }
    const selfClosing = tag.endsWith("/>");
    const body = selfClosing ? "" : bodyOf(src, m[1], end);
    const hasLabel = /\baccessibilityLabel\s*=/.test(tag);
    // Text inside, or a child expression such as {children} / {inner} that
    // this static check cannot look into.
    const hasText = /<(Text|Animated\.Text)\b/.test(body) || /(^|[^=])\{\s*[A-Za-z_][\w.]*\s*\}/.test(body);
    if (!hasLabel && !hasText) {
      problems.push(`${where} <${m[1]}> has no text and no accessibilityLabel (icon-only?)`);
    }
    // An accessible touchable swallows its children into one element on iOS:
    // a button inside it can no longer be reached with VoiceOver.
    if (new RegExp(`<(${TOUCHABLES.join("|")})\\b`).test(body)) {
      problems.push(`${where} <${m[1]}> wraps another touchable — make the outer one accessible={false} or a sibling`);
    }
  }
  // Icons are hidden from screen readers by default (decorative-icons.ts):
  // one that carries its own label must opt back in, or the label is lost.
  const iconRe = /<Ionicons\b/g;
  while ((m = iconRe.exec(src))) {
    const tag = src.slice(m.index, endOfOpeningTag(src, m.index));
    if (/\baccessibilityLabel\s*=/.test(tag) && !/importantForAccessibility\s*=\s*"yes"/.test(tag)) {
      problems.push(`${file}:${lineOf(src, m.index)} <Ionicons> has a label but stays hidden — add importantForAccessibility="yes" and accessibilityElementsHidden={false}`);
    }
  }
  const noScale = /allowFontScaling\s*=\s*\{\s*false\s*\}/g;
  while ((m = noScale.exec(src))) {
    problems.push(`${file}:${lineOf(src, m.index)} allowFontScaling={false} blocks large text`);
  }
  const cap = /maxFontSizeMultiplier\s*=\s*\{\s*([\d.]+)\s*\}/g;
  while ((m = cap.exec(src))) {
    if (Number(m[1]) < MIN_FONT_MULTIPLIER) {
      problems.push(`${file}:${lineOf(src, m.index)} maxFontSizeMultiplier=${m[1]} caps large text below ${MIN_FONT_MULTIPLIER}`);
    }
  }
  return problems;
}

function selfTest() {
  const bad = `<Pressable onPress={() => a > b}><Icon /></Pressable><Text allowFontScaling={false}>x</Text>
    <TouchableOpacity accessibilityRole="button"><Pressable accessibilityRole="button"><Text>a</Text></Pressable></TouchableOpacity>
    <Ionicons name="x" accessibilityLabel={t("on")} />`;
  const p = checkSource(bad);
  if (p.length !== 5) throw new Error(`self-test: expected 3 problems, got ${p.length}: ${p.join("; ")}`);
  const good = `<Pressable accessibilityRole="button" onPress={() => a > b}><Text>Hi</Text></Pressable>
    <TouchableOpacity accessibilityRole="button" accessibilityLabel={t("x")} onPress={go} />`;
  const q = checkSource(good);
  if (q.length) throw new Error(`self-test: expected no problems, got: ${q.join("; ")}`);
}

selfTest();
const problems = [];
// The default that hides icon glyphs must stay wired in at the app root.
if (!/import\s+"\.\.\/src\/utils\/decorative-icons"/.test(readFileSync(join(mobile, "app/_layout.tsx"), "utf8"))) {
  problems.push(`mobile/app/_layout.tsx no longer imports src/utils/decorative-icons — icon glyphs become empty screen-reader stops`);
}
let files = 0;
for (const root of ROOTS) {
  for (const f of walk(root)) {
    files++;
    problems.push(...checkSource(readFileSync(f, "utf8"), relative(resolve(mobile, ".."), f)));
  }
}
if (problems.length) {
  console.error(`Accessibility check failed (${problems.length}):`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exit(1);
}
console.log(`a11y labels: OK (${files} .tsx files)`);

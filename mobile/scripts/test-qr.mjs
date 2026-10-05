#!/usr/bin/env node
/**
 * Table test for src/utils/qr.ts — run with `node scripts/test-qr.mjs`.
 *
 * The encoder is not trusted about itself: every symbol here is READ BACK
 * by an independent reader written in this file — format bits decoded from
 * both copies, the mask lifted, codewords collected in placement order,
 * de-interleaved, every block's Reed–Solomon syndromes checked to be zero,
 * and the byte-mode payload parsed — and must equal the input. Plus the
 * fixed patterns a scanner locks onto: finders, timing, the dark module.
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deepStrictEqual } from "node:assert";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const appRequire = createRequire(join(root, "package.json"));
const ts = appRequire("typescript");

function loadTs(file) {
  const { outputText } = ts.transpileModule(readFileSync(file, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020, esModuleInterop: true },
    fileName: file,
  });
  const module = { exports: {} };
  const requireHere = (spec) => (spec.startsWith(".") ? loadTs(resolve(dirname(file), `${spec}.ts`)) : appRequire(spec));
  new Function("require", "module", "exports", outputText)(requireHere, module, module.exports);
  return module.exports;
}

const { encodeQr, versionFor, dataCodewords, formatBits, rsEncode, gfMul, MAX_VERSION } = loadTs(join(root, "src/utils/qr.ts"));

// ── An independent reader ─────────────────────────────────────────

const SPEC = {
  L: [[26, 1, 7], [44, 1, 10], [70, 1, 15], [100, 1, 20], [134, 1, 26], [172, 2, 18]],
  M: [[26, 1, 10], [44, 1, 16], [70, 1, 26], [100, 2, 18], [134, 2, 24], [172, 4, 16]],
};
const MASK_FN = [
  (r, c) => (r + c) % 2 === 0, (r) => r % 2 === 0, (_r, c) => c % 3 === 0, (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0, (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0, (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

/** Decodes 15 format bits by nearest valid codeword (as a scanner would). */
function readFormat(bits15) {
  let best = null;
  for (let data = 0; data < 32; data++) {
    let rem = data;
    for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
    const code = ((data << 10) | rem) ^ 0x5412;
    const distance = (code ^ bits15).toString(2).split("1").length - 1;
    if (!best || distance < best.distance) best = { data, distance };
  }
  return { ec: ["M", "L", "H", "Q"][best.data >> 3], mask: best.data & 7, distance: best.distance };
}

function functionArea(version) {
  const size = 17 + 4 * version;
  const f = Array.from({ length: size }, () => new Array(size).fill(false));
  const sq = (r0, c0, n) => { for (let r = r0; r < r0 + n; r++) for (let c = c0; c < c0 + n; c++) if (r >= 0 && c >= 0 && r < size && c < size) f[r][c] = true; };
  sq(-1, -1, 9); sq(-1, size - 8, 9); sq(size - 8, -1, 9);
  for (let i = 0; i < size; i++) { f[6][i] = true; f[i][6] = true; }
  if (version >= 2) { const a = [0, 0, 18, 22, 26, 30, 34][version]; sq(a - 2, a - 2, 5); }
  for (let i = 0; i < 8; i++) { f[8][i] = true; f[i][8] = true; f[8][size - 1 - i] = true; f[size - 1 - i][8] = true; }
  f[8][8] = true;
  return f;
}

function readSymbol(sym) {
  const { size, modules: m } = sym;
  const version = (size - 17) / 4;
  const topLeft = [[8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8], [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]];
  let f1 = 0;
  for (const [r, c] of topLeft) f1 = (f1 << 1) | (m[r][c] ? 1 : 0);
  // The second copy the way zxing reads it: column 8 from the bottom edge up (7 bits), then row 8 left to right (8 bits).
  let f2 = 0;
  for (let i = 0; i < 7; i++) f2 = (f2 << 1) | (m[size - 1 - i][8] ? 1 : 0);
  for (let i = 0; i < 8; i++) f2 = (f2 << 1) | (m[8][size - 8 + i] ? 1 : 0);
  const fmt1 = readFormat(f1);
  const fmt2 = readFormat(f2);
  const fn = functionArea(version);
  const bits = [];
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let i = 0; i < size; i++) {
      const r = upward ? size - 1 - i : i;
      for (const c of [right, right - 1]) if (!fn[r][c]) bits.push(m[r][c] !== MASK_FN[fmt1.mask](r, c) ? 1 : 0);
    }
    upward = !upward;
  }
  const [total, blocks, ecPer] = SPEC[fmt1.ec][version - 1];
  const words = [];
  for (let i = 0; i + 8 <= bits.length && words.length < total; i += 8) words.push(parseInt(bits.slice(i, i + 8).join(""), 2));
  const dataPer = (total - blocks * ecPer) / blocks;
  const blockData = Array.from({ length: blocks }, () => []);
  const blockEc = Array.from({ length: blocks }, () => []);
  let k = 0;
  for (let i = 0; i < dataPer; i++) for (let b = 0; b < blocks; b++) blockData[b].push(words[k++]);
  for (let i = 0; i < ecPer; i++) for (let b = 0; b < blocks; b++) blockEc[b].push(words[k++]);
  // Syndromes: evaluate the whole block polynomial at α^0..α^(ec-1); all zero ⇔ no error.
  const exp = [];
  let x = 1;
  for (let i = 0; i < 255; i++) { exp.push(x); x <<= 1; if (x & 0x100) x ^= 0x11d; }
  const syndromesZero = blockData.every((d, b) => {
    const poly = [...d, ...blockEc[b]];
    for (let s = 0; s < ecPer; s++) {
      let acc = 0;
      for (const coef of poly) acc = gfMul(acc, exp[s]) ^ coef;
      if (acc !== 0) return false;
    }
    return true;
  });
  const dataBits = blockData.flat().flatMap((w) => w.toString(2).padStart(8, "0").split("").map(Number));
  const mode = parseInt(dataBits.slice(0, 4).join(""), 2);
  const len = parseInt(dataBits.slice(4, 12).join(""), 2);
  const bytes = [];
  for (let i = 0; i < len; i++) bytes.push(parseInt(dataBits.slice(12 + 8 * i, 20 + 8 * i).join(""), 2));
  return { version, fmt1, fmt2, mode, text: Buffer.from(bytes).toString("utf8"), syndromesZero, wordsRead: words.length, total };
}

const finderAt = (m, r0, c0) => {
  for (let r = 0; r < 7; r++) for (let c = 0; c < 7; c++) {
    const ring = Math.max(Math.abs(r - 3), Math.abs(c - 3));
    if (m[r0 + r][c0 + c] !== (ring <= 1 || ring === 3)) return false;
  }
  return true;
};

const CLAIM = "cleanway://claim?code=482913";

const roundTrip = (text, preferred) => {
  const sym = encodeQr(text, preferred);
  const read = readSymbol(sym);
  return {
    text: read.text, mode: read.mode, version: read.version === sym.version, ec: read.fmt1.ec === sym.ecLevel && read.fmt2.ec === sym.ecLevel,
    mask: read.fmt1.mask === sym.mask && read.fmt2.mask === sym.mask, exactFormat: read.fmt1.distance === 0 && read.fmt2.distance === 0,
    rs: read.syndromesZero, filled: read.wordsRead === read.total,
  };
};
const ok = (text) => ({ text, mode: 4, version: true, ec: true, mask: true, exactFormat: true, rs: true, filled: true });

const CASES = [
  ["the claim payload reads back, level M", () => roundTrip(CLAIM, "M"), ok(CLAIM)],
  ["the claim payload is a version-3 M symbol (29×29)", () => { const s = encodeQr(CLAIM); return [s.version, s.ecLevel, s.size]; }, [3, "M", 29]],
  ["one byte, version 1", () => ({ ...roundTrip("a", "M"), v: encodeQr("a").version }), { ...ok("a"), v: 1 }],
  ["utf-8 survives (Cyrillic)", () => roundTrip("код 123456 для мамы", "M"), ok("код 123456 для мамы")],
  ["two RS blocks (version 4 M, 64 data bytes)", () => { const t = "x".repeat(60); return { ...roundTrip(t, "M"), v: encodeQr(t).version }; }, { ...ok("x".repeat(60)), v: 4 }],
  ["four RS blocks (version 6 M)", () => { const t = "y".repeat(100); return { ...roundTrip(t, "M"), v: encodeQr(t).version }; }, { ...ok("y".repeat(100)), v: 6 }],
  ["too long for M falls back to L; too long for both throws", () => {
    const t = "z".repeat(120);
    const s = encodeQr(t);
    let threw = false;
    try { encodeQr("w".repeat(140)); } catch { threw = true; }
    return { ...roundTrip(t, "M"), ec: s.ecLevel, v: s.version, threw };
  }, { ...ok("z".repeat(120)), ec: "L", v: 6, threw: true }],
  ["level L explicitly, two blocks (version 6 L)", () => { const t = "q".repeat(120); return roundTrip(t, "L"); }, ok("q".repeat(120))],
  ["every mask chosen by the penalty is a real one, and each one reads back", () => {
    const seen = new Set();
    const results = [];
    for (let i = 0; i < 40; i++) {
      const t = `cleanway://claim?code=${String(100000 + i * 23457).slice(0, 6)}`;
      const s = encodeQr(t);
      seen.add(s.mask);
      results.push(readSymbol(s).text === t && s.mask >= 0 && s.mask <= 7);
    }
    return { allRead: results.every(Boolean), masksVaried: seen.size >= 2 };
  }, { allRead: true, masksVaried: true }],
  ["finders, timing and the dark module where a scanner expects them", () => {
    const s = encodeQr(CLAIM);
    const m = s.modules;
    const n = s.size;
    const timingRow = Array.from({ length: n - 16 }, (_, i) => m[6][8 + i] === ((8 + i) % 2 === 0)).every(Boolean);
    const timingCol = Array.from({ length: n - 16 }, (_, i) => m[8 + i][6] === ((8 + i) % 2 === 0)).every(Boolean);
    const separators = [...Array(8).keys()].every((i) => !m[7][i] && !m[i][7] && !m[7][n - 1 - i] && !m[i][n - 8] && !m[n - 8][i] && !m[n - 1 - i][7]);
    return { tl: finderAt(m, 0, 0), tr: finderAt(m, 0, n - 7), bl: finderAt(m, n - 7, 0), timingRow, timingCol, dark: m[n - 8][8], separators };
  }, { tl: true, tr: true, bl: true, timingRow: true, timingCol: true, dark: true, separators: true }],
  ["capacity table: version for a length (byte mode), data codewords", () => [
    versionFor(14, "M"), versionFor(15, "M"), versionFor(26, "M"), versionFor(27, "M"), versionFor(31, "L"), versionFor(106, "M"), versionFor(107, "M"),
    versionFor(134, "L"), versionFor(135, "L"), dataCodewords(1, "L"), dataCodewords(1, "M"), dataCodewords(6, "M"),
  ], [1, 2, 2, 3, 2, 6, null, 6, null, 19, 16, 108]],
  ["format bits: the published example (M, mask 5 → 0x40CE); every codeword carries its data and the code's distance is 7", () => {
    const codes = [];
    for (const ec of ["L", "M"]) for (let mask = 0; mask < 8; mask++) codes.push({ ec, mask, code: formatBits(ec, mask) });
    const carriesData = codes.every(({ ec, mask, code }) => ((code ^ 0x5412) >> 10) === (({ L: 1, M: 0 })[ec] << 3 | mask));
    const popcount = (n) => n.toString(2).split("1").length - 1;
    const minDistance = Math.min(...codes.flatMap((a) => codes.filter((b) => b !== a).map((b) => popcount(a.code ^ b.code))));
    return [formatBits("M", 5).toString(16), carriesData, minDistance];
  }, ["40ce", true, 7]],
  ["RS: the spec's version-1 M worked example ec codewords", () => rsEncode(
    [0x10, 0x20, 0x0c, 0x56, 0x61, 0x80, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11], 10,
  ), [0xa5, 0x24, 0xd4, 0xc1, 0xed, 0x36, 0xc7, 0x87, 0x2c, 0x55]],
  ["version cap is 6", () => MAX_VERSION, 6],
];

let failed = 0;
for (const [name, run, expected] of CASES) {
  try {
    deepStrictEqual(run(), expected);
    console.log(`  ok    ${name}`);
  } catch (e) {
    failed += 1;
    console.log(`  FAIL  ${name}\n        ${String(e.message).split("\n").join("\n        ")}`);
  }
}
if (failed > 0) {
  console.error(`\n${failed} of ${CASES.length} cases failed`);
  process.exitCode = 1;
} else {
  console.log(`\nall ${CASES.length} cases pass`);
}

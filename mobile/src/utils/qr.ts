/**
 * A small QR encoder for the "add a relative's phone" screen: the 6-digit
 * claim code as `cleanway://claim?code=…`, scanned by the relative's phone.
 *
 * Why in-house: the app has a QR *scanner* (expo-camera) but no encoder, and
 * the payload is short and fixed in shape — byte mode, versions 1–6, error
 * correction M (L when M does not fit). Everything the symbol needs is here:
 * Reed–Solomon over GF(256), the eight masks with the standard penalty
 * score, format information, and placement. scripts/test-qr.mjs reads the
 * symbols back (format, unmask, codewords, RS syndromes, data) rather than
 * trusting the encoder about itself.
 */

export type EcLevel = "L" | "M";

export interface QrSymbol {
  version: number;
  ecLevel: EcLevel;
  mask: number;
  size: number;
  /** modules[row][col] — true is dark. */
  modules: boolean[][];
}

interface Spec {
  totalCodewords: number;
  /** Blocks (all of equal size for versions 1–6 at L/M) and EC codewords per block. */
  blocks: number;
  ecPerBlock: number;
}

/** ISO/IEC 18004 Table 9 for versions 1–6; data codewords = total − blocks·ecPerBlock. */
const SPECS: Record<EcLevel, Spec[]> = {
  L: [
    { totalCodewords: 26, blocks: 1, ecPerBlock: 7 },
    { totalCodewords: 44, blocks: 1, ecPerBlock: 10 },
    { totalCodewords: 70, blocks: 1, ecPerBlock: 15 },
    { totalCodewords: 100, blocks: 1, ecPerBlock: 20 },
    { totalCodewords: 134, blocks: 1, ecPerBlock: 26 },
    { totalCodewords: 172, blocks: 2, ecPerBlock: 18 },
  ],
  M: [
    { totalCodewords: 26, blocks: 1, ecPerBlock: 10 },
    { totalCodewords: 44, blocks: 1, ecPerBlock: 16 },
    { totalCodewords: 70, blocks: 1, ecPerBlock: 26 },
    { totalCodewords: 100, blocks: 2, ecPerBlock: 18 },
    { totalCodewords: 134, blocks: 2, ecPerBlock: 24 },
    { totalCodewords: 172, blocks: 4, ecPerBlock: 16 },
  ],
};

export const MAX_VERSION = 6;
const EC_BITS: Record<EcLevel, number> = { L: 1, M: 0 };
const ALIGNMENT_CENTER = [0, 0, 18, 22, 26, 30, 34];
const MODE_BYTE = 0b0100;

export function dataCodewords(version: number, ec: EcLevel): number {
  const s = SPECS[ec][version - 1];
  return s.totalCodewords - s.blocks * s.ecPerBlock;
}

/** The smallest version whose data area holds [byteLength] bytes at [ec], or null above version 6. */
export function versionFor(byteLength: number, ec: EcLevel): number | null {
  for (let v = 1; v <= MAX_VERSION; v++) {
    if (4 + 8 + 8 * byteLength <= dataCodewords(v, ec) * 8) return v;
  }
  return null;
}

// ── GF(256) with the QR polynomial 0x11d ──

const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);
(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

export function gfMul(a: number, b: number): number {
  return a === 0 || b === 0 ? 0 : EXP[LOG[a] + LOG[b]];
}

function generator(degree: number): number[] {
  let poly = [1];
  for (let i = 0; i < degree; i++) {
    const next = new Array<number>(poly.length + 1).fill(0);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly;
}

/** The [degree] Reed–Solomon error-correction codewords for [data]. */
export function rsEncode(data: readonly number[], degree: number): number[] {
  const gen = generator(degree);
  const rest = new Array<number>(degree).fill(0);
  for (const byte of data) {
    const factor = byte ^ rest.shift()!;
    rest.push(0);
    if (factor !== 0) for (let j = 0; j < degree; j++) rest[j] ^= gfMul(gen[j + 1], factor);
  }
  return rest;
}

// ── Bits → codewords ──

function utf8Bytes(text: string): number[] {
  const out: number[] = [];
  for (const ch of encodeURIComponent(text).match(/%[0-9A-F]{2}|./g) ?? []) {
    out.push(ch.length === 3 ? parseInt(ch.slice(1), 16) : ch.charCodeAt(0));
  }
  return out;
}

function dataBits(bytes: readonly number[], capacityBits: number): number[] {
  const bits: number[] = [];
  const push = (value: number, width: number) => {
    for (let i = width - 1; i >= 0; i--) bits.push((value >> i) & 1);
  };
  push(MODE_BYTE, 4);
  push(bytes.length, 8);
  for (const b of bytes) push(b, 8);
  push(0, Math.min(4, capacityBits - bits.length));
  while (bits.length % 8 !== 0) bits.push(0);
  const pads = [0xec, 0x11];
  for (let i = 0; bits.length < capacityBits; i++) push(pads[i % 2], 8);
  return bits;
}

function toCodewords(bits: readonly number[]): number[] {
  const out: number[] = [];
  for (let i = 0; i < bits.length; i += 8) {
    let byte = 0;
    for (let j = 0; j < 8; j++) byte = (byte << 1) | bits[i + j];
    out.push(byte);
  }
  return out;
}

/** Data split into blocks, each followed by its EC codewords, then interleaved as the symbol wants them. */
function interleave(data: readonly number[], spec: Spec): number[] {
  const perBlock = data.length / spec.blocks;
  const blocks = Array.from({ length: spec.blocks }, (_, i) => data.slice(i * perBlock, (i + 1) * perBlock));
  const ecs = blocks.map((b) => rsEncode(b, spec.ecPerBlock));
  const out: number[] = [];
  for (let i = 0; i < perBlock; i++) for (const b of blocks) out.push(b[i]);
  for (let i = 0; i < spec.ecPerBlock; i++) for (const e of ecs) out.push(e[i]);
  return out;
}

// ── The matrix ──

type Grid = boolean[][];

function emptyGrid(size: number): Grid {
  return Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
}

/** The modules no data goes into: finders, separators, timing, alignment, format, dark module. */
export function functionMask(version: number): Grid {
  const size = 17 + 4 * version;
  const g = emptyGrid(size);
  const square = (r0: number, c0: number, n: number) => {
    for (let r = r0; r < r0 + n; r++) for (let c = c0; c < c0 + n; c++) if (r >= 0 && c >= 0 && r < size && c < size) g[r][c] = true;
  };
  square(-1, -1, 9);
  square(-1, size - 8, 9);
  square(size - 8, -1, 9);
  for (let i = 0; i < size; i++) {
    g[6][i] = true;
    g[i][6] = true;
  }
  if (version >= 2) {
    const a = ALIGNMENT_CENTER[version];
    square(a - 2, a - 2, 5);
  }
  for (let i = 0; i < 8; i++) {
    g[8][i] = true;
    g[i][8] = true;
    g[8][size - 1 - i] = true;
    g[size - 1 - i][8] = true;
  }
  g[8][8] = true;
  return g;
}

function drawFinder(g: Grid, r0: number, c0: number): void {
  for (let r = -1; r <= 7; r++) {
    for (let c = -1; c <= 7; c++) {
      const rr = r0 + r;
      const cc = c0 + c;
      if (rr < 0 || cc < 0 || rr >= g.length || cc >= g.length) continue;
      const ring = Math.max(Math.abs(r - 3), Math.abs(c - 3));
      g[rr][cc] = ring <= 1 || ring === 3;
    }
  }
}

function drawFixedPatterns(g: Grid, version: number): void {
  const size = g.length;
  drawFinder(g, 0, 0);
  drawFinder(g, 0, size - 7);
  drawFinder(g, size - 7, 0);
  for (let i = 8; i < size - 8; i++) {
    g[6][i] = i % 2 === 0;
    g[i][6] = i % 2 === 0;
  }
  if (version >= 2) {
    const a = ALIGNMENT_CENTER[version];
    for (let r = -2; r <= 2; r++) for (let c = -2; c <= 2; c++) g[a + r][a + c] = Math.max(Math.abs(r), Math.abs(c)) !== 1;
  }
  g[size - 8][8] = true; // the dark module
}

/** The 15 format bits for [ec] and [mask]: BCH(15,5) with the fixed XOR mask. */
export function formatBits(ec: EcLevel, mask: number): number {
  const data = (EC_BITS[ec] << 3) | mask;
  let rem = data;
  for (let i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
  return ((data << 10) | rem) ^ 0x5412;
}

function drawFormat(g: Grid, ec: EcLevel, mask: number): void {
  const size = g.length;
  const bits = formatBits(ec, mask);
  const bit = (i: number) => ((bits >> i) & 1) === 1;
  // Around the top-left finder (bit 14 first), skipping the timing row/column.
  const topLeft: Array<[number, number]> = [[8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8], [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8]];
  topLeft.forEach(([r, c], i) => { g[r][c] = bit(14 - i); });
  // The second copy: bits 14..8 down column 8 from the bottom edge (seven
  // modules, above them the dark module), bits 7..0 along row 8 at the right.
  for (let i = 0; i < 7; i++) g[size - 1 - i][8] = bit(14 - i);
  for (let i = 0; i < 8; i++) g[8][size - 8 + i] = bit(7 - i);
}

/** Data module coordinates in placement order: two columns at a time, right to left, snaking up and down. */
export function placementOrder(version: number, isFunction: Grid): Array<[number, number]> {
  const size = 17 + 4 * version;
  const order: Array<[number, number]> = [];
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let i = 0; i < size; i++) {
      const r = upward ? size - 1 - i : i;
      for (const c of [right, right - 1]) if (!isFunction[r][c]) order.push([r, c]);
    }
    upward = !upward;
  }
  return order;
}

const MASKS: ReadonlyArray<(r: number, c: number) => boolean> = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (_r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

export function maskBit(mask: number, r: number, c: number): boolean {
  return MASKS[mask](r, c);
}

/** ISO/IEC 18004 §7.8.3 penalty score; the lowest wins. */
export function penalty(g: Grid): number {
  const size = g.length;
  let score = 0;
  const runs = (at: (i: number, j: number) => boolean) => {
    for (let i = 0; i < size; i++) {
      let run = 1;
      for (let j = 1; j <= size; j++) {
        if (j < size && at(i, j) === at(i, j - 1)) {
          run++;
          continue;
        }
        if (run >= 5) score += 3 + (run - 5);
        run = 1;
      }
    }
  };
  runs((r, c) => g[r][c]);
  runs((c, r) => g[r][c]);
  for (let r = 0; r + 1 < size; r++) {
    for (let c = 0; c + 1 < size; c++) {
      const v = g[r][c];
      if (g[r][c + 1] === v && g[r + 1][c] === v && g[r + 1][c + 1] === v) score += 3;
    }
  }
  const finderLike = (at: (i: number, j: number) => boolean) => {
    const pattern = [true, false, true, true, true, false, true];
    for (let i = 0; i < size; i++) {
      for (let j = 0; j + 7 <= size; j++) {
        if (!pattern.every((p, k) => at(i, j + k) === p)) continue;
        const lightBefore = j >= 4 && [1, 2, 3, 4].every((k) => !at(i, j - k));
        const lightAfter = j + 11 <= size && [7, 8, 9, 10].every((k) => !at(i, j + k));
        if (lightBefore || lightAfter) score += 40;
      }
    }
  };
  finderLike((r, c) => g[r][c]);
  finderLike((c, r) => g[r][c]);
  let dark = 0;
  for (const row of g) for (const m of row) if (m) dark++;
  const percent = (dark * 100) / (size * size);
  score += 10 * Math.floor(Math.abs(percent - 50) / 5);
  return score;
}

function render(version: number, ec: EcLevel, codewords: readonly number[], mask: number): Grid {
  const isFunction = functionMask(version);
  const g = emptyGrid(isFunction.length);
  drawFixedPatterns(g, version);
  drawFormat(g, ec, mask);
  const order = placementOrder(version, isFunction);
  order.forEach(([r, c], i) => {
    const bit = i < codewords.length * 8 ? ((codewords[i >> 3] >> (7 - (i & 7))) & 1) === 1 : false;
    g[r][c] = bit !== maskBit(mask, r, c);
  });
  return g;
}

/**
 * Encodes [text] (UTF-8, byte mode). Level M when it fits within version 6,
 * else L; throws when the text is too long for either — the claim payload
 * is 31 bytes, far below that.
 */
export function encodeQr(text: string, preferred: EcLevel = "M"): QrSymbol {
  const bytes = utf8Bytes(text);
  const levels: EcLevel[] = preferred === "M" ? ["M", "L"] : ["L"];
  for (const ec of levels) {
    const version = versionFor(bytes.length, ec);
    if (version === null) continue;
    const spec = SPECS[ec][version - 1];
    const codewords = interleave(toCodewords(dataBits(bytes, dataCodewords(version, ec) * 8)), spec);
    let best: { mask: number; grid: Grid; score: number } | null = null;
    for (let mask = 0; mask < MASKS.length; mask++) {
      const grid = render(version, ec, codewords, mask);
      const score = penalty(grid);
      if (!best || score < best.score) best = { mask, grid, score };
    }
    const chosen = best as { mask: number; grid: Grid; score: number };
    return { version, ecLevel: ec, mask: chosen.mask, size: chosen.grid.length, modules: chosen.grid };
  }
  throw new Error(`text too long for a version-${MAX_VERSION} QR code: ${bytes.length} bytes`);
}

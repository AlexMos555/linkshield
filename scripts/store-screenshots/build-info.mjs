/**
 * What was loaded, for the README: the build's version and git tree, and how it
 * differs from the store ZIP in dist/store-artifacts (read here with a tiny
 * ZIP reader, so nothing has to be unpacked).
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import vm from "node:vm";
import { inflateRawSync } from "node:zlib";

const SCORER_FILES = ["src/utils/scorer-data.js", "src/utils/name-rules.js", "src/utils/local-scorer.js"];

/** The offline rules of a build, as the content script runs them: host -> verdict. */
export function scorerFrom(readFile) {
  const ctx = vm.createContext({});
  for (const rel of SCORER_FILES) vm.runInContext(readFile(rel), ctx, { filename: rel });
  return (host) => ctx.localScore(host);
}

/** Every file in a ZIP (no ZIP64, stored or deflated): name -> Buffer. */
export function readZip(file) {
  const buf = readFileSync(file);
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error(`${file}: not a ZIP`);
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const out = new Map();
  for (let n = 0; n < count; n++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error(`${file}: bad central directory`);
    const method = buf.readUInt16LE(p + 10);
    const size = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28), extraLen = buf.readUInt16LE(p + 30), commentLen = buf.readUInt16LE(p + 32);
    const local = buf.readUInt32LE(p + 42);
    const name = buf.toString("utf8", p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;
    if (name.endsWith("/")) continue;
    const start = local + 30 + buf.readUInt16LE(local + 26) + buf.readUInt16LE(local + 28);
    const raw = buf.subarray(start, start + size);
    out.set(name, method === 8 ? inflateRawSync(raw) : Buffer.from(raw));
  }
  return out;
}

function listFiles(dir, base = dir) {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    return statSync(full).isDirectory() ? listFiles(full, base) : [relative(base, full).split("\\").join("/")];
  });
}

function git(root, args) {
  try {
    return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch (e) {
    return "";
  }
}

/**
 * @returns {{version, tree, dirty, zip, zipDiff, zipScore}} zip/zipDiff/zipScore are null without the ZIP.
 */
export function buildInfo(root, extDir) {
  const version = JSON.parse(readFileSync(join(extDir, "manifest.json"), "utf8")).version;
  const relExt = relative(root, extDir);
  const inRepo = relExt && !relExt.startsWith("..");
  // The build's git tree, not a commit: it names exactly these files and stays
  // the same when the branch carrying a new set of shots is rebased or
  // squash-merged, which gives the files a new commit but never a new tree.
  const tree = inRepo ? git(root, ["rev-parse", "--short", `HEAD:${relExt.split("\\").join("/")}`]) : "";
  const dirty = inRepo ? git(root, ["status", "--porcelain", "--", relExt]) !== "" : false;
  const zipPath = join(root, "dist", "store-artifacts", `cleanway-${version}-chrome.zip`);
  if (!existsSync(zipPath)) return { version, tree, dirty, zip: null, zipDiff: null, zipScore: null };
  const entries = readZip(zipPath);
  const local = new Set(listFiles(extDir));
  const zipDiff = [];
  for (const [name, data] of entries) {
    if (!local.has(name)) zipDiff.push(`${name} (only in the ZIP)`);
    else if (!readFileSync(join(extDir, name)).equals(data)) zipDiff.push(name);
    local.delete(name);
  }
  for (const name of local) if (name !== "STORE_LISTING.md") zipDiff.push(`${name} (not in the ZIP)`);
  const zipScore = scorerFrom((rel) => entries.get(rel).toString("utf8"));
  return { version, tree, dirty, zip: relative(root, zipPath), zipDiff: zipDiff.sort(), zipScore };
}

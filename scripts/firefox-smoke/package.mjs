/**
 * What the smoke test loads: the store ZIP (or an unpacked folder) as a map
 * of file name → bytes, and how it differs from extension-firefox/.
 */
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { readZip } from "../store-screenshots/build-info.mjs";

function listFiles(dir, base = dir) {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    return statSync(full).isDirectory() ? listFiles(full, base) : [relative(base, full).split("\\").join("/")];
  });
}

// scripts/build-store-artifacts.sh leaves these out of the ZIP.
const notPacked = (name) => /(^|\/)\.DS_Store$/.test(name) || name.endsWith(".md") || name.startsWith("overrides/");

const folderFiles = (dir) =>
  new Map(listFiles(dir).filter((n) => !notPacked(n)).map((n) => [n, readFileSync(join(dir, n))]));

/** {files: Map<name, Buffer>, label} of a ZIP or, with `extDir`, of a folder. */
export function readPackage(root, { zip, extDir }) {
  if (extDir) return { files: folderFiles(extDir), label: relative(root, extDir) || extDir };
  return { files: readZip(zip), label: relative(root, zip) };
}

/** Names that differ between `files` and the folder `treeDir` (what the ZIP would hold). */
export function diffWithTree(files, treeDir) {
  const tree = folderFiles(treeDir);
  const diff = [];
  for (const [name, data] of files) {
    if (!tree.has(name)) diff.push(`${name} (only in the ZIP)`);
    else if (!tree.get(name).equals(data)) diff.push(name);
    tree.delete(name);
  }
  for (const name of tree.keys()) diff.push(`${name} (not in the ZIP)`);
  return diff.sort();
}

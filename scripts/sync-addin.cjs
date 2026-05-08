#!/usr/bin/env node
// Sync email-plugin-outlook/ → landing/public/outlook/ at build time.
//
// Why a script and not a symlink: Next.js + Vercel pack `landing/public/`
// into the build output deterministically. A symlink would break across
// the dev's machine ↔ Vercel build container boundary, and in some Vercel
// configurations the symlink target is outside the Next.js root which
// gets stripped from the deploy artifact entirely.
//
// Why a copy and not committing the files in two places: single source
// of truth. The Outlook add-in is authored in `email-plugin-outlook/`
// (where Microsoft AppSource reviewers expect to see it). The
// `landing/public/outlook/` directory is build artifact, gitignored.
//
// The manifest.xml references `https://addin.cleanway.ai/outlook/...`
// so files MUST land at `landing/public/outlook/<same-relative-path>`.
// `addin.cleanway.ai` is set up in Vercel as an alias domain pointing at
// the landing project — Vercel serves /public files for ANY domain
// aliased to the project, no rewrite needed.

const fs = require("fs");
const path = require("path");

const ROOT = path.resolve(__dirname, "..");
const SRC = path.join(ROOT, "email-plugin-outlook");
const DST = path.join(ROOT, "landing", "public", "outlook");

// Files we DON'T want to ship to the public CDN. README is internal docs;
// hidden files (.DS_Store etc.) are macOS junk; node_modules shouldn't
// exist here but we guard against it.
const EXCLUDE = new Set([
  "README.md",
  "node_modules",
  ".DS_Store",
  ".git",
]);

function copyRecursive(src, dst) {
  const stat = fs.statSync(src);
  if (stat.isDirectory()) {
    if (!fs.existsSync(dst)) fs.mkdirSync(dst, { recursive: true });
    for (const entry of fs.readdirSync(src)) {
      if (EXCLUDE.has(entry)) continue;
      copyRecursive(path.join(src, entry), path.join(dst, entry));
    }
  } else if (stat.isFile()) {
    fs.copyFileSync(src, dst);
  }
}

if (!fs.existsSync(SRC)) {
  console.error(`sync-addin: source missing at ${SRC}`);
  process.exit(1);
}

// Wipe-and-replace so renames / deletes in the source dir actually take
// effect — incremental copies would leave stale files behind on the CDN.
if (fs.existsSync(DST)) {
  fs.rmSync(DST, { recursive: true });
}
copyRecursive(SRC, DST);

const fileCount = (function count(dir) {
  let n = 0;
  for (const entry of fs.readdirSync(dir)) {
    const p = path.join(dir, entry);
    n += fs.statSync(p).isDirectory() ? count(p) : 1;
  }
  return n;
})(DST);

console.log(`sync-addin: copied ${fileCount} files → ${path.relative(ROOT, DST)}`);

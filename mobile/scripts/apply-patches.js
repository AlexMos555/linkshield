#!/usr/bin/env node
/**
 * Run patch-package against whichever node_modules actually holds the packages.
 *
 * Why this exists: `mobile/` is an npm WORKSPACE, so its dependencies are
 * hoisted to the monorepo root. `patch-package` resolves `node_modules`
 * relative to its cwd, and npm runs a postinstall with cwd = the package —
 * so it looked in `mobile/node_modules/xcode`, found nothing, and failed the
 * whole `npm ci`. That took CI's mobile and openapi-drift jobs down with it.
 *
 * The build mirror (~/Library/Caches/cleanway-dev/cwmobile) is a STANDALONE
 * copy where the same packages ARE local, so the fix cannot simply hard-code
 * the parent directory: it has to look.
 *
 * Strategy: walk up from mobile/ until we find a node_modules that contains the
 * packages our patches name, then run patch-package there with --patch-dir
 * pointing back at mobile/patches. A patch whose package is missing EVERYWHERE
 * is still a hard failure — that means a dependency vanished and the patch is
 * silently doing nothing, which is exactly what we want CI to catch.
 */
const { execFileSync } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const mobileDir = path.resolve(__dirname, "..");
const patchDir = path.join(mobileDir, "patches");

if (!fs.existsSync(patchDir)) process.exit(0);

const packages = fs
  .readdirSync(patchDir)
  .filter((f) => f.endsWith(".patch"))
  // "xcode+3.0.1.patch" -> "xcode"; "@scope+pkg+1.0.0.patch" -> "@scope/pkg"
  .map((f) => {
    const base = f.replace(/\.patch$/, "");
    const parts = base.split("+");
    parts.pop(); // version
    return parts.join("/");
  });

if (packages.length === 0) process.exit(0);

/** The nearest ancestor whose node_modules holds every patched package. */
function findRoot() {
  let dir = mobileDir;
  for (;;) {
    const nm = path.join(dir, "node_modules");
    if (fs.existsSync(nm) && packages.every((p) => fs.existsSync(path.join(nm, p)))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) return null;
    dir = parent;
  }
}

const root = findRoot();

if (!root) {
  console.error(
    `\npatch-package: none of the searched node_modules contain [${packages.join(", ")}].\n` +
      `Searched upward from ${mobileDir}.\n` +
      `Either the dependency was removed (delete the stale patch in mobile/patches/)\n` +
      `or install did not complete. Not skipping silently — a patch that applies to\n` +
      `nothing is a bug, not a no-op.\n`,
  );
  process.exit(1);
}

// patch-package rejects an absolute --patch-dir, and it resolves the value
// against ITS cwd — which is the hoist root we just found, not mobile/.
const relPatchDir = path.relative(root, patchDir) || ".";

execFileSync(
  process.execPath,
  [require.resolve("patch-package/index.js"), "--patch-dir", relPatchDir],
  { cwd: root, stdio: "inherit" },
);

#!/usr/bin/env node
/**
 * The build mirror's lock still describes mobile/package.json — run with
 * `node mobile/scripts/check-mirror-lock.mjs` (CI: the mobile job; the build
 * recipes run it before `npm install` in the mirror).
 *
 * WHY
 * Store builds are made in a copy of mobile/ outside the monorepo
 * (docs/RUSTORE_SUBMISSION.md §2, docs/IOS.md §1.1), installed from
 * mobile/package-lock.json — not from the root lock, which is the only one
 * npm workspaces, CI and Dependabot update. A dependency bump in
 * mobile/package.json that does not also regenerate this file leaves the
 * mirror's lock naming the old range: `npm install` then resolves the new
 * range afresh on the day of each build, so the iPhone and the Android files
 * of one release can carry different versions nobody tested (i18next ^26.5.3
 * after #303: 26.5.7, 26.5.8 and 26.5.10 in three 1.0.6 builds), and `npm ci`
 * refuses the lock outright.
 *
 * WHAT
 * Every dependency range at the lock's root (dependencies, devDependencies,
 * optionalDependencies, peerDependencies) equals mobile/package.json's. The
 * two workspace packages are vendored in the mirror, so a "*" in the repo is
 * `file:./vendor/<name>` in the lock. Fix: regenerate the lock in the mirror
 * (docs/RUSTORE_SUBMISSION.md §2, "When mobile/package.json changes").
 *
 * `--dir <path>` checks another copy (e.g. the mirror itself, whose
 * package.json already names the vendored paths).
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const flag = process.argv.indexOf("--dir");
const dir = flag >= 0 && process.argv[flag + 1] ? resolve(process.argv[flag + 1]) : resolve(here, "..");

const SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
const VENDORED = { "@cleanway/api-client": "api-client", "@cleanway/api-types": "api-types" };

const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
const lock = JSON.parse(readFileSync(join(dir, "package-lock.json"), "utf8"));
const root = lock.packages?.[""];

const problems = [];
if (lock.lockfileVersion !== 3 || !root) {
  problems.push(`package-lock.json is not an npm lockfile v3 with a root entry (lockfileVersion ${lock.lockfileVersion})`);
} else {
  for (const section of SECTIONS) {
    const want = pkg[section] ?? {};
    const have = root[section] ?? {};
    for (const name of new Set([...Object.keys(want), ...Object.keys(have)])) {
      const expected = want[name] === "*" && VENDORED[name] ? `file:./vendor/${VENDORED[name]}` : want[name];
      if (have[name] !== expected) {
        problems.push(`${section}.${name}: package.json ${JSON.stringify(want[name])}, lock ${JSON.stringify(have[name])}`);
      }
    }
  }
}

if (problems.length) {
  console.log(`mobile/package-lock.json is out of step with package.json (${dir}):`);
  for (const p of problems) console.log(`  ${p}`);
  console.log("Regenerate it in the build mirror: docs/RUSTORE_SUBMISSION.md §2, \"When mobile/package.json changes\".");
  process.exit(1);
}
console.log(`ok: the mirror lock's ${SECTIONS.filter((s) => pkg[s]).map((s) => Object.keys(pkg[s]).length + " " + s).join(", ")} match package.json`);

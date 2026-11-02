#!/usr/bin/env node
/**
 * The build mirror's lock still describes mobile/package.json, and resolves the
 * same versions CI tests — run with `node mobile/scripts/check-mirror-lock.mjs`
 * (CI: the mobile job; the build recipes run it before `npm install` in the
 * mirror). Table test: scripts/test-check-mirror-lock.mjs.
 *
 * WHY
 * Store builds are made in a copy of mobile/ outside the monorepo
 * (docs/RUSTORE_SUBMISSION.md §2, docs/IOS.md §1.1), installed from
 * mobile/package-lock.json. CI's `npm ci` installs the root package-lock.json
 * instead, which is the one npm workspaces and Dependabot's version updates
 * change. Two ways the two drift apart:
 *   - a dependency bump in mobile/package.json that does not also regenerate
 *     this file leaves the mirror's lock naming the old range: `npm install`
 *     then resolves the new range afresh on the day of each build, so the
 *     iPhone and the Android files of one release can carry different versions
 *     nobody tested (i18next ^26.5.3 after #303: 26.5.7, 26.5.8 and 26.5.10 in
 *     three 1.0.6 builds), and `npm ci` refuses the lock outright;
 *   - equal ranges, different releases: the mirror locked i18next 26.5.10
 *     while CI kept testing the root lock's 26.5.3.
 * And Dependabot's *security* updates do open PRs against this file (#329,
 * undici): it regenerates the lock outside the mirror, so the vendored entries
 * come out as "*". Such a PR is closed, and the bump made in the mirror.
 *
 * WHAT
 *   1. Every dependency range at the lock's root (dependencies,
 *      devDependencies, optionalDependencies, peerDependencies) equals
 *      mobile/package.json's. The two workspace packages are vendored in the
 *      mirror, so a "*" in the repo is `file:./vendor/<name>` in the lock.
 *   2. Every direct dependency (not the vendored two) resolves to the same
 *      version here as in the root lock, looked up the way Node resolves it
 *      from mobile/: mobile/node_modules/<name>, else node_modules/<name>.
 * Fix: regenerate the lock in the mirror (docs/RUSTORE_SUBMISSION.md §2, "When
 * mobile/package.json changes").
 *
 * `--dir <path>` checks another copy (e.g. the mirror itself, whose
 * package.json already names the vendored paths). `--root-lock <path>` names
 * the monorepo lock (default: the one next to this script's repo — so run the
 * repo's copy of this script, not the mirror's).
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && process.argv[i + 1] ? resolve(process.argv[i + 1]) : fallback;
}
const dir = arg("--dir", resolve(here, ".."));
const rootLockPath = arg("--root-lock", resolve(here, "../../package-lock.json"));

const SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
const INSTALLED = ["dependencies", "devDependencies", "optionalDependencies"];
const VENDORED = { "@cleanway/api-client": "api-client", "@cleanway/api-types": "api-types" };
const WORKSPACE = "mobile";

const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
const lock = JSON.parse(readFileSync(join(dir, "package-lock.json"), "utf8"));
const root = lock.packages?.[""];

const problems = [];
const hints = new Set();
if (lock.lockfileVersion !== 3 || !root) {
  problems.push(`package-lock.json is not an npm lockfile v3 with a root entry (lockfileVersion ${lock.lockfileVersion})`);
} else {
  for (const section of SECTIONS) {
    const want = pkg[section] ?? {};
    const have = root[section] ?? {};
    for (const name of new Set([...Object.keys(want), ...Object.keys(have)])) {
      const vendored = want[name] === "*" && VENDORED[name];
      const expected = vendored ? `file:./vendor/${VENDORED[name]}` : want[name];
      if (have[name] === expected) continue;
      const via = vendored ? ` (package.json ${JSON.stringify(want[name])}: vendored in the mirror)` : "";
      const told = vendored ? "" : `, package.json ${JSON.stringify(want[name])}`;
      problems.push(`${section}.${name}: lock has ${JSON.stringify(have[name])}${vendored ? `, expected ${JSON.stringify(expected)}${via}` : told}`);
      if (VENDORED[name] && have[name] === "*") {
        hints.add(
          "The vendored entries say \"*\": this lock was regenerated outside the mirror — a Dependabot " +
            "security PR on mobile/package-lock.json does that. Do not merge it: close it and make the same " +
            "bump in the mirror (`npm update <name> --package-lock-only --ignore-scripts`, then copy the lock back).",
        );
      }
    }
  }

  let rootLock = null;
  try {
    rootLock = JSON.parse(readFileSync(rootLockPath, "utf8"));
  } catch (e) {
    problems.push(`cannot read the root package-lock.json at ${rootLockPath} (${e.code ?? e.message}): run the repo's copy of this script, or pass --root-lock`);
  }
  if (rootLock) {
    const rp = rootLock.packages ?? {};
    for (const section of INSTALLED) {
      for (const name of Object.keys(pkg[section] ?? {})) {
        if (VENDORED[name]) continue;
        const mine = lock.packages[`node_modules/${name}`]?.version;
        const ci = (rp[`${WORKSPACE}/node_modules/${name}`] ?? rp[`node_modules/${name}`])?.version;
        if (mine !== ci) {
          problems.push(`${name}: mirror lock ${mine ?? "(none)"}, root package-lock.json ${ci ?? "(none)"}`);
          hints.add(
            "Resolved versions differ, so what CI tests is not what the store builds ship. Bring the older " +
              "lock up to the newer release: `npm update <name> --package-lock-only --ignore-scripts` at the repo " +
              "root or in the mirror (docs/RUSTORE_SUBMISSION.md §2).",
          );
        }
      }
    }
  }
}

if (problems.length) {
  console.log(`mobile/package-lock.json is out of step (${dir}):`);
  for (const p of problems) console.log(`  ${p}`);
  for (const h of hints) console.log(h);
  console.log("Regenerate it in the build mirror: docs/RUSTORE_SUBMISSION.md §2, \"When mobile/package.json changes\".");
  process.exit(1);
}
const counts = SECTIONS.filter((s) => pkg[s]).map((s) => `${Object.keys(pkg[s]).length} ${s}`).join(", ");
console.log(`ok: the mirror lock's ${counts} match package.json, at the root lock's versions`);

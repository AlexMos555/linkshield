#!/usr/bin/env node
/**
 * Table test for scripts/check-mirror-lock.mjs — run with
 * `node mobile/scripts/test-check-mirror-lock.mjs`.
 *
 * Each case writes a tiny mobile/package.json, mirror lock and root lock into a
 * temp dir and runs the check on them as CI does. Three of the rows are what
 * went wrong before the check existed or slipped past its first version:
 *   - #303 bumped i18next in package.json and the root lock only, so every
 *     store build resolved the new range afresh (26.5.7, 26.5.8, 26.5.10);
 *   - the mirror lock then said 26.5.10 while the root lock — what CI's npm ci
 *     installs and #303 tested — said 26.5.3; equal ranges hid the gap;
 *   - Dependabot security PR #329 regenerated mobile/package-lock.json outside
 *     the mirror and rewrote the vendored entries to "*", and the message did
 *     not say what the lock should have held instead.
 */
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const script = resolve(here, "check-mirror-lock.mjs");
const tmp = mkdtempSync(join(tmpdir(), "cleanway-mirror-lock-"));

const PKG = {
  name: "cleanway-mobile",
  dependencies: { "@cleanway/api-client": "*", i18next: "^26.5.3", expo: "~54.0.37" },
  devDependencies: { typescript: "~5.9.2" },
};

function mirrorLock({ client = "file:./vendor/api-client", i18nextRange = "^26.5.3", i18next = "26.5.10", lockfileVersion = 3 } = {}) {
  return {
    name: "cleanway-mobile",
    lockfileVersion,
    packages: {
      "": {
        name: "cleanway-mobile",
        dependencies: { "@cleanway/api-client": client, i18next: i18nextRange, expo: "~54.0.37" },
        devDependencies: { typescript: "~5.9.2" },
      },
      "node_modules/@cleanway/api-client": { resolved: "vendor/api-client", link: true },
      "node_modules/i18next": { version: i18next },
      "node_modules/expo": { version: "54.0.37" },
      "node_modules/typescript": { version: "5.9.3" },
    },
  };
}

// The monorepo lock: workspace deps are hoisted to node_modules/ unless another
// workspace wants a different version, then they sit in mobile/node_modules/.
function rootLock({ i18next = "26.5.10", nestedExpo = null } = {}) {
  const packages = {
    "": { name: "cleanway", workspaces: ["mobile"] },
    mobile: { name: "cleanway-mobile", dependencies: PKG.dependencies, devDependencies: PKG.devDependencies },
    "node_modules/@cleanway/api-client": { resolved: "packages/api-client", link: true },
    "node_modules/i18next": { version: i18next },
    "node_modules/expo": { version: nestedExpo ? "53.0.0" : "54.0.37" },
    "node_modules/typescript": { version: "5.9.3" },
  };
  if (nestedExpo) packages["mobile/node_modules/expo"] = { version: nestedExpo };
  return { name: "cleanway", lockfileVersion: 3, packages };
}

let n = 0;
function run({ pkg = PKG, mirror = mirrorLock(), root = rootLock() } = {}) {
  const dir = join(tmp, `case-${++n}`);
  mkdirSync(dir);
  writeFileSync(join(dir, "package.json"), JSON.stringify(pkg));
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify(mirror));
  const args = [script, "--dir", dir];
  if (root !== null) {
    writeFileSync(join(dir, "root-lock.json"), JSON.stringify(root));
    args.push("--root-lock", join(dir, "root-lock.json"));
  } else {
    args.push("--root-lock", join(dir, "missing-root-lock.json"));
  }
  const r = spawnSync(process.execPath, args, { encoding: "utf8" });
  return { code: r.status, out: `${r.stdout}${r.stderr}` };
}

const CASES = [
  ["in step: ranges and resolved versions match", {}, 0, [/^ok: /m]],
  ["a hoisted root entry is found in mobile/node_modules/ first", { root: rootLock({ nestedExpo: "54.0.37" }) }, 0, [/^ok: /m]],
  [
    "#303: package.json range bumped, mirror lock not regenerated",
    { mirror: mirrorLock({ i18nextRange: "^23.15.0", i18next: "23.16.8" }), root: rootLock() },
    1,
    [/dependencies\.i18next: lock has "\^23\.15\.0", package\.json "\^26\.5\.3"/, /i18next: mirror lock 23\.16\.8, root package-lock\.json 26\.5\.10/],
  ],
  [
    "same range, different release: mirror 26.5.10, root (CI) 26.5.3",
    { root: rootLock({ i18next: "26.5.3" }) },
    1,
    [/i18next: mirror lock 26\.5\.10, root package-lock\.json 26\.5\.3/, /what CI tests is not what the store builds ship/],
  ],
  [
    "#329: a security PR regenerated the lock outside the mirror (vendored entry \"*\")",
    { mirror: mirrorLock({ client: "*" }) },
    1,
    [/@cleanway\/api-client: lock has "\*", expected "file:\.\/vendor\/api-client"/, /regenerated outside the mirror/],
  ],
  ["not a v3 lock", { mirror: mirrorLock({ lockfileVersion: 2 }) }, 1, [/not an npm lockfile v3/]],
  ["no root lock to compare with: STOP, not a silent pass", { root: null }, 1, [/cannot read the root package-lock\.json/]],
];

let failed = 0;
try {
  for (const [name, input, wantCode, patterns] of CASES) {
    const { code, out } = run(input);
    const missing = patterns.filter((p) => !p.test(out));
    const ok = code === wantCode && missing.length === 0;
    if (!ok) failed++;
    console.log(`${ok ? "  ok  " : "  FAIL"}  ${name}`);
    if (!ok) {
      console.log(`        exit ${code} (want ${wantCode}); missing ${missing.map(String).join(", ") || "nothing"}`);
      console.log(out.replace(/^/gm, "        | "));
    }
  }
  // The real files: what CI's "Build mirror lock matches mobile/package.json" runs.
  const real = spawnSync(process.execPath, [script], { encoding: "utf8" });
  const ok = real.status === 0;
  if (!ok) failed++;
  console.log(`${ok ? "  ok  " : "  FAIL"}  this repo's mobile/package-lock.json and package-lock.json`);
  if (!ok) console.log(`${real.stdout}${real.stderr}`.replace(/^/gm, "        | "));
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

console.log(failed === 0 ? `\nall ${CASES.length + 1} cases pass` : `\n${failed} FAILED`);
process.exit(failed === 0 ? 0 : 1);

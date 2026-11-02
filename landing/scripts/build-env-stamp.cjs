#!/usr/bin/env node
// The stamp of the NEXT_PUBLIC_* variables a landing build inlines, so the
// Vercel ignore step (scripts/vercel-ignore.sh) can tell an environment change
// from a push that changed nothing.
//
// Next.js copies every NEXT_PUBLIC_* value into the bundles at build time:
// NEXT_PUBLIC_STRIPE_LIVE, NEXT_PUBLIC_BILLING_ENABLED, the APK URL reach the
// site only through a new build. The runbooks apply them with a dashboard
// Redeploy, and Vercel runs the ignore step on a Redeploy too, with nothing
// that tells it from a push: VERCEL_GIT_PREVIOUS_SHA is still the last
// successful deployment. Redeploying a push the step had canceled compared the
// same two commits and canceled again, so the change never reached the site.
// Now every build publishes this stamp at /build-env.txt, and the ignore step
// builds whenever its own variables differ from the live site's.
//
// The stamp is a SHA-256 over the names and values, never the values: they
// are public anyway (they are in the JavaScript every visitor downloads), but
// the stamp has no need to repeat them. NEXT_PUBLIC_VERCEL_* are left out:
// Vercel sets them per deployment (URL, commit, deployment id), so with them
// no two builds would ever match.
//
//   node scripts/build-env-stamp.cjs --print            the stamp of this environment
//   node scripts/build-env-stamp.cjs --write FILE       write it to FILE (landing's prebuild)
//   node scripts/build-env-stamp.cjs --compare BASE     fetch BASE/build-env.txt and compare
//
// --compare prints one line saying what it found and exits 0 when the stamps
// match, 1 when they differ, 2 when the live one cannot be read. BASE is
// a bare host as Vercel gives it (VERCEL_PROJECT_PRODUCTION_URL) or a URL.
//
// Tested by landing/e2e/vercel-ignore.spec.ts.

const crypto = require("node:crypto");
const fs = require("node:fs");

const PREFIX = "NEXT_PUBLIC_";
const VERCEL_SET = "NEXT_PUBLIC_VERCEL_";
// Served from landing/public/, outside the locale middleware (a dotted path).
const STAMP_PATH = "build-env.txt";
const FETCH_TIMEOUT_MS = 10_000;

function stampOf(env) {
  const entries = Object.keys(env)
    .filter((name) => name.startsWith(PREFIX) && !name.startsWith(VERCEL_SET))
    .sort()
    .map((name) => [name, env[name]]);
  const digest = crypto.createHash("sha256").update(JSON.stringify(entries)).digest("hex");
  return `v1 ${entries.length} ${digest}`;
}

/** The stamp's URL under `base`, or null when `base` is not a usable host or URL. */
function stampUrl(base) {
  const value = (base || "").trim();
  if (!value) return null;
  try {
    const url = new URL(/^https?:\/\//i.test(value) ? value : `https://${value}`);
    if (url.username || url.password || url.search || url.hash) return null;
    if (!/^[a-z0-9.-]+$/i.test(url.hostname)) return null;
    url.pathname = `${url.pathname.replace(/\/+$/, "")}/${STAMP_PATH}`;
    return url;
  } catch {
    return null;
  }
}

function count(stamp) {
  const match = /^v1 (\d+) [0-9a-f]{64}$/.exec(stamp);
  return match ? Number(match[1]) : null;
}

async function compare(base) {
  const url = stampUrl(base);
  if (!url) return [2, `there is no live site to compare its NEXT_PUBLIC_* variables with (URL "${base || ""}")`];
  let live;
  try {
    const response = await fetch(url, { cache: "no-store", redirect: "follow", signal: AbortSignal.timeout(FETCH_TIMEOUT_MS) });
    if (!response.ok) return [2, `the live site's NEXT_PUBLIC_* stamp could not be read (${url.host}: HTTP ${response.status})`];
    live = (await response.text()).trim();
  } catch (error) {
    const reason = error && error.name === "TimeoutError" ? "timed out" : "unreachable";
    return [2, `the live site's NEXT_PUBLIC_* stamp could not be read (${url.host}: ${reason})`];
  }
  const ours = stampOf(process.env);
  if (count(live) === null) return [2, `the live site's NEXT_PUBLIC_* stamp is not one (${url.host})`];
  if (live !== ours) {
    return [1, `NEXT_PUBLIC_* variables differ from the live site's (${count(ours)} here, ${count(live)} there): an environment change to build`];
  }
  return [0, `NEXT_PUBLIC_* variables match the live site's (${count(ours)})`];
}

async function main(argv) {
  const [mode, arg] = argv;
  if (mode === "--print" && arg === undefined) {
    process.stdout.write(`${stampOf(process.env)}\n`);
    return 0;
  }
  if (mode === "--write" && arg) {
    fs.writeFileSync(arg, `${stampOf(process.env)}\n`);
    process.stdout.write(`build-env-stamp: wrote ${arg} (${count(stampOf(process.env))} NEXT_PUBLIC_* variables)\n`);
    return 0;
  }
  if (mode === "--compare" && arg !== undefined) {
    const [code, line] = await compare(arg);
    process.stdout.write(`${line}\n`);
    return code;
  }
  process.stderr.write("usage: build-env-stamp.cjs --print | --write FILE | --compare BASE\n");
  return 2;
}

if (require.main === module) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (error) => {
      process.stdout.write(`the NEXT_PUBLIC_* comparison failed (${error && error.name})\n`);
      process.exit(2);
    },
  );
}

module.exports = { stampOf, stampUrl, STAMP_PATH };

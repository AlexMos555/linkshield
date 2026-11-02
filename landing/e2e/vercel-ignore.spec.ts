import { execFileSync, spawn, spawnSync, type ChildProcess } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test, expect } from "@playwright/test";

/**
 * landing/scripts/vercel-ignore.sh tells Vercel whether a push needs a landing
 * build (exit 1) or not (exit 0). A wrong "skip" on main would leave the live
 * site behind its code, so every case runs the real script against a real git
 * repository shaped like the clone Vercel makes (shallow, one branch).
 *
 * No browser is involved; the spec sits here so the landing e2e job runs it.
 * On its own (BASE_URL turns off the dev server):
 *   cd landing && BASE_URL=http://127.0.0.1:9 npx playwright test e2e/vercel-ignore.spec.ts --project=chromium
 */

const SCRIPT = join(__dirname, "..", "scripts", "vercel-ignore.sh");
const STAMP = join(__dirname, "..", "scripts", "build-env-stamp.cjs");
const VERCEL_JSON = join(__dirname, "..", "vercel.json");
const LANDING_PACKAGE = join(__dirname, "..", "package.json");
const LANDING_GITIGNORE = join(__dirname, "..", ".gitignore");
const REPO_ROOT = join(__dirname, "..", "..");

/**
 * Stands in for the live site, which publishes the stamp of the NEXT_PUBLIC_*
 * variables it was built with (build-env.txt): serves the files of the
 * directory in argv[1]. A process of its own, because the script runs under
 * spawnSync, which blocks this one.
 */
const LIVE_SITE_SERVER = `
const http = require("node:http"), fs = require("node:fs"), path = require("node:path");
const root = process.argv[1];
http.createServer((req, res) => {
  const file = path.join(root, decodeURIComponent(new URL(req.url, "http://x").pathname));
  fs.readFile(file.startsWith(root + path.sep) ? file : root, (err, body) => {
    res.writeHead(err ? 404 : 200, { "content-type": "text/plain" });
    res.end(err ? "not found" : body);
  });
}).listen(0, "127.0.0.1", function () { console.log("http://127.0.0.1:" + this.address().port); });
`;

// Set up in beforeAll, so listing the tests creates no temporary directory.
let sandbox = "";
let GIT_ENV: NodeJS.ProcessEnv = { NODE_ENV: "test" };
let www = "";
let liveOrigin = "";
let liveServer: ChildProcess | null = null;

test.beforeAll(async () => {
  sandbox = realpathSync(mkdtempSync(join(tmpdir(), "vercel-ignore-")));
  www = join(sandbox, "www");
  mkdirSync(www);
  const server = spawn(process.execPath, ["-e", LIVE_SITE_SERVER, www], { stdio: ["ignore", "pipe", "inherit"] });
  liveServer = server;
  liveOrigin = await new Promise<string>((resolve, reject) => {
    server.stdout?.once("data", (line) => resolve(String(line).trim()));
    server.once("exit", (code) => reject(new Error(`the live-site stand-in exited with ${code}`)));
  });
  const emptyGitConfig = join(sandbox, "gitconfig");
  writeFileSync(emptyGitConfig, "");
  // Git with none of this machine's config (signing, hooks, default branch),
  // and unable to wander out of the sandbox into a repository above it.
  GIT_ENV = {
    NODE_ENV: "test",
    PATH: process.env.PATH ?? "/usr/bin:/bin",
    HOME: sandbox,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: emptyGitConfig,
    GIT_CEILING_DIRECTORIES: sandbox,
    GIT_AUTHOR_NAME: "e2e",
    GIT_AUTHOR_EMAIL: "e2e@example.invalid",
    GIT_COMMITTER_NAME: "e2e",
    GIT_COMMITTER_EMAIL: "e2e@example.invalid",
  };
});

test.afterAll(() => {
  liveServer?.kill();
  if (sandbox) rmSync(sandbox, { recursive: true, force: true });
});

/** One file per area of the monorepo, so a case can touch exactly one. */
const REPO_FILES: Record<string, string> = {
  "landing/app/page.tsx": "export default function Page() {}\n",
  "landing/vercel.json": "{}\n",
  "landing/messages/en.json": "{}\n",
  "landing/e2e/home.spec.ts": "// e2e\n",
  "packages/api-client/src/index.ts": "export {};\n",
  "packages/api-types/src/index.ts": "export {};\n",
  "packages/email-templates/package.json": "{}\n",
  "packages/email-templates/src/index.ts": "export {};\n",
  "packages/extension-core/src/index.js": "// extension\n",
  "packages/i18n-strings/src/en.json": "{}\n",
  "package.json": "{}\n",
  "package-lock.json": "{}\n",
  ".npmrc": "legacy-peer-deps=true\n",
  "mobile/package.json": "{}\n",
  "mobile/app/index.tsx": "// app\n",
  "mobile/patches/xcode+3.0.1.patch": "diff --git a/x b/x\n",
  "mobile/scripts/apply-patches.js": "// postinstall\n",
  "mobile/scripts/test-freemium.mjs": "// test\n",
  "scripts/sync-addin.cjs": "// sync\n",
  "scripts/build-i18n.py": "# i18n\n",
  "email-plugin-outlook/manifest.xml": "<OfficeApp/>\n",
  // docs/benchmarks/latest.json is a symlink to the first of these
  // (LATEST_TARGET), made by newOrigin: as in the repository.
  "docs/benchmarks/2026-10-18-fresh-urls.json": "{}\n",
  "docs/benchmarks/2026-10-11-fresh-urls.json": "{}\n",
  "docs/ROADMAP.md": "# roadmap\n",
  "api/main.py": "# api\n",
  "ml/train.py": "# ml\n",
  "extension/manifest.json": "{}\n",
  ".github/workflows/ci.yml": "# ci\n",
  ".gitignore": "node_modules\n",
};

/** Files `npm install` + `next build` read for the landing: a change must build. */
const LANDING_INPUTS = [
  "landing/app/page.tsx",
  "landing/vercel.json",
  "landing/messages/en.json",
  "landing/e2e/home.spec.ts",
  "packages/api-client/src/index.ts",
  "packages/api-types/src/index.ts",
  "packages/email-templates/package.json",
  "package.json",
  "package-lock.json",
  ".npmrc",
  "mobile/package.json",
  // mobile's postinstall, run by the same root install, patches packages in
  // the shared node_modules the site is built from.
  "mobile/patches/xcode+3.0.1.patch",
  "mobile/scripts/apply-patches.js",
  "scripts/sync-addin.cjs",
  "email-plugin-outlook/manifest.xml",
  // The report latest.json points to: lib/benchmark.ts reads it through the link.
  "docs/benchmarks/2026-10-18-fresh-urls.json",
  ".gitignore",
];

/** Files the landing build never reads: a change alone must skip. */
const NOT_LANDING_INPUTS = [
  "api/main.py",
  "ml/train.py",
  "extension/manifest.json",
  "packages/extension-core/src/index.js",
  "packages/i18n-strings/src/en.json",
  "packages/email-templates/src/index.ts",
  "mobile/app/index.tsx",
  "mobile/scripts/test-freemium.mjs",
  "scripts/build-i18n.py",
  "docs/ROADMAP.md",
  // An older report: latest.json does not point to it.
  "docs/benchmarks/2026-10-11-fresh-urls.json",
  ".github/workflows/ci.yml",
];

const LATEST = "docs/benchmarks/latest.json";
const LATEST_TARGET = "2026-10-18-fresh-urls.json";

let counter = 0;

function git(cwd: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd, env: GIT_ENV, encoding: "utf-8" }).trim();
}

function write(dir: string, files: Record<string, string>): void {
  for (const [file, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, file)), { recursive: true });
    writeFileSync(join(dir, file), content);
  }
}

function commit(dir: string, message: string, files: Record<string, string> = {}): string {
  write(dir, files);
  git(dir, "add", "--all");
  git(dir, "commit", "--quiet", "--allow-empty", "-m", message);
  return git(dir, "rev-parse", "HEAD");
}

/** Points docs/benchmarks/latest.json at `target`, as the benchmark script does. */
function pointLatestAt(dir: string, target: string): void {
  const link = join(dir, LATEST);
  rmSync(link, { force: true });
  symlinkSync(target, link);
}

/** Stands in for GitHub: a repository on `main` with every area committed once. */
function newOrigin(): { dir: string; base: string } {
  const dir = join(sandbox, `origin-${++counter}`);
  mkdirSync(dir);
  git(dir, "init", "--quiet", "--initial-branch=main");
  // GitHub serves a commit by its SHA; a plain local repository refuses to.
  git(dir, "config", "uploadpack.allowAnySHA1InWant", "true");
  write(dir, REPO_FILES);
  pointLatestAt(dir, LATEST_TARGET);
  return { dir, base: commit(dir, "base") };
}

/** The stamp build-env-stamp.cjs gives a build with these variables. */
function stampOf(env: Record<string, string>): string {
  const run = spawnSync(process.execPath, [STAMP, "--print"], { env: Object.assign({}, GIT_ENV, env), encoding: "utf-8" });
  expect(run.status, run.stderr).toBe(0);
  return run.stdout.trim();
}

/**
 * A live site built with these NEXT_PUBLIC_* variables, as the base URL the
 * script is given (VERCEL_PROJECT_PRODUCTION_URL, VERCEL_BRANCH_URL). The
 * stand-in serves http, so its URL carries a scheme; Vercel's is a bare host.
 * `stamp: null` is a site that publishes none (built before the stamp existed).
 */
function liveSite(env: Record<string, string>, stamp: string | null = stampOf(env)): string {
  const dir = `site-${++counter}`;
  mkdirSync(join(www, dir));
  if (stamp !== null) writeFileSync(join(www, dir, "build-env.txt"), `${stamp}\n`);
  return `${liveOrigin}/${dir}`;
}

/** Vercel's checkout of one branch: shallow (10 commits), that branch only. */
function vercelClone(origin: string, branch = "main"): string {
  const dir = join(sandbox, `clone-${++counter}`);
  git(sandbox, "clone", "--quiet", "--depth=10", "--branch", branch, `file://${origin}`, dir);
  return dir;
}

function hasCommit(dir: string, sha: string): boolean {
  return spawnSync("git", ["cat-file", "-e", `${sha}^{commit}`], { cwd: dir, env: GIT_ENV }).status === 0;
}

/**
 * Runs the script the way Vercel does: from the Root Directory (landing/).
 * Unless a case says otherwise, the live site (at the production and the
 * branch URL) was built with the same NEXT_PUBLIC_* variables as this build.
 */
function ignoreStep(checkout: string, env: Record<string, string>): { code: number | null; out: string } {
  const live = liveSite(env);
  const run = spawnSync("sh", [SCRIPT], {
    cwd: join(checkout, "landing"),
    env: Object.assign({}, GIT_ENV, { VERCEL_PROJECT_PRODUCTION_URL: live, VERCEL_BRANCH_URL: live }, env),
    encoding: "utf-8",
  });
  const out = `${run.stdout}${run.stderr}`.trim();
  // Vercel reads only the exit code; the one line is for whoever opens the log.
  expect(out.split("\n"), out).toHaveLength(1);
  expect(out).toMatch(/^vercel-ignore: (BUILD|SKIP) - /);
  return { code: run.status, out };
}

const BUILD = 1;
const SKIP = 0;

test.describe("Vercel ignored build step (landing/scripts/vercel-ignore.sh)", () => {
  test("production: the first deployment builds, there is nothing to compare with", () => {
    const { dir } = newOrigin();
    const run = ignoreStep(vercelClone(dir), { VERCEL_ENV: "production", VERCEL_GIT_PREVIOUS_SHA: "" });
    expect(run.code, run.out).toBe(BUILD);
    expect(run.out).toContain("no previous successful deployment");
  });

  test("with no VERCEL_ENV at all it is treated as production and builds", () => {
    const { dir } = newOrigin();
    const run = ignoreStep(vercelClone(dir), {});
    expect(run.code, run.out).toBe(BUILD);
  });

  test("a redeploy of the last successful commit builds", () => {
    const { dir, base } = newOrigin();
    const run = ignoreStep(vercelClone(dir), { VERCEL_ENV: "production", VERCEL_GIT_PREVIOUS_SHA: base });
    expect(run.code, run.out).toBe(BUILD);
    expect(run.out).toContain("redeploy");
  });

  // NEXT_PUBLIC_* is inlined at build time: flipping NEXT_PUBLIC_STRIPE_LIVE,
  // NEXT_PUBLIC_BILLING_ENABLED or the APK URL reaches the site only through
  // a new build. Vercel's Redeploy runs this step too, and gives it nothing
  // that tells it from a push (VERCEL_GIT_PREVIOUS_SHA is still the last
  // successful deployment). Redeploying the newest row, a push this step
  // canceled, compared the same two commits and canceled again.
  test("a Redeploy of a canceled push that applies a changed NEXT_PUBLIC_* variable builds", () => {
    const { dir, base } = newOrigin();
    commit(dir, "api only, canceled", { "api/main.py": "# later\n" });
    const clone = vercelClone(dir);
    const live = liveSite({ NEXT_PUBLIC_API_URL: "https://api.cleanway.ai" });
    const changes: Record<string, string>[] = [
      { NEXT_PUBLIC_API_URL: "https://api.cleanway.ai", NEXT_PUBLIC_STRIPE_LIVE: "1" }, // a flag switched on
      { NEXT_PUBLIC_API_URL: "https://api.cleanway.ai/v2" }, // a value changed
      {}, // a variable removed
    ];
    for (const changed of changes) {
      const run = ignoreStep(clone, {
        VERCEL_ENV: "production",
        VERCEL_GIT_PREVIOUS_SHA: base,
        VERCEL_PROJECT_PRODUCTION_URL: live,
        ...changed,
      });
      expect(run.code, `${JSON.stringify(changed)}: ${run.out}`).toBe(BUILD);
      expect(run.out).toContain("NEXT_PUBLIC_");
    }
  });

  test("with the live site's NEXT_PUBLIC_* values it still skips; Vercel's own NEXT_PUBLIC_VERCEL_* do not count", () => {
    const { dir, base } = newOrigin();
    commit(dir, "api only", { "api/main.py": "# later\n" });
    const clone = vercelClone(dir);
    const live = liveSite({ NEXT_PUBLIC_STRIPE_LIVE: "1", NEXT_PUBLIC_VERCEL_URL: "cleanway-abc.vercel.app" });
    const run = ignoreStep(clone, {
      VERCEL_ENV: "production",
      VERCEL_GIT_PREVIOUS_SHA: base,
      VERCEL_PROJECT_PRODUCTION_URL: live,
      NEXT_PUBLIC_STRIPE_LIVE: "1",
      NEXT_PUBLIC_VERCEL_URL: "cleanway-def.vercel.app",
    });
    expect(run.code, run.out).toBe(SKIP);
    expect(run.out).toContain("Use project's Ignore Build Step");
  });

  test("builds when the live site's variables cannot be read", () => {
    const { dir, base } = newOrigin();
    commit(dir, "api only", { "api/main.py": "# later\n" });
    const clone = vercelClone(dir);
    for (const live of [
      liveSite({}, null), // built before the stamp existed: 404
      "http://127.0.0.1:9", // nothing listens
      "", // no production URL
      "not a host/../x",
    ]) {
      const run = ignoreStep(clone, {
        VERCEL_ENV: "production",
        VERCEL_GIT_PREVIOUS_SHA: base,
        VERCEL_PROJECT_PRODUCTION_URL: live,
      });
      expect(run.code, `${live}: ${run.out}`).toBe(BUILD);
    }
  });

  test("preview: compares the variables with the branch's last deployment, or with production when it has none", () => {
    const { dir } = newOrigin();
    git(dir, "checkout", "--quiet", "-b", "landing-then-ml");
    const built = commit(dir, "landing", { "landing/app/page.tsx": "preview me\n" });
    commit(dir, "ml", { "ml/train.py": "# new model\n" });
    const clone = vercelClone(dir, "landing-then-ml");
    const same = liveSite({});
    const other = liveSite({ NEXT_PUBLIC_STRIPE_LIVE: "1" });
    const deployed = { VERCEL_ENV: "preview", VERCEL_GIT_PREVIOUS_SHA: built };
    expect(ignoreStep(clone, { ...deployed, VERCEL_BRANCH_URL: same, VERCEL_PROJECT_PRODUCTION_URL: other }).code).toBe(SKIP);
    expect(ignoreStep(clone, { ...deployed, VERCEL_BRANCH_URL: other, VERCEL_PROJECT_PRODUCTION_URL: same }).code).toBe(BUILD);

    git(dir, "checkout", "--quiet", "main");
    git(dir, "checkout", "--quiet", "-b", "ml-only");
    commit(dir, "ml", { "ml/train.py": "# another model\n" });
    const first = { VERCEL_ENV: "preview", VERCEL_GIT_PREVIOUS_SHA: "" };
    const mlClone = vercelClone(dir, "ml-only");
    expect(ignoreStep(mlClone, { ...first, VERCEL_BRANCH_URL: other, VERCEL_PROJECT_PRODUCTION_URL: same }).code).toBe(SKIP);
    expect(ignoreStep(mlClone, { ...first, VERCEL_BRANCH_URL: same, VERCEL_PROJECT_PRODUCTION_URL: other }).code).toBe(BUILD);
  });

  test("a redeploy of the last successful commit builds without asking the live site", () => {
    const { dir, base } = newOrigin();
    const run = ignoreStep(vercelClone(dir), {
      VERCEL_ENV: "production",
      VERCEL_GIT_PREVIOUS_SHA: base,
      VERCEL_PROJECT_PRODUCTION_URL: "",
    });
    expect(run.code, run.out).toBe(BUILD);
    expect(run.out).toContain("redeploy");
  });

  test("every file the landing build reads triggers a build when it changes", () => {
    const { dir, base } = newOrigin();
    const skipped: string[] = [];
    for (const [i, file] of LANDING_INPUTS.entries()) {
      git(dir, "checkout", "--quiet", "-b", `landing-${i}`, base);
      commit(dir, `touch ${file}`, { [file]: `changed ${i}\n` });
      const run = ignoreStep(dir, { VERCEL_ENV: "production", VERCEL_GIT_PREVIOUS_SHA: base });
      if (run.code !== BUILD) skipped.push(`${file}: ${run.out}`);
    }
    expect(skipped).toEqual([]);
  });

  test("deleting a landing file triggers a build", () => {
    const { dir, base } = newOrigin();
    unlinkSync(join(dir, "landing/e2e/home.spec.ts"));
    commit(dir, "delete a spec");
    const run = ignoreStep(dir, { VERCEL_ENV: "production", VERCEL_GIT_PREVIOUS_SHA: base });
    expect(run.code, run.out).toBe(BUILD);
  });

  // docs/benchmarks/latest.json is a symlink, and git compares a symlink by
  // the name it holds. The site reads the report through it: a same-day rerun
  // that rewrote the report in place changed the numbers the site shows,
  // while latest.json itself stayed byte for byte the same.
  test("the fixture's latest.json is a symlink, as the repository's is", () => {
    const { dir } = newOrigin();
    expect(git(dir, "ls-files", "-s", LATEST)).toMatch(/^120000 /);
    expect(git(REPO_ROOT, "ls-files", "-s", LATEST)).toMatch(/^120000 /);
  });

  test("a rewrite of the report latest.json points to builds", () => {
    const { dir, base } = newOrigin();
    commit(dir, "rerun the same day", { [`docs/benchmarks/${LATEST_TARGET}`]: '{"recall": 0.41}\n' });
    expect(git(dir, "diff", "--name-only", base, "HEAD", "--", LATEST)).toBe("");
    const run = ignoreStep(vercelClone(dir), { VERCEL_ENV: "production", VERCEL_GIT_PREVIOUS_SHA: base });
    expect(run.code, run.out).toBe(BUILD);
    expect(run.out).toContain("1 landing file(s) changed");
  });

  test("pointing latest.json at another report builds", () => {
    const { dir, base } = newOrigin();
    pointLatestAt(dir, "2026-10-11-fresh-urls.json");
    commit(dir, "publish an older run");
    const run = ignoreStep(vercelClone(dir), { VERCEL_ENV: "production", VERCEL_GIT_PREVIOUS_SHA: base });
    expect(run.code, run.out).toBe(BUILD);
  });

  test("builds when latest.json points outside docs/benchmarks", () => {
    const { dir } = newOrigin();
    pointLatestAt(dir, "../../api/main.py");
    const deployed = commit(dir, "odd link");
    commit(dir, "ml", { "ml/train.py": "# later\n" });
    // The link is what was deployed; what it points to is not a report the
    // script knows how to compare.
    const run = ignoreStep(vercelClone(dir), { VERCEL_ENV: "production", VERCEL_GIT_PREVIOUS_SHA: deployed });
    expect(run.code, run.out).toBe(BUILD);
    expect(run.out).toContain("latest.json");
  });

  test("a change only to files the landing build never reads skips", () => {
    const { dir, base } = newOrigin();
    const built: string[] = [];
    for (const [i, file] of NOT_LANDING_INPUTS.entries()) {
      git(dir, "checkout", "--quiet", "-b", `other-${i}`, base);
      commit(dir, `touch ${file}`, { [file]: `changed ${i}\n` });
      const run = ignoreStep(dir, { VERCEL_ENV: "production", VERCEL_GIT_PREVIOUS_SHA: base });
      if (run.code !== SKIP) built.push(`${file}: ${run.out}`);
    }
    expect(built).toEqual([]);
  });

  test("production: a base older than the shallow clone is fetched, and a landing change after it builds", () => {
    const { dir, base } = newOrigin();
    commit(dir, "landing change", { "landing/app/page.tsx": "export default function Page() { return null; }\n" });
    for (let i = 0; i < 12; i++) commit(dir, `ml ${i}`, { "ml/train.py": `# ${i}\n` });
    const clone = vercelClone(dir);
    expect(hasCommit(clone, base), "the base must start outside the clone").toBe(false);
    const run = ignoreStep(clone, { VERCEL_ENV: "production", VERCEL_GIT_PREVIOUS_SHA: base });
    expect(run.code, run.out).toBe(BUILD);
    expect(run.out).toContain("1 landing file(s) changed since the last successful deployment");
  });

  test("production: a base older than the shallow clone is fetched, and with no landing change it skips", () => {
    const { dir, base } = newOrigin();
    for (let i = 0; i < 12; i++) commit(dir, `api ${i}`, { "api/main.py": `# ${i}\n` });
    const clone = vercelClone(dir);
    expect(hasCommit(clone, base), "the base must start outside the clone").toBe(false);
    const run = ignoreStep(clone, { VERCEL_ENV: "production", VERCEL_GIT_PREVIOUS_SHA: base });
    expect(run.code, run.out).toBe(SKIP);
  });

  test("a landing change that was reverted later still compares by content", () => {
    const { dir, base } = newOrigin();
    commit(dir, "landing change", { "landing/app/page.tsx": "changed\n" });
    commit(dir, "revert it", { "landing/app/page.tsx": REPO_FILES["landing/app/page.tsx"] });
    const run = ignoreStep(vercelClone(dir), { VERCEL_ENV: "production", VERCEL_GIT_PREVIOUS_SHA: base });
    expect(run.code, run.out).toBe(SKIP);
  });

  test("builds when the last deployment's commit cannot be found anywhere", () => {
    const { dir } = newOrigin();
    const run = ignoreStep(vercelClone(dir), {
      VERCEL_ENV: "production",
      VERCEL_GIT_PREVIOUS_SHA: "0123456789abcdef0123456789abcdef01234567",
    });
    expect(run.code, run.out).toBe(BUILD);
    expect(run.out).toContain("could not be fetched");
  });

  test("builds, and passes nothing to git, when VERCEL_GIT_PREVIOUS_SHA is not a SHA", () => {
    const { dir } = newOrigin();
    const run = ignoreStep(vercelClone(dir), {
      VERCEL_ENV: "production",
      VERCEL_GIT_PREVIOUS_SHA: "--upload-pack=false",
    });
    expect(run.code, run.out).toBe(BUILD);
    expect(run.out).toContain("not a commit SHA");
  });

  test("preview: a new branch that leaves the landing alone skips (compared with main)", () => {
    const { dir } = newOrigin();
    git(dir, "checkout", "--quiet", "-b", "ml-only");
    commit(dir, "ml", { "ml/train.py": "# new model\n" });
    const run = ignoreStep(vercelClone(dir, "ml-only"), { VERCEL_ENV: "preview", VERCEL_GIT_PREVIOUS_SHA: "" });
    expect(run.code, run.out).toBe(SKIP);
    expect(run.out).toContain("compared with main");
  });

  test("preview: a new branch that changes the landing builds", () => {
    const { dir } = newOrigin();
    git(dir, "checkout", "--quiet", "-b", "landing-copy");
    commit(dir, "copy", { "landing/messages/en.json": '{"hello":"world"}\n' });
    const run = ignoreStep(vercelClone(dir, "landing-copy"), { VERCEL_ENV: "preview", VERCEL_GIT_PREVIOUS_SHA: "" });
    expect(run.code, run.out).toBe(BUILD);
  });

  test("preview: a new branch builds when main has landing changes the branch lacks", () => {
    const { dir, base } = newOrigin();
    git(dir, "checkout", "--quiet", "-b", "old-branch");
    commit(dir, "ml", { "ml/train.py": "# new model\n" });
    git(dir, "checkout", "--quiet", "main");
    commit(dir, "landing on main", { "landing/app/page.tsx": "newer\n" });
    expect(git(dir, "merge-base", "main", "old-branch")).toBe(base);
    const run = ignoreStep(vercelClone(dir, "old-branch"), { VERCEL_ENV: "preview", VERCEL_GIT_PREVIOUS_SHA: "" });
    expect(run.code, run.out).toBe(BUILD);
  });

  test("preview: a new branch builds when main cannot be fetched", () => {
    const { dir } = newOrigin();
    git(dir, "checkout", "--quiet", "-b", "ml-only");
    commit(dir, "ml", { "ml/train.py": "# new model\n" });
    const clone = vercelClone(dir, "ml-only");
    git(clone, "remote", "remove", "origin");
    const run = ignoreStep(clone, { VERCEL_ENV: "preview", VERCEL_GIT_PREVIOUS_SHA: "" });
    expect(run.code, run.out).toBe(BUILD);
    expect(run.out).toContain("could not be fetched");
  });

  test("preview: once a branch has a successful deployment, it compares with that, not with main", () => {
    const { dir } = newOrigin();
    git(dir, "checkout", "--quiet", "-b", "landing-then-ml");
    const built = commit(dir, "landing", { "landing/app/page.tsx": "preview me\n" });
    commit(dir, "ml", { "ml/train.py": "# new model\n" });
    const run = ignoreStep(vercelClone(dir, "landing-then-ml"), {
      VERCEL_ENV: "preview",
      VERCEL_GIT_PREVIOUS_SHA: built,
    });
    expect(run.code, run.out).toBe(SKIP);
    expect(run.out).toContain("since the last successful deployment");
  });

  test("outside a git checkout it builds", () => {
    const plain = join(sandbox, `plain-${++counter}`);
    mkdirSync(join(plain, "landing"), { recursive: true });
    const run = ignoreStep(plain, { VERCEL_ENV: "production", VERCEL_GIT_PREVIOUS_SHA: "" });
    expect(run.code, run.out).toBe(BUILD);
    expect(run.out).toContain("not inside a git checkout");
  });
});

/** The paths the script compares, read from its `set -- \` list. */
function scriptPaths(): string[] {
  const block = readFileSync(SCRIPT, "utf-8").match(/^set -- \\\n((?: {2}\S+(?: \\)?\n)+)/m);
  expect(block, "the `set --` path list in vercel-ignore.sh").not.toBeNull();
  return (block?.[1] ?? "")
    .split("\n")
    .map((line) => line.replace(/\\$/, "").trim())
    .filter(Boolean);
}

/**
 * The lifecycle scripts a root `npm install` runs for the root package and its
 * workspaces, and the files each one reads. Vercel's installCommand is that
 * install, so those files are landing inputs too.
 */
const INSTALL_SCRIPTS: Record<string, string[]> = {
  "mobile/package.json postinstall: node scripts/apply-patches.js": [
    "mobile/scripts/apply-patches.js",
    "mobile/patches",
  ],
};
const INSTALL_LIFECYCLE = ["preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare"];

function workspaceManifests(): string[] {
  const root = JSON.parse(readFileSync(join(REPO_ROOT, "package.json"), "utf-8")) as { workspaces?: string[] };
  const dirs: string[] = [];
  for (const entry of root.workspaces ?? []) {
    if (entry.endsWith("/*")) {
      const parent = entry.slice(0, -2);
      for (const child of readdirSync(join(REPO_ROOT, parent))) dirs.push(`${parent}/${child}`);
    } else {
      expect(entry, "a workspace pattern this test can expand").not.toMatch(/[*?{[]/);
      dirs.push(entry);
    }
  }
  return ["package.json", ...dirs.map((dir) => `${dir}/package.json`)].filter((file) =>
    existsSync(join(REPO_ROOT, file)),
  );
}

test.describe("Vercel project config (landing/vercel.json)", () => {
  test("runs the ignore script, deploys main only, and does not comment on pull requests", () => {
    const config = JSON.parse(readFileSync(VERCEL_JSON, "utf-8"));
    expect(config.ignoreCommand).toBe("sh scripts/vercel-ignore.sh");
    // A deployment the ignore script cancels still uses one of Hobby's 100
    // deployments a day, so other branches must not create one at all.
    // `**`, not `*`: Vercel matches branch names with minimatch, where `*`
    // stops at "/" and would leave fix/..., feat/... deploying. main matches
    // both keys; Vercel deploys when any matching key is true.
    expect(config.git?.deploymentEnabled).toEqual({ main: true, "**": false });
    // Deprecated in favor of the dashboard toggle, still honored: no
    // vercel[bot] comments on pull requests and commits.
    expect(config.github?.silent).toBe(true);
  });

  test("every build publishes the stamp of its NEXT_PUBLIC_* variables at /build-env.txt", () => {
    // landing's prebuild runs before `next build` copies public/ into the site.
    const prebuild = (JSON.parse(readFileSync(LANDING_PACKAGE, "utf-8")).scripts ?? {}).prebuild as string;
    expect(prebuild).toContain("node scripts/build-env-stamp.cjs --write public/build-env.txt");
    // A build artifact, like public/outlook/.
    expect(readFileSync(LANDING_GITIGNORE, "utf-8").split("\n")).toContain("public/build-env.txt");

    const out = join(sandbox, `stamp-${++counter}.txt`);
    const env = { NEXT_PUBLIC_STRIPE_LIVE: "1", NEXT_PUBLIC_VERCEL_URL: "cleanway-abc.vercel.app", SECRET_KEY: "x" };
    const run = spawnSync(process.execPath, [STAMP, "--write", out], { env: Object.assign({}, GIT_ENV, env), encoding: "utf-8" });
    expect(run.status, run.stderr).toBe(0);
    const written = readFileSync(out, "utf-8").trim();
    expect(written).toBe(stampOf(env));
    expect(written).toBe(stampOf({ NEXT_PUBLIC_STRIPE_LIVE: "1" }));
    expect(written).not.toBe(stampOf({ NEXT_PUBLIC_STRIPE_LIVE: "" }));
    // A fingerprint: no value, and no variable that is not NEXT_PUBLIC_*.
    expect(written).toMatch(/^v1 1 [0-9a-f]{64}$/);
  });

  test("every install script the root npm install runs has the files it reads in the script's path list", () => {
    const found: string[] = [];
    for (const manifest of workspaceManifests()) {
      const scripts = (JSON.parse(readFileSync(join(REPO_ROOT, manifest), "utf-8")).scripts ?? {}) as Record<
        string,
        string
      >;
      for (const name of INSTALL_LIFECYCLE) {
        if (scripts[name]) found.push(`${manifest} ${name}: ${scripts[name]}`);
      }
    }
    // A new or changed install script: add the files it reads to the `set --`
    // list in landing/scripts/vercel-ignore.sh, then list it here.
    expect(found.sort()).toEqual(Object.keys(INSTALL_SCRIPTS).sort());
    const listed = scriptPaths();
    for (const reads of Object.values(INSTALL_SCRIPTS)) {
      for (const path of reads) expect(listed, `vercel-ignore.sh compares ${path}`).toContain(path);
    }
  });
});

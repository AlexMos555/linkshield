import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, realpathSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
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

// Set up in beforeAll, so listing the tests creates no temporary directory.
let sandbox = "";
let GIT_ENV: NodeJS.ProcessEnv = { NODE_ENV: "test" };

test.beforeAll(() => {
  sandbox = realpathSync(mkdtempSync(join(tmpdir(), "vercel-ignore-")));
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
  "mobile/package.json": "{}\n",
  "mobile/app/index.tsx": "// app\n",
  "scripts/sync-addin.cjs": "// sync\n",
  "scripts/build-i18n.py": "# i18n\n",
  "email-plugin-outlook/manifest.xml": "<OfficeApp/>\n",
  "docs/benchmarks/latest.json": "{}\n",
  "docs/benchmarks/2026-10-18.json": "{}\n",
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
  "mobile/package.json",
  "scripts/sync-addin.cjs",
  "email-plugin-outlook/manifest.xml",
  "docs/benchmarks/latest.json",
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
  "scripts/build-i18n.py",
  "docs/ROADMAP.md",
  "docs/benchmarks/2026-10-18.json",
  ".github/workflows/ci.yml",
];

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

/** Stands in for GitHub: a repository on `main` with every area committed once. */
function newOrigin(): { dir: string; base: string } {
  const dir = join(sandbox, `origin-${++counter}`);
  mkdirSync(dir);
  git(dir, "init", "--quiet", "--initial-branch=main");
  // GitHub serves a commit by its SHA; a plain local repository refuses to.
  git(dir, "config", "uploadpack.allowAnySHA1InWant", "true");
  return { dir, base: commit(dir, "base", REPO_FILES) };
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

/** Runs the script the way Vercel does: from the Root Directory (landing/). */
function ignoreStep(checkout: string, env: Record<string, string>): { code: number | null; out: string } {
  const run = spawnSync("sh", [SCRIPT], {
    cwd: join(checkout, "landing"),
    env: Object.assign({}, GIT_ENV, env),
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

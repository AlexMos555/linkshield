#!/usr/bin/env node
/**
 * Smoke test of the Firefox add-on in a real Firefox, before an AMO upload.
 *
 *   node scripts/smoke-firefox-extension.mjs --firefox <firefox binary> --geckodriver <geckodriver>
 *        [--zip <file> | --ext <dir>] [--out <dir>]
 *
 * Chromium cannot load the MV2 build, so scripts/test-extension-sw.mjs and
 * the store screenshots never run it; this does, in Firefox itself, headless.
 * Needs Node, openssl and the two binaries (docs/STORE_SUBMISSION_KIT.md §5
 * puts them in a temp folder); nothing is added to the repository.
 *
 * What is loaded: the store package dist/store-artifacts/cleanway-<v>-firefox.zip
 * — the file uploaded to AMO — as a temporary add-on, the about:debugging
 * route that release Firefox allows for an unsigned add-on (--ext: an
 * unpacked folder instead). The run first checks that the ZIP holds exactly
 * extension-firefox/.
 *
 * The network (firefox-smoke/stub-proxy.mjs): every request Firefox makes
 * goes to a local proxy. api.cleanway.ai is the store-screenshot stub (a site
 * check gets the verdict the add-on's OWN offline rules give that host), the
 * demo pages of store-screenshots/fixtures.mjs are served, everything else is
 * dropped and listed. No live API, no real scam site.
 *
 * The checks (firefox-smoke/steps.mjs), all run, every failure listed:
 *   - the background starts: the welcome tab of a first install opens, and
 *     its "who uses this device" choice is saved;
 *   - content scripts mark the links of a search page green, yellow, red;
 *   - Settings loads: the account row, the level picked on the welcome page,
 *     the webmail switch; a new level is saved;
 *   - the toolbar popup gives a verdict, not an endless "Checking this
 *     page…": on an ordinary page (safe), a doubtful one (caution), the block
 *     page (scam); its buttons open their panels on the page;
 *   - opening the scam page takes the tab to the block page, which names the
 *     site; "Go back to safety" and "open anyway" (after its countdown) work;
 *   - the block-page sample (src/popup/block-preview.html) renders;
 *   - Settings' statistics show what the background counted;
 *   - no error from the add-on in Firefox's error console (uncaught errors,
 *     CSP refusals and console.error of its pages, background and content
 *     scripts). One planted error per kind proves the console is being read.
 * Screenshots (PNG) and summary.json go to --out (default: a folder in the
 * system temp dir, printed at the end); a run replaces only its own files
 * there (OUTPUTS below). Exit code 1 when a check failed.
 */
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Session, errorConsole, startGeckodriver, watchErrorConsole } from "./firefox-smoke/geckodriver.mjs";
import { diffWithTree, readPackage } from "./firefox-smoke/package.mjs";
import {
  ADDON_ID, blockButtons, blockPreview, installAndWelcome, linkMarks, popup, popupButtons, scamIsBlocked, settings,
  statistics,
} from "./firefox-smoke/steps.mjs";
import { proxyPrefs, startStubProxy } from "./firefox-smoke/stub-proxy.mjs";
import { scorerFrom } from "./store-screenshots/build-info.mjs";
import { EXPECTED, HOSTS, URLS } from "./store-screenshots/fixtures.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TREE = join(ROOT, "extension-firefox");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const LANG = "en"; // the demo pages' language (store-screenshots/fixtures.mjs)

// ── arguments ──
const argv = process.argv.slice(2);
const opt = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : null;
};
const version = JSON.parse(readFileSync(join(TREE, "manifest.json"), "utf8")).version;
const FIREFOX = opt("--firefox") || process.env.FIREFOX_BIN ||
  ["/Applications/Firefox.app/Contents/MacOS/firefox", "/usr/bin/firefox"].find((p) => existsSync(p));
const GECKODRIVER = opt("--geckodriver") || process.env.GECKODRIVER || "geckodriver";
const EXT_DIR = opt("--ext") ? resolve(opt("--ext")) : null;
const ZIP = EXT_DIR ? null : resolve(opt("--zip") || join(ROOT, "dist", "store-artifacts", `cleanway-${version}-firefox.zip`));
const OUT = resolve(opt("--out") || join(tmpdir(), `cleanway-firefox-smoke-${version}`));
if (!FIREFOX || !existsSync(FIREFOX)) {
  console.error("Firefox not found: pass --firefox <path to the firefox binary> (docs/STORE_SUBMISSION_KIT.md §5.0)");
  process.exit(2);
}
if (ZIP && !existsSync(ZIP)) {
  console.error(`${ZIP} is missing: run scripts/build-store-artifacts.sh, or pass --zip / --ext`);
  process.exit(2);
}

// ── checks and evidence ──
const checks = [];
function check(name, ok, detail = "") {
  checks.push({ name, ok: Boolean(ok), detail: detail || "" });
  console.log(`${ok ? "  ok  " : "  FAIL"} ${name}${detail ? ` — ${detail}` : ""}`);
}
async function until(fn, timeoutMs = 15000, stepMs = 200) {
  const deadline = Date.now() + timeoutMs;
  let last;
  while (Date.now() < deadline) {
    last = await fn().catch((e) => ({ error: String(e.message || e) }));
    if (last && !last.pending && !last.error) return last;
    await sleep(stepMs);
  }
  return last;
}
// Everything this script writes to --out. Only these names are cleared before
// a run (so no stale picture passes for a new one): --out may be any folder —
// the repository root, store-assets/, the Desktop — and nothing else in it is
// touched.
const OUTPUTS = ["00-welcome.png", "01-link-badges.png", "02-popup-safe.png", "03-popup-caution.png",
  "04-block-page.png", "04-popup-on-block-page.png", "05-settings.png", "06-block-preview.png", "summary.json"];
mkdirSync(OUT, { recursive: true });
for (const f of OUTPUTS) rmSync(join(OUT, f), { force: true });
function shot(file, png) {
  if (!OUTPUTS.includes(file)) throw new Error(`${file}: add it to OUTPUTS, the files cleared before a run`);
  writeFileSync(join(OUT, file), png);
  console.log(`        ${join(OUT, file)}`);
}

// ── what is loaded ──
const pkg = readPackage(ROOT, { zip: ZIP, extDir: EXT_DIR });
console.log(`Firefox smoke test of ${pkg.label}`);
const manifest = JSON.parse(pkg.files.get("manifest.json").toString("utf8"));
const gecko = manifest.browser_specific_settings?.gecko || {};
check("manifest: MV2, add-on id, version", manifest.manifest_version === 2 && gecko.id === ADDON_ID && manifest.version === version,
  `MV${manifest.manifest_version}, ${gecko.id}, ${manifest.version}`);
if (ZIP) {
  const diff = diffWithTree(pkg.files, TREE);
  check("the ZIP holds exactly extension-firefox/", diff.length === 0, diff.length
    ? `differs: ${diff.slice(0, 8).join(", ")}${diff.length > 8 ? ` and ${diff.length - 8} more` : ""} — rebuild it (§5)`
    : `${pkg.files.size} files`);
}
const score = scorerFrom((rel) => pkg.files.get(rel).toString("utf8"));
const offline = Object.entries(EXPECTED).filter(([host, level]) => score(host).level !== level);
check("the add-on's offline rules give the demo hosts their expected verdicts", offline.length === 0,
  offline.map(([h, l]) => `${h}: ${score(h).level}, expected ${l}`).join("; "));

// ── the run ──
const uuid = randomUUID();
const base = `moz-extension://${uuid}/`;
// Planted errors, one per way an error reaches us, so a clean console means
// "read and empty", not "never read".
const tag = uuid.slice(0, 8);
const CANARY = { ext: `smoke-canary-ext-${tag}`, web: `smoke-canary-web-${tag}`, log: `smoke-canary-log-${tag}` };
const reject = (text) => `window.Promise.reject(new window.Error(${JSON.stringify(text)})); return true;`;
const work = mkdtempSync(join(tmpdir(), "cleanway-ff-smoke-")); // the certificate, Firefox's profile
const summary = { date: new Date().toISOString(), loaded: pkg.label, version, popupHeights: {} };
let proxy = null, driver = null, s = null;
try {
  proxy = await startStubProxy({ dir: work, lang: LANG, score });
  driver = await startGeckodriver(GECKODRIVER, work);
  s = await Session.create(driver.base, {
    acceptInsecureCerts: true, // the stub's self-signed certificate
    timeouts: { script: 30000, pageLoad: 30000, implicit: 0 },
    "moz:firefoxOptions": {
      binary: FIREFOX,
      args: ["-headless"],
      prefs: {
        ...proxyPrefs(proxy.port),
        // The add-on's moz-extension:// address, fixed before it is installed.
        "extensions.webextensions.uuids": JSON.stringify({ [ADDON_ID]: uuid }),
        // console.* of every page, the add-on's included, printed on stdout.
        "devtools.console.stdout.content": true,
        "intl.locale.requested": "en-US",
      },
    },
  });
  summary.firefox = `Firefox ${s.capabilities.browserVersion}${s.capabilities["moz:headless"] ? " (headless)" : ""}`;
  console.log(`${summary.firefox}, stub proxy on 127.0.0.1:${proxy.port}`);
  await watchErrorConsole(s);
  await s.setRect(1280, 800);
  const ctx = { s, base, lang: LANG, check, shot, until, sleep, popupHeights: summary.popupHeights };
  const tabA = await s.currentHandle();

  const welcome = await installAndWelcome(ctx, EXT_DIR || ZIP, tabA, async () => {
    await s.content(reject(CANARY.ext));
    await s.content(`window.console.error(${JSON.stringify(CANARY.log)}); return true;`);
  });
  await s.switchTo(tabA);
  await linkMarks(ctx);
  await s.content(reject(CANARY.web));

  const second = await s.newWindow();
  await s.switchTo(second);
  await s.setRect(1280, 800);
  await settings(ctx);

  await s.switchTo(tabA);
  await s.go(URLS.recipe);
  await sleep(1500); // the page's own check
  await s.switchTo(second);
  await popup(ctx, "02-popup-safe.png", URLS.recipe, "safe", HOSTS.recipes);
  await popupButtons(ctx, tabA, second);

  await s.switchTo(tabA);
  await s.go(URLS.caution);
  await sleep(1500);
  const cautionUrl = await s.url();
  check("a caution page is not blocked", new URL(cautionUrl).hostname === HOSTS.caution, cautionUrl);
  await s.switchTo(second);
  await popup(ctx, "03-popup-caution.png", URLS.caution, "warning", HOSTS.caution);

  await s.switchTo(tabA);
  await scamIsBlocked(ctx);
  await s.switchTo(second);
  await popup(ctx, "04-popup-on-block-page.png", `${base}src/blocked/blocked.html`, "danger", HOSTS.scam);
  await s.switchTo(tabA);
  await blockButtons(ctx);

  await s.switchTo(second);
  await blockPreview(ctx);
  await statistics(ctx);
  if (welcome) { // the welcome tab, now that Firefox's fonts are in
    await s.switchTo(welcome);
    shot("00-welcome.png", await s.screenshot());
  }

  // ── Firefox's error console and the add-on's console output ──
  const logged = await errorConsole(s);
  const printed = driver.output.filter((l) => /^console\.(error|warn): /.test(l));
  const seen = (text) => logged.some((m) => m.message.includes(text));
  check("the error console is read (planted errors seen)", seen(CANARY.ext) && seen(CANARY.web) &&
    printed.some((l) => l.includes(CANARY.log)),
  `extension page ${seen(CANARY.ext)}, web page ${seen(CANARY.web)}, console.error ${printed.some((l) => l.includes(CANARY.log))}`);
  const planted = (text) => Object.values(CANARY).some((c) => text.includes(c));
  // The add-on's own files, its name ("[Cleanway] …"), or Firefox reading its manifest.
  const isOurs = (m) => (m.source || "").includes(uuid) || /cleanway/i.test(`${m.source} ${m.message}`) ||
    /^Reading manifest:/.test(m.message);
  const all = logged.filter((m) => !planted(m.message));
  const where = (m) => `${(m.source || "?").replace(base, "")}:${m.line} ${m.message}`;
  const errors = all.filter((m) => isOurs(m) && m.level === "error").map(where)
    .concat(printed.filter((l) => l.startsWith("console.error") && /cleanway/i.test(l) && !planted(l)));
  const warnings = all.filter((m) => isOurs(m) && m.level === "warning").map(where)
    .concat(printed.filter((l) => l.startsWith("console.warn") && /cleanway/i.test(l)));
  check("no error from the add-on in Firefox's error console", errors.length === 0, errors.join(" | "));
  if (warnings.length) console.log(`        warnings from the add-on: ${warnings.join(" | ")}`);
  summary.console = { addonErrors: errors, addonWarnings: warnings,
    firefoxOwn: all.filter((m) => !isOurs(m)).map((m) => `${m.level}: ${m.source}:${m.line} ${m.message}`) };
} catch (err) {
  check("the run finished", false, String(err.stack || err));
} finally {
  if (s) await s.quit();
  if (driver) driver.stop();
  if (proxy) proxy.close();
  rmSync(work, { recursive: true, force: true });
}
if (!proxy || !driver) process.exit(1); // nothing ran; the reason is printed above

// ── what the stub saw, and the verdict ──
const hostOf = (u) => new URL(u.replace(/^ws:/, "http:")).hostname;
const isMozilla = (u) => /(^|\.)(mozilla\.(com|org|net)|firefox\.com|mozaws\.net|mozgcp\.net)$/.test(hostOf(u));
check("the add-on's site checks reached the stub API", proxy.log.api.some((l) => l.includes("/api/v1/public/check/")),
  `${proxy.log.api.length} requests`);
const dropped = [...proxy.log.refused].filter((u) => !isMozilla(u)).sort();
if (dropped.length) console.log(`        dropped (the stub serves no such page): ${dropped.join(", ")}`);
// Firefox's own services (updates, remote settings, …), never answered: only their hosts.
const firefoxOwn = {};
for (const u of [...proxy.log.refused].filter(isMozilla)) firefoxOwn[hostOf(u)] = (firefoxOwn[hostOf(u)] || 0) + 1;
Object.assign(summary, { api: proxy.log.api, pages: proxy.log.pages, dropped, firefoxOwnRequestsDropped: firefoxOwn, checks });
writeFileSync(join(OUT, "summary.json"), JSON.stringify(summary, null, 2) + "\n");
const failed = checks.filter((c) => !c.ok);
console.log(`\n${failed.length ? `FAILED: ${failed.length} of ${checks.length} checks` : `all ${checks.length} checks passed`}` +
  ` — screenshots and summary.json in ${OUT}`);
process.exit(failed.length ? 1 : 0);

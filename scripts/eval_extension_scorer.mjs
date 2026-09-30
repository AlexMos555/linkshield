#!/usr/bin/env node
/**
 * Offline measurement of the extension's scorer (src/utils/local-scorer.js)
 * on the labelled host lists the server's name rules are measured on.
 *
 * The extension draws its badge — and, for the page itself, the block page —
 * from this scorer whenever the API does not answer. It gets the bare host
 * and nothing else, exactly like scripts/eval_ru_heuristics.py gives the
 * server's calculate_score() the bare host, so the two are comparable.
 *
 *   tests/data/ru_heuristics_legit.txt   Russian sites that must not be flagged
 *   data/benchmark_legit_ru.txt          the weekly benchmark's legit sample
 *   tests/data/ru_heuristics_phish.txt   look-alikes that must stay caught
 *   --top        data/top_100k.json: every one a real site
 *   --variants   the rows of `python3 scripts/eval_typo_variants.py --out X`:
 *                seeded typos of every brand, and whether the server caught
 *                each one — recall per edit class, and agreement
 *
 * Usage:
 *   node scripts/eval_extension_scorer.mjs [--tree DIR] [--top] [--variants X.json] [--out R.json]
 *   node scripts/eval_extension_scorer.mjs --compare before.json after.json
 *
 * --tree is a directory holding src/utils/ (default packages/extension-core).
 * For a "before", check the old scorer out into one:
 *   mkdir -p /tmp/before/src/utils
 *   git show main:packages/extension-core/src/utils/local-scorer.js > /tmp/before/src/utils/local-scorer.js
 * Scorer files that tree does not have (scorer-data.js, name-rules.js) are
 * skipped. No network.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

process.removeAllListeners("warning"); // node:punycode is deprecated, and fine here
const { default: punycode } = await import("node:punycode");

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCORER_FILES = ["src/utils/scorer-data.js", "src/utils/name-rules.js", "src/utils/local-scorer.js"];
const SETS = {
  legit: "tests/data/ru_heuristics_legit.txt",
  benchmark_legit: "data/benchmark_legit_ru.txt",
  phish: "tests/data/ru_heuristics_phish.txt",
};
const LEVELS = ["safe", "caution", "dangerous"];
const BUCKETS = ["3", "4", "5-7", "8+"];

function args(argv) {
  const out = { tree: join(ROOT, "packages/extension-core"), top: false, variants: null, out: null, compare: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--tree") out.tree = resolve(argv[++i]);
    else if (a === "--top") out.top = true;
    else if (a === "--variants") out.variants = resolve(argv[++i]);
    else if (a === "--out") out.out = resolve(argv[++i]);
    else if (a === "--compare") out.compare = [resolve(argv[++i]), resolve(argv[++i])];
    else throw new Error(`unknown argument ${a}`);
  }
  return out;
}

/** The scorer as a content script sees it: classic files in one global. */
function loadScorer(tree) {
  const ctx = vm.createContext({});
  const loaded = [];
  for (const rel of SCORER_FILES) {
    const path = join(tree, rel);
    if (!existsSync(path)) continue;
    vm.runInContext(readFileSync(path, "utf8"), ctx, { filename: path });
    loaded.push(rel);
  }
  if (typeof ctx.localScore !== "function") throw new Error(`${tree}: no localScore`);
  return { score: (host) => ctx.localScore(host), loaded };
}

/** 'host | category | …' lines, as scripts/eval_ru_heuristics.py reads them. */
function hostsOf(rel) {
  return readFileSync(join(ROOT, rel), "utf8").split("\n")
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith("#"))
    .map((l) => {
      const [host, category] = l.split(" | ").map((f) => f.trim());
      return { host, category };
    });
}

// The wire form the extension receives: each non-ASCII label punycoded.
function asciiHost(host) {
  return host.split(".").map((l) => (/^[\x00-\x7F]*$/.test(l) ? l : "xn--" + punycode.encode(l))).join(".");
}

function signals(r) { return r.reasons.map((x) => x.signal); }

function scoreSet(scorer, hosts) {
  return hosts.map(({ host, category }) => {
    const r = scorer.score(host);
    return { host, category, score: r.score, level: r.level, signals: signals(r) };
  });
}

function summary(rows) {
  const levels = Object.fromEntries(LEVELS.map((l) => [l, rows.filter((r) => r.level === l).length]));
  const bySignal = {};
  for (const r of rows) for (const s of new Set(r.signals)) bySignal[s] = (bySignal[s] || 0) + 1;
  return { n: rows.length, levels, flagged: levels.caution + levels.dangerous, bySignal };
}

function scoreVariants(scorer, path) {
  const data = JSON.parse(readFileSync(path, "utf8"));
  return data.rows.map((row) => {
    const r = scorer.score(asciiHost(row.host));
    return {
      host: row.host, class: row.class, bucket: row.bucket,
      server: row.caught, caught: signals(r).includes("typosquatting"),
    };
  });
}

function variantTable(rows) {
  const table = {};
  for (const r of rows) {
    const cell = (table[r.class] ||= {})[r.bucket] ||= [0, 0];
    cell[0] += r.caught ? 1 : 0;
    cell[1] += 1;
  }
  const agree = rows.filter((r) => r.caught === r.server).length;
  return { table, caught: rows.filter((r) => r.caught).length, n: rows.length, agree };
}

function evaluate(opts) {
  const scorer = loadScorer(opts.tree);
  const result = { tree: opts.tree, loaded: scorer.loaded, sets: {}, rows: {} };
  for (const [name, rel] of Object.entries(SETS)) {
    const rows = scoreSet(scorer, hostsOf(rel));
    result.rows[name] = rows;
    result.sets[name] = summary(rows);
  }
  if (opts.top) {
    const top = JSON.parse(readFileSync(join(ROOT, "data/top_100k.json"), "utf8"));
    const rows = scoreSet(scorer, top.map((host) => ({ host, category: "top" })));
    result.sets.top_100k = summary(rows);
    result.rows.top_100k = rows.filter((r) => r.level !== "safe");
  }
  if (opts.variants) {
    const rows = scoreVariants(scorer, opts.variants);
    result.variants = variantTable(rows);
    result.rows.variants = rows;
  }
  return result;
}

function printResult(r) {
  console.log(`scorer: ${r.tree} (${r.loaded.join(", ")})`);
  for (const [name, s] of Object.entries(r.sets)) {
    console.log(`${name} (${s.n}): safe ${s.levels.safe}, caution ${s.levels.caution}, dangerous ${s.levels.dangerous}`);
    console.log(`  signals: ${JSON.stringify(s.bySignal)}`);
  }
  if (r.variants) {
    console.log(`variants: typosquatting fires on ${r.variants.caught}/${r.variants.n}; ` +
      `agrees with the server on ${r.variants.agree}/${r.variants.n}`);
  }
}

function compare(before, after) {
  console.log("| set | metric | before | after |\n|---|---|---:|---:|");
  for (const name of Object.keys(after.sets)) {
    const b = before.sets[name], a = after.sets[name];
    if (!b) continue;
    const phish = name === "phish";
    const lines = phish
      ? [["caught (caution + dangerous)", "flagged"], ["dangerous", "dangerous"]]
      : [["caution", "caution"], ["dangerous", "dangerous"]];
    for (const [label, key] of lines) {
      const get = (s) => (key === "flagged" ? s.flagged : s.levels[key]);
      console.log(`| ${name} (${a.n}) | ${label} | ${get(b)} | ${get(a)} |`);
    }
    for (const sig of ["typosquatting", "brand_subdomain", "fake_tld", "deep_subdomains"]) {
      console.log(`| ${name} (${a.n}) | ${sig} fires | ${b.bySignal[sig] || 0} | ${a.bySignal[sig] || 0} |`);
    }
  }
  for (const name of ["legit", "benchmark_legit", "phish"]) {
    const bRows = new Map(before.rows[name].map((r) => [r.host, r]));
    const moved = after.rows[name].filter((r) => bRows.get(r.host).level !== r.level);
    console.log(`\n${name}: ${moved.length} hosts changed level`);
    for (const r of moved) {
      const b = bRows.get(r.host);
      console.log(`  ${r.host} (${r.category}): ${b.level} ${b.score} [${b.signals.join(",")}] → ${r.level} ${r.score} [${r.signals.join(",")}]`);
    }
  }
  if (before.variants && after.variants) {
    console.log("\n| class | " + BUCKETS.map((x) => `names of ${x}`).join(" | ") + " |");
    console.log("|---|" + "---|".repeat(BUCKETS.length));
    for (const cls of Object.keys(after.variants.table)) {
      const cells = BUCKETS.map((x) => {
        const cb = (before.variants.table[cls] || {})[x], ca = (after.variants.table[cls] || {})[x];
        return cb && ca ? `${cb[0]} → ${ca[0]} of ${ca[1]}` : "–";
      });
      console.log(`| ${cls} | ${cells.join(" | ")} |`);
    }
    console.log(`\ncaught ${before.variants.caught} → ${after.variants.caught} of ${after.variants.n}; ` +
      `agreement with the server ${before.variants.agree} → ${after.variants.agree}`);
  }
}

const opts = args(process.argv.slice(2));
if (opts.compare) {
  const [b, a] = opts.compare.map((p) => JSON.parse(readFileSync(p, "utf8")));
  compare(b, a);
} else {
  const result = evaluate(opts);
  printResult(result);
  if (opts.out) writeFileSync(opts.out, JSON.stringify(result));
}

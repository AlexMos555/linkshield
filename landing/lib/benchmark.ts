import fs from "node:fs/promises";
import path from "node:path";

/**
 * The committed weekly benchmark (docs/benchmarks/latest.json) and the one
 * rule for when any number from it may be shown on the site.
 *
 * Every percentage the landing prints about our own accuracy comes from this
 * file — never from a hand-typed constant. And it only comes from here when
 * the sample is big enough to mean something: the same gate the benchmark
 * script applies before it moves latest.json
 * (scripts/eval_fresh_urls.check_quality_gate; tests/fixtures/
 * benchmark-gate-cases.json holds both to the same cases). Below that we say
 * plainly that there is no trustworthy number yet.
 */

/** A Wilson 95% interval [low, high] of a rate, 0..1; null when nothing was counted. */
export type Wilson95 = [number, number] | null;

export interface ResolverStats {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  /** Everything but tp/fn/fp/tn: caution, not found and no answer alike. */
  unknown: number;
  /** tp / (tp + fn): leaves caution, dead names and no answer out (see the counts below). */
  recall: number | null;
  fpr: number | null;
  precision: number | null;
  f1: number | null;
  latency_p50_ms: number | null;
  // Since method_version 2 (2026-11-03, scripts/benchmark_method.py summarize);
  // absent in older snapshots. Only the gate reads them (no_answer,
  // resolving): which figure the site shows is the founder's call.
  /** Rows in the batch. */
  n?: number;
  dangerous?: number;
  caution?: number;
  safe?: number;
  /** Rows whose name does not exist (the benchmark's own probe): not found for every resolver, whatever it answered. */
  not_found?: number;
  /** Live rows that got no answer: HTTP 429, an error, a timeout. */
  no_answer?: number;
  /** n - not_found: the live rows. */
  resolving?: number;
  /** n - not_found - no_answer: the live rows that got an answer, the rates' denominator. */
  answered?: number;
  dangerous_rate_answered?: number | null;
  /** (dangerous + caution) / answered: how often a warning was shown. */
  warned_rate_answered?: number | null;
  recall_wilson95?: Wilson95;
  fpr_wilson95?: Wilson95;
  dangerous_rate_answered_wilson95?: Wilson95;
  warned_rate_answered_wilson95?: Wilson95;
}

/** The rows the phishing sample was drawn from: those submitted in `days` before the dump's newest row. */
export interface BenchmarkWindow {
  /** 0 = the whole dump (start and end null). */
  days: number;
  start: string | null;
  end: string | null;
  /** Rows without a readable submission time, never in the window. */
  undated_rows: number;
}

/** How the phishing sample was drawn (method_version 2). */
export interface BenchmarkSampling {
  seed: number;
  max_per_site: number;
  window: BenchmarkWindow;
  /** Rows of the whole dump. */
  dump_rows: number;
  /** Rows, hosts and sites in the window: the pool. */
  pool_rows: number;
  pool_hosts: number;
  pool_sites: number;
  n: number;
  sites: number;
  site_rule: string;
  dump_sha256: string | null;
  submitted: { oldest: string; median: string; newest: string } | null;
}

/** Rows by existence: the same fact for every resolver's row. */
export interface ExistenceCounts {
  resolves: number;
  nxdomain: number;
  unknown: number;
}

export interface BenchmarkSources {
  /**
   * True only when the legitimate sample holds real sites OUTSIDE the list
   * our server trusts without analysis (the top 100k, is_trusted_top_domain).
   * Written by scripts/eval_fresh_urls.py; absent in older snapshots.
   */
  legit_outside_allowlist?: boolean;
  /** What the legitimate sample is, in the script's words (eval_fresh_urls.pick_legit). */
  legit?: string;
}

export interface BenchmarkSnapshot {
  ts: string;
  /**
   * 2 since 2026-11-03: a fixed-seed sample capped per site, and a name that
   * resolves nowhere counted as not found for every resolver. Absent = 1, the
   * old rules; the two are not comparable.
   */
  method_version?: number;
  n_phishing: number;
  n_safe: number;
  sources?: BenchmarkSources;
  sampling?: BenchmarkSampling;
  existence?: { phishing: ExistenceCounts; safe: ExistenceCounts };
  phishing: Record<string, ResolverStats>;
  safe: Record<string, ResolverStats>;
}

/** Minimum sample before a recall figure is published (mirrors the script's gate). */
export const MIN_PHISHING_SAMPLE = 100;
/** Minimum phishing URLs that got a real verdict (not rate-limited / unknown). */
export const MIN_PHISHING_CLASSIFIED = 50;
/**
 * Minimum live phishing links (method 2: n - not_found). The same 50 as the
 * verdicts — there are never fewer live links than verdicts on them — so it
 * hides nothing more; the script names it as the reason when most names died
 * (eval_fresh_urls._QG_MIN_RESOLVING_PHISHING says why not 100).
 */
export const MIN_PHISHING_RESOLVING = 50;
/** Minimum legitimate sites that got a real verdict before a false-positive rate is shown. */
export const MIN_SAFE_CLASSIFIED = 50;
/**
 * Above this share of live links with no answer at all (HTTP 429, an error, a
 * timeout) the run measured our rate limit, not our detection. Until
 * 2026-11-03 it was the share of "unknown", which since method_version 2 also
 * holds every dead name and every caution: about half of a fresh week's
 * sample, measurements rather than trouble. A snapshot without no_answer
 * (method 1) is still judged by its "unknown".
 */
export const MAX_NO_ANSWER_RATE = 0.3;

const OURS = "cleanway";

/**
 * Services the weekly run stopped comparing on 2026-10-24: their free APIs
 * bar a commercial product — VirusTotal's public API "must not be used in
 * commercial products or services", Safe Browsing v4 is "for non-commercial
 * use only" (scripts/eval_fresh_urls.py, NON_COMMERCIAL_RESOLVERS). Snapshots
 * from before still hold their rows; the site leaves those rows out rather
 * than show a comparison the weekly run no longer makes. The raw files on
 * GitHub keep them.
 */
export const RETIRED_RESOLVERS: ReadonlySet<string> = new Set(["gsb", "virustotal"]);

/** One batch's rows as the site shows them: the services still compared, in the snapshot's order. */
export function comparedRows(batch: Record<string, ResolverStats> | undefined): [string, ResolverStats][] {
  return Object.entries(batch ?? {}).filter(([name]) => !RETIRED_RESOLVERS.has(name));
}

function count(value: number | undefined): number {
  return typeof value === "number" ? value : 0;
}

function classified(stats: ResolverStats | undefined, a: "tp" | "tn", b: "fn" | "fp"): number {
  return stats ? count(stats[a]) + count(stats[b]) : 0;
}

/** Method 2: live links without an answer / live links. Older snapshots: unknown / (verdicts + unknown). */
function noAnswerRate(ours: ResolverStats | undefined): number {
  if (typeof ours?.no_answer === "number" && typeof ours.resolving === "number") {
    return ours.resolving > 0 ? ours.no_answer / ours.resolving : 1;
  }
  const answered = classified(ours, "tp", "fn");
  const unknown = count(ours?.unknown);
  return answered + unknown > 0 ? unknown / (answered + unknown) : 1;
}

/** True when the snapshot's phishing half is large enough to quote our recall. */
export function recallIsPublishable(snapshot: BenchmarkSnapshot | null): boolean {
  if (!snapshot) return false;
  const ours = snapshot.phishing?.[OURS];
  const live = typeof ours?.resolving === "number" ? ours.resolving : count(snapshot.n_phishing);
  return (
    typeof ours?.recall === "number" &&
    ours.recall > 0 &&
    count(snapshot.n_phishing) >= MIN_PHISHING_SAMPLE &&
    live >= MIN_PHISHING_RESOLVING &&
    classified(ours, "tp", "fn") >= MIN_PHISHING_CLASSIFIED &&
    noAnswerRate(ours) <= MAX_NO_ANSWER_RATE
  );
}

/**
 * True when a false-positive rate from this snapshot would mean something:
 * enough legitimate sites got a verdict AND they were sites our server really
 * analysed. The benchmark's old legitimate sample came from Tranco ranks
 * 100–100,000, and the public check answered every one of those "safe" without
 * looking (is_trusted_top_domain, then on Tranco's top 100k). A rate from that sample is near 0% by
 * construction — the hand-written "0.08%" again, with a real-looking source —
 * while real Russian sites outside the top got "Dangerous" 6 times in 12
 * (report 2026-09-25 #1).
 */
export function falsePositiveRateIsPublishable(snapshot: BenchmarkSnapshot | null): boolean {
  if (!snapshot || snapshot.sources?.legit_outside_allowlist !== true) return false;
  const ours = snapshot.safe?.[OURS];
  return typeof ours?.fpr === "number" && classified(ours, "tn", "fp") >= MIN_SAFE_CLASSIFIED;
}

/**
 * The list a snapshot's legitimate sample was taken from outside of: the one
 * the server trusted without analysis when the run was made. Tranco's top
 * 100k until 2026-10-23; since then (#284) a ranking built from the Majestic
 * Million and the Chrome UX Report. A snapshot from before keeps describing a
 * sample chosen against Tranco, and the page has to say so: the 2026-10-18
 * sample has sites the new ranking trusts.
 *
 * Keyed on the old snapshots' text, not the new one's: their sources.legit
 * names Tranco and is never rewritten, while eval_fresh_urls.pick_legit's
 * current wording may change with the next ranking rebuild (a pytest keeps
 * "Tranco" out of it).
 */
export type LegitRanking = "tranco" | "majestic_crux";

export function legitSampleRanking(snapshot: BenchmarkSnapshot | null): LegitRanking {
  return /Tranco/.test(snapshot?.sources?.legit ?? "") ? "tranco" : "majestic_crux";
}

/** Read latest.json from the repo (SSR / build time). Null when missing or unreadable. */
export async function loadLatestBenchmark(): Promise<BenchmarkSnapshot | null> {
  const candidates = [
    path.join(process.cwd(), "..", "docs", "benchmarks", "latest.json"),
    path.join(process.cwd(), "docs", "benchmarks", "latest.json"),
  ];
  for (const candidate of candidates) {
    try {
      return JSON.parse(await fs.readFile(candidate, "utf-8")) as BenchmarkSnapshot;
    } catch {
      continue;
    }
  }
  return null;
}

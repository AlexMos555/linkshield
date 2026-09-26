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
 * (scripts/eval_fresh_urls.check_quality_gate). Below that we say plainly
 * that there is no trustworthy number yet.
 */

export interface ResolverStats {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  unknown: number;
  recall: number | null;
  fpr: number | null;
  precision: number | null;
  f1: number | null;
  latency_p50_ms: number | null;
}

export interface BenchmarkSnapshot {
  ts: string;
  n_phishing: number;
  n_safe: number;
  phishing: Record<string, ResolverStats>;
  safe: Record<string, ResolverStats>;
}

/** Minimum sample before a recall figure is published (mirrors the script's gate). */
export const MIN_PHISHING_SAMPLE = 100;
/** Minimum phishing URLs that got a real verdict (not rate-limited / unknown). */
export const MIN_PHISHING_CLASSIFIED = 50;
/** Minimum legitimate sites that got a real verdict before a false-positive rate is shown. */
export const MIN_SAFE_CLASSIFIED = 50;
/** Above this share of "no answer" verdicts the run measured our rate limit, not our detection. */
export const MAX_UNKNOWN_RATE = 0.3;

const OURS = "cleanway";

function count(value: number | undefined): number {
  return typeof value === "number" ? value : 0;
}

function classified(stats: ResolverStats | undefined, a: "tp" | "tn", b: "fn" | "fp"): number {
  return stats ? count(stats[a]) + count(stats[b]) : 0;
}

/** True when the snapshot's phishing half is large enough to quote our recall. */
export function recallIsPublishable(snapshot: BenchmarkSnapshot | null): boolean {
  if (!snapshot) return false;
  const ours = snapshot.phishing?.[OURS];
  const answered = classified(ours, "tp", "fn");
  const unknown = count(ours?.unknown);
  const unknownRate = answered + unknown > 0 ? unknown / (answered + unknown) : 1;
  return (
    typeof ours?.recall === "number" &&
    ours.recall > 0 &&
    count(snapshot.n_phishing) >= MIN_PHISHING_SAMPLE &&
    answered >= MIN_PHISHING_CLASSIFIED &&
    unknownRate <= MAX_UNKNOWN_RATE
  );
}

/** True when enough legitimate sites got a verdict to quote a false-positive rate. */
export function falsePositiveRateIsPublishable(snapshot: BenchmarkSnapshot | null): boolean {
  if (!snapshot) return false;
  const ours = snapshot.safe?.[OURS];
  return typeof ours?.fpr === "number" && classified(ours, "tn", "fp") >= MIN_SAFE_CLASSIFIED;
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

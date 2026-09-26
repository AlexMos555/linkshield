import { loadLatestBenchmark, recallIsPublishable } from "./benchmark";

export interface LiveRecall {
  /** 0..1 — exact value from latest.json */
  fraction: number;
  /** Rounded to one decimal place, e.g. 72.7 */
  pct: number;
  /** ISO timestamp of the benchmark run */
  ts: string;
  /** Number of phishing URLs in the run */
  n_phishing: number;
  /** TP / FN / unknown counts (lets the caller mention the "unknown" footnote) */
  tp: number;
  fn: number;
  unknown: number;
}

/**
 * Load Cleanway's measured recall from the most recent weekly fresh-URL
 * benchmark.
 *
 * Returns null when latest.json is missing or its sample does not clear the
 * quality gate in lib/benchmark.ts (the same gate the benchmark script
 * applies). Below that the number is statistically meaningless — e.g. the
 * n=24 / 13-classified snapshot — so callers must render no percentage at
 * all rather than a misleading X%. NEVER hardcode a recall number anywhere
 * else in the landing — point at this helper.
 */
export async function loadLiveRecall(): Promise<LiveRecall | null> {
  const snapshot = await loadLatestBenchmark();
  if (!snapshot || !recallIsPublishable(snapshot)) return null;
  const ours = snapshot.phishing.cleanway;
  const fraction = ours.recall ?? 0;
  return {
    fraction,
    pct: Math.round(fraction * 1000) / 10,
    ts: snapshot.ts ?? "",
    n_phishing: snapshot.n_phishing ?? 0,
    tp: ours.tp,
    fn: ours.fn,
    unknown: ours.unknown,
  };
}

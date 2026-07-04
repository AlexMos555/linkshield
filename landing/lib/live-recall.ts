import fs from "node:fs/promises";
import path from "node:path";

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
 * Returns null when:
 *   - latest.json is missing or malformed
 *   - Cleanway's recall is null in that snapshot (e.g. every URL came back
 *     "unknown" because the API was rate-limited mid-run)
 *
 * Callers should render a soft fallback ("Privacy-first protection —
 * published weekly recall") instead of a hard "X%" claim when this
 * returns null. NEVER hardcode a recall number anywhere else in the
 * landing — point at this helper.
 */
export async function loadLiveRecall(): Promise<LiveRecall | null> {
  const candidates = [
    path.join(process.cwd(), "..", "docs", "benchmarks", "latest.json"),
    path.join(process.cwd(), "docs", "benchmarks", "latest.json"),
  ];
  for (const p of candidates) {
    try {
      const raw = await fs.readFile(p, "utf-8");
      const data = JSON.parse(raw) as {
        ts?: string;
        n_phishing?: number;
        phishing?: {
          cleanway?: {
            tp?: number;
            fn?: number;
            unknown?: number;
            recall?: number | null;
          };
        };
      };
      const cw = data?.phishing?.cleanway;
      const nPhishing = data.n_phishing ?? 0;
      const classified =
        (typeof cw?.tp === "number" ? cw.tp : 0) +
        (typeof cw?.fn === "number" ? cw.fn : 0);
      // Self-consistency with the benchmark quality gate
      // (scripts/eval_fresh_urls.check_quality_gate): never surface a hard
      // recall % from a sample the project's own tooling would reject. The
      // gate requires n_phishing >= 100 and >= 50 classified. Below that the
      // number is statistically meaningless (e.g. the n=24 / 13-classified
      // snapshot), so we return null and the caller renders the soft
      // "recall published weekly" fallback instead of a misleading X%.
      const MIN_N_PHISHING = 100;
      const MIN_CLASSIFIED = 50;
      if (
        cw &&
        typeof cw.recall === "number" &&
        cw.recall > 0 &&
        typeof cw.tp === "number" &&
        typeof cw.fn === "number" &&
        typeof cw.unknown === "number" &&
        nPhishing >= MIN_N_PHISHING &&
        classified >= MIN_CLASSIFIED
      ) {
        return {
          fraction: cw.recall,
          pct: Math.round(cw.recall * 1000) / 10,
          ts: data.ts ?? "",
          n_phishing: data.n_phishing ?? 0,
          tp: cw.tp,
          fn: cw.fn,
          unknown: cw.unknown,
        };
      }
      return null;
    } catch {
      continue;
    }
  }
  return null;
}

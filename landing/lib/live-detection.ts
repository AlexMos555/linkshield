import { detectionFigures, loadLatestBenchmark, type DetectionFigures } from "./benchmark";

/**
 * Cleanway's detection figure from the most recent weekly fresh-URL
 * benchmark (docs/benchmarks/latest.json), for the home page's badge.
 *
 * Null when latest.json is missing, is a method 1 report (every run before
 * 2026-11-03, whose counts cannot give this figure) or does not clear the
 * quality gate in lib/benchmark.ts (the same gate the benchmark script
 * applies). Callers then render no percentage at all rather than a misleading
 * one. NEVER hardcode a detection number anywhere else in the landing — point
 * at this helper or at lib/benchmark.ts detectionFigures.
 */
export async function loadLiveDetection(): Promise<DetectionFigures | null> {
  return detectionFigures(await loadLatestBenchmark());
}

# Cleanway fresh-URL benchmark

**Run**: 2026-06-29T12:54:14Z  •  **Sample**: 50 phishing + 50 legit

## Sources
- **phishing**: URLhaus daily feed (50 URLs) + PhishTank online-valid (50 URLs), deduplicated by registrable domain.
- **legit**: Tranco top-1M rank 100-100000, random sample (seed=42).
- **cleanway_api**: https://api.cleanway.ai

## Phishing batch (expected: dangerous)

| Resolver | Recall | Precision | F1 | FP | TP | FN | Unknown | p50 ms |
|---|---|---|---|---|---|---|---|---|
| cleanway | 72.7% | 100.0% | 84.2% | 0 | 16 | 6 | 28 | 3688 |
| gsb | — | — | — | 0 | 0 | 0 | 50 | — |
| phishtank | 100.0% | 100.0% | 100.0% | 0 | 21 | 0 | 29 | 318 |
| cloudflare_families | 58.0% | 100.0% | 73.4% | 0 | 29 | 21 | 0 | 30 |

## Safe batch (expected: safe → measure FPR)

| Resolver | FPR | FP | TN | Unknown | p50 ms |
|---|---|---|---|---|---|
| cleanway | — | 0 | 0 | 50 | 378 |
| gsb | — | 0 | 0 | 50 | — |
| phishtank | — | 0 | 0 | 50 | 13 |
| cloudflare_families | 0.00% | 0 | 36 | 14 | 30 |

## Methodology

- Phishing samples are fresh URLhaus + PhishTank entries; the Cleanway ML model has NOT been trained on these specific URLs.
- Legit samples are random Tranco top-100k entries (rank 100-100000), skipping the top-100 to avoid 'too easy' baseline reputation.
- We send DOMAIN only to Cleanway (server-blind invariant). GSB / PhishTank / VT receive the full URL.
- 'Unknown' = the resolver didn't return a definitive verdict (rate-limited, not indexed, error). 'Unknown' is NOT counted as either correct or incorrect — it's reported separately.
- VirusTotal verdict is 'dangerous' iff ≥2 vendors out of 70+ flag the URL.
- Cloudflare 1.1.1.1 for Families is treated as 'dangerous' on NXDOMAIN or 0.0.0.0 sinkhole response.
- Cleanway's 'caution' band is reported as 'unknown' here so the binary comparison is apples-to-apples. The raw JSON shows the per-resolver level distribution.

**Reproduce**: `python3 scripts/eval_fresh_urls.py` (set `VT_API_KEY` for VirusTotal).
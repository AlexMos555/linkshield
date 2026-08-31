# Cleanway fresh-URL benchmark

**Run**: 2026-08-24T07:04:25Z  •  **Sample**: 60 phishing + 60 legit

## Sources
- **phishing**: URLhaus daily feed (60 URLs) + PhishTank online-valid (60 URLs), deduplicated by registrable domain.
- **legit**: Tranco top-1M rank 100-100000, random sample (seed=42).
- **cleanway_api**: https://api.cleanway.ai

## Phishing batch (expected: dangerous)

| Resolver | Recall | Precision | F1 | FP | TP | FN | Unknown | p50 ms |
|---|---|---|---|---|---|---|---|---|
| cleanway | 94.6% | 100.0% | 97.2% | 0 | 35 | 2 | 23 | 3477 |
| gsb | 8.3% | 100.0% | 15.4% | 0 | 5 | 55 | 0 | 15 |
| phishtank | 100.0% | 100.0% | 100.0% | 0 | 31 | 0 | 29 | 183 |
| cloudflare_families | 94.9% | 100.0% | 97.4% | 0 | 56 | 3 | 1 | 13 |
| virustotal | 91.7% | 100.0% | 95.7% | 0 | 55 | 5 | 0 | 312 |

## Safe batch (expected: safe → measure FPR)

| Resolver | FPR | FP | TN | Unknown | p50 ms |
|---|---|---|---|---|---|
| cleanway | — | 0 | 0 | 60 | 25547 |
| gsb | 0.00% | 0 | 60 | 0 | 15 |
| phishtank | — | 0 | 0 | 60 | 11 |
| cloudflare_families | 3.92% | 2 | 49 | 9 | 38 |
| virustotal | 1.67% | 1 | 59 | 0 | 337 |

## Methodology

- Phishing samples are fresh URLhaus + PhishTank entries; the Cleanway ML model has NOT been trained on these specific URLs.
- Legit samples are random Tranco top-100k entries (rank 100-100000), skipping the top-100 to avoid 'too easy' baseline reputation.
- We send DOMAIN only to Cleanway (server-blind invariant). GSB / PhishTank / VT receive the full URL.
- 'Unknown' = the resolver didn't return a definitive verdict (rate-limited, not indexed, error). 'Unknown' is NOT counted as either correct or incorrect — it's reported separately.
- VirusTotal verdict is 'dangerous' iff ≥2 vendors out of 70+ flag the URL.
- Cloudflare 1.1.1.1 for Families is treated as 'dangerous' on NXDOMAIN or 0.0.0.0 sinkhole response.
- Cleanway's 'caution' band is reported as 'unknown' here so the binary comparison is apples-to-apples. The raw JSON shows the per-resolver level distribution.

**Reproduce**: `python3 scripts/eval_fresh_urls.py` (set `VT_API_KEY` for VirusTotal).
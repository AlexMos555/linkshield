# Cleanway fresh-URL benchmark

**Run**: 2026-08-17T07:00:54Z  •  **Sample**: 60 phishing + 60 legit

## Sources
- **phishing**: URLhaus daily feed (60 URLs) + PhishTank online-valid (60 URLs), deduplicated by registrable domain.
- **legit**: Tranco top-1M rank 100-100000, random sample (seed=42).
- **cleanway_api**: https://api.cleanway.ai

## Phishing batch (expected: dangerous)

| Resolver | Recall | Precision | F1 | FP | TP | FN | Unknown | p50 ms |
|---|---|---|---|---|---|---|---|---|
| cleanway | 80.4% | 100.0% | 89.1% | 0 | 45 | 11 | 4 | 1409 |
| gsb | 23.3% | 100.0% | 37.8% | 0 | 14 | 46 | 0 | 7 |
| phishtank | 100.0% | 100.0% | 100.0% | 0 | 43 | 0 | 17 | 101 |
| cloudflare_families | 68.4% | 100.0% | 81.3% | 0 | 39 | 18 | 3 | 9 |
| virustotal | 96.7% | 100.0% | 98.3% | 0 | 58 | 2 | 0 | 227 |

## Safe batch (expected: safe → measure FPR)

| Resolver | FPR | FP | TN | Unknown | p50 ms |
|---|---|---|---|---|---|
| cleanway | — | 0 | 0 | 60 | 25548 |
| gsb | 0.00% | 0 | 60 | 0 | 6 |
| phishtank | — | 0 | 0 | 60 | 6 |
| cloudflare_families | 3.92% | 2 | 49 | 9 | 16 |
| virustotal | 1.67% | 1 | 59 | 0 | 255 |

## Methodology

- Phishing samples are fresh URLhaus + PhishTank entries; the Cleanway ML model has NOT been trained on these specific URLs.
- Legit samples are random Tranco top-100k entries (rank 100-100000), skipping the top-100 to avoid 'too easy' baseline reputation.
- We send DOMAIN only to Cleanway (server-blind invariant). GSB / PhishTank / VT receive the full URL.
- 'Unknown' = the resolver didn't return a definitive verdict (rate-limited, not indexed, error). 'Unknown' is NOT counted as either correct or incorrect — it's reported separately.
- VirusTotal verdict is 'dangerous' iff ≥2 vendors out of 70+ flag the URL.
- Cloudflare 1.1.1.1 for Families is treated as 'dangerous' on NXDOMAIN or 0.0.0.0 sinkhole response.
- Cleanway's 'caution' band is reported as 'unknown' here so the binary comparison is apples-to-apples. The raw JSON shows the per-resolver level distribution.

**Reproduce**: `python3 scripts/eval_fresh_urls.py` (set `VT_API_KEY` for VirusTotal).
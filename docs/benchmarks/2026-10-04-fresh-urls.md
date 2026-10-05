# Cleanway fresh-URL benchmark

**Run**: 2026-10-04T20:24:32Z  •  **Sample**: 200 phishing + 200 legit

## Sources
- **phishing**: URLhaus daily feed (200 URLs) + PhishTank online-valid (200 URLs), deduplicated by registrable domain.
- **legit**: data/benchmark_legit_ru.txt: 200 of 271 real Russian sites outside the Tranco top-100k (regional and city government, universities, .рф, small banks and businesses, museums, theatres), random sample (seed=42); 47 were unreachable from outside Russia when listed.
- **legit_outside_allowlist**: True
- **cleanway_api**: https://api.cleanway.ai
- **cleanway_identity**: 4 rotating installs (X-Cleanway-Install), a new id every 50 checks, one check per install every 16s, at most 1400 an hour from one IP

## Phishing batch (expected: dangerous)

| Resolver | Recall | Precision | F1 | FP | TP | FN | Unknown | p50 ms |
|---|---|---|---|---|---|---|---|---|
| cleanway | 98.5% | 100.0% | 99.2% | 0 | 192 | 3 | 5 | 2393 |
| gsb | 9.0% | 100.0% | 16.5% | 0 | 18 | 182 | 0 | 6 |
| phishtank | — | — | — | 0 | 0 | 0 | 200 | 7 |
| cloudflare_families | 69.2% | 100.0% | 81.8% | 0 | 45 | 20 | 135 | 19 |
| virustotal | 99.0% | 100.0% | 99.5% | 0 | 193 | 2 | 5 | 252 |

## Safe batch (expected: safe → measure FPR)

| Resolver | FPR | FP | TN | Unknown | p50 ms |
|---|---|---|---|---|---|
| cleanway | 0.00% | 0 | 130 | 70 | 3247 |
| gsb | 0.00% | 0 | 200 | 0 | 6 |
| phishtank | — | 0 | 0 | 200 | 7 |
| cloudflare_families | 0.00% | 0 | 198 | 2 | 267 |
| virustotal | 0.59% | 1 | 169 | 30 | 292 |

## Cleanway on the legitimate sample

Every site here is real and outside the list our server trusts without analysis. 'dangerous' is a false positive; 'caution' is not counted in the FPR above but is shown, because a warning on a bank's or a government's own site is a harm too.

| Slice | safe | caution | dangerous | not found | no answer |
|---|---|---|---|---|---|
| all | 130 | 70 | 0 | 0 | 0 |
| reachable-abroad | 102 | 51 | 0 | 0 | 0 |
| blocked-abroad | 28 | 19 | 0 | 0 | 0 |
| category: bank | 10 | 3 | 0 | 0 | 0 |
| category: business | 23 | 11 | 0 | 0 | 0 |
| category: city | 16 | 15 | 0 | 0 | 0 |
| category: museum | 6 | 10 | 0 | 0 | 0 |
| category: regional_gov | 26 | 5 | 0 | 0 | 0 |
| category: rf | 19 | 12 | 0 | 0 | 0 |
| category: theatre | 6 | 5 | 0 | 0 | 0 |
| category: university | 24 | 9 | 0 | 0 | 0 |

## Methodology

- Phishing samples are fresh URLhaus + PhishTank entries; the Cleanway ML model has NOT been trained on these specific URLs.
- Legit samples are real Russian sites OUTSIDE the Tranco top-100k — regional and city government, universities, .рф, small banks and businesses, museums, theatres (data/benchmark_legit_ru.txt, each with its source). The server analyses every one of them; none gets the instant 'safe' popular sites get.
- We send DOMAIN only to Cleanway (server-blind invariant). GSB / PhishTank / VT receive the full URL.
- Cleanway requests identify as: 4 rotating installs (X-Cleanway-Install), a new id every 50 checks, one check per install every 16s, at most 1400 an hour from one IP. Each check may use the service's daily paid-source budgets; checks past a cap run without that source, as a user's would. Phishing and legitimate URLs are interleaved, so both batches meet the same budget state. The Cleanway checks ran 2026-10-04T18:38:02Z – 2026-10-04T19:04:17Z.
- 'Unknown' = the resolver didn't return a definitive verdict (rate-limited, not indexed, error). 'Unknown' is NOT counted as either correct or incorrect — it's reported separately.
- VirusTotal verdict is 'dangerous' iff ≥2 vendors out of 70+ flag the URL.
- Cloudflare 1.1.1.1 for Families is treated as 'dangerous' on a 0.0.0.0 sinkhole, or on NXDOMAIN only when Cloudflare's unfiltered resolver still resolves the name. A domain that no longer exists (NXDOMAIN everywhere) is 'unknown' for every resolver, not a catch.
- Cleanway's 'caution' band is reported as 'unknown' here so the binary comparison is apples-to-apples. The raw JSON shows the per-resolver level distribution.

**Reproduce**: `python3 scripts/eval_fresh_urls.py` (set `VT_API_KEY` for VirusTotal).
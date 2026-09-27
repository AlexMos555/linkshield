# Cleanway fresh-URL benchmark

**Run**: 2026-09-27T20:45:14Z  •  **Sample**: 200 phishing + 200 legit

## Sources
- **phishing**: URLhaus daily feed (200 URLs) + PhishTank online-valid (200 URLs), deduplicated by registrable domain.
- **legit**: data/benchmark_legit_ru.txt: 200 of 271 real Russian sites outside the Tranco top-100k (regional and city government, universities, .рф, small banks and businesses, museums, theatres), random sample (seed=42); 47 were unreachable from outside Russia when listed.
- **legit_outside_allowlist**: True
- **cleanway_api**: https://api.cleanway.ai
- **cleanway_identity**: 4 rotating installs (X-Cleanway-Install), a new id every 50 checks, one check per install every 16s, at most 1400 an hour from one IP

## Phishing batch (expected: dangerous)

| Resolver | Recall | Precision | F1 | FP | TP | FN | Unknown | p50 ms |
|---|---|---|---|---|---|---|---|---|
| cleanway | 97.9% | 100.0% | 99.0% | 0 | 190 | 4 | 6 | 1507 |
| gsb | 14.0% | 100.0% | 24.6% | 0 | 28 | 172 | 0 | 24 |
| phishtank | — | — | — | 0 | 0 | 0 | 200 | 11 |
| cloudflare_families | 69.8% | 100.0% | 82.2% | 0 | 67 | 29 | 104 | 62 |
| virustotal | 86.5% | 100.0% | 92.8% | 0 | 173 | 27 | 0 | 254 |

## Safe batch (expected: safe → measure FPR)

| Resolver | FPR | FP | TN | Unknown | p50 ms |
|---|---|---|---|---|---|
| cleanway | 1.54% | 2 | 128 | 70 | 3275 |
| gsb | 0.00% | 0 | 200 | 0 | 24 |
| phishtank | — | 0 | 0 | 200 | 12 |
| cloudflare_families | 0.00% | 0 | 200 | 0 | 164 |
| virustotal | 0.59% | 1 | 169 | 30 | 260 |

## Cleanway on the legitimate sample

Every site here is real and outside the list our server trusts without analysis. 'dangerous' is a false positive; 'caution' is not counted in the FPR above but is shown, because a warning on a bank's or a government's own site is a harm too.

| Slice | safe | caution | dangerous | not found | no answer |
|---|---|---|---|---|---|
| all | 128 | 70 | 2 | 0 | 0 |
| reachable-abroad | 97 | 55 | 1 | 0 | 0 |
| blocked-abroad | 31 | 15 | 1 | 0 | 0 |
| category: bank | 9 | 4 | 0 | 0 | 0 |
| category: business | 21 | 13 | 0 | 0 | 0 |
| category: city | 18 | 11 | 2 | 0 | 0 |
| category: museum | 6 | 10 | 0 | 0 | 0 |
| category: regional_gov | 27 | 4 | 0 | 0 | 0 |
| category: rf | 16 | 15 | 0 | 0 | 0 |
| category: theatre | 6 | 5 | 0 | 0 | 0 |
| category: university | 25 | 8 | 0 | 0 | 0 |

## Methodology

- Phishing samples are fresh URLhaus + PhishTank entries; the Cleanway ML model has NOT been trained on these specific URLs.
- Legit samples are real Russian sites OUTSIDE the Tranco top-100k — regional and city government, universities, .рф, small banks and businesses, museums, theatres (data/benchmark_legit_ru.txt, each with its source). The server analyses every one of them; none gets the instant 'safe' popular sites get.
- We send DOMAIN only to Cleanway (server-blind invariant). GSB / PhishTank / VT receive the full URL.
- Cleanway requests identify as: 4 rotating installs (X-Cleanway-Install), a new id every 50 checks, one check per install every 16s, at most 1400 an hour from one IP. Each check may use the service's daily paid-source budgets; checks past a cap run without that source, as a user's would. Phishing and legitimate URLs are interleaved, so both batches meet the same budget state. The Cleanway checks ran 2026-09-27T18:58:43Z – 2026-09-27T19:24:58Z.
- 'Unknown' = the resolver didn't return a definitive verdict (rate-limited, not indexed, error). 'Unknown' is NOT counted as either correct or incorrect — it's reported separately.
- VirusTotal verdict is 'dangerous' iff ≥2 vendors out of 70+ flag the URL.
- Cloudflare 1.1.1.1 for Families is treated as 'dangerous' on a 0.0.0.0 sinkhole, or on NXDOMAIN only when Cloudflare's unfiltered resolver still resolves the name. A domain that no longer exists (NXDOMAIN everywhere) is 'unknown' for every resolver, not a catch.
- Cleanway's 'caution' band is reported as 'unknown' here so the binary comparison is apples-to-apples. The raw JSON shows the per-resolver level distribution.

**Reproduce**: `python3 scripts/eval_fresh_urls.py` (set `VT_API_KEY` for VirusTotal).
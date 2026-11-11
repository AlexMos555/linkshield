# Cleanway fresh-URL benchmark

**Run**: 2026-11-08T20:05:35Z  •  **Sample**: 200 phishing + 200 legit

## Sources
- **phishing**: PhishTank online-valid (200 URLs), deduplicated by registrable domain.
- **legit**: data/benchmark_legit_ru.txt: 200 of 249 real Russian sites outside the allowlist's top 100,000 (Majestic Million + Chrome UX Report; regional and city government, universities, .рф, small banks and businesses, museums, theatres), random sample (seed=42); 42 were unreachable from outside Russia when listed.
- **legit_outside_allowlist**: True
- **cleanway_api**: https://api.cleanway.ai
- **cleanway_identity**: 4 rotating installs (X-Cleanway-Install), a new id every 50 checks, one check per install every 16s, at most 1400 an hour from one IP

## Phishing batch (expected: dangerous)

| Resolver | Recall | Precision | F1 | FP | TP | FN | Unknown | p50 ms |
|---|---|---|---|---|---|---|---|---|
| cleanway | 94.8% | 100.0% | 97.3% | 0 | 164 | 9 | 27 | 454 |
| phishtank | 100.0% | 100.0% | 100.0% | 0 | 50 | 0 | 150 | 21 |
| cloudflare_families | 74.7% | 100.0% | 85.5% | 0 | 148 | 50 | 2 | 17 |

## Safe batch (expected: safe → measure FPR)

| Resolver | FPR | FP | TN | Unknown | p50 ms |
|---|---|---|---|---|---|
| cleanway | 0.00% | 0 | 133 | 67 | 942 |
| phishtank | — | 0 | 0 | 200 | 20 |
| cloudflare_families | 0.00% | 0 | 200 | 0 | 374 |

## Cleanway on the legitimate sample

Every site here is real and outside the list our server trusts without analysis. 'dangerous' is a false positive; 'caution' is not counted in the FPR above but is shown, because a warning on a bank's or a government's own site is a harm too.

| Slice | safe | caution | dangerous | not found | no answer |
|---|---|---|---|---|---|
| all | 133 | 67 | 0 | 0 | 0 |
| reachable-abroad | 106 | 52 | 0 | 0 | 0 |
| blocked-abroad | 27 | 15 | 0 | 0 | 0 |
| category: bank | 8 | 6 | 0 | 0 | 0 |
| category: business | 18 | 12 | 0 | 0 | 0 |
| category: city | 23 | 12 | 0 | 0 | 0 |
| category: museum | 6 | 8 | 0 | 0 | 0 |
| category: regional_gov | 30 | 2 | 0 | 0 | 0 |
| category: rf | 14 | 20 | 0 | 0 | 0 |
| category: theatre | 7 | 3 | 0 | 0 | 0 |
| category: university | 27 | 4 | 0 | 0 | 0 |

## Methodology

- Phishing samples are fresh PhishTank entries (online-valid dump; until 2026-10-21 also URLhaus, which then closed anonymous downloads — earlier runs are a different mix); the Cleanway ML model has NOT been trained on these specific URLs.
- Legit samples are real Russian sites OUTSIDE the top 100,000 the server trusts on sight (Majestic Million + Chrome UX Report; Tranco's until 2026-10-23) — regional and city government, universities, .рф, small banks and businesses, museums, theatres (data/benchmark_legit_ru.txt, each with its source). The server analyses every one of them; none gets the instant 'safe' popular sites get.
- We send DOMAIN only to Cleanway (server-blind invariant) and to Cloudflare (a DNS lookup). PhishTank receives the full URL.
- Cleanway requests identify as: 4 rotating installs (X-Cleanway-Install), a new id every 50 checks, one check per install every 16s, at most 1400 an hour from one IP. Each check may use the service's daily paid-source budgets; checks past a cap run without that source, as a user's would. Phishing and legitimate URLs are interleaved, so both batches meet the same budget state. The Cleanway checks ran 2026-11-08T19:39:22Z – 2026-11-08T20:05:35Z.
- 'Unknown' = the resolver didn't return a definitive verdict (rate-limited, not indexed, error). 'Unknown' is NOT counted as either correct or incorrect — it's reported separately.
- Not compared: VirusTotal (its public API "must not be used in commercial products or services" — docs.virustotal.com/reference/public-vs-premium-api) and Google Safe Browsing (its v4 API is "for non-commercial use only", Google sells the same lookup as Web Risk — developers.google.com/safe-browsing/v4). Cleanway is a commercial product. Earlier runs in docs/benchmarks/ include them.
- Cloudflare 1.1.1.1 for Families is treated as 'dangerous' on a 0.0.0.0 sinkhole, or on NXDOMAIN only when Cloudflare's unfiltered resolver still resolves the name. A domain that no longer exists (NXDOMAIN everywhere) is 'unknown' for every resolver, not a catch.
- Cleanway's 'caution' band is reported as 'unknown' here so the binary comparison is apples-to-apples. The raw JSON shows the per-resolver level distribution.

**Reproduce**: `python3 scripts/eval_fresh_urls.py`.
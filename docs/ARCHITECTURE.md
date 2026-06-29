# Cleanway architecture

> Last updated: 2026-06-29. Update this file when changing the verdict pipeline, adding/removing intel sources, or changing the privacy invariants.

## TL;DR

A user visits a URL. The browser extension extracts the **registrable domain only** and sends it to the API. The API runs an 18-check fan-out across intel sources, ML model, popularity, brand-clone, and typosquat detectors, then returns a verdict + confidence. Caution-band verdicts are optionally re-scored by an LLM Judge. The full URL never leaves the user's device.

## Verdict pipeline (request lifecycle)

```
[browser/mobile/landing]
        |
        | POST /api/v1/check  { domain: "example.com" }   <- domain only, never full URL
        v
[FastAPI]
        |
        | 1. Rate limit (Redis sliding window per user / IP)
        | 2. SSRF guard (domain_validator.py - reject private/loopback/metadata)
        | 3. Cache lookup (24h Redis TTL)
        | 4. Analyzer fan-out (asyncio.gather across ~18 checks):
        |       - safe_browsing      (Google Safe Browsing v4)
        |       - phishtank          (PhishTank online-valid)
        |       - urlhaus            (abuse.ch URLhaus)
        |       - phishstats         (PhishStats)
        |       - threatfox          (abuse.ch ThreatFox)
        |       - malware_bazaar     (abuse.ch MalwareBazaar)
        |       - feodo_tracker      (abuse.ch Feodo)
        |       - spamhaus_dbl       (Spamhaus DBL)
        |       - surbl              (SURBL)
        |       - alienvault_otx     (AlienVault OTX)
        |       - ipqualityscore     (IPQualityScore)
        |       - whois_age          (RDAP - domain age)
        |       - ssl                (TLS issuer + age)
        |       - security_headers   (HSTS / CSP presence)
        |       - dns                (NS / MX patterns)
        |       - redirect_chain     (redirect graph)
        |       - tranco             (top-1M popularity -> negative weight)
        |       - favicon_hash       (brand-clone gallery, sha-256 prefix)
        |       - watchtower        (typosquat - Levenshtein + crt.sh)
        |
        | 5. Each check is wrapped by a named CircuitBreaker.
        |    Failure threshold + cooldown configured per-integration.
        |    Trip -> fallback value, NEVER an exception. Pipeline always ships a verdict.
        |
        | 6. ML scorer (CatBoost, 27 features) emits raw probability.
        |    Conformal calibration -> confidence_pct in [50, 99].
        |
        | 7. Rule engine (scoring.py) combines fan-out signals + ML score.
        |    Verdict in {safe, caution, dangerous}. Each contributing signal
        |    is attached to the response for the block-page explainer.
        |
        | 8. LLM Judge (Strategy #21) - fires only if:
        |       - verdict is in the caution band
        |       - no blocklist hit
        |       - ANTHROPIC_API_KEY present
        |    Sends DOMAIN-FREE feature vector (SAFE_KEYS whitelist) to Claude
        |    Haiku 4.5. sha256 cache. Result clamped to +/- 20 score shift. 4s timeout.
        |    Crash -> silent no-op (verdict ships unchanged).
        |
        | 9. Cache write (24h). Audit-log write (user-action only).
        v
[response]
   {
     domain, verdict, confidence_pct, signals[], explainer,
     llm_judge: { fired: bool, shift: int, reason: str | null }
   }
```

## Server-blind URL flow

The **single most important invariant**: full URLs never leave the device.

- Extension content script extracts `getRegistrableDomain(href)` using the public suffix list.
- Path / query / fragment are dropped before the network call.
- API logs (structured JSON) scrub anything that looks like a URL path, JWT, Bearer header, or IP. See `api/services/sentry_scrubber.py` and `api/services/logger.py`.
- Sentry breadcrumbs: PII scrubber enabled, full URL fields blocked.
- Family alerts: AES-256-GCM payload, server stores ciphertext only - content is undecryptable server-side.
- Breach Check: HIBP k-anonymity (SHA-1 prefix 5 chars sent, 35-char match done locally).
- Pwned Password: same protocol on blur, plaintext never leaves the page boundary (no WeakMap retention, no Referer leak).

If the server were breached tomorrow, attackers would get: emails, subscription tiers, device hashes, weekly aggregate counts. They would not get: a single URL the user visited, family alert contents, or any password.

## Circuit breakers + graceful degradation

Every external dependency is wrapped by `CircuitBreaker(name, failure_threshold, cooldown_seconds, fallback)` from `api/services/circuit_breaker.py`. Currently 20+ named breakers. The contract:

- Open state -> return `fallback` immediately, log breaker name + reason.
- Cooldown elapses -> half-open: one canary request. Success -> close. Failure -> re-open.
- `/health` endpoint exposes breaker states for ops.
- **Verdict always ships.** Even if every external integration is down, the verdict falls through to rule-based scoring on URL features alone.

## Open vs closed boundary (per docs/OPEN-SOURCE.md plan)

**Open** (proposed `cleanway-ai/cleanway-engine`, MIT):
- `api/services/{analyzer,scoring,llm_judge,watchtower,favicon_hash,tranco,doh_gateway,competitor_verdicts}.py`
- `ml/train_model.py` + 27-feature extractor
- `scripts/eval_fresh_urls.py` - the credibility moat
- `packages/extension-core/src/content/block-page.js`

**Closed** (stays private):
- Stripe wiring, family-hub crypto, audit log, trained model weights (`data/phishing_model.cbm`), brand favicon gallery hashes, intel-source API keys, customer-facing copy.

## Where to look for what

| Concern | File |
|---|---|
| Verdict pipeline | `api/services/analyzer.py` |
| Per-integration circuit breaker | `api/services/circuit_breaker.py` |
| Rule weights + thresholds | `api/services/scoring.py` |
| ML feature extraction | `api/services/ml_features.py`, `api/services/url_features.py` |
| ML scoring + conformal calibration | `api/services/ml_scorer.py` |
| LLM Judge | `api/services/llm_judge.py` |
| Typosquat Watchtower | `api/services/watchtower.py`, `api/services/watchtower_lookup.py` |
| Brand favicon gallery | `api/services/favicon_hash.py` |
| Tranco popularity | `api/services/tranco.py`, `scripts/refresh_tranco.py` |
| DoH gateway | `api/services/doh_gateway.py` |
| SSRF guard | `api/services/domain_validator.py` |
| Audit log | `api/services/audit_log.py`, migration `014_audit_log.sql` |
| Privacy headers / scrubbing | `api/services/security_headers.py`, `api/services/sentry_scrubber.py`, `api/services/logger.py` |
| Public endpoint (rate-limited, full fan-out) | `api/routers/public.py` |
| Transparency endpoint | `api/routers/transparency.py` |
| Reproducible benchmark | `scripts/eval_fresh_urls.py` |

## Related docs

- [docs/architecture/README.md](architecture/README.md) - monorepo layout + invariants I1-I5
- [docs/architecture/environments.md](architecture/environments.md) - env-by-env config
- [docs/OPEN-SOURCE.md](OPEN-SOURCE.md) - open/closed carve-out plan
- [docs/benchmarks/latest.json](benchmarks/latest.json) - published metrics
- [docs/transparency/2026-q2.json](transparency/2026-q2.json) - quarterly FP-rate disclosure
- [SECURITY.md](../SECURITY.md) - threat model, T1-T6 attacker classes

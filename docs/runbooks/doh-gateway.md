# Runbook: the DoH gateway (`/dns-query`)

Written 2026-10-09, when the gateway was hardened to become the system-wide
resolver of every iPhone with the DNS shield on (NEDNSSettingsManager — see
docs/MOBILE_AUTO_PROTECTION.md). On iOS there is **no fallback resolver**: if
this endpoint does not answer, nothing on the phone resolves. Everything below
follows from that.

## How a query is answered

```
DohFastPath (raw ASGI, outermost; api/services/doh_fastpath.py)
  → per-IP budget, in process            (rate_limiter.doh_rate_check)
  → blocklist decision, in memory        (api/services/doh_filter.py)
       hash of any suffix listed? → confirm with ONE Redis SISMEMBER → NXDOMAIN
  → response cache, in memory            (api/services/doh_cache.py)
  → upstreams: Cloudflare, then Quad9    (api/services/doh_upstream.py)
       HTTP/2 pool · immediate failover on error · hedge after 400 ms · breaker
  → stale cached answer (RFC 8767, TTL 30 s)
  → SERVFAIL  (only when no upstream answered in 4 s and nothing was cached)
```

* **Blocklist in memory.** Each worker holds the same v2 artifact phones sync
  (sorted 48-bit SHA-256 prefixes, ~3.5 MB as `array('Q')`), refreshed every
  30 s by comparing the published sha256 (`dangerous_domains:mobile:v1:meta`)
  and downloading the body only when it changed. ~98% of queries never touch
  Redis. A hash hit is confirmed against the exact `dangerous_domains` set
  (removes the 48-bit collision risk; deleting the set stays an instant
  server-side kill switch). Redis down → the hash alone decides.
* **Cold start / no artifact** → the old per-query Redis suffix walk, with a
  150 ms deadline and a breaker (3 failures → Redis skipped for 5 s).
* **Response cache.** Per worker, LRU of 20k answers (~10 MB), TTL = the
  smallest TTL in the answer (capped at 1 h; negative answers per RFC 2308),
  TTLs decremented when served, the client's own ID and question case echoed.
  Queries with ECS / cookies / any EDNS option other than padding are never
  cached. The blocklist check always runs first, so a cached answer can never
  outlive a new listing. Identical concurrent misses are coalesced.
* **Upstreams.** `https://cloudflare-dns.com/dns-query`, then
  `https://dns.quad9.net/dns-query` (Quad9's endpoint without ECS). Query bytes
  are forwarded unchanged: EDNS0 and padding pass through, no ECS is added.
  An answer is believed only if it is HTTP 200, 12..65535 bytes and carries
  the query's ID. A pooled connection closed by the server (HTTP/2 GOAWAY) is
  retried once in place.

## Decision: fail open

Nothing that goes wrong **on our side** may stop a query from being answered:
Redis down or slow, the filter not loaded, a bug in the filter, the cache or
the fast path — the query is forwarded upstream unfiltered. Rationale: on iOS
a failed DNS query is "the internet is broken" for every app, for every
install at once, and the user's remedy is to delete the app. A phishing name
missed during an outage is bounded (the phone's own protections still run, the
outage ends); a dark internet is not. The only SERVFAIL we send means "no
upstream answered and nothing was cached" — a stub retries a SERVFAIL, but
would believe (and negatively cache) an NXDOMAIN for every site.

What still blocks during a Redis outage: everything on the last loaded list
(`decision.filter_hit_unconfirmed` in the counters). What does not: names
listed after Redis went away, and — only if the worker started during the
outage and never loaded a list — anything (`decision.redis_down`).

Guards: names in `NEVER_BLOCK_GUARDS` (github.com, google.com, apple.com …)
are never blocked by the gateway even if they reach the list. A `status=revoked`
artifact (the phones' kill switch) makes the gateway block nothing too.

## Privacy

* No per-query log line: the fast path bypasses the request logger, the
  request logger skips `/dns-query` anyway, and the old "DoH blocked qname"
  line (with the name's tail) is gone. uvicorn's access log is at WARNING.
* Aggregates only: `doh_metrics` counters + a latency histogram, one
  `doh_stats` log line every 5 min per worker, the same numbers at
  `/health/doh`. Pinned by `tests/test_doh_resilience.py::test_no_name_or_ip_is_ever_logged`.
* The per-IP budget lives in process memory, keyed by a keyed BLAKE2b of the
  IP (random key per process), cleared every window. No raw IP, no Redis key.
* The answer cache is keyed by the question only, in memory, ≤ 1 h + 6 h
  stale window, gone on restart.

**Open item for the founder:** the public privacy policy §11 says names not
blocked go "to Cloudflare". With the Quad9 failover it should read "to
Cloudflare — or to Quad9 if Cloudflare does not answer" (Quad9 is already
listed as a processor in §3). The policy strings live in
`packages/i18n-strings/src/*.json` and regenerate into `mobile/i18n/` too, so
this PR does not change them. Until then either update the text or set
`DOH_UPSTREAMS=https://cloudflare-dns.com/dns-query,https://1.1.1.1/dns-query`
(same provider, two addresses).

## Measurements (2026-10-09)

Local, one uvicorn worker (uvloop + httptools) on an i5-9600K, real Redis 6
with a 430k-name set + artifact, a fake RFC 8484 upstream over TLS (HTTP/2 +
HTTP/1.1, 15 ms added delay standing in for Cloudflare). Query mix
(`scripts/doh_loadtest.py`): Zipf over the top-5000 names, 30% `www.`,
A/AAAA/HTTPS 45/45/10, 2% listed names, 3% never-seen names, 20% GET, half with
EDNS0 padding. Each row: 20 s, same sequence for both builds, cold start.

| clients | before: req/s · p50 · p95 | after: req/s · p50 · p95 |
|---:|---|---|
| 1 | 46 · 20.9 ms · 23.2 ms | 70 · 19.2 ms · 20.8 ms |
| 16 | 246 · 58.6 ms · 97.9 ms | 842 · 4.8 ms · 51 ms |
| 64 | 156 · 327 ms · 882 ms | 1,646 · 5.6 ms · 161 ms |
| 128 | 164 · 595 ms · 1,898 ms | 1,943 · 3.8 ms · 368 ms |

* Warm cache, 1 client: p50 **1.2 ms** (a cache hit, end to end), p95 19.9 ms
  (a miss = upstream + ~4 ms). Warm, 16 clients: 1,385 req/s, p95 33 ms.
* Without the response cache (every query upstream): 489 req/s at 16 clients
  (p50 30 ms) vs 246 before. Same build with HTTP/1.1 instead of HTTP/2:
  278 req/s — httpcore's HTTP/1.1 pool does O(queued × connections) work per
  request and collapses under concurrency (measured standalone: 64 concurrent
  requests over 64 HTTP/1.1 connections = 54 req/s at 10.9 ms CPU each;
  over one HTTP/2 connection = 768 req/s at 1.2 ms).
* Redis killed mid-run (16 clients): 0 errors, 1,405 req/s, listed names still
  blocked. Before, with Redis refusing connections: answered but nothing
  blocked, and 69 req/s at p50 200 ms (two failed connects and a warning log
  line per query); a *hanging* Redis had no timeout at all.
* Upstream killed: 0 HTTP errors; cached names answered, never-seen names
  SERVFAIL. Primary black-holed (10.255.255.1), Quad9 healthy, 4 clients,
  no cache: p50 22 ms, p95 32 ms, p99 53 ms — the breaker let only 9 queries
  in 15 s pay the 400 ms hedge.
* Memory: ~164 MB RSS per worker at start (most of it the ML model the API
  loads anyway), +~10 MB with 12k cached answers.

What the old path cost per query: two Redis round trips (the SISMEMBER walk
and the rate limiter's EVAL — ~0.5–1 ms each to Railway Redis), the full
FastAPI middleware stack plus an access-log line, and an HTTP/1.1 pool that
also closed idle connections whenever it held more than 32 (an httpcore 1.0
quirk: it counts all connections, not idle ones — so new TLS handshakes to
Cloudflare under load).

Reproduce: see the module docstring of `scripts/doh_loadtest.py`
(`redis-server`, `doh_loadtest.py upstream`, `seed`, the gateway with
`DOH_UPSTREAMS=…`, `run`). Use `DOH_RATE_LIMIT_PER_WINDOW=1000000000` or the
load test hits the per-IP budget.

### Capacity estimate

A phone sends roughly 1–3k DNS queries a day (≈0.02–0.04 q/s, ×3 at peak).
At ~900 req/s — half a worker's saturation point with this mix — one worker
serves on the order of **10k phones at peak**. Latency stays low while a
worker is below ~60% busy; above that, misses queue. Scale on CPU, not memory.

## Scaling on Railway

* **Workers.** uvicorn reads `WEB_CONCURRENCY` (the Procfile/nixpacks start
  command needs no change). One worker per vCPU; each holds its own list and
  cache (~170–200 MB). Set `WEB_CONCURRENCY=2` on a 2-vCPU / 1 GB plan.
* **Replicas.** Railway service → Settings → Replicas ≥ 2, so a crashed or
  redeploying container is not an outage. Replicas share nothing but Redis,
  which the hot path does not need.
* **Rate limit.** The per-IP budget is per worker: the effective ceiling is
  `DOH_RATE_LIMIT_PER_WINDOW × workers × replicas`. That is deliberate — a
  429 to a carrier CGNAT address takes DNS away from everyone behind it.
* **Region.** Put the service in the region closest to the first market (for
  Tele2 / Russia: Railway's EU West, Amsterdam). Every DNS lookup on the phone
  pays the round trip to it.
* **Health check.** Railway's deploy health check: `/health` (liveness).
  DNS readiness: `/health/doh` — 503 only when every upstream's breaker is
  open; body has filter version/age/error, upstream state and the counters.
  Do **not** use `/health/deep` for DNS routing: it goes 503 on a Supabase
  outage, which does not affect DNS.

## Recommended plan: Cloudflare in front, then a second region

Today `dns.cleanway.ai` is a DNS-only CNAME to Railway: one region, one
service. In order of value per effort:

1. **Now (before iOS install volume): replicas + monitoring.** Replicas ≥ 2,
   `WEB_CONCURRENCY` per vCPU, an external monitor on
   `GET https://api.cleanway.ai/health/doh` every minute (alert on non-200,
   or `"loaded":false`, or `age_s` > 46800 — the 13 h artifact threshold).
2. **Before the iOS public release: Cloudflare proxy + edge fail-open.**
   Turn the proxy ON for `dns.cleanway.ai` and route `dns.cleanway.ai/dns-query*`
   to a Worker that forwards to the origin with a ~2 s timeout and, on a
   timeout or a 5xx, re-sends the same bytes to
   `https://cloudflare-dns.com/dns-query`. An origin outage then degrades to
   "unfiltered DNS" instead of "no internet" for every install. Sketch:

   ```js
   export default {
     async fetch(req) {
       const body = req.method === "POST" ? await req.arrayBuffer() : null;
       const init = (url) => new Request(url, { method: req.method, headers: req.headers, body });
       const url = new URL(req.url);
       try {
         const origin = await fetch(init(`https://api.cleanway.ai${url.pathname}${url.search}`),
                                    { signal: AbortSignal.timeout(2000) });
         if (origin.status < 500) return origin;
       } catch (_) {}
       return fetch(init(`https://cloudflare-dns.com/dns-query${url.search}`));
     },
   };
   ```
   Notes: the Worker must not log (no `console.log` of the request; Workers
   Logs off for this route). Behind the proxy the client IP arrives in
   `X-Forwarded-For`: add Cloudflare's IP ranges
   (https://www.cloudflare.com/ips/) to `TRUSTED_PROXY_CIDRS`, or every phone
   shares one rate-limit bucket per Cloudflare edge address. Workers bill per
   request (Paid: $5/month incl. 10M, then $0.30/M) — at 10k phones × ~2k
   queries/day ≈ 600M/month ≈ $180/month; the alternative at that size is
   step 3. Cloudflare already is our upstream, so the proxy adds no new party
   that sees the names.
3. **At scale: a second Railway region + Cloudflare Load Balancing.** Deploy
   the same service in a second region (e.g. US East), keep one Redis (the
   gateway reads it every 30 s plus ~2% of queries for confirmation; slow
   cross-region confirmation simply falls back to the hash), and put a
   Cloudflare Load Balancer (health monitor: `GET /health/doh`, expect 200)
   with geo steering in front of both. Origin outage in one region = traffic
   moves to the other within the monitor interval.

## Operating

**Counters** (`/health/doh` → `stats.counts`, and the `doh_stats` log line):

| counter | means | worry when |
|---|---|---|
| `queries`, `blocked` | totals | — |
| `decision.filter_miss` / `filter_hit` | in-memory list used | — |
| `decision.filter_hit_unconfirmed` | blocked on the hash alone: Redis unreachable | sustained → Redis is down |
| `decision.collision` | hash hit the exact set rejected | rising → set and artifact disagree (publisher bug / rollback window) |
| `decision.redis_hit` / `redis_miss` | no list in memory, per-query Redis fallback | sustained → check `filter.error` |
| `decision.redis_down` | no list AND no Redis: **not filtering** | any |
| `cache_hit` / `cache_miss` / `coalesced` | cache effectiveness | hit ratio < 50% → raise `DOH_CACHE_MAX_ENTRIES` |
| `upstream_failed`, `served_stale`, `servfail` | upstreams unreachable | any sustained `servfail` |
| `rate_limited` | 429s sent | rising → a CGNAT address hit the ceiling; raise the limit |
| `internal_error`, `filter_error`, `cache_error` | a bug, failed open | any |

**`filter.error`**: `no_artifact` (publisher never wrote one / it expired),
`sha_mismatch` (body ≠ meta — publisher bug; the old list is kept),
an exception name (Redis trouble; the old list is kept).

**Config** (env vars, `api/config.py`):

| var | default | |
|---|---|---|
| `DOH_UPSTREAMS` | Cloudflare, Quad9 | comma-separated RFC 8484 URLs, in order |
| `DOH_CACHE_MAX_ENTRIES` | 20000 | 0 disables the cache |
| `DOH_CACHE_MAX_TTL_S` | 3600 | |
| `DOH_SERVE_STALE_S` | 21600 | how long past its TTL an answer may be served while upstreams are down |
| `DOH_FILTER_REFRESH_S` | 30 | artifact sha check interval |
| `DOH_REDIS_TIMEOUT_MS` | 150 | deadline for hit confirmation / cold-start fallback |
| `DOH_FAST_PATH` | true | false = serve through the FastAPI routes (same logic, slower) |
| `DOH_RATE_LIMIT_PER_WINDOW` / `_WINDOW_SECONDS` | 20000 / 3600 | per IP, per worker |

## What the founder must configure (nothing here is done by code)

1. Railway: `WEB_CONCURRENCY` = vCPUs, Replicas ≥ 2, region nearest the
   first market, deploy health check `/health`.
2. External monitor on `/health/doh` (step 1 above).
3. Privacy policy §11: mention the Quad9 failover (see "Privacy"), or pin
   `DOH_UPSTREAMS` to Cloudflare-only until it does.
4. Before iOS launch: Cloudflare proxy + the fail-open Worker (step 2), and
   `TRUSTED_PROXY_CIDRS` extended with Cloudflare's ranges in the same change.
5. Later: second region + load balancer (step 3).

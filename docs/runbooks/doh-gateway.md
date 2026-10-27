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
  → upstreams: Cloudflare by name, then by IP; Quad9 opt-in    (api/services/doh_upstream.py)
       HTTP/2, one connection each · ≤ 96 requests per upstream · per zone ≤ 16
       plus half of the upstream's free slots · immediate failover on error
       · hedge 400 ms after send, into spare room · breaker
  → stale cached answer (RFC 8767, TTL 30 s)
  → SERVFAIL  (no upstream answered in 4 s and nothing was cached — or the
               query got no turn at the upstreams in 4 s: "A zone that never answers")
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
  retried once in place. Requests in flight are limited per upstream and per
  zone, and a request once sent is never cancelled ("A zone that never
  answers" below).

## Decision: fail open

Nothing that goes wrong **on our side** may stop a query from being answered:
Redis down or slow, the filter not loaded, a bug in the filter, the cache or
the fast path — the query is forwarded upstream unfiltered. Rationale: on iOS
a failed DNS query is "the internet is broken" for every app, for every
install at once, and the user's remedy is to delete the app. A phishing name
missed during an outage is bounded (the phone's own protections still run, the
outage ends); a dark internet is not. The only SERVFAIL we send means "no
upstream answered and nothing was cached" — a stub retries a SERVFAIL, but
would believe (and negatively cache) an NXDOMAIN for every site. A cache
miss can also get SERVFAIL without being forwarded, when in 4 s it got no
turn at the upstreams: `upstream_shed` (the worker's
`LOAD_SHED_DNS_UPSTREAM_MAX_INFLIGHT`), or every stream of the upstream
connections taken, or its zone's room at the upstreams taken the whole time
— by names nobody answers, or by a zone that answers but too slowly for the
rate of its queries (the room is 43 requests with the upstream otherwise
idle, 16 when other names hold its slots; stand: 1 s answers at 40 unique
names a second per worker, 16 % of them SERVFAIL; "A zone that never
answers"). The first two are the
upstream connections' capacity: one more request would fail at once. The
zone's room is a choice: it keeps one zone from taking the slots every other
cache miss needs.

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

> Superseded by measured numbers for the whole API (DoH + /check + Redis + cost):
> `docs/runbooks/capacity.md` (2026-10-22).

A phone sends roughly 1–3k DNS queries a day (≈0.02–0.04 q/s, ×3 at peak).
At ~900 req/s — half a worker's saturation point with this mix — one worker
serves on the order of **10k phones at peak**. Latency stays low while a
worker is below ~60% busy; above that, misses queue. Scale on CPU, not memory.

## A zone that never answers (2026-10-23, reworked 2026-10-27 and -28)

**The problem.** Random subdomains of a zone whose authoritative servers
never answer (`r<hex>.dead.example`: a DGA, a broken app, a lame
delegation) are never cached, and each waits the whole 4 s budget.
Cloudflare answers them SERVFAIL, but late: measured 2026-10-28 from a
workstation (not from Railway), 280 random names under four reverse zones whose servers do not
answer (`48.189.in-addr.arpa`, `36.78.202.in-addr.arpa`,
`38.78.202.in-addr.arpa`, `40.78.202.in-addr.arpa`; checked with
`dig +trace`), half to `cloudflare-dns.com`, half to `1.1.1.1`, RFC 8484
POST, at most one query a second: every one HTTP 200 + SERVFAIL with EDE 22
(No Reachable Authority), after 0.1-9.3 s — p50 2.5 s, p90 5.6 s, p99
8.5 s, none past 10 s (2026-10-23: up to ~5.4 s). The first name of a zone
takes longest; once Cloudflare has marked the zone's servers unreachable,
names under it come back in ~1.3 s.
Until 2026-10-23 a worker had 32 upstream slots, hedges included, and ~4-8
such names a second took all of them: every other cache miss queued behind
them. Worse, a request cancelled at the deadline kept its HTTP/2 stream open
at the upstream (httpcore sends no `RST_STREAM`), and at 100 open streams
every new request on that connection failed at once (`LocalProtocolError:
Max outbound streams is 100`). On the stand, 10 % such names in one zone gave
84-90 % of the healthy cache misses SERVFAIL. The first fix (a zone limit of
8, 96 slots shared by both upstreams) was reviewed on 2026-10-27; the
reasons in the list below are what the review found it got wrong.

**How it works** (`api/services/doh_upstream.py`, numbers per worker):

* **A request, once sent, is not cancelled.** It runs until the upstream
  answers, holding its slot, so the slots count the connection's open
  streams. A request still unanswered `REQUEST_TIMEOUT_S` (10 s) after it was
  first sent is given up together with its connection — cancelled alone, its
  stream would stay open all the same; only closing the connection closes
  it. The requests still on that connection fail; those a query waits for
  are re-sent once on a new one. httpx's own read timeout does not bound a
  request over HTTP/2: it times one read on the shared connection, and any
  other stream's data starts it again. Cloudflare's slowest SERVFAIL above
  (9.3 s) came inside this bound, but not by much.
* **Slots per upstream: 96** — each upstream is one HTTP/2 connection with
  100 streams. Cloudflare by name and by IP: 2 × 96. A query goes to the
  first upstream (healthy ones first) with a free slot. Without `h2` the cap
  is the HTTP/1.1 pool's size, 32.
* **Zone room: 16 requests plus half of the upstream's free slots.** The
  zone's requests at the upstreams are counted together (both upstreams,
  hedges included); the free slots are those of the upstream the query is
  about to use. Alone, a zone gets 43 of an upstream's 96 slots: one nobody
  answers leaves the other names 53. The more slots other names hold, the
  closer a zone's room comes to 16. Until the final review (2026-10-27) the
  room was a fixed 16: a zone answering in 1 s at 40 names a second per
  worker got 62-64 % SERVFAIL on the stand while the upstream had 60 slots
  free (row e); now 16.5 %.
  The zone is the query name's parent, never shorter than its registrable
  domain: `r1.dead.example` → `dead.example`, `www.bank.com` → `bank.com` but
  `r1.old.bank.com` → `old.bank.com`, `4.3.2.1.in-addr.arpa` →
  `3.2.1.in-addr.arpa`. A query over its zone's room waits for room without
  holding a slot; a query waiting for a slot does not take its zone's room
  (taken first, a busy zone's own queued queries filled it).
* **A freed slot goes to the newest waiting query whose zone has room** —
  the oldest is the closest to its deadline. So under any slot shortage
  (names nobody answers, but also a slow upstream) the oldest waiting misses
  get SERVFAIL at 4 s instead of every miss arriving late.
* **Hedge: 400 ms after the request was sent, into spare room only** — more
  than half of the target upstream's slots free, fewer than 8 of the zone's
  requests at the upstreams, nobody waiting for the zone. Both default
  upstreams are one resolver: a hedge helps when a connection stalls, not
  when a name is slow.
* A request no query waits for any more is not re-sent after a GOAWAY.

**Known limits** (not fixed):

* Names nobody answers spread over many zones (one name per zone) are
  bounded only by the slots: ~2 × 96 / 5.4 s ≈ 35 a second per worker with
  5.4 s answers (Cloudflare's p90 above is 5.6 s). On a virtual-clock model with 6 s answers: 0 %
  SERVFAIL up to 30 a second, 3-6 % at 33-36. Past that the oldest waiting
  misses get SERVFAIL; main answered late at those rates and failed with
  `LocalProtocolError` from ~16 a second. Stand: 20 a second per worker over
  200 zones, 2 upstreams (row c2+) — 8 % (main 78 %); 40 a second with one
  upstream (rows c 10 %) — 64-70 % (main 77-89 %).
* An upstream that never answers some names (Cloudflare did not, in the
  measurement above; the stub of rows d, or a stalled connection, does):
  each such request holds its slot up to `REQUEST_TIMEOUT_S`, so ~96 / 10 s
  ≈ 10 a second per upstream, and then costs the connection. Under a steady
  stream of them a connection goes about every 6 s, not every 10 s: the
  requests re-sent on the new connection keep the time they were first
  sent (row d2, 8 a second per worker, two upstreams: ~44 drops a minute
  over two workers, 2026-10-28). Dropping only once the upstream had no
  slot free halved the drops but gave 0.4-0.7 % of the healthy misses
  SERVFAIL instead of 0-0.1 % (four runs each, same seeds; final review
  2026-10-27) — not taken. With Cloudflare's timing above, a drop needs a
  SERVFAIL slower than 10 s (none in 280) or a stalled connection. Rows
  d / d+ / d2: 8 a second per worker — 0-0.5 % (main 0.1 % while the stub
  recycled its connections, which also closed main's leaked streams; 70-79 %
  without).
* Dropping a connection (`upstream_dropped`, one WARNING per drop with the
  number of requests it cut off) fails every request on it; those a query
  still waits for are re-sent once, so it costs latency, not answers. A
  failed request no query waits for any more is logged at DEBUG, whatever
  closed its connection — our drop, the upstream's GOAWAY, httpx's read
  timeout on a connection that carried nothing else for 10 s. As warnings
  they were ~1850 lines a minute in row d2 (~25 per drop) and 365 in a 30 s
  run of row a (the stub's GOAWAY every 1000 requests); a query's own failed
  request is still a WARNING.
* A zone that answers, but slowly, is capped too: ~43 / answer time unique
  names a second per worker while the upstream's slots are otherwise free,
  down to 16 / answer time when other names hold most of them — the same
  name is asked once (the router coalesces it). Virtual-clock model (one
  worker, one upstream, 2026-10-28), share of the zone's names that get
  SERVFAIL: 1 s answers at 40 a second 0.7 %, at 60 a second 26 %; 2 s
  answers at 30 a second 29 % (a fixed 16: 58 / 71 / 73 %; main: 89 / 100 /
  100 %, and its other cache misses waited seconds). The stand does worse
  than the model, 16.5 % at 40 a second with 1 s answers: there the answers
  took ~1.6 s with that many requests open on the connection (next item).
* Every request open on a connection slows the other answers on it:
  httpcore reads an HTTP/2 connection under one lock that every waiting
  stream takes in turn, so an answer waits for the reads of the streams
  queued before it. A zone nobody answers keeps 43 requests open instead of
  16, and the other cache misses' p50 in row a went from 30 to 70 ms (p95
  70 → 138 ms); with a zone answering in 1 s at 40 names a second, 32 →
  51 ms. A quarter of the free slots instead of half (measured the same
  day): 55 ms in row a, and 32 % of the 1 s zone's names SERVFAIL.
* Six or more zones nobody answers, each sent enough names to fill its 16,
  take every slot of one upstream (6 × 16 = 96), as they did with a fixed
  16. Model, one upstream, 40 such names a second in all: healthy misses
  0 % SERVFAIL with five zones, 54 % with six; two upstreams: 0 % with ten.
* The zone is a heuristic. Shared parents (`cloudfront.net`, `github.io`,
  `blogspot.com`, `s3.amazonaws.com`) are one zone each: fine at 20 ms
  answers (16-43 requests at once: ~800-2000 a second per worker). IPv6 reverse lookups are per /124,
  i.e. practically unlimited per zone.
* Queries waiting for their zone still hold the router's `dns_upstream`
  budget: production's 1024 is ~250 queries a second per worker for one dead
  zone before `upstream_shed`. With the one-machine 128 of
  docs/runbooks/capacity.md it shows: row a128, 26 % (main 73 %).

**Measured** (stand, 2026-10-27; docs/runbooks/capacity.md «Как повторить без
Docker», 2 workers, 800 queries a second for 30 s after a 10 s warm-up, a
fresh API per run, the same seeds for every variant). Cells: p50 / p95 / p99
of never-cached names in 50 healthy zones, and the share of them that got
SERVFAIL; medians over the runs. Rows: 10 % / 2 % of all queries are names
the stub answers after 6 s ("slow") or never ("never"), in 1, 20 or 200
zones; one upstream unless "2 upstreams"; "norecycle" — a stub that does not
close its HTTP/2 connections after 1000 requests (hypercorn's default);
a128 — `LOAD_SHED_DNS_MAX_INFLIGHT` and `_UPSTREAM_MAX_INFLIGHT` at 128;
e — a zone that answers in 0.3 s / 1 s. "First version": the commit of
2026-10-23 before the review. Direction only: the stub and the load run on
the same machine, load average 2-25 from other work.

| scenario | main | first version | before the final review |
|---|---|---|---|
| b control (no slow names) (6 runs) | 16 / 32 / 93 ms, 0.0 % | 16 / 22 / 38 ms, 0.0 % | 16 / 28 / 57 ms, 0.0 % |
| a 10% slow, 1 zone, 6 s (2 runs) | 4 / 3498 / 3719 ms, 86.6 % | 22 / 44 / 72 ms, 0.0 % | 30 / 66 / 100 ms, 0.0 % |
| c 10% slow, 20 zones, 6 s (2 runs) | 3 / 3469 / 3620 ms, 88.9 % | 4002 / 4004 / 4017 ms, 79.8 % | 4001 / 4004 / 4010 ms, 63.6 % |
| c 2% slow, 200 zones, 6 s (2 runs) | 1228 / 2016 / 2226 ms, 0.0 % | 88 / 4000 / 4004 ms, 5.4 % | 60 / 1074 / 3362 ms, 0.4 % |
| c 10% slow, 200 zones, 6 s (2 runs) | 648 / 3676 / 3822 ms, 77.3 % | 4001 / 4004 / 4018 ms, 72.6 % | 4002 / 4004 / 4049 ms, 69.9 % |
| d 10% never, 1 zone (2 runs) | 4 / 3490 / 3622 ms, 89.4 % | 23 / 121 / 240 ms, 0.0 % | 30 / 66 / 100 ms, 0.0 % |
| d 2% never, 200 zones (2 runs) | 904 / 2536 / 2886 ms, 0.1 % | 110 / 4003 / 4004 ms, 23.0 % | 66 / 842 / 2462 ms, 0.4 % |
| d+ 10% never, 1 zone, norecycle, 60s (1 run) | 3 / 2346 / 3548 ms, 96.1 % | 21 / 50 / 128 ms, 0.0 % | 32 / 73 / 116 ms, 0.0 % |
| d+ 2% never, 200 zones, norecycle, 60s (1 run) | 3 / 1657 / 2252 ms, 79.4 % | 867 / 4004 / 4037 ms, 42.8 % | 84 / 1185 / 2158 ms, 0.0 % |
| a+ 10% 6s, 1 zone, norecycle (1 run) | 3 / 3433 / 3592 ms, 80.2 % | 21 / 44 / 73 ms, 0.0 % | 29 / 66 / 95 ms, 0.0 % |
| c+ 2% 6s, 200 zones, norecycle (1 run) | 1356 / 2099 / 2584 ms, 0.3 % | 82 / 266 / 489 ms, 0.0 % | 77 / 134 / 171 ms, 0.0 % |
| a128 10% 6s, 1 zone, budgets 128 (1 run) | 2 / 2694 / 3572 ms, 72.9 % | 18 / 38 / 103 ms, 24.2 % | 27 / 69 / 128 ms, 26.3 % |
| b2 control, 2 upstreams (2 runs) | 16 / 22 / 35 ms, 0.0 % | 16 / 29 / 67 ms, 0.0 % | 16 / 22 / 29 ms, 0.0 % |
| a2 10% 6s, 1 zone, 2 upstreams (2 runs) | 7 / 3548 / 3705 ms, 88.5 % | 21 / 74 / 175 ms, 0.0 % | 27 / 60 / 94 ms, 0.0 % |
| c2 2% 6s, 200 zones, 2 upstreams (2 runs) | 2370 / 3000 / 3159 ms, 0.0 % | 222 / 4003 / 4011 ms, 23.3 % | 66 / 202 / 1026 ms, 0.0 % |
| c2n 2% 6s, 200 zones, 2 ups, norecycle (2 runs) | 2138 / 2828 / 3010 ms, 0.0 % | 130 / 4002 / 4068 ms, 10.8 % | 72 / 150 / 226 ms, 0.0 % |
| c1n 1% 6s, 200 zones, 2 ups, norecycle (2 runs) | 606 / 2192 / 2572 ms, 0.0 % | 38 / 88 / 170 ms, 0.0 % | 36 / 79 / 115 ms, 0.0 % |
| e 10% alive 0.3 s, 1 zone (1 run) | 25 / 74 / 169 ms, 0.0 % | — | 24 / 48 / 84 ms, 0.0 % |
| e 10% alive 1 s, 1 zone (1 run) | 3516 / 4004 / 4026 ms, 9.2 % | — | 28 / 81 / 181 ms, 0.0 % |
| c2+ 5% 6s, 200 zones, 2 ups (1 run) | 4011 / 4155 / 4512 ms, 77.6 % | — | 102 / 4002 / 4003 ms, 8.4 % |
| d2 2% never, 200 zones, 2 ups, norecycle, 60s (1 run) | 5 / 2539 / 2987 ms, 70.0 % | — | 84 / 357 / 3350 ms, 0.5 % |

`scripts/capacity/loadgen.py --mode doh` reports p95 over every HTTP 200,
SERVFAIL included: ~4 s for both fixes in row a, because the slow names now
wait the whole budget instead of failing in milliseconds (main: 3.1-3.6 s).
The per-name split above comes from a scratch bench that is not in the repo.

**After the final review** (2026-10-28: the same recipe, rows and seeds, on
ports of its own; the PR before the final review, 9ed6fb36, and the final
code run within the same two hours, load average 2-10, 2 runs each unless
noted). Cells as above, plus "zone" — the share of the slow zone's own names
that got SERVFAIL — and "log" — upstream WARNING lines and connection drops
per run.

| scenario | before the final review | final |
|---|---|---|
| b control (no slow names) | (table above) 16 / 28 / 57 ms, 0.0 % | 15 / 20 / 34 ms, 0.0 %; log 0 |
| a 10% slow, 1 zone, 6 s | 30 / 70 / 118 ms, 0.0 %; log 96-144 | 70 / 138 / 201 ms, 0.0 %; log 0-1 |
| c 2% slow, 200 zones, 6 s | 64 / 768 / 2510 ms, 0.2 %; log 326-357, 1-5 drops | 57 / 224 / 1920 ms, 0.0 %; log 15-28, 2-3 drops |
| c2 2% 6s, 200 zones, 2 upstreams | 68 / 199 / 710 ms, 0.0 %; log 405-437, 6-7 drops | 69 / 195 / 766 ms, 0.0 %; log 5, 2-4 drops |
| e 10% alive 0.3 s, 1 zone | 24 / 54 / 96 ms, 0.0 %; zone 0 % | 24 / 161 / 350 ms, 0.0 %; zone 0 % (p95 279 ms and 43 ms) |
| e 10% alive 1 s, 1 zone | 32 / 357 / 1447 ms, 0.2 %; zone 63.2 % | 51 / 204 / 438 ms, 0.0 %; zone 16.5 % |
| d2 2% never, 200 zones, 2 ups, norecycle, 60s | (4 runs) 84 / 296 / 1623 ms, 0.1 %; log ~1850, 36-47 drops | 79 / 282 / 1975 ms, 0.0 %; log 33-35 = the drops |
| a, zone room 16 + a quarter of the free slots | — | 55 / 119 / 173 ms, 0.1 % |
| e 1 s, zone room 16 + a quarter of the free slots | — | 46 / 138 / 318 ms, 0.0 %; zone 31.7 % |
| d2, connection dropped only when its upstream has no slot free | — | (4 runs) 84 / 283 / 2133 ms, 0.5 %; 20-22 drops |

The last three rows are the alternatives the final review's findings were
decided against.

**Watch:** `upstream_zone_wait`, `upstream_slot_wait`, `upstream_dropped`
(counters table below) and the slot gauges in `/health/doh`.

## Scaling on Railway

State on 2026-10-09: `WEB_CONCURRENCY=2`, 2 replicas, deploy health check
`/health` — all live. Since the 2026-10 move both `web` and `Redis` run in
EU West (Amsterdam); before that, Southeast Asia (Singapore).

* **Workers.** uvicorn reads `WEB_CONCURRENCY` (the Dockerfile start
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
   `WEB_CONCURRENCY` per vCPU, and a minute-level monitor of the DNS path —
   since 2026-10-22 the uptime Worker (`ops/uptime-worker/`): a real query
   must resolve (`doh_resolve`), the list canary must get our NXDOMAIN
   (`doh_block`, which also fails when the filter is not loaded), and the
   artifact must be under 13 h old (`blocklist`, from `/health/deep`).
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
   Logs off for this route). Once DNS runs in a Railway service of its own
   (`docs/runbooks/dns-service-split.md`), the origin is that service's
   `*.up.railway.app` domain, not `api.cleanway.ai`: with `SERVICE_ROLE=api`
   that answers `/dns-query` with 404, which the sketch (`< 500`) would hand
   to every phone. Behind the proxy the client IP comes from
   `CF-Connecting-IP`, which the API believes only when the hop in front of
   Railway's edge is a Cloudflare address (vendored ranges,
   `api/data/cloudflare_ips.txt`) — `TRUSTED_PROXY_CIDRS` stays
   `100.64.0.0/10`. Before proxying `dns.` read
   `docs/runbooks/cloudflare-proxy.md` (why it stays DNS-only for now). Workers bill per
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
| `upstream_shed` | not forwarded: this worker already had `LOAD_SHED_DNS_UPSTREAM_MAX_INFLIGHT` queries waiting on the upstream; answered stale or SERVFAIL (docs/runbooks/capacity.md, «Сброс нагрузки») | rising → the upstream is slow; see `load_shed.dns_upstream` |
| `upstream_zone_wait` | a query waited for room in its zone: the zone had its room at the upstreams — `ZONE_MAX_IN_FLIGHT` (16) requests plus half of the upstream's free slots | rising with `servfail` → a zone nobody answers is being flooded, or one answers too slowly for its query rate; `upstream_slots.zones_full` |
| `upstream_slot_wait` | a query waited for a slot: all 96 of an upstream's were taken | rising → slots are short; `upstreams[].in_flight` and `upstream_slots.abandoned` say by what |
| `upstream_abandoned` | a sent request no query waited for any more — a hedge loser, or still out at the deadline; it runs on, holding its slot | has a baseline (every lost hedge); worry when it rises with `servfail` |
| `upstream_hedge_skipped` | a hedge was due but no upstream had spare room for it (more than half its slots free) | rising → slots are short |
| `upstream_dropped` | a request stayed unanswered for `REQUEST_TIMEOUT_S` (10 s): it was given up together with its connection; one WARNING per drop says how many other requests were on it | any, sustained → the upstream leaves requests unanswered (Cloudflare's SERVFAIL for an unreachable zone took ≤ 9.3 s in 280 tries) |
| `rate_limited` | 429s sent | rising → a CGNAT address hit the ceiling; raise the limit |
| `internal_error`, `filter_error`, `cache_error` | a bug, failed open | any |

**Upstream slots now** (`/health/doh`, the worker that answered — the
counters above are since start): `upstreams[].in_flight` / `waiting` —
requests at that upstream (of 96) and queries waiting for one of its slots;
`upstream_slots` — `zones_full` (zones with a query waiting for room),
`zone_waiting` (queries waiting for room in them), `abandoned` (requests no
query waits for, still open), `dropping` (connections being dropped after
`upstream_dropped`).
Slots full and most of them `abandoned`: names nobody answers. Slots full,
few abandoned: the upstream itself is slow.

**`filter.error`**: `no_artifact` (publisher never wrote one / it expired),
`sha_mismatch` (body ≠ meta — publisher bug; the old list is kept),
an exception name (Redis trouble; the old list is kept).

**Config** (env vars, `api/config.py`):

| var | default | |
|---|---|---|
| `DOH_UPSTREAMS` | `cloudflare-dns.com`, `1.1.1.1` | comma-separated RFC 8484 URLs, in order; add `https://dns.quad9.net/dns-query` only after privacy policy §11 names Quad9 |
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
4. Before iOS launch: Cloudflare proxy + the fail-open Worker (step 2). No
   `TRUSTED_PROXY_CIDRS` change is needed: the API recognises Cloudflare's
   ranges itself (`docs/runbooks/cloudflare-proxy.md`).
5. Later: second region + load balancer (step 3).


> **2026-10-09:** the default is Cloudflare only (two endpoints of the same resolver), so the public privacy policy stays true without a text change. Turning on the Quad9 failover = update §11 in all 10 locales, then set `DOH_UPSTREAMS`.

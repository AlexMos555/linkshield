# Uptime monitor (Cloudflare Worker)

`worker.js` runs every minute in the founder's Cloudflare account as the Worker
`cleanway-uptime` and checks what users depend on:

| Check | What counts as up | Red means |
|---|---|---|
| `landing` | `https://cleanway.ai/` answers 200 | the site is down (Vercel) |
| `install_page` | `https://cleanway.ai/ru/android` answers 200 | the page Tele2 subscribers install from is down |
| `api` | `https://api.cleanway.ai/health/deep` answers 200 with `"status":"ok"` | Redis or Supabase is down for the API (the mail names which) |
| `blocklist` | `blocklist` is not in `/health/deep` → `warnings` | the list phones sync is stale (13 h+) or empty |
| `dns_filter` | `doh` is not in `warnings` | the gateway's own decision code blocks nothing (`dangerous_domains` expired, Redis down) |
| `server_key` | `supabase_server_key` is not in `warnings` | the Supabase server key no longer acts as service_role: account deletion and server writes fail |
| `warnings_other` | `warnings` holds nothing else | `/health/deep` raised a warning this monitor does not know yet |
| `doh_resolve` | a DNS-over-HTTPS query for `google.com` to `dns.cleanway.ai` gets RCODE 0 and an answer | iPhones with DNS protection resolve nothing |
| `doh_block` | the same query for `list-canary.cleanway.ai` gets NXDOMAIN **with our SOA** (`blocked.cleanway.ai`) | the public DNS path does not block; an upstream NXDOMAIN does not count |
| `dns_latency` | `https://dns.cleanway.ai/health/doh` → `stats.recent.p95_ms_le` (the last 150–180 s) under 200 — **alerts after 5 slow minutes in a row**, not 2 | DNS is short of CPU: the capacity runbook's line (`docs/runbooks/capacity.md`) for another DNS replica, or for DNS in a service of its own (`docs/runbooks/dns-service-split.md`) |
| `backup` | the newest `db/` object in R2 is under 30 h old — **only with the `BACKUPS` binding** | the nightly `DB backup` workflow stopped (GitHub sends no mail for a run that never starts) |

**How `dns_latency` reads `/health/doh`.** It judges `stats.recent`: the
latency histogram of the one worker process that answered, over its last
150–180 s (`api/services/doh_metrics.py`; `window_s` says 180). Not the
lifetime fields next to it (`stats.p95_ms_le`, counted since the worker
started): those move in proportion to uptime, so a day-old worker needed over
an hour of slow answers before they showed it, and kept looking slow for hours
after it was fast again. `p95_ms_le` is the upper bound of the latency bucket
the p95 falls in (buckets … 50, 100, 200, 500 … ms), server time only. So
`200` means the p95 is between 100 and 200 ms, and `null` with queries means
over 5 s (counted as slow). The window is shorter than the five minutes, so a
slowdown of a minute or so does not mail; one that lasts two to three minutes
or more does, four to five minutes after it started, and the "снова работает"
mail comes about three minutes after it ends.

Each minute may reach another of the 2 × 2 workers, and one fast reading
starts the count again: five slow readings in a row mean most workers are
slow. If only one replica is slow (half the workers), the readings alternate
and five in a row is luck: expect the mail after an hour or more, and the
"снова работает" mail at the next fast reading. Railway → Metrics per replica
shows that case. A worker with fewer than 100 queries in the window is not
judged: a p95 of a handful of lookups says nothing. At today's volume (about
2 queries a minute per worker, mostly this monitor's own two probes) that is
every worker, so the check waits; it starts judging at about 35–40 queries a
minute per worker (with 2 × 2 workers, ~70 active phones on average). An
answer that cannot be read, or one from an API without `recent`, is not
judged either: an unreachable DNS service is `doh_resolve`'s alert. The URL is
on the DNS name, so it watches whichever service serves `dns.cleanway.ai`,
before and after the split.

Each warning is its own check, so a warning that stays red (one email) never
hides the next one. One `/health/deep` request per minute serves all of them;
the endpoint reuses a result for 30 s, so the API's dependencies see no extra
load. `/health` is not used: it is always 200, and its `status` turned
`degraded` whenever a third-party threat-intel breaker opened.

After two failed runs in a row (`dns_latency`: five) it emails `amoskotin@gmail.com` from
`alerts@cleanway.ai` (Cloudflare Email Routing `send_email` binding — the
destination must stay a verified Email Routing address), and once more when the
check recovers. The mail says what the check means and points at
`docs/runbooks/monitoring.md`. A send that fails is retried the next minute and
recorded as `alert_error` until a mail goes out or none is owed any more (the
check recovered before the founder was told).

State is kept in the KV namespace `cleanway-uptime`: written when it changes and
at least every 10 minutes (`heartbeat_at`). `GET
https://cleanway-uptime.amoskotin.workers.dev/` shows it; the DNS canary
(`scripts/dns_canary.py`, workflow `dns-canary.yml`) fails when the heartbeat is
older than 30 minutes, so a dead monitor is noticed too.

## Deploying a change

The Worker was created through the Cloudflare API (no wrangler project). To
update it, upload `worker.js` as an ES module named `worker.js` with bindings:

- `STATE` — KV namespace `cleanway-uptime`
- `ALERT` — `send_email`, destination `amoskotin@gmail.com`
- `ALERT_TO` — plain text `amoskotin@gmail.com`
- `BACKUPS` — **optional** (bound since 2026-10-23), R2 bucket `cleanway-db-backups`. Turns on the
  `backup` check. The Worker only lists object names and upload times.

and keep the cron trigger `* * * * *`. Free-plan limits are far away: 1,440
runs/day, up to 11 subrequests per run (the free limit is 50), a KV read per run,
a KV write on change and every 10 minutes (~150/day of 1,000), and with
`BACKUPS` one R2 list per run (~43k/month of the free 1M class-A operations).

Dashboard path for the founder: Cloudflare → Workers & Pages →
`cleanway-uptime` → Edit code → paste `worker.js` → Deploy; then Settings →
Bindings → Add → R2 bucket → variable `BACKUPS`, bucket `cleanway-db-backups`.

**2026-10-24 version (`dns_latency`): paste the new `worker.js`, nothing else.**
No new binding or variable; the KV state from the previous version is read
as is. It reads `stats.recent`, which the API has from the same PR (Railway
deploys it on merge); paste after that deploy, though pasting earlier is
harmless (an API without `recent` is not judged). `dns_latency` stays absent
from `fails` in `GET https://cleanway-uptime.amoskotin.workers.dev/` while
every worker it reaches has fewer than 100 queries in its window, which is
the case at today's volume; once traffic grows it shows `0`. The first alert
can come no sooner than five minutes after the check starts judging. It works
the same before and after DNS moves to its own Railway service.

Tests: `node --test ops/uptime-worker/worker.test.mjs` (CI runs it through
`tests/test_uptime_worker.py`).

## Why not an external service

No new account to secure: it lives in the Cloudflare account that already holds
the cleanway.ai zone, runs outside Railway and Vercel (so it sees their outages),
and alerts arrive at night like any email. A paging service (phone call) can be
added later if email is not loud enough.

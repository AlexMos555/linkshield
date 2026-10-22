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
| `backup` | the newest `db/` object in R2 is under 30 h old — **only with the `BACKUPS` binding** | the nightly `DB backup` workflow stopped (GitHub sends no mail for a run that never starts) |

Each warning is its own check, so a warning that stays red (one email) never
hides the next one. One `/health/deep` request per minute serves all of them;
the endpoint reuses a result for 30 s, so the API's dependencies see no extra
load. `/health` is not used: it is always 200, and its `status` turned
`degraded` whenever a third-party threat-intel breaker opened.

After two failed runs in a row it emails `amoskotin@gmail.com` from
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
- `BACKUPS` — **optional**, R2 bucket `cleanway-db-backups`. Turns on the
  `backup` check. The Worker only lists object names and upload times.

and keep the cron trigger `* * * * *`. Free-plan limits are far away: 1,440
runs/day, up to 10 subrequests per run (the free limit is 50), a KV read per run,
a KV write on change and every 10 minutes (~150/day of 1,000), and with
`BACKUPS` one R2 list per run (~43k/month of the free 1M class-A operations).

Dashboard path for the founder: Cloudflare → Workers & Pages →
`cleanway-uptime` → Edit code → paste `worker.js` → Deploy; then Settings →
Bindings → Add → R2 bucket → variable `BACKUPS`, bucket `cleanway-db-backups`.

Tests: `node --test ops/uptime-worker/worker.test.mjs` (CI runs it through
`tests/test_uptime_worker.py`).

## Why not an external service

No new account to secure: it lives in the Cloudflare account that already holds
the cleanway.ai zone, runs outside Railway and Vercel (so it sees their outages),
and alerts arrive at night like any email. A paging service (phone call) can be
added later if email is not loud enough.

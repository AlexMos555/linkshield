# Uptime monitor (Cloudflare Worker)

`worker.js` runs every minute in the founder's Cloudflare account as the Worker
`cleanway-uptime` and checks:

| Check | What counts as up |
|---|---|
| `landing` | `https://cleanway.ai/` answers 200 |
| `api` | `https://api.cleanway.ai/health` answers 200 with `"status": "ok"` |
| `doh` | a real DNS-over-HTTPS query for google.com to `dns.cleanway.ai` gets RCODE 0 and an answer |

After two failed runs in a row it emails `amoskotin@gmail.com` from
`alerts@cleanway.ai` (Cloudflare Email Routing `send_email` binding — the
destination must stay a verified Email Routing address), and once more when the
check recovers. State is kept in the KV namespace `cleanway-uptime` and written
only when it changes. `GET https://cleanway-uptime.amoskotin.workers.dev/` shows
the current state.

## Deploying a change

The Worker was created through the Cloudflare API (no wrangler project). To
update it, upload `worker.js` as an ES module named `worker.js` with bindings:

- `STATE` — KV namespace `cleanway-uptime`
- `ALERT` — `send_email`, destination `amoskotin@gmail.com`
- `ALERT_TO` — plain text `amoskotin@gmail.com`

and keep the cron trigger `* * * * *`. Free-plan limits are far away: 1,440
runs/day, a KV read per run, a KV write only on change.

## Why not an external service

No new account to secure: it lives in the Cloudflare account that already holds
the cleanway.ai zone, runs outside Railway and Vercel (so it sees their outages),
and alerts arrive at night like any email. A paging service (phone call) can be
added later if email is not loud enough.

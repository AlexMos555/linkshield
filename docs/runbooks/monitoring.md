# Runbook: Monitoring the blocklist and DNS

What watches production, how often it really runs, and what to do when it
goes red. Written 2026-09-26 after the service check of 2026-09-25 found the
DNS canary could not fail and ran every ~3.5 h instead of every 15 min.

## What runs

| Job | Scheduled | Really runs | Red means |
|---|---|---|---|
| `dns-canary.yml` | 4× per hour | ~1 per 3.5 h (46–47 runs in 7 days, measured 2026-09-18..25) | a must-resolve name is dark, the gateway resolves nothing, a listed name is not blocked **by us**, the phone artifact is stale/broken, `/health/deep` is degraded, or `/ru/android` is down |
| `refresh-dangerous-domains.yml` | every 6 h | on time so far (199 of 200 runs green) | exit 2: no feed readable · 4: a gate kept the previous set · 5: post-publish check failed, rolled back · **6: published, but a feed has been down or truncated for 12 h+** |
| `security.yml` → gitleaks | every push + weekly | on time | a committed secret — or a new false positive (see below) |

**GitHub scheduled workflows are best-effort.** GitHub drops scheduled runs
under load; nothing in the repository can make the canary run every 15
minutes. Treat it as a periodic audit, not a pager.

## What only the founder can set up

1. **External uptime monitor (minute-level alerting).** Any free monitor
   (UptimeRobot, Better Stack, Healthchecks.io …) with two checks, every 5
   minutes, alerting to your email or Telegram:
   - `GET https://api.cleanway.ai/health/deep` — alert unless HTTP 200 and the
     body contains `"status":"ok"`;
   - `GET https://cleanway.ai/ru/android` — alert unless HTTP 200.
   Use GET, not HEAD: the API answers HEAD with 405.

   **What this monitor does not see.** `/health/deep` checks only Redis and
   Supabase. It stays green while the phone blocklist is stale or missing,
   while the `dangerous_domains` set has expired, and while the DNS gateway
   has stopped filtering. Those failures are caught only by the DNS canary
   (really about once every 3.5 h, see the table) and by the refresh job's
   own red runs. So the monitor watches the API, not grandma's protection.
   Putting blocklist freshness into `/health/deep` is an open follow-up.
2. **Optional: run the DNS canary on a real clock.** An external cron (e.g.
   cron-job.org) can call GitHub's `workflow_dispatch` for `dns-canary.yml`
   every 15 minutes. It needs a fine-grained token with *Actions: read and
   write* on this repository only — create it yourself and store it only in
   that service; it never goes into the repository.
3. **Let the favicon job open its PR.** `refresh-brand-favicons.yml` failed
   15 of 15 runs with "GitHub Actions is not permitted to create or approve
   pull requests". Settings → Actions → General → Workflow permissions →
   tick **Allow GitHub Actions to create and approve pull requests** → Save.

## When the blocklist refresh exits 6 (a feed is down)

The list was still published — the names the missing feed backed on its last
healthy run were kept ("outage guard: keeping N published names <feed>
backed" in the log), for up to 14 days of **that** feed's outage. Names the
healthy feeds dropped meanwhile leave through retention as usual. Each run
that publishes records which names every healthy feed backed (Redis hash
`dangerous_domains:feed_backing`, ~1.2 MB). A feed with no such record yet —
an outage in the first runs after 2026-09-27, before that feed has published
healthy once — makes the run keep every published name no live source lists
and stop recording departures; the log says "no record of which names it
backed". So if a feed is down on the very first runs after the merge, the
~50k single-subdomain registrables the #17 fix drops stay published until
that feed is back (the expected shrink shows on that run instead). Look for
the `FEED DEGRADED:` line:

- **`unavailable (download or read failed)`** — open the feed URL from the
  constants at the top of `scripts/refresh_dangerous_domains.py`. Temporary
  (5xx, timeout): wait, the next healthy run closes the outage by itself.
  Moved or gone for good: fix or remove the feed in a PR; after 14 days its
  carry stops and its names leave the list anyway (other feeds' outages are
  still carried). For **`Cleanway checks`** (only while server-confirmed
  hosts are switched on, see below) the unreadable source is the Redis set
  `dangerous_domains:confirmed` (written by the API): check the key's type
  and the API logs. Its hosts are never carried — they are off the list
  until the set is readable again.
- **`shrank from X to Y hosts`** — the feed answered with under half its last
  healthy size. Truncated or broken: wait or fix the parser. A real change
  (the maintainer pruned it): run the workflow by hand with **force** ticked;
  that accepts the new sizes as the baseline (it also bypasses the churn
  gate, so check the dry-run output first).

## Server-confirmed hosts (`PUBLISH_CONFIRMED_THREATS`) — off

With the switch on, a host a person checks that Google Safe Browsing lists as
phishing or malware (and our scorer rates dangerous) is kept in
`dangerous_domains:confirmed` and published to every phone for 7 days after
the last such check (`api/services/confirmed_threats.py`). It is **off**,
and it stays off until you decide otherwise: the feed-licence audit of
2026-09-21 lists Google Safe Browsing among the sources whose terms bar
commercial redistribution, and this ships Google's verdicts to every phone
(hashed in the app, as plain names in the DNS gateway's set). No other
source counts: PhishTank is our held-out benchmark, the abuse.ch lookups
(URLhaus host, ThreatFox, MalwareBazaar) do not answer "is this exact host
malicious now" and their terms bar derivative works.

Before switching it on:

1. A written legal answer (or a paid licence) that covers redistributing
   Safe-Browsing-derived hosts this way.
2. The public privacy policy (`/ru/privacy-policy` and the other locales)
   describes it; `docs/PRIVACY.md` already does.
3. Set `PUBLISH_CONFIRMED_THREATS=1` in **both** places: the API service on
   Railway (it records) and GitHub → Settings → Secrets and variables →
   Actions → Variables (the refresh job publishes). One without the other
   does nothing useful.

To switch it off, unset both. Stored hosts leave the list at the next refresh
with no retention tail, and the Redis set expires within 10 days.

**A wrongly confirmed site** (Google's false positive on a small legitimate
site) stays on every phone until 7 days after the last check that confirmed
it. To take it off sooner — a production Redis write, your decision — mark
its confirmation as just expired, then run the refresh workflow by hand:

    ZADD dangerous_domains:confirmed XX <now minus 7 days and 1 hour, unix seconds> <host>

Not `ZREM`: a host that vanishes from the set looks like a feed departure,
and retention would keep it published for 14 more days. Not score `0`
either: the next write would delete it before the refresh sees it expired,
with the same result. While Google still lists the site, the next dangerous
check records it again; the lasting fix is Google's — the site owner asks
for a review in Google Search Console (Security issues), or report it at
https://safebrowsing.google.com/safebrowsing/report_error/.

## When the DNS canary goes red

- `LISTED NAME NOT BLOCKED` / `NOT BLOCKED BY US` — the gateway is not
  filtering. Check `/health` (`blocklist_version`, `blocklist_age_s`) and the
  last refresh run; the `dangerous_domains` set may have expired (3-day TTL).
- `BLOCKED A POPULAR NAME` — a real site is dark for everyone on the DNS
  profile. The refresh job rolls itself back when its own post-publish check
  sees one of `NEVER_BLOCK_GUARDS` dark (exit 5); a name outside that list
  it cannot see. There is no one-command manual rollback yet: the snapshot
  lives in `dangerous_domains:prev` for 3 days, and restoring it is a
  production Redis write — your decision. Then add the name to
  `data/brand_owned_hosts.txt` (with evidence) or fix the rule that let it
  through, and re-run the refresh workflow.
- `GATEWAY RESOLVES ALMOST NOTHING` — upstream (1.1.1.1) unreachable from
  Railway, or the DoH route is broken.
- `live-block-check: … (skipped: …)` is a note, not a failure: no host of the
  Phishunt feed was on our list and resolvable at that moment.

## When gitleaks goes red

Read the flagged line first (`gitleaks detect --redact` locally, or the job
log). A real secret: rotate it, then remove it from history. A false
positive: add its exact fingerprint (`commit:file:rule:line`, printed in the
log) to `.gitleaksignore` with a comment saying what the line really is.
Never widen `.gitleaks.toml` to a whole directory, and never allowlist a
secret instead of rotating it.

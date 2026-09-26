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

The list was still published — every name the missing feed backed was kept
("outage guard: keeping N published names" in the log), for up to 14 days of
outage. Look for the `FEED DEGRADED:` line:

- **`download failed`** — open the feed URL from the constants at the top of
  `scripts/refresh_dangerous_domains.py`. Temporary (5xx, timeout): wait, the
  next healthy run closes the outage by itself. Moved or gone for good: fix or
  remove the feed in a PR; after 14 days the carry stops and its names leave
  the list anyway.
- **`shrank from X to Y hosts`** — the feed answered with under half its last
  healthy size. Truncated or broken: wait or fix the parser. A real change
  (the maintainer pruned it): run the workflow by hand with **force** ticked;
  that accepts the new sizes as the baseline (it also bypasses the churn
  gate, so check the dry-run output first).

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

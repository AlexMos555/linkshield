# Runbook: Monitoring the blocklist and DNS

What watches production, how often it really runs, and what to do when it
goes red. Written 2026-09-26 after the service check of 2026-09-25 found the
DNS canary could not fail and ran every ~3.5 h instead of every 15 min.

## What runs

| Job | Scheduled | Really runs | Red means |
|---|---|---|---|
| Cloudflare Worker `cleanway-uptime` (`ops/uptime-worker/`) | every minute | every minute (Cloudflare cron); writes a heartbeat every 10 min | an email `Cleanway: не работает <check>` after two failed minutes: `api` (`/health/deep` not 200/ok — Redis or Supabase), `blocklist` / `dns_filter` / `server_key` / `warnings_other` (one per `/health/deep` warning), `doh_resolve` (the gateway resolves nothing), `doh_block` (the list canary is not NXDOMAIN'd **by us** on the public path), `landing`, `install_page` (`/ru/android`), `backup` (newest R2 backup over 30 h, only with the `BACKUPS` binding). Table: `ops/uptime-worker/README.md` |
| Cloudflare Worker `cleanway-mail-security` (`ops/mail-security-worker/`) | on each TLS report mailed to `tls-reports@cleanway.ai` | once a day per sender that delivered mail to cleanway.ai that day (only after it is deployed and the `_smtp._tls` TXT record is published) | an email `Cleanway: сбои TLS при доставке почты на cleanway.ai (<n>)`, at most one a day per known sender (Google, Microsoft) and one for all others (their subject ends `, отправитель не проверен`): a sender's TLS sessions to our MX hosts failed. Daily counts, Google's and Microsoft's under `verified`: `https://cleanway-mail-security.amoskotin.workers.dev/` |
| `dns-canary.yml` | 4× per hour | ~1 per 3.5 h (46–47 runs in 7 days, measured 2026-09-18..25; 6 on 2026-10-21) | a must-resolve name is dark, the gateway resolves nothing, a listed name is not blocked **by us**, the phone artifact is stale/broken, `/health/deep` is degraded, `/ru/android` is down, or the uptime Worker's heartbeat is older than 30 min / it cannot send mail |
| `refresh-dangerous-domains.yml` | every 6 h | on time so far (199 of 200 runs green) | exit 2: no feed readable · 4: a gate kept the previous set · 5: post-publish check failed, rolled back · **6: published, but a feed has been down or truncated for 12 h+** |
| `security.yml` → gitleaks | every push + weekly | on time | a committed secret — or a new false positive (see below) |
| `weekly-benchmark.yml` | Sundays 15:15 UTC; a scheduled start after 23:00 UTC Sunday is skipped (yellow warning, `window` job) so the run never spends Monday's paid-source budgets | not yet measured on the new schedule; the old Monday 05:15 cron started 0.5–6.3 h late (last 5 runs) | the run crashed or hit its 150-min timeout (VirusTotal alone takes ~105 min at sample 200; a cancelled run writes nothing). A failed "Check the legitimate sample" step (the job still passes) means a site in `data/benchmark_legit_ru.txt` stopped resolving or is now auto-trusted: prune it (the run itself still counts it as no answer / drops it). A small or rate-limited run is not red — it just leaves `latest.json` alone |

**GitHub scheduled workflows are best-effort.** GitHub drops scheduled runs
under load; nothing in the repository can make the canary run every 15
minutes. Treat it as a periodic audit, not a pager — the pager is the
uptime Worker, and the canary is what notices when the Worker itself dies.

**Payment webhooks** that arrive with a valid signature but fail to apply
email the founder through the security alerts (`webhook_processing_failed`,
`security-incident.md`). **Sign-in codes** (Supabase SMTP via Resend) are not
watched yet — `sign-in-email.md` has the checks and the canary design.

## What only the founder can set up

1. **Upload the uptime Worker after a change to it.** The minute-level
   monitor is the Cloudflare Worker `cleanway-uptime`; its source is
   `ops/uptime-worker/worker.js` and it is deployed by hand (README there).
   Since 2026-10-22 it probes `/health/deep` and each of its warnings, our
   block on the public DNS path and `/ru/android`; until that version is
   uploaded the live Worker still probes `/health` (the DNS canary prints
   "no heartbeat_at yet"). Optional: bind the R2 bucket `cleanway-db-backups`
   as `BACKUPS` to get the backup-age alert.

   **What `/health/deep` warns about.** Components that never page (never turn
   it into a 503) but are listed in `warnings` when they fail — the Worker
   alerts on each one separately:
   - `blocklist` — the artifact phones sync: published, more than the list
     canary alone, and younger than 13 h (`MAX_HEALTHY_AGE_S`, the canary's
     threshold). `error`: `unavailable` (nothing servable in Redis),
     `empty`, `stale`, `bad_meta`, `timeout`;
   - `doh` — one query for `list-canary.cleanway.ai` through the gateway's
     own decision code, in process, with a stub upstream (no network). OK =
     our NXDOMAIN. `error: listed_name_not_blocked` means the DNS profile
     blocks nothing right now: `dangerous_domains` expired or lost the
     canary, or Redis is down and the gateway is failing open.
   - `supabase_server_key` (since 2026-10-22) — the server key no longer acts
     as service_role (`GET /auth/v1/admin/users` is not 200): account deletion
     and every server write fail while Supabase itself answers. `kind` says
     which key generation is live (`supabase-jwt-signing-keys.md`).
   Informational, never in `warnings`: `ml` (model loaded) and `retention`
   (`RETENTION_PURGE` and the last successful pass, `data-retention.md`).

   **What the Worker does not see.** The in-process DoH probe proves the
   decision code and the Redis set; the Worker's `doh_block` adds the public
   path for one name (Railway routing, TLS, `/dns-query`). Real listed hosts
   from a live feed, the artifact's self-consistency and the must-resolve
   list are only in the DNS canary (about once every 3.5 h, see the table).
2. **Optional: run the DNS canary on a real clock.** An external cron (e.g.
   cron-job.org) can call GitHub's `workflow_dispatch` for `dns-canary.yml`
   every 15 minutes. It needs a fine-grained token with *Actions: read and
   write* on this repository only — create it yourself and store it only in
   that service; it never goes into the repository.
3. ~~Let the favicon job open its PR~~ — done: `refresh-brand-favicons.yml`
   has been green since 2026-10-12.

## Когда пришло письмо «Cleanway: не работает …»

Письмо шлёт `cleanway-uptime` после двух неудачных минут подряд; второе
письмо — «снова работает» — придёт само. Первым делом —
`curl -s https://api.cleanway.ai/health/deep`.

| Проверка | Что сделать первым |
|---|---|
| `api` | В письме — какой компонент: `redis` → Railway → сервис `Redis` (жив ли, Restart); `supabase` → status.supabase.com, Supabase → проект → не на паузе ли. Совпало с деплоем — `rollback.md` |
| `landing`, `install_page` | Vercel → Deployments: последний деплой упал? Откат — Promote предыдущего (`rollback.md`) |
| `blocklist` | GitHub → Actions → Refresh dangerous domains: последние запуски красные? Ниже — «When the blocklist refresh exits 6» |
| `dns_filter`, `doh_block` | DNS-профиль ничего не блокирует. `components.doh` и `components.blocklist` в `/health/deep`; набор `dangerous_domains` мог истечь (TTL 3 дня) — запустить Refresh dangerous domains вручную. `dns_filter` зелёный, а `doh_block` красный — сломан публичный путь (маршрут Railway, `/dns-query`) |
| `doh_resolve` | `dns.cleanway.ai` не отвечает: `/health/doh` (`ok`, `upstreams`). У iPhone с DNS-защитой не открываются сайты — это срочно |
| `server_key` | Серверный ключ Supabase отклонён: `supabase-jwt-signing-keys.md`; сверить `SUPABASE_SECRET_KEY` / `SUPABASE_SERVICE_KEY` в Railway с Supabase → API Keys |
| `warnings_other` | В `/health/deep` новое предупреждение — посмотреть `warnings` и `components`; дописать проверку в `ops/uptime-worker/worker.js` |
| `backup` | GitHub → Actions → DB backup: последний запуск красный или не стартовал? Запустить вручную (Run workflow); `restore.md` |

Монитор молчит, а DNS canary пишет `UPTIME MONITOR SILENT` или `CANNOT SEND
MAIL` — Cloudflare → Workers & Pages → `cleanway-uptime`: на месте ли cron
`* * * * *`, привязки `STATE`, `ALERT`, `ALERT_TO`, подтверждён ли адрес в
Email Routing (`ops/uptime-worker/README.md`).

## Когда пришло письмо «Cleanway: сбои TLS при доставке почты…»

Письмо шлёт `cleanway-mail-security`, не чаще раза в день от Google, раза от
Microsoft и раза от всех остальных вместе: почтовый сервис прислал отчёт
TLS-RPT, в котором часть сессий к нашим MX (`route1/2/3.mx.cloudflare.net`)
не прошла проверку TLS. Если в теме «отправитель не проверен», это может быть
подделка: на адрес может написать кто угодно. Такие отчёты считаются отдельно
(`unverified` на странице сводки) и сами по себе не повод откатывать. В режиме
`testing` почта всё равно доставляется; в `enforce` такая почта не доходит.
В письме — тип ошибки (`result-type`); что делать по каждому —
`ops/mail-security-worker/README.md`, раздел «When the alert arrives».
Если `enforce` блокирует настоящую почту (сбои повторяются в отчётах Google или
Microsoft — блок `verified` на странице сводки) — вернуть `testing` (Rollout 4
там же). Счётчики по дням — на странице сводки.

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

## Own sources: CT lookalikes and in-app reports (`LOOKALIKE_GENERATOR_ENABLED`) — off

`scripts/refresh_lookalikes.py` (workflow *Refresh own sources*, hourly)
reads every new Let's Encrypt certificate from the CT logs, keeps the names
the scorer's rules say imitate a Russian brand (`sberbamk.ru`,
`gosuslugi-lk.help`, `сбербанк-бонус.рф`) as candidates, and promotes one
into `dangerous_domains:lookalike` only on evidence it gathered itself: the
site serves a password form that names the brand. In-app reports
(«Пожаловаться на сайт», `POST /api/v1/feedback/report` with
`false_negative`) are queued and need the same evidence — a report, or a
hundred, is never enough on its own. A third party's listing (Safe Browsing,
abuse.ch …) is recorded with the evidence but never publishes a host: that
would derive this list from theirs, the licence problem it exists to avoid.
The blocklist refresh publishes both sets as exact hosts through every guard
a feed host meets (top-100k/top-1M popularity veto, brand-owned veto, hosting-platform
apexes, zones), for 14 days after the last confirmation.

It is **off**. Set `LOOKALIKE_GENERATOR_ENABLED=1` in **both** places: the
API service on Railway (it queues reports and shows the report button via
`/api/v1/mobile/version` → `features.report_sites`) and GitHub → Actions →
Variables (the hourly job runs, and the refresh job publishes). Unset both
to switch off: stored hosts leave the list at the next refresh, with no
retention tail.

Before switching on, run the workflow by hand with *dry run* checked (the
default): it writes nothing and uploads `lookalikes-report.json` — the
candidates, which of them pass the publisher's gates, and `would_publish`.
Look through the names for brand-owned ones first.

**A wrongly promoted site**: make its confirmation look expired, then run
the refresh workflow by hand (a production Redis write, your decision):

    ZADD dangerous_domains:lookalike XX <now minus 14 days and 1 hour, unix seconds> <host>

(`dangerous_domains:reports` for a reported one). The lasting fix: the
brand's own name goes into `data/typosquat_targets_ru.json` (`official`, with
its evidence) so the rule never matches it again, or another owner's exact
host into `data/brand_owned_hosts.txt`.

## When the DNS canary goes red

- `LISTED NAME NOT BLOCKED` / `NOT BLOCKED BY US` — the gateway is not
  filtering. Check `/health/deep` (`components.doh`, `components.blocklist`)
  and the last refresh run; the `dangerous_domains` set may have expired
  (3-day TTL). If `components.doh.ok` is true while the canary says not
  blocked, the decision code works and the fault is on the public path
  (routing, the `/dns-query` route, caching in front of it).
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
secret instead of rotating it. The one file-name exception: the weekly
benchmark's generated `docs/benchmarks/<date>-fresh-urls.{json,md}` (public
phishing URLs whose tracking tokens took a new shape every week and kept the
scheduled scan red) are allowlisted by that exact name pattern; every other
file under `docs/benchmarks/` is still scanned.

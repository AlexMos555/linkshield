# CT lookalike generator: dry run on live logs, 2026-10-05

`scripts/refresh_lookalikes.py --dry-run` (PR #74) against Let's Encrypt's CT
logs from a developer machine, after this PR's fixes (Cyrillic names compared
decoded, every shard read, publishing only on our own evidence).

    python scripts/refresh_lookalikes.py --dry-run --verify none --max-fetch 0 \
        --max-verify 100000 --hours 1 \
        --artifact live_list.bin --state-file state.json --report-json report.json

What the runs touched: the logs (data tiles and checkpoints), Google's log
list, the Public Suffix List, and the public phone artifact
(`/api/v1/blocklist/dns`, version 1791179446, 467,945 names) for the "already
listed" check. Nothing else: no Redis, no production API, no suspected site
(`--verify none --max-fetch 0`). Every candidate below is a name; none was
opened in a browser or fetched. Names were judged by spelling plus a DNS NS
lookup.

## Shards: the first runs read a seventh of the issuance

Static-CT logs are sharded by certificate **expiry**. The reader first took
only the shard whose interval covers today (2026h2). Measured on 2026-10-05,
Sycamore2026h2 grew ~94k leaves an hour, and Sycamore2027h1 (where today's
90-day certificates go) ~570k. The fix reads every usable shard a certificate
issued today can land in: 2026h2, 2027h1 and 2027h2 of both logs. The table
keeps the earlier runs (2026h2 only) for comparison.

## Numbers

| | **1 h, all shards** (final) | 1 h, 2026h2 only | 3 h, 2026h2 only |
|---|---:|---:|---:|
| shards read | 6 | 2 | 2 |
| tiles read / failed | 9,530 / 0 | 3,127 / 0 | 9,377 / 0 |
| CT entries (leaves) scanned | 2,438,179 | 800,000 | 2,400,000 |
| certificate names | 4,405,990 | 1,364,247 | 4,493,982 |
| distinct hosts | 1,789,442 | 533,171 | 1,804,651 |
| candidates (match a Russian brand) | **19** | 5 | 11 |
| …already on the phone list | 0 | 0 | 0 |
| …pass the publisher's gates | 19 | 5 | 11 |
| **would be published** | **0** | 0 | 0 |
| wall time (of which matching) | 1,195 s (523 s) | 341 s (102 s) | 876 s (305 s) |

"1 h" is the bootstrap window: the last 600k leaves of each shard (2026h2
takes ~6 h for that, 2027h1 ~1 h, 2027h2 all 19k leaves so far). Peak memory
1.5 GB; matching ran on every core of a laptop.

**Would be published: 0, by construction.** A candidate is published only on
evidence we gather ourselves, a password form naming the brand, and that
needs a page fetch, which these runs did not do from a developer's machine.
The gates row is what the publisher would keep *if* that evidence were
found. Tranco-1M is not in the dry run's gates (it needs production Redis);
the bundled top-100k and the brand-owned veto are.

Final run by method: character substitution 8, high similarity 4, TLD
confusion 3, brand under open zone 2, hyphen injection 1, combosquatting 1.
By brand: Avito 4, T-Bank 4, VK group 2, Beeline 2, Russian Post 2,
Alfa-Bank, MTS, Sber, Sovcombank, Yandex 1 each. The 3-hour 2026h2 run also
found a brand + Russian lure name, `bonus-spasibo-sberbank.ru`.

## The candidates, judged by name (final run, plus the 3-hour run)

| host | imitates | method | judgement |
|---|---|---|---|
| login.tbank.com.ru, go.tbank.com.ru | tbank.ru | brand under open zone | **suspicious**: T-Bank's name under the open com.ru zone, a `login.` host |
| sberdaǹk.ph (`xn--sberdak-mqc.ph`) | sberbank.ru | character substitution | **suspicious**: mixed-script spelling of Sberbank |
| sovᴋomɓank.ph (`xn--sovomank-ipd1159d.ph`) | sovcombank.ru | character substitution | **suspicious**: mixed-script spelling of Sovcombank |
| bonus-spasibo-sberbank.ru (3 h run) | sberbank.ru | combosquatting, lure word | **suspicious**: Sber's «Спасибо» programme plus «bonus» |
| hochtabank.ru (3 h run) | pochtabank.ru | character substitution | **suspicious**: one letter off Pochta Bank, under .ru |
| russian-post.site | pochta.ru | hyphen injection | **suspicious**: Russian Post's English name under .site |
| контакти.com (`xn--80aqebnf3ac.com`) | vk.com | high similarity | unclear: Ukrainian/Bulgarian «contacts» |
| alfabantu.com | alfabank.ru | high similarity | unclear |
| qvito.dk, evito.se | avito.ru | character substitution | unclear, leaning legitimate: Scandinavian names on local hosts |
| tinkoff.de | tinkoff.ru | TLD confusion | parked (ParkingCrew NS): harmless today, a classic resale lookalike |
| ww38.yandexmail.co | yandex.ru | combosquatting | parked (Above.com NS; `ww38.` is a parking host) |
| mairu.net | mail.ru | high similarity | **likely false positive**: a Japanese name on Japanese DNS |
| blog.avita.guide | avito.ru | character substitution | **likely false positive**: Avita is its own brand |
| www.avitro.de | avito.ru | high similarity | **likely false positive**: a German name |
| pay.beeline.buzz, www. | beeline.ru | TLD confusion | **likely false positive**: "beeline" is an English word; the apex is a Squarespace site |
| thank.miami | tbank.ru | character substitution | **false positive**: an English word |
| www.m75.ca | mts.ru | character substitution | **false positive**: m75 is not MTS |
| test.russiangost.com | pochta.ru | character substitution | **likely false positive**: "Russian GOST" means standards |

By name alone, about 6 of 17 registrables in the final run look like
phishing, 2 are parked, and 6 look like other owners' legitimate sites. That
is why a name never publishes anything: the independent signal has to
separate them. None of the likely false positives is a site that would serve
a password form naming MTS, T-Bank, Avito or Beeline. The short-name
substitutions (`m75` ~ `mts`, `thank` ~ `tbank`) come from the scorer's rule
itself, and this PR does not change that rule. They are worth a look in the
scorer (see the PR).

No brand-owned name became a candidate (the pre-gate drops them before
matching), and none of the candidates is on the phone list today: the feeds
we ship had none of them.

## What this does not measure

* **How many candidates the page check confirms.** That means fetching each
  suspected site, so run it on a server: the workflow *Refresh own sources*,
  run by hand with *dry run* checked, fetches up to 40 pages per run from a
  GitHub runner and uploads the same report with `would_publish` filled in.
  It writes nothing.
* **Recall.** The generator only sees Russian-brand phishing whose name
  imitates the brand, with a certificate from Let's Encrypt. Other CAs'
  tiled logs can be added with `LOOKALIKE_CT_OPERATORS`.
* **Cost at full rate.** Steady state is one hour of every shard per run,
  about 1.3M leaves (2 × (~570k + ~94k)): ~5,200 tiles, ~2.5 GB downloaded,
  ~1M distinct hosts. Here matching ran at ~3,400 hosts/s on a laptop, so
  about 5 minutes. On a 4-core GitHub runner, expect 10 to 20 minutes per
  hourly run, inside the job's 50-minute lock. These are estimates from one
  checkpoint reading; the first scheduled runs will show the real figures.

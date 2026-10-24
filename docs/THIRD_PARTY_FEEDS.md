# Third-party data Cleanway uses, and under what terms

Every external source the product talks to, what we do with its data, the
licence or terms it comes under, and the switch (if any) that turns it off.
This is the attribution notice the CC BY feeds ask for and the working list
behind plan §4 ("лицензионный срез до первого рубля"). Terms were read on
the dates given; a row marked *likely* rests on a secondary source or an
earlier reading and should be re-read before it is relied on.

While the product was free, non-commercial terms were a grey area. With
the first paid subscription they are not. Where things stand (2026-10-24):
`BLOCKLIST_LICENSED_ONLY` is `true` in the repository's Actions variables
(read 2026-10-24), so the published blocklist no longer reads OpenPhish,
phishing.army, since 2026-10-23 CSIRT Italia, and — from the first forced
publish after the change of 2026-10-24 — Phishing.Database (§1; unset, the
code still builds the list as before); `LICENSED_INTEL=licensed` is the
analyzer's default since 2026-10-21, so without an explicit `all` the six
non-commercial lookups are not asked (§2); URLhaus is retired from the
blocklist and from training since 2026-10-21 (§1, §3); Tranco left
training on 2026-10-22 and the popularity ranking on 2026-10-23 (§2a, §3),
though installed app and extension copies keep its lists until their next
releases (§2a). CSIRT Italia's terms were settled on 2026-10-23 by leaving
it out under the switch until ACN grants written permission (§1).
Phishing.Database's provenance, the last open question here, was settled
on 2026-10-24 as far as the public record goes: part of its data is the
maintainers' own, the rest comes from upstream "partners" and "trusted
third party sources" they do not name and cannot attribute entry by entry,
so those partners' terms are unknown, and an MIT notice on the compilation
cannot relicense them. That makes use in a paid product *not clearly
permitted* — not shown to be barred: §1 gives the evidence both ways — so
under the commercially-licensed-only policy the switch leaves it out too,
until they say in writing what is in it and under which terms (§1; the
first publish without it needs `--force` once, and the merge starts a
clock — §1, the switch). The order of flipping, the numbers it cost and
what replaced the loss are in the PR that added this file and in
`docs/benchmarks/day-one-coverage-latest.json`.

## 1. Bulk feeds that build the phone's blocklist

Built by `scripts/refresh_dangerous_domains.py` every 6 h into the DNS
gateway's set and the phone artifact (`GET /api/v1/blocklist/dns`). What the
phone receives is a list of 48-bit hashes of names; the DoH gateway holds the
names. Redistribution to every phone is the act each licence has to allow.

| Source | URL | Terms (date read) | How we use it | Switch |
|---|---|---|---|---|
| ~~**URLhaus** (abuse.ch)~~ | ~~`https://urlhaus.abuse.ch/downloads/csv_online/`~~ | abuse.ch Terms of Use 2025-11-04: free for not-for-profit use only, no derivative works; commercial use through a Spamhaus subscription (read 2026-09-21, 2026-09-29). Since 2026-10-21 the anonymous exports answer **410 Gone**; downloads need a personal Auth-Key in the URL | **Retired 2026-10-21** (`RETIRED_FEEDS`): never fetched; the ~900 published names only it backed left with the first publish without it (not carried, not retained). Cleanway sells plans, so we did not request a key | Gone |
| **OpenPhish** community feed | `https://openphish.com/feed.txt` | openphish.com/terms.html: no commercial use "including … security operations, threat intelligence, detection … customer protection", no redistribution of any part to third parties; lifted only by written consent (read 2026-09-21, 2026-09-29) | Phishing URL hosts | **`BLOCKLIST_LICENSED_ONLY=1` removes it** |
| **phishing.army** extended | `https://phishing.army/download/phishing_army_blocklist_extended.txt` | CC BY-NC 4.0 (the file's own header). Aggregates PhishTank, OpenPhish, CERT.pl, PhishFindR, urlscan, Phishunt (read 2026-09-21) | ~150k domain names | **`BLOCKLIST_LICENSED_ONLY=1` removes it** |
| **Phishing.Database** (mitchellkrogza; now github.com/Phishing-Database) | `https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt` | MIT on the compilation (LICENSE, © Mitchell Krog, Nissar Chababy, Phishing.Database Contributors). **Provenance (read 2026-10-24): an aggregation of third-party feeds the project does not name.** No list of sources exists in the README, the organisation's README, the contribution repo (Phishing-Database/phishing: community additions, false positives, a url-shorteners whitelist), or the public build script (`ci/update.sh` and `ci/.loadenv` in the first commit after the 2024-12-18 history rewrite, `394b74e9`: it only unpacks `input-source/ALL-phishing-*.zip`, made off GitHub). What the maintainers have said in the issue tracker: the build fetches and cleans "the different sources" (funilrys, #2, 2018-09-25); "combined input sources files" (mitchellkrogza, #9, 2019-07-03); an entry "very possible" came "from Phishtank or Phishstats" (#274, 2021-11-26); PhishTank inputs "suspended" for false positives (#275, 2022-01-07); "multiple sources", and no time to tell "which provider it came from" (#329, 2022-07-18); an entry from "one of our partners", not their crawlers (funilrys, #365, 2022-09-20); "We have our very own. + Others." (funilrys, #348, 2024-12-18); a Safekeeper: domains imported "from trusted third party sources" (discussion #1261, 2025-03-20), and another asking for the crawler logs to see why a name was listed (dev-center #7, 2024-03-30). Their 2024 README asked false-positive reporters for proof of removal "from other platforms (e.g., Phishtank, Openphish)", and the issue form still offers PhishTank and OpenPhish as where a listing was found. PyFunceble (Apache-2.0) only re-tests whether a name is up; it is not a source. **Against a restriction** (read 2026-10-24): the README calls the project "an official data **vendor** for **VirusTotal**", a commercial service; the organisation's new-adopter issue form invites an "Organization / Company" or a "Security Vendor"; and part of the data is the maintainers' own ("We have our very own", #348). **The upstreams they named:** PhishTank is the best-evidenced — verbatim PhishTank CSV rows in ALL-phishing-links (#275, until those inputs were suspended), and the "partner" listing in #365 traced by a commenter to PhishTank phish_id 5976284 — and PhishTank allows commercial use (§2). PhishStats was named once, in 2021, as a possible origin ("Very possible … from Phishtank or Phishstats I guess", #274); the terms quoted for it are the June 2026 edition (phishstats.info/terms §5: no sharing or redistributing "raw PhishStats data feeds without our written permission"), not necessarily the terms in force when that data came in. OpenPhish (above) bars redistribution and is only implied. **What decides it:** the rest comes from unnamed "partners" (#365) and "trusted third party sources" (discussion #1261) whose terms are unknown, and the maintainers cannot say whose each entry is (#329); an MIT notice cannot relicense data its authors did not own. So **use in a paid product is not clearly permitted** — not shown to be barred either — and the policy (commercially licensed sources only) leaves it out until it is. Also: the GitHub copy has not changed since 2026-10-02 15:30 UTC and phish.co.za, the official download, has been down since 2026-10-03 (503 when read 2026-10-24; their #2325, open) | ~392k "active" phishing domains (392,072 distinct on 2026-10-24), the bulk of the list until this change: 381,804 of the 675,263 names a licensed build held on 2026-10-24 were backed by it alone (56.5 %); 6,314 of its hosts (1.6 %) are on another licensed feed. Of 400 of those names drawn at random, 53 % still resolve (65 % of the names that stay) | **`BLOCKLIST_LICENSED_ONLY=1` removes it** (`NON_COMMERCIAL_FEEDS`) — left out under `BLOCKLIST_LICENSED_ONLY` since 2026-10-24. **The first publish without it needs `--force` once** (58.3 % of the live artifact changes, 50 % gate; the merge-day steps and their deadline are below). Revisit if the maintainers name, in writing, every source in it and the terms each comes under (contact@phish.co.za; not sent — a founder step); bringing it back adds ~381k names at once and needs one forced publish too (the same steps). Never used for training (§3). Credited on the methodology page in the past tense, not as a source in use: MIT's notice goes with every copy, and the Android files built while it was in carry it in their seed list (§5); with the switch off it is read exactly as before |
| **Phishunt.io** | `https://phishunt.io/feed.txt` | Terms §7 "Data license": feeds and API responses released as CC0 1.0 (read 2026-09-21) | Hourly phishing URL hosts | Keep |
| **TweetFeed.live** | `https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv` | README: CSV/JSON/RSS/MISP/STIX feeds and public API responses under CC0 1.0, no attribution required. The `/v1/ioc` and `external.json` blocks are abuse.ch-licensed and are never read (read 2026-09-21) | 365-day window of reported domains/URLs | Keep — but it is a *source*, so a TweetFeed sample is not a held-out benchmark for this list |
| **CERT Polska** Lista Ostrzeżeń | `https://hole.cert.pl/domains/v2/domains.txt` | API spec §1: publicly available, may be processed without restriction, manually or automatically; names that leave the list must be unblocked (we rebuild from scratch every run) (read 2026-09-21) | Exact hosts only (never promoted to a whole domain) | Keep |
| **CSIRT Italia / ACN** MISP feed | `https://www.csirt.gov.it/feed-misp/manifest.json` | Only events tagged `tlp:clear` / `tlp:white` are read — TLP:CLEAR means unlimited disclosure; anything else is skipped (the TLP marking is read per event, 2026-09-21). TLP is a sharing label, not a licence: FIRST says it "was not designed to handle licensing terms" and TLP:CLEAR sharing is "subject to standard copyright rules" (first.org/tlp, read 2026-10-23). The feed states no licence (manifest and events, 2026-10-23). ACN's Note legali (acn.gov.it/portale/note-legali, read 2026-10-23; www.csirt.gov.it redirects to acn.gov.it) say the site's contents, data included, are ACN's unless stated otherwise, grant no licence beyond personal use, and bar commercial use without ACN's prior written authorisation. Whether that covers the MISP feed is not stated | Malware C2 hostnames, exact only | **`BLOCKLIST_LICENSED_ONLY=1` removes it** (`NON_COMMERCIAL_FEEDS`) — left out under `BLOCKLIST_LICENSED_ONLY` since 2026-10-23; revisit if ACN grants permission. Policy: commercially licensed sources only, and nothing here grants a commercial licence. Not fetched, not an outage; the exact hosts only it backed leave with the first publish after the change, like a switched-off feed's — its window read 2026-10-23 held 340 host entries, 184 distinct hosts, none on the popularity guard: ~0.03 % of the ~700k live set (699,870 members in production's refresh run of 2026-10-23), far under the 50 % churn gate, so no `--force`. Names it listed before that window and production still holds in retention go when their 14-day window ends, as for any switched-off feed. No longer credited on the methodology page as a source in use; with the switch off it is read exactly as before |
| **PhishDestroy** DestroyList, DNS-verified active domains | `https://raw.githubusercontent.com/phishdestroy/destroylist/main/dns/active_domains.json` | phishdestroy.io/dataset: data "Released under CC0 1.0 Universal", "no restrictions, no attribution required", fit for "commercial products"; repository MIT; the same page notes the HuggingFace card says MIT and the Live page CC-BY-4.0 — all three allow a paid product, and §5 attributes it anyway. Sources: their own parsers (ads, SEO, social, dnstwist) and Telegram-bot reports; the aggregated "Community" list is a different file and is not read. "Non-commercial volunteer project" describes the operator, not a term (read 2026-10-21) | ~137k crypto-drainer, wallet/exchange-lure and fake-shop domains, re-resolved daily by the maintainer; promotes like Phishing.Database. Measured 2026-10-21: ~114k names new to the list after every guard, 0 on Tranco-1M, 0 on the must-resolve and RU legit lists, ~850 under RU/CIS ccTLDs | Keep |
| **PhishTank** (Cisco/OpenDNS) online-valid dump | `https://data.phishtank.com/data/<key>/online-valid.csv.gz` | FAQ: commercial use of the API — "Yes, it is OK" (read 2026-09-29). Needs an application key; registration closed at the moment. Terms of Use refer to the Cisco EULA (*likely*) | Verified-online phishing URL hosts, **one cached download a day** (`api/services/phishtank_feed.py`) | **Off without `PHISHTANK_API_KEY`**; on the job through the `BLOCKLIST_PHISHTANK_SOURCE` variable |
| **Cleanway checks** (server-confirmed hosts) | — | Google Safe Browsing / Web Risk verdicts; both bar passing results on (see §2) | Hosts our own checks confirmed dangerous | **Off** (`PUBLISH_CONFIRMED_THREATS`), stays off |

Guards on every source, whatever its terms: the top-100k / top-1M
popularity vetoes (§2a: Majestic Million + Chrome UX Report; Tranco's until
2026-10-23) with the hand-curated infrastructure names
(`data/infrastructure_domains.txt`), public suffix list vetoes,
shared-hosting tenant rules (the curated `data/hosting_platforms.json`
suffixes and the publisher's `UNRANKED_SHARED_DOMAINS` since 2026-10-23),
hand-verified brand-owned hosts (`data/brand_owned_hosts.txt`), the churn
and post-publish gates. Sources: Public Suffix List
(`https://publicsuffix.org/list/public_suffix_list.dat`, MPL 2.0) and the
popularity ranking of §2a.

### What `BLOCKLIST_LICENSED_ONLY` does, exactly

Unset (default): every row above except PhishTank, byte for byte the list
published today (proved in the PR on one feed snapshot: same names, same
count, the only header difference the build timestamp). Set to `1`:

* OpenPhish, phishing.army, (since 2026-10-23) CSIRT Italia and (since
  2026-10-24) Phishing.Database (`NON_COMMERCIAL_FEEDS`) are not downloaded
  and not in `fetched` — so they are **not an outage**: nothing is carried
  for them, their stored health state is forgotten, and the run does not
  go red.
* The published names only they backed (per the last healthy run's backing
  record) leave with that publish. They are *not* held for the 14-day
  retention window: that window exists for feeds that forget a live
  phishing site, not for data we may no longer ship.
* The set changes by more than the 50 % churn gate: the first run after
  flipping needs `--force` (the workflow's `force` input). One run.
  (Retiring URLhaus did not: ~900 names of ~560k, 0.2 %. Measured
  2026-10-21 on a dry run against the live artifact, the first publish with
  PhishDestroy and without URLhaus changes the artifact by ~29 % at most —
  +114k / −28.6k hashes, and most of the −28.6k are names production keeps
  in retention, which a Redis-less dry run cannot see — so no allowance was
  needed. Nor does CSIRT Italia joining the switch on 2026-10-23, with the
  switch already on: its window held 184 distinct exact hosts (340 host
  entries) of the ~700k live set, ~0.03 %; `tests/test_blocklist_licence_switches.py`
  publishes such a switch-on run without `--force`.)
* **Phishing.Database joining the switch (2026-10-24) does need `--force`,
  once.** Measured on one feed snapshot of 2026-10-24 with
  `scripts/eval_day_one_coverage.py` (fingerprint `e55e4cfe…`, the same in
  `docs/benchmarks/day-one-coverage-2026-10-24-with-phishing-database.json`
  and `day-one-coverage-2026-10-24.json`): the licensed build goes from
  675,263 names to 293,459 (381,804 leave, none join: 56.5 % of the set),
  its artifact from 602,426 hashes / 3.61 MB to 263,363 / 1.58 MB. Against
  the live artifact of that day (628,733 hashes, of which the licensed build
  without the change holds 600,901) a publish without it changes 58.3 %;
  against the 699,870 names production's Redis set held on 2026-10-23,
  ~55 %. Both are over `MAX_CHURN` (50 %). So after the merge **every
  scheduled run is refused by the gate** (`PUBLISH GATE: churn …`, exit 4,
  the run goes red) and the live set and phone artifact stay as they were,
  Phishing.Database's names included, until one forced publish.
  **A refused run refreshes nothing, so the clock runs from the last
  successful publish before the merge** (runs every 6 h at :23), not from
  the merge: after **~13 h** `/health/deep` reports the blocklist stale
  (`MAX_HEALTHY_AGE_S`, `api/services/blocklist_artifact.py`;
  `api/services/health_probes.py`), the DNS canary fails and the uptime
  worker alerts («Список опасных сайтов для телефонов устарел…»); after
  **48 h** Android calls its copy stale (`BlockList.kt` `STALE_AFTER_MS`);
  after **72 h** the set and the artifact expire (`TTL_SECONDS`) — no DNS
  blocking, nothing for the phones to sync. **Right after merging, before
  the next :23 run:**
  1. Dispatch `refresh-dangerous-domains.yml` with `dry_run: true` and
     `force` **off**. It is expected to end red on `PUBLISH GATE: churn
     ~55–58 %`. Check its log: the line `licence switch: N published names
     only Phishing.Database backed leave with this publish` shows N ≈
     381,000, and there is **no `FEED DEGRADED` line**. Not with `force`:
     `--force` also takes every feed's size at face value (`accept_sizes`),
     so it would hide a truncated feed — which the forced run would then
     keep as that feed's new baseline. If a `FEED DEGRADED` line is there,
     stop and wait for the feed to recover.
  2. At once after it, dispatch again with `force: true` only. It should be
     green with `publish gate: ok` and the same leaving line.
  3. The next scheduled run is green without `--force`.

  The forced run takes the names only it backed out (not carried, not
  retained, not an outage). `tests/test_blocklist_licence_switches.py`
  walks refused → forced → ordinary, pins that a dry run without force is
  the check `--force` cannot be, and that bringing the feed back needs the
  same one forced publish.
* `BLOCKLIST_EXCLUDE_FEEDS=TweetFeed` (comma-separated names) leaves further
  feeds out — used by `scripts/eval_day_one_coverage.py` to build the
  variants it scores, never in production.

**What leaving Phishing.Database out costs** (2026-10-24, the snapshot
above; the phone's rule — a listed name blocks itself and its subdomains;
`licensed` is what production publishes):

| Held-out sample | With it | Without it |
|---|---:|---:|
| PhishTank online-valid, first reported ≤ 1 day (196 hosts), `licensed` | 25.5 % | 25.0 % |
| — ≤ 7 days (861) / ≤ 30 days (2,279) | 30.9 % / 29.4 % | 30.7 % / 29.2 % |
| — the whole dump (28,061 distinct hosts, any age) | 28.3 % | 24.0 % |
| TweetFeed ≤ 1 / 7 / 30 days (106 / 1,683 / 3,082), `licensed-minus-tweetfeed` (the honest variant) | 3.8 / 32.7 / 20.4 % | 3.8 / 32.7 / 19.7 % |
| The weekly benchmark's selection (`eval_fresh_urls.py`: first 600 PhishTank rows, one per host, 200 kept), drawn 2026-10-24 | 50 of 200 | 49 of 200 |
| The committed weekly sample of 2026-10-18 (`docs/benchmarks/latest.json`, URLhaus + PhishTank, 121 IP literals) | 17 of 200 | 17 of 200 |

Fresh phishing barely moves because the feed has stopped: its GitHub copy
stopped changing on 2026-10-02 and phish.co.za is down (§1), so what it
alone held is the long tail (28.3 → 24.0 % on the whole dump). The weekly
benchmark scores the live `/public/check`, where a listed host is
dangerous at once (`cleanway_blocklist`) but every other signal still runs,
so this change can cost that number at most the hosts only it covered: 1
of the 200 drawn on 2026-10-24 (8ezsnw.n0c.world), 0 of the 2026-10-18
sample. Top-10k false positives: 0 with and without it. ML training never
read it (§3), so the Monday retrain does not change.

### The held-out problem

Every coverage number needs a sample the list was *not* built from.

* **PhishTank** is that sample today (`scripts/eval_blocklist_coverage.py`,
  `scripts/eval_day_one_coverage.py`). The day `PHISHTANK_API_KEY` reaches
  the refresh job, PhishTank is a source and every PhishTank number becomes
  circular. The day-one report builds with whatever the key adds (each
  build's `feeds` is what it was really made from, `run_sources`), marks
  such numbers `circular: true` and drops them from `headline` — with the
  key set, the report has no PhishTank headline at all.
* **TweetFeed** has been a source since 2026-09-26 (#47). Its "independent
  30-day sample" (report of 2026-09-25) is honest only against a list built
  without it; the day-one report builds such variants.
* **phishing.army is itself built from PhishTank**, so as long as it is in
  the list the PhishTank number is inflated by that path (82 % of a PhishTank
  sample verbatim, 2026-09-21). The `licensed` variant has no such path —
  and since 2026-10-24 not the older one either: Phishing.Database took
  PhishTank inputs until its maintainer suspended them on 2022-01-07 (§1),
  and its "active" list keeps such names while they resolve.

Proposal for after the flips (a founder decision, not made here): hold out
**CERT Polska** (small, exact-host, no overlap with the aggregates — cheap to
give up as a source) and a **TweetFeed 30-day window with TweetFeed dropped
as a source** (it bought 12 held-out hosts in 3,000 on 2026-09-21). Then
PhishTank can be ingested and the public number stays measurable.

## 2. Lookups the API makes for one `/check`

`api/services/analyzer.py` asks up to 19 sources about the bare domain name
(never a URL, never who asked) — 13 under the default `LICENSED_INTEL=licensed`.
`docs/PRIVACY.md` lists them for users.

| Source | Endpoint | Terms (date read) | Switch |
|---|---|---|---|
| **Google Safe Browsing v4** | `safebrowsing.googleapis.com/v4/threatMatches:find` | developers.google.com/safe-browsing/terms: "Unless you have a separate agreement … you may not use the Safe Browsing API for commercial purposes" (read 2026-09-29). v4 support ends 2027-03-31 (*likely*) | Replaced by Web Risk when `WEB_RISK_API_KEY` is set |
| **Google Web Risk** Lookup API | `webrisk.googleapis.com/v1/uris:search` | Google Cloud terms; billed per lookup after 100,000 a month (cloud.google.com/web-risk/pricing, read 2026-09-29). Results may not be passed on to third parties — `PUBLISH_CONFIRMED_THREATS` stays off. Needs a Google Cloud project with billing, which may not be open to a Russian legal entity (*uncertain*) | **On with `WEB_RISK_API_KEY`** (`api/services/web_risk.py`); threat types MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE; answers cached until Google's `expireTime` |
| **PhishTank** checkurl | `checkurl.phishtank.com/checkurl/` | FAQ: commercial use OK; key needed for rate limits (read 2026-09-29) | Always on (answers nothing for fresh URLs without a key) |
| **URLhaus** host API | `urlhaus-api.abuse.ch/v1/host/` | abuse.ch ToU 2025-11-04 (non-commercial). **401 Unauthorized without a personal `Auth-Key` header since 2026-10-21** (probed that day) | **Off by default** (`LICENSED_INTEL=licensed`). The open question of 2026-09-21 is resolved: same terms as ThreatFox, so it goes with them. Until the fix a 401 read as "not listed" on every check; a non-2xx answer now raises (a failed, unmeasured check) |
| **ThreatFox** | `threatfox-api.abuse.ch/api/v1/` | abuse.ch ToU 2025-11-04 (non-commercial, no derivative works). 401 without a key since 2026-10-21 | **Off by default** (`LICENSED_INTEL=licensed`); a 401 raises |
| **MalwareBazaar** | `mb-api.abuse.ch/api/v1/` | abuse.ch ToU 2025-11-04. 401 without a key since 2026-10-21 | **Off by default** (`LICENSED_INTEL=licensed`); a 401 raises |
| **Feodo Tracker** | `feodotracker.abuse.ch/downloads/ipblocklist.json` | abuse.ch ToU 2025-11-04. Still answers 200 without a key (2026-10-21) | **Off by default** (`LICENSED_INTEL=licensed`) |
| **Spamhaus DBL** public mirror | DNS `<domain>.dbl.spamhaus.org` | DNSBL fair-use policy: "free of charge for non-commercial use by small and medium sized organisations"; queries must come from an identifiable resolver, not large shared hosting (read 2026-09-29). Through a public resolver the mirror answers `127.255.255.254` — until 2026-09-29 the analyzer read that as "not listed" (`api/services/dnsbl_checks.py` fixes it: an error code is "not consulted") | **Off by default** (`LICENSED_INTEL=licensed`) |
| **SURBL** multi | DNS `<base>.multi.surbl.org` | surbl.org/guidelines: `127.0.0.1` means access is blocked, sign up for the Sponsored Data Service; the usage policy excludes the free service from paid products (*likely*, read 2026-09-21/29) | **Off by default** (`LICENSED_INTEL=licensed`) |
| **PhishStats** | `phishstats.info:2096/api/phishing` | Free API, no key, tiered plans. Terms of Service (phishstats.info/terms, "Last updated: June 2026", read 2026-10-24): §10 a limited, revocable licence to use the Service "for lawful security research, threat intelligence, and related purposes"; §5 no sharing, reselling or redistributing raw data feeds without written permission, no bulk download beyond the tier's limits; §11 (Disclaimers): "Phishing intelligence is provided for informational and security-research purposes only". Commercial use is neither granted nor barred in words — by §1's standard that is **not clearly permitted for a paid product** either. It stays On for now, and that is a different call from §1's, said here so it is not mistaken for the same one: a per-check lookup copies nothing to anyone (§5's bar is on redistributing feeds, which is what §1 removes Phishing.Database for), the terms are known and §10 licenses threat-intelligence use by name, and §11 sits in the warranty disclaimer. The strict reading would add `phishstats` to `RESTRICTED_CHECKS` (`api/services/licensed_intel.py`), leaving it off under `LICENSED_INTEL=licensed`; whether a paid product's lookups are within §10–§11 is a founder decision, or a question for PhishStats | On |
| **AlienVault / LevelBlue OTX** | `otx.alienvault.com/api/v1/indicators/domain/…` | Free community API; OTX terms of service (*likely*: free use with attribution) | On |
| **IPQualityScore** | `ipqualityscore.com/api/json/url/…` | Vendor API terms, free tier 5,000/month, paid above; keyed | On with `IPQUALITYSCORE_KEY`, daily budget |
| **RDAP** | `rdap.org/domain/…` | Public registry protocol (redirector) | On |
| **Popularity rank** (§2a) | Redis `tranco:ranks`: the top-1M of the Majestic Million + Chrome UX Report ranking, rebuilt daily by `scripts/refresh_tranco.py` (Tranco's list until 2026-10-23; a Tranco URL is now refused) | CC BY 3.0 / CC BY 4.0 (§2a) | On |
| **crt.sh** (Watchtower) | `crt.sh/?q=…` | Sectigo's public CT log search, no terms beyond politeness | On |
| **Anthropic Claude** (LLM judge, explainer) | `api.anthropic.com` | Commercial API terms; only a domain-free feature vector is sent | On with `ANTHROPIC_API_KEY`, daily budget |
| **Have I Been Pwned** Pwned Passwords | `api.pwnedpasswords.com/range/…` | Free, k-anonymity range API; no key | On |
| **Cloudflare DNS** (DoH gateway upstream; 1.1.1.1 for Families in the public comparison) | `cloudflare-dns.com/dns-query`, `family.cloudflare-dns.com` | Cloudflare public resolver terms | On |

### What `LICENSED_INTEL=licensed` does, exactly

**The default since 2026-10-21** (it was `all`). That day abuse.ch's APIs
started answering 401 without a personal key — URLhaus, ThreatFox and
MalwareBazaar had been reporting "not listed" for every domain, a silent
miss inflating the measured-check count — and Cleanway sells plans, which
all six free tiers exclude. `LICENSED_INTEL=all` is the explicit opt-in for
a not-for-profit deployment; the abuse.ch lookups then also need a key the
analyzer does not send, and without one they fail as unmeasured checks.

The six sources (SURBL, Spamhaus DBL, URLhaus, ThreatFox, MalwareBazaar,
Feodo Tracker) are not in the analyzer's plan at all: not asked, so never
"not listed", and they leave the total a verdict is measured against — an
analysis is 13 checks of 13, not 13 of 19 with six that were never asked.
Scores, levels and `confidence_pct` for the same evidence are identical
with the switch on or off (pinned in `tests/test_licensed_intel.py`).

Measured offline on `tests/data/ru_heuristics_{legit,phish}.txt`
(`scripts/eval_ru_heuristics.py`, name-only scoring, 2026-09-29): identical
row for row with the switch on and off, ML on or off — LEGIT 291: safe 290,
caution 1; PHISH 174: caught 142 (caution 108 + dangerous 32). That is
expected and is the point: the name-only rules never consult these sources.
What the switch costs is only measurable on live traffic — on 2026-09-21
SURBL appeared in 9 of 10 dangerous verdicts sampled, but 9 of those 10 also
rested on our own signals. That is the cost of the default: verdicts SURBL or
the DBL alone carried. Watch the weekly benchmark after the flip; the way
back for those two is a paid feed (Spamhaus DQS / SURBL Sponsored Data), not
the free mirrors. Do not re-weight the scorer blind.

### 2a. Domain popularity: the allowlist, the top-1M and the vetoes (since 2026-10-23)

One ranking of registrable domains, built by `scripts/build_top_domains.py`
and nowhere else. Until 2026-10-23 every one of these was Tranco's: no
licence stated for the list, and its default list averages Cloudflare
Radar, CC BY-NC 4.0 (§3).

| Source | Terms (date read) | Use |
|---|---|---|
| **Majestic Million** `https://downloads.majestic.com/majestic_million.csv` | CC BY 3.0 (majestic.com/reports/majestic-million, read 2026-10-22/23; the site-terms question is in §3) | Ranked by linking IP subnets |
| **Chrome UX Report** top origins, global and Russia, via `github.com/zakird/crux-top-lists` | CC BY 4.0 (developer.chrome.com/docs/crux/methodology, read 2026-10-22) | Ranked by Chrome page loads, in buckets |
| **Public Suffix List** | MPL 2.0 | Which hosts are tenants; the public-suffix rules under top names |
| PhishDestroy, CERT Polska, TweetFeed, Phishunt (§3) | CC0 / unrestricted | Names they report leave the instant-safe allowlist unless popularity vouches for them (never the ranking) |

How the rank is made (parameters in the script, provenance of each build
in `data/top_domains_sources.json`):

1. Every host is folded to its registrable domain the way the scorer reads
   it (`www.gosuslugi.ru` → `gosuslugi.ru`, `kvs.gov.spb.ru` →
   `gov.spb.ru`), best rank per list; tenants of shared suffixes (PSL
   private section, `data/hosting_platforms.json`) are dropped. Where the
   scorer's reading is an ICANN public suffix (`srv.hrdc-drhc.gc.ca` →
   `gc.ca`, `x.nhsbsa.nhs.uk` → `nhs.uk`), the host is folded to its PSL
   registrable instead (`hrdc-drhc.gc.ca`, as Tranco ranked it), and a
   suffix itself is never a name. The first build of 2026-10-23 ranked 502
   ICANN suffixes (gc.ca #149, nhs.uk #399), which pulled 2,364 ICANN rules
   into `public_suffixes_in_top.json` (Tranco's: 12) and made the model
   read government hosts as hosting tenants; now 0 suffixes, 0 ICANN rules.
2. CrUX rank = the global bucket, or Russia's bucket × 6 when better.
   Chrome counts few Russians: the Russian sites both lists carry sit
   20-50× lower globally than at home. Without Russia's list the top
   100,000 held 1,842 Russian names (Tranco's: 3,799); × 6 keeps the top
   10,000 as Russian as it was (389 against 360) and lets Russia's 10,000
   most-opened origins in (4,986 Russian names in the 100,000).
3. Dowdall rule, as Tranco itself: score = 1/rank in Majestic + 1/CrUX rank.
4. For the allowlist files only: a name a feed reports stays only when
   both lists rank it in their top 100,000, Majestic in its top 10,000, or
   either in its top 1,000. That keeps facebook.com, t.me, discord.gg,
   docsend.com instant-safe (reporters post the platform a page sits on)
   and keeps roblox.com.bz, sstake.eu, narco24.to, the ushort.* shorteners
   and ~90 more of the ~180 reported names the top 100,000 would have held
   out of it (1,296 in the whole ranking). The names stay in the ranking:
   the Redis top-1M and `data/top_domains_reported.json` (the 701 of them
   in the top 1M, with their rank) feed the popularity bonus, the
   publisher's never-block guard and the phone's veto. The first version
   applied the rule to the whole ranking and so took maya.ph (a bank, CrUX
   top 10,000), rezultati.com, dub.sh, filemail.com, eim.ae and ~690 more
   out of the guard: one feed's report would have blocked them whole for
   every DNS user.
5. Top-N by that rank: 1,000 / 10,000 / 100,000 / 1,000,000 mean the same
   positions they meant in Tranco, so no threshold moved.

| Consumer | Reads | Note |
|---|---|---|
| Instant-safe allowlist (`scoring.is_trusted_top_domain`, `/check`, `/public/check`, scorer Layer 2) | `data/top_100k.json` | 55% of the names are Tranco's; 45,036 enter, 45,036 leave |
| "Ranked #N", OTX gating | `data/top_10k.json`, `data/top_100k.json` and the Redis rank of the host or its registrable (top 100k: OTX skipped; top 1M: skipped up to 5 pulses, halved above; an OTX mention of a ranked name is not a blocklist hit, so the LLM judge still runs) | |
| Popularity bonus −25/−15/−8/−3, unreachable-site vouch, LLM judge (`popularity_*`), publisher's top-1M guard, a company's own GitLab / Jira / Confluence | Redis `tranco:ranks` (key name kept) — the whole ranking, step 4 not applied — loaded daily by `scripts/refresh_tranco.py` from the same `rank()`; `tranco:ranks:meta` says what it was built from (`/health/deep` `components.popularity`); a CrUX month recorded in `data/top_domains_sources.json` that comes back with other bytes is refused | |
| ML features `in_top_domains`, `is_homograph` and the tenant features | `data/top_100k.json`, `data/public_suffixes_in_top.json` — the copies named by hash in `model_meta.json` `feature_data` | see "Sequencing" |
| Publisher popular / tenant guards, own-source lookalike gate | `data/top_100k.json` + `data/top_domains_reported.json` + `data/infrastructure_domains.txt`, `data/public_suffixes_in_top.json`, Redis top-1M | see "Blocklist" |
| Android veto (`popular_veto.txt`, `shared_suffixes.txt`) and the extensions' `hostingTenantSuffixes` | `data/top_10k.json` + the reported names of that rank + `data/infrastructure_domains.txt`, `data/public_suffixes_in_top.json` | each file starts with the CC BY attribution of §5; ship with the next app / extension releases; installed copies keep Tranco's until then, and the methodology page says so (the committed `dist/store-artifacts/cleanway-0.2.2-*`, not uploaded yet, carry the new files since #286) |

**Sequencing.** The model reads the two data files as features, so a model
must be served the copies it was trained on. `ml/train_model.py` records
their sha256 in `model_meta.json` (`feature_data`); `ml_scorer` serves the
model those exact copies — the live files, or archived ones in
`data/feature_data/<name>.<sha12>.json` — and serves no model at all
(rules only, `/health` `ml.feature_data_problem`, `backend_status()` =
`feature_data_mismatch`) when neither is there. `scripts/build_top_domains.py`
archives what the served model reads before it replaces a file and prunes
archives no model names; the replacement guard in `ml/train_model.py`
scores the committed model on its own archived inputs. In this change the
data and a model trained on it land in one commit, so no archive is left;
a future refresh of the list without a retrain keeps the old model on its
archive until the weekly job trains on the new files. That job commits the
three model files only, so the old copy stays in `data/feature_data/`
until the next list rebuild prunes it — harmless (copies are chosen by
hash; `tests/test_ml_feature_data.py` checks each is the file its name
says and walks rebuild → retrain → suite), and no YAML change is needed.

**Tenant zones whatever their rank** (`data/tenant_zones.json`, read by
`scripts/build_public_suffixes_in_top.py`). Tranco ranked a tunnel or
dynamic-DNS zone by its tenants' DNS traffic; the licensed ranking drops
tenant rows before it ranks a name (step 1), so the zone's own name rarely
ranks, and the rebuild above took 468 PSL private-section rules under 235
names out of `data/public_suffixes_in_top.json` (trycloudflare.com,
cloud.goog, jcloud.kz, playstation-cloud.com, ngrok.io, on.aws, us.kg,
replit.dev, dynv6.net …). Every private-section rule of a listed operator
is now kept, rules it adds later included (four more on 2026-10-23), and so
are the zones the PSL lacks, each with dated evidence (Cloud.ru's bucket
zones `s3.cloud.ru`, `s3-website.cloud.ru`, `s3-alt.cloud.ru`). The file
went 1,187 → 1,662 rules in the same offline build (the 2026-10-23
downloads; the other four files byte for byte as before), so the served
model reads its archived copy `data/feature_data/public_suffixes_in_top.8a40e6f92329.json`
until the weekly job trains on the new one. Not `data/hosting_platforms.json`:
its `tenant_suffixes` reach the served model at once, with no pairing.
The file's `registries` (za.com, us.kg, com.ru, com.de, eu.cc … — domain
registries, each with dated evidence) tell the blocklist publisher that one
label under the zone is a registrant's own domain: `build_blockset` promotes
it the way it promotes any registrable (cs-money.com.ru on its www. host,
awi.za.com on 14 listed subdomains), where every other tenant zone stays
exact-only (hnd1.zeabur.app is a Zeabur region, not one owner).

**Blocklist.** The DNS-traffic lists Tranco averaged ranked internet
infrastructure (gtld-servers.net, nflxvideo.net, lencr.org) and free
dynamic-DNS zones; links and page loads do not. Two first-party lists put
the protection back: `data/infrastructure_domains.txt` (DNS, CDN, OCSP,
push and update names from the operators' own documentation; never
blocked, in the phone's veto) and the publisher's
`UNRANKED_SHARED_DOMAINS` plus the curated `data/hosting_platforms.json`
suffixes (tenants blocked exactly, the apex never promoted) — Blogger's
country domains, free DNS, tunnel and hosting zones included. The phone's
veto goes from 9,879 names to 10,026 (the top-10k, the reported names of
that rank, the infrastructure names). A dry run of the publisher on the
2026-10-23 licensed feeds (no Redis, the top-1M guard simulated with each
era's ranking): Tranco era 620,678 names, this change 666,728; the names
the first version blocked whole on one feed's report (maya.ph,
rezultati.com, dub.sh …, 696 registrables) are vetoed. Still blocked whole
although Tranco protected them: 38 registrables of Tranco's top-100k and
529 that only its top-1M carried, mostly reported scam apexes its
DNS-traffic inputs ranked; the PR (#284) lists them, and the legitimate
ones among them go to `data/brand_owned_hosts.txt` after a WHOIS check.
Reviewed the same day, each name checked by RDAP, DNS over HTTPS, a
homepage GET and the feeds, then re-checked independently: 13 brand
domains the feeds list by mistake went to `data/brand_owned_hosts.txt`
(the header now says how a .ru-style registry with no registrant
organisation is handled), 3 wallet node and RPC endpoints to a
hand-verified section of `data/infrastructure_domains.txt`, and 74 zones
whose feeds list tenants only (free DNS, hosters' account and reverse
zones, site builders, CASB proxies, two regency governments) to
`UNRANKED_SHARED_DOMAINS` — with ipq.co's sibling fdns.uk and tr.ht's
com. and net. zones — and Canarytokens' and Websupport's path-shared
hosts in `SHARED_HOSTNAMES`. Every listed tenant stays blocked exactly;
the rest of the 567 stays blocked whole (access.ly too, until its .ly
registrant can be read).

**Measured** (2026-10-23; host-only scoring — `calculate_score({"domain":
host})`: the allowlist, the name rules and the local model; "with
popularity" adds the Redis top-1M signals the analyzer passes; the sets are
fixed files, scored in every column):

| Set | Served today (Tranco list, 2026-10-21 model) | First version of this change | This change, final (licensed list, model retrained on it, seed 42) |
|---|---:|---:|---:|
| Held-out real Russian sites (539), not safe | 1 | 2 | 2 |
| Held-out Russian look-alikes (186), caught | 174 | 173 | 174 |
| Fresh phishing names (5,000, the four feeds on 2026-10-23, none a training row), caught | 1,567 (31.3%) | 1,989 (39.8%) | 1,969 (39.4%) |
| — wrongly answered on sight | 21 | 11 | 9 |
| Long-tail real sites (5,000, ranks 100k-1M), not safe / with popularity | 130 / 108 | 158 / 124 | 154 / 121 |
| Names leaving the allowlist (45,036), not safe with popularity | 4 | 1,921 | 1,899 |
| Government hosts in CrUX's top 50k (1,688), not safe / read as hosting tenants | 315 / 0 | 339 / 362 | 316 / 0 |
| CrUX Russia top-50k hosts under leaving names (1,290), not safe with popularity | 0 | 97 | 63 |
| Phishing.Database ACTIVE hosts (392,164), answered instant-safe | 3,442 | 2,969 | 1,882 |
| AlienVault OTX sample (87 names, 28 with pulses), not safe with popularity | — | 31 | 12 |

The final model: test AUC 0.9120 (names only 0.9098, recall at 0.6
42.5%, benign over 0.6 0.94%). `in_top_domains` is 42% of its importance.
Every step of `retrain-ml.yml` passes on it (AUC health gate; FP /
subdomain / tenant / brand-tenant / recall gates — secure-login.wasmer.app
0.788 against the 0.6 bar; the held-out Russian gate: beeline-online.info
the one ML-flagged site) and the full suite. The leaving names the final
model flags are mostly numeric .xyz names and gambling mirrors from
Tranco's DNS tail (199 "dangerous"); the visible cost is ~190 brand-owned
alternates (googlemail.com, outlook.de, yahoo.de, santander.pl,
protonmail.ch, adobelogin.com, office365.us) that the typosquat rule now
flags "caution" — they were exempt only because Tranco listed them.

## 3. ML training data (`scripts/refresh_training_feeds.py`, weekly)

| Source | Terms | Use |
|---|---|---|
| PhishDestroy DestroyList (DNS-verified) | CC0 1.0 dataset, named fit for commercial products and ML training; repo MIT (read 2026-10-21) | Phishing corpus, at most 6,000 hosts (3,500 until 2026-10-22) |
| CERT Polska Lista Ostrzeżeń | API spec §1: processing without restriction (read 2026-09-21) | Phishing corpus, at most 6,000 hosts |
| TweetFeed `year.csv` | CC0 1.0 (README; the abuse.ch `external` block is never read) | Phishing corpus, at most 6,000 hosts |
| Phishunt `feed.txt` | CC0 1.0 (terms §7) | Phishing corpus (~1,400 hosts, all it carries) |
| **Majestic Million** `https://downloads.majestic.com/majestic_million.csv` | majestic.com/reports/majestic-million, "License": "Licensed under a Creative Commons Attribution 3.0 Unported License" (read 2026-10-22). CC BY allows commercial use; it asks for attribution (§5) | Benign corpus since 2026-10-22 (`data/benign-domains.csv`, with CrUX's registrable domains): the famous / long tail / Russian (.ru/.su/.рф) / IDN / brand-named / lure-word strata and the labels of the synthetic tenants (`ml/train_model.load_benign_domains`) |
| **Chrome UX Report (CrUX) top origins**, global and Russia, `https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/{global,country/ru}/<YYYYMM>.csv.gz` | developer.chrome.com/docs/crux/methodology, "License": "CrUX datasets by Google are licensed under a Creative Commons Attribution 4.0 International License" (read 2026-10-22). Read through zakird/crux-top-lists, a monthly CSV cache of the public BigQuery tables: "The data in this repo is all publicly posted by Google to their CrUX dataset … This is simply a cache of that public data" (README, read 2026-10-22); the repository states no licence of its own, and a cache cannot narrow the data's (CC BY 4.0 §2(a)(5)(B): no downstream restrictions) | Benign corpus since 2026-10-22: the registrable domains of the global list join Majestic's (`data/benign-domains.csv`); every origin's host, global and Russia, is the host list (`data/benign-hosts.csv`): subdomain shapes, names under Russian regional zones, real hosting tenants, lure-word real sites |
| ~~Tranco top-1M, and with subdomains~~ | No licence stated for the list itself (tranco-list.eu, read 2026-10-22); its default list averages five providers: Cisco Umbrella ("free of charge"), Majestic (CC BY 3.0), CrUX (CC BY 4.0 per Google's methodology page; this row said CC BY-SA 4.0 until it was checked there), Farsight (none stated) and **Cloudflare Radar (CC BY-NC 4.0)** | **Removed from training 2026-10-22.** Until then every ranked benign sample (all but the two rows below) |
| `data/typosquat_targets_ru.json` — the `official` and `unrelated` domains | Our own hand verification (name servers, Wikidata P856, whois; 2026-09-27) — first-party data | Benign corpus since 2026-10-22: ~340 real sites that carry a brand's name (gosuslugi29.ru, sberbank1.ru, sberbank.cz), three times each; the ones in the held-out sets are left out |
| Synthetic tenants | Built from the Majestic / CrUX names above (a ranked site's label under a curated hosting platform) | Benign corpus since 2026-10-22, ~2,000: what a real site's name looks like on pages.dev |

Since 2026-10-21. Before: the URLhaus full dump (abuse.ch ToU 2025-11-04:
non-commercial, no derivative works — a trained model is a derivative; the
anonymous download answers 410 Gone since that day) and the OpenPhish public
feed (terms: no "product development", "detection" or "customer
protection"). **Removed from training**: URLhaus and OpenPhish (both
2026-10-21), Tranco (2026-10-22, the benign side). **Not used for
training**: Cisco Umbrella's list (no licence stated), Cloudflare Radar
(CC BY-NC 4.0), Phishing.Database (MIT on the compilation; besides their
own data its maintainers import from upstream partners they do not name,
whose terms are unknown — settled 2026-10-24, §1: it stays out of training
as it is out of the licensed blocklist; the weekly retrain never read it,
so nothing changes there),
phishing.army (CC BY-NC), PhishTank (needs a key; the weekly benchmark's
held-out PhishTank sample is evaluation only, never a training row).

**Majestic's site terms against the Majestic Million's licence** (read
2026-10-23 at majestic.com/company/terms, the Terms and Conditions released
13 April 2026). The terms' intellectual-property section bars commercial use
of "the materials on our sites" without a licence from Majestic, and §14.1,
the customer's obligations "in utilising any Subscription", bars querying
their servers with automated tools without prior permission (f) and making
derivative works of what they provide (g). We read the CC BY 3.0 notice on
the Majestic Million page as that licence for this one file: it is specific
to the dataset, and CC BY 3.0 has no non-commercial term and allows
adaptations. §14.1 governs subscriptions, and the download needs none: the
weekly job fetches the one CSV the page links ("Export CSV"), once a week,
and never queries their API or search. Low risk. A written confirmation from
Majestic (majestic.com/help/contact-us) would close it; that e-mail is a
founder step and has not been sent.

**The served model**: `data/phishing_model.onnx` (2026-10-21, AUC 0.9703)
was still trained on URLhaus + OpenPhish. A model trained on the clean
corpus above failed the retrain gates on 2026-10-21 (official-shop.myshopify.com
0.59, 6 held-out Russian sites flagged, 69 of 539 held-out real sites over
0.6 where the served model puts none), so the replacement guard kept the
served one. The cause was the benign class, not the feeds; since 2026-10-22
`ml/train_model.py` draws it differently (see `N_BENIGN` there: Russian and
IDN names, brand-named and generic-lure-word real sites, the hand-verified
brand file, synthetic tenants, 48,000 samples weighted 3:1, the mean of three
models). Measured offline on the 2026-10-21 feeds, five seeds of the whole
pipeline (refresh → train → every gate in `retrain-ml.yml` → full test
suite) all pass and all replace the served model; held-out numbers, served →
clean (range over the five seeds):

| Held-out set | Served (URLhaus + OpenPhish) | Clean, 2026-10-22 |
|---|---|---|
| Fresh phishing (PhishTank, 30 days, not in any training feed), model > 0.6 | 30.1% | 42.7-44.0% |
| — at the served model's false-positive rate | 30.7% | 39.6-41.3% |
| — ROC AUC against real long-tail + Russian sites | 0.861 | 0.892-0.896 |
| Real Russian sites (539), model > 0.6 | 0 | 0-1 (beeline-online.info) |
| Tranco rank > 10k, a bucket never trained on, model > 0.6 | 0.47% | 0.73-0.83% |
| Name-only verdict not "safe": fresh phishing / Tranco > 100k / Russian sites | 52.4% / 3.60% / 0.19% | 51.2-52.1% / 3.60-3.74% / 0.19-0.37% |
| Russian look-alikes (186) caught by the verdict | 93.6% | 93.0% |

That table is #279's: the clean phishing feeds with Tranco's benign list.
The served file stays the old one until a weekly retrain replaces it.

**Measured with the licensed benign lists (2026-10-22)**: the whole
pipeline offline on the 2026-10-22 feeds (refresh → `ml/train_model.py
--seed S` → every gate step of `retrain-ml.yml` → full test suite), three
seeds (42, 7, 123): every gate and the full suite pass on all three, and
all three replace the served model. The held-out sets are not the ones in
the table above, so the served model is measured again on them: fresh
phishing is PhishTank online-valid submitted in the 30 days to 2026-10-21,
minus every host any of the four training feeds listed on 2026-10-22, by
exact host or by registrable domain (1,540 hosts); the long tail is a 4% hash
bucket of the ranked list's names past rank 10k (54,130) and of CrUX's
global apex domains past 10k (12,259), minus every name any of the nine
ensemble members trained on.

| Held-out set | Served (URLhaus + OpenPhish, Tranco) | Licensed, 3 seeds |
|---|---|---|
| Fresh phishing, model > 0.6 / > 0.85 | 29.3% / 9.5% | 31.0-31.3% / 17.9-18.5% |
| — at the served model's false-positive rate | 29.4% | 23.5-24.3% |
| — ROC AUC against the long tail + Russian sites | 0.841 | 0.838-0.839 |
| Real Russian sites (539), model > 0.6 | 0 | 1 (beeline-online.info) |
| Ranked-list long tail / CrUX long tail, model > 0.6 | 0.38% / 0.52% | 1.13-1.26% / 2.09-2.32% |
| Russian look-alikes (186), model > 0.6 | 21.0% | 17.7-20.4% |
| Name-only verdict not "safe": fresh phishing / ranked > 100k / Russian sites | 42.6% / 3.10% / 0.19% | 40.5-41.3% / 3.42-3.54% / 0.37% |
| Russian look-alikes caught by the verdict | 93.5% | 93.0-93.5% |

**The regression gate is the thin margin.** secure-login.wasmer.app, the
recall host the rules leave to the model (it must score above 0.6), scored
0.69-0.77 on those three seeds. An independent re-run on 2026-10-23 used the
same benign snapshot (byte-identical Majestic + CrUX 202609), phishing feeds
re-downloaded about 3 hours later (18,187 rows after exclusions against
18,202), and seeds 42, 99 and 2026. Seed 42, the one the weekly job always
uses, passed everything (test AUC 0.903, wasmer 0.712), and so did seed 99
(0.897, 0.767). Seed 2026 passed the other three gate steps and the full
suite but **failed the regression gate: wasmer 0.594** (RECALL REGRESSION).
Over the five draws wasmer is 0.59-0.77, and the 2%-medium-TLD variant below
gave 0.598. The job's seed is fixed, so the week-to-week change in the feeds
plays the part of a new seed: about one weekly run in five may fail this
gate. That is fail-safe, because the job stops before the commit step. But
until a run passes, production serves the 2026-10-21 model, which was
trained on URLhaus + OpenPhish with Tranco's benign list. Merging this
change does not replace that model. A passing retrain does: the Monday
schedule, or a manual `workflow_dispatch` of `retrain-ml.yml`; then check
that its "chore(ml): weekly retrain" commit landed.

The re-run's held-out numbers (seeds 2026 and 99, on the sets above after
dropping every name those seeds trained on) fall inside the table's ranges
or just past them. Fresh phishing over 0.6 / 0.85 was 30.1-31.5% /
17.9-18.9%, and 23.7-24.1% at the served model's false-positive rate. ROC
AUC against the long tail + Russian sites was 0.843. The ranked / CrUX long
tail over 0.6 was 1.02-1.10% / 1.96-2.12%, and Russian look-alikes over 0.6
17.2-18.8%. The verdict was not "safe" for 40.8-41.3% / 3.36-3.49% / 0.37%,
and it caught 93.0-93.5% of the look-alikes. The held-out Russian gate
flagged only beeline-online.info, and the replacement guard was 1 vs 0 of
539 on both seeds.

**Leakage, checked.** None of the 756 held-out hosts (both
`ru_heuristics_*` files and `benchmark_legit_ru.txt`) is a training row on
any of the 15 ensemble members rebuilt, by exact host or by registrable
domain, and no regression-gate host is either. The gate hosts are excluded
by exact name only, so their siblings can be training rows: example.com
(the gate has www.example.com), sberbank.ru and other *.sberbank.ru hosts
(online.sberbank.ru), 64 *.yandex.ru and 51 *.google.com hosts. The
subdomain and false-positive gates therefore partly measure recall of
close siblings. That design predates the licensed lists, but CrUX's hosts
add siblings. The PR's evaluation sets were carved from the same pool after
training, so they hold out only for the draws that built them. Anyone who
reuses them must first drop their own training union: for seeds 2026 and
99 on newer feeds, 2,178-2,248 of the 54,130 ranked-tail names and 482-518
of the 12,259 CrUX-tail names were training rows.

So the first weekly retrain after this ships a model with no
non-commercial training rows — and a weaker one than the Tranco-trained
clean model above: at the scorer's 0.6 bar it flags three to four and a
half times as many long-tail real sites as the served model, and at the
served model's false-positive rate it catches less fresh phishing (24%
against 29%),
where the Tranco-trained one caught a third more. The verdict moves less
(3.4-3.5% of the long tail past rank 100k not "safe", against 3.1%),
because 0.6 alone adds 20 points and leaves a name "safe". What is left in
the long tail is cheap-TLD real sites (.shop, .store, .info, .online):
26% of the phishing class is under a high- or medium-risk TLD and 3.3% of
the benign class. Two fixes were measured on one seed each and are not
in: 3% of the class from ranked names under those TLDs took the long tail
to 0.25% / 0.40% and the recall at the served model's false-positive rate
to 30.6%, but put the obvious lures' median at 0.74
(`tests/test_ml_scorer.py` wants 0.8); 2% from the medium-risk TLDs only
gave 0.57% / 1.09% and 25.8%, and secure-login.wasmer.app 0.598 against
the regression gate's 0.6.

**The benign list (closed 2026-10-22)**: Tranco states no licence for its
lists, and its default list averages Cloudflare Radar, which is CC BY-NC
4.0. Until 2026-10-22 every ranked benign sample came from it. Since then
`scripts/refresh_training_feeds.py` writes, and `ml/train_model.py` reads:

* `data/benign-domains.csv` — the Majestic Million plus the registrable
  domains of CrUX's global top-1M origins (hosting tenants left out), one
  row per domain at its best rank: 1,568,364 domains on 2026-10-22.
  Majestic alone was tried first and is not enough: it ranks by links, and
  a model trained on its long tail scored 4.3% of CrUX's real-traffic long
  tail above 0.6 (the served model 0.5%) — cheap-TLD real sites (.online,
  .shop, .site) were rarer in it than in the phishing feeds — and it has
  110 generic lure-word names to Tranco's ~300, which put
  shopify-connect.com at 0.87, dangerous (`tests/test_scoring.py`).
* `data/benign-hosts.csv` — every host of CrUX's global and Russian top
  origins (1,555,774). The subdomain stratum takes only hosts in CrUX's
  top-100k buckets (`SHAPE_MAX_RANK`): drawn from the whole 1M, where 67%
  of the subdomain hosts sit under names outside the ranked top 100k, a
  subdomain stopped adding anything (track.safeinflow.com 0.099 under its
  apex's 0.102,
  `tests/test_ml_scorer.py`). Names under Russian zones and tenants keep
  every rank. The Russian list is what carries the regional zones: 3,584
  names under them against the global list's 139.
* The generic lure-word stratum also reads the registrable domains of the
  Russian hosts (`lure_word_domains`): 306 names, about Tranco's count.

Russian and .рф coverage against Tranco's: IDN names 2,749 (.рф 1,175)
against ~1,400 (~500); .ru/.su/.рф registrable domains 32,764; regional-zone
names 3,574 for the 1,800 the stratum takes. No gap to fill, so the
hand-verified file is used as #279 used it, no more.

**Still Tranco, not training rows** (closed 2026-10-23, §2a): two inputs
the features read were built from Tranco. Both are the licensed ranking's
now, the model was retrained on them, and `model_meta.json` names them by
hash. What this paragraph said until then:

* The `in_top_domains` feature reads `data/top_100k.json`, a Tranco
  top-100k snapshot (2026-10-05). The scorer's allowlist, the blocklist's
  veto and the extension also read it (§1, §2), and
  `.github/workflows/refresh-tranco.yml` / `api/services/tranco.py` keep a
  Tranco copy for serving. It is one input column, the same at training
  and serving time, but it is the model's most important one (a third of
  the importance in the 2026-10-22 retrains; the served model's second,
  16%).
* The tenant features (`ml_features.shared_tenant`, through
  `scoring._SCORER_SHARED_SUFFIXES`) read `data/public_suffixes_in_top.json`.
  `scripts/build_public_suffixes_in_top.py` builds that file from the Public
  Suffix List rules whose base is in `data/top_100k.json`, so Tranco
  decides which hosting suffixes count as shared.

Replacing them (with a Majestic + CrUX top-100k, say) changes serving and
the allowlist, not only training. That is a separate change, measured on
its own.

## 4. Considered and not used

Bank of Russia warning list (non-commercial, and a licensing-perimeter list,
not a fraud list), Maltrail (Community Data License, written agreement
needed), Yandex Safe Browsing, VirusTotal (benchmark only, `VT_API_KEY`,
never in the list), Google Safe Browsing hash prefixes for the phone,
SI-CERT, USOM Turkey, CERT-AgID, NCSC-UK PDNS, ruSpamModels / RUSpam
datasets (CC BY-NC 4.0). Commercial feeds (Kaspersky Phishing URL Data Feed
OEM, F6) are priced for later.

Checked 2026-10-21 for the DNS list (licence read at the source; overlap and
false-positive numbers against the live artifact of that day, 493,525
hashes, after the same guards the refresh applies):

* **HaGeZi TIF / Fake**, **jarelllama Scam-Blocklist**, **ScamSniffer** —
  GPL-3.0 on the list; HaGeZi also says its inputs keep their own licences.
  Copyleft on data we ship as hashes is not a term we can meet. jarelllama
  has not been updated since 2025-11; ScamSniffer's public copy is 7 days
  late by design.
* **The Block List Project** phishing/scam/fraud (Unlicense) — licence fine,
  data not: 37 % (phishing) and 18 % (fraud) of a sample resolve, the
  phishing list is years of compromised legitimate sites, and it is fed
  from HaGeZi (GPL) among others, so the Unlicense cannot be relied on.
* **MetaMask eth-phishing-detect** — ~103k crypto-phishing names, 59 % live,
  no FP found; but the licence is the "Don't Be A Dick Public License", not
  a standard one. A founder decision, not wired.
* **polkadot-js/phishing** (Apache-2.0) — 85 % of a sample NXDOMAIN.
* **Discord-AntiScam** (no licence = all rights reserved), **KADhosts**
  (CC BY-SA 4.0), **malware-filter phishing-filter** (built from OpenPhish
  and PhishTank, CC BY-SA), **StevenBlack/hosts** (ad and tracker hosts, 1,430
  Tranco top-10k registrables), **ShadowWhisperer Scam** / **durablenapkin**
  (small, opinionated "scam" verdicts on ranked sites such as xcover.com),
  **DigitalSide** (133 names, last push 2024-10).
* **urlscan.io** — terms: "personal, non-commercial use"; commercial use
  "requires express written permission". **Spamhaus DROP** is free with
  credit but is IP ranges, not names. **PhishStats** no longer offers a bulk
  file (API, 50 requests a day anonymous).
* No Russian or CIS CERT (НКЦКИ, RU-CERT, F6/CERT-GIB, KZ-CERT, UZCERT,
  CERT.BY) publishes a downloadable phishing-domain list; the .RU/.РФ
  Coordination Center's Domain Patrol is a per-domain lookup only.

## 5. Attribution

**Where people read it.** The "Data sources" section at the end of
cleanway.ai/transparency/methodology (`#data-sources`; the list is
`landing/lib/data-sources.ts`, the text `landing.methodology.sources_*` in
all ten languages) credits the datasets below with links to their licence
texts and says what we changed. The transparency report links to it, and so
does the app's Settings → About → "Data sources" (from the next app build;
builds made before this change have no such row). CC BY 4.0 §3(a)(2) allows
the credit as a link to a page that carries it. `tests/test_data_attribution.py`
fails when a feed the blocklist or the model reads is missing from that list,
and when the list credits a feed neither reads (one the licence switch
leaves out, such as CSIRT Italia since 2026-10-23 and Phishing.Database
since 2026-10-24, or a retired one) as a source in use. A feed that left
while copies of its data are still handed out keeps a past-tense credit
(`FORMER_PHISHING_SOURCES`): Phishing.Database is MIT, whose notice goes
with every copy, and release Android files embed the published list as
their seed (`mobile/scripts/fetch-seed-blocklist.sh`, `SeedBlocklist.kt`)
— the released 1.0.3 APK, and any 1.0.6 file built before the first
forced publish without it. So build the 1.0.6 Android files (or re-run
`fetch-seed-blocklist.sh`) only after that publish: the new seed (~263k
hashes on 2026-10-24) is well above the script's 100,000 `MIN_COUNT`.
`scripts/test-landing-honesty.mjs` holds the CC BY lines to the licences
`data/top_domains_sources.json` and `data/model_meta.json` record, and an
MIT line to its copyright notice.

Cleanway's blocklist includes data from Phishunt.io (CC0), TweetFeed.live
(CC0), CERT Polska's Lista Ostrzeżeń, PhishDestroy DestroyList
(phishdestroy.io, CC0 / MIT); before the licence cut also phishing.army
(CC BY-NC 4.0) and OpenPhish (`BLOCKLIST_LICENSED_ONLY` is `true` in the
repository's Actions variables, read 2026-10-24), until 2026-10-23 CSIRT
Italia / ACN (TLP:CLEAR events; no licence stated and ACN's terms bar
commercial use, so the switch leaves it out — §1), until the first forced
publish after 2026-10-24 Phishing.Database (MIT on the compilation,
© Mitchell Krog, Nissar Chababy, Phishing.Database Contributors,
github.com/Phishing-Database/Phishing.Database; part of its data comes
from upstream partners it does not name, terms unknown, so the switch
leaves it out — §1; the methodology page keeps this credit in the past
tense while Android files built with it are handed out), and until
2026-10-21 URLhaus (abuse.ch). Public suffixes from the Mozilla Public
Suffix List (MPL 2.0).

Cleanway's domain popularity ranking — the allowlist, the top-1M in Redis,
the blocklist's popularity veto, the phone's veto list and the
extensions' tenant suffixes — is built from the Majestic Million by
Majestic (majestic.com/reports/majestic-million), licensed under the
Creative Commons Attribution 3.0 Unported License
(https://creativecommons.org/licenses/by/3.0/), and the Chrome UX Report by
Google (developer.chrome.com/docs/crux), licensed under the Creative
Commons Attribution 4.0 International License
(https://creativecommons.org/licenses/by/4.0/), read through
github.com/zakird/crux-top-lists. Changes made: hosts folded to
registrable domains (public suffixes left out), hosting tenants dropped,
the two lists merged by the Dowdall rule with Russia's CrUX list counted at
six times its bucket, cut to the top 100,000 / 10,000 / 1,000,000, and for
the allowlist only, names reported by phishing feeds removed unless
popularity vouches for them (`scripts/build_top_domains.py`,
`data/top_domains_sources.json`). The adapted copies that ship — the
phone's `popular_veto.txt` and `shared_suffixes.txt`, the extensions'
`scorer-data.js` (`hostingTenantSuffixes`) — carry this notice in their
header, generated from `data/top_domains_sources.json`. Until 2026-10-23
domain popularity came from Tranco (Le Pochat et al., NDSS 2019).

Cleanway's phishing model learns what real sites look like from the
Majestic Million by Majestic (majestic.com/reports/majestic-million),
licensed under the Creative Commons Attribution 3.0 Unported License
(https://creativecommons.org/licenses/by/3.0/), and the Chrome UX Report by
Google (developer.chrome.com/docs/crux), licensed under the Creative Commons
Attribution 4.0 International License
(https://creativecommons.org/licenses/by/4.0/), read through the
crux-top-lists cache by Zakir Durumeric et al.
(github.com/zakird/crux-top-lists). Its phishing examples come from
PhishDestroy, CERT Polska, TweetFeed and Phishunt (§3). Changes made: the
lists are reduced to host names and registrable domains, merged at each
name's best rank, and sampled as training examples. The lists themselves
are not redistributed. `data/model_meta.json` (`benign_sources`) records
the CrUX month and the row counts each served model learned from.

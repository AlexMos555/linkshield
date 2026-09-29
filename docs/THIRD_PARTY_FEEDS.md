# Third-party data Cleanway uses, and under what terms

Every external source the product talks to, what we do with its data, the
licence or terms it comes under, and the switch (if any) that turns it off.
This is the attribution notice the CC BY feeds ask for and the working list
behind plan §4 ("лицензионный срез до первого рубля"). Terms were read on
the dates given; a row marked *likely* rests on a secondary source or an
earlier reading and should be re-read before it is relied on.

While the product was free, non-commercial terms were a grey area. With the
first paid subscription they are not. Nothing here is flipped yet: every
switch defaults to today's behaviour. The order of flipping, the numbers it
costs and what replaces the loss are in the PR that added this file and in
`docs/benchmarks/day-one-coverage-latest.json`.

## 1. Bulk feeds that build the phone's blocklist

Built by `scripts/refresh_dangerous_domains.py` every 6 h into the DNS
gateway's set and the phone artifact (`GET /api/v1/blocklist/dns`). What the
phone receives is a list of 48-bit hashes of names; the DoH gateway holds the
names. Redistribution to every phone is the act each licence has to allow.

| Source | URL | Terms (date read) | How we use it | Switch |
|---|---|---|---|---|
| **URLhaus** (abuse.ch) | `https://urlhaus.abuse.ch/downloads/csv_online/` | abuse.ch Terms of Use 2025-11-04: free for not-for-profit use only, no derivative works; commercial use through a Spamhaus subscription (read 2026-09-21, 2026-09-29) | Hosts of online malware URLs | **`BLOCKLIST_LICENSED_ONLY=1` removes it** |
| **OpenPhish** community feed | `https://openphish.com/feed.txt` | openphish.com/terms.html: no commercial use "including … security operations, threat intelligence, detection … customer protection", no redistribution of any part to third parties; lifted only by written consent (read 2026-09-21, 2026-09-29) | Phishing URL hosts | **`BLOCKLIST_LICENSED_ONLY=1` removes it** |
| **phishing.army** extended | `https://phishing.army/download/phishing_army_blocklist_extended.txt` | CC BY-NC 4.0 (the file's own header). Aggregates PhishTank, OpenPhish, CERT.pl, PhishFindR, urlscan, Phishunt (read 2026-09-21) | ~150k domain names | **`BLOCKLIST_LICENSED_ONLY=1` removes it** |
| **Phishing.Database** (mitchellkrogza) | `https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt` | MIT on the compilation; the README does not name its sources, and MIT does not launder PhishTank/OpenPhish terms if the data comes from there (read 2026-09-29) | ~390k active phishing domains — the bulk of the list | Keep. **One e-mail to the maintainer about provenance is open** (plan §4) |
| **Phishunt.io** | `https://phishunt.io/feed.txt` | Terms §7 "Data license": feeds and API responses released as CC0 1.0 (read 2026-09-21) | Hourly phishing URL hosts | Keep |
| **TweetFeed.live** | `https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv` | README: CSV/JSON/RSS/MISP/STIX feeds and public API responses under CC0 1.0, no attribution required. The `/v1/ioc` and `external.json` blocks are abuse.ch-licensed and are never read (read 2026-09-21) | 365-day window of reported domains/URLs | Keep — but it is a *source*, so a TweetFeed sample is not a held-out benchmark for this list |
| **CERT Polska** Lista Ostrzeżeń | `https://hole.cert.pl/domains/v2/domains.txt` | API spec §1: publicly available, may be processed without restriction, manually or automatically; names that leave the list must be unblocked (we rebuild from scratch every run) (read 2026-09-21) | Exact hosts only (never promoted to a whole domain) | Keep |
| **CSIRT Italia / ACN** MISP feed | `https://www.csirt.gov.it/feed-misp/manifest.json` | Only events tagged `tlp:clear` / `tlp:white` are read — TLP:CLEAR means unlimited disclosure; anything else is skipped (*likely* for the feed as a whole; the TLP marking is read per event, 2026-09-21) | Malware C2 hostnames, exact only | Keep |
| **PhishTank** (Cisco/OpenDNS) online-valid dump | `https://data.phishtank.com/data/<key>/online-valid.csv.gz` | FAQ: commercial use of the API — "Yes, it is OK" (read 2026-09-29). Needs an application key; registration closed at the moment. Terms of Use refer to the Cisco EULA (*likely*) | Verified-online phishing URL hosts, **one cached download a day** (`api/services/phishtank_feed.py`) | **Off without `PHISHTANK_API_KEY`**; on the job through the `BLOCKLIST_PHISHTANK_SOURCE` variable |
| **Cleanway checks** (server-confirmed hosts) | — | Google Safe Browsing / Web Risk verdicts; both bar passing results on (see §2) | Hosts our own checks confirmed dangerous | **Off** (`PUBLISH_CONFIRMED_THREATS`), stays off |

Guards on every source, whatever its terms: Tranco top-100k/1M and public
suffix list vetoes, shared-hosting tenant rules, hand-verified brand-owned
hosts (`data/brand_owned_hosts.txt`), the churn and post-publish gates.
Sources: Public Suffix List (`https://publicsuffix.org/list/public_suffix_list.dat`,
MPL 2.0) and Tranco (`https://tranco-list.eu`, free research list; cite
*Le Pochat et al., NDSS 2019*).

### What `BLOCKLIST_LICENSED_ONLY` does, exactly

Unset (default): every row above except PhishTank, byte for byte the list
published today (proved in the PR on one feed snapshot: same names, same
count, the only header difference the build timestamp). Set to `1`:

* URLhaus, OpenPhish and phishing.army are not downloaded and not in
  `fetched` — so they are **not an outage**: nothing is carried for them,
  their stored health state is forgotten, and the run does not go red.
* The published names only they backed (per the last healthy run's backing
  record) leave with that publish. They are *not* held for the 14-day
  retention window: that window exists for feeds that forget a live
  phishing site, not for data we may no longer ship.
* The set changes by more than the 50 % churn gate: the first run after
  flipping needs `--force` (the workflow's `force` input). One run.
* `BLOCKLIST_EXCLUDE_FEEDS=TweetFeed` (comma-separated names) leaves further
  feeds out — used by `scripts/eval_day_one_coverage.py` to build the
  variants it scores, never in production.

### The held-out problem

Every coverage number needs a sample the list was *not* built from.

* **PhishTank** is that sample today (`scripts/eval_blocklist_coverage.py`,
  `scripts/eval_day_one_coverage.py`). The day `PHISHTANK_API_KEY` reaches
  the refresh job, PhishTank is a source and every PhishTank number becomes
  circular — the day-one report marks it `circular: true` automatically.
* **TweetFeed** has been a source since 2026-09-26 (#47). Its "independent
  30-day sample" (report of 2026-09-25) is honest only against a list built
  without it; the day-one report builds such variants.
* **phishing.army is itself built from PhishTank**, so as long as it is in
  the list the PhishTank number is inflated by that path (82 % of a PhishTank
  sample verbatim, 2026-09-21). The `licensed` variant has no such path.

Proposal for after the flips (a founder decision, not made here): hold out
**CERT Polska** (small, exact-host, no overlap with the aggregates — cheap to
give up as a source) and a **TweetFeed 30-day window with TweetFeed dropped
as a source** (it bought 12 held-out hosts in 3,000 on 2026-09-21). Then
PhishTank can be ingested and the public number stays measurable.

## 2. Lookups the API makes for one `/check`

`api/services/analyzer.py` asks up to 19 sources about the bare domain name
(never a URL, never who asked). `docs/PRIVACY.md` lists them for users.

| Source | Endpoint | Terms (date read) | Switch |
|---|---|---|---|
| **Google Safe Browsing v4** | `safebrowsing.googleapis.com/v4/threatMatches:find` | developers.google.com/safe-browsing/terms: "Unless you have a separate agreement … you may not use the Safe Browsing API for commercial purposes" (read 2026-09-29). v4 support ends 2027-03-31 (*likely*) | Replaced by Web Risk when `WEB_RISK_API_KEY` is set |
| **Google Web Risk** Lookup API | `webrisk.googleapis.com/v1/uris:search` | Google Cloud terms; billed per lookup after 100,000 a month (cloud.google.com/web-risk/pricing, read 2026-09-29). Results may not be passed on to third parties — `PUBLISH_CONFIRMED_THREATS` stays off. Needs a Google Cloud project with billing, which may not be open to a Russian legal entity (*uncertain*) | **On with `WEB_RISK_API_KEY`** (`api/services/web_risk.py`); threat types MALWARE, SOCIAL_ENGINEERING, UNWANTED_SOFTWARE; answers cached until Google's `expireTime` |
| **PhishTank** checkurl | `checkurl.phishtank.com/checkurl/` | FAQ: commercial use OK; key needed for rate limits (read 2026-09-29) | Always on (answers nothing for fresh URLs without a key) |
| **URLhaus** host API | `urlhaus-api.abuse.ch/v1/host/` | abuse.ch ToU 2025-11-04 (non-commercial) | Not in `LICENSED_INTEL` — **open question**: same terms as ThreatFox; kept for now because the licence audit of 2026-09-21 scoped the runtime cut to the five below. Decide with the others |
| **ThreatFox** | `threatfox-api.abuse.ch/api/v1/` | abuse.ch ToU 2025-11-04 (non-commercial, no derivative works) | **`LICENSED_INTEL=licensed` switches off** |
| **MalwareBazaar** | `mb-api.abuse.ch/api/v1/` | abuse.ch ToU 2025-11-04 | **`LICENSED_INTEL=licensed` switches off** |
| **Feodo Tracker** | `feodotracker.abuse.ch/downloads/ipblocklist.json` | abuse.ch ToU 2025-11-04 | **`LICENSED_INTEL=licensed` switches off** |
| **Spamhaus DBL** public mirror | DNS `<domain>.dbl.spamhaus.org` | DNSBL fair-use policy: "free of charge for non-commercial use by small and medium sized organisations"; queries must come from an identifiable resolver, not large shared hosting (read 2026-09-29). Through a public resolver the mirror answers `127.255.255.254` — until 2026-09-29 the analyzer read that as "not listed" (`api/services/dnsbl_checks.py` fixes it: an error code is "not consulted") | **`LICENSED_INTEL=licensed` switches off** |
| **SURBL** multi | DNS `<base>.multi.surbl.org` | surbl.org/guidelines: `127.0.0.1` means access is blocked, sign up for the Sponsored Data Service; the usage policy excludes the free service from paid products (*likely*, read 2026-09-21/29) | **`LICENSED_INTEL=licensed` switches off** |
| **PhishStats** | `phishstats.info:2096/api/phishing` | Free API, no key; terms not located (*uncertain*) | On |
| **AlienVault / LevelBlue OTX** | `otx.alienvault.com/api/v1/indicators/domain/…` | Free community API; OTX terms of service (*likely*: free use with attribution) | On |
| **IPQualityScore** | `ipqualityscore.com/api/json/url/…` | Vendor API terms, free tier 5,000/month, paid above; keyed | On with `IPQUALITYSCORE_KEY`, daily budget |
| **RDAP** | `rdap.org/domain/…` | Public registry protocol (redirector) | On |
| **Tranco** ranks | Redis copy of `tranco-list.eu` top-1M, refreshed daily | Free research list (cite) | On |
| **crt.sh** (Watchtower) | `crt.sh/?q=…` | Sectigo's public CT log search, no terms beyond politeness | On |
| **Anthropic Claude** (LLM judge, explainer) | `api.anthropic.com` | Commercial API terms; only a domain-free feature vector is sent | On with `ANTHROPIC_API_KEY`, daily budget |
| **Have I Been Pwned** Pwned Passwords | `api.pwnedpasswords.com/range/…` | Free, k-anonymity range API; no key | On |
| **Cloudflare DNS** (DoH gateway upstream; 1.1.1.1 for Families in the public comparison) | `cloudflare-dns.com/dns-query`, `family.cloudflare-dns.com` | Cloudflare public resolver terms | On |

### What `LICENSED_INTEL=licensed` does, exactly

The five sources are not in the analyzer's plan at all: not asked, so never
"not listed", and they leave the total a verdict is measured against — an
analysis is 14 checks of 14, not 14 of 19 with five that were never asked.
Scores, levels and `confidence_pct` for the same evidence are identical
with the switch on or off (pinned in `tests/test_licensed_intel.py`).

Measured offline on `tests/data/ru_heuristics_{legit,phish}.txt`
(`scripts/eval_ru_heuristics.py`, name-only scoring, 2026-09-29): identical
row for row with the switch on and off, ML on or off — LEGIT 291: safe 290,
caution 1; PHISH 174: caught 142 (caution 108 + dangerous 32). That is
expected and is the point: the name-only rules never consult these sources.
What the switch costs is only measurable on live traffic — on 2026-09-21
SURBL appeared in 9 of 10 dangerous verdicts sampled, but 9 of those 10 also
rested on our own signals. Measure on the live fan-out before flipping;
do not re-weight the scorer blind.

## 3. ML training data (`scripts/refresh_training_feeds.py`, weekly)

| Source | Terms | Use |
|---|---|---|
| URLhaus full dump `https://urlhaus.abuse.ch/downloads/csv/` | abuse.ch ToU 2025-11-04 (non-commercial, no derivative works — a trained model is a derivative) | Phishing/malware corpus for `ml/train_model.py` |
| OpenPhish public feed (GitHub mirror) | openphish.com terms (non-commercial) | Phishing corpus |
| Tranco top-1M | Free research list | Benign corpus |

**Open**: the model shipped in production (`data/phishing_model.onnx`) was
trained on the two non-commercial corpora. The licence cut for the list and
the API does not cover it; a retrain on Phishing.Database + Phishunt +
TweetFeed + PhishTank (with a key) is the clean path. Not in this PR.

## 4. Considered and not used

Bank of Russia warning list (non-commercial, and a licensing-perimeter list,
not a fraud list), Maltrail (Community Data License, written agreement
needed), Yandex Safe Browsing, VirusTotal (benchmark only, `VT_API_KEY`,
never in the list), Google Safe Browsing hash prefixes for the phone,
SI-CERT, USOM Turkey, CERT-AgID, NCSC-UK PDNS, ruSpamModels / RUSpam
datasets (CC BY-NC 4.0). Commercial feeds (Kaspersky Phishing URL Data Feed
OEM, F6) are priced for later.

## 5. Attribution

Cleanway's blocklist includes data from Phishunt.io (CC0), TweetFeed.live
(CC0), CERT Polska's Lista Ostrzeżeń, CSIRT Italia (TLP:CLEAR),
Phishing.Database (MIT, © Mitchell Krog) and — until the licence cut —
phishing.army (CC BY-NC 4.0), OpenPhish and URLhaus (abuse.ch). Domain
popularity from Tranco (Le Pochat et al.). Public suffixes from the Mozilla
Public Suffix List (MPL 2.0).

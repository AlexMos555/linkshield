# Global brands, 2026-10-05: candidates, false-positive pass, recall

The typosquat rule, `brand_subdomain_abuse` and the hosting-tenant rule (#80) all read the
global brand list, `data/typosquat_targets.json` (125 names). Most of the PhishTank week in
`docs/benchmarks/2026-10-04-ml-eval.json` imitates brands that were not on it. This pass adds
14 names for 11 owners and rejects 10 candidates. Every candidate was run against four kinds of
legitimate names before it was added.

## Result

| | before | after |
|---|---:|---:|
| global names | 125 | 139 |
| PhishTank week (612 hosts): typosquatting or brand_subdomain_abuse | 6 | **158** |
| PhishTank week: caught, heuristics only (caution + dangerous) | 221 (36.1%) | **245 (40.0%)** |
| PhishTank week: dangerous, heuristics only | 63 | **145** |
| TweetFeed week (207 hosts): typosquatting or brand_subdomain_abuse | 4 | **6** |
| TweetFeed week: caught, heuristics only | 28 | **29** |
| Tranco top-1M + top-1M-with-subdomains hosts whose level changes (ML stubbed) | – | 14 (listed below) |
| macOS dictionary as `<word>.com` (234,454), new hits | – | 0 |
| `ru_heuristics_legit` (300) and `benchmark_legit_ru` (271), new hits | – | 0 |

"Heuristics only" means `calculate_score` with `api.services.ml_scorer.ml_predict` monkeypatched
to return `None`, as `scripts/eval_ml_model.py` does for its `heuristics` column. Nothing was lost:
every host flagged before is still flagged.

## Candidates

The candidates came from reading the 819 hosts of `rows["phishtank_recent"]` and
`rows["tweetfeed_week"]`. A brand became a candidate when at least one host imitates it. Two
brands with no host in the week were added to the candidates from the telecom and parcel-delivery
families (verizon, inpost) and measured too.

| brand | official domain | hosts in the week (PhishTank / TweetFeed) | shape |
|---|---|---:|---|
| allegro, allegrolokalnie | allegro.pl, allegrolokalnie.pl | 162 / 1 | `allegro.<random>.sbs`, `allegrolokalnie.<random>.cfd`, typos `allegrolokainie`, `allegrolokalne` |
| olx | olx.pl | 5 / 0 | `olx.pl-dyu8h.sbs`, next to the allegro family |
| xfinity, comcast | xfinity.com, comcast.com | 10 / 1 | site builders: `my-xfinitysignin.weebly.com`, `xfinity-security-update.webflow.io`, `supportxfinty.square.site` |
| att, bellsouth | att.com | 3 / 0 | Webflow: `att-sign-in-1c41ac.webflow.io`, `bellsouth-verifier-sign-in-17cc27.webflow.io` |
| pichincha | pichincha.com | 4 / 0 | Replit: `pichincha--credito2020.replit.app` |
| novobanco | novobanco.pt | 2 / 0 | `novobanco.novoalerta.com`, `alertas-novobanco.ph` |
| mbway | mbway.pt | 2 / 0 | `mbway.online`, `mbway.site` |
| nubank | nubank.com.br | 1 / 0 | `nubanksaldo2.vercel.app` |
| correios | correios.com.br | 1 / 0 | `correiosapool0gin-correiopt.netlify.app` |
| kucoin | kucoin.com | 1 / 0 | `kucoxen-login-1.gitbook.io` |
| trezor | trezor.io | 2 / 1 | typos: `terezerwallet.webflow.io`, `trzer-briedge-io.framer.website` |
| tmobile | t-mobile.com | 1 / 0 | `t-mobile.obnovatelekom.com` |
| aruba | aruba.it | 2 / 0 | `aruba.renew-service.net` |
| sunrise | sunrise.ch | 2 / 0 | `sunrise-mail-ch.jimdofree.com` |
| interbank | interbank.pe | 1 / 0 | `interbankkingresaa12.onrender.com` |
| raiffeisen | rbinternational.com | 1 / 0 | `raiffeise.vercel.app` |
| caixa | caixa.gov.br | 1 / 0 | `caixa-indeniza.github.io` |
| kleinanzeigen | kleinanzeigen.de | 1 / 0 | `klelnanzeigen-deutch.egsbc.com` |
| sharepoint | sharepoint.com | 0 / 2 | `docsharepoint.top`, `pdfsharepoint.top` |
| verizon, inpost | verizon.com, inpost.pl | 0 / 0 | telecom and parcel-delivery families |

## Method

For each candidate, each host of each source was run through the three rules that read the global
list: `_check_typosquatting_v2`, `_check_brand_in_subdomain` and `_check_brand_on_hosting_tenant`.
Each run had only that candidate on the list. A hit counts as **new** when the list before this
change does not flag the host already, by any of those rules or by `_check_brand_under_open_zone`.

Sources:

- (a) the Tranco top-1M and the top-1M including subdomains, both generated 2026-10-04 and
  downloaded to a scratch directory;
- (b) `/usr/share/dict/words` as `<word>.com`: 234,454 unique lower-case words;
- (c) `tests/data/ru_heuristics_legit.txt` (300 hosts) and `data/benchmark_legit_ru.txt` (271).

Each remaining domain was checked on 2026-10-05. The checks were its name servers (1.1.1.1), where
`http://` lands, its page title, and whois or RDAP where DNS alone was not proof. A domain the check
could not tie to an owner stays flagged. The flag is a 25- or 30-point caution signal, not a block.

**Calibration.** The current list's `brand_subdomain_abuse` already fires on 2,654 hosts of the
top-1M with subdomains. They are mostly CDN and vendor names built from a customer's brand:
`instagram.*.fbcdn.net` (443), `aws.*` (382), `apple.map.fastly.net`, `microsoft.com.edgekey.net`.
The new brands add the same kind of host (`att.demdex.net`, `xfinity.com.edgekey.net`). Most of
them sit under a registrable domain the scorer trusts, and score safe.

### Rule changes the pass forced

1. **The slip rule for the new names.** Under 8 letters, a single substitution in a new name has
   to be a slip of the hand: a neighbouring key, a look-alike, a vowel for a vowel (`_is_slip`, as
   for the Russian names since #62). A free substitution made other companies' names into
   look-alikes. `nfinity.com`, `ufinity.jp` and `efinity.rs` matched xfinity, `myway.com`, `myway.be`
   and `m-way.ch` matched mbway, `comcash.com` matched comcast, and `tremor.com` and `trevor.com`
   matched trezor. The 125 older names are unchanged: their neighbourhoods have not been measured
   this way.
2. **Exemptions for global brands.** `data/typosquat_targets.json` gains a `measured` section. It
   has one entry per owner in `data/typosquat_targets_ru.json`'s format: `official`, `unrelated`,
   `not_typos` and `shared_name`, each with its evidence. `api.services.ru_brands.parse_group`
   validates it. The scorer's exemption sets, and so the extension's `scorer-data.js`, now merge both
   files. A malformed entry is logged, and the flat list keeps working without the exemptions.
3. **The ML similarity feature keeps the trained list.** `url_features._max_brand_similarity` leaves
   out `not_in_model` (the 14 names). The served model (features_version 6) learned that feature over
   the old list, and a new name would move the value for every host that resembles it.
   `is_typosquat` and `brand_in_subdomain` do fire on the new names' imitations, which is what they
   mean. Empty `not_in_model` at the next retrain.

## Per brand: false positives and how they were resolved

The table counts new hits as top-1M / top-1M with subdomains / dictionary. Both legit `.ru` sets
had 0 hits for every candidate. The first cut is the rule as it was. After the pass means with the
slip rule and the exemptions.

### Added

| brand | first cut | after the pass | resolution |
|---|---:|---:|---|
| allegro | 14 / 13 / 1 | 2 / 2 / 0 | **official** (NS `dns1-4.allegro.pl`): allegro.com, .cz, .sk, .hu, .eu, .tech (and `salescenter.allegro.com` with it). **unrelated**: allegro.cc (the Allegro game-library community), allegrologin.com (nCino Indirect Lending), allego.com (sales software), allego.eu (EV charging), allegra.com (an allergy medicine), alegro.pt (Portuguese shopping centres). **Still flagged**: allegro.sale (no DNS), wallegro.ru («allegro.pl по-русски», a reseller trading on the name), allegro.hit.gemius.pl (Gemius analytics, trusted, safe). |
| allegrolokalnie | 0 / 0 / 0 | 0 / 0 / 0 | – |
| olx | 15 / 46 / 0 | 4 / 4 / 0 | **official**: olx.ua, .ro, .pt, .bg, .kz, .uz (self-hosted NS `ns1-4.olx.<cc>`, olx.pl's pattern), olx.in (registrant OLX India B.V.), olx.com and olx.org (CSC Corporate Domains), olx.io (olx.com's NS). **unrelated**: olx.ba (now PIK.ba). **Still flagged**: olx.tools (no address; trusted, safe), olx.ru (no website, hidden registrant), 0lx.net (free hosting) and 01x.buzz (404) are look-alikes, olx.recamweek.com (trusted, safe). |
| xfinity | 5 / 7 / 1 | 0 / 3 / 0 | **slip rule**: nfinity.com, ufinity.jp, efinity.rs. **unrelated**: dfinity.org, dfinity.network (the DFINITY Foundation; `d` and `x` are neighbouring keys, so the slip rule alone keeps them). **not_typos**: finity. **Still flagged**: xfinity.com.edgekey.net (Akamai, was caution 50 from fake_tld_subdomain, now dangerous 80), xfinity.rbm.goog and xfinity.com.ssl.sc.omtrdc.net (trusted, safe). |
| comcast | 4 / 54 / 0 | 1 / 1 / 0 | **official**: comcast.net (NS `dns101-105.comcast.net`, as comcast.com and xfinity.com). **slip rule**: comcash.com, comcash.cc. **Still flagged**: comcast.jp (no website), comcast.demdex.net (trusted, safe). |
| att | 3 / 70 / 0 | 0 / 27 / 0 | **official**: att.net (NS `*.els-gms.att.net`), att.jobs (AT&T Careers; `.jobs` registers employers' names), att-mail.com (CSC, bellsouth.com's Akamai NS). **Still flagged**, all `brand_subdomain_abuse`. 21 vendor or CDN hosts sit under trusted domains and stay safe: `att.yahoo.com` (AT&T's Yahoo mail portal), `att.*.appsflyersdk.com`, `att.demdex.net`, `att.sliide.cloud`, `att.quantummetric.com` and others. 6 are not under a trusted domain. Three are Akamai hosts under `att.com.edgekey.net`: the apex goes from caution 50 to dangerous 80 (fake_tld_subdomain was already there), and the other two were dangerous before. `www.att.verintefm.com` (Verint) goes from safe 15 to caution 45. On two hosts `att` means attendance: `att.nepalconsular.gov.np` (safe → caution 30) and `att.akijbiri.com` (safe 10 → caution 40). A three-letter label is the price of att; its recall came from the hosting-tenant rule. |
| bellsouth | 2 / 1 / 1 | 0 / 0 / 0 | **official**: bellsouth.net (NS `attdns.com`), bellsouth.com (CSC, AT&T's Akamai NS). **unrelated**: allsouth.org (AllSouth Federal Credit Union). **not_typos**: bellmouth. |
| nubank | 2 / 3 / 0 | 1 / 2 / 0 | **official**: nubank.com (registrant Nu Pagamentos SA). **Still flagged**: nubank.world (no website, hidden registrant), nubank.atlassian.net (trusted, safe). |
| correios | 5 / 9 / 1 | 2 / 2 / 0 | **unrelated**: correos.es and correos.com (Correos, Spain), correos.cl (Correos de Chile). **not_typos**: corresol. **Still flagged**: correio.biz (no DNS), sorryios.ai (no page title, two edits at eight letters). |
| pichincha | 1 / 1 / 0 | 0 / 0 / 0 | **official**: pichincha.pe (NIC.PE: registrant Banco Financiero del Perú, admin Banco Pichincha). |
| novobanco | 0 / 0 / 0 | 0 / 0 / 0 | – |
| mbway | 3 / 3 / 0 | 0 / 0 / 0 | **slip rule**: myway.com, myway.be, m-way.ch. |
| kucoin | 4 / 6 / 0 | 0 / 0 / 0 | **official**: kucoin.plus, .cloud, .biz, plus .top and .work. All five are in the `SAFE_WEB_DOMAIN` list on www.kucoin.com's own page. **unrelated**: ucoin.net (a coin collectors' catalogue). |
| trezor | 2 / 1 / 2 | 0 / 0 / 0 | **shared name**: the Czech, Slovak and Croatian word for a safe. trezor.cz sells safes (registrant Trezor s.r.o.). The bare name under a country's TLD is not reported; under a TLD phishing favours it still is (`trezor.top`). **unrelated**: trezor.cz, trezlor.com (salon software). **slip rule**: tremor.com, trevor.com. |

### Rejected

The counts are under the slip rule, with no exemptions written.

| brand | new hits | why |
|---|---:|---|
| tmobile | 24 / 390 / 1 | It is `t` plus the word *mobile*. `mobile.de` and its subdomains alone are 335 hits, plus ymobile.jp, vmobile.jp, gmobile.mn, 2tmobile.com and the T-Mobile ccTLDs. Recall in the week: 1 host. |
| sharepoint | 12 / 43 / 0 | Share/point compounds: chargepoint.com (#12,431), shortpoint.com, storepoint.co, smartpoint.pro. Also `sharepoint.com.*.spo-msedge.net` and Microsoft's own sharepoint.us/.cn/.de. Recall: 0 (`docsharepoint` is no keyword combo). |
| interbank | 18 / 18 / 3 | *Inter* plus a word: interpark.com, interlink.*, interland.net, interbrand.com, interpack.com. The bare word is taken under .com too (interbank.com). Recall: 0. |
| aruba | 8 / 20 / 1 | A country's name (aruba.com), and one vowel from ariba.com (SAP Ariba, #12,636). Recall: 1. |
| raiffeisen | 10 / 15 / 0 | The name of a cooperative movement: raiffeisen.ch, .at, .ru, .ua, .ro, .hu, .it, .sk and .al are separate banks. The same reason kept it off the Russian list in #62. Recall: 0 (`raiffeise.vercel.app`). |
| caixa | 3 / 18 / 0 | Portuguese for *box*: caixa.cv is Cabo Verde's Caixa Económica, and caida.org is one letter away. Recall: 0 (`caixa-indeniza.github.io` was already flagged). |
| inpost | 9 / 12 / 1 | Nine other owners sit one edit away: ilpost.it (#6,331), anpost.com, anpost.ie, ipost.com, vnpost.vn. No host in the week. |
| verizon | 1 / 15 / 0 | The false positives are explained: verizon.net is Verizon's, and the rest are vendor hosts. It is rejected only because the week has no Verizon host. It is cheap to add when one appears. |
| sunrise, kleinanzeigen | 2 / 3 / 1, 3 / 3 / 0 | Ordinary words (*Kleinanzeigen* means classified ads, and kleinanzeigen.com and kleinanzeigen.at are other sites). Recall: 0. |

## Recall gain, per brand

Hosts newly flagged by `typosquatting` or `brand_subdomain_abuse`, with ML stubbed:

| brand | PhishTank | TweetFeed | rule | level change |
|---|---:|---:|---|---|
| allegrolokalnie | 103 | 0 | brand_subdomain_abuse | 55 caution → dangerous, 10 safe → caution, 38 already dangerous |
| allegro | 37 | 1 | brand_subdomain_abuse | 24 caution → dangerous (one on TweetFeed), 7 safe → caution, 7 already dangerous |
| olx | 5 | 0 | brand_subdomain_abuse | 4 caution → dangerous, 1 already dangerous |
| att, bellsouth | 3 | 0 | hosting tenant | 3 safe → caution |
| xfinity | 1 | 1 | hosting tenant | 2 safe → caution |
| mbway | 2 | 0 | typosquatting (TLD confusion) | 2 safe → caution |
| novobanco | 1 | 0 | brand_subdomain_abuse | 1 safe → caution |

The week shows comcast, nubank, correios, pichincha, kucoin and trezor being imitated, but none of
these brands caught a host. Their hosts are typos inside a hosting-platform name
(`supportxfinty`, `kucoxen`, `trzer`), or the brand next to a word that is no lure keyword
(`pichincha--credito2020`, `nubanksaldo2`, `membercomcast`). The names are on the list for the next
host shaped `brand-login.<platform>` or `brand.<random>.<tld>`. Allegro typos used as a subdomain
(`allegrolokainie.pl-5ufkc.sbs`, 37 hosts) are still missed: `brand_subdomain_abuse` matches whole
labels only.

## Reproduce

The measurement scripts lived in a scratch directory and are not committed. The method above is
complete. The candidate-only run patches `GLOBAL_TYPOSQUAT_TARGETS`, `TYPOSQUAT_TARGETS`,
`_NAME_RULES`, `_NAME_RULES_AT_HOME`, `_HOSTING_TENANT_BRANDS` and `_MEASURED_GLOBAL_NAMES` in
`api.services.scoring` to the single candidate, and restores the pre-change list to decide
"already flagged". The tests pin the result: `tests/test_global_brands_2026_10.py` covers the week's
hosts, every listed domain with and without `www.`, the slip-rule and dictionary clears, and the ML
feature. The extension's parity table gained the same shapes.

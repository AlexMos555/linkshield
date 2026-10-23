#!/usr/bin/env python3
"""Cleanway's popularity ranking, from sources a paid product may use.

ONE ranked list of registrable domains, built here and nowhere else:

  data/top_100k.json             the first 100,000 names, in rank order — the
                                 instant-safe allowlist (scoring.TOP_DOMAINS),
                                 the publisher's popular-domain veto and the
                                 ML feature in_top_domains
  data/top_10k.json              {name: rank} for the first 10,000 — OTX
                                 gating, "Ranked #N", the phone's veto
  data/public_suffixes_in_top.json  PSL rules whose base is in the 100,000
                                 or in data/infrastructure_domains.txt
                                 (scripts/build_public_suffixes_in_top.py)
  data/top_domains_sources.json  where all of it came from: list months,
                                 row counts, licences, attribution, hashes
  Redis tranco:ranks             the first 1,000,000 with their rank, loaded
                                 daily by scripts/refresh_tranco.py through
                                 ranked_domains() below — the same function

Until 2026-10-23 every one of these was Tranco's (the 2026-04-10 snapshot of
its top-100k in data/, the daily top-1M in Redis). Tranco states no licence
of its own and its default list averages Cloudflare Radar, CC BY-NC 4.0, so
none of it may stay in a product people pay for (docs/THIRD_PARTY_FEEDS.md
§2a). The sources now, licences read 2026-10-23:

  * Majestic Million (CC BY 3.0) — registrable domains (and some hosts)
    ranked by the number of IP subnets linking to them;
  * Chrome UX Report top origins (CC BY 4.0), the global list and
    Russia's, from the monthly CSV cache of the public BigQuery tables at
    github.com/zakird/crux-top-lists — ranked by Chrome page loads, in
    buckets (1000, 5000, 10000, 50000, 100000, 500000, 1000000);
  * the Public Suffix List (MPL 2.0) — which hosts are someone's tenant;
  * the four licensed phishing feeds the model trains on
    (refresh_training_feeds.PHISHING_SOURCES, CC0 / unrestricted) — which
    names someone reported.

How the rank is made (each step is a parameter below):
  1. Every host is folded to its registrable domain the way the scorer
     reads it (registrable_domain(): play.google.com → google.com,
     kvs.gov.spb.ru → gov.spb.ru), each list keeping a domain's best rank.
     A tenant of a shared suffix (foo.github.io, x.us.org) is dropped: its
     traffic is its own, not the platform's, and the scorer never looks a
     tenant up by name.
  2. CrUX rank = the global bucket, or Russia's bucket × RU_FACTOR when
     that is better. Chrome counts few Russians (Yandex Browser is not in
     CrUX): the Russian sites both lists carry sit 20-50 times lower
     globally than at home (median, 2026-09 lists), so without Russia's
     list the top 100,000 held 1,842 Russian names where Tranco's had
     3,799. Cleanway's users are mostly Russian; × 6 keeps the top 10,000
     as Russian as it was (389 against 360) and lets Russia's 10,000
     most-opened origins into the 100,000 (4,986 Russian names).
  3. The lists are merged by the Dowdall rule — score = 1/rank in Majestic
     + 1/CrUX rank, a list that does not carry the name adding nothing —
     the rule Tranco itself uses. A name both lists carry outranks one only
     a single list knows. Ties: best single rank, then name.
  4. A name a licensed phishing feed reports (the name or its www. host)
     stays only when BOTH lists rank it in their top REPORTED_MIN_RANK, the
     Majestic Million in its top REPORTED_MAJESTIC_RANK, or either list in
     its top REPORTED_ANY_RANK. Reporters post the platform a page sits on
     (facebook.com, github.com, t.me, discord.gg, docsend.com, sendspace.com):
     a platform thousands of sites link to stays — the blocklist publisher
     reads this ranking as "never darken", and a whole platform blocked for
     every DNS user is the worst false positive there is. A name only
     visits vouch for does not: on 2026-10-23 the rule dropped
     roblox.com.bz, sstake.eu, freelitecoin.online, narco24.to and the
     ushort.* shorteners, ~90 of the ~180 reported names the top 100,000
     would have held — CrUX's long tail (Russia's especially) carries the
     scam sites people are sent to, Majestic's the link farms.
  5. Top-N by that rank: the thresholds the consumers use (1,000 / 10,000 /
     100,000 / 1,000,000) mean the same positions they meant in Tranco.

Refusal (exit 2, every previous file untouched): a list missing, shorter
than its MIN_*, or unparseable; fewer than MIN_FEEDS phishing feeds; a
ranking under REDIS_N names; a top 100,000 sharing under MIN_OVERLAP of its
names with the previous one (a deliberate source change: --allow-churn).
Files are written to .tmp first and moved over the old ones only when all
of them were written.

The ML model reads data/top_100k.json and data/public_suffixes_in_top.json
as features. A model keeps the copies it was trained on: when model_meta.json
names a file this run replaces, the old one is first archived under
data/feature_data/ (archive_model_feature_data), and ml_scorer serves the
model from the archive until a model trained on the new files replaces it.
Archives no model names are removed.

Usage:
    python3 scripts/build_top_domains.py                 # fetch, build, write
    python3 scripts/build_top_domains.py --dry-run       # build, report, write nothing
    python3 scripts/build_top_domains.py --allow-churn   # a deliberate source change
    python3 scripts/build_top_domains.py --cache DIR     # keep the downloads in DIR

Only the standard library and httpx at import time (plus
api.services.hosting_platforms, which is standard-library only): the daily
Redis refresh runs on a runner with httpx and redis installed, nothing else.
"""
from __future__ import annotations

import argparse
import datetime
import gzip
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import sys
from typing import Callable, Iterable, NamedTuple, Optional

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SCRIPTS = os.path.dirname(os.path.abspath(__file__))
for _p in (_ROOT, _SCRIPTS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import build_public_suffixes_in_top as psl_in_top  # noqa: E402
import refresh_training_feeds as feeds  # noqa: E402
from api.services import hosting_platforms  # noqa: E402

logger = logging.getLogger("top-domains")

DATA = os.path.join(_ROOT, "data")
FEATURE_DATA_DIR = os.path.join(DATA, "feature_data")
MODEL_META = os.path.join(DATA, "model_meta.json")
TOP_100K = "top_100k.json"
TOP_10K = "top_10k.json"
PSL_IN_TOP = "public_suffixes_in_top.json"
SOURCES = "top_domains_sources.json"
RU_PSL = os.path.join(DATA, "ru_public_suffixes.json")

MAJESTIC = feeds.MAJESTIC
CRUX = feeds.CRUX
PSL_URL = psl_in_top.PSL_URL

TOP_N = 100_000
TOP_RANKED_N = 10_000
REDIS_N = 1_000_000
RU_FACTOR = 6
REPORTED_MIN_RANK = 100_000
REPORTED_MAJESTIC_RANK = 10_000
REPORTED_ANY_RANK = 1_000

# Healthy sizes, 2026-10-23: Majestic 1,000,000 rows; CrUX 202609 global
# 1,000,000 origins, Russia 661,624; PSL 9,780 rules; the four feeds
# 137,458 / 125,336 / 41,230 / 1,369 hosts. Far fewer means an error page,
# a truncated download or a dead feed.
MIN_MAJESTIC = 900_000
CRUX_SCOPES = {"global": 500_000, "country/ru": 200_000}
MIN_PSL_RULES = 5_000
MIN_FEEDS = 3
MIN_PSL_IN_TOP = 500
# Share of the previous top 100,000 the new one must keep. Built from the
# CrUX lists of two consecutive months and the same Majestic file, the
# top 100,000 keeps 92.4% (202608 → 202609); the switch from Tranco kept 55%.
MIN_OVERLAP = 0.85

LICENCES = {
    "majestic_million": {
        "url": MAJESTIC, "licence": "CC BY 3.0",
        "attribution": "The Majestic Million, by Majestic-12 Ltd (majestic.com), CC BY 3.0",
    },
    "crux": {
        "url": CRUX, "licence": "CC BY 4.0", "via": "github.com/zakird/crux-top-lists",
        "attribution": "Chrome UX Report top origins, by Google (developer.chrome.com/docs/crux), CC BY 4.0",
    },
    "public_suffix_list": {"url": PSL_URL, "licence": "MPL 2.0"},
}
CHANGES = (
    "Hosts folded to registrable domains (best rank per list), hosting tenants dropped, the CrUX rank "
    f"taken as the better of the global bucket and Russia's bucket x {RU_FACTOR}, the two lists merged by "
    "the Dowdall rule, names a licensed phishing feed reports dropped unless both lists rank them in "
    f"their top {REPORTED_MIN_RANK:,}, Majestic in its top {REPORTED_MAJESTIC_RANK:,} or either in its top "
    f"{REPORTED_ANY_RANK:,}, cut to the top "
    f"{TOP_N:,} / {TOP_RANKED_N:,} (and {REDIS_N:,} for the Redis rank)."
)


# ── Registrable domains, the scorer's reading ──
#
# api.services.scoring.registrable_domain() is the rule; it cannot be
# imported here (scoring needs pydantic, the Redis runner has httpx and
# redis only). This is the same rule — a Russian PSL rule plus one label,
# else the compound-ccTLD heuristic of doh_gateway._registrable_domain — and
# tests/test_build_top_domains.py holds the two to the same answer.

_CCTLD_SECOND_LEVELS = frozenset({
    "com", "co", "org", "net", "gov", "edu", "ac", "mil", "gob", "gouv",
    "or", "ne", "go", "in", "nom", "gen", "ltd", "plc", "sch", "asn",
    "id", "biz", "info", "web", "gv", "govt",
})
_COMPOUND = frozenset({
    "co.uk", "ac.uk", "gov.uk", "org.uk", "co.jp", "co.in",
    "com.au", "com.br", "com.mx", "co.kr", "co.za", "com.sg",
})


def _load_ru_rules(path: str = RU_PSL) -> tuple[frozenset[str], frozenset[str]]:
    with open(path, encoding="utf-8") as f:
        rules = {r.lower() for r in json.load(f)}
    return (frozenset(r for r in rules if not r.startswith("*.")),
            frozenset(r[2:] for r in rules if r.startswith("*.")))


_RU_EXACT, _RU_WILDCARD = _load_ru_rules()


def _ascii_label(label: str) -> str:
    if label.isascii():
        return label
    try:
        return "xn--" + label.encode("punycode").decode("ascii")
    except UnicodeError:
        return label


def _ru_registrable(parts: list[str]) -> Optional[str]:
    labels = [_ascii_label(p) for p in parts]
    for k in range(len(labels), 1, -1):
        tail = labels[-k:]
        if ".".join(tail) in _RU_EXACT or ".".join(tail[1:]) in _RU_WILDCARD:
            return ".".join(parts[-(k + 1):])
    return None


def registrable_domain(host: str) -> str:
    """The registrable domain a host is judged by (scoring.registrable_domain)."""
    dom = (host or "").lower().strip(".")
    if not dom:
        return ""
    parts = dom.split(".")
    ru = _ru_registrable(parts)
    if ru:
        return ru
    if len(parts) <= 2:
        return dom
    last_two = ".".join(parts[-2:])
    if last_two in _COMPOUND or (len(parts[-1]) == 2 and parts[-2] in _CCTLD_SECOND_LEVELS):
        return ".".join(parts[-3:])
    return last_two


# ── Inputs ──

class PSL(NamedTuple):
    text: str
    private: frozenset[str]  # the PRIVATE section, wildcards stripped
    n_rules: int


def parse_psl(text: str) -> PSL:
    """The PSL's private-section rules ('*.' stripped, exceptions dropped)
    and its rule count. A file without both section markers raises."""
    if "===BEGIN ICANN DOMAINS===" not in text or "===BEGIN PRIVATE DOMAINS===" not in text:
        raise ValueError("not the Public Suffix List (section markers missing)")
    private: set[str] = set()
    n = 0
    in_private = False
    for raw in text.splitlines():
        line = raw.strip()
        if "===BEGIN PRIVATE DOMAINS===" in line:
            in_private = True
        if not line or line.startswith("//") or line.startswith("!"):
            continue
        n += 1
        rule = line[2:] if line.startswith("*.") else line
        if in_private and "." in rule:
            private.add(".".join(_ascii_label(p) for p in rule.lower().split(".")))
    return PSL(text, frozenset(private), n)


def tenant_suffixes(psl: PSL) -> frozenset[str]:
    """Every suffix whose subdomains are separate customers' names: the PSL's
    private section and the curated data/hosting_platforms.json (tenant
    suffixes and dynamic DNS)."""
    return psl.private | hosting_platforms.TENANT_SUFFIXES | hosting_platforms.DYNAMIC_DNS_SUFFIXES


def is_tenant(host: str, suffixes: frozenset[str]) -> bool:
    """A strict subdomain of a shared suffix that is not the platform's own
    host (www.<suffix>, hosting_platforms.OPERATOR_HOSTS) and not a registry
    the registrable rule already reads (kvs.gov.spb.ru is a name under the
    spb.ru zone, not a tenant of it)."""
    parts = host.split(".")
    for k in range(len(parts) - 1, 1, -1):
        suffix = ".".join(parts[-k:])
        if suffix in suffixes:
            if host == "www." + suffix or host in hosting_platforms.OPERATOR_HOSTS:
                return False
            return not registrable_domain(host).endswith("." + suffix)
    return False


_HOSTNAME = re.compile(r"^(?=.{4,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$")


def _is_name(host: str) -> bool:
    if not _HOSTNAME.match(host) or host.endswith(".arpa"):
        return False
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        return True


def fold(rows: Iterable[tuple[int, str]], suffixes: frozenset[str]) -> dict[str, int]:
    """(rank, host) rows → {registrable domain: best rank}, tenants and
    anything that is not a host name (IP literals, .arpa) left out."""
    best: dict[str, int] = {}
    for rank, host in rows:
        host = host.lower().strip(".")
        if rank <= 0 or not _is_name(host) or is_tenant(host, suffixes):
            continue
        domain = registrable_domain(host)
        if rank < best.get(domain, rank + 1):
            best[domain] = rank
    return best


class Sources(NamedTuple):
    majestic: list[tuple[int, str]]
    crux: dict[str, list[tuple[int, str]]]  # scope → (bucket, host)
    crux_months: dict[str, str]
    psl: PSL
    reported: dict[str, frozenset[str]]  # feed → hosts


Fetch = Callable[[str, float], bytes]


def _cached(fetch: Fetch, cache: Optional[str]) -> Fetch:
    """`fetch`, keeping each URL's bytes in `cache` (a directory) and reading
    them back from there on the next run."""
    if not cache:
        return fetch

    def get(url: str, timeout: float = 180.0) -> bytes:
        os.makedirs(cache, exist_ok=True)
        path = os.path.join(cache, re.sub(r"[^A-Za-z0-9._-]+", "_", url)[-200:])
        if os.path.exists(path):
            with open(path, "rb") as f:
                return f.read()
        body = fetch(url, timeout)
        with open(path + ".tmp", "wb") as f:
            f.write(body)
        os.replace(path + ".tmp", path)
        return body

    return get


def _fetch_crux(scope: str, fetch: Fetch, today: datetime.date) -> tuple[str, list[tuple[int, str]]]:
    """The newest published month of one CrUX scope (a 404 tries the month before)."""
    import httpx

    for month in feeds.crux_months(today):
        try:
            body = fetch(CRUX.format(scope=scope, month=month), 180.0)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                continue
            raise
        return month, feeds.parse_crux(gzip.decompress(body).decode("utf-8", "ignore"))
    raise FileNotFoundError(f"no CrUX {scope} list in the last {feeds.CRUX_MONTHS_BACK} months")


def fetch_sources(fetch: Optional[Fetch] = None, cache: Optional[str] = None,
                  today: Optional[datetime.date] = None) -> Sources:
    """Download and parse every input. Raises on any list that is missing,
    unreadable or short; a dead phishing feed is skipped (MIN_FEEDS)."""
    get = _cached(fetch or feeds._get, cache)
    majestic = feeds.parse_majestic(get(MAJESTIC, 300.0).decode("utf-8", "ignore"))
    if len(majestic) < MIN_MAJESTIC:
        raise ValueError(f"Majestic Million: {len(majestic)} rows, need {MIN_MAJESTIC}")
    crux: dict[str, list[tuple[int, str]]] = {}
    months: dict[str, str] = {}
    for scope, minimum in CRUX_SCOPES.items():
        month, rows = _fetch_crux(scope, get, today or datetime.date.today())
        if len(rows) < minimum:
            raise ValueError(f"CrUX {scope} {month}: {len(rows)} origins, need {minimum}")
        crux[scope], months[scope] = rows, month
    psl = parse_psl(get(PSL_URL, 60.0).decode("utf-8"))
    if psl.n_rules < MIN_PSL_RULES:
        raise ValueError(f"Public Suffix List: {psl.n_rules} rules, need {MIN_PSL_RULES}")
    reported: dict[str, frozenset[str]] = {}
    for spec in feeds.PHISHING_SOURCES:
        try:
            reported[spec.name] = frozenset(spec.parser(get(spec.url, 180.0).decode("utf-8", "ignore")))
        except Exception as e:  # noqa: BLE001 — one dead feed must not stop the others
            logger.warning("%s fetch failed: %s", spec.name, e)
    if len(reported) < MIN_FEEDS:
        raise ValueError(f"only {len(reported)} phishing feeds readable ({sorted(reported)}), need {MIN_FEEDS}")
    return Sources(majestic, crux, months, psl, reported)


# ── The ranking ──

class Ranking(NamedTuple):
    names: list[str]  # rank order: names[0] is rank 1
    majestic: dict[str, int]
    crux: dict[str, int]
    removed_reported: list[str]  # reported names dropped (step 4), in rank order


def rank(sources: Sources) -> Ranking:
    """Steps 1-4 of the module docstring."""
    suffixes = tenant_suffixes(sources.psl)
    majestic = fold(sources.majestic, suffixes)
    crux = fold(sources.crux["global"], suffixes)
    for domain, bucket in fold(sources.crux["country/ru"], suffixes).items():
        scaled = bucket * RU_FACTOR
        if scaled < crux.get(domain, scaled + 1):
            crux[domain] = scaled
    score: dict[str, float] = {}
    best: dict[str, int] = {}
    for ranks in (majestic, crux):
        for domain, r in ranks.items():
            score[domain] = score.get(domain, 0.0) + 1.0 / r
            best[domain] = min(best.get(domain, r), r)
    ordered = sorted(score, key=lambda d: (-score[d], best[d], d))
    reported = frozenset().union(*sources.reported.values())
    kept: list[str] = []
    removed: list[str] = []
    for domain in ordered:
        if (domain in reported or "www." + domain in reported) and not _vouched(domain, majestic, crux):
            removed.append(domain)
        else:
            kept.append(domain)
    return Ranking(kept, majestic, crux, removed)


def _vouched(domain: str, majestic: dict[str, int], crux: dict[str, int]) -> bool:
    """Does popularity outweigh a feed's report (step 4)? Both lists in
    their top REPORTED_MIN_RANK, Majestic in its top REPORTED_MAJESTIC_RANK,
    or either in its top REPORTED_ANY_RANK."""
    m, c = majestic.get(domain), crux.get(domain)
    both = m is not None and c is not None and max(m, c) <= REPORTED_MIN_RANK
    linked = m is not None and m <= REPORTED_MAJESTIC_RANK
    return both or linked or min(m or REPORTED_ANY_RANK + 1, c or REPORTED_ANY_RANK + 1) <= REPORTED_ANY_RANK


def ranked_domains(fetch: Optional[Fetch] = None, cache: Optional[str] = None,
                   limit: int = REDIS_N) -> list[tuple[str, int]]:
    """(domain, rank) for the first `limit` names — what scripts/refresh_tranco.py
    loads into Redis. Raises when any input fails (fetch_sources) or the
    ranking is shorter than `limit`."""
    ranking = rank(fetch_sources(fetch, cache))
    if len(ranking.names) < limit:
        raise ValueError(f"ranking has {len(ranking.names)} names, need {limit}")
    return [(d, i + 1) for i, d in enumerate(ranking.names[:limit])]


# ── Files ──

def sha256_of(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except OSError:
        return None


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def render(ranking: Ranking, sources: Sources, today: datetime.date) -> dict[str, str]:
    """{file name: content} for the four data files."""
    top = ranking.names[:TOP_N]
    if len(top) < TOP_N:
        raise ValueError(f"ranking has {len(ranking.names)} names, need {TOP_N}")
    rules = psl_in_top.rules_in_top(set(top) | psl_in_top.load_infrastructure(), sources.psl.text)
    if len(rules) < MIN_PSL_IN_TOP:
        raise ValueError(f"only {len(rules)} public-suffix rules in the top {TOP_N}, need {MIN_PSL_IN_TOP}")
    files = {
        TOP_100K: json.dumps(top, indent=0) + "\n",
        TOP_10K: json.dumps({d: i + 1 for i, d in enumerate(top[:TOP_RANKED_N])}, indent=0) + "\n",
        PSL_IN_TOP: json.dumps(rules, indent=0) + "\n",
    }
    ru = (".ru", ".su", ".xn--p1ai")
    record = {
        "built": today.isoformat(),
        "method": CHANGES,
        "parameters": {
            "top_n": TOP_N, "ranked_n": TOP_RANKED_N, "redis_n": REDIS_N, "ru_factor": RU_FACTOR,
            "reported_min_rank": REPORTED_MIN_RANK, "reported_majestic_rank": REPORTED_MAJESTIC_RANK,
            "reported_any_rank": REPORTED_ANY_RANK,
        },
        "sources": {
            "majestic_million": {**LICENCES["majestic_million"], "rows": len(sources.majestic),
                                 "registrable_domains": len(ranking.majestic)},
            "crux": {**LICENCES["crux"], "months": sources.crux_months,
                     "origins": {scope: len(rows) for scope, rows in sources.crux.items()},
                     "registrable_domains": len(ranking.crux)},
            "public_suffix_list": {**LICENCES["public_suffix_list"], "rules": sources.psl.n_rules},
            "phishing_feeds": {name: len(hosts) for name, hosts in sorted(sources.reported.items())},
        },
        "ranked_names": len(ranking.names),
        "reported_names_removed": len(ranking.removed_reported),
        "russian_names": {"top_10k": sum(d.endswith(ru) for d in top[:TOP_RANKED_N]),
                          "top_100k": sum(d.endswith(ru) for d in top)},
        "files": {
            TOP_100K: {"names": len(top), "sha256": _sha(files[TOP_100K])},
            TOP_10K: {"names": min(len(top), TOP_RANKED_N), "sha256": _sha(files[TOP_10K])},
            PSL_IN_TOP: {"rules": len(rules), "sha256": _sha(files[PSL_IN_TOP])},
        },
    }
    files[SOURCES] = json.dumps(record, indent=2) + "\n"
    return files


def archive_name(file: str, sha256: str) -> str:
    stem, ext = os.path.splitext(file)
    return f"{stem}.{sha256[:12]}{ext}"


def _model_feature_files(meta_path: str = MODEL_META) -> dict[str, str]:
    """{file: sha256} of the feature data model_meta.json names."""
    try:
        with open(meta_path, encoding="utf-8") as f:
            record = json.load(f).get("feature_data") or {}
    except (OSError, ValueError):
        return {}
    return {r["file"]: r["sha256"] for r in record.values()
            if isinstance(r, dict) and isinstance(r.get("file"), str) and isinstance(r.get("sha256"), str)}


def archive_model_feature_data(new_files: dict[str, str], data_dir: str = DATA,
                               meta_path: str = MODEL_META) -> list[str]:
    """Before `new_files` replace the live ones: every live file the served
    model was trained on (model_meta.json feature_data) that is about to
    change is copied to data/feature_data/<stem>.<sha12>.json, where
    ml_scorer finds it by its hash. Returns the archived paths."""
    archive_dir = os.path.join(data_dir, "feature_data")
    out = []
    for file, sha in _model_feature_files(meta_path).items():
        live = os.path.join(data_dir, file)
        if file not in new_files or sha256_of(live) != sha or _sha(new_files[file]) == sha:
            continue
        os.makedirs(archive_dir, exist_ok=True)
        dest = os.path.join(archive_dir, archive_name(file, sha))
        if not os.path.exists(dest):
            shutil.copyfile(live, dest + ".tmp")
            os.replace(dest + ".tmp", dest)
        out.append(dest)
    return out


def prune_feature_archive(data_dir: str = DATA, meta_path: str = MODEL_META) -> list[str]:
    """Remove archived feature data no model names any more. Returns the removed paths."""
    archive_dir = os.path.join(data_dir, "feature_data")
    if not os.path.isdir(archive_dir):
        return []
    wanted = {archive_name(file, sha) for file, sha in _model_feature_files(meta_path).items()}
    removed = []
    for name in sorted(os.listdir(archive_dir)):
        if name not in wanted:
            os.remove(os.path.join(archive_dir, name))
            removed.append(os.path.join(archive_dir, name))
    if not os.listdir(archive_dir):
        os.rmdir(archive_dir)
    return removed


def write_all(files: dict[str, str], data_dir: str = DATA) -> bool:
    """Every file to a .tmp first, then each moved over the previous one; a
    failed write leaves every previous file and no .tmp behind."""
    pending = [(os.path.join(data_dir, name) + ".tmp", os.path.join(data_dir, name), text)
               for name, text in files.items()]
    try:
        for tmp, _, text in pending:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(text)
    except OSError as e:
        logger.error("Write failed, keeping the previous files: %s", e)
        for tmp, _, _ in pending:
            if os.path.isfile(tmp):
                os.remove(tmp)
        return False
    for tmp, out, _ in pending:
        os.replace(tmp, out)
        logger.info("Wrote %s", out)
    return True


def overlap_with_previous(top: list[str], data_dir: str = DATA) -> Optional[float]:
    try:
        with open(os.path.join(data_dir, TOP_100K), encoding="utf-8") as f:
            previous = set(json.load(f))
    except (OSError, ValueError):
        return None
    return len(previous & set(top)) / max(len(top), 1)


def diff_report(top: list[str], data_dir: str = DATA) -> dict:
    """Names entering and leaving the 100,000 and the 10,000."""
    try:
        with open(os.path.join(data_dir, TOP_100K), encoding="utf-8") as f:
            previous = json.load(f)
    except (OSError, ValueError):
        previous = []
    old, new = set(previous), set(top)
    old10, new10 = set(previous[:TOP_RANKED_N]), set(top[:TOP_RANKED_N])
    return {
        "top_100k": {"kept": len(old & new), "entering": len(new - old), "leaving": len(old - new)},
        "top_10k": {"kept": len(old10 & new10), "entering": len(new10 - old10), "leaving": len(old10 - new10)},
    }


def build(args: argparse.Namespace, data_dir: str = DATA, meta_path: str = MODEL_META,
          fetch: Optional[Fetch] = None, today: Optional[datetime.date] = None) -> int:
    today = today or datetime.date.today()
    try:
        sources = fetch_sources(fetch, args.cache, today)
        ranking = rank(sources)
        if len(ranking.names) < REDIS_N:
            raise ValueError(f"ranking has {len(ranking.names)} names, need {REDIS_N}")
        files = render(ranking, sources, today)
    except Exception as e:  # noqa: BLE001 — any failure keeps the previous files
        logger.error("Top-domain build failed, keeping the previous files: %s", e)
        return 2
    top = json.loads(files[TOP_100K])
    report = diff_report(top, data_dir)
    logger.info("Ranked %d names (%d reported names removed); vs the previous list: %s",
                len(ranking.names), len(ranking.removed_reported), report)
    overlap = overlap_with_previous(top, data_dir)
    churned = overlap is not None and overlap < MIN_OVERLAP and not args.allow_churn
    if args.dry_run:
        logger.info("Dry run — nothing written. Russian names: %s%s", json.loads(files[SOURCES])["russian_names"],
                    " (a real run would refuse: too far from the previous list)" if churned else "")
        return 0
    if churned:
        logger.error("The new top %d keeps %.1f%% of the previous one (minimum %.0f%%) — refusing; "
                     "--allow-churn for a deliberate source change", TOP_N, overlap * 100, MIN_OVERLAP * 100)
        return 2
    archived = archive_model_feature_data(files, data_dir, meta_path)
    for path in archived:
        logger.info("Archived %s for the served model (model_meta.json feature_data)", path)
    if not write_all(files, data_dir):
        return 2
    for path in prune_feature_archive(data_dir, meta_path):
        logger.info("Removed %s: no model reads it any more", path)
    logger.info("Next: python3 scripts/build_mobile_assets.py && python3 scripts/build_extension_scorer_data.py, "
                "then retrain (the served model keeps its archived copies until then)")
    return 0


def main(argv: Optional[list[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--dry-run", action="store_true", help="build and report, write nothing")
    p.add_argument("--allow-churn", action="store_true", help="accept a top 100,000 far from the previous one")
    p.add_argument("--cache", help="directory that keeps the downloads (re-runs read them from there)")
    return build(p.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())


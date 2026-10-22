#!/usr/bin/env python3
"""Refresh the ML training feeds so retraining learns CURRENT phishing.

The model's training data was a frozen Apr-2026 snapshot (data/phishtank.csv,
data/top-1m.csv) with no refresher — so a retrain just re-learned April's phish.
This script pulls fresh, free, bulk sources into the exact files ml/train_model.py
reads, turning the model into a living, retrainable system (run by retrain-ml.yml).

Phishing sources — only feeds whose terms allow training a paid product's
model on them (docs/THIRD_PARTY_FEEDS.md §3). Until 2026-10-21 the corpus was
the URLhaus full dump plus the OpenPhish community feed; both are
non-commercial (abuse.ch terms 2025-11-04: not-for-profit, no derivative
works — a model is one; openphish.com/terms.html: no "product development",
"detection" or "customer protection"), and abuse.ch retired anonymous
downloads that day (the dump answers 410 Gone). Each source is capped and the
corpus is interleaved, so no single feed decides what "phishing" looks like:
PhishDestroy alone is mostly English crypto drainers, CERT Polska Polish
parcel/bank lures, TweetFeed and Phishunt what researchers report.

Phishing.Database is NOT read here although the blocklist uses it: MIT
covers the compilation, its README does not say where the names come from,
and a model trained on them would be a derivative of whatever that is
(PhishTank/OpenPhish terms do not survive an MIT re-licence). It joins when
the provenance question in docs/THIRD_PARTY_FEEDS.md §1 is answered.

The corpus is all names now (URLhaus was mostly bare IPs), and on
2026-10-21 a model trained on it flagged far more real sites than the served
one — so ml/train_model.py keeps the served model unless the candidate is no
worse on the held-out real sites (its replacement guard).

Benign sources — the same rule (docs/THIRD_PARTY_FEEDS.md §3). Until
2026-10-22 both lists were Tranco's, which states no licence of its own and
whose default list averages Cloudflare Radar (CC BY-NC 4.0). Now:
  * Majestic Million (CC BY 3.0) — ranked registrable domains, by links;
  * Chrome UX Report top origins (CC BY 4.0), the global list and Russia's,
    from the monthly CSV cache of the public BigQuery tables at
    github.com/zakird/crux-top-lists — ranked by Chrome page loads. CrUX
    names origins (https://www.example.com), so it has the host shapes a
    registrable-domain list folds away, and the Russian list carries the
    names under regional zones (gorzdrav.spb.ru) that the global one barely
    has (139 against 3,584 on 2026-10-22).
Majestic alone is not enough for the registrable domains: its long tail is
what sites link to, not what people open, and a model trained on it scored
4.3% of CrUX's long tail above 0.6 (the served model 0.5%) — cheap-TLD real
sites (.online, .shop, .site) were rarer in it than in the phishing feeds.
So the global CrUX list's registrable domains join it (Tranco averaged
both, among others); Russia's list stays a host-shape source only: with
its registrable domains 16.7% of the long tail would be Russian, not 2.2%.

Writes (all gitignored — regenerated each run):
  data/phishtank.csv  — phishing corpus: 'url' (https://<host>/) and 'source'
                        columns. Name kept for train_model.py compatibility.
  data/benign-domains.csv — `rank,domain`: the Majestic Million and the
                        registrable domains of the global CrUX list (hosting
                        tenants left out), one row per domain at its best rank.
  data/benign-hosts.csv   — `rank,host`: CrUX global + Russia top origins,
                        one row per host (its best rank; CrUX ranks are
                        buckets: 1000, 5000, 10000 …): the benign host shapes
                        (www.example.com, kvs.gov.spb.ru-style names) and
                        hosting tenants. See ml/train_model.load_benign_domains.

Refusal (exit 2, previous files untouched): fewer than MIN_SOURCES feeds
readable, or fewer than MIN_HOSTS hosts in all; for the benign lists, any
list unreadable or shorter than its MIN_*. In retrain-ml.yml that stops the
job before the commit step, so production keeps the last good model instead
of one trained on a lopsided corpus.

Usage:
    python scripts/refresh_training_feeds.py
    python scripts/refresh_training_feeds.py --phishing-only
"""
from __future__ import annotations

import argparse
import csv
import datetime
import gzip
import json
import logging
import os
import random
import sys
from typing import Callable, Iterable, NamedTuple, Optional
from urllib.parse import urlparse

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("training-feeds")

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_DATA = os.path.join(os.path.dirname(__file__), "..", "data")

# Benign lists (licences read 2026-10-22; the table is docs/THIRD_PARTY_FEEDS.md §3).
MAJESTIC = "https://downloads.majestic.com/majestic_million.csv"
# One file per month and scope; the country lists have no 'current' alias.
CRUX = "https://raw.githubusercontent.com/zakird/crux-top-lists/main/data/{scope}/{month}.csv.gz"
# Scope → fewest origins a healthy file has. 2026-10-22: Majestic 1,000,000
# rows, CrUX global 1,000,000 origins, Russia 661,624 (998,690 and 660,433
# hosts). Far fewer means an error page or a truncated file.
CRUX_SCOPES = {"global": 500_000, "country/ru": 200_000}
# The scopes whose registrable domains join the Majestic Million in
# BENIGN_DOMAINS (see the module docstring).
CRUX_DOMAIN_SCOPES = ("global",)
MIN_BENIGN_DOMAINS = 500_000
# CrUX publishes a month on the second Tuesday of the next one, so early in
# a month the newest file is two months back.
CRUX_MONTHS_BACK = 4
BENIGN_DOMAINS = "benign-domains.csv"
BENIGN_HOSTS = "benign-hosts.csv"

# ml/train_model.train() reads this many phishing hosts (names first, then
# IP literals, in file order).
TRAINING_PHISHING_HOSTS = 20_000
# Per feed. Four feeds: three at 6,000 plus Phishunt's ~1,400 (all it carries
# at a time) fill ~19,400 hosts, every feed 7-31%. ml/train_model then caps
# hosting tenants (PHISH_TENANT_SHARE), which takes ~1,200 out. (3,500 each
# until 2026-10-22: ~200 names with a lure word in the whole class was too
# few to learn secure-login.<platform> from.)
DEFAULT_CAP = 6_000
MIN_SOURCES = 3
MIN_HOSTS = 5_000
SEED = 42


def _get(url: str, timeout: float = 180.0) -> bytes:
    with httpx.Client(timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": "cleanway-training"}) as c:
        r = c.get(url)
        r.raise_for_status()
        return r.content


def _clean(host: str) -> str:
    return host.strip().lower().rstrip(".")


def parse_domain_list(text: str) -> Iterable[str]:
    """One domain per line, '#' comments, hosts-file lines ("0.0.0.0 x")."""
    for raw in text.splitlines():
        line = _clean(raw)
        if not line or line.startswith("#"):
            continue
        if " " in line or "\t" in line:
            line = line.split()[-1]
        if "." in line and "/" not in line:
            yield line


def parse_url_list(text: str) -> Iterable[str]:
    for raw in text.splitlines():
        try:
            host = urlparse(raw.strip()).hostname
        except ValueError:
            continue
        if host and "." in host:
            yield _clean(host)


def parse_json_list(text: str) -> Iterable[str]:
    """A JSON array of hostnames. Anything else raises, so an error page is
    a dead feed, not an empty one. Wildcards and leading dots are skipped."""
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError(f"expected a JSON array of hostnames, got {type(data).__name__}")
    for item in data:
        if not isinstance(item, str):
            continue
        host = _clean(item)
        if host and not host.startswith(("*", ".")) and "/" not in host and not any(c.isspace() for c in host):
            yield host


# TweetFeed reporters post malware attachment names ('documents.zip') in the
# domain/url columns — filenames, not hosts.
_FILENAME_TLDS = (".zip", ".mov")


def parse_tweetfeed(text: str) -> Iterable[str]:
    """TweetFeed year.csv: `date,user,type,value,tags,tweet`. Only `domain`
    and `url` rows name a host."""
    for row in csv.reader(text.splitlines()):
        if len(row) < 4:
            continue
        kind, value = row[2].strip().lower(), row[3].strip()
        if kind == "domain":
            host = value
        elif kind == "url":
            try:
                host = urlparse(value).hostname or ""
            except ValueError:
                continue
        else:
            continue
        host = _clean(host)
        if host and "/" not in host and not host.endswith(_FILENAME_TLDS):
            yield host


class Source(NamedTuple):
    name: str
    url: str
    parser: Callable[[str], Iterable[str]]
    licence: str
    cap: int = DEFAULT_CAP


# Licences as read 2026-10-21; the full table is docs/THIRD_PARTY_FEEDS.md.
# The blocklist reads the same URLs (scripts/refresh_dangerous_domains.py).
PHISHING_SOURCES: tuple[Source, ...] = (
    Source("PhishDestroy",
           "https://raw.githubusercontent.com/phishdestroy/destroylist/main/dns/active_domains.json",
           parse_json_list,
           "phishdestroy.io/dataset: CC0 1.0, named fit for commercial products and ML training; repo MIT"),
    Source("CERT Polska", "https://hole.cert.pl/domains/v2/domains.txt", parse_domain_list,
           "Lista Ostrzezen API spec s.1: may be processed without restriction, manually or automatically"),
    Source("TweetFeed", "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv",
           parse_tweetfeed,
           "README: CSV feeds CC0 1.0 (the abuse.ch-licensed /v1/ioc external block is never read)"),
    Source("Phishunt", "https://phishunt.io/feed.txt", parse_url_list,
           "phishunt.io terms s.7: feeds released under CC0 1.0"),
)


def build_corpus(hosts_by_source: dict[str, Iterable[str]], caps: dict[str, int],
                 seed: int = SEED) -> list[tuple[str, str]]:
    """(host, source) rows: each source's hosts shuffled with a fixed seed,
    at most caps[source] of them, interleaved round-robin so every prefix of
    the file — train_model reads the first TRAINING_PHISHING_HOSTS — is
    already mixed. A host two feeds list is kept once, for the first."""
    queues: dict[str, list[str]] = {}
    for name, hosts in hosts_by_source.items():
        unique = sorted({_clean(h) for h in hosts} - {""})
        random.Random(f"{seed}:{name}").shuffle(unique)
        queues[name] = unique
    taken = dict.fromkeys(queues, 0)
    position = dict.fromkeys(queues, 0)
    seen: set[str] = set()
    rows: list[tuple[str, str]] = []
    active = [name for name in queues if caps.get(name, 0) > 0]
    while active:
        still = []
        for name in active:
            queue = queues[name]
            while position[name] < len(queue) and queue[position[name]] in seen:
                position[name] += 1
            if position[name] >= len(queue):
                continue
            host = queue[position[name]]
            position[name] += 1
            seen.add(host)
            rows.append((host, name))
            taken[name] += 1
            if taken[name] < caps[name]:
                still.append(name)
        active = still
    return rows


def refresh_phishing() -> int:
    hosts_by_source: dict[str, list[str]] = {}
    for spec in PHISHING_SOURCES:
        try:
            hosts = list(spec.parser(_get(spec.url).decode("utf-8", "ignore")))
        except Exception as e:  # noqa: BLE001 — one dead feed must not stop the others
            logger.warning("%s fetch failed: %s", spec.name, e)
            continue
        hosts_by_source[spec.name] = hosts
        logger.info("%s: %d hosts (%d distinct)", spec.name, len(hosts), len(set(hosts)))

    corpus = build_corpus(hosts_by_source, {spec.name: spec.cap for spec in PHISHING_SOURCES})
    used = {source for _, source in corpus}
    if len(used) < MIN_SOURCES or len(corpus) < MIN_HOSTS:
        logger.error("Only %d phishing hosts from %d feeds (%s) — need %d from at least %d; too "
                     "lopsided to retrain safely, keeping the previous corpus", len(corpus), len(used),
                     ", ".join(sorted(used)) or "none", MIN_HOSTS, MIN_SOURCES)
        return 2
    out = os.path.join(_DATA, "phishtank.csv")
    tmp = out + ".tmp"
    with open(tmp, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url", "source"])
        for host, source in corpus:
            w.writerow([f"https://{host}/", source])
    os.replace(tmp, out)
    mix = {name: sum(1 for _, s in corpus if s == name) for name in sorted(used)}
    logger.info("Wrote %s (%d hosts: %s)", out, len(corpus), mix)
    return 0


def parse_majestic(text: str) -> list[tuple[int, str]]:
    """majestic_million.csv → (GlobalRank, Domain) rows. Domain is the ASCII
    (punycode) form; IDN_Domain, the Unicode one, is not read. A file
    without those columns raises — an error page is a dead list."""
    reader = csv.DictReader(text.splitlines())
    if not {"GlobalRank", "Domain"} <= set(reader.fieldnames or ()):
        raise ValueError(f"not the Majestic Million CSV (columns {reader.fieldnames})")
    rows = []
    for row in reader:
        domain = _clean(row["Domain"] or "")
        try:
            rank = int(row["GlobalRank"])
        except (TypeError, ValueError):
            continue
        if "." in domain and "/" not in domain:
            rows.append((rank, domain))
    return rows


def parse_crux(text: str) -> list[tuple[int, str]]:
    """crux-top-lists `origin,rank` → (rank, host). The rank is CrUX's
    bucket (1000, 5000, 10000 …), the host the origin's: the scheme and any
    port are dropped, so https://www.example.com and http://www.example.com
    are one host."""
    reader = csv.DictReader(text.splitlines())
    if not {"origin", "rank"} <= set(reader.fieldnames or ()):
        raise ValueError(f"not a CrUX top list (columns {reader.fieldnames})")
    rows = []
    for row in reader:
        try:
            host = urlparse(row["origin"] or "").hostname
            rank = int(row["rank"])
        except (TypeError, ValueError):
            continue
        if host and "." in host:
            rows.append((rank, _clean(host)))
    return rows


def crux_months(today: datetime.date, back: int = CRUX_MONTHS_BACK) -> list[str]:
    """YYYYMM of the last `back` full months, newest first."""
    out = []
    year, month = today.year, today.month
    for _ in range(back):
        year, month = (year, month - 1) if month > 1 else (year - 1, 12)
        out.append(f"{year}{month:02d}")
    return out


def fetch_crux(scope: str, today: Optional[datetime.date] = None) -> tuple[str, list[tuple[int, str]]]:
    """(month, rows) of the newest published month of one CrUX scope. A
    missing month (404) tries the one before; anything else raises."""
    for month in crux_months(today or datetime.date.today()):
        url = CRUX.format(scope=scope, month=month)
        try:
            body = _get(url)
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                continue
            raise
        return month, parse_crux(gzip.decompress(body).decode("utf-8", "ignore"))
    raise FileNotFoundError(f"no CrUX {scope} list in the last {CRUX_MONTHS_BACK} months")


def registrable_rows(rows: Iterable[tuple[int, str]]) -> list[tuple[int, str]]:
    """(rank, host) → (rank, registrable domain), the scorer's reading
    (www.gosuslugi.ru → gosuslugi.ru, kvs.gov.spb.ru → gov.spb.ru). Hosting
    tenants are left out: foo.github.io is not github.io's popularity, and
    tenants are the host list's own stratum."""
    if _ROOT not in sys.path:
        sys.path.insert(0, _ROOT)
    from api.services.ml_features import shared_tenant
    from api.services.scoring import registrable_domain

    return [(rank, registrable_domain(host)) for rank, host in rows if not shared_tenant(host)[0]]


def merge_ranked(*lists: Iterable[tuple[int, str]]) -> list[tuple[int, str]]:
    """One row per host, at its best rank; sorted by rank, then host."""
    best: dict[str, int] = {}
    for rows in lists:
        for rank, host in rows:
            if rank < best.get(host, rank + 1):
                best[host] = rank
    return sorted(((rank, host) for host, rank in best.items()))


def _write_ranked(rows: list[tuple[int, str]], filename: str) -> None:
    out = os.path.join(_DATA, filename)
    tmp = out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.writelines(f"{rank},{host}\n" for rank, host in rows)
    os.replace(tmp, out)
    logger.info("Wrote %s (%d rows)", out, len(rows))


def refresh_benign() -> int:
    # Both files or neither: a retrain without the host list would quietly
    # go back to flagging every host that has a subdomain, and one without
    # the Russian list to flagging names under regional zones.
    try:
        domains = parse_majestic(_get(MAJESTIC, timeout=300.0).decode("utf-8", "ignore"))
        if len(domains) < MIN_BENIGN_DOMAINS:
            raise ValueError(f"Majestic Million: {len(domains)} rows, need {MIN_BENIGN_DOMAINS}")
        crux: dict[str, list[tuple[int, str]]] = {}
        for scope, minimum in CRUX_SCOPES.items():
            month, rows = fetch_crux(scope)
            if len(rows) < minimum:
                raise ValueError(f"CrUX {scope} {month}: {len(rows)} origins, need {minimum}")
            logger.info("CrUX %s %s: %d origins", scope, month, len(rows))
            crux[scope] = rows
        domains = merge_ranked(domains, *(registrable_rows(crux[s]) for s in CRUX_DOMAIN_SCOPES))
    except Exception as e:  # noqa: BLE001 — any failure keeps the previous files
        logger.error("Benign list refresh failed, keeping the previous files: %s", e)
        return 2
    _write_ranked(domains, BENIGN_DOMAINS)
    _write_ranked(merge_ranked(*crux.values()), BENIGN_HOSTS)
    return 0


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--phishing-only", action="store_true")
    args = p.parse_args()
    rc = refresh_phishing()
    if rc:
        return rc
    if not args.phishing_only:
        rc = refresh_benign()
    return rc


if __name__ == "__main__":
    sys.exit(main())

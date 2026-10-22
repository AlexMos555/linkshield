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

Writes (all gitignored — regenerated each run):
  data/phishtank.csv  — phishing corpus: 'url' (https://<host>/) and 'source'
                        columns. Name kept for train_model.py compatibility.
  data/top-1m.csv     — Tranco top-1M (benign corpus).
  data/top-1m-subdomains.csv — Tranco top-1M with subdomains: the benign
                        host shapes (www.example.com, kvs.gov.spb.ru-style
                        names) the default list folds into their registrable
                        domain. See ml/train_model.load_benign_domains.

Refusal (exit 2, previous files untouched): fewer than MIN_SOURCES feeds
readable, or fewer than MIN_HOSTS hosts in all. In retrain-ml.yml that stops
the job before the commit step, so production keeps the last good model
instead of one trained on a lopsided corpus.

Usage:
    python scripts/refresh_training_feeds.py
    python scripts/refresh_training_feeds.py --phishing-only
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import random
import sys
import zipfile
from typing import Callable, Iterable, NamedTuple
from urllib.parse import urlparse

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("training-feeds")

_DATA = os.path.join(os.path.dirname(__file__), "..", "data")
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"
TRANCO_SUBDOMAINS = "https://tranco-list.eu/top-1m-incl-subdomains.csv.zip"

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


def _refresh_tranco(url: str, filename: str) -> int:
    try:
        raw = _get(url)
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            member = next(m for m in zf.namelist() if m.endswith(".csv"))
            data = zf.read(member).decode("utf-8", "ignore")
        out = os.path.join(_DATA, filename)
        with open(out, "w") as f:
            f.write(data)
        logger.info("Wrote %s (%d bytes)", out, len(data))
        return 0
    except Exception as e:  # noqa: BLE001
        logger.error("Tranco fetch failed (%s): %s", url, e)
        return 2


def refresh_benign() -> int:
    # Both lists or neither: a retrain without the subdomain list would
    # quietly go back to flagging every host that has a subdomain.
    return _refresh_tranco(TRANCO, "top-1m.csv") or _refresh_tranco(TRANCO_SUBDOMAINS, "top-1m-subdomains.csv")


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

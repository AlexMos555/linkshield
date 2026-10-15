"""Per-platform phishing prior for the model's platform_abuse_rate feature.

For every hosting or dynamic-DNS platform (ml_features.platform_of):

    rate = (phishing hosts on it + SMOOTHING * prior) / (its tenants in the Tranco top-1M + SMOOTHING)

prior = all phishing hosts on platforms / all Tranco tenants of platforms.
A platform the lists know nothing about gets the prior (DEFAULT in the
file), not 0: "no phishing on record" is not "clean", and a model trained
on 0 for every unrecorded platform learned to clear their tenants
(secure-login.wasmer.app 0.05). A platform with thousands of popular
tenants and no phishing (cloudfront.net) goes to ~0.

Sources: the training feed (data/phishtank.csv: URLhaus + OpenPhish, from
scripts/refresh_training_feeds.py) plus any extra phishing feeds given (a
'url' CSV or one URL per line) — the training feed is mostly malware on IP
addresses and carries few hosting tenants; and the Tranco list with
subdomains (data/top-1m-subdomains.csv), where a platform's popular
customers' sites are. Hosts are counted once, and a host whose registrable
domain is held out (ml/train_model.HELD_OUT_FILES) counts in neither.

Written to data/platform_abuse_rates.json, which the served model reads
(api.services.ml_features): the file and the model are one artifact.
ml/train_model.py uses the committed file as it is and records its sha256
in data/model_meta.json; it computes the file itself (training feed only)
when the file is missing or with --refresh-platform-rates, so a retrain
that commits only the model never serves rates it was not trained on.

Usage:
    python scripts/refresh_platform_abuse_rates.py [--extra-feed FILE ...]
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import sys
from typing import Iterable, Optional
from urllib.parse import urlparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from api.services.ml_features import PLATFORM_ABUSE_RATES_PATH, platform_of  # noqa: E402
from api.services.scoring import registrable_domain  # noqa: E402

DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
# Pseudo-tenants each platform starts with at the pooled rate: one phishing
# host on a platform with no ranked tenant moves it a tenth of the way.
SMOOTHING = 10


def _host(url: str) -> Optional[str]:
    url = url.strip()
    if not url:
        return None
    try:
        host = urlparse(url if "://" in url else "http://" + url).hostname
    except ValueError:
        return None
    return host.lower().strip(".") if host else None


_TWEETFEED_TAGS = ("#phishing", "#scam")


def _tweetfeed_urls(rows: Iterable[list[str]]) -> Iterable[str]:
    """TweetFeed's 'date,user,type,value,tags,tweet' rows: the URLs and
    domains reported as phishing or scam."""
    for row in rows:
        if len(row) >= 5 and row[2] in ("url", "domain") and any(t in row[4].lower() for t in _TWEETFEED_TAGS):
            yield row[3]


def feed_hosts(path: str) -> list[str]:
    """The unique hostnames of a feed: a CSV with a 'url' column
    (data/phishtank.csv; gzip allowed), TweetFeed's CSV (phishing and scam
    reports only) or one URL a line (phishunt.io, OpenPhish)."""
    import gzip

    opener = gzip.open if path.endswith(".gz") else open
    seen: dict[str, None] = {}
    with opener(path, "rt", encoding="utf-8", errors="ignore") as f:
        first = f.readline()
        f.seek(0)
        head = next(csv.reader([first]), [])
        if "url" in [c.strip().lower() for c in head]:
            urls = (row.get("url", "") for row in csv.DictReader(f))
        elif len(head) >= 5 and head[2] in ("url", "domain", "ip", "md5", "sha256"):
            urls = _tweetfeed_urls(csv.reader(f))
        else:
            urls = (line for line in f)
        for url in urls:
            host = _host(url)
            if host:
                seen.setdefault(host, None)
    return list(seen)


def tranco_hosts(path: str) -> list[str]:
    """The hosts of a Tranco '<rank>,<host>' list."""
    out = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = line.strip().split(",", 1)
            if len(parts) == 2 and parts[0].isdigit():
                out.append(parts[1].lower().strip("."))
    return out


def host_key(host: str) -> str:
    """How the file names a counted phishing host: a hash, so the file does
    not republish the feeds."""
    return hashlib.sha256(host.encode("utf-8")).hexdigest()[:12]


def platform_hosts(hosts: Iterable[str], held_out: frozenset[str] = frozenset()) -> dict[str, list[str]]:
    """Unique hosts per platform; held-out registrable domains skipped."""
    out: dict[str, set[str]] = {}
    for host in set(hosts):
        platform = platform_of(host)
        if platform and registrable_domain(host) not in held_out:
            out.setdefault(platform, set()).add(host)
    return {p: sorted(h) for p, h in sorted(out.items())}


def compute(phishing: Iterable[str], benign: Iterable[str], held_out: frozenset[str] = frozenset(),
            smoothing: int = SMOOTHING) -> dict:
    """The file's content: rates, the prior, [phishing, tranco] counts and
    the counted phishing hosts' keys, for every platform in either list."""
    phish = platform_hosts(phishing, held_out)
    tranco = {p: len(h) for p, h in platform_hosts(benign, held_out).items()}
    n_phish, n_tranco = sum(map(len, phish.values())), sum(tranco.values())
    prior = n_phish / n_tranco if n_tranco else 0.0
    platforms = sorted(set(phish) | set(tranco))
    counts = {p: [len(phish.get(p, ())), tranco.get(p, 0)] for p in platforms}
    rates = {p: round((ph + smoothing * prior) / (tr + smoothing), 4) for p, (ph, tr) in counts.items()}
    return {
        "_meta": {
            "formula": f"(phishing hosts on the platform + {smoothing} * prior) / "
                       f"(its tenants in the Tranco top-1M + {smoothing})",
            "smoothing": smoothing,
            "prior": prior,
        },
        "default": round(prior, 4),
        "rates": rates,
        "counts_phishing_tranco": counts,
        "phishing_host_keys": {p: sorted(host_key(h) for h in hs) for p, hs in phish.items()},
    }


def write(doc: dict, path: str = PLATFORM_ABUSE_RATES_PATH, sources: Optional[dict] = None) -> None:
    doc["_meta"] = {
        "what": "Per-platform phishing prior: the model's platform_abuse_rate feature "
                "(api/services/ml_features.py), written by ml/platform_abuse_rates.py. The served "
                "model was trained on these values (data/model_meta.json platform_abuse_rates_sha256): "
                "refresh the file only together with a retrain. 'default' is the rate of a platform "
                "neither list mentions.",
        **doc["_meta"],
        "generated": dt.date.today().isoformat(),
        "sources": sources or {},
        "platforms": len(doc["rates"]),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")


def leave_one_out(host: str, doc: dict) -> Optional[float]:
    """The rate of `host`'s platform with `host` itself not counted, when it
    is one of the phishing hosts the file counted; None otherwise.

    Training needs it: every phishing tenant in the feed is counted in its
    own platform's rate, so in training a platform's first phishing host
    would always lift its own rate. Served hosts are new, so serving uses
    the plain rate.
    """
    platform = platform_of(host)
    if not platform or host_key(host) not in set(doc.get("phishing_host_keys", {}).get(platform, ())):
        return None
    n_phish, n_tranco = doc["counts_phishing_tranco"][platform]
    meta = doc["_meta"]
    return round((n_phish - 1 + meta["smoothing"] * meta["prior"]) / (n_tranco + meta["smoothing"]), 4)


def load(path: str = PLATFORM_ABUSE_RATES_PATH) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def file_sha256(path: str = PLATFORM_ABUSE_RATES_PATH) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def refresh(data_dir: str = DATA_DIR, held_out: frozenset[str] = frozenset(),
            path: str = PLATFORM_ABUSE_RATES_PATH, extra_feeds: Iterable[str] = ()) -> dict:
    """Compute from the training feeds in data_dir (plus extra_feeds) and
    write the file."""
    phish = feed_hosts(os.path.join(data_dir, "phishtank.csv"))
    sources = {"data/phishtank.csv": len(phish)}
    for feed in extra_feeds:
        hosts = feed_hosts(feed)
        sources[os.path.basename(feed)] = len(hosts)
        phish += hosts
    benign = tranco_hosts(os.path.join(data_dir, "top-1m-subdomains.csv"))
    doc = compute(phish, benign, held_out)
    write(doc, path, sources={
        "phishing_hosts_per_feed": sources,
        "benign": f"data/top-1m-subdomains.csv ({len(benign)} hosts)",
        "held_out_registrable_domains": len(held_out),
    })
    return doc


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--extra-feed", action="append", default=[], metavar="FILE",
                    help="another phishing feed: a 'url' CSV (gzip allowed) or one URL a line")
    args = ap.parse_args(argv)
    # The evaluation sets stay out of the counts, as they do out of training.
    sys.path.insert(0, os.path.dirname(__file__))
    from train_model import load_held_out

    doc = refresh(held_out=load_held_out(), extra_feeds=args.extra_feed)
    top = sorted(doc["rates"].items(), key=lambda kv: -kv[1])[:15]
    print(f"{len(doc['rates'])} platforms, prior {doc['default']}; highest: {top}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

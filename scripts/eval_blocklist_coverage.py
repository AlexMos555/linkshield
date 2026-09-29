#!/usr/bin/env python3
"""Measure what the phone's blocklist actually covers — on a HELD-OUT feed.

Measuring the list against the feeds that build it is circular: it would
report ~100% and mean nothing. This script scores an artifact against a
held-out sample and reports two numbers we are allowed to say out loud:

  * coverage — share of held-out phishing HOSTNAMES the list blocks, using the
    phone's exact matching rule (a listed name blocks itself and all its
    subdomains);
  * blockable — share of those hostnames a domain blocklist could cover at
    all. Phishing on shared hosting (sites.google.com/…, *.blogspot.com,
    IP-literal URLs) is invisible to DNS-level blocking by design, and a
    coverage number that hides that is dishonest arithmetic.

It also runs the false-positive side: how many Tranco top-10k names the list
matches (must be exactly 0).

Held-out sets (scripts/heldout_sets.py):
  phishtank  PhishTank online-valid (default). Held out as long as PhishTank
             is not a source — it becomes one the day PHISHTANK_API_KEY is
             set on the refresh job (api/services/phishtank_feed.py), and
             this number becomes circular. Anonymous pulls are throttled
             (HTTP 404): pass --sample-file to score several artifacts
             against ONE pull.
  tweetfeed  TweetFeed year.csv, --days 30 for the "independent 30-day
             sample" of the 2026-09-25 report. TweetFeed has been a SOURCE
             of the list since 2026-09-26 (#47), so against an artifact
             built with it this number is circular — the report says so.
             scripts/eval_day_one_coverage.py builds artifacts without it.

--days N keeps only hosts the held-out source first reported within N days
of its newest report (0 = every host): "fresh phishing", not the long tail.

Usage:
    python3 scripts/eval_blocklist_coverage.py                 # live artifact
    python3 scripts/eval_blocklist_coverage.py --limit 2000
    python3 scripts/eval_blocklist_coverage.py --artifact path/to/list.bin
    python3 scripts/eval_blocklist_coverage.py --held-out tweetfeed --days 30
    python3 scripts/eval_blocklist_coverage.py --sample-file online-valid.csv.gz --artifact a.bin

Writes docs/benchmarks/blocklist-coverage-<YYYY-MM-DD>.json. No secrets.
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import heldout_sets as ho  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("blocklist-coverage")

DEFAULT_ARTIFACT_URL = "https://api.cleanway.ai/api/v1/blocklist/dns"
PHISHTANK_URL = ho.PHISHTANK_ONLINE_VALID_URL
OUT_DIR = ROOT / "docs" / "benchmarks"

HELD_OUT = {
    "phishtank": (PHISHTANK_URL, ho.phishtank_reports, "phishtank_online_valid"),
    "tweetfeed": (ho.TWEETFEED_YEAR_URL, ho.tweetfeed_reports, "tweetfeed_year_csv"),
}
NOTES = {
    "phishtank": ("Coverage is measured against a feed that does not build the list (PhishTank, as long as "
                  "PHISHTANK_API_KEY is not set on the refresh job), so it is not circular."),
    "tweetfeed": ("TweetFeed year.csv has been a SOURCE of the published list since 2026-09-26 (#47): against an "
                  "artifact built with it this number is circular. It is honest only for an artifact built with "
                  "BLOCKLIST_EXCLUDE_FEEDS=TweetFeed (scripts/eval_day_one_coverage.py)."),
}
BLOCKABLE_NOTE = ("'blockable' excludes IP-literal URLs and phishing on shared hosting, which domain-level DNS "
                  "blocking cannot cover by design.")


def fetch(url: str, timeout: float = 90.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Cleanway-benchmark/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def load_artifact(source: str) -> set[int]:
    return ho.load_artifact(source, fetch=fetch)


def held_out_hosts(name: str, limit: int, days: float, sample_file: str | None) -> tuple[list[str], float]:
    """(hosts, as_of): the newest `limit` hosts first reported within `days`
    of the sample's newest report."""
    url, parse, _ = HELD_OUT[name]
    body = Path(sample_file).read_bytes() if sample_file else fetch(url)
    reports = parse(ho.decompress(body))
    as_of = ho.newest_report(reports)
    if as_of is None:
        return [], 0.0
    return ho.fresh_within(reports, days, as_of)[:limit], as_of


def phishtank_hosts(limit: int) -> list[str]:
    """Held-out: PhishTank verified-online. Anonymous download."""
    return held_out_hosts("phishtank", limit, 0, None)[0]


def matches(hashes: set[int], host: str) -> bool:
    """The phone's rule (BlockList.match): a listed name covers itself and all
    its subdomains — evaluated over hashes, exactly as the phone does it."""
    return ho.artifact_covers(hashes, host)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", default=DEFAULT_ARTIFACT_URL)
    ap.add_argument("--limit", type=int, default=3000, help="held-out hostnames to score")
    ap.add_argument("--held-out", choices=sorted(HELD_OUT), default="phishtank")
    ap.add_argument("--days", type=float, default=0, help="only hosts first reported within N days (0 = all)")
    ap.add_argument("--sample-file", default=None, help="a saved copy of the held-out feed (csv or csv.gz)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    names = load_artifact(args.artifact)
    log.info("artifact: %d names", len(names))
    if not names:
        log.error("empty artifact — refusing to report a number")
        return 2

    try:
        hosts, as_of = held_out_hosts(args.held_out, args.limit, args.days, args.sample_file)
    except Exception as exc:  # noqa: BLE001
        log.error("held-out feed unavailable (%s) — NOT falling back to our own "
                  "feeds; a circular number is worse than no number", exc)
        return 3
    if not hosts:
        log.error("held-out feed returned nothing")
        return 3
    log.info("held-out sample: %d hostnames from %s%s", len(hosts), args.held_out,
             f" (first reported within {args.days:g} days of {time.strftime('%Y-%m-%d', time.gmtime(as_of))})"
             if args.days else "")

    stats = ho.coverage(names, hosts, ho.load_shared_suffixes())
    fp = ho.false_positives(names)

    result = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifact_source": args.artifact,
        "artifact_names": len(names),
        "held_out_feed": HELD_OUT[args.held_out][2],
        "freshness_days": args.days or None,
        "as_of": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(as_of)),
        "sample_hostnames": stats["hostnames"],
        "coverage_all_pct": stats["coverage_all_pct"],
        "coverage_blockable_pct": stats["coverage_blockable_pct"],
        "blockable_hostnames": stats["blockable_hostnames"],
        "ip_literal_hostnames": stats["ip_literal_hostnames"],
        "shared_hosting_hostnames": stats["shared_hosting_hostnames"],
        "false_positives_top10k": len(fp),
        "false_positive_examples": fp[:10],
        "note": f"{NOTES[args.held_out]} {BLOCKABLE_NOTE}",
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = Path(args.out) if args.out else OUT_DIR / f"blocklist-coverage-{time.strftime('%Y-%m-%d')}.json"
    out_path.write_text(ho.json.dumps(result, indent=2) + "\n")

    log.info("coverage (all hostnames):        %.1f%%  (%d/%d)", result["coverage_all_pct"], stats["hit"],
             stats["hostnames"])
    if result["coverage_blockable_pct"] is not None:
        log.info("coverage (DNS-blockable only):   %.1f%%  (%d/%d)",
                 result["coverage_blockable_pct"], stats["hit_blockable"], stats["blockable_hostnames"])
    log.info("out of scope: %d IP-literal, %d on shared hosting", stats["ip_literal_hostnames"],
             stats["shared_hosting_hostnames"])
    log.info("false positives in Tranco top-10k: %d %s", len(fp), fp[:5])
    try:
        where = out_path.relative_to(ROOT)
    except ValueError:  # --out outside the repo: report the absolute path
        where = out_path
    log.info("wrote %s", where)
    return 1 if fp else 0


if __name__ == "__main__":
    sys.exit(main())

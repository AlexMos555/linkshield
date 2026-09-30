#!/usr/bin/env python3
"""The honest coverage number: what share of FRESH phishing sites the
phone's list blocks on day one — with and without the non-commercial feeds.

Why a separate script: the published "80–93 %" was measured on a PhishTank
sample the list reaches through phishing.army, which is built from
PhishTank (2026-09-21, 2026-09-25 reports), and the "independent" TweetFeed
number was measured after TweetFeed became a source. Neither says what a
person who taps a link reported today gets. This script does, and says
which of its numbers are circular.

What it does, from ONE snapshot of every feed (so every build sees the same
bytes — feeds move by the minute):

  1. builds the phone artifact four times with scripts/refresh_dangerous_domains.py
     in dry-run (no Redis: no retention, no Tranco-1M guard — the same
     conditions for every variant):
       all                      every feed, as published today
       licensed                 BLOCKLIST_LICENSED_ONLY: without URLhaus,
                                OpenPhish, phishing.army
       all-minus-tweetfeed      as `all`, without TweetFeed
       licensed-minus-tweetfeed as `licensed`, without TweetFeed
  2. scores each against two held-out samples, in freshness windows
     (hosts the source FIRST reported within 1, 7 and 30 days of its newest
     report):
       PhishTank online-valid   held out today; circular the day
                                PHISHTANK_API_KEY makes it a source
       TweetFeed year.csv       a source since 2026-09-26 — honest only for
                                the *-minus-tweetfeed variants, and marked
                                `circular` for the others
  3. writes one JSON (schema `cleanway.day-one-coverage/1`) the methodology
     page can read later: `headline` holds the two honest day-one numbers
     per variant; everything else is the working.

Every number uses the phone's rule (scripts/heldout_sets.coverage): a listed
name blocks itself and every subdomain; IP-literal URLs and one tenant's
page on shared hosting are counted as not blockable by a domain list.

Usage:
    python3 scripts/eval_day_one_coverage.py --snapshot-dir /tmp/feeds
    python3 scripts/eval_day_one_coverage.py --snapshot-dir /tmp/feeds --days 1,7,30 \
        --out docs/benchmarks/day-one-coverage-2026-09-29.json --latest

The snapshot directory is filled on first use (every feed body, the PSL,
the CSIRT events, the PhishTank dump) and reused afterwards, so a re-run
scores the same sample. PhishTank throttles anonymous pulls with HTTP 404:
one pull a session, cached here, is the polite way.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import logging
import sys
import time
from pathlib import Path
from typing import Callable, Optional

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import heldout_sets as ho  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("day-one-coverage")

SCHEMA = "cleanway.day-one-coverage/1"
OUT_DIR = ROOT / "docs" / "benchmarks"
DEFAULT_DAYS = (1, 7, 30)
PHISHTANK_DUMP = "phishtank-online-valid.csv.gz"
# The dump the refresh job downloads with PHISHTANK_API_KEY, when the key is
# set for the benchmark too: one download for every build, kept under a
# fixed name because the URL that fetched it carries the key.
PHISHTANK_KEYED_DUMP = "phishtank-keyed-online-valid.csv.gz"
SNAPSHOT_EXTRAS = frozenset({PHISHTANK_DUMP, PHISHTANK_KEYED_DUMP})
QUESTION = ("Of the phishing hosts a held-out source first reported within the last N days, what share does "
            "the phone's blocklist block on that day? A listed name blocks itself and every subdomain; "
            "IP-literal URLs and one tenant's page on shared hosting cannot be blocked by a domain list and "
            "are reported apart.")


def _load_refresh_module():
    spec = importlib.util.spec_from_file_location("refresh_dangerous_domains",
                                                  ROOT / "scripts" / "refresh_dangerous_domains.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def variants(rdd) -> dict[str, frozenset]:
    """Variant name -> feeds left out of its build."""
    nc = frozenset(rdd.NON_COMMERCIAL_FEEDS)
    return {
        "all": frozenset(),
        "licensed": nc,
        "all-minus-tweetfeed": frozenset({"TweetFeed"}),
        "licensed-minus-tweetfeed": nc | {"TweetFeed"},
    }


# ── Snapshot ─────────────────────────────────────────────────────────────────


class Snapshot:
    """Every URL the refresh job fetches, kept on disk as <sha1(url)>.body so
    a second run, or a second script, reads the same bytes."""

    def __init__(self, directory: Path) -> None:
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self.index_path = self.dir / "index.json"
        self.index: dict[str, str] = json.loads(self.index_path.read_text()) if self.index_path.exists() else {}

    def path_for(self, url: str) -> Path:
        return self.dir / (hashlib.sha1(url.encode("utf-8")).hexdigest() + ".body")

    def fetcher(self, real: Callable) -> Callable:
        async def _fetch(url: str) -> str:
            path = self.path_for(url)
            if path.exists():
                return path.read_text(encoding="utf-8")
            text = await real(url)
            path.write_text(text, encoding="utf-8")
            self.index[path.name] = url
            self.index_path.write_text(json.dumps(self.index, indent=1))
            log.info("snapshot: fetched %s (%d chars)", url, len(text))
            return text
        return _fetch

    async def phishtank_dump(self) -> bytes:
        path = self.dir / PHISHTANK_DUMP
        if path.exists():
            return path.read_bytes()
        async with httpx.AsyncClient(timeout=120.0, follow_redirects=True,
                                     headers={"User-Agent": "Cleanway-benchmark/1.0"}) as client:
            r = await client.get(ho.PHISHTANK_ONLINE_VALID_URL)
            r.raise_for_status()
        path.write_bytes(r.content)
        log.info("snapshot: fetched the PhishTank dump (%d bytes)", len(r.content))
        return r.content

    def conditional_fetcher(self, real: Callable) -> Callable:
        """The refresh job's conditional GET (its keyed PhishTank download)
        through the snapshot: one download, every build reads the same
        bytes. Only the body touches the disk — the URL carries the key, so
        it is neither indexed nor logged."""
        path = self.dir / PHISHTANK_KEYED_DUMP

        async def _fetch(url: str, headers) -> tuple[int, dict, bytes]:
            if path.exists():
                return 200, {}, path.read_bytes()
            status, resp_headers, body = await real(url, headers)
            if status == 200 and body:
                path.write_bytes(body)
                log.info("snapshot: fetched the keyed PhishTank dump (%d bytes)", len(body))
            return status, dict(resp_headers), body
        return _fetch


# ── Builds ───────────────────────────────────────────────────────────────────


async def build_variants(rdd, snapshot: Snapshot, names: dict[str, frozenset]) -> dict[str, dict]:
    """name -> {excluded_feeds, feeds, names, artifact_bytes, sha256, hashes}.
    `feeds` is what the build was made from (rdd.run_sources): with
    PHISHTANK_API_KEY set, PhishTank is in it and score() marks the PhishTank
    numbers circular."""
    rdd._fetch = snapshot.fetcher(rdd._fetch)
    rdd.MISP_EVENT_PAUSE = 0
    if rdd.phishtank_key():
        rdd._fetch_conditional = snapshot.conditional_fetcher(rdd._fetch_conditional)
        log.warning("%s is set: PhishTank is a source of every build here, so its sample is circular "
                    "(held_out.phishtank.*.circular) and leaves the headline", rdd.phishtank_feed.KEY_ENV)
    out: dict[str, dict] = {}
    for name, excluded in names.items():
        path = snapshot.dir / f"artifact-{name}.bin"
        log.info("building %s (without: %s)", name, ", ".join(sorted(excluded)) or "nothing")
        code = await rdd.refresh(None, dry_run=True, artifact_out=str(path), excluded=excluded)
        if code != 0:
            raise RuntimeError(f"build {name} exited {code}")
        blob = path.read_bytes()
        hashes = ho.load_artifact(path)
        out[name] = {
            "excluded_feeds": sorted(excluded),
            "feeds": sorted(rdd.run_sources(excluded)),
            "names": len(hashes),
            "artifact_bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "hashes": hashes,
        }
    return out


# ── Scoring ──────────────────────────────────────────────────────────────────


def score(builds: dict[str, dict], samples: dict[str, list[ho.Report]], days: tuple[int, ...],
          shared: set[str], sources_of_sample: dict[str, str]) -> dict:
    """The held-out block of the report: per sample, per window, per
    variant. `sources_of_sample` names the feed each sample IS (TweetFeed,
    PhishTank) so a variant built with it is marked circular."""
    held_out: dict = {}
    for sample_name, reports in samples.items():
        as_of = ho.newest_report(reports)
        if as_of is None:
            continue
        windows: dict = {}
        for n in days:
            hosts = ho.fresh_within(reports, n, as_of)
            stats = {variant: ho.coverage(build["hashes"], hosts, shared) for variant, build in builds.items()}
            # The sample's own shape (what a domain list can cover at all)
            # does not depend on the variant.
            shape = next(iter(stats.values()), {})
            windows[str(n)] = {
                "hostnames": len(hosts),
                "blockable_hostnames": shape.get("blockable_hostnames", 0),
                "ip_literal_hostnames": shape.get("ip_literal_hostnames", 0),
                "shared_hosting_hostnames": shape.get("shared_hosting_hostnames", 0),
                "coverage": {
                    variant: {
                        "coverage_all_pct": s["coverage_all_pct"],
                        "coverage_blockable_pct": s["coverage_blockable_pct"],
                        "hit": s["hit"],
                        "hit_blockable": s["hit_blockable"],
                        "circular": sources_of_sample.get(sample_name) in builds[variant]["feeds"],
                    }
                    for variant, s in stats.items()
                },
            }
        held_out[sample_name] = {
            "reports": len(reports),
            "distinct_hosts": len(ho.first_seen(reports)),
            "as_of": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(as_of)),
            "windows": windows,
        }
    return held_out


def headline(held_out: dict, day: str = "1") -> dict:
    """The day-one numbers that are not circular, per sample and variant."""
    out: dict = {}
    for sample_name, block in held_out.items():
        window = block.get("windows", {}).get(day)
        if not window:
            continue
        honest = {v: c["coverage_all_pct"] for v, c in window["coverage"].items() if not c["circular"]}
        if honest:
            out[sample_name] = {"days": int(day), "hostnames": window["hostnames"], "coverage_all_pct": honest}
    return out


def snapshot_fingerprint(snapshot: "Snapshot") -> dict:
    """Which bytes were scored: a digest over every cached body, so two
    reports from the same snapshot can be told from two snapshots."""
    digest = hashlib.sha256()
    bodies = sorted(p for p in snapshot.dir.iterdir() if p.suffix == ".body" or p.name in SNAPSHOT_EXTRAS)
    for path in bodies:
        digest.update(path.name.encode("ascii"))
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return {"bodies": len(bodies), "sha256": digest.hexdigest()}


def assemble(builds: dict[str, dict], held_out: dict, days: tuple[int, ...], snapshot: dict,
             generated_at: Optional[str] = None) -> dict:
    return {
        "schema": SCHEMA,
        "generated_at": generated_at or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "question": QUESTION,
        "freshness_days": list(days),
        "feed_snapshot": snapshot,
        "build": ("scripts/refresh_dangerous_domains.py --dry-run --artifact-out, no Redis (no retention, no "
                  "Tranco-1M guard), every variant on one feed snapshot; variants differ only in `excluded`"),
        "variants": {name: {k: v for k, v in b.items() if k != "hashes"} for name, b in builds.items()},
        "held_out": held_out,
        "headline": headline(held_out),
        "notes": [
            "PhishTank is held out only while PHISHTANK_API_KEY is unset on the refresh job; with it set, "
            "PhishTank is a source and its numbers here are circular.",
            "TweetFeed year.csv is a source since 2026-09-26 (#47): its numbers are honest only for the "
            "*-minus-tweetfeed variants (marked circular=false).",
            "phishing.army is built from PhishTank, OpenPhish, CERT.pl, PhishFindR, urlscan and Phishunt, so the "
            "`all` variant's PhishTank number is inflated by that path; `licensed` has no such path.",
            "A dry-run build has no retention window: the published list also keeps names for 14 days after "
            "their feeds drop them, which helps older windows, not day one.",
        ],
    }


# ── Main ─────────────────────────────────────────────────────────────────────


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--snapshot-dir", required=True, type=Path)
    ap.add_argument("--days", default=",".join(str(d) for d in DEFAULT_DAYS))
    ap.add_argument("--out", type=Path, default=None,
                    help=f"default {OUT_DIR}/day-one-coverage-<YYYY-MM-DD>.json")
    ap.add_argument("--latest", action="store_true", help="also write day-one-coverage-latest.json")
    args = ap.parse_args()
    days = tuple(int(d) for d in args.days.split(",") if d.strip())

    rdd = _load_refresh_module()
    snapshot = Snapshot(args.snapshot_dir)
    builds = await build_variants(rdd, snapshot, variants(rdd))
    for name, build in builds.items():
        fp = ho.false_positives(build["hashes"])
        build["false_positives_top10k"] = len(fp)
        build["false_positive_examples"] = fp[:10]
        log.info("%-26s %7d names %9d bytes  top-10k false positives: %d", name, build["names"],
                 build["artifact_bytes"], len(fp))

    samples = {
        "phishtank": ho.phishtank_reports(ho.decompress(await snapshot.phishtank_dump())),
        "tweetfeed": ho.tweetfeed_reports(snapshot.path_for(rdd.TWEETFEED_YEAR).read_text(encoding="utf-8")),
    }
    held_out = score(builds, samples, days, ho.load_shared_suffixes(),
                     {"phishtank": rdd.phishtank_feed.SOURCE_NAME, "tweetfeed": "TweetFeed"})
    report = assemble(builds, held_out, days, snapshot_fingerprint(snapshot))

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = args.out or OUT_DIR / f"day-one-coverage-{time.strftime('%Y-%m-%d')}.json"
    out.write_text(json.dumps(report, indent=2) + "\n")
    log.info("wrote %s", out)
    if args.latest:
        latest = out.parent / "day-one-coverage-latest.json"
        latest.write_text(json.dumps(report, indent=2) + "\n")
        log.info("wrote %s", latest)

    for sample_name, block in held_out.items():
        for n, window in block["windows"].items():
            line = "  ".join(f"{v}={c['coverage_all_pct']}%{'*' if c['circular'] else ''}"
                             for v, c in window["coverage"].items())
            log.info("%-9s %3s d  %5d hosts  %s", sample_name, n, window["hostnames"], line)
    log.info("* = circular (the sample is a source of that build)")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

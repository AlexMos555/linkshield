#!/usr/bin/env python3
"""Measure what the phone's blocklist actually covers — on a HELD-OUT feed.

The published list is built from URLhaus (online) + OpenPhish. Measuring it
against those feeds is circular: it would report ~100% and mean nothing. This
script scores the published artifact against PhishTank's verified-online dump,
which feeds nothing we publish, and reports two numbers we are allowed to say
out loud:

  * coverage — share of held-out phishing HOSTNAMES the list blocks, using the
    phone's exact matching rule (a listed name blocks itself and all its
    subdomains);
  * blockable — share of those hostnames a domain blocklist could cover at
    all. Phishing on shared hosting (sites.google.com/…, *.blogspot.com,
    IP-literal URLs) is invisible to DNS-level blocking by design, and a
    coverage number that hides that is dishonest arithmetic.

It also runs the false-positive side: how many Tranco top-10k names the list
matches (must be exactly 0).

Usage:
    python3 scripts/eval_blocklist_coverage.py                 # live artifact
    python3 scripts/eval_blocklist_coverage.py --limit 2000
    python3 scripts/eval_blocklist_coverage.py --artifact path/to/list.txt

Writes docs/benchmarks/blocklist-coverage-<YYYY-MM-DD>.json. No secrets.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import logging
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from api.services.blocklist_artifact import (  # noqa: E402
    LIST_CANARY, artifact_covers, name_hash, parse_artifact_v2,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("blocklist-coverage")

DEFAULT_ARTIFACT_URL = "https://api.cleanway.ai/api/v1/blocklist/dns"
PHISHTANK_URL = "https://data.phishtank.com/data/online-valid.csv.gz"
OUT_DIR = ROOT / "docs" / "benchmarks"


def fetch(url: str, timeout: float = 90.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "Cleanway-benchmark/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def load_artifact(source: str) -> set[int]:
    """The published hashes (v2 binary)."""
    blob = Path(source).read_bytes() if not source.startswith("http") else fetch(source)
    _, hashes = parse_artifact_v2(blob)
    return set(hashes) - {name_hash(LIST_CANARY)}


def phishtank_hosts(limit: int) -> list[str]:
    """Held-out: PhishTank verified-online. Anonymous download."""
    body = fetch(PHISHTANK_URL)
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    out: list[str] = []
    reader = csv.DictReader(io.StringIO(body.decode("utf-8", "replace")))
    for row in reader:
        url = (row.get("url") or "").strip()
        if not url:
            continue
        host = (urlparse(url).hostname or "").lower().rstrip(".")
        if host:
            out.append(host)
        if len(out) >= limit:
            break
    return out


def matches(hashes: set[int], host: str) -> bool:
    """The phone's rule (BlockList.match): a listed name covers itself and all
    its subdomains — evaluated over hashes, exactly as the phone does it."""
    return artifact_covers(hashes, host)


def is_ip_literal(host: str) -> bool:
    return host.replace(".", "").isdigit() or ":" in host


def load_shared_suffixes() -> set[str]:
    try:
        return {d.lower() for d in json.loads((ROOT / "data" / "public_suffixes_in_top.json").read_text())}
    except Exception:
        return set()


def tenant_suffix(host: str, shared: set[str]) -> str | None:
    parts = host.split(".")
    for k in range(len(parts) - 1, 1, -1):
        suffix = ".".join(parts[-k:])
        if suffix in shared:
            return suffix
    return None


def top_domains(limit: int = 10_000) -> list[str]:
    try:
        raw = json.loads((ROOT / "data" / "top_10k.json").read_text())
        return list(raw.keys() if isinstance(raw, dict) else raw)[:limit]
    except Exception:
        return []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--artifact", default=DEFAULT_ARTIFACT_URL)
    ap.add_argument("--limit", type=int, default=3000, help="held-out hostnames to score")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    names = load_artifact(args.artifact)
    log.info("artifact: %d names", len(names))
    if not names:
        log.error("empty artifact — refusing to report a number")
        return 2

    try:
        hosts = phishtank_hosts(args.limit)
    except Exception as exc:  # noqa: BLE001
        log.error("held-out feed unavailable (%s) — NOT falling back to our own "
                  "feeds; a circular number is worse than no number", exc)
        return 3
    if not hosts:
        log.error("held-out feed returned nothing")
        return 3
    log.info("held-out sample: %d hostnames from PhishTank", len(hosts))

    shared = load_shared_suffixes()
    total = len(hosts)
    ip_hosts = [h for h in hosts if is_ip_literal(h)]
    tenant_hosts = [h for h in hosts if not is_ip_literal(h) and tenant_suffix(h, shared)]
    blockable = [h for h in hosts if not is_ip_literal(h) and not tenant_suffix(h, shared)]

    hit = [h for h in hosts if matches(names, h)]
    hit_blockable = [h for h in blockable if matches(names, h)]

    tops = top_domains()
    fp = [d for d in tops if matches(names, d)]

    result = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "artifact_source": args.artifact,
        "artifact_names": len(names),
        "held_out_feed": "phishtank_online_valid",
        "sample_hostnames": total,
        "coverage_all_pct": round(100.0 * len(hit) / total, 1),
        "coverage_blockable_pct": round(100.0 * len(hit_blockable) / len(blockable), 1) if blockable else None,
        "blockable_hostnames": len(blockable),
        "ip_literal_hostnames": len(ip_hosts),
        "shared_hosting_hostnames": len(tenant_hosts),
        "false_positives_top10k": len(fp),
        "false_positive_examples": fp[:10],
        "note": (
            "Coverage is measured against a feed that does not build the list "
            "(PhishTank), so it is not circular. 'blockable' excludes IP-literal "
            "URLs and phishing on shared hosting, which domain-level DNS "
            "blocking cannot cover by design."
        ),
    }

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = Path(args.out) if args.out else OUT_DIR / f"blocklist-coverage-{time.strftime('%Y-%m-%d')}.json"
    out_path.write_text(json.dumps(result, indent=2) + "\n")

    log.info("coverage (all hostnames):        %.1f%%  (%d/%d)", result["coverage_all_pct"], len(hit), total)
    if result["coverage_blockable_pct"] is not None:
        log.info("coverage (DNS-blockable only):   %.1f%%  (%d/%d)",
                 result["coverage_blockable_pct"], len(hit_blockable), len(blockable))
    log.info("out of scope: %d IP-literal, %d on shared hosting", len(ip_hosts), len(tenant_hosts))
    log.info("false positives in Tranco top-10k: %d %s", len(fp), fp[:5])
    log.info("wrote %s", out_path.relative_to(ROOT))
    return 1 if fp else 0


if __name__ == "__main__":
    sys.exit(main())

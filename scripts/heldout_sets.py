"""Held-out phishing samples for blocklist coverage, and the phone's rule.

Shared by scripts/eval_blocklist_coverage.py and
scripts/eval_day_one_coverage.py. Two sources are readable as
(host, first reported at) pairs:

  * PhishTank online-valid — the CSV dump (columns phish_id, url,
    phish_detail_url, submission_time, …; ISO 8601 times with an offset);
  * TweetFeed — year.csv (`date,user,type,value,tags,tweet`, no header,
    "YYYY-MM-DD HH:MM:SS" UTC; only `domain` and `url` rows carry a name).

"Fresh within N days" takes each host's FIRST report in the sample, so a
host re-reported every day for a month is a month old, not fresh. Coverage
uses the phone's matching rule (blocklist_artifact.artifact_covers: a listed
name blocks itself and every subdomain) over the artifact's hashes, and
separates what a domain-level list can cover at all from what it cannot
(IP-literal URLs, one tenant's page on shared hosting).
"""
from __future__ import annotations

import csv
import gzip
import io
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlparse

from api.services.blocklist_artifact import LIST_CANARY, artifact_covers, name_hash, parse_artifact_v2

ROOT = Path(__file__).resolve().parents[1]
DAY = 86_400.0

PHISHTANK_ONLINE_VALID_URL = "https://data.phishtank.com/data/online-valid.csv.gz"
TWEETFEED_YEAR_URL = "https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/year.csv"
# Attachment names TweetFeed's reporters post in the domain column.
FILENAME_TLDS = (".zip", ".mov")


@dataclass(frozen=True)
class Report:
    host: str
    seen_at: float  # unix time the source reported it


def _host_of(value: str) -> str:
    value = value.strip()
    if "://" in value:
        try:
            return (urlparse(value).hostname or "").lower().rstrip(".")
        except ValueError:
            return ""
    return value.lower().rstrip(".") if "/" not in value else ""


def _iso(text: str) -> Optional[float]:
    text = text.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        when = datetime.fromisoformat(text)
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.timestamp()


def decompress(body: bytes) -> str:
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    return body.decode("utf-8", errors="replace").lstrip("﻿")


def phishtank_reports(text: str) -> list[Report]:
    out: list[Report] = []
    for row in csv.DictReader(io.StringIO(text)):
        host = _host_of(row.get("url") or "")
        when = _iso(row.get("submission_time") or "")
        if host and when is not None:
            out.append(Report(host, when))
    return out


def tweetfeed_reports(text: str) -> list[Report]:
    out: list[Report] = []
    for row in csv.reader(io.StringIO(text)):
        if len(row) < 4:
            continue
        kind = row[2].strip().lower()
        if kind not in ("domain", "url"):
            continue
        host = _host_of(row[3])
        if not host or host.endswith(FILENAME_TLDS):
            continue
        when = _iso(row[0].strip().replace(" ", "T"))
        if when is not None:
            out.append(Report(host, when))
    return out


def first_seen(reports: Iterable[Report]) -> dict[str, float]:
    """host -> its earliest report."""
    out: dict[str, float] = {}
    for r in reports:
        if r.host not in out or r.seen_at < out[r.host]:
            out[r.host] = r.seen_at
    return out


def fresh_within(reports: Iterable[Report], days: float, as_of: float) -> list[str]:
    """Hosts first reported in the `days` before `as_of` (0 = every host),
    newest first."""
    seen = first_seen(reports)
    cutoff = as_of - days * DAY if days > 0 else float("-inf")
    return [h for h, t in sorted(seen.items(), key=lambda kv: (-kv[1], kv[0])) if t >= cutoff and t <= as_of]


def newest_report(reports: Iterable[Report]) -> Optional[float]:
    return max((r.seen_at for r in reports), default=None)


# ── The phone's rule ─────────────────────────────────────────────────────────


def load_artifact(source: str | Path, fetch=None) -> set[int]:
    """The published hashes (v2 binary) minus the canary, from a path or URL."""
    text = str(source)
    if text.startswith("http"):
        if fetch is None:
            raise ValueError("a URL needs a fetcher")
        blob = fetch(text)
    else:
        blob = Path(text).read_bytes()
    _, hashes = parse_artifact_v2(blob)
    return set(hashes) - {name_hash(LIST_CANARY)}


def is_ip_literal(host: str) -> bool:
    return host.replace(".", "").isdigit() or ":" in host


def load_shared_suffixes() -> set[str]:
    try:
        return {d.lower() for d in json.loads((ROOT / "data" / "public_suffixes_in_top.json").read_text())}
    except Exception:  # noqa: BLE001
        return set()


def tenant_suffix(host: str, shared: set[str]) -> Optional[str]:
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
    except Exception:  # noqa: BLE001
        return []


def coverage(hashes: set[int], hosts: list[str], shared: set[str]) -> dict:
    """What the list blocks of `hosts`, by the phone's rule."""
    ip_hosts = [h for h in hosts if is_ip_literal(h)]
    tenant_hosts = [h for h in hosts if not is_ip_literal(h) and tenant_suffix(h, shared)]
    blockable = [h for h in hosts if not is_ip_literal(h) and not tenant_suffix(h, shared)]
    hit = [h for h in hosts if artifact_covers(hashes, h)]
    hit_blockable = [h for h in blockable if artifact_covers(hashes, h)]
    total = len(hosts)
    return {
        "hostnames": total,
        "blockable_hostnames": len(blockable),
        "ip_literal_hostnames": len(ip_hosts),
        "shared_hosting_hostnames": len(tenant_hosts),
        "hit": len(hit),
        "hit_blockable": len(hit_blockable),
        "coverage_all_pct": round(100.0 * len(hit) / total, 1) if total else None,
        "coverage_blockable_pct": round(100.0 * len(hit_blockable) / len(blockable), 1) if blockable else None,
    }


def false_positives(hashes: set[int], limit: int = 10_000) -> list[str]:
    return [d for d in top_domains(limit) if artifact_covers(hashes, d)]

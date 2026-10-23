"""The CC BY notice for files shipped with data adapted from the popularity
ranking (scripts/build_top_domains.py: the Majestic Million, CC BY 3.0, and
the Chrome UX Report, CC BY 4.0).

Standard library only: scripts/build_mobile_assets.py runs in CI with a bare
python3, nothing installed.
"""
from __future__ import annotations

import json
from pathlib import Path

SOURCES = Path(__file__).resolve().parents[1] / "data" / "top_domains_sources.json"


def attribution_lines(record: dict | None = None) -> list[str]:
    """Who made each list, its licence and where to read it, and what was
    changed — from data/top_domains_sources.json, so the notice says what
    the shipped copy was built from."""
    if record is None:
        record = json.loads(SOURCES.read_text(encoding="utf-8"))
    out = ["Contains data adapted from:"]
    for key in ("majestic_million", "crux"):
        src = record["sources"][key]
        out.append(f"  {src['attribution']} ({src['licence_url']})")
    out.append(f"Changes made: {record['method']}")
    out.append("Details: docs/THIRD_PARTY_FEEDS.md section 5, data/top_domains_sources.json.")
    return out

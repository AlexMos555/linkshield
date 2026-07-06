#!/usr/bin/env python3
"""Refresh the ML training feeds so retraining learns CURRENT phishing.

The model's training data was a frozen Apr-2026 snapshot (data/phishtank.csv,
data/top-1m.csv) with no refresher — so a retrain just re-learned April's phish.
This script pulls fresh, free, bulk sources into the exact files ml/train_model.py
reads, turning the model into a living, retrainable system (run by retrain-ml.yml).

Writes (both gitignored — regenerated each run):
  data/phishtank.csv  — phishing corpus, 'url' column (from URLhaus full dump +
                        OpenPhish). Name kept for train_model.py compatibility.
  data/top-1m.csv     — Tranco top-1M (benign corpus).

Usage:
    python scripts/refresh_training_feeds.py
    python scripts/refresh_training_feeds.py --phishing-only
"""
from __future__ import annotations

import argparse
import csv
import io
import logging
import os
import sys
import zipfile

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("training-feeds")

_DATA = os.path.join(os.path.dirname(__file__), "..", "data")
URLHAUS_FULL = "https://urlhaus.abuse.ch/downloads/csv/"          # full dump (zip)
OPENPHISH = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
TRANCO = "https://tranco-list.eu/top-1m.csv.zip"


def _get(url: str, timeout: float = 180.0) -> bytes:
    with httpx.Client(timeout=timeout, follow_redirects=True,
                      headers={"User-Agent": "cleanway-training"}) as c:
        r = c.get(url)
        r.raise_for_status()
        return r.content


def refresh_phishing() -> int:
    urls: list[str] = []
    # URLhaus full dump (zip → csv with a commented header; col 2 = url)
    try:
        raw = _get(URLHAUS_FULL)
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                member = next((m for m in zf.namelist() if m.endswith(".csv") or m.endswith(".txt")), None)
                text = zf.read(member).decode("utf-8", "ignore") if member else ""
        except zipfile.BadZipFile:
            text = raw.decode("utf-8", "ignore")  # served unzipped
        for line in text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            row = next(csv.reader([line]), [])
            if len(row) >= 3 and row[2].startswith("http"):
                urls.append(row[2])
        logger.info("URLhaus full: %d urls", len(urls))
    except Exception as e:  # noqa: BLE001
        logger.warning("URLhaus full fetch failed: %s", e)
    # OpenPhish
    try:
        for line in _get(OPENPHISH, timeout=60).decode("utf-8", "ignore").splitlines():
            if line.strip().startswith("http"):
                urls.append(line.strip())
        logger.info("Total after OpenPhish: %d urls", len(urls))
    except Exception as e:  # noqa: BLE001
        logger.warning("OpenPhish fetch failed: %s", e)

    if len(urls) < 2000:
        logger.error("Only %d phishing urls — too few to retrain safely; aborting", len(urls))
        return 2
    out = os.path.join(_DATA, "phishtank.csv")
    with open(out, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["url"])
        for u in urls:
            w.writerow([u])
    logger.info("Wrote %s (%d rows)", out, len(urls))
    return 0


def refresh_benign() -> int:
    try:
        raw = _get(TRANCO)
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            member = next(m for m in zf.namelist() if m.endswith(".csv"))
            data = zf.read(member).decode("utf-8", "ignore")
        out = os.path.join(_DATA, "top-1m.csv")
        with open(out, "w") as f:
            f.write(data)
        logger.info("Wrote %s (%d bytes)", out, len(data))
        return 0
    except Exception as e:  # noqa: BLE001
        logger.error("Tranco fetch failed: %s", e)
        return 2


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

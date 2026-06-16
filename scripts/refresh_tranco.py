#!/usr/bin/env python3
"""Refresh the Tranco top-1M domain rank cache in Redis.

Run once a day from ops cron. Downloads the current Tranco list
zip, streams it into Redis as a single hash `tranco:ranks` via
HMSET pipeline batches of 10,000 entries.

The whole top-1M fits in ~25 MB on the Redis side. We use a
versioned key (`tranco:ranks:vYYYYMMDD`) and atomically rename
to `tranco:ranks` at the end so concurrent readers never see a
half-loaded map. The previous version is deleted after the
rename succeeds.

Usage:
    python scripts/refresh_tranco.py             # download today's list
    python scripts/refresh_tranco.py --dry-run   # parse but don't write

Environment:
    REDIS_URL          — connection string (required)
    TRANCO_LIST_URL    — override the source URL (optional)
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import logging
import os
import sys
import zipfile

import httpx
import redis.asyncio as redis

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("tranco-refresh")

DEFAULT_URL = "https://tranco-list.eu/top-1m.csv.zip"
BATCH_SIZE = 10_000


async def _download(url: str) -> bytes:
    async with httpx.AsyncClient(timeout=120.0, follow_redirects=True) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        return resp.content


def _iter_ranks(zip_bytes: bytes):
    """Yield (domain, rank) pairs from the Tranco CSV inside the zip."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        # The zip contains a single CSV named like "top-1m.csv".
        member = next((m for m in zf.namelist() if m.endswith(".csv")), None)
        if not member:
            raise ValueError("Tranco zip contained no CSV — bad payload")
        with zf.open(member) as f:
            text = io.TextIOWrapper(f, encoding="utf-8")
            for row in csv.reader(text):
                if len(row) < 2:
                    continue
                try:
                    rank = int(row[0])
                except ValueError:
                    continue
                domain = row[1].strip().lower()
                if not domain:
                    continue
                yield domain, rank


async def refresh(redis_url: str, source_url: str, dry_run: bool) -> int:
    logger.info("Downloading Tranco list from %s …", source_url)
    payload = await _download(source_url)
    logger.info("Downloaded %.1f MB", len(payload) / 1024 / 1024)

    pairs = list(_iter_ranks(payload))
    logger.info("Parsed %d (domain, rank) pairs", len(pairs))
    if not pairs:
        logger.error("Empty Tranco list — refusing to overwrite cache")
        return 1

    if dry_run:
        logger.info("Dry run — first 5 entries: %s", pairs[:5])
        return 0

    r = redis.from_url(redis_url, decode_responses=True)
    try:
        # Use a versioned staging key so concurrent readers see a
        # consistent snapshot. RENAME is atomic in Redis.
        staging = "tranco:ranks:loading"
        await r.delete(staging)
        loaded = 0
        async with r.pipeline(transaction=False) as pipe:
            for i, (domain, rank) in enumerate(pairs):
                pipe.hset(staging, domain, str(rank))
                if (i + 1) % BATCH_SIZE == 0:
                    await pipe.execute()
                    loaded = i + 1
                    if loaded % (BATCH_SIZE * 10) == 0:
                        logger.info("  loaded %d/%d", loaded, len(pairs))
            await pipe.execute()
        await r.rename(staging, "tranco:ranks")
        logger.info("Atomically swapped — cache now serving %d ranks", len(pairs))
        return 0
    finally:
        await r.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--url", default=os.environ.get("TRANCO_LIST_URL", DEFAULT_URL))
    args = parser.parse_args()

    redis_url = os.environ.get("REDIS_URL")
    if not redis_url and not args.dry_run:
        logger.error("REDIS_URL must be set (use --dry-run to skip writes)")
        return 2

    return asyncio.run(refresh(redis_url or "redis://localhost:6379", args.url, args.dry_run))


if __name__ == "__main__":
    sys.exit(main())

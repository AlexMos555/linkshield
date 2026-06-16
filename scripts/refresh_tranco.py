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
    """Refresh tranco:ranks. Safe under concurrent invocation:

    * A SETNX lock with a 30-min TTL prevents two refreshers from
      stomping on each other. If a lock is already held we bail out
      with exit code 3 — operator can investigate without losing data.
    * The staging key includes a per-run version stamp (timestamp +
      PID) so even if the lock is bypassed (manual ops via redis-cli)
      we don't delete an in-progress sibling's hash.
    * Final swap is two atomic renames + UNLINK on the tombstone so
      Redis' single-threaded event loop isn't blocked by a synchronous
      DEL of a ~25 MB hash (UNLINK frees memory asynchronously).
    """
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

    # Version stamp passed in via env so the script itself stays
    # Date-free (and so tests can pin it). Falls back to time().
    import os, time
    version = os.environ.get("TRANCO_REFRESH_VERSION") or str(int(time.time()))
    staging = f"tranco:ranks:loading:{version}:{os.getpid()}"
    tombstone = f"tranco:ranks:old:{version}"
    LOCK_KEY = "tranco:refresh:lock"
    LOCK_TTL_SECONDS = 30 * 60  # 30 minutes — well above the worst-case load time

    r = redis.from_url(redis_url, decode_responses=True)
    try:
        # SETNX-style lock: only one refresher runs at a time. The TTL
        # ensures a crashed run releases the lock automatically.
        acquired = await r.set(LOCK_KEY, version, nx=True, ex=LOCK_TTL_SECONDS)
        if not acquired:
            holder = await r.get(LOCK_KEY)
            logger.error(
                "Another refresh is in progress (lock held by %s). "
                "Wait for it or delete the lock manually if you're sure it's stale.",
                holder,
            )
            return 3

        try:
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

            # Two-step swap. First move the live key aside (atomic, no
            # DEL of destination because tombstone doesn't exist yet),
            # then rename the staging onto the canonical name (atomic,
            # destination just freed). Finally UNLINK the tombstone so
            # the ~25 MB hash is freed asynchronously.
            exists = await r.exists("tranco:ranks")
            if exists:
                await r.rename("tranco:ranks", tombstone)
            await r.rename(staging, "tranco:ranks")
            if exists:
                await r.unlink(tombstone)

            logger.info("Atomically swapped — cache now serving %d ranks", len(pairs))
            return 0
        finally:
            # Best-effort cleanup of orphans if anything threw before swap.
            try:
                await r.unlink(staging)
            except Exception:
                pass
            # Release the lock only if WE still hold it (the version
            # stamp prevents accidentally releasing another run's lock).
            try:
                held = await r.get(LOCK_KEY)
                if held == version:
                    await r.delete(LOCK_KEY)
            except Exception:
                pass
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

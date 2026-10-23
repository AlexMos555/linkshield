#!/usr/bin/env python3
"""Refresh the top-1M popularity rank cache in Redis (hash `tranco:ranks`).

Run once a day by .github/workflows/refresh-tranco.yml. Builds Cleanway's
popularity ranking — the Majestic Million (CC BY 3.0) and the Chrome UX
Report top origins (CC BY 4.0), merged by scripts/build_top_domains.py, the
same function that writes data/top_100k.json — and streams its first
1,000,000 names into Redis via pipelined HSETs of 10,000 entries.

Until 2026-10-23 this downloaded the Tranco list (tranco-list.eu). Tranco
states no licence of its own and its default list averages Cloudflare
Radar, CC BY-NC 4.0, so it may not feed a product people pay for
(docs/THIRD_PARTY_FEEDS.md §2a). A Tranco URL is now refused outright, from
--url or TRANCO_LIST_URL alike. The key keeps its name (`tranco:ranks`) and
the scorer's signals theirs (tranco_ranked, tranco_weight): the API, the
publisher's popular-domain guard and the clients read them by those names.
The first run after this change overwrites Tranco's ranks with the new ones.

The whole top-1M fits in ~25 MB on the Redis side. We load into a
per-run staging key and atomically rename it to `tranco:ranks` at the end,
so concurrent readers never see a half-loaded map. The previous version is
UNLINKed after the rename succeeds.

Usage:
    python scripts/refresh_tranco.py             # build today's ranking, load it
    python scripts/refresh_tranco.py --dry-run   # build it, write nothing
    python scripts/refresh_tranco.py --url URL   # a Majestic Million mirror

Exit codes (the workflow relies on them): 0 loaded (or dry run); 1 the
ranking could not be built — a source down, truncated or unparseable — and
the cache is left as it was; 2 REDIS_URL missing, or a refused URL; 3
another refresh holds the lock.

Environment:
    REDIS_URL               — connection string (required unless --dry-run)
    TRANCO_LIST_URL         — old override; only a non-Tranco Majestic
                              Million mirror is accepted
    TRANCO_REFRESH_VERSION  — staging-key stamp (the workflow's run id)

Imports only httpx and redis beyond the standard library: the workflow
installs nothing else.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import time
from typing import Optional
from urllib.parse import urlparse

import redis.asyncio as redis

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_top_domains  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("popularity-refresh")

REDIS_KEY = "tranco:ranks"
LOCK_KEY = "tranco:refresh:lock"
LOCK_TTL_SECONDS = 30 * 60  # well above the worst-case load time
BATCH_SIZE = 10_000
DEFAULT_URL = build_top_domains.MAJESTIC
# Hosts whose lists must never be loaded again (see the module docstring).
REFUSED_HOSTS = ("tranco-list.eu",)


def refused(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == h or host.endswith("." + h) for h in REFUSED_HOSTS)


def build_pairs(majestic_url: str = DEFAULT_URL, fetch=None) -> list[tuple[str, int]]:
    """(domain, rank) for the first REDIS_N names of the ranking. Raises when
    any source fails (build_top_domains.fetch_sources)."""
    base = fetch or build_top_domains.feeds._get

    def get(url: str, timeout: float = 180.0) -> bytes:
        # A mirror (--url) stands in for the Majestic Million; every other
        # source is fetched as build_top_domains names it.
        return base(majestic_url if url == DEFAULT_URL else url, timeout)

    return build_top_domains.ranked_domains(fetch=get, limit=build_top_domains.REDIS_N)


async def load(redis_url: str, pairs: list[tuple[str, int]], version: str) -> int:
    """Load `pairs` into REDIS_KEY. Safe under concurrent invocation:

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
    staging = f"{REDIS_KEY}:loading:{version}:{os.getpid()}"
    tombstone = f"{REDIS_KEY}:old:{version}"
    r = redis.from_url(redis_url, decode_responses=True)
    try:
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
            async with r.pipeline(transaction=False) as pipe:
                for i, (domain, rank) in enumerate(pairs):
                    pipe.hset(staging, domain, str(rank))
                    if (i + 1) % BATCH_SIZE == 0:
                        await pipe.execute()
                        if (i + 1) % (BATCH_SIZE * 10) == 0:
                            logger.info("  loaded %d/%d", i + 1, len(pairs))
                await pipe.execute()
            exists = await r.exists(REDIS_KEY)
            if exists:
                await r.rename(REDIS_KEY, tombstone)
            await r.rename(staging, REDIS_KEY)
            if exists:
                await r.unlink(tombstone)
            logger.info("Atomically swapped — cache now serving %d ranks", len(pairs))
            return 0
        finally:
            try:
                await r.unlink(staging)
            except Exception:  # noqa: BLE001 — best-effort cleanup of an orphan
                pass
            try:
                if await r.get(LOCK_KEY) == version:
                    await r.delete(LOCK_KEY)
            except Exception:  # noqa: BLE001
                pass
    finally:
        await r.close()


def main(argv: Optional[list[str]] = None, fetch=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--url", default=os.environ.get("TRANCO_LIST_URL") or DEFAULT_URL,
                        help="a Majestic Million mirror (Tranco URLs are refused)")
    args = parser.parse_args(argv)

    if refused(args.url):
        logger.error("Refusing %s: Tranco's list is not licensed for a paid product "
                     "(docs/THIRD_PARTY_FEEDS.md §2a). Unset TRANCO_LIST_URL / drop --url.", args.url)
        return 2
    redis_url = os.environ.get("REDIS_URL")
    if not redis_url and not args.dry_run:
        logger.error("REDIS_URL must be set (use --dry-run to skip writes)")
        return 2

    try:
        pairs = build_pairs(args.url, fetch)
    except Exception as e:  # noqa: BLE001 — any source failure keeps yesterday's cache
        logger.error("Popularity ranking not built, keeping the current cache: %s", e)
        return 1
    logger.info("Built %d (domain, rank) pairs", len(pairs))
    if args.dry_run:
        logger.info("Dry run — first 5 entries: %s", pairs[:5])
        return 0
    version = os.environ.get("TRANCO_REFRESH_VERSION") or str(int(time.time()))
    return asyncio.run(load(redis_url, pairs, version))


if __name__ == "__main__":
    sys.exit(main())

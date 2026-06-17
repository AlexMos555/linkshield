#!/usr/bin/env python3
"""Daily Watchtower scan job — Strategy doc Top-20 #17.

For every DISTINCT brand_root_domain across all users' watchlists,
run scan_brand() and UPSERT typosquat_alerts. Stamp last_scanned_at
on the corresponding brand_watchlist rows.

Designed to run from GH Actions on a daily cron (~03:33 UTC,
off-peak from the Tranco refresh at 03:17). One process at a
time — if a previous run is still in flight, the SETNX lock
makes the new one exit cleanly.

Environment:
    SUPABASE_URL              required
    SUPABASE_SERVICE_KEY      required (service_role; bypasses RLS)
    REDIS_URL                 optional, used for the global lock
    WATCHTOWER_MAX_BRANDS     optional cap per run (default 200)
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from datetime import datetime, timezone

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("watchtower-refresh")

LOCK_KEY = "watchtower:refresh:lock"
LOCK_TTL_SECONDS = 60 * 60  # one hour — well above worst-case scan duration


def _hash_brand(root: str) -> str:
    """Stable, non-reversible label for log lines so a public GH
    Actions log doesn't leak the brands users watch.

    Truncated SHA-256; 16 hex chars is enough to disambiguate while
    keeping logs readable. The actual scan still works on the raw
    domain in memory — only the LOG SURFACE is hashed.
    """
    import hashlib
    return hashlib.sha256((root or "").encode("utf-8")).hexdigest()[:16]


async def _acquire_lock(redis_url: str | None) -> tuple[object | None, bool, str | None]:
    """Try to acquire the global single-flight lock. Returns
    (client, acquired, our_token). client may be None when no
    REDIS_URL is configured (lock is then a no-op)."""
    if not redis_url:
        logger.warning("No REDIS_URL — proceeding without single-flight lock")
        return None, True, None
    import redis.asyncio as redis
    r = redis.from_url(redis_url, decode_responses=True)
    # Cron run id is the GH Actions run id when present, else PID.
    token = os.environ.get("GITHUB_RUN_ID") or str(os.getpid())
    got = await r.set(LOCK_KEY, token, nx=True, ex=LOCK_TTL_SECONDS)
    if not got:
        holder = await r.get(LOCK_KEY)
        logger.error("Another watchtower scan is in progress (held by %s)", holder)
        await r.close()
        return None, False, None
    return r, True, token


async def _release_lock(client, token: str | None) -> None:
    if client is None:
        return
    try:
        held = await client.get(LOCK_KEY)
        if held == token:
            await client.delete(LOCK_KEY)
    except Exception:
        pass
    try:
        await client.close()
    except Exception:
        pass


async def _supabase(http: httpx.AsyncClient, method: str, path: str, **kwargs):
    settings_url = os.environ["SUPABASE_URL"].rstrip("/")
    service_key = os.environ["SUPABASE_SERVICE_KEY"]
    return await http.request(
        method,
        f"{settings_url}/rest/v1/{path}",
        headers={
            "apikey": service_key,
            "Authorization": f"Bearer {service_key}",
            "Content-Type": "application/json",
            **kwargs.pop("headers", {}),
        },
        **kwargs,
    )


async def _distinct_brands(http: httpx.AsyncClient, cap: int) -> list[dict]:
    """Return up to `cap` DISTINCT brand_root_domain values, ordered
    by oldest last_scanned_at first (NULL first = brand-new entries).

    The previous version applied `limit=200` to the raw rows and
    THEN deduplicated in Python — meaning a single brand watched
    by 200 users could fill the entire window and silently squeeze
    every other brand out (adversarial-review #3). PostgREST 11+
    supports `?select=distinct(col)`; we paginate by 1000-row
    batches and dedup until we have `cap` unique brands.
    """
    seen: set[str] = set()
    unique: list[dict] = []
    page_size = 1000
    offset = 0
    while len(unique) < cap:
        resp = await _supabase(
            http, "GET", "brand_watchlist",
            params={
                "select": "brand_root_domain,last_scanned_at",
                "order": "last_scanned_at.asc.nullsfirst",
                "limit": str(page_size),
                "offset": str(offset),
            },
        )
        if resp.status_code != 200:
            logger.error("brand_watchlist read failed %s %s", resp.status_code, resp.text[:200])
            return unique
        rows = resp.json()
        if not rows:
            break
        for r in rows:
            root = r.get("brand_root_domain")
            if not root or root in seen:
                continue
            seen.add(root)
            unique.append(r)
            if len(unique) >= cap:
                break
        offset += page_size
        # Guard: bail out if the rows count drops below page_size
        # (we've reached the end of the table).
        if len(rows) < page_size:
            break
    return unique


async def _upsert_alerts(http: httpx.AsyncClient, payload: list[dict]) -> int:
    if not payload:
        return 0
    resp = await _supabase(
        http, "POST", "typosquat_alerts",
        json=payload,
        headers={
            # Existing rows on (brand_root_domain, suspect_domain) are
            # left alone — first_seen_at must NOT regress to the new
            # cert's notBefore if a cousin already saw its first hit.
            "Prefer": "resolution=ignore-duplicates,return=representation",
        },
    )
    if resp.status_code not in (200, 201):
        logger.warning("alert upsert failed %s %s", resp.status_code, resp.text[:200])
        return 0
    rows = resp.json()
    return len(rows) if isinstance(rows, list) else 0


async def _stamp_scanned(http: httpx.AsyncClient, brand_root: str) -> None:
    """Stamp last_scanned_at on every row matching this brand_root.

    A silent failure here used to leave the brand at the head of the
    NULLS-FIRST queue forever — next run would re-scan it, every run
    after that too, while other brands starved (adversarial-review #7).
    Now we log non-2xx with the brand and let the watchdog notice.
    """
    now = datetime.now(timezone.utc).isoformat()
    resp = await _supabase(
        http, "PATCH", "brand_watchlist",
        params={"brand_root_domain": f"eq.{brand_root}"},
        json={"last_scanned_at": now},
    )
    if resp.status_code not in (200, 204):
        logger.warning(
            "stamp_scanned failed for brand_root_hash=%s status=%s body=%s",
            _hash_brand(brand_root), resp.status_code, resp.text[:200],
        )


async def run_once(cap: int) -> int:
    from api.services.watchtower import scan_brand

    async with httpx.AsyncClient(timeout=30.0) as http:
        brands = await _distinct_brands(http, cap)
        if not brands:
            logger.info("No brands in watchlist — nothing to do")
            return 0

        logger.info("Scanning %d distinct brands…", len(brands))
        total_new = 0
        for b in brands:
            root = b["brand_root_domain"]
            tag = _hash_brand(root)  # log-safe label
            try:
                candidates = await scan_brand(root)
            except Exception as exc:
                logger.exception("scan_brand crashed for brand_hash=%s: %s", tag, exc)
                continue
            n = await _upsert_alerts(http, [c.as_dict() for c in candidates])
            await _stamp_scanned(http, root)
            total_new += n
            logger.info("  brand_hash=%s → %d candidates → %d new alerts",
                        tag, len(candidates), n)
        logger.info("Done. %d new alerts across %d brands.", total_new, len(brands))
        return 0


async def main(args) -> int:
    cap = int(os.environ.get("WATCHTOWER_MAX_BRANDS", "200"))
    if not (os.environ.get("SUPABASE_URL") and os.environ.get("SUPABASE_SERVICE_KEY")):
        logger.error("SUPABASE_URL and SUPABASE_SERVICE_KEY must be set")
        return 2

    client, acquired, token = await _acquire_lock(os.environ.get("REDIS_URL"))
    if not acquired:
        return 3
    try:
        return await run_once(cap)
    finally:
        await _release_lock(client, token)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    args = p.parse_args()
    sys.exit(asyncio.run(main(args)))

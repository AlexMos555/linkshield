#!/usr/bin/env python3
"""Populate brand_favicons.json with current favicon hashes.

Fetches the favicon from the FIRST verified_host of each brand,
hashes it, and writes the resulting hash into known_favicon_hashes.

Run when a brand changes their favicon (rare) or when adding new
brands to the gallery. Idempotent: a hash already present is
preserved; only NEW hashes get appended.

Usage:
    python scripts/refresh_brand_favicons.py
    python scripts/refresh_brand_favicons.py --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import pathlib
import sys

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("brand-favicons")

GALLERY_PATH = pathlib.Path(__file__).resolve().parent.parent / "api" / "data" / "brand_favicons.json"


def _hash_bytes(b: bytes) -> str:
    """Mirror api.services.favicon_hash._hash_bytes — must match
    HASH_HEX_LEN there or the ops script populates hashes the
    runtime cannot recognise."""
    import hashlib
    from api.services.favicon_hash import HASH_HEX_LEN
    return hashlib.sha256(b).hexdigest()[:HASH_HEX_LEN]


async def _fetch(client: httpx.AsyncClient, host: str) -> bytes | None:
    url = f"https://{host}/favicon.ico"
    try:
        resp = await client.get(url, timeout=5.0)
        if resp.status_code == 200 and 0 < len(resp.content) <= 256 * 1024:
            return resp.content
        logger.warning("  %s → status=%d size=%d", url, resp.status_code, len(resp.content))
    except Exception as exc:
        logger.warning("  %s → %s", url, exc)
    return None


async def main(dry_run: bool) -> int:
    with open(GALLERY_PATH, "r", encoding="utf-8") as f:
        gallery = json.load(f)

    async with httpx.AsyncClient(follow_redirects=True) as client:
        updated = 0
        for slug, brand in gallery.items():
            if slug.startswith("_"):
                continue
            hosts = brand.get("verified_hosts") or []
            if not hosts:
                continue
            first = hosts[0]
            logger.info("Fetching %s favicon …", slug)
            payload = await _fetch(client, first)
            if not payload:
                continue
            digest = _hash_bytes(payload)
            known = brand.setdefault("known_favicon_hashes", [])
            if digest in known:
                logger.info("  %s already has hash %s", slug, digest)
            else:
                known.append(digest)
                updated += 1
                logger.info("  %s ← new hash %s", slug, digest)

        logger.info("Updated %d brand entries", updated)

    if dry_run:
        logger.info("Dry run — gallery not written")
        return 0

    if updated > 0:
        with open(GALLERY_PATH, "w", encoding="utf-8") as f:
            json.dump(gallery, f, indent=2, sort_keys=False)
            f.write("\n")
        logger.info("Wrote %s", GALLERY_PATH)
    return 0


def cli() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()
    return asyncio.run(main(args.dry_run))


if __name__ == "__main__":
    sys.exit(cli())

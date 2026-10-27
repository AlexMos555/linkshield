#!/usr/bin/env python3
"""Populate brand_favicons.json with current favicon hashes.

For each brand, tries /favicon.ico on every verified_host in order, then
the <link rel="icon"> of each host's home page (only when it points at one of
the brand's verified hosts); the first image found is hashed into
known_favicon_hashes. hosts[0] alone was not enough (measured 2026-10-27):
linkedin.com/favicon.ico is a 20 KB HTML page to every client while
www.linkedin.com/favicon.ico is the icon, and FedEx serves a "Page Not Found"
page at /favicon.ico on both hosts; its icon is the one the page links.

Run when a brand changes their favicon (rare) or when adding new
brands to the gallery. Idempotent: a hash already present is
preserved; only NEW hashes get appended.

A response that is not an image is skipped: bot walls answer a datacenter
fetch with "200 OK" and an HTML page, and the 2026-10-25 run filed those
pages as the UPS, FedEx and LinkedIn favicons.

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
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("brand-favicons")

GALLERY_PATH = pathlib.Path(__file__).resolve().parent.parent / "api" / "data" / "brand_favicons.json"


# Must match api.services.favicon_hash.HASH_HEX_LEN. Hardcoded (not imported) so this
# ops script stays dependency-free: importing favicon_hash drags in the redis/pydantic
# api chain, which the CI cron (httpx-only, no requirements.txt) cannot load — that
# crashed this job for 4 weeks. tests/test_favicon_refresh_drift.py guards the match.
HASH_HEX_LEN = 24


# Copy of api.services.favicon_hash._RASTER_MAGIC / looks_like_favicon, kept
# here for the same reason as HASH_HEX_LEN; the drift test compares them.
_RASTER_MAGIC = (
    b"\x00\x00\x01\x00",
    b"\x00\x00\x02\x00",
    b"\x89PNG\r\n\x1a\n",
    b"GIF87a",
    b"GIF89a",
    b"\xff\xd8\xff",
    b"BM",
)


def looks_like_favicon(b: bytes) -> bool:
    """True when the bytes are an image a browser would show as a favicon."""
    if b.startswith(_RASTER_MAGIC):
        return True
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return True
    head = b[:1024].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    return (
        head.startswith((b"<svg", b"<?xml", b"<!--", b"<!doctype svg"))
        and b"<svg" in head
        and b"<html" not in head
    )


def _hash_bytes(b: bytes) -> str:
    """SHA-256 truncated to HASH_HEX_LEN hex chars, matching the runtime hasher."""
    import hashlib
    return hashlib.sha256(b).hexdigest()[:HASH_HEX_LEN]


async def _fetch(client: httpx.AsyncClient, host: str) -> bytes | None:
    return await _fetch_image(client, f"https://{host}/favicon.ico")


async def _fetch_image(client: httpx.AsyncClient, url: str, **kwargs) -> bytes | None:
    try:
        resp = await client.get(url, timeout=5.0, **kwargs)
        if resp.status_code == 200 and 0 < len(resp.content) <= 256 * 1024:
            if looks_like_favicon(resp.content):
                return resp.content
            logger.warning(
                "  %s → not an image (content-type=%s size=%d), skipped",
                url, resp.headers.get("content-type", "?"), len(resp.content),
            )
            return None
        logger.warning("  %s → status=%d size=%d", url, resp.status_code, len(resp.content))
    except Exception as exc:
        logger.warning("  %s → %s", url, exc)
    return None


class _IconLink(HTMLParser):
    """The href of the first <link> whose rel has the token "icon"
    ("icon", "shortcut icon"; not "apple-touch-icon")."""

    def __init__(self) -> None:
        super().__init__()
        self.href: str | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        if self.href is None and tag == "link":
            a = {k: (v or "") for k, v in attrs}
            if "icon" in a.get("rel", "").lower().split() and a.get("href", "").strip():
                self.href = a["href"].strip()


async def _linked_icon(client: httpx.AsyncClient, host: str, verified: set[str]) -> bytes | None:
    """The image the home page's <link rel="icon"> names, when it is on one
    of the brand's own hosts and served there without a redirect: the
    gallery takes bytes from the brand's hosts only."""
    page = f"https://{host}/"
    try:
        resp = await client.get(page, timeout=5.0)
    except Exception as exc:
        logger.warning("  %s → %s", page, exc)
        return None
    if resp.status_code != 200:
        logger.warning("  %s → status=%d", page, resp.status_code)
        return None
    parser = _IconLink()
    parser.feed(resp.text[: 512 * 1024])  # <head> is at the top
    if not parser.href:
        logger.warning("  %s → no <link rel=icon>", page)
        return None
    url = urljoin(str(resp.url), parser.href)
    parts = urlsplit(url)
    if parts.scheme != "https" or (parts.hostname or "").lower() not in verified:
        logger.warning("  %s → icon link %s is not on a verified host, skipped", page, url)
        return None
    return await _fetch_image(client, url, follow_redirects=False)


async def _brand_icon(client: httpx.AsyncClient, hosts: list[str]) -> bytes | None:
    """/favicon.ico on each host first (that is what the runtime hashes on a
    suspect page), then each host's linked icon."""
    for host in hosts:
        payload = await _fetch(client, host)
        if payload:
            return payload
    verified = {h.lower() for h in hosts}
    for host in hosts:
        payload = await _linked_icon(client, host, verified)
        if payload:
            return payload
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
            logger.info("Fetching %s favicon …", slug)
            payload = await _brand_icon(client, hosts)
            if not payload:
                logger.warning("  %s: no verified host served an image, not refreshed", slug)
                if not brand.get("known_favicon_hashes"):
                    logger.warning("  %s has no favicon hash at all: no clone detection for it", slug)
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

#!/usr/bin/env python3
"""Populate the DoH gateway's `dangerous_domains` Redis set from live blocklists.

Until 2026-07-06 this set had ZERO writers — the DoH/DNS resolver checked an
empty set and blocked nothing (a dead feature). This job aggregates fresh
phishing/malware hosts from free bulk feeds and rebuilds the set on a schedule,
so DNS-level blocking actually works.

Sources (free, no API key, bulk):
  * URLhaus  — abuse.ch online URL CSV
  * OpenPhish — community phishing feed (feed.txt)

Safety: the DoH gateway checks BOTH the exact QNAME and the registrable base
(doh_gateway.is_blocked_redis). So we add the FULL phishing hostname always, and
the REGISTRABLE domain only when it is a dedicated phishing domain — never when
the registrable is a known hosting platform or a Tranco-popular domain (blocking
`000webhost.com` or a top-100k site because one subdomain is phishing would be a
catastrophic false positive).

Atomic swap: SADD into a versioned staging key, then RENAME to `dangerous_domains`
so concurrent SISMEMBER readers never see a half-loaded set. A SETNX lock guards
against overlapping runs (exit 3 = lock held).

Usage:
    python scripts/refresh_dangerous_domains.py            # fetch + write Redis
    python scripts/refresh_dangerous_domains.py --dry-run  # fetch + report, no write

Env:
    REDIS_URL   — connection string (required unless --dry-run)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from urllib.parse import urlparse

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("dangerous-domains-refresh")

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_online/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"
BATCH = 5_000
SET_KEY = "dangerous_domains"
TTL_SECONDS = 60 * 60 * 24 * 3  # 3-day safety TTL: if the cron dies, the set expires

# Registrables we must NEVER add (blocking these blocks legit infra). Shared
# hosting / URL platforms where phishing lives on subdomains/paths.
HOSTING_PLATFORMS = frozenset({
    "pages.dev", "workers.dev", "r2.dev", "netlify.app", "vercel.app",
    "herokuapp.com", "github.io", "gitlab.io", "web.app", "firebaseapp.com",
    "appspot.com", "azurewebsites.net", "cloudfront.net", "onrender.com",
    "fly.dev", "railway.app", "blogspot.com", "wordpress.com", "wixsite.com",
    "wixstudio.com", "weebly.com", "webflow.io", "framer.app", "framer.website",
    "carrd.co", "notion.site", "myshopify.com", "replit.app", "webcindario.com",
    "000webhostapp.com", "000webhost.com", "glitch.me", "surge.sh", "duckdns.org",
    "run.app", "s3.amazonaws.com", "blob.core.windows.net", "sharepoint.com",
    "google.com", "microsoft.com", "amazonaws.com", "cloudflare.com",
})

_COMPOUND_TLDS = frozenset({
    "co.uk", "ac.uk", "gov.uk", "org.uk", "co.jp", "co.in", "com.au", "com.br",
    "com.mx", "co.kr", "co.za", "com.sg", "com.tr", "co.id", "com.ar", "com.co",
})


def _registrable_domain(host: str) -> str:
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    last_two = ".".join(parts[-2:])
    if last_two in _COMPOUND_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def _load_top_100k() -> set[str]:
    try:
        with open(os.path.join(_DATA_DIR, "top_100k.json")) as f:
            data = json.load(f)
        return set(d.lower() for d in (data.keys() if isinstance(data, dict) else data))
    except Exception as e:  # noqa: BLE001
        logger.warning("top_100k.json not loaded (%s) — popular-domain guard weaker", e)
        return set()


async def _fetch(url: str) -> str:
    async with httpx.AsyncClient(timeout=90.0, follow_redirects=True,
                                 headers={"User-Agent": "cleanway-blocklist"}) as c:
        r = await c.get(url)
        r.raise_for_status()
        return r.text


def _hosts_from_urlhaus(text: str):
    import csv
    for line in text.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        row = next(csv.reader([line]), [])
        if len(row) >= 3:
            h = urlparse(row[2]).hostname
            if h:
                yield h.lower()


def _hosts_from_openphish(text: str):
    for line in text.splitlines():
        line = line.strip()
        if line:
            h = urlparse(line).hostname
            if h:
                yield h.lower()


def build_blockset(hosts, top_100k: set[str]) -> set[str]:
    """Full phishing hostnames + guarded registrables (never hosting/popular)."""
    out: set[str] = set()
    for h in hosts:
        if not h or h.replace(".", "").replace(":", "").isdigit():
            continue  # skip IPs
        out.add(h)  # always block the exact phishing host
        reg = _registrable_domain(h)
        if reg and reg != h and reg not in HOSTING_PLATFORMS and reg not in top_100k:
            out.add(reg)  # dedicated phishing domain — block the registrable too
        elif reg == h and reg not in HOSTING_PLATFORMS and reg not in top_100k:
            out.add(reg)
    return out


async def refresh(redis_url: str | None, dry_run: bool) -> int:
    top_100k = _load_top_100k()
    hosts: set[str] = set()
    for name, url, parser in (
        ("URLhaus", URLHAUS_CSV, _hosts_from_urlhaus),
        ("OpenPhish", OPENPHISH_FEED, _hosts_from_openphish),
    ):
        try:
            text = await _fetch(url)
            n0 = len(hosts)
            hosts.update(parser(text))
            logger.info("%s: +%d hosts", name, len(hosts) - n0)
        except Exception as e:  # noqa: BLE001
            logger.warning("%s fetch failed: %s (continuing)", name, e)

    if not hosts:
        logger.error("No hosts fetched from any feed — refusing to wipe the set")
        return 2

    blockset = build_blockset(hosts, top_100k)
    logger.info("Built dangerous set: %d entries (from %d raw hosts, %d popular/hosting guarded)",
                len(blockset), len(hosts), len(top_100k))

    if dry_run:
        logger.info("[dry-run] would rebuild '%s' with %d entries; sample: %s",
                    SET_KEY, len(blockset), list(sorted(blockset))[:8])
        return 0

    if not redis_url:
        logger.error("REDIS_URL not set — cannot write")
        return 1

    import redis.asyncio as redis
    r = redis.from_url(redis_url, decode_responses=True)
    lock_key = "lock:dangerous_domains_refresh"
    try:
        if not await r.set(lock_key, "1", nx=True, ex=1800):
            logger.warning("Another refresh holds the lock — exiting 3")
            return 3
        staging = f"{SET_KEY}:staging:{os.getpid()}"
        await r.delete(staging)
        members = list(blockset)
        for i in range(0, len(members), BATCH):
            await r.sadd(staging, *members[i:i + BATCH])
        await r.expire(staging, TTL_SECONDS)
        await r.rename(staging, SET_KEY)
        await r.expire(SET_KEY, TTL_SECONDS)
        card = await r.scard(SET_KEY)
        logger.info("Rebuilt '%s' atomically — %d members live", SET_KEY, card)
        return 0
    finally:
        try:
            await r.delete(lock_key)
            await r.aclose()
        except Exception:  # noqa: BLE001
            pass


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true", help="Fetch + report, do not write Redis")
    args = p.parse_args()
    return asyncio.run(refresh(os.environ.get("REDIS_URL", "").strip() or None, args.dry_run))


if __name__ == "__main__":
    sys.exit(main())

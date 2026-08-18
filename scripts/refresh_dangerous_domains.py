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

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from api.services.blocklist_artifact import (  # noqa: E402
    REDIS_META_KEY, REDIS_TEXT_KEY, meta_for, render_artifact,
)

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

# Big orgs whose subdomains are THEIR OWN services, not tenant sites. A
# subdomain of these is never a block target (the popular-registrable rule
# already skips them; listed here so they are never treated as tenant suffixes).
BIG_ORGS = frozenset({"google.com", "microsoft.com", "amazonaws.com", "cloudflare.com"})

# Hostnames shared by everyone through URL *paths* — one hostname carries a
# million users' files. Blocking any of them = blocking a product for every
# user. URLhaus is full of malware hosted on them; the hostname is never the
# right unit to block, so they are skipped no matter what the feed says.
# (github.com had 869 URLhaus entries on 2026-08-18 and was in production's
# blocklist — every *.github.com was NXDOMAIN for every DNS user we had.)
SHARED_HOSTNAMES = frozenset({
    "github.com", "www.github.com", "gist.github.com", "api.github.com",
    "raw.githubusercontent.com", "gist.githubusercontent.com",
    "objects.githubusercontent.com", "user-images.githubusercontent.com",
    "storage.googleapis.com", "firebasestorage.googleapis.com",
    "drive.google.com", "drive.usercontent.google.com", "docs.google.com",
    "sites.google.com", "forms.google.com", "script.google.com",
    "cdn.discordapp.com", "media.discordapp.net", "discord.com",
    "dl.dropboxusercontent.com", "www.dropbox.com", "dropbox.com",
    "onedrive.live.com", "1drv.ms", "pastebin.com", "transfer.sh",
    "i.imgur.com", "imgur.com", "t.me", "telegra.ph", "mediafire.com",
    "www.mediafire.com", "s3.amazonaws.com", "s3.us-east-1.amazonaws.com",
    "s3.eu-west-1.amazonaws.com", "s3.us-west-2.amazonaws.com",
    "bitbucket.org", "gitlab.com", "sourceforge.net", "archive.org",
    "web.archive.org", "ipfs.io", "cloudflare-ipfs.com", "dweb.link",
})

# A single hostname carrying at least this many distinct feed URLs is a
# shared host (a platform's file store), not one tenant's phishing site —
# tenant sites carry one to a handful. Backstop for shared hosts we did not
# list explicitly.
SHARED_URL_THRESHOLD = 15

_COMPOUND_TLDS = frozenset({
    "co.uk", "ac.uk", "gov.uk", "org.uk", "co.jp", "co.in", "com.au", "com.br",
    "com.mx", "co.kr", "co.za", "com.sg", "com.tr", "co.id", "com.ar", "com.co",
})


# Generic second-level labels under 2-letter ccTLDs (com.am, co.nz, org.uk,
# gob.mx …): the registrable is three labels. Fallback when the PSL could not
# be fetched. Promoting `com.am` to the blocklist would darken every Armenian
# .com.am site — that exact promotion was live in production on 2026-08-18.
_CCTLD_SECOND_LEVELS = frozenset({
    "com", "co", "org", "net", "gov", "gob", "edu", "ac", "ne", "or", "go", "in",
    "nom", "gen", "ltd", "plc", "sch", "asn", "id", "biz", "info", "web", "gv",
    "govt", "mil", "nic", "int", "art", "name", "pro", "tv", "mobi", "priv",
    "perso", "presse", "asso", "firm", "store", "res", "ind", "me", "my", "ltda",
})

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"


def parse_psl(text: str) -> set[str]:
    """PSL rules, lowercased, wildcards kept as '*.x', exceptions dropped."""
    out: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("//") or line.startswith("!"):
            continue
        out.add(line.lower())
    return out


async def _fetch_psl() -> set[str] | None:
    try:
        return parse_psl(await _fetch(PSL_URL))
    except Exception as e:  # noqa: BLE001
        logger.warning("PSL fetch failed (%s) — using ccTLD heuristic", e)
        return None


def _registrable_domain(host: str, public_suffixes: set[str] | None = None) -> str:
    """eTLD+1. With a PSL: longest matching public suffix + one label.
    Without: last two labels, or three under a compound / generic-SLD ccTLD."""
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if public_suffixes:
        for k in range(len(parts) - 1, 0, -1):
            suffix = ".".join(parts[-k:])
            wildcard = "*." + ".".join(parts[-(k - 1):]) if k >= 2 else None
            if suffix in public_suffixes or (wildcard and wildcard in public_suffixes):
                return ".".join(parts[-(k + 1):])
        return ".".join(parts[-2:])
    last_two = ".".join(parts[-2:])
    if last_two in _COMPOUND_TLDS:
        return ".".join(parts[-3:])
    tld, sld = parts[-1], parts[-2]
    if len(tld) == 2 and sld in _CCTLD_SECOND_LEVELS:
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


def _load_public_suffixes_in_top() -> set[str]:
    """PSL rules that are also Tranco top domains (us.org, github.io,
    blob.core.windows.net …) — built by scripts/build_public_suffixes_in_top.py.
    Subdomains of these are tenant sites; the apex is the platform."""
    try:
        with open(os.path.join(_DATA_DIR, "public_suffixes_in_top.json")) as f:
            return {d.lower() for d in json.load(f)}
    except Exception as e:  # noqa: BLE001
        logger.warning("public_suffixes_in_top.json not loaded (%s) — tenant guard weaker", e)
        return set()


def default_shared_suffixes() -> set[str]:
    """Suffixes under which a subdomain is ONE tenant's site (safe to block
    exactly) while the apex is a platform (never blocked)."""
    return (set(HOSTING_PLATFORMS) - BIG_ORGS) | _load_public_suffixes_in_top()


def _tenant_suffix(host: str, shared_suffixes: set[str]) -> str | None:
    """Longest proper suffix of `host` that is a shared/tenant suffix."""
    parts = host.split(".")
    for k in range(len(parts) - 1, 1, -1):  # longest first, at least 2 labels
        suffix = ".".join(parts[-k:])
        if suffix in shared_suffixes:
            return suffix
    return None


def build_blockset(hosts, top_100k: set[str], shared_suffixes: set[str] | None = None,
                   is_popular=None, public_suffixes: set[str] | None = None) -> set[str]:
    """Decide, per feed hostname, what (if anything) to block.

    Never darken a shared or popular host — a false positive here breaks a
    product for every DNS user, while a miss costs one phishing page that
    the other layers may still catch.

      SKIP           host in SHARED_HOSTNAMES (path-shared by everyone);
                     host is a shared-platform apex (github.io, us.org);
                     host's registrable is popular (top-100k, or Tranco-1M via
                     `is_popular`) and host is NOT under a tenant suffix
                     (github.com, attach.mail.daum.net, adclick.g.doubleclick.net);
                     host under a tenant suffix but carrying >= SHARED_URL_THRESHOLD
                     feed URLs (a shared file host, not a tenant).
      EXACT ONLY     host is one tenant's site under a shared suffix
                     (evil.github.io, gwcu.us.org, x.blob.core.windows.net).
      EXACT + REG    dedicated phishing domain: block the host and its
                     registrable (login.scotiabano.com + scotiabano.com).

    `hosts` may contain repeats (one per feed URL); repeats feed the
    shared-host threshold. `is_popular(registrable) -> bool` is optional
    (Tranco-1M lookup when Redis is available).
    """
    shared = default_shared_suffixes() if shared_suffixes is None else set(shared_suffixes)
    counts: dict[str, int] = {}
    for h in hosts:
        if h:
            counts[h] = counts.get(h, 0) + 1

    def popular(reg: str) -> bool:
        if reg in top_100k:
            return True
        try:
            return bool(is_popular and is_popular(reg))
        except Exception:  # noqa: BLE001
            return False

    out: set[str] = set()
    for h in counts:
        if h.replace(".", "").replace(":", "").isdigit():
            continue  # IP literal — DNS blocking cannot cover it
        if h in SHARED_HOSTNAMES:
            continue
        reg = _registrable_domain(h, public_suffixes)
        suffix = _tenant_suffix(h, shared)
        if h in shared or (public_suffixes and h in public_suffixes):
            continue  # platform apex / a public suffix itself — never
        if public_suffixes and reg in public_suffixes:
            continue  # cannot even name a registrable — never promote a suffix
        if suffix is not None:
            # One tenant's site on a shared platform — unless the feed shows
            # this single hostname carrying many URLs (then it is a shared
            # host itself, e.g. files.<platform>).
            if counts[h] >= SHARED_URL_THRESHOLD:
                continue
            out.add(h)
            continue
        if popular(reg) or reg in BIG_ORGS:
            continue  # popular org's own host — never
        out.add(h)
        if reg:
            out.add(reg)  # dedicated phishing domain
    return out


# Publish gates. A bad publish darkens sites for every DNS user; a skipped
# publish just leaves the previous set (3-day TTL) in place. Prefer skipping.
MIN_ENTRIES = 300
MAX_ENTRIES = 50_000
MAX_CHURN = 0.5  # more than half the previous set replaced → suspicious


def publish_gate(blockset: set[str], previous: set[str] | None, popular: set[str],
                 shared: set[str], force: bool = False) -> tuple[bool, str]:
    """(ok, reason). Never lets a popular domain, a shared-platform apex or a
    wildly different set through."""
    n = len(blockset)
    if n < MIN_ENTRIES:
        return False, f"set too small ({n} < {MIN_ENTRIES}) — feeds probably failed"
    if n > MAX_ENTRIES:
        return False, f"set too large ({n} > {MAX_ENTRIES}) — parser probably broke"
    bad = sorted((blockset & popular) | (blockset & shared))
    if bad:
        return False, f"popular/shared names in set: {bad[:10]}"
    if previous and not force:
        churn = len(blockset ^ previous) / max(1, len(previous))
        if churn > MAX_CHURN:
            return False, f"churn {churn:.0%} vs previous {len(previous)} entries (use --force if intended)"
    return True, "ok"


async def refresh(redis_url: str | None, dry_run: bool, force: bool = False) -> int:
    top_100k = _load_top_100k()
    hosts: list[str] = []  # one entry per feed URL — repeats feed the shared-host guard
    for name, url, parser in (
        ("URLhaus", URLHAUS_CSV, _hosts_from_urlhaus),
        ("OpenPhish", OPENPHISH_FEED, _hosts_from_openphish),
    ):
        try:
            text = await _fetch(url)
            n0 = len(hosts)
            hosts.extend(parser(text))
            logger.info("%s: +%d host entries (%d distinct so far)", name, len(hosts) - n0, len(set(hosts)))
        except Exception as e:  # noqa: BLE001
            logger.warning("%s fetch failed: %s (continuing)", name, e)

    if not hosts:
        logger.error("No hosts fetched from any feed — refusing to wipe the set")
        return 2

    public_suffixes = await _fetch_psl()
    if public_suffixes:
        logger.info("PSL loaded: %d rules", len(public_suffixes))

    # Tranco-1M popularity from prod Redis (tranco:ranks, refreshed daily) —
    # a stronger guard than the bundled top-100k, when we can reach it.
    is_popular = None
    r = None
    if redis_url:
        try:
            import redis.asyncio as redis
            r = redis.from_url(redis_url, decode_responses=True)
            candidates = sorted({_registrable_domain(h, public_suffixes) for h in hosts if h})
            ranks = await r.hmget("tranco:ranks", candidates) if candidates else []
            popular_set = {d for d, rank in zip(candidates, ranks) if rank}
            logger.info("Tranco-1M guard: %d of %d registrables are ranked", len(popular_set), len(candidates))
            is_popular = popular_set.__contains__
        except Exception as e:  # noqa: BLE001
            logger.warning("Tranco rank guard unavailable (%s) — top-100k only", e)

    blockset = build_blockset(hosts, top_100k, is_popular=is_popular, public_suffixes=public_suffixes)
    logger.info("Built dangerous set: %d entries (from %d feed URLs / %d distinct hosts)",
                len(blockset), len(hosts), len(set(hosts)))
    shared_all = default_shared_suffixes()
    previous: set[str] | None = None
    if r is not None:
        try:
            previous = set(await r.smembers(SET_KEY))
        except Exception as e:  # noqa: BLE001
            logger.warning("could not read previous set (%s) — churn gate skipped", e)
    ok, why = publish_gate(blockset, previous, top_100k | (public_suffixes or set()), shared_all, force=force)
    if not ok:
        logger.error("PUBLISH GATE: %s — keeping the previous set", why)
        return 4
    logger.info("publish gate: %s", why)

    artifact = render_artifact(blockset)
    meta = meta_for(artifact)
    logger.info("mobile artifact: %s bytes, sha256 %s…, count %s", len(artifact), meta["sha256"][:12], meta["count"])

    if dry_run:
        logger.info("[dry-run] would rebuild '%s' with %d entries; sample: %s",
                    SET_KEY, len(blockset), list(sorted(blockset))[:8])
        return 0

    if not redis_url:
        logger.error("REDIS_URL not set — cannot write")
        return 1

    if r is None:
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
        # One transaction: the gateway's set and the phones' artifact flip
        # together, so a phone can never sync a list the gateway disagrees with.
        pipe = r.pipeline(transaction=True)
        pipe.rename(staging, SET_KEY)
        pipe.expire(SET_KEY, TTL_SECONDS)
        pipe.set(REDIS_TEXT_KEY, artifact, ex=TTL_SECONDS)
        pipe.delete(REDIS_META_KEY)
        pipe.hset(REDIS_META_KEY, mapping=meta)
        pipe.expire(REDIS_META_KEY, TTL_SECONDS)
        await pipe.execute()
        card = await r.scard(SET_KEY)
        logger.info("Rebuilt '%s' atomically — %d members live; artifact version %s", SET_KEY, card, meta["version"])
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
    p.add_argument("--force", action="store_true", help="Bypass the churn gate (intentional big change)")
    args = p.parse_args()
    return asyncio.run(refresh(os.environ.get("REDIS_URL", "").strip() or None, args.dry_run, force=args.force))


if __name__ == "__main__":
    sys.exit(main())

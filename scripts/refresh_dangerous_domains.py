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
import base64
import json
import logging
import os
import sys
from urllib.parse import urlparse

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from api.services.blocklist_artifact import (  # noqa: E402
    LIST_CANARY, NEVER_BLOCK_GUARDS, REDIS_META_KEY, REDIS_TEXT_KEY, delta_key,
    meta_for_v2, parse_artifact_v2, render_artifact_v2, render_delta,
)

API_BASE = os.environ.get("CLEANWAY_API_BASE", "https://api.cleanway.ai")
PREV_SET_KEY = "dangerous_domains:prev"
PREV_TEXT_KEY = REDIS_TEXT_KEY + ":prev"


def _wire_query(name: str) -> bytes:
    labels = b"".join(bytes([len(l)]) + l.encode("ascii") for l in name.split(".")) + b"\x00"
    # Random transaction id: a fixed one makes the GET URL cacheable at the
    # edge, and a cached answer proves nothing about what we just published.
    return os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00\x01\x00\x01"


async def _live_rcode(client: "httpx.AsyncClient", name: str) -> int | None:
    """RCODE the live gateway returns for `name`, or None if unreachable."""
    import base64
    q = base64.urlsafe_b64encode(_wire_query(name)).decode().rstrip("=")
    try:
        r = await client.get(f"{API_BASE}/dns-query", params={"dns": q},
                             headers={"accept": "application/dns-message"})
        if r.status_code != 200 or len(r.content) < 12:
            return None
        return r.content[3] & 0x0F
    except Exception:  # noqa: BLE001
        return None


async def verify_published(sample_listed: list[str]) -> list[str]:
    """Ask the LIVE gateway what it now does. Empty list = healthy.

    Publishing is the moment a mistake becomes everyone's problem, so the
    check happens here rather than only in the 15-minute canary: a bad set is
    rolled back within seconds instead of hours.
    """
    problems: list[str] = []
    async with httpx.AsyncClient(timeout=15.0) as client:
        for name in NEVER_BLOCK_GUARDS:
            rcode = await _live_rcode(client, name)
            if rcode is None:
                logger.warning("verify: %s unreachable — skipping (not treated as failure)", name)
                continue
            if rcode == 3:
                problems.append(f"{name} is NXDOMAIN after publish")
        for name in sample_listed[:3]:
            rcode = await _live_rcode(client, name)
            if rcode is not None and rcode != 3:
                problems.append(f"listed {name} is NOT blocked after publish (rcode {rcode})")
    return problems

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("dangerous-domains-refresh")

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
URLHAUS_CSV = "https://urlhaus.abuse.ch/downloads/csv_online/"
OPENPHISH_FEED = "https://openphish.com/feed.txt"

# Domain-level phishing aggregates. Measured 2026-08-19 on a held-out
# PhishTank sample: URLhaus + OpenPhish alone covered 0.4% of live phishing
# hostnames (816 names — a correct architecture with an empty tank). Adding
# these two took the same measurement to 54.2% overall / 73.3% of the
# hostnames a domain blocklist can cover at all, with zero Tranco top-10k
# false positives after the guards. That is the difference between a product
# and a demo.
PHISHING_DATABASE = ("https://raw.githubusercontent.com/mitchellkrogza/"
                     "Phishing.Database/master/phishing-domains-ACTIVE.txt")
PHISHING_ARMY = "https://phishing.army/download/phishing_army_blocklist_extended.txt"
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

# Suffixes where EVERY label belongs to the platform operator — there are no
# tenants under them, only the operator's own infrastructure. The tenant rule
# must never fire here: on 2026-08-19 it put media.githubusercontent.com
# (GitHub's own media CDN, one URLhaus entry) into production, so every phone
# and every DoH user got NXDOMAIN for it.
OPERATOR_SUFFIXES = frozenset({
    "githubusercontent.com", "googleusercontent.com", "googleapis.com",
    "gstatic.com", "ggpht.com", "usercontent.goog", "withgoogle.com",
    "cloudfront.net", "akamaihd.net", "akamaized.net", "akamai.net",
    "fbcdn.net", "cdninstagram.com", "licdn.com", "twimg.com",
    "wp.com", "gravatar.com", "shopifycdn.com", "cloudflarestorage.com",
    "linodeusercontent.com", "digitaloceanspaces.com", "oaiusercontent.com",
})

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


def _hosts_from_domain_list(text: str):
    """One lowercase domain per line, '#' comments. Already host-level, so
    each line counts once (the shared-host threshold does not apply)."""
    for raw in text.splitlines():
        line = raw.strip().lower().rstrip(".")
        if not line or line.startswith("#"):
            continue
        # Some lists ship "0.0.0.0 domain" hosts-file syntax.
        if " " in line or "\t" in line:
            parts = line.split()
            line = parts[-1]
        if "." in line and "/" not in line:
            yield line


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
    exactly) while the apex is a platform (never blocked). Operator-only
    suffixes are excluded: a name under those is the operator's, not a
    tenant's, and blocking it breaks the platform for everyone."""
    return ((set(HOSTING_PLATFORMS) - BIG_ORGS) | _load_public_suffixes_in_top()) - OPERATOR_SUFFIXES


def _tenant_suffix(host: str, shared_suffixes: set[str]) -> str | None:
    """Longest proper suffix of `host` that is a shared/tenant suffix."""
    parts = host.split(".")
    for k in range(len(parts) - 1, 1, -1):  # longest first, at least 2 labels
        suffix = ".".join(parts[-k:])
        if suffix in shared_suffixes:
            return suffix
    return None


_LABEL_OK = __import__("re").compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def is_hostname(host: str) -> bool:
    """A syntactically valid DNS name. The aggregates contain URL-encoded junk
    ('%20mandrillapp.com', 'redacted@redacted.invalid') that can never match a
    real query and only bloats the artifact."""
    if not host or len(host) > 253 or ".." in host:
        return False
    labels = host.split(".")
    if len(labels) < 2:
        return False
    if len(labels[-1]) < 2 or labels[-1].isdigit():
        return False
    return all(_LABEL_OK.match(l) for l in labels)


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

    def norm(h: str) -> str:
        """One normalisation for every consumer. Without it a trailing-dot
        host ('example.com.') reached the gate and the Redis set unnormalised
        while the artifact renderer stripped the dot later — so the gate's
        set-intersection could be defeated by a dot, and the registrable of
        'example.com.' was 'com.', a bare TLD."""
        return h.strip().lower().rstrip(".")

    counts: dict[str, int] = {}
    for raw_host in hosts:
        h = norm(raw_host or "")
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
        if not is_hostname(h):
            continue
        if h in SHARED_HOSTNAMES:
            continue
        # Operator infrastructure: never a tenant, never blockable by host.
        if _tenant_suffix(h, set(OPERATOR_SUFFIXES)) is not None or h in OPERATOR_SUFFIXES:
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
            # host itself, e.g. files.<platform>), or the host itself is
            # popular enough to be ranked (a tenant site people actually use).
            if counts[h] >= SHARED_URL_THRESHOLD:
                continue
            if popular(h):
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
# The aggregates carry ~500k names. The phone holds them as a sorted array of
# 48-bit hashes (3 MB), not strings, so the ceiling is about the artifact size
# and the publish blast radius, not memory.
MAX_ENTRIES = 2_000_000
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
        ("Phishing.Database", PHISHING_DATABASE, _hosts_from_domain_list),
        ("phishing.army", PHISHING_ARMY, _hosts_from_domain_list),
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
    if not public_suffixes:
        # Without the PSL the registrable heuristic knows ~40 generic SLDs and
        # promotes everything else — a public suffix (pe.kr, blog.br …) would
        # be published as a blockable domain, darkening a whole zone on every
        # phone. Keeping the previous set is always the cheaper mistake.
        logger.error("PSL unavailable — refusing to publish (the fallback heuristic "
                     "would promote public suffixes). Previous set stays live.")
        return 4
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

    # A listed name already blocks its subdomains, so a subdomain whose parent
    # is listed is dead weight in the artifact.
    def _redundant(n: str) -> bool:
        parts = n.split(".")
        return any(".".join(parts[i:]) in blockset for i in range(1, len(parts) - 1))

    minimal = {n for n in blockset if not _redundant(n)}
    # The canary lives in both places: the artifact (so a phone can prove its
    # list is live) and the gateway set (so the 15-minute canary can prove
    # server-side filtering is not silently dead — the state that once lasted
    # months).
    blockset.add(LIST_CANARY)
    artifact = render_artifact_v2(minimal)
    meta = meta_for_v2(artifact)
    logger.info("mobile artifact v2: %s bytes, sha256 %s…, count %s (from %d names, %d redundant)",
                len(artifact), meta["sha256"][:12], meta["count"], len(blockset), len(blockset) - len(minimal))

    if dry_run:
        logger.info("[dry-run] would rebuild '%s' with %d entries; sample: %s",
                    SET_KEY, len(blockset), list(sorted(blockset))[:8])
        if r is not None:
            # Redis capacity is now a real constraint: the live set is ~40 MB
            # and the artifact another ~3.5 MB. If the instance evicts, the
            # artifact disappears and every phone stops updating — which is
            # exactly what happened on 2026-08-19.
            try:
                info = await r.info("memory")
                logger.info("redis: used %.1f MB / maxmemory %.1f MB (policy %s)",
                            info.get("used_memory", 0) / 1e6,
                            info.get("maxmemory", 0) / 1e6,
                            info.get("maxmemory_policy", "?"))
                for key in (SET_KEY, REDIS_TEXT_KEY, REDIS_META_KEY, "tranco:ranks"):
                    exists = await r.exists(key)
                    size = await r.memory_usage(key) if exists else 0
                    logger.info("redis key %-34s exists=%s %.1f MB", key, bool(exists), (size or 0) / 1e6)
            except Exception as e:  # noqa: BLE001
                logger.warning("redis report failed: %s", e)
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
        # Snapshot what is live so a bad publish can be undone in one step.
        await r.delete(PREV_SET_KEY, PREV_TEXT_KEY)
        try:
            if await r.exists(SET_KEY):
                await r.sunionstore(PREV_SET_KEY, [SET_KEY])
                await r.expire(PREV_SET_KEY, TTL_SECONDS)
            prev_text = await r.get(REDIS_TEXT_KEY)
            if prev_text:
                await r.set(PREV_TEXT_KEY, prev_text, ex=TTL_SECONDS)
        except Exception as e:  # noqa: BLE001
            logger.warning("could not snapshot the live set (%s) — rollback unavailable", e)

        staging = f"{SET_KEY}:staging:{os.getpid()}"
        await r.delete(staging)
        members = list(blockset)
        # TTL first: if the write dies half way (Redis OOM on a big set), the
        # staging key expires instead of leaking until someone notices.
        await r.sadd(staging, members[0])
        await r.expire(staging, TTL_SECONDS)
        for i in range(0, len(members), BATCH):
            await r.sadd(staging, *members[i:i + BATCH])
        try:
            used = await r.memory_usage(staging)
            if used:
                logger.info("staging set: %.1f MB in Redis", used / 1e6)
        except Exception:  # noqa: BLE001
            pass
        # One transaction: the gateway's set and the phones' artifact flip
        # together, so a phone can never sync a list the gateway disagrees with.
        # A delta from whatever we are replacing. Real churn is ~0.2% per half
        # day, so this is a few KB against a 2.5 MB artifact — which is what
        # lets a phone on a metered plan stay current instead of waiting a day.
        delta_blob: bytes | None = None
        delta_from: int | None = None
        try:
            prev_encoded = await r.get(REDIS_TEXT_KEY)
            if prev_encoded:
                prev_blob = base64.b64decode(prev_encoded)
                prev_header, prev_hashes = parse_artifact_v2(prev_blob)
                _, new_hashes = parse_artifact_v2(artifact)
                delta_from = prev_header["generated"]
                delta_blob = render_delta(prev_hashes, new_hashes, from_gen=delta_from,
                                          to_gen=int(meta["generated_at"]), target_sha=meta["sha256"])
                logger.info("delta %s -> %s: %d bytes (artifact %d bytes)",
                            delta_from, meta["generated_at"], len(delta_blob), len(artifact))
        except Exception as e:  # noqa: BLE001
            logger.warning("could not build a delta (%s) — phones will fetch the full artifact", e)
            delta_blob = None

        pipe = r.pipeline(transaction=True)
        pipe.rename(staging, SET_KEY)
        pipe.expire(SET_KEY, TTL_SECONDS)
        # Redis client runs with decode_responses=True for everything else;
        # base64 keeps the binary artifact in that one text world.
        pipe.set(REDIS_TEXT_KEY, base64.b64encode(artifact).decode("ascii"), ex=TTL_SECONDS)
        pipe.delete(REDIS_META_KEY)
        pipe.hset(REDIS_META_KEY, mapping=meta)
        pipe.expire(REDIS_META_KEY, TTL_SECONDS)
        if delta_blob is not None and delta_from is not None:
            pipe.set(delta_key(delta_from), base64.b64encode(delta_blob).decode("ascii"), ex=TTL_SECONDS)
        await pipe.execute()
        card = await r.scard(SET_KEY)
        logger.info("Rebuilt '%s' atomically — %d members live; artifact version %s", SET_KEY, card, meta["version"])

        # Now ask production what it actually does. If we just darkened
        # something that must never be dark, put the old set back.
        sample = sorted(n for n in blockset if n != "list-canary.cleanway.ai")[:3]
        problems = await verify_published(sample)
        if problems:
            logger.error("POST-PUBLISH VERIFICATION FAILED: %s", problems)
            restored = await rollback(r)
            logger.error("rolled back: %s", "previous set restored" if restored
                         else "NO SNAPSHOT — the bad set is still live, revert manually")
            return 5
        logger.info("post-publish verification: live gateway healthy")
        return 0
    finally:
        try:
            await r.delete(lock_key)
            await r.aclose()
        except Exception:  # noqa: BLE001
            pass


async def rollback(r) -> bool:
    """Put the snapshot back. True if something was restored."""
    try:
        if not await r.exists(PREV_SET_KEY):
            return False
        pipe = r.pipeline(transaction=True)
        pipe.rename(PREV_SET_KEY, SET_KEY)
        pipe.expire(SET_KEY, TTL_SECONDS)
        await pipe.execute()
        prev_text = await r.get(PREV_TEXT_KEY)
        if prev_text:
            pipe = r.pipeline(transaction=True)
            pipe.set(REDIS_TEXT_KEY, prev_text, ex=TTL_SECONDS)
            pipe.delete(REDIS_META_KEY)
            pipe.hset(REDIS_META_KEY, mapping=meta_for_v2(base64.b64decode(prev_text)))
            pipe.expire(REDIS_META_KEY, TTL_SECONDS)
            await pipe.execute()
        return True
    except Exception as e:  # noqa: BLE001
        logger.error("rollback failed: %s", e)
        return False


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true", help="Fetch + report, do not write Redis")
    p.add_argument("--force", action="store_true", help="Bypass the churn gate (intentional big change)")
    args = p.parse_args()
    return asyncio.run(refresh(os.environ.get("REDIS_URL", "").strip() or None, args.dry_run, force=args.force))


if __name__ == "__main__":
    sys.exit(main())

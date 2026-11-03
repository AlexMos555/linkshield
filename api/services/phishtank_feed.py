"""PhishTank as a blocklist source: one download a day, cached in Redis.

Off unless the refresh job has PHISHTANK_API_KEY or BLOCKLIST_PHISHTANK_SOURCE
(scripts/refresh_dangerous_domains.py, phishtank_enabled). PhishTank's FAQ
allows commercial use of its data ("Yes, it is OK" — phishtank.com/faq.php,
read 2026-09-29 and 2026-11-03). The key is optional: the developer page
(developer_info.php, read 2026-11-03) lists the keyless download URLs and
says that without a key you are limited to "a few downloads per day". We
make one. Registration is closed, so until a key comes by e-mail the job
pulls the public dump (ANON_FEED_URL); once the secret exists the keyed URL
is used with no code change. Whether a list built from the dump may go to
apps and our DNS service is not in the FAQ — asked in the key request
(docs/THIRD_PARTY_FEEDS.md §1).

Circularity, stated once here: PhishTank is the held-out set every
blocklist coverage number is measured on (scripts/eval_blocklist_coverage.py,
scripts/eval_day_one_coverage.py). Once it is a source those numbers are
circular; the day-one report marks them so, and a different held-out must be
chosen before any of them is quoted (see docs/THIRD_PARTY_FEEDS.md).

The dump ("online-valid", every verified phish still online, ~1-3 MB
gzipped) is rebuilt hourly on PhishTank's side, and the developer page asks
for a descriptive User-Agent and offers ETag checks. We download it at most
once in FETCH_INTERVAL_SECONDS, send If-None-Match / If-Modified-Since when
we do, and honour a longer Cache-Control max-age if one is ever sent. The
parsed hostnames are kept in one Redis hash (CACHE_KEY, zlib-packed, a few
hundred KB) so the four daily cron runs share one download. A failed
download — a non-200 answer or a raised connection error alike — uses the
cached hosts for up to STALE_MAX_SECONDS; past that the source is reported
down and the outage guard carries its names (see blocklist_feed_health).
Without a key a failed pull also holds the next try back for
RETRY_AFTER_FAILURE_SECONDS (RETRY_KEY), so a throttled day costs about two
requests, not four; with a key every run may retry.

The key never appears in a log line or an exception: the URL that carries
it is built in `feed_url` and passed only to the fetcher.
"""
from __future__ import annotations

import base64
import csv
import gzip
import io
import logging
import re
import time
import zlib
from dataclasses import dataclass, replace
from typing import Awaitable, Callable, Mapping, Optional
from urllib.parse import urlparse

logger = logging.getLogger("dangerous-domains-refresh")

KEY_ENV = "PHISHTANK_API_KEY"
# On without a key: the anonymous dump (the same file; the developer page
# limits keyless pulls to "a few downloads per day", and we make one).
SOURCE_ENV = "BLOCKLIST_PHISHTANK_SOURCE"
SOURCE_NAME = "PhishTank"
FEED_URL_TEMPLATE = "https://data.phishtank.com/data/{key}/online-valid.csv.gz"
ANON_FEED_URL = "https://data.phishtank.com/data/online-valid.csv.gz"
# The developer page requires a descriptive User-Agent and suggests
# "phishtank/<username>". We have no PhishTank account (registration is
# closed), so the agent names the product instead of looking like a username
# that may be somebody else's.
USER_AGENT = "Cleanway-blocklist/1.0 (+https://cleanway.ai)"
CACHE_KEY = "phishtank:online_valid"
FETCH_INTERVAL_SECONDS = 86_400
STALE_MAX_SECONDS = 3 * 86_400
CACHE_TTL_SECONDS = STALE_MAX_SECONDS + 86_400
# Keyless only: after a failed pull, no new try before this time (a Unix
# timestamp in RETRY_KEY). Without it each of the four daily runs would ask
# again while PhishTank throttles us. 11 h, not 12: the runs are 6 h apart and
# start a few minutes late, so this lands the next try on the second run
# after the failure — about every 12 h.
RETRY_KEY = "phishtank:keyless_retry_after"
RETRY_AFTER_FAILURE_SECONDS = 11 * 3600
_MAX_AGE = re.compile(r"max-age\s*=\s*(\d+)", re.IGNORECASE)

# (status, response headers, body). Injected so the job's httpx code and the
# tests' canned answers look the same to this module.
Fetcher = Callable[[str, Mapping[str, str]], Awaitable[tuple[int, Mapping[str, str], bytes]]]


@dataclass(frozen=True)
class CachedDump:
    """What the last download left behind."""
    hosts: tuple[str, ...]
    fetched_at: float
    etag: str = ""
    last_modified: str = ""
    max_age: int = 0

    def next_fetch_at(self) -> float:
        return self.fetched_at + max(FETCH_INTERVAL_SECONDS, self.max_age)

    def usable_at(self, now: float) -> bool:
        return now - self.fetched_at <= STALE_MAX_SECONDS


def feed_url(key: str) -> str:
    key = key.strip()
    return FEED_URL_TEMPLATE.format(key=key) if key else ANON_FEED_URL


def parse_hosts(text: str) -> list[str]:
    """Hostnames of the `url` column, lowercase, one per row. The dump has a
    header row (phish_id,url,phish_detail_url,submission_time,…); a row
    without a URL, or whose URL has no host, is skipped."""
    out: list[str] = []
    for row in csv.DictReader(io.StringIO(text.lstrip("﻿"))):
        url = (row.get("url") or "").strip()
        if not url:
            continue
        try:
            host = (urlparse(url).hostname or "").lower().rstrip(".")
        except ValueError:
            continue
        if host:
            out.append(host)
    return out


def decompress(body: bytes) -> str:
    if body[:2] == b"\x1f\x8b":
        body = gzip.decompress(body)
    return body.decode("utf-8", errors="replace")


def parse_max_age(cache_control: Optional[str]) -> int:
    match = _MAX_AGE.search(cache_control or "")
    return int(match.group(1)) if match else 0


def conditional_headers(cached: Optional[CachedDump]) -> dict[str, str]:
    headers = {"User-Agent": USER_AGENT}
    if cached is None:
        return headers
    if cached.etag:
        headers["If-None-Match"] = cached.etag
    if cached.last_modified:
        headers["If-Modified-Since"] = cached.last_modified
    return headers


def encode(cached: CachedDump) -> dict[str, str]:
    packed = zlib.compress("\n".join(cached.hosts).encode("utf-8"), 9)
    return {
        "fetched_at": str(int(cached.fetched_at)),
        "etag": cached.etag,
        "last_modified": cached.last_modified,
        "max_age": str(int(cached.max_age)),
        "count": str(len(cached.hosts)),
        "hosts": base64.b64encode(packed).decode("ascii"),
    }


def decode(raw: Mapping[str, str]) -> Optional[CachedDump]:
    """None for an empty or unreadable record — the next run downloads."""
    try:
        text = zlib.decompress(base64.b64decode(raw["hosts"])).decode("utf-8")
        return CachedDump(
            hosts=tuple(h for h in text.split("\n") if h),
            fetched_at=float(raw["fetched_at"]),
            etag=str(raw.get("etag", "") or ""),
            last_modified=str(raw.get("last_modified", "") or ""),
            max_age=int(raw.get("max_age", 0) or 0),
        )
    except (KeyError, ValueError, TypeError, zlib.error):
        return None


async def load(r) -> Optional[CachedDump]:
    """The cached dump, or None. Never raises: a Redis blip costs one
    download, not the source."""
    if r is None:
        return None
    try:
        raw = await r.hgetall(CACHE_KEY)
    except Exception as e:  # noqa: BLE001
        logger.warning("PhishTank cache unreadable (%s) — downloading", e)
        return None
    return decode(raw) if raw else None


async def save(r, cached: CachedDump) -> None:
    if r is None:
        return
    try:
        pipe = r.pipeline(transaction=True)
        pipe.delete(CACHE_KEY)
        pipe.hset(CACHE_KEY, mapping=encode(cached))
        pipe.expire(CACHE_KEY, CACHE_TTL_SECONDS)
        await pipe.execute()
    except Exception as e:  # noqa: BLE001
        logger.warning("PhishTank cache not saved (%s) — the next run downloads again", e)


def _utc(ts: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))


async def _retry_after(r) -> float:
    """When a keyless pull may be tried again; 0 when nothing holds it.
    Never raises: a Redis blip costs one download, as in load()."""
    if r is None:
        return 0.0
    try:
        raw = await r.get(RETRY_KEY)
        return float(raw) if raw else 0.0
    except Exception as e:  # noqa: BLE001
        logger.warning("PhishTank retry time unreadable (%s) — trying the download", e)
        return 0.0


async def _hold_off(r, now: float) -> None:
    """Note a failed keyless pull so the next runs do not repeat it before
    RETRY_AFTER_FAILURE_SECONDS. The stored time decides; the key's TTL
    (an hour longer) only clears it away. Without Redis (a measurement's
    dry build) there is nothing to hold."""
    if r is None:
        return
    retry_at = now + RETRY_AFTER_FAILURE_SECONDS
    try:
        await r.set(RETRY_KEY, str(int(retry_at)), ex=RETRY_AFTER_FAILURE_SECONDS + 3600)
    except Exception as e:  # noqa: BLE001
        logger.warning("PhishTank retry time not saved (%s) — the next run may try again", e)
        return
    logger.info("PhishTank: keyless download failed — next try after %s", _utc(retry_at))


def _cached_or_raise(cached: Optional[CachedDump], now: float, reason: str) -> list[str]:
    if cached is not None and cached.usable_at(now):
        logger.warning("PhishTank: %s — using the cached dump from %s", reason, _utc(cached.fetched_at))
        return list(cached.hosts)
    raise RuntimeError(f"PhishTank: {reason}, and no usable cache")


async def fetch_hosts(r, key: str, now: float, fetch: Fetcher, dry_run: bool = False) -> list[str]:
    """The dump's hostnames for this run: from the cache while it is fresh,
    else one conditional download. Raises when nothing usable came back —
    the caller records the source as down, like any other feed.

    Without a key a failed pull (an error, a non-200/304 answer, an empty
    dump) also holds the next try back for RETRY_AFTER_FAILURE_SECONDS;
    meanwhile the cached dump serves while usable, and past that the source
    is down without another request. A dry run reads that hold but never
    writes it, as it never writes the cache."""
    cached = await load(r)
    if cached is not None and now < cached.next_fetch_at():
        logger.info("PhishTank: cached dump from %s (%d hosts), next download after %s",
                    _utc(cached.fetched_at), len(cached.hosts), _utc(cached.next_fetch_at()))
        return list(cached.hosts)

    keyless = not key.strip()
    if keyless:
        retry_at = await _retry_after(r)
        if now < retry_at:
            return _cached_or_raise(cached, now, f"the last keyless download failed; next try after {_utc(retry_at)}")

    pulled = False
    try:
        hosts, pulled = await _download(r, key, now, fetch, cached, dry_run)
        return hosts
    finally:
        if keyless and not pulled and not dry_run:
            await _hold_off(r, now)


async def _download(r, key: str, now: float, fetch: Fetcher, cached: Optional[CachedDump],
                    dry_run: bool) -> tuple[list[str], bool]:
    """(hosts, True) after a good answer (200 with hosts, or 304), (cached
    hosts, False) when a failed one fell back on the cache; raises when it
    could not."""
    try:
        status, headers, body = await fetch(feed_url(key), conditional_headers(cached))
    except Exception as e:  # noqa: BLE001
        # A timeout or a refused connection is no different from a throttled
        # answer: the cached dump carries the day while it is usable. Only
        # the exception's type is logged — its message may quote the URL.
        if cached is not None and cached.usable_at(now):
            logger.warning("PhishTank: download failed (%s) — using the cached dump from %s",
                           type(e).__name__, _utc(cached.fetched_at))
            return list(cached.hosts), False
        raise
    lower = {str(k).lower(): str(v) for k, v in dict(headers).items()}
    if status == 304 and cached is not None:
        fresh = replace(cached, fetched_at=now, max_age=parse_max_age(lower.get("cache-control")))
        logger.info("PhishTank: dump unchanged since %s (304), %d hosts", _utc(cached.fetched_at), len(fresh.hosts))
        if not dry_run:
            await save(r, fresh)
        return list(fresh.hosts), True
    if status == 200:
        hosts = parse_hosts(decompress(body))
        if not hosts:
            raise ValueError("PhishTank dump parsed to no hosts")
        fresh = CachedDump(hosts=tuple(dict.fromkeys(hosts)), fetched_at=now, etag=lower.get("etag", ""),
                           last_modified=lower.get("last-modified", ""),
                           max_age=parse_max_age(lower.get("cache-control")))
        logger.info("PhishTank: downloaded %d URLs (%d distinct hosts)", len(hosts), len(fresh.hosts))
        if not dry_run:
            await save(r, fresh)
        return list(fresh.hosts), True
    if cached is not None and cached.usable_at(now):
        logger.warning("PhishTank: download answered HTTP %d — using the cached dump from %s",
                       status, _utc(cached.fetched_at))
        return list(cached.hosts), False
    raise RuntimeError(f"PhishTank download answered HTTP {status} and no usable cache")

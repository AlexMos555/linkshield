"""Hosts our own checks confirmed as dangerous from threat intelligence.

Why: the phone's blocklist is built only from bulk public feeds, and those
miss most fresh phishing (measured 2026-09-25: the list covered 11% of an
independent 30-day TweetFeed sample). The analyzer behind /check already asks
Google Safe Browsing, URLhaus, ThreatFox and others about every host a person
checks, and GSB caught both fresh phishing hosts in that test the list did
not. That knowledge died in a 24-hour result cache. This module keeps it: a
host whose DANGEROUS verdict rests on a threat-intel hit is recorded, and the
blocklist publisher (scripts/refresh_dangerous_domains.py) ships it to every
phone through the same false-positive guards as a feed host.

Heuristic verdicts (young domain, missing headers, lookalike name, the LLM
judge) never qualify — a guess must not become a DNS block on every phone.
Only the sources in INTEL_SIGNALS count, and only when the final verdict is
dangerous.

Storage — one Redis sorted set, CONFIRMED_KEY:
  member = the checked host (lowercase, no trailing dot),
  score  = unix time it was last confirmed.
Capped at CONFIRMED_MAX members (oldest dropped first) so request volume
cannot grow it without bound. No user, IP or URL is stored — only the host,
which the threat-intel provider already lists as dangerous.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Mapping, Optional

logger = logging.getLogger("cleanway.confirmed_threats")

CONFIRMED_KEY = "dangerous_domains:confirmed"

# Signals from sources that list a host because it IS malicious (a verified
# report or a malware URL), not because it looks odd. Deliberately absent:
# PhishStats (substring match — "bank.com" matches "evilbank.com"), Spamhaus
# DBL and SURBL (spam listings, non-commercial terms), AlienVault OTX (pulse
# counts — our measured false-positive source), IPQualityScore (a score).
INTEL_SIGNALS = (
    "safe_browsing_hit",
    "phishtank_hit",
    "urlhaus_hit",
    "threatfox_hit",
    "malware_bazaar_hit",
    "feodo_hit",
)

# A confirmation keeps a host "listed by us" for a week; after that it
# behaves like any host that left a feed (blocklist_retention decides).
CONFIRMED_WINDOW_SECONDS = 7 * 86_400
# ~6 bytes per name on every phone; 20k is ~120 KB of artifact at worst.
CONFIRMED_MAX = 20_000
# Entries past the window are kept this much longer so the publisher can
# still tell "expired confirmation" from "left a feed" if a publish fails.
EXPIRED_GRACE_SECONDS = 2 * 86_400
KEY_TTL_SECONDS = CONFIRMED_WINDOW_SECONDS + EXPIRED_GRACE_SECONDS + 86_400
# The analyzer's answer must never wait on this bookkeeping.
RECORD_TIMEOUT_S = 0.25


def intel_sources(signals: Mapping) -> tuple:
    """The threat-intel sources that flagged this host."""
    return tuple(name for name in INTEL_SIGNALS if signals.get(name))


def should_record(level: str, signals: Mapping) -> bool:
    """True only for a dangerous verdict backed by threat intel."""
    return level == "dangerous" and bool(intel_sources(signals))


def normalize_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


async def record(r, host: str, now: float) -> None:
    """Upsert the host with `now`, trim to the cap, refresh the key TTL."""
    pipe = r.pipeline(transaction=True)
    pipe.zadd(CONFIRMED_KEY, {host: int(now)})
    pipe.zremrangebyrank(CONFIRMED_KEY, 0, -(CONFIRMED_MAX + 1))
    pipe.expire(CONFIRMED_KEY, KEY_TTL_SECONDS)
    await pipe.execute()


async def record_if_confirmed(host: str, level: str, signals: Mapping,
                              now: Optional[float] = None) -> bool:
    """Record `host` when its verdict qualifies. Never raises and never
    delays the caller by more than RECORD_TIMEOUT_S. True if recorded."""
    name = normalize_host(host)
    if not name or not should_record(level, signals):
        return False
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        await asyncio.wait_for(record(r, name, time.time() if now is None else now), RECORD_TIMEOUT_S)
        logger.info("confirmed_threat_recorded", extra={"sources": list(intel_sources(signals))})
        return True
    except Exception:  # noqa: BLE001
        logger.warning("confirmed threat not recorded (redis unavailable)", exc_info=True)
        return False


async def load(r) -> dict[str, float]:
    """The whole set — small by construction (capped)."""
    rows = await r.zrange(CONFIRMED_KEY, 0, -1, withscores=True)
    return {str(name): float(score) for name, score in rows}


def split(entries: Mapping[str, float], now: float,
          window_seconds: int = CONFIRMED_WINDOW_SECONDS) -> tuple[set, set]:
    """(active, expired): confirmed inside the window vs. before it."""
    cutoff = now - window_seconds
    active = {name for name, seen in entries.items() if seen >= cutoff}
    return active, set(entries) - active


async def prune(r, now: float) -> None:
    """Forget confirmations older than the window plus the grace period."""
    cutoff = int(now) - CONFIRMED_WINDOW_SECONDS - EXPIRED_GRACE_SECONDS
    await r.zremrangebyscore(CONFIRMED_KEY, "-inf", f"({cutoff}")

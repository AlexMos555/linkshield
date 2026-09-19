"""Keep a blocklist name for a while after the feeds stop listing it.

Why: every refresh rebuilt the DNS blocklist ONLY from what the four feeds
contain at that moment. OpenPhish's free feed is a rolling window of ~300 URLs
republished every 12 h; over 100 snapshots (2026-08-01..09-19) a median 21.5%
of its hosts were still listed 12 h later and 3% four days later. So a
phishing host rotated out — and off every phone — while the site was still
up. Measured 2026-09-19: of 33 OpenPhish-covered brand-phishing hosts on the
list on 2026-09-15, 10 had dropped off while still answering HTTP 200/403
(securebankofamerica.vercel.app, open-instagram.vercel.app, …).

Storage — one Redis sorted set, LAST_SEEN_KEY:
  member = a published name that NO feed backs any more,
  score  = unix time of the first refresh that no longer saw it (at most one
           cron interval after it was last seen).
Names still in a feed are deliberately NOT stored: their last-seen time is
"now" by definition, and storing all ~500k feed hosts would cost an estimated
~60 MB in a Redis that has already evicted the phone artifact once. Only
departures are stored: ~1.2k artifact names left per day over the 39 publishes
of 2026-09-09..19, so on the order of 20k members at a 14-day window.

The refresh job feeds retained names back into build_blockset as ordinary
hosts, so every false-positive guard (popular veto, shared-tenant rules,
operator suffixes, hostname syntax) re-applies to them on every run.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Mapping, Optional

from api.services.blocklist_artifact import LIST_CANARY

logger = logging.getLogger("dangerous-domains-refresh")

LAST_SEEN_KEY = "dangerous_domains:last_seen"
RETAIN_DAYS_ENV = "BLOCKLIST_RETAIN_DAYS"

# The trade-off behind the window. Longer = fewer live phishing sites
# un-blocked when a rolling feed forgets them, but also longer-lived false
# positives, more parked or re-registered domains held dark after the
# phisher is gone, and a bigger artifact for every phone (~6 bytes a name).
# 14 days covers the observed case (all 10 still-live hosts had left OpenPhish
# 4 days earlier) while most phishing sites die within days anyway.
DEFAULT_RETAIN_DAYS = 14
# Past two months a retained name is more likely a re-registered domain than
# the phishing site that got it listed.
MAX_RETAIN_DAYS = 60
# The key outlives the window, so a dead cron cannot leave it behind forever.
TTL_MARGIN_SECONDS = 7 * 86_400
WRITE_BATCH = 5_000
SECONDS_PER_DAY = 86_400


@dataclass(frozen=True)
class RetentionPlan:
    retained: frozenset   # names no feed lists now but still inside the window
    departed: frozenset   # newly missing from the feeds — record with `now`
    returned: frozenset   # back in a feed — forget, their clock restarts later
    cutoff: int           # prune everything last seen before this


def retain_days_from_env(raw: Optional[str]) -> int:
    """RETAIN_DAYS from the environment. An invalid value falls back to the
    default with a warning — a typo must not stop the blocklist publishing."""
    if raw is None or not raw.strip():
        return DEFAULT_RETAIN_DAYS
    try:
        days = int(raw.strip())
    except ValueError:
        days = -1
    if not 0 <= days <= MAX_RETAIN_DAYS:
        logger.warning("%s=%r is not a whole number of days in [0, %d] — using %d",
                       RETAIN_DAYS_ENV, raw, MAX_RETAIN_DAYS, DEFAULT_RETAIN_DAYS)
        return DEFAULT_RETAIN_DAYS
    return days


def plan_retention(stored: Mapping[str, float], previous: set, present: set,
                   now: float, window_seconds: int) -> RetentionPlan:
    """Decide what to keep, record, forget and prune — no I/O.

    `stored` is the sorted set as read; `previous` the live published set;
    `present` every name a current feed still backs. A name already stored
    keeps its first-departure time: re-stamping it each run would retain it
    forever.
    """
    cutoff = int(now) - window_seconds
    departed = set(previous) - set(present) - set(stored) - {LIST_CANARY}
    returned = set(stored) & set(present)
    kept = {name for name, seen in stored.items() if seen >= cutoff and name not in present}
    return RetentionPlan(
        retained=frozenset(kept | departed),
        departed=frozenset(departed),
        returned=frozenset(returned),
        cutoff=cutoff,
    )


async def load_last_seen(r) -> dict[str, float]:
    """The whole sorted set — small by construction (departures only)."""
    rows = await r.zrange(LAST_SEEN_KEY, 0, -1, withscores=True)
    return {str(name): float(score) for name, score in rows}


async def save_plan(r, plan: RetentionPlan, now: float, window_seconds: int) -> None:
    """Record departures, forget returns, prune, refresh the TTL in one
    MULTI/EXEC. Raises on any failure; the caller then publishes from the
    feeds alone. A partly applied write is harmless: departures are recorded
    with NX, so the next run keeps their first timestamp."""
    pipe = r.pipeline(transaction=True)
    departed = sorted(plan.departed)
    for i in range(0, len(departed), WRITE_BATCH):
        pipe.zadd(LAST_SEEN_KEY, {name: int(now) for name in departed[i:i + WRITE_BATCH]}, nx=True)
    returned = sorted(plan.returned)
    for i in range(0, len(returned), WRITE_BATCH):
        pipe.zrem(LAST_SEEN_KEY, *returned[i:i + WRITE_BATCH])
    pipe.zremrangebyscore(LAST_SEEN_KEY, "-inf", f"({plan.cutoff}")
    pipe.expire(LAST_SEEN_KEY, window_seconds + TTL_MARGIN_SECONDS)
    await pipe.execute()

"""Notice when a blocklist feed goes missing, and do not publish around it.

Why: every refresh rebuilt the list from whatever the feeds returned. When a
feed failed to download, its names simply were not there, and the publish
gate did not notice: measured 2026-09-25, a run without phishing.army changes
the set by 28.9% — under the 50% churn gate — while dropping coverage of
fresh PhishTank phishing from ~73% to ~1%. Retention (blocklist_retention)
already refused to record such an outage as departures, but the names were
still missing from the set that run published. A feed that answers but comes
back a fraction of its usual size (a truncated file, an HTML error page, a
format change) looked perfectly healthy.

What this module decides (no I/O in `assess`):
  * a feed is DEGRADED when its download failed, when it parsed to no hosts
    at all after having some, or when a big feed parsed to less than
    SHRINK_FLOOR of the size it had on its last healthy run;
  * while any feed is degraded, the refresh job keeps every published name
    that no healthy feed backs any more (the "carry"), for at most
    CARRY_MAX_SECONDS of outage;
  * an outage older than ALERT_AFTER_SECONDS makes the job exit non-zero
    after publishing, so the run goes red and GitHub mails the owner.

Storage (two small Redis hashes, one field per feed):
  FEED_COUNTS_KEY      feed -> distinct hosts on its last healthy run
  FEED_DOWN_SINCE_KEY  feed -> unix time of the first degraded run of the
                       current outage (removed when the feed is healthy again)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Mapping, Optional

logger = logging.getLogger("dangerous-domains-refresh")

FEED_COUNTS_KEY = "dangerous_domains:feed_counts"
FEED_DOWN_SINCE_KEY = "dangerous_domains:feed_down_since"

# Below half its last healthy size a feed is treated as down. Real day-to-day
# movement of the big aggregates is a few percent; a halving is breakage.
SHRINK_FLOOR = 0.5
# Small rolling feeds (OpenPhish ~300 URLs, the CSIRT Italia MISP window)
# swing by more than half on an ordinary day. Shrinkage is only judged for a
# feed that normally carries at least this many hosts.
MIN_BASELINE = 1_000
# …but any feed that had at least this many hosts and now parses to none is
# down (OpenPhish answering with an HTML page parses to zero URLs).
EMPTY_MIN_BASELINE = 20
# One failed run can be weather (a 502 from a CDN). Two runs in a row — the
# cron is every 6 h — is an outage someone should look at.
ALERT_AFTER_SECONDS = 12 * 3600
# Carrying a dead feed's names forever would freeze them in the list. After
# the same window retention uses, the carry stops and its names depart.
CARRY_MAX_SECONDS = 14 * 86_400
# The state keys outlive any outage we would still act on.
STATE_TTL_SECONDS = CARRY_MAX_SECONDS + 7 * 86_400


@dataclass(frozen=True)
class FeedHealth:
    """What this run saw. `degraded` maps feed -> human reason."""
    degraded: Mapping[str, str] = field(default_factory=dict)
    healthy_counts: Mapping[str, int] = field(default_factory=dict)
    down_since: Mapping[str, float] = field(default_factory=dict)

    def outage_seconds(self, now: float) -> float:
        """Age of the oldest ongoing outage, 0 when every feed is healthy."""
        return max((now - since for since in self.down_since.values()), default=0.0)


def assess(fetched: Mapping[str, Optional[int]], baselines: Mapping[str, int],
           down_since: Mapping[str, float], now: float,
           accept_sizes: bool = False) -> FeedHealth:
    """Classify each feed of this run. `fetched` is feed -> distinct hosts
    parsed, or None when the download failed. `accept_sizes` (the job's
    --force) takes a shrunken feed at face value — the operator has looked —
    but never excuses a failed download."""
    degraded: dict[str, str] = {}
    healthy: dict[str, int] = {}
    for feed, count in fetched.items():
        baseline = int(baselines.get(feed, 0) or 0)
        if count is None:
            degraded[feed] = "download failed"
        elif accept_sizes:
            healthy[feed] = int(count)
        elif count == 0 and baseline >= EMPTY_MIN_BASELINE:
            # Even a small feed: an empty parse of a feed that had names is
            # an error page or a format change, not a quiet day.
            degraded[feed] = f"returned no hosts (had {baseline})"
        elif baseline >= MIN_BASELINE and count < SHRINK_FLOOR * baseline:
            degraded[feed] = f"shrank from {baseline} to {count} hosts"
        else:
            healthy[feed] = int(count)
    since = {feed: float(down_since.get(feed, now)) for feed in degraded}
    return FeedHealth(degraded=degraded, healthy_counts=healthy, down_since=since)


def carry_names(previous: set, present: set, protected: set) -> set:
    """Published names nothing backs this run: what a degraded feed took with
    it. `protected` (the list canary) is re-added by the job anyway."""
    return set(previous) - set(present) - set(protected)


async def load_state(r) -> tuple[dict[str, int], dict[str, float]]:
    """(baselines, down_since). Raises on a Redis failure — the caller then
    judges sizes without baselines and cannot carry."""
    counts = await r.hgetall(FEED_COUNTS_KEY) or {}
    since = await r.hgetall(FEED_DOWN_SINCE_KEY) or {}
    return ({str(k): int(v) for k, v in counts.items()},
            {str(k): float(v) for k, v in since.items()})


async def save_state(r, health: FeedHealth) -> None:
    """Record healthy sizes, open/keep outages, close the ones that ended —
    in one MULTI/EXEC. A degraded feed keeps its old baseline: a broken run
    must never become the yardstick for the next one."""
    pipe = r.pipeline(transaction=True)
    if health.healthy_counts:
        pipe.hset(FEED_COUNTS_KEY, mapping={k: str(v) for k, v in health.healthy_counts.items()})
        pipe.hdel(FEED_DOWN_SINCE_KEY, *sorted(health.healthy_counts))
    if health.down_since:
        pipe.hset(FEED_DOWN_SINCE_KEY, mapping={k: str(int(v)) for k, v in health.down_since.items()})
    pipe.expire(FEED_COUNTS_KEY, STATE_TTL_SECONDS)
    pipe.expire(FEED_DOWN_SINCE_KEY, STATE_TTL_SECONDS)
    await pipe.execute()

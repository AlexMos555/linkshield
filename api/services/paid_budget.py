"""Service-wide daily caps on the paid / quota-bound sources of an analysis.

A fresh analysis may call IPQualityScore (5,000 lookups a month on the free
plan) and, in the caution band, Claude (the LLM judge). Per-IP and
per-install limits bound ONE caller, never the sum of all of them — and the
install id is unauthenticated, so a single address rotating random ids gets
up to its per-IP ceiling (1500 fresh analyses an hour). These counters cap
how many such calls the whole service makes per UTC day; past the cap the
source is skipped and the verdict rests on the other checks, as it already
does when the source has no key.

One Redis INCR per paid call, under a day-stamped key that expires after two
days. With Redis unavailable the policy follows `rate_limit_fail_closed`:
production fails closed (skips the paid source), dev and tests fail open.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from api.config import get_settings

logger = logging.getLogger("cleanway.paid_budget")

_KEY_TTL_SECONDS = 2 * 24 * 60 * 60


def _key(source: str) -> str:
    return f"paid_budget:{source}:{datetime.now(timezone.utc):%Y-%m-%d}"


async def take(source: str, daily_limit: int) -> bool:
    """Claim one call of `source` from today's budget. True = go ahead."""
    if daily_limit <= 0:
        return False
    try:
        from api.services.cache import get_redis
        from api.services.rate_limiter import _incr_with_ttl_on_first
        r = await get_redis()
        used = await _incr_with_ttl_on_first(r, _key(source), _KEY_TTL_SECONDS)
    except Exception:
        fail_closed = get_settings().rate_limit_fail_closed
        logger.warning("paid_budget_unavailable", extra={"source": source, "fail_closed": fail_closed})
        return not fail_closed
    if used > daily_limit:
        if used == daily_limit + 1:  # once a day, not on every skipped call
            logger.warning("paid_budget_exhausted", extra={"source": source, "limit": daily_limit})
        return False
    return True

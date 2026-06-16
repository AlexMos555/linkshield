"""Tranco top-1M popularity signal — Strategy doc Top-20 #14.

Tranco (https://tranco-list.eu/) publishes a daily ranking of the
top 1,000,000 most-popular domains, averaged over 30 days from
the four major lists (Alexa/Umbrella/Majestic/Quantcast). A
domain that's been in the top 100k for a month is, with very
high confidence, NOT a phishing landing page — phishing kits
churn through fresh domains because takedown is fast.

Why this matters for Cleanway:

  * We currently have NO popularity signal. A brand-new domain
    looks the same as `wikipedia.org` to our scoring engine.
    Combining brand-clone detection with a popularity floor is
    the single biggest false-positive reducer available.
  * Other vendors charge for this. Tranco is free, MIT-licensed.

How we use the rank:

  * rank ≤ 1,000      → very-trusted, -25 pts
  * rank ≤ 10,000     → trusted, -15 pts
  * rank ≤ 100,000    → reputable, -8 pts
  * rank ≤ 1,000,000  → known-public, -3 pts
  * unknown / unranked → no signal (0 pts)

Negative weights pull the score DOWN — popularity is a trust
signal, not a danger signal. Phishing campaigns can still target
top-ranked domains via subdomain takeover; the rank should never
be the SOLE reason to call something safe. But it dampens
false-positives on legitimate-but-unfamiliar sites.

Storage:

  * Redis hash `tranco:ranks` — key=domain (lowercase, idna),
    value=rank (int as string).
  * Refresh is a separate ops job (see `scripts/refresh_tranco.py`)
    that downloads the CSV and HMSETs the whole map. We do NOT
    refresh on every check — that would be a daily network call
    per pod and a 50 MB download.

Privacy:

  * Lookup is local Redis HGET on the registrable domain only.
    No external network call per check, no per-user telemetry.
  * Cleanway server never sees the user's full URL — domain only.
    This signal preserves that invariant.
"""

from __future__ import annotations

import logging
from typing import Optional

from api.services.cache import get_redis

logger = logging.getLogger(__name__)

# Score deltas keyed by the maximum rank that qualifies for the
# tier. Iterate in ascending order; first match wins.
TRANCO_TIERS: tuple[tuple[int, int, str], ...] = (
    (1_000, -25, "in the worldwide top 1,000 most-visited sites"),
    (10_000, -15, "in the worldwide top 10,000 most-visited sites"),
    (100_000, -8, "in the worldwide top 100,000 most-visited sites"),
    (1_000_000, -3, "in the public top 1,000,000 domains"),
)


async def get_tranco_rank(domain: str) -> Optional[int]:
    """Return the Tranco rank for `domain`, or None if not ranked.

    The lookup never raises — Redis errors return None so the
    caller treats the domain as un-ranked and the scoring engine
    simply skips this signal. However, Redis OUTAGES log at
    WARNING (not DEBUG) so a sustained outage is visible in
    production logs and Sentry catches the breadcrumb — silent
    DEBUG-only logging hid Redis-down behind a "0% popularity
    coverage" symptom that looked like benign cache miss.
    """
    domain_key = (domain or "").strip().lower()
    if not domain_key:
        return None
    try:
        r = await get_redis()
        raw = await r.hget("tranco:ranks", domain_key)
        if raw is None:
            return None
        return int(raw)
    except Exception as exc:
        # WARNING — Redis errors here are operational signals, not
        # routine misses. The circuit breaker also bails out via the
        # check_tranco_popularity path, but only when the exception
        # PROPAGATES; this swallow happens before then, hence the
        # log promotion.
        logger.warning("tranco rank lookup failed for %s: %s", domain_key, exc)
        return None


async def check_tranco_popularity(domain: str) -> dict:
    """Parallel-check entry point. Returns the scoring contribution.

    Output shape:
        {
          "ranked": bool,
          "rank": int | None,
          "weight": int,   # negative for popular domains
          "label": str,    # human-readable explanation, or ""
        }

    Always returns a dict (never raises). The analyzer wraps this
    call in `tranco_breaker.call(...)` so a Redis outage still
    yields {"ranked": False, "weight": 0} via the breaker fallback.
    """
    rank = await get_tranco_rank(domain)
    if rank is None or rank <= 0:
        return {"ranked": False, "rank": None, "weight": 0, "label": ""}
    for threshold, delta, label in TRANCO_TIERS:
        if rank <= threshold:
            return {
                "ranked": True,
                "rank": rank,
                "weight": delta,
                "label": label,
            }
    # Rank > 1,000,000 — shouldn't happen because the list IS top-1M
    # but treat as un-ranked for safety.
    return {"ranked": False, "rank": rank, "weight": 0, "label": ""}

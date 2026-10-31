"""Top-1M popularity signal — Strategy doc Top-20 #14.

Cleanway's popularity ranking (scripts/build_top_domains.py): the Majestic
Million (CC BY 3.0, registrable domains ranked by linking IP subnets) and
the Chrome UX Report top origins (CC BY 4.0, ranked by Chrome page loads;
Russia's list counted too), merged by the Dowdall rule into one rank. Its
first 100,000 names are data/top_100k.json (the allowlist); its first
1,000,000 are the Redis hash this module reads. A domain that many sites
link to and many people open is, with very high confidence, NOT a phishing
landing page — phishing kits churn through fresh domains because takedown
is fast.

The module, the Redis key and the signal names (tranco_ranked,
tranco_weight, the reason code tranco_popularity) keep the name of the list
they replaced: Tranco until 2026-10-23, whose default list averages
Cloudflare Radar (CC BY-NC 4.0) and so could not stay in a paid product
(docs/THIRD_PARTY_FEEDS.md §2a). Clients map the reason code to
'popular_site'; renaming it would break the ones already installed.

Why this matters for Cleanway:

  * Without a popularity signal a brand-new domain looks the same as
    `wikipedia.org` to the scoring engine. Combining brand-clone detection
    with a popularity floor is the single biggest false-positive reducer
    available.

How we use the rank (positions in the ranking, the same thresholds as with
Tranco):

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
  * Refresh is a separate ops job (`scripts/refresh_tranco.py`, daily)
    that builds the ranking and HSETs the whole map. We do NOT refresh on
    every check — that would be a daily network call per pod and a
    ~100 MB download.

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
# The labels say "popular", not "most-visited": half of the rank is links
# (Majestic), half page loads (CrUX).
TRANCO_TIERS: tuple[tuple[int, int, str], ...] = (
    (1_000, -25, "among the 1,000 most popular sites worldwide"),
    (10_000, -15, "among the 10,000 most popular sites worldwide"),
    (100_000, -8, "among the 100,000 most popular sites worldwide"),
    (1_000_000, -3, "among the 1,000,000 most popular sites worldwide"),
)


async def get_tranco_rank(domain: str) -> Optional[int]:
    """Return the popularity rank for `domain`, or None if not ranked.

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
    registrable_rank = await _registrable_rank(domain, rank)
    if rank is None or rank <= 0:
        return {"ranked": False, "rank": None, "weight": 0, "label": "", "registrable_rank": registrable_rank}
    for threshold, delta, label in TRANCO_TIERS:
        if rank <= threshold:
            return {
                "ranked": True,
                "rank": rank,
                "weight": delta,
                "label": label,
                "registrable_rank": registrable_rank,
            }
    # Rank > 1,000,000 — shouldn't happen because the hash holds the top
    # 1M only, but treat as un-ranked for safety.
    return {"ranked": False, "rank": rank, "weight": 0, "label": "", "registrable_rank": registrable_rank}


async def _registrable_rank(domain: str, host_rank: Optional[int]) -> Optional[int]:
    """The rank of the name's registrable domain (the host's own when it is
    one). The bonus above stays the HOST's — a subdomain is not its parent —
    but the scorer reads this one where a popular registrable changes what
    a signal means: an AlienVault OTX mention of a top-1M site is a victim
    reference far more often than a verdict, and gitlab.<bank>.ru is the
    bank's own GitLab (scoring.calculate_score).

    The registrable domain whose rank this is: scoring.rank_registrable_domain
    — never a zone above the registrant (co.ua for evil.co.ua)."""
    from api.services.scoring import rank_registrable_domain

    registrable = rank_registrable_domain((domain or "").strip().lower())
    if not registrable or registrable == (domain or "").strip().lower():
        return host_rank if host_rank and host_rank > 0 else None
    rank = await get_tranco_rank(registrable)
    return rank if rank and rank > 0 else None


async def popularity_status(r=None) -> dict:
    """What the live Redis rank was built from (tranco:ranks:meta, written by
    scripts/refresh_tranco.py) — /health/deep components.popularity. A
    cache Tranco filled has no meta: `ok` is false until the licensed
    refresh has run."""
    import json

    try:
        r = r or await get_redis()
        raw = await r.get("tranco:ranks:meta")
    except Exception as exc:  # noqa: BLE001 — health is informational
        return {"ok": False, "error": type(exc).__name__}
    if not raw:
        return {"ok": False, "source": None, "detail": "no tranco:ranks:meta — the ranks predate the licensed refresh"}
    try:
        meta = json.loads(raw)
    except ValueError:
        return {"ok": False, "error": "unreadable tranco:ranks:meta"}
    out = {k: meta.get(k) for k in ("source", "built", "names", "crux_months")}
    out["ok"] = meta.get("source") == "majestic+crux"
    return out

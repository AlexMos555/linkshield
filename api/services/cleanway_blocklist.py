"""Is a host on Cleanway's own published blocklist?

The phone blocked gosuslugee.ru, while a manual check of the same address
said only "caution, 25" — the check never looked at our own list (report
2026-09-25 #9). Now it does, first, and a listed host is 'dangerous'
immediately, with reason `cleanway_blocklist`.

"Our list" is the `dangerous_domains` set the DoH gateway answers from. The
refresh job writes it in the SAME Redis transaction as the phone's artifact,
so the check, the DNS profile and the phone cannot disagree; the lookup is
the gateway's own suffix walk (a listed name covers all its subdomains).
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger("cleanway.cleanway_blocklist")

_LIST_KEY = "dangerous_domains"


async def listed_as(domain: str) -> Optional[str]:
    """The listed name that covers `domain` — itself or the nearest listed
    parent — or None.

    The gateway's own suffix walk (doh_gateway.block_candidates, longest
    first), in one pipelined Redis round-trip; returning WHICH name matched
    lets the verdict say when a host is covered only through a parent.
    Fails open (None) when Redis is unavailable: the full analysis still
    runs, and a missed listing is better than a check that errors.
    """
    try:
        from api.services.cache import get_redis
        from api.services.doh_gateway import block_candidates
        candidates = block_candidates(domain)
        if not candidates:
            return None
        r = await get_redis()
        pipe = r.pipeline()
        for name in candidates:
            pipe.sismember(_LIST_KEY, name)
        found = await pipe.execute()
    except Exception:
        logger.debug("cleanway blocklist lookup failed", exc_info=True)
        return None
    return next((name for name, hit in zip(candidates, found) if hit), None)


async def is_listed(domain: str) -> bool:
    """True when `domain` or one of its parent names is on the list."""
    return await listed_as(domain) is not None

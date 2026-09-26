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

logger = logging.getLogger("cleanway.cleanway_blocklist")


async def is_listed(domain: str) -> bool:
    """True when `domain` or one of its parent names is on the list.

    One pipelined Redis round-trip. Fails open (False) when Redis is
    unavailable: the full analysis still runs, and a missed listing is
    better than a check that errors.
    """
    try:
        from api.services.cache import get_redis
        from api.services.doh_gateway import is_blocked_redis
        r = await get_redis()
        return await is_blocked_redis(domain, r)
    except Exception:
        logger.debug("cleanway blocklist lookup failed", exc_info=True)
        return False

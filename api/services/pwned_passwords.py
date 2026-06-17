"""Pwned-passwords k-anonymity lookup — Strategy doc Top-20 #13.

We proxy Have I Been Pwned's Pwned Passwords API
(https://api.pwnedpasswords.com/range/{first5}) so the extension
can ask "is this password in any known breach?" without ever
sending the full hash off the user's device.

The k-anonymity contract:

  * Extension hashes the password with SHA-1
  * Extension sends only the first 5 hex chars of the hash to Cleanway
  * Cleanway proxies that prefix to api.pwnedpasswords.com
  * HIBP returns a list of ~500 SUFFIXES that share that prefix,
    each annotated with a breach-count
  * Extension matches the suffix locally
  * Cleanway server NEVER sees the suffix the user actually typed,
    let alone the full hash

Why proxy at all (vs the extension calling HIBP directly):

  * Caching — popular prefix queries dominate the distribution.
    We serve a 24h Redis cache so the 80th-percentile request is
    sub-10ms instead of ~150ms WAN.
  * CSP — adding api.pwnedpasswords.com to the extension's
    `connect-src` enlarges the trust list for every page.
    Routing through api.cleanway.ai keeps the extension's CSP
    list small and audited.
  * Rate-limit absorption — if HIBP raises their rate ceiling,
    we move that decision to the server side without re-shipping
    the extension.

Privacy invariants:

  * Server only ever sees the 5-char prefix. No fingerprint.
  * No per-request logging of the prefix to non-Redis surfaces
    (no Sentry breadcrumb, no Datadog tag).
  * Cache key is the prefix itself — there's nothing else to leak.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

import httpx

from api.services.cache import get_redis

logger = logging.getLogger(__name__)

HIBP_BASE = "https://api.pwnedpasswords.com/range/"
HIBP_TIMEOUT_S = 4.0
CACHE_TTL_S = 24 * 60 * 60
PREFIX_RE = re.compile(r"^[A-Fa-f0-9]{5}$")
# HIBP recommends sending this header so they can return the
# padded form (random pad suffixes so a network observer can't
# infer "how many real matches" by counting the response size).
HIBP_HEADERS = {
    "Add-Padding": "true",
    "User-Agent": "Cleanway-pwned-passwords/1.0 (+https://cleanway.ai)",
}


def _is_valid_prefix(prefix: str) -> bool:
    """Strict whitelist on the input. Anything outside [0-9A-F]{5}
    is refused at the perimeter — protects HIBP from us spamming
    garbage and protects us from log-injection via the cache key."""
    return bool(prefix and PREFIX_RE.match(prefix))


async def fetch_hibp_range(prefix: str) -> Optional[str]:
    """Fetch the raw suffix list for a 5-char hash prefix.

    Returns the body string (multiple lines, each
    `<35-char-suffix>:<count>`) or None on any failure. Caller
    splits and parses.
    """
    if not _is_valid_prefix(prefix):
        return None
    prefix_upper = prefix.upper()

    # L1: Redis cache. We index by lower-case prefix for case
    # consistency (HIBP itself is case-insensitive).
    cache_key = f"pwned:range:{prefix_upper}"
    try:
        r = await get_redis()
        cached = await r.get(cache_key)
        if cached:
            return cached
    except Exception:
        r = None

    # L2: HIBP live fetch.
    try:
        async with httpx.AsyncClient(
            timeout=HIBP_TIMEOUT_S, headers=HIBP_HEADERS,
        ) as client:
            resp = await client.get(HIBP_BASE + prefix_upper)
            if resp.status_code != 200:
                # NB: deliberately do NOT log the prefix — it would
                # surface in Sentry breadcrumbs and external log
                # sinks, violating the privacy invariant documented
                # at the top of this module.
                logger.warning(
                    "pwnedpasswords HIBP returned non-200: %d",
                    resp.status_code,
                )
                return None
            body = resp.text
    except Exception as exc:
        logger.warning("pwnedpasswords HIBP fetch failed: %s", exc)
        return None

    if r is not None:
        try:
            await r.setex(cache_key, CACHE_TTL_S, body)
        except Exception:
            pass
    return body


def parse_range_body(body: str) -> dict[str, int]:
    """Parse `<suffix>:<count>` lines into a dict.

    HIBP's padding response includes lines with count=0 (random
    noise to defeat size-based traffic analysis). We KEEP those
    rows because the client also filters by exact suffix match —
    sending a partial list could turn the padding back into a
    signal. Real attackers can find the suffix list themselves
    anyway by querying HIBP directly.
    """
    out: dict[str, int] = {}
    if not body:
        return out
    for line in body.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        suffix, _, count = line.partition(":")
        suffix = suffix.strip().upper()
        if not suffix:
            continue
        try:
            out[suffix] = int(count.strip())
        except ValueError:
            continue
    return out

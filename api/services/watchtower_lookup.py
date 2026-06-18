"""Watchtower lookup hot path — Strategy doc Top-20 #17.

Called per /check request from analyzer.py: given a candidate
domain, look it up in typosquat_alerts. If a row exists AND
auto_block=true, return a positive-weight scoring contribution.

Separated from watchtower.py (which deals with the public CRUD
+ crt.sh scan) so the analyzer can import this without pulling
in httpx + the CT-log scanner. Keeps the per-request import
cost low.

The lookup hits Supabase REST with the service key. We DON'T
cache per-domain — the suspect lookup is a single indexed query
on a small table (suspects ≤ a few thousand globally) and a wrong
cache TTL could mean we keep flagging a brand-clone after the
user dismissed it.
"""

from __future__ import annotations

import logging

import httpx

from api.config import get_settings

logger = logging.getLogger(__name__)

WATCHTOWER_LOOKUP_TIMEOUT_S = 1.5


async def check_typosquat_alert(domain: str) -> dict:
    """Look up `domain` against typosquat_alerts. Returns:

        {
          "matched": bool,
          "brand": str | None,
          "variant_kind": str | None,   # typo / tld / homograph / subdomain
          "edit_distance": int | None,
          "weight": int,
        }

    Score contribution when matched:
      typo (Levenshtein ≤ 2)  → +30
      homograph               → +35  (almost always malicious)
      tld switch              → +25  (very common in low-budget kits)
      subdomain               → +20  (legit if it's brand's own subdomain
                                      tree, but we already filter brand's
                                      own domain in the scanner)
    """
    neutral = {
        "matched": False, "brand": None, "variant_kind": None,
        "edit_distance": None, "weight": 0,
    }
    domain_key = (domain or "").strip().lower()
    if not domain_key:
        return neutral

    settings = get_settings()
    if not settings.supabase_url or not settings.supabase_service_key:
        return neutral

    try:
        async with httpx.AsyncClient(timeout=WATCHTOWER_LOOKUP_TIMEOUT_S) as client:
            resp = await client.get(
                f"{settings.supabase_url}/rest/v1/typosquat_alerts",
                params={
                    "suspect_domain": f"eq.{domain_key}",
                    "auto_block": "eq.true",
                    "select": "brand_root_domain,variant_kind,edit_distance",
                    "limit": "1",
                },
                headers={
                    "apikey": settings.supabase_service_key,
                    "Authorization": f"Bearer {settings.supabase_service_key}",
                },
            )
            if resp.status_code != 200:
                return neutral
            rows = resp.json()
    except Exception as exc:
        logger.debug("watchtower lookup failed for %s: %s", domain_key, exc)
        return neutral

    if not rows:
        return neutral

    row = rows[0]
    kind = row.get("variant_kind") or ""
    weight = {
        "typo": 30,
        "homograph": 35,
        "tld": 25,
        "subdomain": 20,
    }.get(kind, 25)

    return {
        "matched": True,
        "brand": row.get("brand_root_domain"),
        "variant_kind": kind,
        "edit_distance": row.get("edit_distance"),
        "weight": weight,
    }

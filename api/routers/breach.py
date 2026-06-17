"""
Breach Monitoring API.

Uses k-anonymity to check if user's email appears in data breaches
WITHOUT sending the full email to any third party.

How k-anonymity works:
  1. Client hashes email with SHA-1
  2. Client sends only first 5 chars of hash to our API
  3. We query HIBP API with the 5-char prefix
  4. HIBP returns ~500 matching suffixes
  5. We return suffixes to client
  6. Client checks locally if their full hash is in the list
  → Server never sees the full email hash. HIBP never sees it either.

Endpoints:
  GET /api/v1/breach/check/{hash_prefix} — k-anonymity breach check
  GET /api/v1/breach/count/{hash_prefix} — just count of breaches
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
import httpx

from api.services.auth import get_optional_user
from api.services.rate_limiter import rate_limit
from api.models.schemas import AuthUser

logger = logging.getLogger("cleanway.breach")

router = APIRouter(prefix="/api/v1/breach", tags=["breach"])


@router.get(
    "/check/{hash_prefix}",
    dependencies=[Depends(rate_limit(mode="ip", category="breach_check"))],
)
async def check_breach(
    hash_prefix: str,
    user: Optional[AuthUser] = Depends(get_optional_user),
):
    """k-anonymity breach lookup.

    The client SHA-1s either a password (Strategy doc #13) or an
    email and sends only the first 5 hex chars of the hash. We
    proxy to HIBP's free /range API, cache the response in Redis
    24h, and return the full suffix list so the client matches on
    device. The server NEVER sees the suffix the user typed.

    We return EVERY row HIBP gives us — including the padding rows
    with count=0. Stripping those rows would defeat the response-
    padding privacy feature (a network observer could count "real
    matches" by comparing response sizes between an unpadded and a
    padded view).
    """
    from api.services.pwned_passwords import (
        _is_valid_prefix, fetch_hibp_range, parse_range_body,
    )

    prefix = (hash_prefix or "").upper().strip()
    if not _is_valid_prefix(prefix):
        raise HTTPException(400, "Hash prefix must be exactly 5 hex characters")

    body = await fetch_hibp_range(prefix)
    if body is None:
        raise HTTPException(503, "Breach check temporarily unavailable")

    suffixes_map = parse_range_body(body)
    # Backwards-compat shape: a list of {suffix, count} so the
    # existing breach-check.js content script doesn't have to
    # change. Real-matches stat omits the padding rows.
    results = [{"suffix": s, "count": c} for s, c in suffixes_map.items()]
    real_matches = sum(1 for c in suffixes_map.values() if c > 0)

    return {
        "prefix": prefix,
        "matches": real_matches,
        "suffixes": results,
        "note": "Compare your full SHA-1 hash suffix against these results on-device.",
    }


@router.get(
    "/domain/{domain}",
    dependencies=[Depends(rate_limit(mode="ip", category="breach_domain"))],
)
async def check_domain_breaches(
    domain: str,
    user: Optional[AuthUser] = Depends(get_optional_user),
):
    """
    Check if a domain has been involved in known data breaches.
    Uses HIBP v3 API (requires API key for this endpoint).
    Falls back to basic info without key.
    """
    from api.config import get_settings
    settings = get_settings()

    hibp_key = getattr(settings, "hibp_api_key", "")

    if not hibp_key:
        # Without API key, return basic guidance
        return {
            "domain": domain,
            "breaches_found": None,
            "note": "Domain breach lookup requires HIBP API key. Use email k-anonymity check instead.",
            "check_url": f"https://haveibeenpwned.com/DomainSearch/{domain}",
        }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"https://haveibeenpwned.com/api/v3/breaches?domain={domain}",
                headers={
                    "hibp-api-key": hibp_key,
                    "User-Agent": "Cleanway-BreachCheck",
                },
            )

            if resp.status_code == 404:
                return {"domain": domain, "breaches_found": 0, "breaches": []}

            if resp.status_code == 200:
                breaches = resp.json()
                return {
                    "domain": domain,
                    "breaches_found": len(breaches),
                    "breaches": [
                        {
                            "name": b.get("Name"),
                            "date": b.get("BreachDate"),
                            "count": b.get("PwnCount"),
                            "data_types": b.get("DataClasses", []),
                        }
                        for b in breaches[:10]
                    ],
                }

            return {"domain": domain, "breaches_found": None, "error": "Service unavailable"}

    except Exception as e:
        logger.warning("domain_breach_error", extra={"error": str(e)})
        return {"domain": domain, "breaches_found": None, "error": "Temporarily unavailable"}

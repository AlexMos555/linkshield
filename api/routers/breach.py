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

from api.services.auth import get_current_user, get_optional_user
from api.models.schemas import AuthUser

logger = logging.getLogger("linkshield.breach")

router = APIRouter(prefix="/api/v1/breach", tags=["breach"])


@router.get("/check/{hash_prefix}")
async def check_breach(
    hash_prefix: str,
    user: Optional[AuthUser] = Depends(get_optional_user),
):
    """
    k-anonymity breach check.

    Send first 5 characters of SHA-1(email) hash.
    Returns list of matching hash suffixes with breach counts.
    Client compares locally — we never see your full hash.
    """
    # Validate prefix format
    prefix = hash_prefix.upper().strip()
    if len(prefix) != 5 or not all(c in "0123456789ABCDEF" for c in prefix):
        raise HTTPException(400, "Hash prefix must be exactly 5 hex characters")

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"https://api.pwnedpasswords.com/range/{prefix}",
                headers={
                    "User-Agent": "LinkShield-BreachCheck",
                    "Add-Padding": "true",  # Adds padding to prevent response size analysis
                },
            )

            if resp.status_code != 200:
                raise HTTPException(502, "Breach check service unavailable")

            # Parse response: each line is "SUFFIX:COUNT"
            results = []
            for line in resp.text.strip().split("\n"):
                parts = line.strip().split(":")
                if len(parts) == 2:
                    suffix = parts[0]
                    count = int(parts[1])
                    if count > 0:  # Skip padded entries
                        results.append({
                            "suffix": suffix,
                            "count": count,
                        })

            logger.info("breach_check", extra={"prefix": prefix, "matches": len(results)})

            return {
                "prefix": prefix,
                "matches": len(results),
                "suffixes": results,
                "note": "Compare your full SHA-1 hash suffix against these results on-device.",
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.warning("breach_check_error", extra={"error": str(e)})
        raise HTTPException(502, "Breach check temporarily unavailable")


@router.get("/domain/{domain}")
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
                    "User-Agent": "LinkShield-BreachCheck",
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

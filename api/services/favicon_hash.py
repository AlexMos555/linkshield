"""Favicon brand-clone detection — Strategy doc Top-20 #2 (partial).

Security hardening (2026-06-16 review): redirects DISABLED,
body STREAMED with a hard cap, SSRF re-checked inside the
fetch path, hash widened to 96 bits.

Phishing kits copy a brand's homepage WHOLESALE, including the
exact favicon. The favicon is fetched from
`/favicon.ico` (or the link rel="icon" hint, but ~95% of brand
pages still ship at /favicon.ico). When the bytes match a known
brand's favicon but the host is NOT that brand's verified host
→ near-certain brand-clone phishing.

We use SHA-256 of the favicon bytes (truncated to 12 hex chars)
as the perceptual identity. Not a TRUE perceptual hash — a single
pixel change defeats it. But it catches the long tail of kits
that copy/paste the file as-is (≈80% of consumer brand-clone
campaigns per public threat-intel reports). The expensive
visual-similarity engine that catches pixel-perturbed clones is
deferred to a follow-up.

Privacy:

  * Cleanway only fetches the favicon for domains the user
    explicitly checked. No background crawl.
  * The favicon URL never includes user identity, query params,
    or the user's full URL — just `<scheme>://<domain>/favicon.ico`.
  * Cached in Redis with 24h TTL so repeated checks of the same
    domain don't re-fetch.

Threat model — bypasses we accept:

  * A phisher who changes one pixel evades this signal. That's
    expected — perceptual hashing addresses it (deferred).
  * A phisher who uses a different favicon evades it. That's also
    expected — we never claim absence-of-signal = safe.
  * A brand that legitimately uses multiple favicons (e.g.
    Google's Doodles) → gallery stores multiple hashes per brand.
"""

from __future__ import annotations

import hashlib
import json
import logging
import pathlib
from typing import Optional

import httpx

from api.services.cache import get_redis

logger = logging.getLogger(__name__)

FAVICON_CACHE_TTL = 24 * 60 * 60  # 24 hours
FAVICON_FETCH_TIMEOUT = 2.0  # seconds — block-on-first-fetch budget
FAVICON_MAX_BYTES = 256 * 1024  # 256 KB — bigger than any sane favicon
HASH_HEX_LEN = 24  # 24 hex chars = 96 bits — comfortably past consumer
                   # GPU second-preimage horizon (~2^96 vs ~2^48 prior)

GALLERY_PATH = pathlib.Path(__file__).resolve().parent.parent / "data" / "brand_favicons.json"

_gallery_cache: Optional[dict] = None


def _load_gallery() -> dict:
    """Load and memoize the brand-favicon gallery.

    Structure:
        {
          "brand_slug": {
            "verified_hosts": ["paypal.com", "www.paypal.com", ...],
            "known_favicon_hashes": ["abc123def456", "..."]
          },
          ...
        }
    """
    global _gallery_cache
    if _gallery_cache is not None:
        return _gallery_cache
    try:
        with open(GALLERY_PATH, "r", encoding="utf-8") as f:
            _gallery_cache = json.load(f)
    except FileNotFoundError:
        logger.warning("brand favicon gallery missing at %s", GALLERY_PATH)
        _gallery_cache = {}
    return _gallery_cache


def _hash_bytes(b: bytes) -> str:
    """SHA-256 truncated to HASH_HEX_LEN hex chars (96 bits at 24).

    96-bit second-preimage takes ~2^96 trial hashes — well past
    any consumer-GPU horizon, while still 64 bits shorter than a
    full SHA-256 hex string for Redis-key efficiency.
    """
    return hashlib.sha256(b).hexdigest()[:HASH_HEX_LEN]


async def _fetch_favicon(domain: str) -> Optional[bytes]:
    """Fetch /favicon.ico over HTTPS; return None on any failure.

    Hardened against:

      * SSRF — re-validates the domain's DNS just before connect,
        rejecting any answer that points at private/link-local space.
        analyzer.py validates at the top of analyze_domain too;
        this is defense-in-depth against DNS rebinding between
        the analyzer's gate and our connect (TOCTOU narrowing).
      * Redirect-based bypass — `follow_redirects=False` because a
        302 to a new host has NOT been gated by validate_domain_resolution.
      * Body-size DoS — streams the response, aborting once we've
        accumulated FAVICON_MAX_BYTES instead of trusting the whole
        Content-Length / unmetered download.
    """
    # Local import — avoids a cycle in module-load order.
    from api.services.domain_validator import (
        DomainValidationError, validate_domain_resolution,
    )
    try:
        await validate_domain_resolution(domain)
    except DomainValidationError as exc:
        # The analyzer already filtered this, but a re-check here
        # closes the rebinding window between that gate and our
        # TCP connect. A failure here is silent — no upstream signal.
        logger.warning("favicon fetch SSRF re-check rejected %s: %s", domain, exc)
        return None

    url = f"https://{domain}/favicon.ico"
    try:
        async with httpx.AsyncClient(
            timeout=FAVICON_FETCH_TIMEOUT,
            follow_redirects=False,  # see docstring — redirects bypass SSRF gate
        ) as client:
            async with client.stream("GET", url) as resp:
                if resp.status_code != 200:
                    return None
                buf = bytearray()
                async for chunk in resp.aiter_bytes():
                    buf.extend(chunk)
                    if len(buf) > FAVICON_MAX_BYTES:
                        # Don't drain the stream — closing the
                        # context exits the connection.
                        return None
                if not buf:
                    return None
                return bytes(buf)
    except Exception as exc:
        logger.debug("favicon fetch failed for %s: %s", domain, exc)
        return None


async def get_favicon_hash(domain: str) -> Optional[str]:
    """Return the cached or freshly-fetched favicon hash for a domain.

    Cache key: `favicon:hash:<domain>`. Stored value is the
    12-char hex digest, or the sentinel "MISS" if the last fetch
    came back empty (so we don't re-fetch every 30s).
    """
    domain_key = (domain or "").strip().lower()
    if not domain_key:
        return None

    cache_key = f"favicon:hash:{domain_key}"
    try:
        r = await get_redis()
        cached = await r.get(cache_key)
        if cached == "MISS":
            return None
        if cached:
            return cached
    except Exception:
        # Cache outage — proceed to live fetch but don't store result.
        r = None

    content = await _fetch_favicon(domain_key)
    if not content:
        if r is not None:
            try:
                await r.setex(cache_key, FAVICON_CACHE_TTL, "MISS")
            except Exception:
                pass
        return None

    digest = _hash_bytes(content)
    if r is not None:
        try:
            await r.setex(cache_key, FAVICON_CACHE_TTL, digest)
        except Exception:
            pass
    return digest


async def check_favicon_brand_clone(domain: str) -> dict:
    """Parallel-check entry. Returns the scoring contribution.

    Output:
        {
          "cloned": bool,
          "brand": str | None,
          "matched_hash": str | None,
          "weight": int,        # positive — pushes score UP toward danger
          "detail": str,
        }

    The check fires ONLY when:
      1. We can hash the candidate's favicon, AND
      2. That hash appears in some brand's `known_favicon_hashes`, AND
      3. The candidate domain is NOT in that brand's `verified_hosts`.

    A legitimate brand serving its own favicon returns `cloned=False`
    even though the hash matches — that's the correct behavior.
    """
    gallery = _load_gallery()
    if not gallery:
        return {"cloned": False, "brand": None, "matched_hash": None, "weight": 0, "detail": ""}

    digest = await get_favicon_hash(domain)
    if not digest:
        return {"cloned": False, "brand": None, "matched_hash": None, "weight": 0, "detail": ""}

    domain_key = (domain or "").strip().lower()
    for brand_slug, brand in gallery.items():
        # Skip pseudo-brands like the `_meta` schema marker. We use
        # the underscore-prefix convention everywhere else (refresh
        # script, transparency router) — match it here.
        if brand_slug.startswith("_"):
            continue
        known = brand.get("known_favicon_hashes") or []
        if digest not in known:
            continue
        verified = {h.lower() for h in (brand.get("verified_hosts") or [])}
        if domain_key in verified:
            # Brand's own host — favicon match is expected.
            return {
                "cloned": False,
                "brand": brand_slug,
                "matched_hash": digest,
                "weight": 0,
                "detail": "",
            }
        # Brand-clone confirmed.
        return {
            "cloned": True,
            "brand": brand_slug,
            "matched_hash": digest,
            "weight": 35,
            "detail": (
                f"This page serves the {brand_slug} favicon but is "
                f"hosted on {domain_key} — a classic brand-clone "
                "phishing signature."
            ),
        }

    return {"cloned": False, "brand": None, "matched_hash": digest, "weight": 0, "detail": ""}

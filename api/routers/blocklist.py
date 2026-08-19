"""GET /api/v1/blocklist/dns — serve the DNS blocklist artifact to phones.

Bytes + validators only. The artifact is prepared by the refresh cron
(scripts/refresh_dangerous_domains.py) and stored in Redis; this handler
never computes anything per request, so it is never the slow part of a
phone's sync. ETag = sha256(text) — the phone verifies the body against it
before loading, so a truncated or tampered artifact is rejected at both ends.
"""
from __future__ import annotations

import base64
import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, Request, Response

from api.services.blocklist_artifact import (
    REDIS_META_KEY,
    REDIS_TEXT_KEY,
    delta_key,
    sha256_bytes,
)
from api.services.rate_limiter import rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/blocklist", tags=["blocklist"])

CACHE_MAX_AGE_S = 1800
RETRY_AFTER_S = 600


# The artifact is ~2.6 MB of packed hashes, stored base64 in Redis (the client
# runs with decode_responses=True for everything else). Decoding it per request
# would be pure waste, so keep the last one in process, keyed by its sha.
_cached: Optional[tuple[str, bytes]] = None


async def load_artifact() -> Optional[tuple[bytes, dict]]:
    """(blob, meta) from Redis, or None when absent/inconsistent."""
    global _cached
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        encoded = await r.get(REDIS_TEXT_KEY)
        meta = await r.hgetall(REDIS_META_KEY) or {}
    except Exception:
        logger.warning("blocklist artifact: redis unavailable", exc_info=True)
        return None
    if not encoded or not meta:
        return None
    meta = {(k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
            for k, v in meta.items()}
    sha = meta.get("sha256", "")
    if _cached and _cached[0] == sha:
        return _cached[1], meta
    try:
        blob = base64.b64decode(encoded)
    except Exception:
        logger.error("blocklist artifact: not valid base64 — refusing to serve")
        return None
    if sha != sha256_bytes(blob):
        logger.error("blocklist artifact: meta sha256 does not match body — refusing to serve")
        return None
    _cached = (sha, blob)
    return blob, meta


async def artifact_age_seconds() -> Optional[int]:
    """For /health: seconds since the artifact was generated, None if absent."""
    loaded = await load_artifact()
    if not loaded:
        return None
    _, meta = loaded
    try:
        return max(0, int(time.time()) - int(meta.get("generated_at", 0)))
    except (TypeError, ValueError):
        return None


async def load_delta(from_generation: int) -> Optional[bytes]:
    """The delta from `from_generation` to the current artifact, if we still
    have it. Deltas expire with the artifact, so an old phone simply gets the
    full file instead of being stuck."""
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        encoded = await r.get(delta_key(from_generation))
    except Exception:
        logger.warning("blocklist delta: redis unavailable", exc_info=True)
        return None
    if not encoded:
        return None
    try:
        return base64.b64decode(encoded)
    except Exception:
        logger.error("blocklist delta: not valid base64")
        return None


@router.get(
    "/dns",
    dependencies=[Depends(rate_limit(mode="ip", category="blocklist"))],
)
async def get_dns_blocklist(request: Request) -> Response:
    # `from=<version>` says "I already have this one". Real feed movement is
    # ~0.2% per half day, so the answer is usually a few KB instead of 2.5 MB
    # — the difference between a phone that stays current on a metered plan
    # and one that does not.
    raw_from = request.query_params.get("from")
    if raw_from and raw_from.isdigit():
        delta = await load_delta(int(raw_from))
        if delta:
            return Response(
                content=delta,
                media_type="application/octet-stream",
                headers={
                    "ETag": f'"{sha256_bytes(delta)}"',
                    "Cache-Control": f"public, max-age={CACHE_MAX_AGE_S}",
                    "X-Cleanway-Blocklist-Delta": "1",
                },
            )

    loaded = await load_artifact()
    if not loaded:
        return Response(
            status_code=503,
            content="blocklist temporarily unavailable\n",
            media_type="text/plain",
            headers={"Retry-After": str(RETRY_AFTER_S), "Cache-Control": "no-store"},
        )
    blob, meta = loaded
    etag = f'"{meta["sha256"]}"'
    headers = {
        "ETag": etag,
        "Cache-Control": f"public, max-age={CACHE_MAX_AGE_S}",
        "X-Cleanway-Blocklist-Version": str(meta.get("version", "")),
        "X-Cleanway-Blocklist-Count": str(meta.get("count", "")),
    }
    # Edges that gzip the body rewrite our strong ETag into a weak one
    # (W/"<sha>") on the way out, and clients echo that back. Compare on the
    # sha alone so those clients still get their 304.
    inm = request.headers.get("if-none-match", "")
    presented = {t.strip().removeprefix("W/").strip('"') for t in inm.split(",") if t.strip()}
    if meta["sha256"] in presented:
        return Response(status_code=304, headers=headers)
    return Response(content=blob, media_type="application/octet-stream", headers=headers)

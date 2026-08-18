"""GET /api/v1/blocklist/dns — serve the DNS blocklist artifact to phones.

Bytes + validators only. The artifact is prepared by the refresh cron
(scripts/refresh_dangerous_domains.py) and stored in Redis; this handler
never computes anything per request, so it is never the slow part of a
phone's sync. ETag = sha256(text) — the phone verifies the body against it
before loading, so a truncated or tampered artifact is rejected at both ends.
"""
from __future__ import annotations

import logging
import time
from typing import Optional

from fastapi import APIRouter, Depends, Request, Response

from api.services.blocklist_artifact import (
    REDIS_META_KEY,
    REDIS_TEXT_KEY,
    sha256_hex,
)
from api.services.rate_limiter import rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/blocklist", tags=["blocklist"])

CACHE_MAX_AGE_S = 1800
RETRY_AFTER_S = 600


async def load_artifact() -> Optional[tuple[str, dict]]:
    """(text, meta) from Redis, or None when absent/inconsistent."""
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        text = await r.get(REDIS_TEXT_KEY)
        meta = await r.hgetall(REDIS_META_KEY) or {}
    except Exception:
        logger.warning("blocklist artifact: redis unavailable", exc_info=True)
        return None
    if not text or not meta:
        return None
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    meta = {(k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
            for k, v in meta.items()}
    if meta.get("sha256") != sha256_hex(text):
        logger.error("blocklist artifact: meta sha256 does not match body — refusing to serve")
        return None
    return text, meta


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


@router.get(
    "/dns",
    dependencies=[Depends(rate_limit(mode="ip", category="blocklist"))],
)
async def get_dns_blocklist(request: Request) -> Response:
    loaded = await load_artifact()
    if not loaded:
        return Response(
            status_code=503,
            content="blocklist temporarily unavailable\n",
            media_type="text/plain",
            headers={"Retry-After": str(RETRY_AFTER_S), "Cache-Control": "no-store"},
        )
    text, meta = loaded
    etag = f'"{meta["sha256"]}"'
    headers = {
        "ETag": etag,
        "Cache-Control": f"public, max-age={CACHE_MAX_AGE_S}",
        "X-Cleanway-Blocklist-Version": str(meta.get("version", "")),
        "X-Cleanway-Blocklist-Count": str(meta.get("count", "")),
    }
    inm = request.headers.get("if-none-match", "")
    if inm and etag in [t.strip() for t in inm.split(",")]:
        return Response(status_code=304, headers=headers)
    return Response(content=text, media_type="text/plain; charset=utf-8", headers=headers)

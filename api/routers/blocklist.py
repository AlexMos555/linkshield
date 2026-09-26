"""GET /api/v1/blocklist/dns — serve the DNS blocklist artifact to phones.

Bytes + validators only. The artifact is prepared by the refresh cron
(scripts/refresh_dangerous_domains.py) and stored in Redis; this handler
never computes anything per request, so it is never the slow part of a
phone's sync. ETag = sha256(text) — the phone verifies the body against it
before loading, so a truncated or tampered artifact is rejected at both ends.

A sync costs, in order of preference: 304 when `?from=` names the current
version or If-None-Match names its sha; a few-KB delta when `?from=` names an
older version we still have a delta for; the full artifact otherwise.
"""
from __future__ import annotations

import base64
import logging
import time
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, Response

from api.services.blocklist_artifact import (
    REDIS_META_KEY,
    REDIS_TEXT_KEY,
    delta_key,
    sha256_bytes,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/blocklist", tags=["blocklist"])

CACHE_MAX_AGE_S = 1800
RETRY_AFTER_S = 600


# The artifact is ~2.6 MB of packed hashes, stored base64 in Redis (the client
# runs with decode_responses=True for everything else). Reading and decoding it
# per request would be pure waste, so keep the last one in process, keyed by
# its sha — and read the small meta hash first, so the body is fetched from
# Redis only when the published sha changed.
_cached: Optional[tuple[str, bytes]] = None


async def load_meta() -> Optional[dict]:
    """The artifact's meta hash (version, sha256, count, generated_at), or
    None when Redis is unreachable or nothing is published."""
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        raw = await r.hgetall(REDIS_META_KEY) or {}
    except Exception:
        logger.warning("blocklist artifact: redis unavailable", exc_info=True)
        return None
    meta = {(k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
            for k, v in raw.items()}
    return meta if meta.get("sha256") else None


async def load_artifact(meta: Optional[dict] = None) -> Optional[tuple[bytes, dict]]:
    """(blob, meta) from Redis, or None when absent/inconsistent."""
    global _cached
    meta = meta or await load_meta()
    if not meta:
        return None
    sha = meta["sha256"]
    if _cached and _cached[0] == sha:
        return _cached[1], meta
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        encoded = await r.get(REDIS_TEXT_KEY)
    except Exception:
        logger.warning("blocklist artifact: redis unavailable", exc_info=True)
        return None
    if not encoded:
        return None
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


async def _full_send_allowed(request: Request) -> bool:
    """Bandwidth guard, applied ONLY to full-artifact responses.

    The endpoint is a small request that returns ~2.6 MB, i.e. an amplifier, and
    there is no CDN in front of it yet. A blanket per-IP limit is the wrong tool
    (it would 429 a whole Tele2 CGNAT gateway of fresh installs into an empty
    blocklist), so instead we only count the expensive case — a full send — and
    set the ceiling far above anything real traffic produces. Cheap responses
    (304, deltas) are never counted, so returning users are never affected.

    Fails OPEN on any limiter problem: an unprotected phone is worse than a
    served byte.
    """
    try:
        from api.config import get_settings
        from api.services.rate_limiter import _extract_client_ip, check_ip_rate_limit
        s = get_settings()
        await check_ip_rate_limit(
            _extract_client_ip(request),
            category="blocklist",
            limit=s.blocklist_full_sends_per_ip_per_hour,
            window_seconds=3600,
        )
        return True
    except HTTPException:
        return False
    except Exception:
        logger.warning("blocklist bandwidth guard unavailable — allowing", exc_info=True)
        return True


# No blanket per-IP rate limit on this GET, on purpose.
#
# It is a SIGNED, ETag'd, edge-cacheable public static file (the same bytes for
# everyone), and the real first customers arrive behind Tele2 carrier-grade NAT
# — thousands of phones share one public IPv4. A per-IP cap can't tell that
# apart from abuse, so it would 429 a whole CGNAT gateway of fresh installs and
# leave them with an EMPTY blocklist = unprotected, for up to the cap window.
# For a static public artifact that is the wrong trade. Abuse is bounded by the
# in-process cache here and the CDN in front (docs/TELE2_LAUNCH_PLAN.md B4).
def _unavailable() -> Response:
    return Response(
        status_code=503,
        content="blocklist temporarily unavailable\n",
        media_type="text/plain",
        headers={"Retry-After": str(RETRY_AFTER_S), "Cache-Control": "no-store"},
    )


def _presents_sha(request: Request, sha: str) -> bool:
    """Does If-None-Match name this sha? Edges that gzip the body rewrite our
    strong ETag into a weak one (W/"<sha>") on the way out, and clients echo
    that back. Compare on the sha alone so those clients still get their 304."""
    inm = request.headers.get("if-none-match", "")
    return sha in {t.strip().removeprefix("W/").strip('"') for t in inm.split(",") if t.strip()}


@router.get("/dns")
async def get_dns_blocklist(request: Request) -> Response:
    meta = await load_meta()
    if not meta:
        return _unavailable()
    headers = {
        "ETag": f'"{meta["sha256"]}"',
        "Cache-Control": f"public, max-age={CACHE_MAX_AGE_S}",
        "X-Cleanway-Blocklist-Version": str(meta.get("version", "")),
        "X-Cleanway-Blocklist-Count": str(meta.get("count", "")),
    }
    # `from=<version>` says "I already have this one". When that IS the
    # current version there is nothing to send, with or without an ETag: the
    # Android 1.0.1 app keeps no ETag after applying a delta, and each such
    # poll used to fall through to the full 2.57 MB (~24 MB a month per phone
    # instead of ~0.3 MB). Answering here, before any delta lookup, also means
    # a phone on a version restored by a rollback is never handed the delta
    # that leads to the rolled-back list.
    raw_from = request.query_params.get("from")
    if raw_from and raw_from == str(meta.get("version", "")):
        return Response(status_code=304, headers=headers)
    # An older version: real feed movement is ~0.2% per half day, so the
    # answer is usually a few KB instead of 2.5 MB. The delta keeps its own
    # sha as ETag — the phone verifies the body it received against it.
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
    if _presents_sha(request, meta["sha256"]):
        # Cheap: never counted against the bandwidth guard.
        return Response(status_code=304, headers=headers)

    # Only the expensive full send is metered.
    if not await _full_send_allowed(request):
        return Response(
            status_code=429,
            content="too many full blocklist downloads from this address\n",
            media_type="text/plain",
            headers={"Retry-After": "900", "Cache-Control": "no-store"},
        )
    loaded = await load_artifact(meta)
    if not loaded:
        return _unavailable()
    blob, _ = loaded
    return Response(content=blob, media_type="application/octet-stream", headers=headers)

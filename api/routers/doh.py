"""DNS-over-HTTPS resolver router — Strategy doc Top-20 #6.

Exposes RFC 8484 endpoints at dns.cleanway.ai/dns-query (when DNS
is wired) and api.cleanway.ai/dns-query (works today). Both POST
(body = wire-format DNS query) and GET (?dns=base64url-encoded
wire) per the spec.

Phishing-blocking is the only modification we make versus a
plain Cloudflare 1.1.1.1 resolver. Adult-content blocking,
ad-blocking, and per-user policy are intentionally NOT shipped
— they belong to dns.cleanway.ai/families (a future #6 lane).
"""

from __future__ import annotations

import base64
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import Response as FastAPIResponse

from api.services.doh_gateway import (
    DOH_CONTENT_TYPE,
    is_blocked,
    make_nxdomain_response,
    parse_qname,
    proxy_to_upstream,
)
from api.services.rate_limiter import rate_limit

logger = logging.getLogger(__name__)

# No prefix — Apple Private Relay / Android Private DNS both
# expect `/dns-query` at the root of the resolver hostname.
router = APIRouter(tags=["doh"])


async def _danger_set() -> set[str]:
    """Pull the current dangerous-domain set from Redis.

    The analyzer warms `dangerous_domains` whenever a /check call
    returns dangerous; the threat-intel cron also pre-warms top
    PhishTank / URLhaus entries. Cache outage → empty set, which
    means we proxy clean — fail-open is correct here because
    blocking a clean domain is worse than missing a malicious one.
    """
    try:
        from api.services.cache import get_redis
        r = await get_redis()
        members = await r.smembers("dangerous_domains")
        # Redis client returns bytes or str depending on
        # decode_responses; normalise to lowercase strings.
        return {
            (m.decode("utf-8") if isinstance(m, bytes) else m).lower()
            for m in (members or set())
        }
    except Exception:
        logger.debug("DoH danger-set fetch failed", exc_info=True)
        return set()


async def _handle_query(wire: bytes) -> tuple[bytes, int]:
    """Core decision: block or proxy. Returns (response_wire, http_status)."""
    if not wire:
        return b"", 400
    qname = parse_qname(wire)
    danger = await _danger_set()
    if qname and await is_blocked(qname, danger):
        logger.info(
            "DoH blocked qname",
            extra={"qname_suffix": qname[-32:] if qname else None},
        )
        return make_nxdomain_response(wire), 200

    upstream = await proxy_to_upstream(wire)
    if upstream is None:
        # Upstream outage — fall back to a SERVFAIL response so
        # the client retries with its other resolvers cleanly
        # instead of timing out.
        return make_nxdomain_response(wire), 200
    return upstream, 200


@router.post(
    "/dns-query",
    dependencies=[Depends(rate_limit(mode="ip", category="doh"))],
)
async def doh_post(request: Request) -> Response:
    """RFC 8484 §4.1.1 — wire-format DNS message in request body.

    Apple's Private Relay configuration profile uses this form.
    """
    wire = await request.body()
    body, status = await _handle_query(wire)
    return FastAPIResponse(
        content=body,
        media_type=DOH_CONTENT_TYPE,
        status_code=status,
        headers={"Cache-Control": "max-age=300"},
    )


@router.get(
    "/dns-query",
    dependencies=[Depends(rate_limit(mode="ip", category="doh"))],
)
async def doh_get(
    request: Request,
    dns: Optional[str] = Query(None, max_length=512),
) -> Response:
    """RFC 8484 §4.1.1 — base64url-encoded wire in `dns` parameter.

    Android's Private DNS uses GET form. Cloudflare 1.1.1.1's
    DoH endpoint also accepts GET; we mirror that.
    """
    if not dns:
        return FastAPIResponse(content=b"", status_code=400)
    try:
        # Base64url decode — RFC 8484 requires it without padding.
        padded = dns + "=" * (-len(dns) % 4)
        wire = base64.urlsafe_b64decode(padded)
    except Exception:
        return FastAPIResponse(content=b"", status_code=400)
    body, status = await _handle_query(wire)
    return FastAPIResponse(
        content=body,
        media_type=DOH_CONTENT_TYPE,
        status_code=status,
        headers={"Cache-Control": "max-age=300"},
    )

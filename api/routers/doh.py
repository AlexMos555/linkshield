"""DNS-over-HTTPS resolver router — Strategy doc Top-20 #6.

Exposes RFC 8484 endpoints at dns.cleanway.ai/dns-query (when DNS
is wired) and api.cleanway.ai/dns-query (works today). Both POST
(body = wire-format DNS query) and GET (?dns=base64url-encoded
wire) per the spec.

Phishing-blocking is the only modification we make versus a
plain Cloudflare 1.1.1.1 resolver. Adult-content blocking,
ad-blocking, and per-user policy are intentionally NOT shipped
— they belong to dns.cleanway.ai/families (a future #6 lane).

Hot path (docs/runbooks/doh-gateway.md has the measurements):
  DohFastPath (raw ASGI, outermost) → rate limit (in process) →
  resolve(): in-process blocklist filter → response cache → upstreams
  (Cloudflare, Quad9; HTTP/2, hedged failover) → serve-stale → SERVFAIL.
The FastAPI routes below stay for the OpenAPI contract and as the path
taken when DOH_FAST_PATH=false; both call the same resolve().

Fail-open, by decision: nothing that goes wrong on OUR side (filter, cache,
Redis, a bug) may stop a query from being forwarded. The only SERVFAIL we
ever send means "no upstream answered in 4 s and nothing was cached".
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import re
import time
from typing import Awaitable, Callable, NamedTuple, Optional

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import Response as FastAPIResponse

from api.services import doh_filter, doh_metrics
from api.services.doh_cache import ResponseCache
from api.services.doh_gateway import (
    DOH_CONTENT_TYPE,
    NEGATIVE_TTL_S,
    block_candidates,
    make_nxdomain_response,
    make_servfail_response,
    parse_qname,
    proxy_to_upstream,
)
from api.services.doh_upstream import UPSTREAM_TIMEOUT_S
from api.services.doh_wire import http_max_age, query_shape
from api.services.rate_limiter import doh_rate_limit

# No prefix — Apple Private Relay / Android Private DNS both
# expect `/dns-query` at the root of the resolver hostname.
router = APIRouter(tags=["doh"])

MAX_QUERY_BYTES = 4096  # a real query is < 300 B, ~512 B padded
_B64URL = re.compile(r"^[A-Za-z0-9_-]*={0,2}$")


class DohAnswer(NamedTuple):
    body: bytes
    status: int
    max_age: int


_cache: Optional[ResponseCache] = None
# Cache keys with an upstream request in flight: identical concurrent misses
# (a cold cache after a deploy, a popular name expiring under load) wait for
# the first one instead of each costing an upstream round trip.
_inflight: dict[bytes, "asyncio.Future[None]"] = {}


def response_cache() -> ResponseCache:
    global _cache
    if _cache is None:
        from api.config import get_settings
        s = get_settings()
        _cache = ResponseCache(s.doh_cache_max_entries, s.doh_cache_max_ttl_s, s.doh_serve_stale_s)
    return _cache


def reset_for_tests() -> None:
    global _cache
    _cache = None
    _inflight.clear()


def _redis_timeout_s() -> float:
    from api.config import get_settings
    return get_settings().doh_redis_timeout_ms / 1000


async def resolve(
    wire: bytes,
    proxy: Optional[Callable[[bytes], Awaitable[Optional[bytes]]]] = None,
    log_block: bool = True,
) -> DohAnswer:
    """Block, answer from cache, or forward. Never raises.

    `proxy` replaces the upstream call (default: proxy_to_upstream) and turns
    the response cache off. The /health/deep self-probe passes one that never
    touches the network, so a name that is NOT blocked comes back SERVFAIL
    instead of costing a Cloudflare round-trip — the probe tests our
    decision, not their uptime. It also passes `log_block=False` so its
    canary block is not counted as a user's block in the metrics.
    """
    if not wire or len(wire) < 12:
        return DohAnswer(b"", 400, 0)
    if len(wire) > MAX_QUERY_BYTES:
        return DohAnswer(b"", 413, 0)
    m = doh_metrics.METRICS
    started = time.perf_counter()
    m.inc("queries")
    try:
        answer = await _resolve(wire, proxy, log_block, m)
    except Exception:  # noqa: BLE001 — last line of defence: forward as-is
        m.inc("internal_error")
        upstream = await (proxy or proxy_to_upstream)(wire)
        answer = (DohAnswer(upstream, 200, http_max_age(upstream)) if upstream is not None
                  else DohAnswer(make_servfail_response(wire), 200, 0))
    m.observe(time.perf_counter() - started)
    return answer


async def _resolve(wire: bytes, proxy, log_block: bool, m) -> DohAnswer:
    try:
        qname = parse_qname(wire)
        blocked, how = await doh_filter.decide(qname, block_candidates(qname or ""), _redis_timeout_s())
    except Exception:  # noqa: BLE001 — a filter bug must not cost the lookup
        blocked, how = False, "filter_error"
    m.inc(f"decision.{how}")
    if blocked:
        if log_block:
            m.inc("blocked")
        return DohAnswer(make_nxdomain_response(wire), 200, NEGATIVE_TTL_S)

    cache = response_cache() if proxy is None else None
    shape = None
    if cache is not None:
        try:
            shape = query_shape(wire)
            hit = cache.get(shape, wire) if shape is not None else None
        except Exception:  # noqa: BLE001
            m.inc("cache_error")
            shape, hit = None, None
        if hit is not None:
            m.inc("cache_hit")
            return DohAnswer(hit.body, 200, hit.max_age)
        m.inc("cache_miss")
        if shape is not None and shape.cache_key is not None:
            leader = _inflight.get(shape.cache_key)
            if leader is not None:
                m.inc("coalesced")
                try:
                    await asyncio.wait_for(asyncio.shield(leader), UPSTREAM_TIMEOUT_S + 0.5)
                except Exception:  # noqa: BLE001 — then ask upstream ourselves
                    pass
                hit = cache.get(shape, wire)
                if hit is not None:
                    return DohAnswer(hit.body, 200, hit.max_age)
            else:
                done = asyncio.get_running_loop().create_future()
                _inflight[shape.cache_key] = done
                try:
                    return await _forward(wire, proxy, cache, shape, m)
                finally:
                    _inflight.pop(shape.cache_key, None)
                    done.set_result(None)
    return await _forward(wire, proxy, cache, shape, m)


async def _forward(wire: bytes, proxy, cache: Optional[ResponseCache], shape, m) -> DohAnswer:
    upstream = await (proxy or proxy_to_upstream)(wire)
    if upstream is not None:
        m.inc("upstream_ok")
        ttl = None
        if cache is not None and shape is not None:
            try:
                ttl = cache.put(shape, upstream)
            except Exception:  # noqa: BLE001
                m.inc("cache_error")
        return DohAnswer(upstream, 200, ttl if ttl is not None else http_max_age(upstream))

    m.inc("upstream_failed")
    if cache is not None and shape is not None:
        stale = cache.get(shape, wire, allow_stale=True)
        if stale is not None:
            m.inc("served_stale")
            return DohAnswer(stale.body, 200, stale.max_age)
    # No upstream answered and nothing is cached — SERVFAIL, so the client
    # retries elsewhere instead of believing (and negatively caching) that
    # every site on the internet does not exist.
    m.inc("servfail")
    return DohAnswer(make_servfail_response(wire), 200, 0)


async def handle_query(
    wire: bytes,
    proxy: Optional[Callable[[bytes], Awaitable[Optional[bytes]]]] = None,
    log_block: bool = True,
) -> tuple[bytes, int]:
    """(response_wire, http_status) — the original interface of resolve()."""
    answer = await resolve(wire, proxy=proxy, log_block=log_block)
    return answer.body, answer.status


def decode_get_param(dns: Optional[str]) -> Optional[bytes]:
    """RFC 8484 §4.1: base64url without padding (padding tolerated). Strict —
    the stdlib decoder would silently drop characters outside the alphabet."""
    if not dns or len(dns) > (MAX_QUERY_BYTES * 4) // 3 + 4 or not _B64URL.match(dns):
        return None
    try:
        return base64.urlsafe_b64decode(dns.rstrip("=") + "=" * (-len(dns.rstrip("=")) % 4))
    except (binascii.Error, ValueError):
        return None


def response_headers(answer: DohAnswer) -> dict[str, str]:
    if answer.status != 200:
        return {"Cache-Control": "no-store"}
    return {"Cache-Control": f"max-age={answer.max_age}"}


def _content_type_ok(value: Optional[str]) -> bool:
    return not value or value.split(";", 1)[0].strip().lower() == DOH_CONTENT_TYPE


def _dns_response(answer: DohAnswer) -> Response:
    return FastAPIResponse(
        content=answer.body,
        media_type=DOH_CONTENT_TYPE if answer.status == 200 else None,
        status_code=answer.status,
        headers=response_headers(answer),
    )


@router.post(
    "/dns-query",
    dependencies=[Depends(doh_rate_limit)],
)
async def doh_post(request: Request) -> Response:
    """RFC 8484 §4.1.1 — wire-format DNS message in request body.

    Apple's Private Relay configuration profile uses this form.
    """
    if not _content_type_ok(request.headers.get("content-type")):
        return FastAPIResponse(content=b"", status_code=415, headers={"Cache-Control": "no-store"})
    wire = await request.body()
    return _dns_response(await resolve(wire))


@router.get(
    "/dns-query",
    dependencies=[Depends(doh_rate_limit)],
)
async def doh_get(
    request: Request,
    dns: Optional[str] = Query(None, max_length=512),
) -> Response:
    """RFC 8484 §4.1.1 — base64url-encoded wire in `dns` parameter.

    Android's Private DNS uses GET form. Cloudflare 1.1.1.1's
    DoH endpoint also accepts GET; we mirror that.
    """
    wire = decode_get_param(dns)
    if wire is None:
        return FastAPIResponse(content=b"", status_code=400, headers={"Cache-Control": "no-store"})
    return _dns_response(await resolve(wire))


@router.get("/health/doh", include_in_schema=False)
async def doh_health() -> Response:
    """Load-balancer / monitor probe for the DNS path only: 200 while at
    least one upstream is healthy. Never touches Supabase or the network."""
    from fastapi.responses import JSONResponse

    from api.services import doh_upstream
    ups = doh_upstream.status()
    body = {
        "ok": any(u["healthy"] for u in ups),
        "filter": doh_filter.HOLDER.status(),
        "upstreams": ups,
        "http2": doh_upstream.HTTP2_AVAILABLE,
        "cache_entries": len(response_cache()),
        "stats": doh_metrics.METRICS.snapshot(),
    }
    return JSONResponse(body, status_code=200 if body["ok"] else 503, headers={"Cache-Control": "no-store"})


# ── startup / shutdown (called from api.main lifespan) ────────────────
_stats_task = None


async def startup() -> None:
    from api.config import get_settings
    global _stats_task
    doh_filter.HOLDER.start(get_settings().doh_filter_refresh_s)
    if _stats_task is None or _stats_task.done():
        _stats_task = asyncio.get_running_loop().create_task(doh_metrics.stats_logger())


async def shutdown() -> None:
    global _stats_task
    await doh_filter.HOLDER.stop()
    task, _stats_task = _stats_task, None
    if task is not None:
        task.cancel()
    from api.services.doh_gateway import close_upstream_client
    await close_upstream_client()


"""Upstream resolvers for the DoH gateway: pooled, HTTP/2, with failover.

One shared httpx.AsyncClient per event loop, HTTP/2 when the `h2` package is
installed (one multiplexed TLS connection per upstream instead of a pool of
HTTP/1.1 sockets — measured in docs/runbooks/doh-gateway.md, the HTTP/1.1
pool's per-request bookkeeping was the gateway's main CPU cost under load).

Order of attempts for one query (proxy_to_upstream):
  1. the first healthy upstream (configured order: Cloudflare, then Quad9);
  2. if it fails outright (refused, reset, TLS, non-200, garbage) → the next
     one immediately;
  3. if it is merely slow → after HEDGE_AFTER_S the next one is asked in
     parallel and whichever answers first wins (the loser is cancelled);
  4. all of it inside one UPSTREAM_TIMEOUT_S budget. Nothing answered → None,
     and the caller serves a stale cached answer or SERVFAIL.

A per-upstream breaker (3 consecutive failures or lost hedges → skipped for
10 s, then retried) means a dead upstream costs the hedge delay a handful of
times, not on every query. A skipped upstream is still tried last.

Responses are validated before they are believed: HTTP 200, 12..65535 bytes,
the query's transaction ID. Query bytes are forwarded exactly as received —
EDNS0 options and padding pass through, and no ECS option is ever added.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger("api.services.doh_gateway")

CLOUDFLARE_DOH_URL = "https://cloudflare-dns.com/dns-query"
QUAD9_DOH_URL = "https://dns.quad9.net/dns-query"  # no ECS on this endpoint
DEFAULT_UPSTREAMS = (CLOUDFLARE_DOH_URL, QUAD9_DOH_URL)
DOH_CONTENT_TYPE = "application/dns-message"
UPSTREAM_TIMEOUT_S = 4.0
HEDGE_AFTER_S = 0.4
MAX_RESPONSE_BYTES = 65535
BREAKER_THRESHOLD = 3
BREAKER_COOLDOWN_S = 10.0

try:  # HTTP/2 needs the optional `h2` package (httpx[http2]).
    import h2  # noqa: F401
    HTTP2_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    HTTP2_AVAILABLE = False

# Connections per process, and the cap on upstream requests in flight.
# Keepalive == max on purpose: httpcore 1.0's pool closes an idle connection
# whenever the pool holds more than max_keepalive connections IN TOTAL (it
# counts all of them, not the idle ones), so keepalive < max meant a fresh
# TCP+TLS handshake to Cloudflare for a share of queries under load. The
# in-flight cap keeps the pool's O(queued x connections) bookkeeping from
# growing with load: excess queries wait on a cheap asyncio semaphore instead.
_UPSTREAM_MAX_CONNECTIONS = 32
_UPSTREAM_KEEPALIVE = 32
MAX_IN_FLIGHT = 32
_HEADERS = {"Content-Type": DOH_CONTENT_TYPE, "Accept": DOH_CONTENT_TYPE}


class Upstream:
    __slots__ = ("url", "fail_streak", "skip_until", "ok_count", "fail_count")

    def __init__(self, url: str) -> None:
        self.url = url
        self.fail_streak = 0
        self.skip_until = 0.0
        self.ok_count = 0
        self.fail_count = 0

    def healthy(self, now: float) -> bool:
        return now >= self.skip_until

    def record(self, ok: bool) -> None:
        if ok:
            self.ok_count += 1
            self.fail_streak = 0
            self.skip_until = 0.0
            return
        self.fail_count += 1
        self.fail_streak += 1
        if self.fail_streak >= BREAKER_THRESHOLD:
            self.skip_until = time.monotonic() + BREAKER_COOLDOWN_S

    def status(self) -> dict:
        return {"url": self.url, "healthy": self.healthy(time.monotonic()),
                "ok": self.ok_count, "failed": self.fail_count}


_upstreams: list[Upstream] = []
_upstream_client: Optional[httpx.AsyncClient] = None
_upstream_client_loop: object = None
_in_flight: Optional[asyncio.Semaphore] = None


def configured_urls() -> list[str]:
    try:
        from api.config import get_settings
        raw = (get_settings().doh_upstreams or "").strip()
    except Exception:  # noqa: BLE001
        raw = ""
    urls = [u.strip() for u in raw.split(",") if u.strip()]
    return urls or list(DEFAULT_UPSTREAMS)


def upstreams() -> list[Upstream]:
    global _upstreams
    urls = configured_urls()
    if [u.url for u in _upstreams] != urls:
        _upstreams = [Upstream(u) for u in urls]
    return _upstreams


def _get_upstream_client() -> httpx.AsyncClient:
    global _upstream_client, _upstream_client_loop, _in_flight
    loop = asyncio.get_running_loop()
    client = _upstream_client
    if client is None or _upstream_client_loop is not loop or getattr(client, "is_closed", False):
        _in_flight = asyncio.Semaphore(MAX_IN_FLIGHT)
        client = httpx.AsyncClient(
            http2=HTTP2_AVAILABLE,
            timeout=httpx.Timeout(UPSTREAM_TIMEOUT_S, connect=1.5),
            limits=httpx.Limits(
                max_connections=_UPSTREAM_MAX_CONNECTIONS,
                max_keepalive_connections=_UPSTREAM_KEEPALIVE,
                keepalive_expiry=90.0,
            ),
            headers=_HEADERS,
        )
        _upstream_client = client
        _upstream_client_loop = loop
    return client


def _reset_upstream_client_for_tests() -> None:
    global _upstream_client, _upstream_client_loop, _upstreams, _in_flight
    _upstream_client = None
    _upstream_client_loop = None
    _upstreams = []
    _in_flight = None


async def close_upstream_client() -> None:
    """Release the pooled connections (call from app shutdown)."""
    global _upstream_client, _upstream_client_loop
    client, _upstream_client, _upstream_client_loop = _upstream_client, None, None
    if client is not None:
        try:
            await client.aclose()
        except Exception:  # noqa: BLE001
            logger.debug("DoH upstream client close failed", exc_info=True)


def valid_answer(wire: bytes, status: int, body: bytes) -> bool:
    return status == 200 and 12 <= len(body) <= MAX_RESPONSE_BYTES and body[:2] == wire[:2]


# A pooled connection the server has just closed (HTTP/2 GOAWAY after N
# streams — Cloudflare rotates connections — or an HTTP/1.1 keep-alive race)
# fails the request with one of these before any answer exists. A DNS query
# is idempotent, so it is re-sent once, at once, on a fresh connection.
_RETRY_ONCE = (httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError)


async def _post(client: httpx.AsyncClient, url: str, wire: bytes, timeout: float) -> httpx.Response:
    try:
        return await client.post(url, content=wire, headers=_HEADERS, timeout=timeout)
    except _RETRY_ONCE:
        return await client.post(url, content=wire, headers=_HEADERS, timeout=timeout)


async def _ask(client: httpx.AsyncClient, up: Upstream, wire: bytes, timeout: float) -> Optional[bytes]:
    try:
        sem = _in_flight
        if sem is None:
            resp = await _post(client, up.url, wire, timeout)
        else:
            async with sem:
                resp = await _post(client, up.url, wire, timeout)
        body = resp.content
        if not valid_answer(wire, resp.status_code, body):
            logger.warning("DoH upstream returned an unusable answer (HTTP %d)", resp.status_code)
            up.record(False)
            return None
    except asyncio.CancelledError:
        # Lost a hedge race: counts toward the breaker, so a black-holed
        # upstream stops costing every query the hedge delay.
        up.record(False)
        raise
    except Exception as exc:  # noqa: BLE001
        logger.warning("DoH upstream call failed: %s", type(exc).__name__)
        up.record(False)
        return None
    up.record(True)
    return body


async def proxy_to_upstream(wire: bytes) -> Optional[bytes]:
    """Forward the wire-format query; the first valid answer, or None when
    every upstream failed inside the budget. Never raises."""
    try:
        client = _get_upstream_client()
        now = time.monotonic()
        ups = upstreams()
        order = [u for u in ups if u.healthy(now)] + [u for u in ups if not u.healthy(now)]
        loop = asyncio.get_running_loop()
        deadline = loop.time() + UPSTREAM_TIMEOUT_S
        pending: set[asyncio.Task] = set()
        nxt = 0

        def launch() -> None:
            nonlocal nxt
            remaining = max(0.05, deadline - loop.time())
            pending.add(loop.create_task(_ask(client, order[nxt], wire, remaining)))
            nxt += 1

        launch()
        try:
            while pending:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    break
                wait = min(HEDGE_AFTER_S, remaining) if nxt < len(order) else remaining
                done, pending = await asyncio.wait(pending, timeout=wait, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    answer = task.result()
                    if answer is not None:
                        return answer
                # Either the hedge timer fired or an upstream failed: ask the next.
                if nxt < len(order):
                    launch()
            return None
        finally:
            for task in pending:
                task.cancel()
    except Exception as exc:  # noqa: BLE001 — the caller decides what to answer
        logger.warning("DoH upstream dispatch failed: %s", type(exc).__name__)
        return None


def status() -> list[dict]:
    return [u.status() for u in upstreams()]

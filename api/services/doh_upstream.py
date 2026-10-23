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
     parallel and whichever answers first wins;
  4. all of it inside one UPSTREAM_TIMEOUT_S budget. Nothing answered → None,
     and the caller serves a stale cached answer or SERVFAIL.
A request the query no longer waits for (the hedge loser, or one still out at
the deadline) is not cancelled: it runs on until the upstream answers it, and
keeps its slot until then (see MAX_IN_FLIGHT).

A per-upstream breaker (3 consecutive failures or lost hedges → skipped for
10 s, then retried) means a dead upstream costs the hedge delay a handful of
times, not on every query. A skipped upstream is still tried last.

Requests at the upstreams are limited per worker (MAX_IN_FLIGHT) and per zone
(ZONE_MAX_IN_FLIGHT, the name's registrable domain): random subdomains of a
zone whose servers never answer each wait the whole budget, and without the
zone limit a few of them a second took every slot while every other cache
miss queued behind them (docs/runbooks/doh-gateway.md, 2026-10-23). A query
over its zone's limit waits without being sent; a freed slot goes to the
newest waiting query.

Responses are validated before they are believed: HTTP 200, 12..65535 bytes,
the query's transaction ID. Query bytes are forwarded exactly as received —
EDNS0 options and padding pass through, and no ECS option is ever added.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import Optional

import httpx

from api.services import doh_metrics

logger = logging.getLogger("api.services.doh_gateway")

CLOUDFLARE_DOH_URL = "https://cloudflare-dns.com/dns-query"
QUAD9_DOH_URL = "https://dns.quad9.net/dns-query"  # no ECS on this endpoint
CLOUDFLARE_IP_DOH_URL = "https://1.1.1.1/dns-query"  # same resolver, no DNS lookup of its own name
# Cloudflare only by default: the public privacy policy (§11) names Cloudflare as
# where unblocked names go. Quad9 is a ready second operator — add it with
# DOH_UPSTREAMS once the policy paragraph says so in all locales.
DEFAULT_UPSTREAMS = (CLOUDFLARE_DOH_URL, CLOUDFLARE_IP_DOH_URL)
DOH_CONTENT_TYPE = "application/dns-message"
UPSTREAM_TIMEOUT_S = 4.0
# How long one HTTP request may stay open — longer than a query waits: a
# request the query gave up on runs on until the upstream answers (see
# proxy_to_upstream). Cloudflare answers a zone whose servers never respond
# with SERVFAIL after up to ~5.4 s (measured 2026-10-23).
REQUEST_TIMEOUT_S = 10.0
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
# growing with load: excess queries wait on a cheap asyncio queue instead.
# Over HTTP/2 every request to one upstream shares one connection (httpcore
# opens no second one), which carries at most 100 open streams (what
# Cloudflare and Quad9 announce, and httpcore's own ceiling). At 100, every
# new request on it fails at once ("Max outbound streams is 100") — and a
# cancelled request's stream stays open until the upstream answers it
# (httpcore sends no RST_STREAM). So no request is cancelled once sent, and
# the cap counts every open stream: 100 less a margin for the streams
# httpcore drops on its own (REQUEST_TIMEOUT_S, a connection error).
# Names nobody answers each hold a slot until Cloudflare gives up (≤ ~5.4 s;
# with the hedge, two): 32 slots were gone at ~4 such names a second.
_UPSTREAM_MAX_CONNECTIONS = 32
_UPSTREAM_KEEPALIVE = 32
MAX_IN_FLIGHT = 96
# One zone (registrable domain), hedges included. A zone answering in 20 ms
# reaches it only at ~400 queries/s from one worker; a zone that never
# answers holds it, and nothing more.
ZONE_MAX_IN_FLIGHT = 8
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


class _Slots:
    """At most `size` holders; the rest wait, and a freed slot goes to the
    NEWEST waiter. When there are waiters, the oldest is the closest to giving
    up (UPSTREAM_TIMEOUT_S): sending its request would put one nobody waits
    for on the upstream connection, where it stays open until answered."""

    __slots__ = ("free", "waiters")

    def __init__(self, size: int) -> None:
        self.free = size
        self.waiters: list[asyncio.Future] = []

    async def acquire(self) -> None:
        if self.free > 0:
            self.free -= 1
            return
        fut = asyncio.get_running_loop().create_future()
        self.waiters.append(fut)
        try:
            await fut
        except asyncio.CancelledError:
            if fut.done() and not fut.cancelled():
                self.release()  # handed a slot just as we gave up: pass it on
            elif fut in self.waiters:
                self.waiters.remove(fut)
            raise

    def release(self) -> None:
        while self.waiters:
            fut = self.waiters.pop()
            if not fut.done():
                fut.set_result(None)
                return
        self.free += 1


class _Attempt:
    """One query's request to one upstream."""

    __slots__ = ("up", "sent", "abandoned")

    def __init__(self, up: Upstream) -> None:
        self.up = up
        self.sent = False  # at the upstream (it holds a stream there)
        self.abandoned = False  # the query has its outcome without this answer


_upstreams: list[Upstream] = []
_upstream_client: Optional[httpx.AsyncClient] = None
_upstream_client_loop: object = None
_in_flight: Optional[_Slots] = None
_zones: dict[str, _Slots] = {}
# Requests no query waits for any more, running on until the upstream answers.
# Referenced here because the event loop keeps only weak references to tasks.
_abandoned: set[asyncio.Task] = set()


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
    global _upstream_client, _upstream_client_loop, _in_flight, _zones
    loop = asyncio.get_running_loop()
    client = _upstream_client
    if client is None or _upstream_client_loop is not loop or getattr(client, "is_closed", False):
        _in_flight = _Slots(MAX_IN_FLIGHT)
        _zones = {}
        client = httpx.AsyncClient(
            http2=HTTP2_AVAILABLE,
            timeout=httpx.Timeout(REQUEST_TIMEOUT_S, connect=1.5),
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
    global _upstream_client, _upstream_client_loop, _upstreams, _in_flight, _zones
    _upstream_client = None
    _upstream_client_loop = None
    _upstreams = []
    _in_flight = None
    _zones = {}
    _abandoned.clear()


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


async def _post(client: httpx.AsyncClient, url: str, wire: bytes) -> httpx.Response:
    try:
        return await client.post(url, content=wire, headers=_HEADERS)
    except _RETRY_ONCE:
        return await client.post(url, content=wire, headers=_HEADERS)


def _zone_of(wire: bytes) -> str:
    """The query's registrable domain (doh_gateway's eTLD+1 heuristic)."""
    # doh_gateway imports this module at the end of its own body.
    from api.services.doh_gateway import _registrable_domain, parse_qname
    return _registrable_domain(parse_qname(wire) or "")


@contextlib.asynccontextmanager
async def _turn(zone: str):
    """A slot of the zone, then a worker slot: held while the request is at the
    upstream. A query waiting for its zone holds no worker slot."""
    worker = _in_flight
    slots = _zones.get(zone)
    if slots is None:
        slots = _zones[zone] = _Slots(ZONE_MAX_IN_FLIGHT)
    try:
        if slots.free == 0:
            doh_metrics.METRICS.inc("upstream_zone_wait")
        await slots.acquire()
        try:
            if worker.free == 0:
                doh_metrics.METRICS.inc("upstream_slot_wait")
            await worker.acquire()
            try:
                yield
            finally:
                worker.release()
        finally:
            slots.release()
    finally:
        if slots.free == ZONE_MAX_IN_FLIGHT and _zones.get(zone) is slots:
            del _zones[zone]


async def _ask(client: httpx.AsyncClient, attempt: _Attempt, wire: bytes, zone: str) -> Optional[bytes]:
    up = attempt.up
    body: Optional[bytes] = None
    try:
        async with _turn(zone):
            attempt.sent = True
            resp = await _post(client, up.url, wire)
        if valid_answer(wire, resp.status_code, resp.content):
            body = resp.content
        else:
            logger.warning("DoH upstream returned an unusable answer (HTTP %d)", resp.status_code)
    except Exception as exc:  # noqa: BLE001
        logger.warning("DoH upstream call failed: %s", type(exc).__name__)
    if attempt.abandoned:
        return None  # the query has counted this upstream's outcome already
    up.record(body is not None)
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
        zone = _zone_of(wire)
        pending: set[asyncio.Task] = set()
        attempts: dict[asyncio.Task, _Attempt] = {}
        nxt = 0

        def launch() -> None:
            nonlocal nxt
            attempt = _Attempt(order[nxt])
            task = loop.create_task(_ask(client, attempt, wire, zone))
            attempts[task] = attempt
            pending.add(task)
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
                attempt = attempts[task]
                if not attempt.sent:
                    task.cancel()  # still waiting for its turn: nothing at the upstream yet
                    continue
                # Lost a hedge race or ran out of time: counts toward the
                # breaker, so a black-holed upstream stops costing every query
                # the hedge delay. The request itself runs on, holding its slot:
                # cancelled, its stream would stay open at the upstream anyway.
                attempt.abandoned = True
                attempt.up.record(False)
                doh_metrics.METRICS.inc("upstream_abandoned")
                _abandoned.add(task)
                task.add_done_callback(_abandoned.discard)
    except Exception as exc:  # noqa: BLE001 — the caller decides what to answer
        logger.warning("DoH upstream dispatch failed: %s", type(exc).__name__)
        return None


def status() -> list[dict]:
    return [u.status() for u in upstreams()]

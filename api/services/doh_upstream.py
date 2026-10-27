"""Upstream resolvers for the DoH gateway: pooled, HTTP/2, with failover.

One httpx.AsyncClient per upstream and event loop, HTTP/2 when the `h2`
package is installed (one multiplexed TLS connection per upstream instead of a
pool of HTTP/1.1 sockets — measured in docs/runbooks/doh-gateway.md, the
HTTP/1.1 pool's per-request bookkeeping was the gateway's main CPU cost under
load).

Order of attempts for one query (proxy_to_upstream):
  1. the first healthy upstream (configured order: Cloudflare, then Quad9),
     or the next one with a free slot when it has none;
  2. if it fails outright (refused, reset, TLS, non-200, garbage) → the next
     one immediately;
  3. if it is merely slow → HEDGE_AFTER_S after it was sent the next one is
     asked in parallel if it has spare room (_take), and whichever answers
     first wins;
  4. all of it inside one UPSTREAM_TIMEOUT_S budget. Nothing answered → None,
     and the caller serves a stale cached answer or SERVFAIL.
A request the query no longer waits for (the hedge loser, or one still out at
the deadline) is not cancelled: it runs on until the upstream answers it, and
keeps its slot until then (see MAX_IN_FLIGHT) — at most REQUEST_TIMEOUT_S after
it was sent, when it is dropped together with its connection.

A per-upstream breaker (3 consecutive failures or lost hedges → skipped for
10 s, then retried) means a dead upstream costs the hedge delay a handful of
times, not on every query. A skipped upstream is still tried last.

Requests at the upstreams are limited per upstream (MAX_IN_FLIGHT, the streams
of its one connection) and per zone (ZONE_MAX_IN_FLIGHT, plus half of the
upstream's free slots): random subdomains of a zone whose servers never answer
each wait the whole budget, and until 2026-10-23 ~4-8 of them a second took
all 32 slots a worker then had, while every other cache miss queued behind
them (docs/runbooks/doh-gateway.md, «A zone that never answers»). A query
waits for room in its zone holding no slot, and for a slot without taking its
zone's room; a freed slot goes to the newest waiting query whose zone has
room.

Responses are validated before they are believed: HTTP 200, 12..65535 bytes,
the query's transaction ID. Query bytes are forwarded exactly as received —
EDNS0 options and padding pass through, and no ECS option is ever added.
"""
from __future__ import annotations

import asyncio
import logging
import time
import weakref
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
# How long one request may stay open at the upstream — longer than a query
# waits: a request the query gave up on runs on until the upstream answers
# (see proxy_to_upstream). Cloudflare answers a zone whose servers never
# respond with SERVFAIL after 0.1-9.3 s: p50 2.5 s, p99 8.5 s, none past
# 10 s (280 names under four such zones, both endpoints, 2026-10-28; up to
# ~5.4 s on 2026-10-23) — inside this bound, if not by much. httpx's read
# timeout (the same value) does not bound a request over HTTP/2: it times one
# network read on the shared connection, and any other stream's data starts
# it again, so a stream the upstream never answers stayed open for as long as
# the connection carried traffic (probe 2026-10-27: still open after 8 s at a
# 1 s timeout; stand: every slot gone in ~9 s with 2 % such names). A request
# unanswered this long after it was first sent (a re-send included) is given
# up together with its connection (_ask, _drop) — cancelled alone, its stream
# would stay open there (see MAX_IN_FLIGHT); the requests still on that
# connection fail and are re-sent once on a new one (_post). Counted per
# re-send instead, fewer connections were dropped, and each drop is what
# frees the slots of every unanswered stream on it: with one upstream and 2 %
# names nobody answers, 12-39 % of the healthy misses got SERVFAIL instead of
# 0.1-5 % (stand, 2026-10-27, same seeds). Dropping the connection only once
# its upstream had no slot free (final review 2026-10-27) halved the drops
# under a stub that never answers 2 % of the names (stand row d2, two
# workers: ~21 a minute instead of ~44, one per connection every ~11 s, not ~6)
# but gave 0.4-0.7 % of the healthy misses SERVFAIL instead of 0-0.1 % (four
# runs each, same seeds): not taken. A drop costs a re-send of the requests a
# query still waits for and one warning.
REQUEST_TIMEOUT_S = 10.0
HEDGE_AFTER_S = 0.4
# uvloop (uvicorn[standard], so production) reads libuv's clock, in whole
# milliseconds: a wait can return with loop.time() just short of the time it
# waited for, and a wait for the rest returns at once until the millisecond
# ticks — p50 81 waits per query nobody answers instead of 10, CPU 1.9 ms
# instead of 0.7 (review 2026-10-28). The hedge time and the deadline count
# as reached this close to them.
_CLOCK_SLACK_S = 0.001
MAX_RESPONSE_BYTES = 65535
BREAKER_THRESHOLD = 3
BREAKER_COOLDOWN_S = 10.0

try:  # HTTP/2 needs the optional `h2` package (httpx[http2]).
    import h2  # noqa: F401
    HTTP2_AVAILABLE = True
except ImportError:  # pragma: no cover - depends on the environment
    HTTP2_AVAILABLE = False

# Connections per upstream, and the cap on its requests in flight.
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
# the cap counts the connection's open streams, a margin below 100.
# The cap is per upstream because the ceiling is per connection: Cloudflare
# by name and by IP are two connections, 2 x 96 slots. Shared, 96 slots were
# gone at ~9 names nobody answers a second (each held two, with the hedge,
# for Cloudflare's ~5.4 s; review 2026-10-27). Over HTTP/1.1 (no `h2`) a
# request needs a connection of its own: the cap is the pool's size.
_UPSTREAM_MAX_CONNECTIONS = 32
_UPSTREAM_KEEPALIVE = 32
MAX_IN_FLIGHT = 96
# A zone's room at an upstream (_Zone.has_room): ZONE_MAX_IN_FLIGHT requests
# at the upstreams (both upstreams and hedges counted), plus half of the slots
# that upstream has free. The zone is the query name's parent, never shorter
# than its registrable domain (_zone_of). Alone, a zone gets 43 of an
# upstream's 96 slots: one nobody answers leaves the other names 53. The more
# of the slots other names use, the less a zone gets past its 16. A fixed 16
# gave a zone answering in 1 s at 40 queries/s per worker 62-64 % SERVFAIL
# while the upstream had 60 slots free (stand, row e; final review
# 2026-10-27; main's semaphore answered such a zone up to its 32 slots); now
# 16.5 %, its answers slowed to ~1.6 s with that many requests open on one
# connection. Each open request slows the other answers on its connection:
# httpcore reads it under one lock, taken in turn by every waiting stream.
# With 43 requests open instead of 16, a zone nobody answers raised the other
# cache misses' p50 from 30 to 70 ms (stand, row a, 2026-10-28); a quarter of
# the free slots instead of half gave 55 ms and 32 % SERVFAIL for the 1 s
# zone.
# Six or more zones nobody answers, each sent enough names to fill its 16,
# take every slot of an upstream, as six did with a fixed 16 (virtual-clock
# model, 2026-10-28: healthy misses 0 % SERVFAIL with five, 54 % with six on
# one upstream, 0 % with ten on two).
ZONE_MAX_IN_FLIGHT = 16
_HEADERS = {"Content-Type": DOH_CONTENT_TYPE, "Accept": DOH_CONTENT_TYPE}


class _Waiters:
    """Queries waiting for something, woken NEWEST first. When there are
    waiters, the oldest is the closest to giving up (UPSTREAM_TIMEOUT_S):
    sending its request would put one nobody waits for on the upstream
    connection, where it stays open until answered."""

    __slots__ = ("waiters",)

    def __init__(self) -> None:
        self.waiters: list[asyncio.Future] = []

    async def _park(self) -> None:
        fut = asyncio.get_running_loop().create_future()
        self.waiters.append(fut)
        try:
            await fut
        except asyncio.CancelledError:
            if fut.done() and not fut.cancelled():
                self._pass_on()  # woken just as we gave up
            elif fut in self.waiters:
                self.waiters.remove(fut)
            raise

    def _wake(self) -> bool:
        while self.waiters:
            fut = self.waiters.pop()
            if not fut.done():
                fut.set_result(None)
                return True
        return False

    def _pass_on(self) -> None:
        """A waiter handed something gave up before it ran: pass it on. A
        zone hands nothing (its woken waiter checks the room again), and
        _acquire wakes the next one whenever a query leaves with room left."""

    def waiting(self) -> int:
        return sum(1 for f in self.waiters if not f.done())


class _Slots(_Waiters):
    """At most `size` requests at one upstream; the rest wait for a slot."""

    __slots__ = ("size", "free")

    def __init__(self, size: int) -> None:
        super().__init__()
        self.size = self.free = size

    async def acquire(self) -> None:
        if self.free > 0:
            self.free -= 1
            return
        await self._park()  # release() handed us its slot

    def release(self) -> None:
        if not self._wake():
            self.free += 1

    _pass_on = release


class _Zone(_Waiters):
    """One zone's requests at the upstreams, and the queries waiting for room
    in it. A waiter is woken when a request of the zone finishes; it then
    waits for a slot like any other query, and checks the room again once it
    has one."""

    __slots__ = ("used", "refs")

    def __init__(self) -> None:
        super().__init__()
        self.used = 0  # requests at the upstreams
        self.refs = 0  # attempts holding or waiting for room here

    def has_room(self, slots: _Slots, held: int = 0) -> bool:
        """Room for one more request at the upstream `slots` belong to: the
        zone's ZONE_MAX_IN_FLIGHT, plus half of the slots that upstream has
        free (`held`: a slot the asking query has taken already, counted as
        free)."""
        return self.used < ZONE_MAX_IN_FLIGHT + (slots.free + held) // 2

    async def wait_for_room(self) -> None:
        await self._park()


class Upstream:
    __slots__ = ("url", "fail_streak", "skip_until", "ok_count", "fail_count", "client", "slots")

    def __init__(self, url: str) -> None:
        self.url = url
        self.fail_streak = 0
        self.skip_until = 0.0
        self.ok_count = 0
        self.fail_count = 0
        # This event loop's (_bind): its pooled connection and its slots.
        self.client: Optional[httpx.AsyncClient] = None
        self.slots: Optional[_Slots] = None

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
        slots = self.slots
        return {"url": self.url, "healthy": self.healthy(time.monotonic()),
                "ok": self.ok_count, "failed": self.fail_count,
                # now, not since start: requests at it, and queries waiting for a slot
                "in_flight": slots.size - slots.free if slots else 0,
                "waiting": slots.waiting() if slots else 0}


class _Attempt:
    """One query's request to one upstream."""

    __slots__ = ("up", "sent", "sent_at", "started", "abandoned", "client")

    def __init__(self, up: Upstream, loop: asyncio.AbstractEventLoop) -> None:
        self.up = up
        self.sent = loop.create_future()  # done once it is at the upstream
        self.sent_at: Optional[float] = None  # holds a slot (and a stream) there since
        self.started = False  # its task has run (_ask)
        self.abandoned = False  # the query has its outcome without this answer
        self.client: Optional[httpx.AsyncClient] = None  # the one its request went out on

    def mark_sent(self, now: float) -> None:
        self.sent_at = now
        if not self.sent.done():
            self.sent.set_result(None)


_upstreams: list[Upstream] = []
# The event loop the upstreams' clients and slots, and the zones, belong to.
_loop: object = None
_zones: dict[str, _Zone] = {}
# Requests no query waits for any more, running on until the upstream answers,
# and clients being closed (_drop). Referenced here because the event loop
# keeps only weak references to tasks.
_abandoned: set[asyncio.Task] = set()
_closing: dict[httpx.AsyncClient, asyncio.Task] = {}
_dropped: "weakref.WeakSet[httpx.AsyncClient]" = weakref.WeakSet()
# Requests out on each client now: a drop's one warning says how many it cut off.
_open: dict[httpx.AsyncClient, int] = {}


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


def _bind(loop: asyncio.AbstractEventLoop, ups: list[Upstream]) -> None:
    """Clients, slots and zones are this event loop's (tests run many)."""
    global _loop, _zones
    if _loop is not loop:
        _loop, _zones = loop, {}
        _abandoned.clear()
        _closing.clear()
        _open.clear()
        for up in ups:
            up.client = up.slots = None
    for up in ups:
        if up.slots is None:
            up.slots = _Slots(MAX_IN_FLIGHT if HTTP2_AVAILABLE else _UPSTREAM_MAX_CONNECTIONS)


def _client_for(up: Upstream) -> httpx.AsyncClient:
    client = up.client
    if client is None or getattr(client, "is_closed", False):
        client = up.client = httpx.AsyncClient(
            http2=HTTP2_AVAILABLE,
            timeout=httpx.Timeout(REQUEST_TIMEOUT_S, connect=1.5),
            limits=httpx.Limits(
                max_connections=_UPSTREAM_MAX_CONNECTIONS,
                max_keepalive_connections=_UPSTREAM_KEEPALIVE,
                keepalive_expiry=90.0,
            ),
            headers=_HEADERS,
        )
    return client


def _reset_upstream_client_for_tests() -> None:
    global _upstreams, _loop, _zones
    _upstreams = []
    _loop = None
    _zones = {}
    _abandoned.clear()
    _closing.clear()
    _open.clear()


async def _close(client: httpx.AsyncClient) -> None:
    try:
        await client.aclose()
    except Exception:  # noqa: BLE001
        logger.debug("DoH upstream client close failed", exc_info=True)


def _drop(up: Upstream, client: Optional[httpx.AsyncClient]) -> None:
    """A request on `client` stayed unanswered REQUEST_TIMEOUT_S: close the
    client and its connection; the upstream's next request opens a new one.
    One warning per connection, however many requests fail with it — each of
    them is logged at DEBUG (one warning each: ~25 lines per drop on the
    stand, final review 2026-10-27)."""
    if up.client is client:
        up.client = None
    if client is None or client in _dropped:
        logger.debug("DoH upstream request unanswered for %.0f s on a connection already dropped",
                     REQUEST_TIMEOUT_S)
        return
    _dropped.add(client)
    doh_metrics.METRICS.inc("upstream_dropped")
    logger.warning("DoH upstream left a request unanswered for %.0f s: connection dropped with %d other "
                   "requests on it (those a query still waits for are sent again)",
                   REQUEST_TIMEOUT_S, _open.get(client, 0))
    task = asyncio.get_running_loop().create_task(_close(client))
    _closing[client] = task
    task.add_done_callback(lambda _t: _closing.pop(client, None))


async def close_upstream_client() -> None:
    """Release the pooled connections (call from app shutdown). Requests no
    query waits for are cancelled first: their streams go with the
    connection, and failed by the close each would log an upstream failure
    (5-9 warnings per API restart on the stand, 2026-10-27)."""
    if _loop is asyncio.get_running_loop() and _abandoned:
        left = list(_abandoned)
        for task in left:
            task.cancel()
        await asyncio.gather(*left, return_exceptions=True)
    for up in _upstreams:
        client, up.client = up.client, None
        if client is not None:
            await _close(client)


def valid_answer(wire: bytes, status: int, body: bytes) -> bool:
    return status == 200 and 12 <= len(body) <= MAX_RESPONSE_BYTES and body[:2] == wire[:2]


# A pooled connection the server has just closed (HTTP/2 GOAWAY after N
# streams — Cloudflare rotates connections — or an HTTP/1.1 keep-alive race)
# fails the request with one of these before any answer exists. A DNS query
# is idempotent, so it is re-sent once, at once, on a fresh connection — as
# is a request whose connection we dropped (_drop), whatever it failed with
# (caught mid-send: LocalProtocolError) — unless no query waits for its
# answer any more: re-sent, it would hold a slot for another whole answer
# time (stand 2026-10-27: the stub's GOAWAY every 1000 requests, 5.4 % vs
# 0 % SERVFAIL).
_RETRY_ONCE = (httpx.RemoteProtocolError, httpx.ReadError, httpx.WriteError)


async def _send(attempt: _Attempt, wire: bytes) -> httpx.Response:
    client = attempt.client = _client_for(attempt.up)
    _open[client] = _open.get(client, 0) + 1
    try:
        return await client.post(attempt.up.url, content=wire, headers=_HEADERS)
    finally:
        left = _open.pop(client, 1) - 1
        if left > 0:
            _open[client] = left


async def _post(attempt: _Attempt, wire: bytes) -> httpx.Response:
    try:
        return await _send(attempt, wire)
    except Exception as exc:  # noqa: BLE001 — re-raised unless re-sent
        if attempt.abandoned or not (isinstance(exc, _RETRY_ONCE) or attempt.client in _dropped):
            raise
        return await _send(attempt, wire)


def _zone_of(wire: bytes) -> str:
    """The query name's parent, never shorter than its registrable domain
    (doh_gateway's eTLD+1 heuristic): r1f.dead.example → dead.example,
    4.3.2.1.in-addr.arpa → 3.2.1.in-addr.arpa (its /24), www.bbc.co.uk →
    bbc.co.uk. Not the registrable domain itself: that put a dead subzone
    (old.bank.com) and its siblings (www.bank.com), every tenant of a shared
    suffix the heuristic does not know (x.eu.org) and every reverse lookup
    (in-addr.arpa) under one limit (review 2026-10-27)."""
    # doh_gateway imports this module at the end of its own body.
    from api.services.doh_gateway import _registrable_domain, parse_qname
    name = parse_qname(wire) or ""
    registrable = _registrable_domain(name)
    parent = name.partition(".")[2]
    return parent if len(parent) > len(registrable) else registrable


async def _acquire(zone: str, attempt: _Attempt) -> _Zone:
    """Room in the zone and a slot of the attempt's upstream, both held until
    _release. Waiting for one holds neither: a query waiting for room in its
    zone holds no slot, and one waiting for a slot does not take its zone's
    room — taken first, a busy zone's queued queries filled it while every
    freed slot went to other zones (review 2026-10-27). The room is checked
    again once the slot is ours: it depends on the upstream's free slots."""
    z = _zones.get(zone)
    if z is None:
        z = _zones[zone] = _Zone()
    z.refs += 1
    slots = attempt.up.slots
    waited_zone = waited_slot = False
    try:
        while True:
            if not z.has_room(slots):
                if not waited_zone:
                    doh_metrics.METRICS.inc("upstream_zone_wait")
                    waited_zone = True
                await z.wait_for_room()
                continue
            if slots.free == 0 and not waited_slot:
                doh_metrics.METRICS.inc("upstream_slot_wait")
                waited_slot = True
            await slots.acquire()
            if z.has_room(slots, held=1):
                z.used += 1
                return z
            slots.release()  # the zone filled while we waited for the slot: pass it on
    except BaseException:
        if z.has_room(slots):
            z._wake()  # it may have been woken for this room: hand it on
        _unref(zone, z)
        raise


def _take(zone: str, up: Upstream, spare: bool = False) -> Optional[_Zone]:
    """Room in the zone and a slot of `up`, taken at once — or None, and the
    attempt waits for them in _acquire. Taken here, not when the attempt's
    task first runs: a burst of queries would all pick the same upstream.

    A hedge (`spare`) only uses spare room: more than half of the upstream's
    slots and of the zone's share free, nobody waiting for the zone. Both
    default upstreams are one resolver — a hedge helps when a connection
    stalls, not when a name is slow — so slots are worth more to queries
    that have none (hedged, a name nobody answers held two; review
    2026-10-27)."""
    slots = up.slots
    z = _zones.get(zone)
    used = z.used if z is not None else 0
    if spare:
        if slots.free * 2 <= slots.size or used * 2 >= ZONE_MAX_IN_FLIGHT or (z is not None and z.waiting()):
            return None
    elif slots.free == 0 or (z is not None and not z.has_room(slots)):
        return None
    if z is None:
        z = _zones[zone] = _Zone()
    slots.free -= 1
    z.used += 1
    z.refs += 1
    return z


def _release(zone: str, z: _Zone, up: Upstream) -> None:
    z.used -= 1
    z._wake()
    up.slots.release()
    _unref(zone, z)


def _unref(zone: str, z: _Zone) -> None:
    z.refs -= 1
    if z.refs == 0 and _zones.get(zone) is z:
        del _zones[zone]


async def _ask(attempt: _Attempt, wire: bytes, zone: str, z: Optional[_Zone]) -> Optional[bytes]:
    """`z`: the room _take already took for this attempt, if any."""
    up = attempt.up
    attempt.started = True
    body: Optional[bytes] = None
    try:
        if z is None:
            z = await _acquire(zone, attempt)
            attempt.mark_sent(asyncio.get_running_loop().time())
        try:
            # Its query ended before its task started (_take took its room in
            # the round that reached the deadline). Inside the try: its slot
            # and its room still come back.
            if attempt.abandoned:
                return None
            resp = await asyncio.wait_for(_post(attempt, wire), REQUEST_TIMEOUT_S)
        finally:
            _release(zone, z, up)
        if valid_answer(wire, resp.status_code, resp.content):
            body = resp.content
        else:
            logger.warning("DoH upstream returned an unusable answer (HTTP %d)", resp.status_code)
    except asyncio.TimeoutError:
        _drop(up, attempt.client)
    except Exception as exc:  # noqa: BLE001
        if attempt.abandoned or attempt.client in _dropped:
            # No query waits for it (upstream_abandoned has counted it), or
            # _drop has said so, once for every request on the connection: a
            # connection that goes fails them all (GOAWAY, read timeout).
            logger.debug("DoH upstream call failed, nobody waiting or connection dropped: %s",
                         type(exc).__name__)
        else:
            logger.warning("DoH upstream call failed: %s", type(exc).__name__)
    if attempt.abandoned:
        return None  # the query has counted this upstream's outcome already
    up.record(body is not None)
    return body


def _first_free(order: list[Upstream]) -> Upstream:
    """The first upstream with a free slot, in order (healthy ones first),
    else the first. The breaker sets the order, not whether a free slot is
    used: an upstream that only gets hedges sees only slow names, and its
    breaker opens on races nobody won (virtual-clock run, 2026-10-27: 15
    dead names a second, the second upstream's breaker open with 48 slots
    free, 100-240 queries waiting for the first one's)."""
    for up in order:
        if up.slots.free > 0:
            return up
    return order[0]


async def proxy_to_upstream(wire: bytes) -> Optional[bytes]:
    """Forward the wire-format query; the first valid answer, or None when
    every upstream failed inside the budget. Never raises."""
    try:
        loop = asyncio.get_running_loop()
        ups = upstreams()
        _bind(loop, ups)
        now = time.monotonic()
        order = [u for u in ups if u.healthy(now)] + [u for u in ups if not u.healthy(now)]
        deadline = loop.time() + UPSTREAM_TIMEOUT_S
        zone = _zone_of(wire)
        pending: set[asyncio.Task] = set()
        attempts: dict[asyncio.Task, _Attempt] = {}
        newest: Optional[_Attempt] = None
        hedge_at: Optional[float] = None
        hedge_skipped = False

        def launch(up: Upstream, z: Optional[_Zone]) -> None:
            nonlocal newest, hedge_at
            order.remove(up)
            newest = _Attempt(up, loop)
            if z is not None:  # its room is taken: as good as sent
                newest.mark_sent(loop.time())
            task = loop.create_task(_ask(newest, wire, zone, z))
            attempts[task] = newest
            pending.add(task)
            hedge_at = None

        def launch_next() -> None:
            up = _first_free(order)
            launch(up, _take(zone, up))

        launch_next()
        try:
            while pending:
                remaining = deadline - loop.time()
                if remaining <= _CLOCK_SLACK_S:
                    break
                waits, wait = pending, remaining
                if order:  # an upstream is left to ask
                    if newest.sent_at is None:
                        # Its hedge timer starts when it is sent: while it
                        # waits on our side (its zone full, or no upstream had
                        # a free slot) a second request would only wait too.
                        waits = pending | {newest.sent}
                    else:
                        if hedge_at is None:
                            hedge_at = newest.sent_at + HEDGE_AFTER_S
                        wait = min(remaining, max(0.0, hedge_at - loop.time()))
                done, _ = await asyncio.wait(waits, timeout=wait, return_when=asyncio.FIRST_COMPLETED)
                failed = False
                for task in done:
                    if task in pending:
                        pending.discard(task)
                        answer = task.result()
                        if answer is not None:
                            return answer
                        failed = True
                if not order:
                    continue
                if failed:  # an upstream failed outright: the next one at once
                    launch_next()
                elif hedge_at is not None and loop.time() >= hedge_at - _CLOCK_SLACK_S:
                    for up in order:
                        z = _take(zone, up, spare=True)
                        if z is not None:
                            launch(up, z)
                            break
                    else:  # no spare room now: look again a hedge delay later
                        if not hedge_skipped:
                            doh_metrics.METRICS.inc("upstream_hedge_skipped")
                            hedge_skipped = True
                        hedge_at += HEDGE_AFTER_S
            return None
        finally:
            for task in pending:
                if task.done():
                    # Finished in the same round as the answer we returned:
                    # _ask has counted its outcome, and it holds nothing.
                    continue
                attempt = attempts[task]
                if attempt.sent_at is None:
                    task.cancel()  # still waiting for its turn: nothing at the upstream yet
                    continue
                attempt.abandoned = True
                _abandoned.add(task)
                task.add_done_callback(_abandoned.discard)
                if not attempt.started:
                    # Launched in the round that reached the deadline: its
                    # task gives the slot back without asking (_ask), so it
                    # says nothing about the upstream.
                    continue
                # Lost a hedge race or ran out of time: counts toward the
                # breaker, so a black-holed upstream stops costing every query
                # the hedge delay. The request itself runs on, holding its slot:
                # cancelled, its stream would stay open at the upstream anyway.
                attempt.up.record(False)
                doh_metrics.METRICS.inc("upstream_abandoned")
    except Exception as exc:  # noqa: BLE001 — the caller decides what to answer
        logger.warning("DoH upstream dispatch failed: %s", type(exc).__name__)
        return None


def status() -> list[dict]:
    return [u.status() for u in upstreams()]


def slots_status() -> dict:
    """What holds this worker's upstream slots now (/health/doh): zones at
    their limit and the queries waiting for room in them, requests no query
    waits for still open, connections being dropped (REQUEST_TIMEOUT_S)."""
    zones = list(_zones.values())
    return {"zones_full": sum(1 for z in zones if z.waiting()),
            "zone_waiting": sum(z.waiting() for z in zones),
            "abandoned": len(_abandoned),
            "dropping": len(_closing)}

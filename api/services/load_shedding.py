"""Load shedding: a bounded amount of work in flight per worker process.

Measured 2026-10-22 (docs/runbooks/capacity.md): past saturation the API
refused nothing. Requests piled up in memory — ~550 MB, once 917 MB of a
1 GB container — latency climbed to seconds, and the server kept working on
requests whose clients had long timed out. Now every request needs a slot of
its class; with none free it gets an immediate 503 with Retry-After, before
routing, auth or a log line. A flood then costs a fraction of what serving
it would, and the requests already admitted finish in time.

A slot bounds the work THIS worker does, never the time it waits on someone
else (review of PR #295: each of these let a few hundred idle connections
or a slow upstream refuse everyone):
  * at most 64 KiB of a request body (a DoH query, the API's JSON) is read
    before the slot is taken, so a client that sends it slowly, or never,
    holds no slot. The rest of a bigger body is read as the route asks for
    it, and the voice upload — its route checks the caller first — gets
    nothing read ahead. Every byte stays under the route's size cap
    (request_guards, 413) and a deadline (408). Until the audit of
    2026-10-25 the whole body was read ahead: 26 MiB for the voice upload,
    before auth or any budget — ~40 stalled anonymous uploads held ~1 GB;
  * the slot is given back when the answer starts going out: a slow reader
    of a big answer (the 2.6 MB phone blocklist) is the client's time;
  * a DNS query gives its slot back while it waits on the upstream (its own
    forward, or another query's for the same name). The forwards have their
    own budget, dns_upstream; past it a query is answered as when the
    upstream fails — serve-stale, else SERVFAIL, HTTP 200, never a 503.

Limits are per worker process — each uvicorn worker has its own counters, so
a replica with WEB_CONCURRENCY=2 admits twice these. 0 = no limit. Settings
LOAD_SHED_* in api/config.py; LOAD_SHED_ENABLED=false switches all of it off.

  request classes (LoadShedding, the outermost middleware)
    dns          /dns-query, the work on our side                    1024
    health       /health                                               64
    health_doh   /health/doh (the DNS monitor's probe)                 64
    health_deep  /health/deep (its probes queue behind each other)     64
    api          every other request                                  128

  inside a request — refused or skipped at once, never queued
    dns upstream  DoH forwards waiting on Cloudflare/Quad9: answered as a
                  failed upstream (serve-stale, else SERVFAIL)        1024
    fresh analyses   the analyzer's full fan-out (/check, the fresh path of
                     /public/check): 503 without a slot.               32
                     One /check takes at most a quarter of them; the rest
                     of its batch waits its turn (routers/check.py)
    LLM calls        the judge, the explainer (each its own budget):
                     skipped — the verdict stands, the explainer
                     answers from its template                          4
    competitor lookups  the Cloudflare comparison on public checks:
                     skipped (`competitors` empty)                     32

  outbound gate — waits instead
    every source call and site probe of an analysis waits for one of
    LOAD_SHED_OUTBOUND_MAX_INFLIGHT (512). The wait is bounded by what was
    admitted (fresh analyses x checks) and by the analysis deadline, which
    cancels it; a source's own time limit starts once the call may run.

The classes are separate so a flood of one cannot take the slots of another:
a crawler storm on /public/check gets 503s while phones keep resolving and
monitors keep getting answers. All classes share one event loop; what keeps
DNS's CPU is that the expensive work is capped and everything past a budget
is refused cheaply — measured: cached names answered in ~15-40 ms (before:
0.5-1.5 s and timeouts) while public checks flooded the API. An extra limit
on the loop's lag was tried on top and changed nothing in those runs, so
there is none.

Shedding is logged as ONE aggregate `load_shed` line per worker at most every
LOG_EVERY_S, never a line per refused request; the counters are in
/health/doh (`load_shed`).
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from contextlib import asynccontextmanager, contextmanager
from contextvars import ContextVar
from typing import AsyncIterator, Iterator, Optional, Union

from fastapi.responses import JSONResponse

logger = logging.getLogger("cleanway.load_shed")

LOG_EVERY_S = 10.0
BUSY_DETAIL = "The server is busy. Please try again in a moment."
_DEFAULT_RETRY_AFTER_S = 2
_DEFAULT_BODY_TIMEOUT_S = 10.0
# A body must arrive within LOAD_SHED_BODY_TIMEOUT_S plus its size at this
# rate (~0.5 Mbit/s): 1 KB of JSON ~10 s, the 1 MiB cap ~26 s, a 25 MB voice
# upload ~7 min. The wait for the part read ahead holds no slot; the rest
# keeps the slot only until this deadline.
_MIN_UPLOAD_BYTES_PER_S = 64 * 1024
# What is read of a body before a slot: a whole DoH message (<= 65,535
# bytes) and the API's usual JSON. uvicorn buffers about as much per
# connection on its own (its read high-water mark).
_PRE_READ_BYTES = 64 * 1024
_GONE = 0  # the client went away mid-body: nobody to answer
_BODY_REFUSALS = {408: "Request body not received in time", 413: "Request body too large"}


def _settings():
    from api.config import get_settings
    return get_settings()


def _enabled() -> bool:
    try:
        return bool(_settings().load_shed_enabled)
    except Exception:  # noqa: BLE001 — shedding must never fail a request
        return False


def _setting(name: str) -> int:
    """A LOAD_SHED_* limit; 0 (no limit) when switched off or unreadable."""
    try:
        settings = _settings()
        return int(getattr(settings, name)) if settings.load_shed_enabled else 0
    except Exception:  # noqa: BLE001
        return 0


def retry_after_s() -> int:
    try:
        return max(1, int(_settings().load_shed_retry_after_s))
    except Exception:  # noqa: BLE001
        return _DEFAULT_RETRY_AFTER_S


def body_timeout_s() -> float:
    try:
        return max(0.0, float(_settings().load_shed_body_timeout_s))
    except Exception:  # noqa: BLE001
        return _DEFAULT_BODY_TIMEOUT_S


class Overloaded(Exception):
    """A budget inside the request had no free slot: answered 503 +
    Retry-After by `overloaded_response` (registered in api.main).

    Not an HTTPException, and without a `status_code`, on purpose: Sentry's
    Starlette integration reports every handled exception carrying a 5xx
    status_code as an error event, and a flood of refusals must not become a
    flood of Sentry events."""

    def __init__(self, budget: str) -> None:
        super().__init__(budget)
        self.budget = budget


def _busy_header_dict() -> dict[str, str]:
    return {"Retry-After": str(retry_after_s()), "Cache-Control": "no-store"}


async def overloaded_response(request, exc: Exception) -> JSONResponse:
    return JSONResponse({"detail": BUSY_DETAIL}, status_code=503, headers=_busy_header_dict())


class Budget:
    """A non-blocking in-flight counter: a caller gets a slot now or is told
    no — nothing waits. One event loop per worker and no await between the
    check and the increment, so a plain int is exact."""

    def __init__(self, name: str, limit: Union[str, int]) -> None:
        self.name = name
        self._limit = limit  # a Settings attribute, or a fixed number
        self.in_flight = 0
        self.peak = 0
        self.shed = 0

    def limit(self) -> int:
        if isinstance(self._limit, int):
            return self._limit if _enabled() else 0
        return _setting(self._limit)

    def full(self) -> bool:
        limit = self.limit()
        return 0 < limit <= self.in_flight

    def try_acquire(self, n: int = 1) -> int:
        """Take up to `n` slots; returns how many were taken (0 when full)."""
        limit = self.limit()
        granted = n if limit <= 0 else max(0, min(n, limit - self.in_flight))
        self.in_flight += granted
        self.peak = max(self.peak, self.in_flight)
        if granted < n:
            self._refused(n - granted)
        return granted

    def release(self, n: int = 1) -> None:
        self.in_flight = max(0, self.in_flight - n)

    def admits(self) -> bool:
        """Is a slot free now? Takes none; a no is counted as shed. For
        refusing before anything is spent on the request (a quota, a paid
        budget) — the slot itself is taken afterwards, and may then be gone."""
        if self.full():
            self._refused(1)
            return False
        return True

    def check(self) -> None:
        """`admits()`, raising Overloaded on a no."""
        if not self.admits():
            raise Overloaded(self.name)

    @contextmanager
    def slot(self) -> Iterator[None]:
        if not self.try_acquire():
            raise Overloaded(self.name)
        try:
            yield
        finally:
            self.release()

    def snapshot(self) -> dict:
        return {"in_flight": self.in_flight, "limit": self.limit(), "peak": self.peak, "shed": self.shed}

    def _refused(self, n: int) -> None:
        self.shed += n
        _note_shed()

    def _reset(self) -> None:
        self.in_flight = self.peak = self.shed = 0


class Gate:
    """The waiting counterpart, for outbound calls: at most `limit` run at
    once, the rest wait their turn. One asyncio.Semaphore per event loop (a
    uvicorn worker has one; each asyncio.run in a test gets its own), sized
    from the settings when the loop first uses it."""

    def __init__(self, name: str, setting: str) -> None:
        self.name = name
        self._setting = setting
        self._sem: Optional[asyncio.Semaphore] = None
        self._loop: object = None
        self._size = 0
        self.in_flight = 0
        self.peak = 0
        self.waited = 0

    def _semaphore(self) -> Optional[asyncio.Semaphore]:
        loop = asyncio.get_running_loop()
        if self._loop is not loop:
            self._size = _setting(self._setting)
            self._sem = asyncio.Semaphore(self._size) if self._size > 0 else None
            self._loop = loop
        return self._sem

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        sem = self._semaphore()
        if sem is None:
            yield
            return
        if sem.locked():
            self.waited += 1
        async with sem:
            self.in_flight += 1
            self.peak = max(self.peak, self.in_flight)
            try:
                yield
            finally:
                self.in_flight -= 1

    def snapshot(self) -> dict:
        limit = self._size if self._loop is not None else _setting(self._setting)
        return {"in_flight": self.in_flight, "limit": limit, "peak": self.peak, "waited": self.waited}

    def _reset(self) -> None:
        self._sem, self._loop, self._size = None, None, 0
        self.in_flight = self.peak = self.waited = 0


DNS = Budget("dns", "load_shed_dns_max_inflight")
DNS_UPSTREAM = Budget("dns_upstream", "load_shed_dns_upstream_max_inflight")
HEALTH = Budget("health", "load_shed_health_max_inflight")
# The DNS monitor's probe: in-process and cheap, so it must not fail because
# /health hangs on Redis or /health/deep callers queue behind a slow probe.
HEALTH_DOH = Budget("health_doh", "load_shed_health_max_inflight")
HEALTH_DEEP = Budget("health_deep", "load_shed_health_max_inflight")
API = Budget("api", "load_shed_api_max_inflight")
FRESH_ANALYSES = Budget("fresh_analysis", "load_shed_fresh_analysis_max_inflight")
LLM_JUDGE = Budget("llm_judge", "load_shed_llm_max_inflight")
LLM_EXPLAINER = Budget("llm_explainer", "load_shed_llm_max_inflight")
# Twice the Cloudflare pool (competitor_verdicts._MAX_CONNECTIONS = 16):
# beyond that a lookup would only wait for a connection, inside the response.
COMPETITOR_LOOKUPS = Budget("competitor_lookups", 32)
OUTBOUND = Gate("outbound", "load_shed_outbound_max_inflight")

_BUDGETS = (DNS, DNS_UPSTREAM, HEALTH, HEALTH_DOH, HEALTH_DEEP, API, FRESH_ANALYSES, LLM_JUDGE,
            LLM_EXPLAINER, COMPETITOR_LOOKUPS)

DNS_PATH = "/dns-query"
_HEALTH_CLASSES = {"/health": HEALTH, "/health/doh": HEALTH_DOH, "/health/deep": HEALTH_DEEP}


def budget_for(path: str) -> Budget:
    if path == DNS_PATH:
        return DNS
    return _HEALTH_CLASSES.get(path, API)


def fresh_share(n: int) -> int:
    """How many of a batch's `n` fresh analyses one request may run at once:
    a quarter of the worker's budget, so one big /check cannot take every
    slot from /public/check and the extension's page checks. No limit: all."""
    limit = FRESH_ANALYSES.limit()
    return n if limit <= 0 else min(n, max(1, limit // 4))


def snapshot() -> dict:
    out = {b.name: b.snapshot() for b in _BUDGETS}
    out[OUTBOUND.name] = OUTBOUND.snapshot()
    return out


_last_log = 0.0


def _note_shed() -> None:
    global _last_log
    now = time.monotonic()
    if now - _last_log < LOG_EVERY_S:
        return
    _last_log = now
    logger.warning("load_shed", extra={"budgets": snapshot()})


class _Slot:
    """One request's slot of its class, given back as soon as the request
    stops doing the work it bounds: when its answer starts going out, or
    when it starts waiting on the DNS upstream (release_request_slot)."""

    __slots__ = ("budget", "held")

    def __init__(self, budget: Budget) -> None:
        self.budget = budget
        self.held = False

    def take(self) -> bool:
        self.held = self.budget.try_acquire() == 1
        return self.held

    def give_back(self) -> None:
        if self.held:
            self.held = False
            self.budget.release()


_REQUEST_SLOT: ContextVar[Optional[_Slot]] = ContextVar("load_shed_request_slot", default=None)


def release_request_slot() -> None:
    """Give the current request's slot back now: it is about to wait on
    something outside this worker (the DNS upstream) and does none of the
    work the slot bounds meanwhile. A no-op outside a request."""
    slot = _REQUEST_SLOT.get()
    if slot is not None:
        slot.give_back()


def _header(scope, name: bytes) -> Optional[bytes]:
    for key, value in scope.get("headers", ()):
        if key == name:
            return value
    return None


def _has_body(scope) -> bool:
    if _header(scope, b"transfer-encoding") is not None:
        return True
    declared = _header(scope, b"content-length")
    try:
        return declared is not None and int(declared) > 0
    except ValueError:
        return False  # BodySizeLimit answers it 400 before reading a byte


class _Body:
    """A request's body on its way to the app: up to `ahead` bytes read
    before the request has a slot (read_ahead), the rest as the app asks for
    it (the `receive` of bind). Every byte counts against the route's cap
    (413) and the body's deadline (408). Past either, after the slot, the
    client gets the refusal — unless the app's answer has started — the app
    a disconnect, so it stops reading, and what it answers then is dropped
    (as request_guards.BodySizeLimit does)."""

    def __init__(self, scope, receive) -> None:
        from api.services.request_guards import body_limit_for, reads_body_after_auth

        path = scope.get("path", "")
        self.limit = body_limit_for(path)
        try:
            self.declared: Optional[int] = int(_header(scope, b"content-length") or b"")
        except ValueError:
            self.declared = None  # chunked
        self.ahead = 0 if reads_body_after_auth(path) else _PRE_READ_BYTES
        expected = self.declared if self.declared is not None else self.limit
        self._deadline = (asyncio.get_running_loop().time() + body_timeout_s()
                          + expected / _MIN_UPLOAD_BYTES_PER_S)
        self._receive = receive
        self._read: list = []
        self._size = 0
        self.complete = False

    def too_big(self) -> bool:
        return self.declared is not None and self.declared > self.limit

    async def _next(self) -> Union[dict, int]:
        """The client's next body message, or why there is none: 408, 413, _GONE."""
        remaining = self._deadline - asyncio.get_running_loop().time()
        try:
            message = await asyncio.wait_for(self._receive(), max(0.0, remaining))
        except asyncio.TimeoutError:
            return 408
        if message["type"] != "http.request":
            return _GONE
        self._size += len(message.get("body", b""))
        if self._size > self.limit:
            return 413
        self.complete = not message.get("more_body")
        return message

    async def read_ahead(self) -> Optional[int]:
        """Read before a slot, `ahead` bytes at most: None when that went
        fine (the body may go on), else why it stopped (408, 413, _GONE)."""
        while not self.complete and self._size < self.ahead:
            message = await self._next()
            if isinstance(message, int):
                return message
            self._read.append(message)
        return None

    def bind(self, send, refuse) -> tuple:
        """The app's `receive` and `send`. `refuse(status)` answers the
        client a 408 or 413."""
        pending = list(reversed(self._read))
        self._read = []
        refused = started = False

        async def receive() -> dict:
            nonlocal refused
            if pending:
                return pending.pop()
            if refused:
                return {"type": "http.disconnect"}
            if self.complete:
                return await self._receive()  # past the body: a disconnect, for whoever listens
            message = await self._next()
            if isinstance(message, dict):
                return message
            if message != _GONE:
                refused = True
                if not started:
                    await refuse(message)
            return {"type": "http.disconnect"}

        async def guarded_send(message) -> None:
            nonlocal started
            if refused:
                return  # the refusal went out instead
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        return receive, guarded_send


class LoadShedding:
    """Outermost raw-ASGI middleware: a slot of the request's class while
    this worker works on it, or a 503 at once. A DNS client gets no body,
    as with the gateway's own errors; a browser on one of our origins gets
    the CORS headers, so it reads the 503 and its Retry-After."""

    def __init__(self, app) -> None:
        self.app = app
        try:
            self._origins = frozenset(_settings().get_allowed_origins())
        except Exception:  # noqa: BLE001
            self._origins = frozenset()

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        budget = budget_for(scope.get("path", ""))
        if budget.limit() <= 0:
            await self.app(scope, receive, send)
            return
        body = _Body(scope, receive) if _has_body(scope) else None
        if body is not None:
            stop = 413 if body.too_big() else await body.read_ahead()
            if stop is not None:
                if stop != _GONE:
                    await self._refuse(scope, send, stop, _BODY_REFUSALS[stop])
                return
        slot = _Slot(budget)
        if not slot.take():
            await self._refuse(scope, send, 503, BUSY_DETAIL, unread_body=body is not None and not body.complete)
            return

        async def send_and_give_back(message) -> None:
            if message["type"] == "http.response.start":
                slot.give_back()  # the answer is ready; sending it is the client's time
            await send(message)

        async def refuse_body(status: int) -> None:
            await self._refuse(scope, send_and_give_back, status, _BODY_REFUSALS[status])

        app_receive, app_send = receive, send_and_give_back
        if body is not None:
            app_receive, app_send = body.bind(send_and_give_back, refuse_body)
        token = _REQUEST_SLOT.set(slot)
        try:
            await self.app(scope, app_receive, app_send)
        finally:
            _REQUEST_SLOT.reset(token)
            slot.give_back()

    async def _refuse(self, scope, send, status: int, detail: str, unread_body: bool = True) -> None:
        from api.services.doh_fastpath import _SECURITY_HEADERS

        body = b"" if scope.get("path") == DNS_PATH else json.dumps({"detail": detail}).encode()
        if status == 503:
            headers = [(name.lower().encode(), value.encode()) for name, value in _busy_header_dict().items()]
        else:
            headers = [(b"cache-control", b"no-store")]
        if unread_body:
            # The body was not read to its end: the connection cannot be reused.
            headers.append((b"connection", b"close"))
        headers.append((b"content-length", str(len(body)).encode()))
        if body:
            headers.append((b"content-type", b"application/json"))
        await send({"type": "http.response.start", "status": status,
                    "headers": headers + self._cors(scope) + _SECURITY_HEADERS})
        await send({"type": "http.response.body", "body": body})

    def _cors(self, scope) -> list:
        """What CORSMiddleware (api.main) would add, which a refusal here
        never reaches."""
        origin = _header(scope, b"origin")
        if origin is None or ("*" not in self._origins and origin.decode("latin-1") not in self._origins):
            return []
        return [(b"access-control-allow-origin", origin), (b"access-control-allow-credentials", b"true"),
                (b"access-control-expose-headers", b"Retry-After"), (b"vary", b"Origin")]


def _reset_for_tests() -> None:
    global _last_log
    for budget in _BUDGETS:
        budget._reset()
    OUTBOUND._reset()
    _last_log = 0.0

"""Load shedding: a bounded amount of work in flight per worker process.

Measured 2026-10-22 (docs/runbooks/capacity.md): past saturation the API
refused nothing. Requests piled up in memory — ~550 MB, once 917 MB of a
1 GB container — latency climbed to seconds, and the server kept working on
requests whose clients had long timed out. Now every request needs a slot of
its class; with none free it gets an immediate 503 with Retry-After, before
routing, auth, body parsing or a log line. A flood then costs a fraction of
what serving it would, and the requests already admitted finish in time.

Limits are per worker process — each uvicorn worker has its own counters, so
a replica with WEB_CONCURRENCY=2 admits twice these. 0 = no limit. Settings
LOAD_SHED_* in api/config.py; LOAD_SHED_ENABLED=false switches all of it off.

  request classes (LoadShedding, the outermost middleware)
    dns      /dns-query                               1024
    health   /health, /health/doh, /health/deep         64
    api      every other request                       128

  inside a request — refused or skipped at once, never queued
    fresh analyses   the analyzer's full fan-out (/check, the fresh path of
                     /public/check): 503 without a slot             16
    LLM calls        the judge, the explainer (each its own budget):
                     skipped — the verdict stands, the explainer
                     answers from its template                       4
    competitor lookups  the Cloudflare comparison on public checks:
                     skipped (`competitors` empty)                   32

  outbound gate — waits instead
    every source call and site probe of an analysis waits for one of
    LOAD_SHED_OUTBOUND_MAX_INFLIGHT (256). The wait is bounded by what was
    admitted (fresh analyses x checks) and by the analysis deadline, which
    cancels it; a source's own time limit starts once the call may run.

The classes are separate so a flood of one cannot take the slots of another:
a crawler storm on /public/check gets 503s while phones keep resolving and
monitors keep getting answers. DNS has the largest count on purpose: queries
waiting on a slow upstream (up to 4 s each) must not crowd out the ones the
cache answers at once. All classes share one event loop; what keeps DNS's CPU
is that the expensive work is capped and everything past a budget is refused
cheaply — measured: cached names answered in ~15-40 ms (before: 0.5-1.5 s
and timeouts) while public checks flooded the API. An extra limit on the
loop's lag was tried on top and changed nothing in those runs, so there is
none.

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
from typing import AsyncIterator, Iterator, Optional, Union

from fastapi.responses import JSONResponse

logger = logging.getLogger("cleanway.load_shed")

LOG_EVERY_S = 10.0
BUSY_DETAIL = "The server is busy. Please try again in a moment."
_DEFAULT_RETRY_AFTER_S = 2


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
HEALTH = Budget("health", "load_shed_health_max_inflight")
API = Budget("api", "load_shed_api_max_inflight")
FRESH_ANALYSES = Budget("fresh_analysis", "load_shed_fresh_analysis_max_inflight")
LLM_JUDGE = Budget("llm_judge", "load_shed_llm_max_inflight")
LLM_EXPLAINER = Budget("llm_explainer", "load_shed_llm_max_inflight")
# Twice the Cloudflare pool (competitor_verdicts._MAX_CONNECTIONS = 16):
# beyond that a lookup would only wait for a connection, inside the response.
COMPETITOR_LOOKUPS = Budget("competitor_lookups", 32)
OUTBOUND = Gate("outbound", "load_shed_outbound_max_inflight")

_BUDGETS = (DNS, HEALTH, API, FRESH_ANALYSES, LLM_JUDGE, LLM_EXPLAINER, COMPETITOR_LOOKUPS)

DNS_PATH = "/dns-query"
HEALTH_PATHS = frozenset({"/health", "/health/doh", "/health/deep"})


def budget_for(path: str) -> Budget:
    if path == DNS_PATH:
        return DNS
    if path in HEALTH_PATHS:
        return HEALTH
    return API


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


def _busy_headers(body: bytes) -> list:
    from api.services.doh_fastpath import _SECURITY_HEADERS

    headers = [(name.lower().encode(), value.encode()) for name, value in _busy_header_dict().items()]
    headers.append((b"content-length", str(len(body)).encode()))
    if body:
        headers.append((b"content-type", b"application/json"))
    return headers + _SECURITY_HEADERS


class LoadShedding:
    """Outermost raw-ASGI middleware: one slot of the request's class for the
    whole request, or a 503 at once. A DNS client gets no body, as with the
    gateway's own errors."""

    def __init__(self, app) -> None:
        self.app = app
        self._busy_json = json.dumps({"detail": BUSY_DETAIL}).encode()

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        budget = budget_for(scope.get("path", ""))
        if not budget.try_acquire():
            body = b"" if budget is DNS else self._busy_json
            await send({"type": "http.response.start", "status": 503, "headers": _busy_headers(body)})
            await send({"type": "http.response.body", "body": body})
            return
        try:
            await self.app(scope, receive, send)
        finally:
            budget.release()


def _reset_for_tests() -> None:
    global _last_log
    for budget in _BUDGETS:
        budget._reset()
    OUTBOUND._reset()
    _last_log = 0.0

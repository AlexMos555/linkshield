"""Abuse protection for the public /health/deep endpoint.

/health/deep has no secret on purpose: the DNS canary workflow and the
founder's external uptime monitor call it as plain GETs. But every fresh call
fans out to Redis, Supabase, the blocklist artifact and an in-process DoH
query, so an unauthenticated loop against it was a free amplifier against
our own dependencies.

Two limits, neither of which ever answers 429 (a monitor would page on it):

  * a result is reused for FRESH_S (30 s): however many callers there are,
    the downstreams see at most one probe per 30 s per process;
  * one client IP triggers at most one fresh probe per PER_IP_S (60 s);
    inside that window it gets the last result instead, even if older than
    30 s. Monitors probe every few minutes, so they always see fresh data.

A degraded answer (503) is cached with its status, so a monitor never gets a
false "ok" for a state nobody re-checked.
"""
from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from typing import Awaitable, Callable, Optional

FRESH_S = 30.0
PER_IP_S = 60.0
MAX_IPS = 4096

Result = tuple[int, dict]


def _now() -> float:
    return time.monotonic()


class DeepHealthGuard:
    def __init__(self, fresh_s: float = FRESH_S, per_ip_s: float = PER_IP_S, max_ips: int = MAX_IPS) -> None:
        self.fresh_s = fresh_s
        self.per_ip_s = per_ip_s
        self.max_ips = max_ips
        self._cached: Optional[tuple[float, Result]] = None
        self._last_probe: "OrderedDict[str, float]" = OrderedDict()
        self._lock = asyncio.Lock()

    def _fresh(self, now: float) -> Optional[Result]:
        if self._cached and now - self._cached[0] < self.fresh_s:
            return self._cached[1]
        return None

    def _remember(self, ip: str, now: float) -> None:
        self._last_probe[ip] = now
        self._last_probe.move_to_end(ip)
        while len(self._last_probe) > self.max_ips:
            self._last_probe.popitem(last=False)

    def _probed_recently(self, ip: str, now: float) -> bool:
        at = self._last_probe.get(ip)
        return at is not None and now - at < self.per_ip_s

    async def serve(self, ip: str, probe: Callable[[], Awaitable[Result]]) -> Result:
        now = _now()
        hit = self._fresh(now)
        if hit is not None:
            return hit
        if self._cached is not None and self._probed_recently(ip, now):
            return self._cached[1]
        async with self._lock:
            # Another request may have refreshed while we waited.
            now = _now()
            hit = self._fresh(now)
            if hit is not None:
                return hit
            self._remember(ip, now)
            result = await probe()
            self._cached = (_now(), result)
            return result


GUARD = DeepHealthGuard()


def reset_for_tests() -> None:
    global GUARD
    GUARD = DeepHealthGuard()

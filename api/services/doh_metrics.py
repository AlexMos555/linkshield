"""Aggregate-only counters for the DoH gateway, plus its in-process rate limit.

Privacy rule: nothing per query is ever logged — no names, no client IPs, no
per-request access line (the fast path bypasses the request logger). What
exists instead is a handful of process-wide counters and a latency histogram,
surfaced in /health/doh and /health/deep and written as ONE `doh_stats` log
line every STATS_LOG_EVERY_S. A counter can't say who asked for what.

The rate limiter is here because it is the other per-query bookkeeping and it
used to be a Redis INCR per DNS query. Now it is a per-process fixed window
keyed by a keyed BLAKE2b of the client IP (random key per process, never
logged), bounded in size. With W workers x R replicas the effective ceiling is
up to W*R times the configured limit — deliberately lenient: a DNS resolver
that 429s a carrier's CGNAT address takes the internet away from everyone
behind it.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from bisect import bisect_left
from collections import Counter
from typing import Optional

logger = logging.getLogger("cleanway.doh")

STATS_LOG_EVERY_S = 300
_BUCKETS_MS = (1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000)


class Metrics:
    def __init__(self) -> None:
        self.started = time.time()
        self.counts: Counter = Counter()
        self.latency = [0] * (len(_BUCKETS_MS) + 1)

    def inc(self, key: str, n: int = 1) -> None:
        self.counts[key] += n

    def observe(self, seconds: float) -> None:
        self.latency[bisect_left(_BUCKETS_MS, seconds * 1000)] += 1

    def _quantile(self, q: float) -> Optional[float]:
        total = sum(self.latency)
        if not total:
            return None
        target = q * total
        acc = 0
        for i, n in enumerate(self.latency):
            acc += n
            if acc >= target:
                return float(_BUCKETS_MS[i]) if i < len(_BUCKETS_MS) else float("inf")
        return None

    def snapshot(self) -> dict:
        return {
            "since": int(self.started),
            "counts": dict(self.counts),
            # Upper bucket bounds, i.e. "p50 <= x ms". Server-side time only.
            "p50_ms_le": self._quantile(0.5),
            "p95_ms_le": self._quantile(0.95),
            "p99_ms_le": self._quantile(0.99),
        }


METRICS = Metrics()


class WindowLimiter:
    def __init__(self, limit: int, window_s: int, max_keys: int = 200_000) -> None:
        self.limit = limit
        self.window_s = window_s
        self.max_keys = max_keys
        self._key = os.urandom(16)
        self._start = time.monotonic()
        self._counts: dict[bytes, int] = {}

    def check(self, ip: str) -> Optional[int]:
        """None when allowed, else seconds until the window resets."""
        now = time.monotonic()
        if now - self._start >= self.window_s:
            self._counts.clear()
            self._start = now
        k = hashlib.blake2b(ip.encode("utf-8", "replace"), key=self._key, digest_size=8).digest()
        c = self._counts.get(k, 0) + 1
        if c == 1 and len(self._counts) >= self.max_keys:
            return None  # table full: fail open rather than grow without bound
        self._counts[k] = c
        if c <= self.limit:
            return None
        return max(1, int(self.window_s - (now - self._start)))


_limiter: Optional[WindowLimiter] = None


def limiter() -> WindowLimiter:
    global _limiter
    from api.config import get_settings
    s = get_settings()
    lim = _limiter
    if lim is None or lim.limit != s.doh_rate_limit_per_window or lim.window_s != s.doh_rate_limit_window_seconds:
        lim = _limiter = WindowLimiter(s.doh_rate_limit_per_window, s.doh_rate_limit_window_seconds)
    return lim


def reset_for_tests() -> None:
    global METRICS, _limiter
    METRICS = Metrics()
    _limiter = None


async def stats_logger(every_s: float = STATS_LOG_EVERY_S) -> None:
    while True:
        await asyncio.sleep(every_s)
        try:
            from api.services import proxy_trust
            logger.info("doh_stats", extra={"doh": METRICS.snapshot(), "proxy_peers": proxy_trust.snapshot()})
        except Exception:  # noqa: BLE001
            pass

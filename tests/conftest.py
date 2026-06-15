"""Shared pytest fixtures + environment setup for Cleanway tests."""
from __future__ import annotations

import os
from typing import Any

import pytest


# Set DEBUG before any api.* imports — prevents crash on missing prod-only env vars
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault(
    "SUPABASE_JWT_SECRET", "test-secret-for-development-only-not-for-production-use"
)


# ─── Shared FakeRedis ──────────────────────────────────────────────
#
# Audit finding backend MEDIUM "No conftest.py shared Redis fixture —
# 4 test files define their own FakeRedis with different surfaces,
# creating drift risk".
#
# This is the single source of truth. Tests that want a working Redis
# request the `fake_redis` fixture; tests that want to simulate Redis
# being down request `redis_down` (which patches get_redis to raise).
#
# Test files can still define their own FakeRedis subclass / mock when
# they need behaviour this minimal one doesn't cover (e.g. atomic
# Lua scripts beyond INCR+EXPIRE, sliding windows). The point is: the
# BASIC Redis surface stops drifting across test files.


class FakeRedis:
    """Minimal async Redis-compatible stand-in.

    Covers the surface every Cleanway service actually uses:
      - get / set / setex / delete
      - incr / incrby
      - smembers / sadd (personal whitelist)
      - expire / ttl (rate-limiter window inspection)
      - eval (Lua INCR + EXPIRE atomic helper)

    Internally just a dict + a TTL dict. Doesn't simulate expiry,
    persistence, or any other Redis-specific behaviour. Tests that
    care about those should construct their own.
    """

    def __init__(self) -> None:
        self._kv: dict[str, Any] = {}
        self._ttls: dict[str, int] = {}

    async def get(self, key: str):
        return self._kv.get(key)

    async def set(self, key: str, val: Any, **_kw):
        self._kv[key] = val
        return True

    async def setex(self, key: str, ttl: int, val: Any):
        self._kv[key] = val
        self._ttls[key] = ttl
        return True

    async def delete(self, *keys: str):
        for k in keys:
            self._kv.pop(k, None)
            self._ttls.pop(k, None)
        return len(keys)

    async def incr(self, key: str) -> int:
        self._kv[key] = int(self._kv.get(key, 0)) + 1
        return self._kv[key]

    async def incrby(self, key: str, amount: int) -> int:
        self._kv[key] = int(self._kv.get(key, 0)) + amount
        return self._kv[key]

    async def expire(self, key: str, seconds: int) -> bool:
        self._ttls[key] = seconds
        return True

    async def ttl(self, key: str) -> int:
        return self._ttls.get(key, -1)

    async def smembers(self, key: str):
        v = self._kv.get(key)
        return set(v) if isinstance(v, (list, set, tuple)) else set()

    async def sadd(self, key: str, *members: Any) -> int:
        cur = self._kv.get(key)
        if not isinstance(cur, set):
            cur = set(cur) if isinstance(cur, (list, tuple)) else set()
        added = 0
        for m in members:
            if m not in cur:
                cur.add(m)
                added += 1
        self._kv[key] = cur
        return added

    async def eval(self, _script: str, _numkeys: int, key: str, *args) -> int:
        """Stand-in for the atomic INCR+TTL Lua used by the rate
        limiter. Emulates observable behaviour: increment, set TTL
        on first write, return new count."""
        self._kv[key] = int(self._kv.get(key, 0)) + 1
        if self._kv[key] == 1 and args:
            try:
                self._ttls[key] = int(args[0])
            except (TypeError, ValueError):
                pass
        return self._kv[key]

    async def close(self):  # pragma: no cover — unused in tests
        return None


@pytest.fixture
def fake_redis(monkeypatch) -> FakeRedis:
    """Patch get_redis() to return a fresh FakeRedis instance.

    Use this when your test wants Redis-dependent code to behave
    normally (rate limit, soft-delete flag, whitelist lookup, etc.).
    """
    fake = FakeRedis()

    async def _get():
        return fake

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    return fake


@pytest.fixture
def redis_down(monkeypatch):
    """Patch get_redis() to raise ConnectionError.

    Use this when your test wants to exercise the fail-open / fail-
    closed code paths. Returns nothing — just configures the mock.
    """
    async def _boom():
        raise ConnectionError("simulated Redis outage")

    monkeypatch.setattr("api.services.cache.get_redis", _boom)

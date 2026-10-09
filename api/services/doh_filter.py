"""The blocklist, in process, for the DoH hot path.

Every DNS query used to cost a Redis round trip (a pipelined SISMEMBER suffix
walk against `dangerous_domains`) before the gateway could even start
forwarding. That is latency on every lookup on every device, and a Redis
outage or a slow Redis turned into slow or failed DNS for everyone.

Now each worker holds the SAME artifact the phones sync (blocklist_artifact,
v2: sorted 48-bit SHA-256 prefixes, ~2.6 MB for ~430k names) as a packed
array('Q') (~3.5 MB) and answers "is any suffix of this name listed?" with a
binary search per suffix — microseconds, no I/O.

How the two sources combine (decide()):
  * filter loaded, no suffix hash listed  → not blocked. No Redis at all.
    This is ~98% of queries.
  * filter loaded, a suffix hash listed   → confirm the matching names with
    one SISMEMBER round trip against `dangerous_domains`, the exact set
    written in the same transaction as the artifact. Confirmation removes the
    (tiny) 48-bit collision risk — server-side a collision would darken a
    legitimate name for every user at once — and keeps "delete the set" as an
    instant server-side kill switch. Redis unreachable → trust the hash.
  * filter not loaded (cold start, artifact never readable) → the old
    per-query Redis suffix walk.
  * any failure anywhere → not blocked (fail-open; see the runbook).

The filter refreshes itself: every refresh_s a background task reads the
artifact's small meta hash and downloads the body only when the published
sha256 changed, verifying body against sha before swapping it in. A failed
refresh keeps the previous list — a stale list beats none. `status=revoked`
(the phones' kill switch) empties it here too.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import time
from array import array
from bisect import bisect_left
from typing import Optional

from api.services.blocklist_artifact import (
    HASH_BYTES,
    MAGIC,
    NEVER_BLOCK_GUARDS,
    REDIS_META_KEY,
    REDIS_TEXT_KEY,
    parse_header,
    sha256_bytes,
)

logger = logging.getLogger(__name__)

SET_KEY = "dangerous_domains"
_NEVER_BLOCK = frozenset(NEVER_BLOCK_GUARDS)


class BlocklistFilter:
    """An immutable loaded artifact."""

    __slots__ = ("hashes", "sha256", "version", "generated", "count", "revoked", "loaded_at")

    def __init__(self, hashes: array, sha256: str, header: dict) -> None:
        self.hashes = hashes
        self.sha256 = sha256
        self.version = str(header.get("generated", ""))
        self.generated = int(header.get("generated", 0))
        self.count = len(hashes)
        self.revoked = header.get("status") == "revoked"
        self.loaded_at = time.time()

    def listed(self, names: list[str]) -> list[str]:
        """The names whose 48-bit hash is in the artifact."""
        out = []
        hashes = self.hashes
        n = len(hashes)
        for name in names:
            h = int.from_bytes(hashlib.sha256(name.encode("utf-8")).digest()[:HASH_BYTES], "big")
            i = bisect_left(hashes, h)
            if i < n and hashes[i] == h:
                out.append(name)
        return out


def parse_filter(blob: bytes, sha256: str) -> BlocklistFilter:
    """Build a filter from artifact bytes. Raises ValueError on anything the
    phone would also refuse (bad magic/header, length or count mismatch,
    unsorted body). CPU-bound (~0.3 s for 430k entries): run it in a thread."""
    if not blob.startswith(MAGIC):
        raise ValueError("bad magic")
    nl = blob.index(b"\n", len(MAGIC))
    header = parse_header(blob[len(MAGIC):nl + 1].decode("ascii", "replace"))
    if not header:
        raise ValueError("bad header")
    body = memoryview(blob)[nl + 1:]
    if len(body) % HASH_BYTES:
        raise ValueError("truncated body")
    if len(body) // HASH_BYTES != header["count"]:
        raise ValueError("count mismatch")
    hashes = array("Q", (int.from_bytes(body[i:i + HASH_BYTES], "big")
                         for i in range(0, len(body), HASH_BYTES)))
    if any(hashes[i] > hashes[i + 1] for i in range(len(hashes) - 1)):
        raise ValueError("hashes not sorted")
    return BlocklistFilter(hashes, sha256, header)


class FilterHolder:
    """The current filter + its refresher + a tiny Redis circuit breaker."""

    def __init__(self) -> None:
        self.current: Optional[BlocklistFilter] = None
        self.last_check_ok: Optional[float] = None
        self.last_error: Optional[str] = None
        self._task: Optional[asyncio.Task] = None
        self._redis_fail_streak = 0
        self._redis_skip_until = 0.0

    # ── Redis with a deadline and a breaker ───────────────────────────
    def redis_available(self) -> bool:
        return time.monotonic() >= self._redis_skip_until

    def _redis_result(self, ok: bool) -> None:
        if ok:
            self._redis_fail_streak = 0
            return
        self._redis_fail_streak += 1
        if self._redis_fail_streak >= 3:
            # Stop paying the timeout on every query while Redis is down.
            self._redis_skip_until = time.monotonic() + 5.0

    async def members(self, names: list[str], timeout_s: float) -> Optional[list[bool]]:
        """SISMEMBER for each name in one round trip; None if Redis is down,
        slow, or skipped by the breaker."""
        if not names or not self.redis_available():
            return None
        try:
            from api.services import cache
            r = await asyncio.wait_for(cache.get_redis(), timeout_s)
            pipe = r.pipeline()
            for name in names:
                pipe.sismember(SET_KEY, name)
            found = await asyncio.wait_for(pipe.execute(), timeout_s)
        except Exception:  # noqa: BLE001 — any Redis trouble means "unknown", never an error
            self._redis_result(False)
            return None
        self._redis_result(True)
        return [bool(x) for x in found]

    # ── refresh ───────────────────────────────────────────────────────
    async def refresh_once(self, timeout_s: float = 15.0) -> bool:
        """Load the published artifact if it changed. True if a new one was
        swapped in. Never raises."""
        try:
            from api.services import cache
            r = await cache.get_redis()
            raw = await asyncio.wait_for(r.hgetall(REDIS_META_KEY), timeout_s) or {}
            meta = {(k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                    for k, v in raw.items()}
            sha = meta.get("sha256")
            if not sha:
                self.last_error = "no_artifact"
                return False
            if self.current is not None and self.current.sha256 == sha:
                self.last_check_ok = time.time()
                self.last_error = None
                return False
            encoded = await asyncio.wait_for(r.get(REDIS_TEXT_KEY), timeout_s)
            if not encoded:
                self.last_error = "no_artifact"
                return False
            blob = base64.b64decode(encoded)
            if sha256_bytes(blob) != sha:
                self.last_error = "sha_mismatch"
                logger.error("doh_filter: artifact body does not match its sha256 — keeping the old list")
                return False
            self.current = await asyncio.to_thread(parse_filter, blob, sha)
            self.last_check_ok = time.time()
            self.last_error = None
            logger.info("doh_filter_loaded", extra={"doh": {"version": self.current.version,
                                                             "count": self.current.count,
                                                             "revoked": self.current.revoked}})
            return True
        except Exception as exc:  # noqa: BLE001 — keep serving the list we have
            self.last_error = type(exc).__name__
            logger.warning("doh_filter_refresh_failed", extra={"error": type(exc).__name__})
            return False

    async def _loop(self, every_s: float) -> None:
        while True:
            await self.refresh_once()
            await asyncio.sleep(every_s)

    def start(self, every_s: float) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.get_running_loop().create_task(self._loop(every_s))

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    def status(self) -> dict:
        f = self.current
        out: dict = {"loaded": f is not None, "error": self.last_error}
        if f is not None:
            out.update(version=f.version, count=f.count, revoked=f.revoked,
                       age_s=max(0, int(time.time()) - f.generated))
        return out


HOLDER = FilterHolder()


def reset_for_tests() -> None:
    global HOLDER
    HOLDER = FilterHolder()


async def decide(qname: Optional[str], candidates: list[str], redis_timeout_s: float) -> tuple[bool, str]:
    """(blocked, how) for a parsed QNAME. `how` feeds the aggregate metrics:
    filter_miss / filter_hit / filter_hit_unconfirmed / collision /
    redis_hit / redis_miss / redis_down / guard / none. Never raises."""
    if not qname or not candidates:
        return False, "none"
    if qname in _NEVER_BLOCK:
        return False, "guard"
    holder = HOLDER
    f = holder.current
    if f is not None:
        if f.revoked:
            return False, "filter_miss"
        hits = f.listed(candidates)
        if not hits:
            return False, "filter_miss"
        confirmed = await holder.members(hits, redis_timeout_s)
        if confirmed is None:
            return True, "filter_hit_unconfirmed"
        return (True, "filter_hit") if any(confirmed) else (False, "collision")
    found = await holder.members(candidates, redis_timeout_s)
    if found is None:
        return False, "redis_down"
    return (True, "redis_hit") if any(found) else (False, "redis_miss")

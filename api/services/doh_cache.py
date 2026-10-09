"""Small in-process DNS response cache for the DoH gateway.

Most of a phone's lookups are the same few hundred names all day, and the
upstream told us how long each answer stays valid. Answering a repeat from
memory saves a round trip to Cloudflare (~1-20 ms from Railway, far more on a
cold recursion) and keeps working when every upstream is down (serve-stale,
RFC 8767).

Rules, in order of importance:
  * The blocklist decision runs BEFORE the cache, every time. A name listed a
    second ago is blocked now even if a pre-listing answer sits in here.
  * Never longer than the TTL the upstream gave (capped at max_ttl), and the
    TTLs in a served answer are decremented by the time it spent here — a
    client must not cache a record longer than its owner allowed.
  * Only queries whose answer cannot depend on who asked: no ECS / cookie /
    other EDNS options (see doh_wire.query_shape). The key folds case but the
    answer echoes the client's exact question bytes and transaction ID.
  * Bounded: LRU over max_entries. Memory is roughly max_entries x ~250 B.
  * Per process. Workers and replicas each hold their own copy; nothing here
    is shared or persisted, so nothing about who asked what outlives the TTL.
"""
from __future__ import annotations

import struct
import time
from collections import OrderedDict
from typing import NamedTuple, Optional

from api.services.doh_wire import QueryShape, response_shape

STALE_ANSWER_TTL = 30  # RFC 8767 §4: TTL of an answer served stale


class CachedAnswer(NamedTuple):
    body: bytes
    max_age: int
    stale: bool


class _Entry(NamedTuple):
    body: bytes  # as received, transaction ID included (rewritten on serve)
    stored: float
    ttl: int
    offsets: tuple[tuple[int, int], ...]
    question_end: int


class ResponseCache:
    def __init__(self, max_entries: int = 20_000, max_ttl: int = 3600, stale_for: int = 6 * 3600,
                 clock=time.monotonic) -> None:
        self.max_entries = max_entries
        self.max_ttl = max_ttl
        self.stale_for = stale_for
        self._clock = clock
        self._data: "OrderedDict[bytes, _Entry]" = OrderedDict()

    def __len__(self) -> int:
        return len(self._data)

    def clear(self) -> None:
        self._data.clear()

    def put(self, query: QueryShape, resp: bytes) -> Optional[int]:
        """Store `resp` for `query` if both allow it. The TTL it was stored
        for, or None when it was not stored."""
        if self.max_entries <= 0 or query.cache_key is None:
            return None
        end = query.question_end
        # The answer must be about exactly this question (case-insensitively);
        # anything else is either a broken upstream or a poisoning attempt.
        if len(resp) < end or resp[4:6] != b"\x00\x01" or resp[12:end].lower() != query.cache_key[1:]:
            return None
        shape = response_shape(resp, self.max_ttl)
        if shape.ttl is None:
            return None
        self._data[query.cache_key] = _Entry(resp, self._clock(), shape.ttl, shape.ttl_offsets, end)
        self._data.move_to_end(query.cache_key)
        while len(self._data) > self.max_entries:
            self._data.popitem(last=False)
        return shape.ttl

    def get(self, query: QueryShape, wire: bytes, allow_stale: bool = False) -> Optional[CachedAnswer]:
        """A fresh answer for `query`, or (allow_stale) one past its TTL but
        within the serve-stale window, with every TTL set to 30 s."""
        if query.cache_key is None:
            return None
        entry = self._data.get(query.cache_key)
        if entry is None:
            return None
        age = self._clock() - entry.stored
        if age >= entry.ttl + self.stale_for:
            del self._data[query.cache_key]
            return None
        stale = age >= entry.ttl
        if stale and not allow_stale:
            return None
        self._data.move_to_end(query.cache_key)
        out = bytearray(entry.body)
        out[0:2] = wire[0:2]
        out[12:entry.question_end] = query.question
        elapsed = int(age)
        for offset, ttl in entry.offsets:
            left = STALE_ANSWER_TTL if stale else max(0, ttl - elapsed)
            struct.pack_into("!I", out, offset, left)
        max_age = STALE_ANSWER_TTL if stale else max(0, entry.ttl - elapsed)
        return CachedAnswer(bytes(out), max_age, stale)

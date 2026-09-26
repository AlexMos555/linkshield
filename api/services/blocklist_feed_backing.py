"""Which published names each blocklist source backed on its last healthy run.

Why: when a feed goes missing, the outage guard (blocklist_feed_health) keeps
its names in the list. Without a record of which names those were, it kept
every published name no live source listed — so an outage of any small feed
also froze delistings by every healthy feed, and on the first runs after the
2026-09-26 promotion fix it carried back whole domains (zoom.pl) that the new
rule no longer promotes. With this record the carry keeps exactly what the
missing feed backed, and retention can still record everything else that left.

A record is a Bloom filter, not the names: ~1.2 bytes a name at a 1% false
positive rate against 6 for a hash and ~22 for the text, in a Redis that
evicted the phone artifact once (2026-08-19). A false positive only means a
name some other feed dropped is carried like the missing feed's own — the
behaviour before these records existed. There are no false negatives.

Storage — one Redis hash, BACKING_KEY: field = source name, value =
"v1 <built_at> <bits> <hashes> <base64 bit array>". Written only for sources
that were healthy on a run that published; a degraded source keeps the record
of its last healthy run. A record older than MAX_AGE_SECONDS is ignored.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import math
from dataclasses import dataclass
from typing import Callable, Iterable, Mapping, Optional

logger = logging.getLogger("dangerous-domains-refresh")

BACKING_KEY = "dangerous_domains:feed_backing"
FALSE_POSITIVE_RATE = 0.01
# Past the carry window plus a week the source's names have long left the
# list: its record has nothing left to attribute.
MAX_AGE_SECONDS = 21 * 86_400
KEY_TTL_SECONDS = MAX_AGE_SECONDS
_FORMAT = "v1"
_MIN_BITS = 64


@dataclass(frozen=True)
class Backing:
    """A Bloom filter over the names one source backed. `name in backing`
    is exact for members and true for ~FALSE_POSITIVE_RATE of the rest."""
    bits: bytes
    size: int         # number of bits
    hashes: int       # bit positions per name
    built_at: float

    def __contains__(self, name: object) -> bool:
        return all(self.bits[p >> 3] & (1 << (p & 7))
                   for p in _positions(str(name), self.size, self.hashes))


def names_backed(published: set, inputs: set, hosts: set, promotes: bool,
                 registrable: Callable[[str], str]) -> set:
    """The published names one source's `hosts` produced in this build: the
    hosts themselves and, for a source that promotes, the registrables the
    build promoted from them. A published name that was an input of its own
    (a feed host, or a retained, carried or confirmed name) was not promoted
    this run — so an old one-subdomain promotion kept alive by a carry is
    never recorded as any feed's, and cannot be carried again."""
    own = set(hosts) & published
    promoted = published - inputs
    if not promotes or not promoted:
        return own
    return own | ({registrable(h) for h in hosts} & promoted)


def _positions(name: str, size: int, hashes: int) -> list[int]:
    """Double hashing (Kirsch-Mitzenmacher) over one SHA-256 of the name."""
    digest = hashlib.sha256(name.encode("utf-8")).digest()
    h1 = int.from_bytes(digest[:8], "big")
    h2 = int.from_bytes(digest[8:16], "big") | 1
    return [(h1 + i * h2) % size for i in range(hashes)]


def build(names: Iterable[str], built_at: float,
          false_positive_rate: float = FALSE_POSITIVE_RATE) -> Backing:
    members = set(names)
    n = max(len(members), 1)
    size = max(_MIN_BITS, math.ceil(-n * math.log(false_positive_rate) / math.log(2) ** 2))
    hashes = max(1, round(size / n * math.log(2)))
    bits = bytearray((size + 7) // 8)
    for name in members:
        for p in _positions(name, size, hashes):
            bits[p >> 3] |= 1 << (p & 7)
    return Backing(bits=bytes(bits), size=size, hashes=hashes, built_at=float(built_at))


def encode(backing: Backing) -> str:
    return " ".join((_FORMAT, str(int(backing.built_at)), str(backing.size), str(backing.hashes),
                     base64.b64encode(backing.bits).decode("ascii")))


def decode(text: str) -> Optional[Backing]:
    """None for anything malformed — the caller treats it as no record."""
    try:
        fmt, built_at, size, hashes, blob = str(text).split(" ")
        bits = base64.b64decode(blob, validate=True)
        backing = Backing(bits=bits, size=int(size), hashes=int(hashes), built_at=float(built_at))
    except (ValueError, TypeError):
        return None
    if fmt != _FORMAT or backing.size < 1 or backing.hashes < 1 or len(bits) * 8 < backing.size:
        return None
    return backing


async def load(r, now: float) -> dict[str, Backing]:
    """Every usable record. Raises on a Redis failure — the caller then
    treats every degraded source as having no record."""
    rows = await r.hgetall(BACKING_KEY) or {}
    out: dict[str, Backing] = {}
    for source, text in rows.items():
        backing = decode(text)
        if backing is None:
            logger.warning("feed backing record for %s is unreadable — ignored", source)
        elif now - backing.built_at <= MAX_AGE_SECONDS:
            out[str(source)] = backing
    return out


async def save(r, records: Mapping[str, Backing], sources: Iterable[str]) -> None:
    """Write fresh records and drop fields of sources that no longer exist,
    in one MULTI/EXEC. `sources` is every source the job knows."""
    known = set(sources)
    stale = [field for field in (await r.hkeys(BACKING_KEY) or []) if field not in known]
    pipe = r.pipeline(transaction=True)
    if records:
        pipe.hset(BACKING_KEY, mapping={source: encode(b) for source, b in records.items()})
    if stale:
        pipe.hdel(BACKING_KEY, *stale)
    pipe.expire(BACKING_KEY, KEY_TTL_SECONDS)
    await pipe.execute()

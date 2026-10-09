"""Shared builders for the DoH gateway tests (wire queries, upstream answers,
a fake Redis holding the published artifact)."""
from __future__ import annotations

import base64
import struct
from typing import Optional

from api.services.blocklist_artifact import (
    LIST_CANARY,
    REDIS_META_KEY,
    REDIS_TEXT_KEY,
    meta_for_v2,
    render_artifact_v2,
)


def query(name: str, qtype: int = 1, txid: int = 0x1234, edns: bool = False, pad_to: int = 0,
          do_bit: bool = False, ecs: bool = False, flags: int = 0x0100) -> bytes:
    opts = b""
    if ecs:  # RFC 7871 client subnet, 192.0.2.0/24
        opts += struct.pack("!HHHBB", 8, 7, 1, 24, 0) + bytes([192, 0, 2])
    edns = edns or bool(pad_to) or ecs
    header = struct.pack("!HHHHHH", txid, flags, 1, 0, 0, 1 if edns else 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack("!HH", qtype, 1)
    msg = header + q
    if edns:
        if pad_to:
            fixed = len(msg) + 11 + len(opts) + 4
            pad = (-fixed) % pad_to
            opts += struct.pack("!HH", 12, pad) + b"\x00" * pad
        msg += b"\x00" + struct.pack("!HHIH", 41, 1232, 0x8000 if do_bit else 0, len(opts)) + opts
    return msg


def question_end(wire: bytes) -> int:
    pos = 12
    while wire[pos]:
        pos += wire[pos] + 1
    return pos + 5


def answer(wire: bytes, ttls: tuple[int, ...] = (300,), rcode: int = 0, soa: Optional[tuple[int, int]] = None,
           tc: bool = False, with_opt: bool = False) -> bytes:
    """An upstream-style response to `wire`: A records with the given TTLs,
    or (soa=(ttl, minimum)) a negative answer carrying an SOA."""
    end = question_end(wire)
    rrs = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, t, 4) + bytes([192, 0, 2, i + 1])
                   for i, t in enumerate(ttls))
    ns = b""
    if soa is not None:
        rdata = b"\x02ns\xc0\x0c" + b"\x04host\xc0\x0c" + struct.pack("!IIIII", 1, 2, 3, 4, soa[1])
        ns = b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, soa[0], len(rdata)) + rdata
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0) if with_opt else b""
    flags = 0x8180 | rcode | (0x0200 if tc else 0)
    header = wire[:2] + struct.pack("!HHHHH", flags, 1, len(ttls), 1 if ns else 0, 1 if opt else 0)
    return header + wire[12:end] + rrs + ns + opt


def b64url(wire: bytes) -> str:
    return base64.urlsafe_b64encode(wire).decode().rstrip("=")


class ArtifactRedis:
    """Fake async Redis: the published artifact (meta hash + base64 body) and
    the `dangerous_domains` set, with call counters and a kill switch."""

    def __init__(self, names: set[str], revoked: bool = False) -> None:
        self.names = set(names) | ({LIST_CANARY} if not revoked else set())
        self.blob = render_artifact_v2(names, revoked=revoked)
        self.meta = meta_for_v2(self.blob)
        self.down = False
        self.calls: dict[str, int] = {"hgetall": 0, "get": 0, "pipeline": 0}

    def _check(self) -> None:
        if self.down:
            raise ConnectionError("redis down")

    async def hgetall(self, key):
        self.calls["hgetall"] += 1
        self._check()
        return dict(self.meta) if key == REDIS_META_KEY else {}

    async def get(self, key):
        self.calls["get"] += 1
        self._check()
        return base64.b64encode(self.blob).decode() if key == REDIS_TEXT_KEY else None

    def pipeline(self):
        self.calls["pipeline"] += 1
        outer = self

        class _Pipe:
            def __init__(self):
                self.asked: list[str] = []

            def sismember(self, _key, member):
                self.asked.append(member)
                return self

            async def execute(self):
                outer._check()
                return [m in outer.names for m in self.asked]

        return _Pipe()


def use_redis(monkeypatch, fake) -> None:
    async def _get():
        if fake is None:
            raise ConnectionError("redis down")
        return fake

    import api.services.cache as cache
    monkeypatch.setattr(cache, "get_redis", _get)

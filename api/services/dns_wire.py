"""Read a DNS response: its RCODE, answer count and authority SOA.

Two readers need the same answer to "was this NXDOMAIN ours?": the DNS canary
(scripts/dns_canary.py, over the network) and /health/deep's in-process DoH
probe (api/services/health_probes.py). The gateway's own NXDOMAIN carries an
SOA whose MNAME is `blocked.cleanway.ai`; an upstream's honest "no such name"
does not. Standard library only — the canary runs on a bare runner without
the API's dependencies.
"""
from __future__ import annotations

import struct
from typing import NamedTuple, Optional

# The SOA MNAME in every NXDOMAIN the gateway synthesises
# (api/services/doh_gateway.py). An NXDOMAIN without it came from upstream.
BLOCK_SOA_MNAME = "blocked.cleanway.ai"


class DnsAnswer(NamedTuple):
    rcode: int
    answers: int
    soa_mname: Optional[str]  # MNAME of the first SOA in the authority section


def read_name(buf: bytes, pos: int) -> tuple[str, int]:
    """A (possibly compressed) domain name at `pos`: (name, offset after it)."""
    labels: list[str] = []
    after: Optional[int] = None
    for _ in range(128):  # bounded: a pointer loop must not hang the reader
        if pos >= len(buf):
            raise ValueError("name runs past the end of the message")
        length = buf[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                raise ValueError("truncated compression pointer")
            after = pos + 2 if after is None else after
            pos = ((length & 0x3F) << 8) | buf[pos + 1]
            continue
        if length == 0:
            return ".".join(labels), (pos + 1 if after is None else after)
        labels.append(buf[pos + 1:pos + 1 + length].decode("ascii", "replace").lower())
        pos += 1 + length
    raise ValueError("name too long or a compression loop")


def parse_response(body: bytes) -> DnsAnswer:
    """RCODE, answer count and the authority SOA's MNAME of a DNS response.
    Raises ValueError on a message too short or malformed to read."""
    if len(body) < 12:
        raise ValueError(f"short DNS response: {len(body)} bytes")
    qdcount, ancount, nscount, _ = struct.unpack("!HHHH", body[4:12])
    try:
        pos = 12
        for _ in range(qdcount):
            pos = read_name(body, pos)[1] + 4          # QTYPE + QCLASS
        for _ in range(ancount):
            pos = read_name(body, pos)[1]
            pos += 10 + struct.unpack("!H", body[pos + 8:pos + 10])[0]
        soa: Optional[str] = None
        for _ in range(nscount):
            pos = read_name(body, pos)[1]
            rtype, _cls, _ttl, rdlength = struct.unpack("!HHIH", body[pos:pos + 10])
            if rtype == 6 and soa is None:
                soa = read_name(body, pos + 10)[0]
            pos += 10 + rdlength
    except struct.error as exc:
        raise ValueError(f"truncated DNS response: {exc}") from exc
    return DnsAnswer(body[3] & 0x0F, ancount, soa)

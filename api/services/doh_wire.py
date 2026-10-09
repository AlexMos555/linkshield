"""DNS wire details the DoH gateway needs beyond the QNAME.

Two jobs, both read-only over bytes we already hold:

  * QueryShape — what a client query asks for and how: the question section,
    the RD/CD header bits and the EDNS0 OPT record (DO bit, padding, any other
    option). It decides whether a query may be answered from the response
    cache at all, and with what key.
  * ResponseShape — where the TTLs of an upstream response live and the TTL
    it may be cached / HTTP-cached for (RFC 8484 §5.1: no longer than the
    smallest TTL in it; RFC 2308 §5 for negative answers).

Plus the OPT record the gateway attaches to the answers it synthesises itself
(NXDOMAIN for a blocked name, SERVFAIL): RFC 6891 §7 says a responder that
saw an OPT in the query includes one in the response, and RFC 8467 §4.1 says
a padded query gets a padded response (468-octet blocks).

Nothing here raises on malformed input: a message we cannot read is simply
"not cacheable" and is still forwarded upstream untouched.
"""
from __future__ import annotations

import struct
from typing import NamedTuple, Optional

TYPE_SOA = 6
TYPE_OPT = 41
OPT_PADDING = 12  # RFC 7830
RESPONSE_PAD_BLOCK = 468  # RFC 8467 §4.1
EDNS_UDP_SIZE = 1232  # DNS flag day 2020 default
MAX_MESSAGE_BYTES = 65535  # RFC 1035 / RFC 8484 §6: one DNS message


class QueryShape(NamedTuple):
    question: bytes  # wire[12:question_end], case preserved
    question_end: int
    edns: bool
    do_bit: bool
    padded: bool
    other_options: bool  # ECS, cookies, anything but padding
    cache_key: Optional[bytes]  # None: never serve this from / store it in the cache


class ResponseShape(NamedTuple):
    rcode: int
    ttl: Optional[int]  # cacheable lifetime in seconds, None = not cacheable
    ttl_offsets: tuple[tuple[int, int], ...]  # (byte offset of a TTL field, its value)


def _skip_name(buf: bytes, pos: int) -> int:
    """Offset just past a (possibly compressed) name. Raises IndexError/ValueError."""
    for _ in range(128):
        length = buf[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(buf):
                raise ValueError("truncated pointer")
            return pos + 2
        if length & 0xC0:
            raise ValueError("reserved label type")
        if length == 0:
            return pos + 1
        pos += 1 + length
    raise ValueError("name too long")


def _read_opt(buf: bytes, pos: int) -> tuple[bool, bool, bool, int]:
    """(do_bit, padded, other_options, end) for the OPT RR whose TYPE is at pos."""
    _rtype, _size, ttl, rdlength = struct.unpack("!HHIH", buf[pos:pos + 10])
    rd_start = pos + 10
    end = rd_start + rdlength
    if end > len(buf):
        raise ValueError("OPT rdata past the end")
    padded = other = False
    p = rd_start
    while p + 4 <= end:
        code, olen = struct.unpack("!HH", buf[p:p + 4])
        if code == OPT_PADDING:
            padded = True
        else:
            other = True
        p += 4 + olen
    if p != end:
        raise ValueError("OPT options do not fill the rdata")
    return bool(ttl & 0x8000), padded, other, end


def query_shape(wire: bytes) -> Optional[QueryShape]:
    """Read a client query. None when it is not a well-formed single-question
    standard query (it is still forwarded, just never cached)."""
    try:
        if len(wire) < 17:
            return None
        flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHH", wire[2:12])
        if flags & 0x8000 or (flags >> 11) & 0xF != 0 or qdcount != 1 or ancount or nscount:
            return None
        pos = 12
        while True:
            length = wire[pos]
            if length == 0:
                pos += 1
                break
            if length & 0xC0:
                return None
            pos += 1 + length
        question_end = pos + 4
        if question_end > len(wire):
            return None
        edns = do_bit = padded = other = False
        pos = question_end
        for _ in range(arcount):
            pos = _skip_name(wire, pos)
            rtype = struct.unpack("!H", wire[pos:pos + 2])[0]
            if rtype != TYPE_OPT or edns:
                other = True  # TSIG/SIG(0)/a second OPT: never cache
                pos += 10 + struct.unpack("!H", wire[pos + 8:pos + 10])[0]
                continue
            edns = True
            do_bit, padded, opt_other, pos = _read_opt(wire, pos)
            other = other or opt_other
        if pos != len(wire):
            return None
    except (IndexError, ValueError, struct.error):
        return None
    question = wire[12:question_end]
    key: Optional[bytes] = None
    if not other:
        # Case-folded question + the bits that change the answer. RD, CD and
        # AD change what a recursive resolver returns; DO adds RRSIGs; whether
        # the client sent OPT / padding changes the shape of the response.
        bits = ((flags >> 8) & 0x01) | (0x02 if flags & 0x0010 else 0) | (0x04 if edns else 0) \
            | (0x08 if do_bit else 0) | (0x10 if padded else 0) | (0x20 if flags & 0x0020 else 0)
        key = bytes([bits]) + question.lower()
    return QueryShape(question, question_end, edns, do_bit, padded, other, key)


def response_shape(resp: bytes, max_ttl: int) -> ResponseShape:
    """TTL bookkeeping for an upstream response. Only NOERROR / NXDOMAIN with
    TC clear and a readable record set are cacheable."""
    if len(resp) < 12:
        return ResponseShape(-1, None, ())
    rcode = resp[3] & 0x0F
    try:
        flags = struct.unpack("!H", resp[2:4])[0]
        qd, an, ns, ar = struct.unpack("!HHHH", resp[4:12])
        pos = 12
        for _ in range(qd):
            pos = _skip_name(resp, pos) + 4
        offsets: list[tuple[int, int]] = []
        negative: Optional[int] = None
        for section, count in ((0, an), (1, ns), (2, ar)):
            for _ in range(count):
                pos = _skip_name(resp, pos)
                rtype, _cls, ttl, rdlength = struct.unpack("!HHIH", resp[pos:pos + 10])
                if rtype != TYPE_OPT:
                    offsets.append((pos + 4, ttl))
                    if section == 1 and rtype == TYPE_SOA and negative is None:
                        rdata = pos + 10
                        p = _skip_name(resp, _skip_name(resp, rdata))
                        minimum = struct.unpack("!I", resp[p + 16:p + 20])[0]
                        negative = min(ttl, minimum)
                pos += 10 + rdlength
                if pos > len(resp):
                    raise ValueError("record past the end")
    except (IndexError, ValueError, struct.error):
        return ResponseShape(rcode, None, ())
    if pos != len(resp):
        return ResponseShape(rcode, None, ())
    ttl: Optional[int] = None
    if rcode in (0, 3) and not flags & 0x0200:
        if rcode == 0 and an:
            ttl = min(t for _, t in offsets)
        elif negative is not None:
            ttl = negative
    if ttl is not None:
        ttl = min(ttl, max_ttl)
        if ttl <= 0:
            ttl = None
    return ResponseShape(rcode, ttl, tuple(offsets))


def http_max_age(resp: bytes, max_ttl: int = 3600) -> int:
    """Cache-Control max-age for a response we pass through (RFC 8484 §5.1)."""
    shape = response_shape(resp, max_ttl)
    return shape.ttl or 0


def opt_record(query: QueryShape, message_len: int) -> bytes:
    """An OPT RR for a response the gateway synthesises, padded to the RFC 8467
    block when the query was padded. `message_len` is the response so far."""
    flags = 0x8000 if query.do_bit else 0
    if not query.padded:
        return b"\x00" + struct.pack("!HHIH", TYPE_OPT, EDNS_UDP_SIZE, flags, 0)
    fixed = message_len + 11 + 4  # OPT RR header + padding option header
    pad = (-fixed) % RESPONSE_PAD_BLOCK
    rdata = struct.pack("!HH", OPT_PADDING, pad) + b"\x00" * pad
    return b"\x00" + struct.pack("!HHIH", TYPE_OPT, EDNS_UDP_SIZE, flags, len(rdata)) + rdata

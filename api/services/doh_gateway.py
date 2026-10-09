"""DoH gateway — Strategy doc Top-20 #6.

Cleanway runs an RFC 8484 DNS-over-HTTPS resolver that:

  1. Reads the DNS QNAME from the wire-format request.
  2. Checks the name and its parents against the published blocklist —
     in memory (doh_filter.py: the artifact phones sync, confirmed against
     the `dangerous_domains` Redis set on a hit), falling back to a
     per-query Redis lookup only while no list is loaded.
  3. On a match: synthesizes an NXDOMAIN response and returns it
     immediately — the user's browser never resolves the phishing
     host.
  4. On a clean lookup: answers from a small TTL-honouring cache or
     forwards the same wire-format request to Cloudflare's DoH endpoint,
     failing over to Quad9 (doh_upstream.py), and returns the response
     verbatim. docs/runbooks/doh-gateway.md has the request path, the
     fail-open decision and the measurements.

Why this matters for #6:
  Users tap a .mobileconfig on iOS (or paste 'dns.cleanway.ai'
  into Android's Private DNS field) and INSTANTLY get phishing-
  blocking protection on the entire device — system-wide, no
  app, no VPN, no battery hit. Cloudflare 1.1.1.1 for Families
  does this for adult content; we do it for phishing
  specifically, with our published FP rate.

Privacy invariants:
  * QNAME is the only identifier we see — same surface as any
    DNS resolver.
  * We do NOT log QNAMEs or client IPs — not to disk, not to Sentry,
    not even for blocked names. Aggregate counters only
    (doh_metrics.py). Answers (keyed by question, never by client) sit
    in a per-process memory cache for at most their TTL + the
    serve-stale window.
  * Rate-limiting is per IP, in process memory, keyed by a keyed hash
    of the IP; nothing about the client is stored elsewhere.
  * The upstreams (Cloudflare, Quad9) have their own privacy policies;
    we add no EDNS client subnet and forward the query bytes unchanged.

This module implements ONLY the protocol layer + intercept
decision. The router (api/routers/doh.py) wires it to FastAPI
with the appropriate Content-Type handling.
"""

from __future__ import annotations

import logging
import struct
from typing import Iterable, Optional

import httpx  # noqa: F401 — kept: tests patch doh_gateway.httpx.AsyncClient

from api.services.dns_wire import BLOCK_SOA_MNAME
from api.services.doh_wire import opt_record, query_shape

logger = logging.getLogger(__name__)

DOH_CONTENT_TYPE = "application/dns-message"

# RFC 1035 wire-format constants.
_RCODE_NOERROR = 0
_RCODE_NXDOMAIN = 3
_QTYPE_A = 1
_QTYPE_AAAA = 28


def parse_qname(wire: bytes) -> Optional[str]:
    """Extract the QNAME from a DNS wire-format query.

    Returns the lowercased fully-qualified domain name without
    trailing dot, or None if the buffer is malformed.

    The DNS header is fixed 12 bytes; the question section
    immediately follows. QNAME is a sequence of length-prefixed
    labels terminated by a zero byte. We don't follow message-
    compression pointers (0xc0) in the question section — they
    are not valid there per RFC 1035 §4.1.4.
    """
    if not wire or len(wire) < 13:
        return None

    # Header: 6 × u16. We only need the question count (QDCOUNT).
    try:
        _id, _flags, qdcount, _ancount, _nscount, _arcount = struct.unpack(
            "!HHHHHH", wire[:12]
        )
    except struct.error:
        return None
    if qdcount < 1:
        return None

    pos = 12
    labels: list[str] = []
    while pos < len(wire):
        length = wire[pos]
        if length == 0:
            # End of QNAME.
            break
        if length & 0xc0:
            # Pointer in question section — protocol-illegal.
            return None
        if length > 63:
            return None
        pos += 1
        end = pos + length
        if end > len(wire):
            return None
        try:
            label = wire[pos:end].decode("ascii").lower()
        except UnicodeDecodeError:
            return None
        labels.append(label)
        pos = end

    if not labels:
        return None
    qname = ".".join(labels).rstrip(".")
    return qname or None


# Generic second-level labels used under 2-letter ccTLDs (com.cn, co.nz, com.tr,
# co.il, com.ar, ...). Enough to treat the common compound suffixes as one eTLD
# without shipping a full public-suffix list.
_CCTLD_SECOND_LEVELS = frozenset({
    "com", "co", "org", "net", "gov", "edu", "ac", "mil", "gob", "gouv",
    "or", "ne", "go", "in", "nom", "gen", "ltd", "plc", "sch", "asn",
    "id", "biz", "info", "web", "gv", "govt",
})


def _registrable_domain(qname: str) -> str:
    """Best-effort registrable domain for the threat-intel lookup.

    Cleanway's `dangerous_domains` set is indexed by registrable
    domain (eTLD+1). For most TLDs this is the last two labels.
    We don't pull in a full PSL because the threat-intel feeds we
    use also index naively — close enough to keep miss-rates low.
    """
    if not qname:
        return ""
    parts = qname.strip(".").lower().split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    last_two = ".".join(parts[-2:])
    # Explicit compound suffixes (belt-and-suspenders for the common ones).
    if last_two in {
        "co.uk", "ac.uk", "gov.uk", "org.uk", "co.jp", "co.in",
        "com.au", "com.br", "com.mx", "co.kr", "co.za", "com.sg",
    }:
        return ".".join(parts[-3:])
    # Heuristic for the long tail of compound ccTLDs without pulling in a full
    # PSL: a 2-letter ccTLD preceded by a generic second-level label
    # (com.cn, co.nz, com.tr, co.il, com.ar, co.th, ...) means the registrable
    # domain is the last THREE labels, so a brand apex like apple.com.cn is not
    # mistaken for a spoof subdomain.
    tld, sld = parts[-1], parts[-2]
    if len(tld) == 2 and sld in _CCTLD_SECOND_LEVELS:
        return ".".join(parts[-3:])
    return last_two


# Negative-cache TTL carried in the SOA of every synthesized NXDOMAIN.
# RFC 2308 §5: a resolver caches a name error only when the response carries
# an SOA in the authority section; without one, netd re-asked on every retry
# and one blocked page became a burst of identical queries.
NEGATIVE_TTL_S = 60
_SOA_MNAME = BLOCK_SOA_MNAME
_SOA_RNAME = "hostmaster.cleanway.ai"


def _question_end(wire: bytes) -> int:
    """Offset just past the question section (QNAME + QTYPE + QCLASS)."""
    pos = 12
    while pos < len(wire):
        length = wire[pos]
        pos += 1
        if length == 0:
            break
        pos += length
    pos += 4  # QTYPE + QCLASS
    return min(pos, len(wire))


def _encode_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode("ascii", "ignore") for part in name.split(".") if part) + b"\x00"


def _soa_rr(qname: str) -> bytes:
    """One SOA record for the authority section. Owner = the parent of the
    queried name (an ancestor, which is what a negative-caching stub checks
    for); MINIMUM = TTL = NEGATIVE_TTL_S."""
    parts = [p for p in (qname or "").split(".") if p]
    owner = ".".join(parts[1:]) if len(parts) >= 2 else (parts[0] if parts else "")
    rdata = (
        _encode_name(_SOA_MNAME) + _encode_name(_SOA_RNAME)
        + struct.pack("!IIIII", 1, 3600, 600, 86400, NEGATIVE_TTL_S)
    )
    return (
        _encode_name(owner)
        + struct.pack("!HHIH", 6, 1, NEGATIVE_TTL_S, len(rdata))  # TYPE SOA, CLASS IN, TTL, RDLENGTH
        + rdata
    )


def _with_opt(wire: bytes, response: bytes) -> bytes:
    """Append an OPT RR (and bump ARCOUNT) when the query carried one —
    RFC 6891 §7; padded to the RFC 8467 block when the query was padded."""
    shape = query_shape(wire)
    if shape is None or not shape.edns:
        return response
    out = bytearray(response)
    struct.pack_into("!H", out, 10, struct.unpack("!H", response[10:12])[0] + 1)
    return bytes(out) + opt_record(shape, len(out))


def make_nxdomain_response(wire: bytes) -> bytes:
    """Build a syntactically-valid NXDOMAIN response for the query
    `wire`: question echoed, RCODE=3, and an SOA in the authority section
    so the client negatively caches it (NEGATIVE_TTL_S). A query with EDNS0
    gets an OPT back (padded if the query was).
    """
    if len(wire) < 12:
        # Can't build a response from a malformed query — return a
        # synthetic SERVFAIL-shaped frame so the client falls back
        # to its other resolvers cleanly.
        return b"\x00\x00\x81\x82" + b"\x00" * 8

    pos = _question_end(wire)
    tx_id = wire[:2]
    # QR=1, AA=1, RA=1 (advisory), RCODE=3; RD and CD echoed from the query.
    flags = struct.pack("!H", 0x8483 | (struct.unpack("!H", wire[2:4])[0] & 0x0110))
    counts = struct.pack("!HHHH", 1, 0, 1, 0)  # QD=1, AN=0, NS=1 (SOA), AR=0
    question = wire[12:pos]
    return _with_opt(wire, tx_id + flags + counts + question + _soa_rr(parse_qname(wire) or ""))


def make_servfail_response(wire: bytes) -> bytes:
    """SERVFAIL (RCODE 2) for the query `wire`. Used only when every upstream
    is unreachable and no stale answer is cached: a stub resolver treats
    SERVFAIL as "try your other servers", whereas an NXDOMAIN would be
    believed — and negatively cached — as "this site does not exist", for
    every site, for the length of the outage.
    """
    if len(wire) < 12:
        return b"\x00\x00\x81\x82" + b"\x00" * 8
    pos = _question_end(wire)
    flags = struct.pack("!H", 0x8182)  # QR=1, RD=1, RA=1, RCODE=2
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    return _with_opt(wire, wire[:2] + flags + counts + wire[12:pos])


async def is_blocked(qname: str, dangerous_domains: Iterable[str]) -> bool:
    """Decide whether to NXDOMAIN this QNAME based on the
    dangerous-domain set. Caller is responsible for fetching the
    set from Redis — this function is the policy decision only.
    """
    if not qname:
        return False
    domain_l = qname.lower()
    base = _registrable_domain(domain_l)
    blocked = set(dangerous_domains or ())
    return domain_l in blocked or base in blocked


# A published entry means "this name and every subdomain of it", so the
# lookup is a suffix walk. It is capped because it runs on every DNS query on
# the device: a pathological 30-label name must not become 30 SISMEMBERs.
# Seven covers the deepest shape we publish (a tenant host under a 3-label
# platform suffix, plus a couple of subdomains).
MAX_SUFFIX_LOOKUPS = 7


def block_candidates(qname: str) -> list[str]:
    """Suffixes to test, longest first, never a bare TLD. Pure, so the phone's
    rule (BlockList.match) and the gateway's can be compared directly."""
    parts = (qname or "").lower().strip(".").split(".")
    if len(parts) < 2 or not all(parts):
        return []
    out = [".".join(parts[i:]) for i in range(len(parts) - 1)]
    if len(out) <= MAX_SUFFIX_LOOKUPS:
        return out
    # Keep the longest few (the exact name and its immediate parents) and the
    # shortest few (the registrable domain and its neighbours) — a match can
    # only be published at one of those ends in practice.
    head = MAX_SUFFIX_LOOKUPS // 2
    return out[:head] + out[-(MAX_SUFFIX_LOOKUPS - head):]


async def is_blocked_redis(qname: str, redis) -> bool:
    """Redis-backed membership check for the DoH hot path.

    One pipelined round-trip of at most MAX_SUFFIX_LOOKUPS SISMEMBERs against
    `dangerous_domains` — never SMEMBERS, which would pull the entire
    half-million-name blocklist over the wire on every single DNS query.

    The walk matters: the published artifact says "this name and all its
    subdomains", and the phone implements exactly that. Checking only the
    exact QNAME and its registrable base meant a subdomain of a tenant entry
    (`login.0-amazon.weebly.com`) was blocked on Android and waved through
    for anyone on the DoH profile — the two surfaces disagreeing about what
    is dangerous.

    Fail-open on any Redis error (returns False → proxy clean):
    blocking a legit domain is worse than missing a malicious one.
    """
    if not qname or redis is None:
        return False
    candidates = block_candidates(qname)
    if not candidates:
        return False
    try:
        pipe = redis.pipeline()
        for name in candidates:
            pipe.sismember("dangerous_domains", name)
        results = await pipe.execute()
        return any(bool(x) for x in results)
    except Exception:
        logger.debug("DoH is_blocked_redis failed", exc_info=True)
        return False


# Upstream forwarding (pooled HTTP/2 client, Cloudflare -> Quad9 failover,
# hedging) lives in doh_upstream.py; the names are re-exported here because
# the router, the health probe, the DNS canary's parity test and older tests
# import them from this module.
from api.services.doh_upstream import (  # noqa: E402,F401
    CLOUDFLARE_DOH_URL,
    QUAD9_DOH_URL,
    UPSTREAM_TIMEOUT_S,
    _get_upstream_client,
    _reset_upstream_client_for_tests,
    close_upstream_client,
    proxy_to_upstream,
)

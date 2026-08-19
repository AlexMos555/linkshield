"""DoH gateway — Strategy doc Top-20 #6.

Cleanway runs an RFC 8484 DNS-over-HTTPS resolver that:

  1. Reads the DNS QNAME from the wire-format request.
  2. Checks the registrable domain against our `dangerous_domains`
     Redis set (populated by URLhaus / PhishTank / Safe Browsing /
     ThreatFox feeds via the existing analyzer cache).
  3. On a match: synthesizes an NXDOMAIN response and returns it
     immediately — the user's browser never resolves the phishing
     host.
  4. On a clean lookup: proxies the same wire-format request to
     Cloudflare's 1.1.1.1 DoH endpoint (cloudflare-dns.com/dns-query)
     and returns the response verbatim. We add NO latency beyond
     the Redis HEXISTS check (~1ms p50).

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
  * We do NOT log QNAMEs to disk or to Sentry. The query exists
    in memory for the duration of the request and is gone.
  * Rate-limiting is by IP at the analyzer layer; the DoH gateway
    itself does not extend the user-identification surface.
  * The upstream (Cloudflare) has its own privacy policy; we
    cannot improve on it but we don't make it worse.

This module implements ONLY the protocol layer + intercept
decision. The router (api/routers/doh.py) wires it to FastAPI
with the appropriate Content-Type handling.
"""

from __future__ import annotations

import logging
import struct
from typing import Iterable, Optional

import httpx

logger = logging.getLogger(__name__)

CLOUDFLARE_DOH_URL = "https://cloudflare-dns.com/dns-query"
DOH_CONTENT_TYPE = "application/dns-message"
UPSTREAM_TIMEOUT_S = 4.0

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
_SOA_MNAME = "blocked.cleanway.ai"
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
    return b"".join(bytes([len(l)]) + l.encode("ascii", "ignore") for l in name.split(".") if l) + b"\x00"


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


def make_nxdomain_response(wire: bytes) -> bytes:
    """Build a syntactically-valid NXDOMAIN response for the query
    `wire`: question echoed, RCODE=3, and an SOA in the authority section
    so the client negatively caches it (NEGATIVE_TTL_S).
    """
    if len(wire) < 12:
        # Can't build a response from a malformed query — return a
        # synthetic SERVFAIL-shaped frame so the client falls back
        # to its other resolvers cleanly.
        return b"\x00\x00\x81\x82" + b"\x00" * 8

    pos = _question_end(wire)
    tx_id = wire[:2]
    flags = struct.pack("!H", 0x8403)  # QR=1, AA=1, RA=1 (advisory), RCODE=3
    counts = struct.pack("!HHHH", 1, 0, 1, 0)  # QD=1, AN=0, NS=1 (SOA), AR=0
    question = wire[12:pos]
    return tx_id + flags + counts + question + _soa_rr(parse_qname(wire) or "")


def make_servfail_response(wire: bytes) -> bytes:
    """SERVFAIL (RCODE 2) for the query `wire`. Used when the upstream is
    unreachable: a stub resolver treats SERVFAIL as "try your other servers",
    whereas an NXDOMAIN would be believed — and negatively cached — as "this
    site does not exist", for every site, for the length of the outage.
    """
    if len(wire) < 12:
        return b"\x00\x00\x81\x82" + b"\x00" * 8
    pos = _question_end(wire)
    flags = struct.pack("!H", 0x8182)  # QR=1, RD=1, RA=1, RCODE=2
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    return wire[:2] + flags + counts + wire[12:pos]


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


# One pooled upstream client per event loop.
#
# This function used to open a fresh ``httpx.AsyncClient`` for EVERY DNS
# query — a full TCP+TLS handshake to Cloudflare per lookup, on a path where
# a single page load costs tens of lookups. Measured from outside: 0.30-0.72s
# per query through the gateway vs 0.025s to 1.1.1.1 directly. The DNS-only
# VPN on the phone was pointed at 1.1.1.1 instead of at us for exactly that
# reason, which is what leaves first-visit blocking to the phone's own
# after-the-fact check. Keeping one client alive reuses the connection.
#
# The client is bound to the running event loop; tests (and any code that
# spins up a new loop) get a new one instead of a stale, closed transport.
_UPSTREAM_MAX_CONNECTIONS = 64
_UPSTREAM_KEEPALIVE = 32
_upstream_client: Optional[httpx.AsyncClient] = None
_upstream_client_loop: object = None


def _get_upstream_client() -> httpx.AsyncClient:
    global _upstream_client, _upstream_client_loop
    import asyncio

    loop = asyncio.get_running_loop()
    client = _upstream_client
    if client is None or _upstream_client_loop is not loop or getattr(client, "is_closed", False):
        client = httpx.AsyncClient(
            timeout=UPSTREAM_TIMEOUT_S,
            limits=httpx.Limits(
                max_connections=_UPSTREAM_MAX_CONNECTIONS,
                max_keepalive_connections=_UPSTREAM_KEEPALIVE,
            ),
        )
        _upstream_client = client
        _upstream_client_loop = loop
    return client


def _reset_upstream_client_for_tests() -> None:
    global _upstream_client, _upstream_client_loop
    _upstream_client = None
    _upstream_client_loop = None


async def close_upstream_client() -> None:
    """Release the pooled connections (call from app shutdown)."""
    global _upstream_client, _upstream_client_loop
    client, _upstream_client, _upstream_client_loop = _upstream_client, None, None
    if client is not None:
        try:
            await client.aclose()
        except Exception:
            logger.debug("DoH upstream client close failed", exc_info=True)


async def proxy_to_upstream(wire: bytes) -> Optional[bytes]:
    """Forward the wire-format query to Cloudflare's DoH endpoint
    and return the response body. None on any error so the caller
    can decide whether to synthesise a SERVFAIL or 503.
    """
    try:
        client = _get_upstream_client()
        resp = await client.post(
            CLOUDFLARE_DOH_URL,
            content=wire,
            headers={
                "Content-Type": DOH_CONTENT_TYPE,
                "Accept": DOH_CONTENT_TYPE,
            },
        )
        if resp.status_code != 200:
            logger.warning("DoH upstream returned %d", resp.status_code)
            return None
        return resp.content
    except Exception as exc:
        logger.warning("DoH upstream call failed: %s", exc)
        return None

"""DoH gateway protocol + intercept tests — Strategy #6."""
from __future__ import annotations

import struct
from unittest.mock import MagicMock

import pytest

from api.services.doh_gateway import (
    is_blocked,
    make_nxdomain_response,
    parse_qname,
    _registrable_domain,
)


def _fake_blocklist_redis(blocked: set[str]) -> MagicMock:
    """Fake Redis whose pipeline().sismember(...)/execute() answers
    membership against `blocked` — matches the is_blocked_redis hot
    path (SISMEMBER, not SMEMBERS). Records the number of members asked
    about per pipeline in `.pipeline_calls`, so a test can pin that the
    suffix walk stays bounded."""
    calls: list[int] = []

    class _Pipe:
        def __init__(self, blk):
            self._blk = blk
            self._queued: list[str] = []

        def sismember(self, _key, member):
            self._queued.append(member)
            return self

        async def execute(self):
            calls.append(len(self._queued))
            out = [m in self._blk for m in self._queued]
            self._queued = []
            return out

    r = MagicMock()
    r.pipeline = lambda: _Pipe(blocked)
    r.pipeline_calls = calls
    return r


# ─────────────────────────────────────────────────────────────────
# Wire-format helpers
# ─────────────────────────────────────────────────────────────────

def _make_query(qname: str) -> bytes:
    """Build a minimal A-record DNS query for `qname`."""
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    labels = qname.encode("ascii").split(b".")
    question = b""
    for lab in labels:
        question += bytes([len(lab)]) + lab
    question += b"\x00"  # QNAME terminator
    question += struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN
    return header + question


# ─────────────────────────────────────────────────────────────────
# parse_qname
# ─────────────────────────────────────────────────────────────────

def test_parse_qname_simple():
    wire = _make_query("paypal.com")
    assert parse_qname(wire) == "paypal.com"


def test_parse_qname_lowercases():
    wire = _make_query("PayPal.COM")
    assert parse_qname(wire) == "paypal.com"


def test_parse_qname_multi_label():
    wire = _make_query("login.bank.example.co.uk")
    assert parse_qname(wire) == "login.bank.example.co.uk"


def test_parse_qname_too_short():
    assert parse_qname(b"") is None
    assert parse_qname(b"\x00" * 11) is None


def test_parse_qname_pointer_in_question_rejected():
    """Compression pointers in the question section are protocol-illegal
    (RFC 1035 §4.1.4). Reject so we don't get fooled into parsing past
    the buffer."""
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    bad_question = b"\xc0\x0c"  # pointer
    assert parse_qname(header + bad_question) is None


def test_parse_qname_overlong_label():
    """Labels are 1..63 octets per RFC 1035 §3.1. Anything else is a
    malformed query — reject."""
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    bad = header + bytes([64]) + (b"a" * 64) + b"\x00"
    assert parse_qname(bad) is None


def test_parse_qname_zero_questions():
    """QDCOUNT=0 is well-formed but uninterpretable. Return None so
    the gateway proxies as a clean lookup."""
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 0, 0, 0, 0)
    assert parse_qname(header) is None


# ─────────────────────────────────────────────────────────────────
# _registrable_domain
# ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "qname, expected",
    [
        ("paypal.com", "paypal.com"),
        ("www.paypal.com", "paypal.com"),
        ("attacker.evil.tk", "evil.tk"),
        ("a.b.c.d.example.com", "example.com"),
        ("example.co.uk", "example.co.uk"),
        ("login.example.co.uk", "example.co.uk"),
        ("foo.bar.baz.example.co.uk", "example.co.uk"),
        ("com.au", "com.au"),  # bare multi-segment TLD — returns itself
        ("example.com.au", "example.com.au"),
        ("subdomain.example.com.au", "example.com.au"),
    ],
)
def test_registrable_domain(qname, expected):
    assert _registrable_domain(qname) == expected


# ─────────────────────────────────────────────────────────────────
# is_blocked
# ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_is_blocked_direct_match():
    assert await is_blocked("phisher.example", {"phisher.example"}) is True


@pytest.mark.asyncio
async def test_is_blocked_via_registrable_domain():
    """`malicious.subdomain.evil.tk` should be blocked if `evil.tk`
    is in the danger set."""
    assert await is_blocked("malicious.subdomain.evil.tk", {"evil.tk"}) is True


@pytest.mark.asyncio
async def test_is_blocked_unknown_passes():
    assert await is_blocked("google.com", {"evil.tk"}) is False


@pytest.mark.asyncio
async def test_is_blocked_case_insensitive():
    assert await is_blocked("PHISHER.example", {"phisher.example"}) is True


@pytest.mark.asyncio
async def test_is_blocked_empty_qname():
    assert await is_blocked("", {"phisher.example"}) is False


@pytest.mark.asyncio
async def test_is_blocked_empty_set():
    assert await is_blocked("phisher.example", set()) is False


# ─────────────────────────────────────────────────────────────────
# make_nxdomain_response
# ─────────────────────────────────────────────────────────────────

def test_nxdomain_response_has_rcode_3():
    """Byte 3 of the DNS header contains the RCODE in the low 4 bits."""
    wire = _make_query("phisher.example")
    resp = make_nxdomain_response(wire)
    flags_byte = resp[3]
    assert (flags_byte & 0x0f) == 3  # NXDOMAIN


def test_nxdomain_response_keeps_transaction_id():
    """The client correlates queries to responses by transaction ID;
    if we mangle it the resolver won't accept our answer."""
    wire = _make_query("phisher.example")
    resp = make_nxdomain_response(wire)
    assert resp[:2] == wire[:2]


def test_nxdomain_response_qr_bit_set():
    """QR=1 (response) must be set in the flags."""
    wire = _make_query("phisher.example")
    resp = make_nxdomain_response(wire)
    assert (resp[2] & 0x80) == 0x80


def test_nxdomain_response_qdcount_1_ancount_0_nscount_1():
    # NSCOUNT=1: the SOA that lets clients negatively cache (RFC 2308).
    # It used to be 0, so netd re-asked on every retry.
    resp = make_nxdomain_response(_make_query("phisher.example"))
    qdcount, ancount, nscount, arcount = struct.unpack("!HHHH", resp[4:12])
    assert qdcount == 1
    assert ancount == 0
    assert nscount == 1
    assert arcount == 0


def test_nxdomain_response_echoes_question():
    wire = _make_query("phisher.example")
    resp = make_nxdomain_response(wire)
    # Question starts at byte 12 in both query and response; the SOA follows.
    qlen = len(wire) - 12
    assert resp[12:12 + qlen] == wire[12:]


def test_nxdomain_response_handles_truncated_query():
    """Defensive: a 6-byte garbage payload should produce a sane
    SERVFAIL-shaped frame, not raise."""
    resp = make_nxdomain_response(b"\x00" * 6)
    assert len(resp) >= 12


# ─────────────────────────────────────────────────────────────────
# Router smoke
# ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_router_blocks_dangerous_domain(monkeypatch):
    """End-to-end: POST /dns-query for a dangerous domain returns
    NXDOMAIN without touching the upstream."""
    from fastapi.testclient import TestClient
    from api.main import app

    # Danger set contains the registrable domain.
    fake_redis = _fake_blocklist_redis({"phisher.example"})

    async def _get_redis():
        return fake_redis
    import api.services.cache as cache
    monkeypatch.setattr(cache, "get_redis", _get_redis)

    # Upstream MUST NOT be called for the blocked path.
    async def _no_upstream(_):
        raise RuntimeError("upstream MUST NOT be called for blocked qname")
    import api.routers.doh as doh_router
    monkeypatch.setattr(doh_router, "proxy_to_upstream", _no_upstream)

    client = TestClient(app)
    resp = client.post(
        "/dns-query",
        content=_make_query("phisher.example"),
        headers={"Content-Type": "application/dns-message"},
    )
    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("application/dns-message")
    # Verify NXDOMAIN in the response.
    assert (resp.content[3] & 0x0f) == 3


@pytest.mark.asyncio
async def test_router_proxies_clean_domain(monkeypatch):
    """A safe lookup goes through to Cloudflare-shaped upstream."""
    from fastapi.testclient import TestClient
    from api.main import app

    fake_redis = _fake_blocklist_redis(set())

    async def _get_redis():
        return fake_redis
    import api.services.cache as cache
    monkeypatch.setattr(cache, "get_redis", _get_redis)

    upstream_response = b"\xde\xad\x81\x80" + b"\x00" * 8  # any valid DNS frame
    async def _upstream(_):
        return upstream_response
    import api.routers.doh as doh_router
    monkeypatch.setattr(doh_router, "proxy_to_upstream", _upstream)

    client = TestClient(app)
    resp = client.post(
        "/dns-query",
        content=_make_query("wikipedia.org"),
        headers={"Content-Type": "application/dns-message"},
    )
    assert resp.status_code == 200
    assert resp.content == upstream_response


def test_router_get_base64url(monkeypatch):
    """RFC 8484 GET form: ?dns=<base64url-encoded wire>."""
    from fastapi.testclient import TestClient
    from api.main import app
    import base64

    wire = _make_query("wikipedia.org")
    encoded = base64.urlsafe_b64encode(wire).decode("ascii").rstrip("=")

    fake_redis = _fake_blocklist_redis(set())

    async def _get_redis():
        return fake_redis
    import api.services.cache as cache
    monkeypatch.setattr(cache, "get_redis", _get_redis)

    async def _upstream(_):
        return b"\xde\xad\x81\x80" + b"\x00" * 8
    import api.routers.doh as doh_router
    monkeypatch.setattr(doh_router, "proxy_to_upstream", _upstream)

    client = TestClient(app)
    resp = client.get(f"/dns-query?dns={encoded}")
    assert resp.status_code == 200


def test_router_get_invalid_base64_returns_400(monkeypatch):
    from fastapi.testclient import TestClient
    from api.main import app

    fake_redis = _fake_blocklist_redis(set())

    async def _get_redis():
        return fake_redis
    import api.services.cache as cache
    monkeypatch.setattr(cache, "get_redis", _get_redis)

    client = TestClient(app)
    resp = client.get("/dns-query?dns=not!valid!base64")
    assert resp.status_code == 400


# ─────────────────────────────────────────────────────────────────
# is_blocked_redis — SISMEMBER hot path (not SMEMBERS)
# ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_is_blocked_redis_direct_match():
    from api.services.doh_gateway import is_blocked_redis
    r = _fake_blocklist_redis({"phisher.example"})
    assert await is_blocked_redis("phisher.example", r) is True


@pytest.mark.asyncio
async def test_is_blocked_redis_via_registrable():
    from api.services.doh_gateway import is_blocked_redis
    r = _fake_blocklist_redis({"evil.tk"})
    assert await is_blocked_redis("malicious.subdomain.evil.tk", r) is True


@pytest.mark.asyncio
async def test_is_blocked_redis_unknown_passes():
    from api.services.doh_gateway import is_blocked_redis
    r = _fake_blocklist_redis({"evil.tk"})
    assert await is_blocked_redis("google.com", r) is False


@pytest.mark.asyncio
async def test_is_blocked_redis_fail_open_on_none():
    """No redis handle → proxy clean (fail-open)."""
    from api.services.doh_gateway import is_blocked_redis
    assert await is_blocked_redis("phisher.example", None) is False


# ─────────────────────────────────────────────────────────────────
# proxy_to_upstream — pooled client (one TLS handshake, not one per query)
# ─────────────────────────────────────────────────────────────────

class _CountingClient:
    """Stand-in for httpx.AsyncClient that counts constructions and posts."""
    constructed = 0
    posted = 0
    fail = False

    def __init__(self, *a, **kw):
        type(self).constructed += 1
        self.is_closed = False

    async def post(self, *a, **kw):
        type(self).posted += 1
        if type(self).fail:
            raise RuntimeError("upstream down")
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"\x12\x34" + b"\x00" * 10
        return resp

    async def aclose(self):
        self.is_closed = True


@pytest.mark.asyncio
async def test_proxy_to_upstream_reuses_one_client(monkeypatch):
    """Every DoH query used to open a fresh httpx.AsyncClient — a full TLS
    handshake to Cloudflare per lookup, on a path where a page load costs
    tens of lookups. Measured 0.3-0.7s/query vs 0.025s direct. The client
    must be created once and reused."""
    import api.services.doh_gateway as g
    _CountingClient.constructed = 0
    _CountingClient.posted = 0
    _CountingClient.fail = False
    monkeypatch.setattr(g.httpx, "AsyncClient", _CountingClient)
    g._reset_upstream_client_for_tests()

    for _ in range(5):
        out = await g.proxy_to_upstream(b"\x12\x34" + b"\x00" * 10)
        assert out is not None

    assert _CountingClient.posted == 5
    assert _CountingClient.constructed == 1


@pytest.mark.asyncio
async def test_proxy_to_upstream_fail_open_returns_none(monkeypatch):
    import api.services.doh_gateway as g
    _CountingClient.constructed = 0
    _CountingClient.fail = True
    monkeypatch.setattr(g.httpx, "AsyncClient", _CountingClient)
    g._reset_upstream_client_for_tests()

    assert await g.proxy_to_upstream(b"\x12\x34" + b"\x00" * 10) is None
    _CountingClient.fail = False


# ─────────────────────────────────────────────────────────────────
# Truth fixes (2026-08-18): SERVFAIL on upstream failure, SOA on NXDOMAIN,
# DNS never 503s on Redis trouble
# ─────────────────────────────────────────────────────────────────

def _q(name: str) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + labels + b"\x00" + b"\x00\x01\x00\x01"


def test_make_servfail_response_has_rcode_2_and_echoes_question():
    from api.services.doh_gateway import make_servfail_response
    q = _q("example.com")
    r = make_servfail_response(q)
    assert r[:2] == b"\x12\x34"
    assert r[3] & 0x0F == 2, "RCODE must be SERVFAIL"
    assert r[2] & 0x80, "QR must be set"
    assert struct.unpack("!H", r[4:6])[0] == 1  # QDCOUNT echoed
    assert r[12:] == q[12:]


def test_nxdomain_response_carries_soa_for_negative_caching():
    """RFC 2308: a client only caches an NXDOMAIN if an SOA is in the
    authority section. Without it netd re-asks on every retry, and a
    blocked page turns into a burst of identical queries."""
    from api.services.doh_gateway import make_nxdomain_response, NEGATIVE_TTL_S
    q = _q("evil.example.com")
    r = make_nxdomain_response(q)
    assert r[3] & 0x0F == 3
    qd, an, ns, ar = struct.unpack("!HHHH", r[4:12])
    assert (qd, an, ns, ar) == (1, 0, 1, 0)
    # The SOA RR follows the question: TYPE=6, CLASS=1, TTL=NEGATIVE_TTL_S.
    qlen = len(q) - 12
    rr = r[12 + qlen:]
    # owner is a compression pointer or labels — find TYPE/CLASS/TTL after it
    assert b"\x00\x06\x00\x01" in rr, "no SOA TYPE/CLASS in authority"
    i = rr.index(b"\x00\x06\x00\x01")
    ttl = struct.unpack("!I", rr[i + 4:i + 8])[0]
    assert ttl == NEGATIVE_TTL_S


@pytest.mark.asyncio
async def test_router_upstream_failure_is_servfail_not_nxdomain(monkeypatch):
    """A Cloudflare outage must not tell every phone that every site does
    not exist (negatively cached!). SERVFAIL makes stubs retry elsewhere."""
    from fastapi.testclient import TestClient
    from api.main import app
    from api.routers import doh as doh_router
    from api.services import cache as cache_mod
    from api.services import rate_limiter

    async def _no_upstream(wire):
        return None

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _no_upstream)
    fake = _fake_blocklist_redis(set())

    async def _r():
        return fake

    monkeypatch.setattr(cache_mod, "get_redis", _r)
    monkeypatch.setattr(rate_limiter, "get_redis", _r)
    fake.pipeline  # exists
    client = TestClient(app)
    resp = client.post("/dns-query", content=_q("example.com"),
                       headers={"content-type": "application/dns-message"})
    assert resp.status_code == 200
    assert resp.content[3] & 0x0F == 2, "expected SERVFAIL rcode 2"


@pytest.mark.asyncio
async def test_router_redis_down_never_503s_dns(monkeypatch):
    """The rate limiter runs before the handler and, in production
    (rate_limit_fail_closed=True), turned a Redis blip into HTTP 503 on every
    DNS query = total DNS failure for anyone pointed at the gateway. DNS must
    fail OPEN: proxy the query."""
    from fastapi.testclient import TestClient
    from api.main import app
    from api.routers import doh as doh_router
    from api.services import cache as cache_mod
    from api.services import rate_limiter
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "rate_limit_fail_closed", True, raising=False)

    async def _boom():
        raise ConnectionError("redis down")

    monkeypatch.setattr(cache_mod, "get_redis", _boom)
    monkeypatch.setattr(rate_limiter, "get_redis", _boom)

    async def _upstream(wire):
        return wire[:2] + b"\x81\x80" + b"\x00\x01\x00\x01\x00\x00\x00\x00" + wire[12:]

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _upstream)
    client = TestClient(app)
    resp = client.post("/dns-query", content=_q("example.com"),
                       headers={"content-type": "application/dns-message"})
    assert resp.status_code == 200, resp.text
    assert resp.content[3] & 0x0F == 0


# ─────────────────────────────────────────────────────────────────
# Subdomain semantics: the artifact says "this name and all its
# subdomains"; the gateway must agree with the phone.
# ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_is_blocked_redis_covers_subdomains_of_a_multi_label_entry():
    """A published entry blocks itself AND everything under it — that is what
    the phone does (BlockList.match walks suffixes). The gateway checked only
    the exact name and its registrable base, so a subdomain of a tenant entry
    like `0-amazon.weebly.com` sailed through for DoH / iOS-profile users
    while the same lookup was blocked on Android."""
    from api.services.doh_gateway import is_blocked_redis
    r = _fake_blocklist_redis({"0-amazon.weebly.com", "evil.tk"})
    assert await is_blocked_redis("0-amazon.weebly.com", r) is True
    assert await is_blocked_redis("login.0-amazon.weebly.com", r) is True
    assert await is_blocked_redis("a.b.0-amazon.weebly.com", r) is True
    assert await is_blocked_redis("sub.evil.tk", r) is True
    # The platform itself is not blocked by a tenant's entry.
    assert await is_blocked_redis("weebly.com", r) is False
    assert await is_blocked_redis("other.weebly.com", r) is False


@pytest.mark.asyncio
async def test_is_blocked_redis_never_consults_a_bare_tld():
    """A one-label suffix must never be looked up: a stray 'com' in the set
    would darken the internet."""
    from api.services.doh_gateway import is_blocked_redis
    r = _fake_blocklist_redis({"com", "uk"})
    assert await is_blocked_redis("example.com", r) is False
    assert await is_blocked_redis("bbc.co.uk", r) is False


@pytest.mark.asyncio
async def test_is_blocked_redis_bounds_the_number_of_lookups():
    """The suffix walk runs on every DNS query on the device, so it must stay
    O(1)-ish: a pathological 30-label name may not become 30 SISMEMBERs."""
    from api.services.doh_gateway import MAX_SUFFIX_LOOKUPS, is_blocked_redis
    r = _fake_blocklist_redis(set())
    long_name = ".".join(f"l{i}" for i in range(30)) + ".example"
    assert await is_blocked_redis(long_name, r) is False
    assert r.pipeline_calls  # recorded by the fake
    assert max(r.pipeline_calls) <= MAX_SUFFIX_LOOKUPS

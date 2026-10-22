"""Malformed and hostile DNS wire messages against the DoH parsers.

Everything here is untrusted bytes from the internet (a client query) or from
an upstream (a response we might cache). The contract: never raise, never
cache what we cannot fully read, never let a malformed query slip a listed
name past the blocklist, and build synthetic answers a stub can parse.
"""
from __future__ import annotations

import struct

import pytest

from api.services import doh_gateway
from api.services.doh_gateway import (
    MAX_SUFFIX_LOOKUPS,
    block_candidates,
    is_blocked_redis,
    make_nxdomain_response,
    make_servfail_response,
    parse_qname,
)
from api.services.doh_wire import (
    EDNS_UDP_SIZE,
    TYPE_OPT,
    http_max_age,
    query_shape,
    response_shape,
)
from tests.doh_helpers import answer, query


def _header(flags: int = 0x0100, qd: int = 1, an: int = 0, ns: int = 0, ar: int = 0, txid: int = 0xBEEF) -> bytes:
    return struct.pack("!HHHHHH", txid, flags, qd, an, ns, ar)


def _qname(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


_QTAIL = struct.pack("!HH", 1, 1)  # QTYPE A, QCLASS IN


def _with_additional(rr: bytes, base_name: str = "example.org") -> bytes:
    """A one-question query whose additional section is exactly `rr`."""
    return _header(ar=1) + _qname(base_name) + _QTAIL + rr


def _opt(rdata: bytes = b"", rdlength: int | None = None, do: bool = False) -> bytes:
    rdlen = len(rdata) if rdlength is None else rdlength
    return b"\x00" + struct.pack("!HHIH", TYPE_OPT, 1232, 0x8000 if do else 0, rdlen) + rdata


# ── query_shape: what may be cached ─────────────────────────────────

def test_a_well_formed_query_has_a_cache_key():
    shape = query_shape(query("Example.ORG"))
    assert shape is not None and shape.cache_key is not None
    assert shape.cache_key == query_shape(query("example.org")).cache_key


@pytest.mark.parametrize(
    "wire",
    [
        pytest.param(b"\x00" * 16, id="shorter-than-header-plus-minimal-question"),
        pytest.param(_header(flags=0x8100) + _qname("example.org") + _QTAIL, id="qr-bit-set-a-response"),
        pytest.param(_header(flags=0x0900) + _qname("example.org") + _QTAIL, id="opcode-iquery"),
        pytest.param(_header(qd=0) + _qname("example.org") + _QTAIL, id="qdcount-0"),
        pytest.param(_header(qd=2) + _qname("example.org") + _QTAIL + _qname("phish.example") + _QTAIL,
                     id="qdcount-2"),
        pytest.param(_header(an=1) + _qname("example.org") + _QTAIL, id="ancount-in-a-query"),
        pytest.param(_header(ns=1) + _qname("example.org") + _QTAIL, id="nscount-in-a-query"),
        pytest.param(_header() + b"\xc0\x0c" + _QTAIL + b"\x00", id="compression-pointer-in-question"),
        pytest.param(_header() + b"\x40abc" + _QTAIL + b"\x00", id="reserved-label-type-in-question"),
        pytest.param(_header() + _qname("example.org") + b"\x00\x01", id="question-missing-qclass"),
        pytest.param(_header() + b"\x07example\x03org\x05", id="name-never-terminated"),
        pytest.param(query("example.org") + b"\x00", id="trailing-garbage"),
        pytest.param(_with_additional(b"\xc0"), id="additional-truncated-pointer"),
        pytest.param(_with_additional(b"\x80" + bytes(10)), id="additional-reserved-label-type"),
        pytest.param(_with_additional(b"\x01a" * 128 + b"\x00" + bytes(10)), id="additional-name-over-128-labels"),
        pytest.param(_with_additional(_opt(rdlength=200)), id="opt-rdata-past-the-end"),
        pytest.param(_with_additional(_opt(b"\x00\x0c")), id="opt-option-header-truncated"),
        pytest.param(_with_additional(_opt(struct.pack("!HH", 12, 40) + b"\x00" * 4)), id="opt-option-overruns-rdata"),
        pytest.param(_with_additional(b"\x00" + struct.pack("!HHIH", 250, 255, 0, 50)), id="tsig-rdata-past-the-end"),
        pytest.param(_with_additional(b"\x00\x00"), id="additional-record-header-truncated"),
    ],
)
def test_malformed_queries_are_never_cacheable_and_never_raise(wire):
    assert query_shape(wire) is None


def test_a_query_signed_with_tsig_is_forwarded_but_never_cached():
    tsig = b"\x00" + struct.pack("!HHIH", 250, 255, 0, 4) + b"sig!"
    shape = query_shape(_with_additional(tsig))
    assert shape is not None
    assert shape.other_options is True and shape.cache_key is None


def test_a_second_opt_record_makes_the_query_uncacheable():
    wire = _header(ar=2) + _qname("example.org") + _QTAIL + _opt() + _opt()
    shape = query_shape(wire)
    assert shape is not None and shape.edns is True
    assert shape.cache_key is None


def test_a_label_of_exactly_63_octets_is_fine():
    label = "a" * 63
    shape = query_shape(query(f"{label}.example"))
    assert shape is not None and shape.cache_key is not None
    assert parse_qname(query(f"{label}.example")) == f"{label}.example"


# ── response_shape: what an upstream answer may be cached for ───────

def test_a_response_shorter_than_a_header_is_not_cacheable():
    assert response_shape(b"\x12\x34\x81", 3600) == (-1, None, ())
    assert http_max_age(b"") == 0


def test_the_opt_record_ttl_is_not_mistaken_for_a_record_ttl():
    q = query("example.org", edns=True)
    resp = answer(q, ttls=(120, 300), with_opt=True)
    shape = response_shape(resp, 3600)
    assert shape.ttl == 120
    # Only the two A records are TTL fields to decrement; the OPT "TTL" holds
    # the extended RCODE / DO bit and must never be rewritten.
    assert len(shape.ttl_offsets) == 2


def test_a_record_whose_rdata_runs_past_the_end_is_not_cacheable():
    resp = answer(query("example.org"), ttls=(300,))
    shape = response_shape(resp[:-2], 3600)
    assert shape.ttl is None and shape.ttl_offsets == ()
    assert shape.rcode == 0


def test_trailing_bytes_after_the_records_are_not_cacheable():
    resp = answer(query("example.org"), ttls=(300,)) + b"junk"
    assert response_shape(resp, 3600).ttl is None
    assert http_max_age(resp) == 0


def test_a_response_with_more_records_announced_than_present_is_not_cacheable():
    resp = bytearray(answer(query("example.org"), ttls=(300,)))
    struct.pack_into("!H", resp, 6, 5)  # ANCOUNT = 5, one present
    assert response_shape(bytes(resp), 3600).ttl is None


def test_a_self_referencing_compression_pointer_is_skipped_not_followed():
    # The answer's owner name points at itself (offset of the pointer). A
    # parser that followed pointers would spin; ours only steps over them.
    q = query("example.org")
    end = len(q)
    rr = struct.pack("!H", 0xC000 | end) + struct.pack("!HHIH", 1, 1, 300, 4) + bytes([192, 0, 2, 1])
    resp = q[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + q[12:] + rr
    assert response_shape(resp, 3600).ttl == 300


@pytest.mark.parametrize("rcode,tc,ttl", [(2, False, 300), (5, False, 300), (0, True, 300), (0, False, 0)])
def test_servfail_refused_truncated_and_zero_ttl_answers_are_not_cacheable(rcode, tc, ttl):
    resp = answer(query("example.org"), ttls=(ttl,), rcode=rcode, tc=tc)
    assert response_shape(resp, 3600).ttl is None


def test_an_nxdomain_without_an_soa_is_not_cacheable():
    resp = answer(query("nope.example"), ttls=(), rcode=3)
    assert response_shape(resp, 3600).ttl is None


def test_the_ttl_is_capped_at_max_ttl():
    resp = answer(query("example.org"), ttls=(86400,))
    assert response_shape(resp, 3600).ttl == 3600


# ── parse_qname: the name the blocklist decision is made on ─────────

def test_parse_qname_needs_a_question():
    assert parse_qname(_header(qd=0) + _qname("phish.example") + _QTAIL) is None


def test_parse_qname_of_the_root_is_none():
    assert parse_qname(_header() + b"\x00" + _QTAIL) is None


def test_parse_qname_refuses_a_label_running_past_the_end():
    assert parse_qname(_header() + b"\x10abc") is None


def test_an_unterminated_qname_still_yields_the_listed_name():
    # A truncated query for a listed name must be judged on that name, not
    # waved through as "unparseable".
    assert parse_qname(_header() + b"\x05phish\x07example") == "phish.example"


def test_a_raw_non_ascii_label_under_a_listed_name_still_sees_the_parent():
    # RFC 2181 §11: a label may hold any octet. A subdomain with a raw 8-bit
    # label below a listed name must still produce the listed suffix,
    # otherwise any such subdomain bypasses the blocklist.
    wire = _header() + b"\x02\xff\xfe\x05phish\x07example\x00" + _QTAIL
    name = parse_qname(wire)
    assert name is not None and name.endswith(".phish.example")
    assert "phish.example" in block_candidates(name)


@pytest.mark.parametrize("label", [b"\x02a.", b"\x03a.b", b"\x01."], ids=["trailing-dot", "inner-dot", "only-dot"])
def test_a_literal_dot_inside_a_label_cannot_hide_the_listed_parent(label):
    # Labels ["a.", "phish", "example"] are a real subdomain of phish.example
    # (an attacker's wildcard answers it); joined naively they became
    # "a..phish.example", for which there were no suffixes to check at all.
    wire = _header() + label + b"\x05phish\x07example\x00" + _QTAIL
    name = parse_qname(wire)
    assert name is not None and name.count(".") == 2
    assert block_candidates(name)[-1] == "phish.example"


def test_a_single_label_holding_a_dot_is_not_the_two_label_name():
    # One wire label "phish.example" (a TLD-level name) is not phish.example.
    wire = _header() + b"\x0dphish.example\x00" + _QTAIL
    assert parse_qname(wire) != "phish.example"


def test_the_nxdomain_for_a_non_ascii_subdomain_is_well_formed():
    wire = _header() + b"\x01x\x02\xff\xfe\x05phish\x07example\x00" + _QTAIL
    out = make_nxdomain_response(wire)
    shape = response_shape(out, 3600)
    assert shape.rcode == 3 and shape.ttl == doh_gateway.NEGATIVE_TTL_S
    # SOA owner = the longest ASCII ancestor, encoded with honest lengths.
    authority = out[len(wire):]
    assert authority.startswith(b"\x05phish\x07example\x00\x00\x06")


def test_a_raw_utf8_label_is_decoded_as_utf8():
    wire = _header() + _qname("x.example").replace(b"\x01x", b"\x02\xc3\xa9") + _QTAIL
    assert parse_qname(wire) == "é.example"


# ── block_candidates: the suffix walk ───────────────────────────────

@pytest.mark.parametrize(
    "qname,expected",
    [
        ("Login.PHISH.Example.", ["login.phish.example", "phish.example"]),
        ("phish.example", ["phish.example"]),
        ("example", []),
        ("", []),
        ("a..example", []),
        (".", []),
    ],
)
def test_block_candidates_normalise_case_and_trailing_dot_and_never_yield_a_tld(qname, expected):
    assert block_candidates(qname) == expected


def test_block_candidates_for_a_very_deep_name_keep_both_ends():
    name = ".".join(f"l{i}" for i in range(12)) + ".phish.example"
    out = block_candidates(name)
    assert len(out) == MAX_SUFFIX_LOOKUPS
    assert out[0] == name  # the exact name
    assert out[-1] == "phish.example"  # the registrable end, never "example"
    assert "example" not in out


# ── is_blocked_redis: the cold-start fallback ───────────────────────

class _RedisThatMustNotBeCalled:
    def pipeline(self):  # pragma: no cover - asserting it is not reached
        raise AssertionError("a bare TLD must not cost a Redis round trip")


class _BrokenPipeRedis:
    def pipeline(self):
        outer = self

        class _P:
            def sismember(self, *_a):
                return self

            async def execute(self):
                outer.executed = True
                raise ConnectionError("connection reset")

        return _P()


@pytest.mark.asyncio
async def test_is_blocked_redis_does_not_query_for_a_single_label():
    assert await is_blocked_redis("example", _RedisThatMustNotBeCalled()) is False


@pytest.mark.asyncio
async def test_is_blocked_redis_fails_open_when_the_pipeline_raises():
    r = _BrokenPipeRedis()
    assert await is_blocked_redis("phish.example", r) is False
    assert r.executed is True


# ── synthesised answers ─────────────────────────────────────────────

def test_registrable_domain_of_nothing_is_nothing():
    assert doh_gateway._registrable_domain("") == ""


@pytest.mark.asyncio
async def test_a_listed_compound_cctld_apex_blocks_its_subdomains_but_not_the_suffix():
    # com.cn is a public suffix: listing paypa1.com.cn must not darken com.cn.
    assert await doh_gateway.is_blocked("login.paypa1.com.cn", {"paypa1.com.cn"}) is True
    assert await doh_gateway.is_blocked("login.paypa1.com.cn", {"com.cn"}) is False


def test_servfail_for_a_frame_shorter_than_a_header_is_a_bare_servfail():
    out = make_servfail_response(b"\x12\x34")
    assert len(out) == 12 and out[3] & 0x0F == 2 and out[2] & 0x80


def test_servfail_for_an_unterminated_question_echoes_what_is_there():
    wire = _header() + b"\x07example\x03org"
    out = make_servfail_response(wire)
    assert out[:2] == wire[:2] and out[3] & 0x0F == 2
    assert out[12:] == wire[12:]


@pytest.mark.parametrize("do", [False, True])
def test_a_blocked_edns_query_gets_an_unpadded_opt_echoing_do(do):
    q = query("phish.example", edns=True, do_bit=do)
    out = make_nxdomain_response(q)
    assert out[3] & 0x0F == 3
    assert struct.unpack("!H", out[10:12])[0] == 1  # ARCOUNT = the OPT
    assert out[-11:] == b"\x00" + struct.pack("!HHIH", TYPE_OPT, EDNS_UDP_SIZE, 0x8000 if do else 0, 0)
    # The synthesised answer is itself a readable, negatively cacheable message.
    assert response_shape(out, 3600).ttl == doh_gateway.NEGATIVE_TTL_S


def test_a_blocked_query_without_edns_gets_no_opt():
    out = make_nxdomain_response(query("phish.example"))
    assert struct.unpack("!H", out[10:12])[0] == 0
    assert response_shape(out, 3600).ttl == doh_gateway.NEGATIVE_TTL_S

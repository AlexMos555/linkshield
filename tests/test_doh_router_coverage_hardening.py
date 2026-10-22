"""The DoH request path end to end: resolve() under failure, request
coalescing, the cache's own failures, hostile query names against the
blocklist, and the HTTP surface (GET ?dns= decoding, media types, 429s) on
both the raw-ASGI fast path and the FastAPI routes.
"""
from __future__ import annotations

import asyncio
import struct

import pytest
from fastapi.testclient import TestClient

import api.routers.doh as doh_router
from api.services import doh_filter, doh_metrics
from api.services.doh_wire import http_max_age
from tests.doh_helpers import ArtifactRedis, answer, b64url, query, use_redis

LISTED = {"phish.example", "xn--pple-43d.com"}
CT = {"content-type": "application/dns-message"}


def _rcode(resp: bytes) -> int:
    return resp[3] & 0x0F


def _counts() -> dict:
    return doh_metrics.METRICS.counts


async def _until(cond, timeout: float = 2.0) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while not cond():
        assert asyncio.get_running_loop().time() < deadline, "condition never became true"
        await asyncio.sleep(0.001)


# ── request coalescing ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_identical_concurrent_misses_cost_one_upstream_round_trip(monkeypatch):
    use_redis(monkeypatch, None)
    gate, calls = asyncio.Event(), []

    async def _up(wire):
        calls.append(wire)
        await gate.wait()
        return answer(wire)

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)
    leader = asyncio.create_task(doh_router.resolve(query("example.org", txid=0x0001)))
    await _until(lambda: len(calls) == 1)
    follower = asyncio.create_task(doh_router.resolve(query("EXAMPLE.org", txid=0x0002)))
    await _until(lambda: _counts().get("coalesced") == 1)
    gate.set()
    first, second = await asyncio.gather(leader, follower)
    assert len(calls) == 1
    assert first.status == second.status == 200
    # The follower gets its own transaction ID and its own spelling back.
    assert second.body[:2] == b"\x00\x02"
    assert b"\x07EXAMPLE" in second.body
    assert doh_router._inflight == {}


@pytest.mark.asyncio
async def test_when_the_leaders_upstream_fails_the_follower_asks_itself(monkeypatch):
    use_redis(monkeypatch, None)
    gate, calls = asyncio.Event(), []

    async def _up(wire):
        calls.append(wire)
        if len(calls) == 1:
            await gate.wait()
            return None
        return answer(wire)

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)
    leader = asyncio.create_task(doh_router.resolve(query("example.org", txid=1)))
    await _until(lambda: len(calls) == 1)
    follower = asyncio.create_task(doh_router.resolve(query("example.org", txid=2)))
    await _until(lambda: _counts().get("coalesced") == 1)
    gate.set()
    first, second = await asyncio.gather(leader, follower)
    assert _rcode(first.body) == 2, "the leader had nothing: SERVFAIL"
    assert _rcode(second.body) == 0 and second.body[:2] == b"\x00\x02"
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_a_hung_leader_does_not_hold_the_follower_past_its_deadline(monkeypatch):
    use_redis(monkeypatch, None)
    gate, calls = asyncio.Event(), []

    async def _up(wire):
        calls.append(wire)
        if len(calls) == 1:
            await gate.wait()
        return answer(wire)

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)
    # Follower waits UPSTREAM_TIMEOUT_S + 0.5 for the leader; shrink it to 50 ms.
    monkeypatch.setattr(doh_router, "UPSTREAM_TIMEOUT_S", -0.45)
    leader = asyncio.create_task(doh_router.resolve(query("example.org", txid=1)))
    await _until(lambda: len(calls) == 1)
    second = await asyncio.wait_for(doh_router.resolve(query("example.org", txid=2)), 2.0)
    assert second.status == 200 and _rcode(second.body) == 0
    assert len(calls) == 2
    gate.set()
    assert (await leader).status == 200
    assert doh_router._inflight == {}


# ── the cache failing must never cost the lookup ────────────────────

class _CacheGetRaises:
    def get(self, *_a, **_k):
        raise RuntimeError("cache bug")

    def put(self, *_a, **_k):  # pragma: no cover - shape is dropped after a get error
        raise AssertionError("must not store after a failed read")


class _CachePutRaises:
    def get(self, *_a, **_k):
        return None

    def put(self, *_a, **_k):
        raise RuntimeError("cache bug")


@pytest.mark.asyncio
@pytest.mark.parametrize("broken", [_CacheGetRaises, _CachePutRaises], ids=["get-raises", "put-raises"])
async def test_a_failing_cache_is_counted_and_the_answer_still_flows(monkeypatch, broken):
    use_redis(monkeypatch, None)
    calls = []

    async def _up(wire):
        calls.append(wire)
        return answer(wire, ttls=(120,))

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)
    monkeypatch.setattr(doh_router, "_cache", broken())
    out = await doh_router.resolve(query("example.org"))
    assert out.status == 200 and _rcode(out.body) == 0
    assert out.max_age == 120 == http_max_age(out.body)
    assert _counts()["cache_error"] == 1 and len(calls) == 1
    assert "internal_error" not in _counts()


@pytest.mark.asyncio
async def test_a_caller_supplied_proxy_bypasses_the_cache(monkeypatch):
    use_redis(monkeypatch, None)

    async def _probe(wire):
        return answer(wire, ttls=(90,))

    out = await doh_router.resolve(query("example.org"), proxy=_probe)
    assert out.status == 200 and out.max_age == 90
    assert len(doh_router.response_cache()) == 0


@pytest.mark.asyncio
async def test_an_unreadable_upstream_answer_is_passed_through_but_never_cached(monkeypatch):
    use_redis(monkeypatch, None)
    calls = []

    async def _up(wire):
        calls.append(wire)
        return wire[:2] + b"\x81\x80" + b"\xff" * 30  # not a parseable message

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)
    for _ in range(2):
        out = await doh_router.resolve(query("example.org"))
        assert out.status == 200 and out.max_age == 0
    assert len(calls) == 2
    assert len(doh_router.response_cache()) == 0


@pytest.mark.asyncio
async def test_an_answer_about_another_name_is_never_cached_for_this_one(monkeypatch):
    use_redis(monkeypatch, None)
    calls = []

    async def _poisoning_up(wire):
        calls.append(wire)
        forged = answer(query("evil.example"))
        return wire[:2] + forged[2:]

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _poisoning_up)
    await doh_router.resolve(query("bank.example"))
    await doh_router.resolve(query("bank.example"))
    assert len(calls) == 2
    assert len(doh_router.response_cache()) == 0


# ── hostile names against the blocklist ─────────────────────────────

async def _loaded(monkeypatch) -> list:
    use_redis(monkeypatch, ArtifactRedis(LISTED))
    assert await doh_filter.HOLDER.refresh_once() is True
    calls: list = []

    async def _up(wire):
        calls.append(wire)
        return answer(wire)

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)
    return calls


def _raw_query(qname_wire: bytes) -> bytes:
    return struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + qname_wire + struct.pack("!HH", 1, 1)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "wire",
    [
        pytest.param(query("LOGIN.PHISH.EXAMPLE"), id="uppercase-subdomain"),
        pytest.param(query("a.b.c.d.e.f.g.h.phish.example"), id="deep-subdomain"),
        pytest.param(query("XN--PPLE-43D.COM"), id="idn-punycode-uppercase"),
        pytest.param(query("www.xn--pple-43d.com", edns=True, pad_to=128), id="idn-padded-edns"),
        pytest.param(_raw_query(b"\x02\xff\xfe\x05phish\x07example\x00"), id="raw-8bit-label"),
        pytest.param(_raw_query(b"\x02a.\x05phish\x07example\x00"), id="dot-inside-label"),
        pytest.param(struct.pack("!HHHHHH", 0x4242, 0x0100, 1, 0, 0, 0) + b"\x05phish\x07example",
                     id="unterminated-name"),
    ],
)
async def test_listed_names_are_blocked_however_the_query_is_spelled(monkeypatch, wire):
    calls = await _loaded(monkeypatch)
    out = await doh_router.resolve(wire)
    assert out.status == 200 and _rcode(out.body) == 3
    assert out.body[:2] == wire[:2]
    assert calls == [], "a listed name must never reach the upstream"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["phish.example.org", "notphish.example", "example"])
async def test_lookalikes_of_a_listed_name_are_not_blocked(monkeypatch, name):
    calls = await _loaded(monkeypatch)
    out = await doh_router.resolve(query(name))
    assert _rcode(out.body) == 0 and len(calls) == 1


@pytest.mark.asyncio
async def test_a_root_or_nameless_query_is_forwarded_not_blocked(monkeypatch):
    calls = await _loaded(monkeypatch)
    out = await doh_router.resolve(_raw_query(b"\x00"))
    assert out.status == 200 and len(calls) == 1
    assert _counts()["decision.none"] == 1


@pytest.mark.asyncio
async def test_garbage_twelve_bytes_is_forwarded_untouched(monkeypatch):
    use_redis(monkeypatch, None)
    sent = []

    async def _up(wire):
        sent.append(wire)
        return None

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)
    garbage = b"\xff" * 12
    out = await doh_router.resolve(garbage)
    assert sent == [garbage]
    assert out.status == 200 and _rcode(out.body) == 2


# ── GET ?dns= decoding ──────────────────────────────────────────────

@pytest.mark.parametrize(
    "value",
    [None, "", "A", "AAAAA", "AA=A", "AAAA===", "AA AA", "AA+A", "AA/A", "AA%3D", "A" * 5470],
    ids=["missing", "empty", "one-char", "len-mod-4-is-1", "inner-padding", "three-pads", "space",
         "std-plus", "std-slash", "percent", "too-long"],
)
def test_decode_get_param_is_strict(value):
    assert doh_router.decode_get_param(value) is None


def test_decode_get_param_accepts_padding_or_none():
    wire = query("example.org")
    raw = b64url(wire)
    assert doh_router.decode_get_param(raw) == wire
    assert doh_router.decode_get_param(raw + "=" * (-len(raw) % 4)) == wire


# ── HTTP surface, both paths ────────────────────────────────────────

@pytest.fixture(params=[True, False], ids=["fast-path", "fastapi-routes"])
def client(request, monkeypatch):
    from api import config
    from api.main import app
    monkeypatch.setattr(config.get_settings(), "doh_fast_path", request.param)
    use_redis(monkeypatch, None)
    return TestClient(app)


@pytest.fixture
def sent(monkeypatch):
    calls: list = []

    async def _up(wire):
        calls.append(wire)
        return answer(wire)

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)
    return calls


def test_get_with_an_undecodable_dns_param_is_400_and_not_forwarded(client, sent):
    for bad in ("A", "AAAAA", "AA=A"):
        resp = client.get("/dns-query", params={"dns": bad})
        assert resp.status_code == 400
        assert resp.headers["cache-control"] == "no-store"
    assert sent == []


def test_get_with_a_decodable_but_too_short_message_is_400(client, sent):
    resp = client.get("/dns-query", params={"dns": b64url(b"\x00" * 6)})
    assert resp.status_code == 400 and sent == []


@pytest.mark.parametrize(
    "ctype", ["application/dns-message; charset=binary", "Application/DNS-Message", None],
    ids=["with-params", "mixed-case", "absent"],
)
def test_post_media_type_matching_is_by_essence(client, sent, ctype):
    headers = {"content-type": ctype} if ctype else {}
    resp = client.post("/dns-query", content=query("example.org"), headers=headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/dns-message"
    assert len(sent) == 1


@pytest.mark.parametrize("ctype", ["application/dns-message-x", "text/plain", "application/dns-json"])
def test_post_with_a_lookalike_media_type_is_415(client, sent, ctype):
    resp = client.post("/dns-query", content=query("example.org"), headers={"content-type": ctype})
    assert resp.status_code == 415 and sent == []
    assert resp.headers["cache-control"] == "no-store"


def test_a_post_of_exactly_the_size_limit_is_accepted(client, sent):
    # Trailing padding bytes: not a cacheable shape, still forwarded.
    wire = query("example.org")
    body = wire + b"\x00" * (doh_router.MAX_QUERY_BYTES - len(wire))
    assert client.post("/dns-query", content=body, headers=CT).status_code == 200
    assert client.post("/dns-query", content=body + b"\x00", headers=CT).status_code == 413
    assert sent == [body]


def test_get_is_rate_limited_like_post(client, sent, monkeypatch):
    from api import config
    monkeypatch.setattr(config.get_settings(), "doh_rate_limit_per_window", 1)
    param = {"dns": b64url(query("example.org"))}
    assert client.get("/dns-query", params=param).status_code == 200
    resp = client.get("/dns-query", params=param)
    assert resp.status_code == 429
    assert int(resp.headers["retry-after"]) > 0
    assert len(sent) == 1


# ── lifecycle ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_startup_is_idempotent_and_shutdown_stops_everything(monkeypatch):
    use_redis(monkeypatch, ArtifactRedis(LISTED))
    await doh_router.startup()
    stats, refresher = doh_router._stats_task, doh_filter.HOLDER._task
    assert stats is not None and refresher is not None
    await doh_router.startup()
    assert doh_router._stats_task is stats and doh_filter.HOLDER._task is refresher
    await _until(lambda: doh_filter.HOLDER.current is not None)
    await doh_router.shutdown()
    assert stats.done() and refresher.done()
    assert doh_router._stats_task is None and doh_filter.HOLDER._task is None
    await doh_router.shutdown()  # a second shutdown is a no-op

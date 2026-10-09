"""RFC 8484 correctness of the DoH gateway, and its response cache.

GET and POST, application/dns-message both ways, Cache-Control max-age from
the smallest TTL (RFC 8484 §5.1, RFC 2308 for negative answers), EDNS0 and
padding passed through untouched, no ECS ever added, size limits — through
both the raw-ASGI fast path and the FastAPI routes behind it.
"""
from __future__ import annotations

import struct

import pytest
from fastapi.testclient import TestClient

from api.services.doh_cache import STALE_ANSWER_TTL, ResponseCache
from api.services.doh_wire import query_shape, response_shape
from tests.doh_helpers import ArtifactRedis, answer, b64url, query, use_redis

CT = {"content-type": "application/dns-message"}


@pytest.fixture(params=[True, False], ids=["fast-path", "fastapi-routes"])
def client(request, monkeypatch):
    from api import config
    from api.main import app
    monkeypatch.setattr(config.get_settings(), "doh_fast_path", request.param)
    use_redis(monkeypatch, ArtifactRedis({"phish.example"}))
    return TestClient(app)


@pytest.fixture
def upstream(monkeypatch):
    """Records the exact bytes forwarded; answers with configurable TTLs."""
    import api.routers.doh as doh_router
    state = {"sent": [], "ttls": (300,), "soa": None, "rcode": 0}

    async def _up(wire):
        state["sent"].append(wire)
        return answer(wire, ttls=state["ttls"], rcode=state["rcode"], soa=state["soa"])

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)
    return state


# ── methods & media type ────────────────────────────────────────────

def test_post_and_get_both_answer_with_dns_message(client, upstream):
    wire = query("example.org")
    post = client.post("/dns-query", content=wire, headers=CT)
    get = client.get("/dns-query", params={"dns": b64url(wire)})
    for resp in (post, get):
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/dns-message"
        assert resp.content[:2] == wire[:2]


def test_get_accepts_padded_base64url_and_rejects_garbage(client, upstream):
    wire = query("example.org")
    padded = b64url(wire) + "=" * (-len(b64url(wire)) % 4)
    assert client.get("/dns-query", params={"dns": padded}).status_code == 200
    for bad in ("not!valid!base64", "", "a+b/c"):
        assert client.get("/dns-query", params={"dns": bad}).status_code == 400
    assert client.get("/dns-query").status_code == 400


def test_post_with_a_foreign_media_type_is_415(client, upstream):
    resp = client.post("/dns-query", content=query("example.org"), headers={"content-type": "application/json"})
    assert resp.status_code == 415
    assert upstream["sent"] == []


def test_oversized_and_undersized_queries_are_refused_not_forwarded(client, upstream):
    assert client.post("/dns-query", content=b"\x00" * 5000, headers=CT).status_code == 413
    assert client.post("/dns-query", content=b"\x00" * 5, headers=CT).status_code == 400
    assert client.post("/dns-query", content=b"", headers=CT).status_code == 400
    assert upstream["sent"] == []


def test_error_responses_are_never_cacheable(client, upstream):
    resp = client.get("/dns-query", params={"dns": "!!"})
    assert resp.headers["cache-control"] == "no-store"


# ── Cache-Control ───────────────────────────────────────────────────

def test_max_age_is_the_smallest_ttl_in_the_answer(client, upstream):
    upstream["ttls"] = (300, 42, 120)
    resp = client.post("/dns-query", content=query("example.org"), headers=CT)
    assert resp.headers["cache-control"] == "max-age=42"


def test_negative_answer_max_age_follows_rfc2308(client, upstream):
    upstream.update(ttls=(), rcode=3, soa=(900, 75))
    resp = client.post("/dns-query", content=query("nope.example.org"), headers=CT)
    assert resp.content[3] & 0x0F == 3
    assert resp.headers["cache-control"] == "max-age=75"


def test_a_blocked_name_carries_the_negative_ttl(client, upstream):
    from api.services.doh_gateway import NEGATIVE_TTL_S
    resp = client.post("/dns-query", content=query("login.phish.example"), headers=CT)
    assert resp.content[3] & 0x0F == 3
    assert resp.headers["cache-control"] == f"max-age={NEGATIVE_TTL_S}"
    assert upstream["sent"] == []


def test_responses_keep_the_api_security_headers(client, upstream):
    resp = client.post("/dns-query", content=query("example.org"), headers=CT)
    assert "max-age=31536000" in resp.headers["strict-transport-security"]
    assert resp.headers["x-content-type-options"] == "nosniff"


# ── EDNS0, padding, ECS ─────────────────────────────────────────────

def test_edns_and_padding_are_forwarded_byte_for_byte(client, upstream):
    wire = query("example.org", edns=True, pad_to=128, do_bit=True)
    client.post("/dns-query", content=wire, headers=CT)
    client.get("/dns-query", params={"dns": b64url(query("example.net", pad_to=128))})
    assert upstream["sent"][0] == wire
    assert upstream["sent"][1] == query("example.net", pad_to=128)
    assert len(wire) % 128 == 0


def test_no_ecs_option_is_ever_added(client, upstream):
    for wire in (query("example.org"), query("example.org", edns=True), query("example.org", pad_to=128)):
        client.post("/dns-query", content=wire, headers=CT)
    for sent in upstream["sent"]:
        shape = query_shape(sent)
        assert shape is not None and not shape.other_options, "an option other than padding appeared"


def test_a_synthesised_block_echoes_edns_and_pads_to_468(client, upstream):
    resp = client.post("/dns-query", content=query("phish.example", pad_to=128, do_bit=True), headers=CT)
    body = resp.content
    assert struct.unpack("!H", body[10:12])[0] == 1, "ARCOUNT: the OPT record"
    assert len(body) % 468 == 0, "RFC 8467: a padded query gets a padded response"
    plain = client.post("/dns-query", content=query("phish.example"), headers=CT).content
    assert struct.unpack("!H", plain[10:12])[0] == 0, "no OPT in the query, none in the answer"


def test_the_nxdomain_echoes_rd_and_cd(client, upstream):
    body = client.post("/dns-query", content=query("phish.example", flags=0x0110), headers=CT).content
    assert body[2] & 0x01 and body[3] & 0x10


# ── response cache ──────────────────────────────────────────────────

def test_a_repeat_is_answered_from_cache_with_the_clients_id_and_case(client, upstream):
    client.post("/dns-query", content=query("Example.org", txid=1), headers=CT)
    again = query("eXAMPLE.ORG", txid=2)
    resp = client.post("/dns-query", content=again, headers=CT)
    assert len(upstream["sent"]) == 1
    assert resp.content[:2] == b"\x00\x02"
    assert resp.content[12:12 + len(again) - 12] == again[12:]


def test_queries_with_ecs_are_never_cached(client, upstream):
    for txid in (1, 2):
        client.post("/dns-query", content=query("example.org", ecs=True, txid=txid), headers=CT)
    assert len(upstream["sent"]) == 2


def test_a_newly_listed_name_is_blocked_even_if_its_answer_is_cached(monkeypatch, client, upstream):
    client.post("/dns-query", content=query("later-phish.example"), headers=CT)
    fake = ArtifactRedis({"phish.example", "later-phish.example"})
    use_redis(monkeypatch, fake)
    resp = client.post("/dns-query", content=query("later-phish.example"), headers=CT)
    assert resp.content[3] & 0x0F == 3


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def _ttls(resp: bytes) -> list[int]:
    return [ttl for _, ttl in response_shape(resp, 10**9).ttl_offsets]


def test_cache_decrements_ttls_and_expires():
    clock = _Clock()
    cache = ResponseCache(max_entries=10, max_ttl=3600, stale_for=600, clock=clock)
    q = query_shape(query("example.org"))
    assert cache.put(q, answer(query("example.org"), ttls=(100, 40))) == 40
    clock.now += 15
    hit = cache.get(q, query("example.org", txid=9))
    assert hit.max_age == 25 and _ttls(hit.body) == [85, 25] and hit.body[:2] == b"\x00\x09"
    clock.now += 30
    assert cache.get(q, query("example.org")) is None, "past the smallest TTL"


def test_serve_stale_only_when_asked_and_with_a_30s_ttl():
    clock = _Clock()
    cache = ResponseCache(max_entries=10, max_ttl=3600, stale_for=600, clock=clock)
    q = query_shape(query("example.org"))
    cache.put(q, answer(query("example.org"), ttls=(60,)))
    clock.now += 300
    stale = cache.get(q, query("example.org"), allow_stale=True)
    assert stale.stale and stale.max_age == STALE_ANSWER_TTL and _ttls(stale.body) == [STALE_ANSWER_TTL]
    clock.now += 600
    assert cache.get(q, query("example.org"), allow_stale=True) is None


@pytest.mark.parametrize("resp_kwargs", [{"rcode": 2}, {"tc": True}, {"ttls": (0,)}, {"ttls": (), "rcode": 0}])
def test_uncacheable_answers_are_not_stored(resp_kwargs):
    cache = ResponseCache()
    q = query_shape(query("example.org"))
    assert cache.put(q, answer(query("example.org"), **resp_kwargs)) is None


def test_an_answer_for_another_question_is_never_stored():
    cache = ResponseCache()
    q = query_shape(query("example.org"))
    assert cache.put(q, answer(query("evil.example"))) is None


def test_cache_is_bounded():
    cache = ResponseCache(max_entries=3)
    for i in range(10):
        cache.put(query_shape(query(f"n{i}.example")), answer(query(f"n{i}.example")))
    assert len(cache) == 3


def test_upstream_down_serves_stale_before_servfail(monkeypatch, client, upstream):
    import api.routers.doh as doh_router
    client.post("/dns-query", content=query("example.org"), headers=CT)
    cache = doh_router.response_cache()
    entry_key = next(iter(cache._data))
    cache._data[entry_key] = cache._data[entry_key]._replace(stored=cache._data[entry_key].stored - 1000)

    async def _down(_wire):
        return None

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _down)
    stale = client.post("/dns-query", content=query("example.org"), headers=CT)
    assert stale.content[3] & 0x0F == 0 and stale.headers["cache-control"] == f"max-age={STALE_ANSWER_TTL}"
    never_seen = client.post("/dns-query", content=query("other.example"), headers=CT)
    assert never_seen.content[3] & 0x0F == 2

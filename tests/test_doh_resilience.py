"""DoH gateway as every phone's resolver: in-memory blocklist, fail-open,
upstream failover, rate limit, privacy.

The gateway must answer through any failure on our side (Redis gone, a bug in
the filter or the cache) by forwarding, keep blocking what is listed while
Redis is down, move to the next upstream fast when one dies, and never write
a queried name or a client IP anywhere.
"""
from __future__ import annotations

import asyncio
import logging
import time

import pytest
from fastapi.testclient import TestClient

from api.services import doh_filter, doh_metrics, doh_upstream
from tests.doh_helpers import ArtifactRedis, answer, query, use_redis

LISTED = {"phish.example", "0-amazon.weebly.com"}


def _client() -> TestClient:
    from api.main import app
    return TestClient(app)


def _post(client: TestClient, wire: bytes):
    return client.post("/dns-query", content=wire, headers={"content-type": "application/dns-message"})


def _stub_upstream(monkeypatch, calls: list | None = None, fail: bool = False):
    import api.routers.doh as doh_router

    async def _up(wire):
        if calls is not None:
            calls.append(wire)
        return None if fail else answer(wire)

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)


async def _load_filter(fake: ArtifactRedis) -> None:
    assert await doh_filter.HOLDER.refresh_once() is True


# ── in-memory filter ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_filter_loads_the_published_artifact_and_matches_suffixes(monkeypatch):
    fake = ArtifactRedis(LISTED)
    use_redis(monkeypatch, fake)
    await _load_filter(fake)
    f = doh_filter.HOLDER.current
    assert f is not None and f.count == len(LISTED) + 1  # + the list canary
    assert f.listed(["login.phish.example", "phish.example", "example"]) == ["phish.example"]
    assert f.listed(["weebly.com"]) == []


@pytest.mark.asyncio
async def test_a_clean_name_never_touches_redis_once_the_filter_is_loaded(monkeypatch):
    fake = ArtifactRedis(LISTED)
    use_redis(monkeypatch, fake)
    await _load_filter(fake)
    before = fake.calls["pipeline"]
    blocked, how = await doh_filter.decide("www.wikipedia.org", ["www.wikipedia.org", "wikipedia.org"], 0.1)
    assert (blocked, how) == (False, "filter_miss")
    assert fake.calls["pipeline"] == before, "the hot path must not pay a Redis round trip"


@pytest.mark.asyncio
async def test_a_hit_is_confirmed_against_the_exact_set(monkeypatch):
    fake = ArtifactRedis(LISTED)
    use_redis(monkeypatch, fake)
    await _load_filter(fake)
    assert await doh_filter.decide("a.phish.example", ["a.phish.example", "phish.example"], 0.1) == (True, "filter_hit")
    # The set says no (a 48-bit collision, or the operator emptied the set as
    # a kill switch): not blocked.
    fake.names.discard("phish.example")
    assert await doh_filter.decide("phish.example", ["phish.example"], 0.1) == (False, "collision")


@pytest.mark.asyncio
async def test_listed_names_stay_blocked_while_redis_is_down(monkeypatch):
    fake = ArtifactRedis(LISTED)
    use_redis(monkeypatch, fake)
    await _load_filter(fake)
    fake.down = True
    assert await doh_filter.decide("phish.example", ["phish.example"], 0.1) == (True, "filter_hit_unconfirmed")
    assert await doh_filter.decide("example.org", ["example.org"], 0.1) == (False, "filter_miss")


@pytest.mark.asyncio
async def test_without_a_filter_the_gateway_falls_back_to_redis_then_fails_open(monkeypatch):
    fake = ArtifactRedis(LISTED)
    use_redis(monkeypatch, fake)
    assert await doh_filter.decide("phish.example", ["phish.example"], 0.1) == (True, "redis_hit")
    fake.down = True
    assert await doh_filter.decide("phish.example", ["phish.example"], 0.1) == (False, "redis_down")


@pytest.mark.asyncio
async def test_a_slow_redis_costs_at_most_the_deadline_and_then_is_skipped(monkeypatch):
    class _Slow(ArtifactRedis):
        def pipeline(self):
            pipe = super().pipeline()

            async def _hang():
                await asyncio.sleep(10)

            pipe.execute = _hang
            return pipe

    use_redis(monkeypatch, _Slow(LISTED))
    started = time.monotonic()
    for _ in range(3):
        assert await doh_filter.decide("phish.example", ["phish.example"], 0.05) == (False, "redis_down")
    assert time.monotonic() - started < 1.0
    # Breaker open: the next query does not even try.
    started = time.monotonic()
    assert await doh_filter.decide("phish.example", ["phish.example"], 0.05) == (False, "redis_down")
    assert time.monotonic() - started < 0.02


@pytest.mark.asyncio
async def test_refresh_downloads_the_body_only_when_the_sha_changes(monkeypatch):
    fake = ArtifactRedis(LISTED)
    use_redis(monkeypatch, fake)
    await _load_filter(fake)
    assert await doh_filter.HOLDER.refresh_once() is False
    assert fake.calls["get"] == 1
    newer = ArtifactRedis(LISTED | {"new-phish.example"})
    fake.blob, fake.meta = newer.blob, newer.meta
    assert await doh_filter.HOLDER.refresh_once() is True
    assert doh_filter.HOLDER.current.listed(["new-phish.example"]) == ["new-phish.example"]


@pytest.mark.asyncio
async def test_a_corrupt_or_unreachable_artifact_keeps_the_previous_list(monkeypatch):
    fake = ArtifactRedis(LISTED)
    use_redis(monkeypatch, fake)
    await _load_filter(fake)
    good = doh_filter.HOLDER.current
    fake.meta = {**fake.meta, "sha256": "0" * 64}  # body no longer matches
    assert await doh_filter.HOLDER.refresh_once() is False
    assert doh_filter.HOLDER.current is good and doh_filter.HOLDER.last_error == "sha_mismatch"
    fake.down = True
    assert await doh_filter.HOLDER.refresh_once() is False
    assert doh_filter.HOLDER.current is good


@pytest.mark.asyncio
async def test_a_revoked_artifact_blocks_nothing(monkeypatch):
    fake = ArtifactRedis(LISTED, revoked=True)
    fake.names = set(LISTED)
    use_redis(monkeypatch, fake)
    await _load_filter(fake)
    assert doh_filter.HOLDER.current.revoked
    assert await doh_filter.decide("phish.example", ["phish.example"], 0.1) == (False, "filter_miss")


@pytest.mark.asyncio
async def test_never_block_guards_are_never_blocked(monkeypatch):
    fake = ArtifactRedis({"github.com"})  # the 2026-08-18 incident
    use_redis(monkeypatch, fake)
    await _load_filter(fake)
    assert await doh_filter.decide("github.com", ["github.com"], 0.1) == (False, "guard")


# ── fail-open through the router ────────────────────────────────────

def test_redis_down_listed_still_blocked_clean_still_forwarded(monkeypatch):
    fake = ArtifactRedis(LISTED)
    use_redis(monkeypatch, fake)
    asyncio.run(doh_filter.HOLDER.refresh_once())
    fake.down = True
    calls: list = []
    _stub_upstream(monkeypatch, calls)
    client = _client()
    assert _post(client, query("login.phish.example")).content[3] & 0x0F == 3
    assert calls == []
    resp = _post(client, query("example.org"))
    assert resp.status_code == 200 and resp.content[3] & 0x0F == 0
    assert len(calls) == 1


@pytest.mark.parametrize("broken", ["decide", "cache"])
def test_an_internal_error_still_forwards_the_query(monkeypatch, broken):
    use_redis(monkeypatch, None)
    calls: list = []
    _stub_upstream(monkeypatch, calls)
    import api.routers.doh as doh_router

    def _boom(*_a, **_k):
        raise RuntimeError("bug on our side")

    if broken == "decide":
        monkeypatch.setattr(doh_filter, "decide", _boom)
    else:
        monkeypatch.setattr(doh_router, "response_cache", _boom)
    resp = _post(_client(), query("example.org"))
    assert resp.status_code == 200
    assert resp.content[3] & 0x0F == 0, "never SERVFAIL for a reason on our side"
    assert len(calls) == 1


# ── upstream failover ───────────────────────────────────────────────

class _FakeClient:
    """httpx.AsyncClient stand-in: behaviour per upstream URL."""
    behaviour: dict = {}
    posts: list = []

    def __init__(self, *a, **kw):
        self.is_closed = False

    async def post(self, url, content=b"", **_kw):
        type(self).posts.append(url)
        how = type(self).behaviour.get(url, "ok")
        if how == "refused":
            raise ConnectionRefusedError("refused")
        if how == "goaway-once" and type(self).posts.count(url) == 1:
            import httpx
            raise httpx.RemoteProtocolError("ConnectionTerminated")
        if how == "hang":
            await asyncio.sleep(30)
        if how == "wrong-id":
            return _Resp(200, b"\xff\xff" + answer(content)[2:])
        if how == "huge":
            return _Resp(200, content[:2] + b"\x00" * 70_000)
        if how == "http500":
            return _Resp(500, b"")
        return _Resp(200, answer(content))

    async def aclose(self):
        self.is_closed = True


class _Resp:
    def __init__(self, status, body):
        self.status_code, self.content = status, body


@pytest.fixture
def two_upstreams(monkeypatch):
    from api import config
    monkeypatch.setattr(config.get_settings(), "doh_upstreams", "https://a.test/dns-query,https://b.test/dns-query")
    monkeypatch.setattr(doh_upstream.httpx, "AsyncClient", _FakeClient)
    _FakeClient.behaviour, _FakeClient.posts = {}, []
    doh_upstream._reset_upstream_client_for_tests()
    return _FakeClient


@pytest.mark.asyncio
@pytest.mark.parametrize("how", ["refused", "wrong-id", "huge", "http500"])
async def test_a_failing_primary_fails_over_at_once(two_upstreams, how):
    two_upstreams.behaviour = {"https://a.test/dns-query": how}
    started = time.monotonic()
    out = await doh_upstream.proxy_to_upstream(query("example.org"))
    assert out is not None and out[:2] == b"\x12\x34"
    assert time.monotonic() - started < doh_upstream.HEDGE_AFTER_S
    assert two_upstreams.posts[-1] == "https://b.test/dns-query"


@pytest.mark.asyncio
async def test_a_hanging_primary_is_hedged_after_the_delay(two_upstreams, monkeypatch):
    monkeypatch.setattr(doh_upstream, "HEDGE_AFTER_S", 0.05)
    two_upstreams.behaviour = {"https://a.test/dns-query": "hang"}
    started = time.monotonic()
    assert await doh_upstream.proxy_to_upstream(query("example.org")) is not None
    assert time.monotonic() - started < 0.5


@pytest.mark.asyncio
async def test_a_dead_primary_trips_its_breaker_and_is_skipped(two_upstreams):
    two_upstreams.behaviour = {"https://a.test/dns-query": "refused"}
    for _ in range(doh_upstream.BREAKER_THRESHOLD):
        assert await doh_upstream.proxy_to_upstream(query("example.org")) is not None
    two_upstreams.posts.clear()
    assert await doh_upstream.proxy_to_upstream(query("example.org")) is not None
    assert two_upstreams.posts == ["https://b.test/dns-query"]
    assert [u["healthy"] for u in doh_upstream.status()] == [False, True]


@pytest.mark.asyncio
async def test_a_goaway_on_a_pooled_connection_is_retried_once_in_place(two_upstreams):
    two_upstreams.behaviour = {"https://a.test/dns-query": "goaway-once"}
    assert await doh_upstream.proxy_to_upstream(query("example.org")) is not None
    assert two_upstreams.posts == ["https://a.test/dns-query"] * 2


@pytest.mark.asyncio
async def test_every_upstream_down_is_none_never_an_exception(two_upstreams):
    two_upstreams.behaviour = {"https://a.test/dns-query": "refused", "https://b.test/dns-query": "refused"}
    assert await doh_upstream.proxy_to_upstream(query("example.org")) is None


def test_default_upstreams_are_cloudflare_only_as_the_privacy_policy_says():
    """§11 of the public privacy policy names Cloudflare for names we don't
    block; Quad9 is added through DOH_UPSTREAMS once the policy says so."""
    assert doh_upstream.configured_urls() == [
        "https://cloudflare-dns.com/dns-query", "https://1.1.1.1/dns-query"]


def test_quad9_can_be_added_by_configuration(monkeypatch):
    from api.config import get_settings
    monkeypatch.setattr(get_settings(), "doh_upstreams",
                        "https://cloudflare-dns.com/dns-query,https://dns.quad9.net/dns-query",
                        raising=False)
    assert doh_upstream.configured_urls()[-1] == "https://dns.quad9.net/dns-query"


# ── rate limit (in process) ─────────────────────────────────────────

def test_rate_limit_is_in_process_and_answers_429(monkeypatch):
    from api import config
    s = config.get_settings()
    monkeypatch.setattr(s, "doh_rate_limit_per_window", 2)
    use_redis(monkeypatch, None)  # no Redis at all: the limiter must not care
    _stub_upstream(monkeypatch)
    client = _client()
    codes = [_post(client, query("example.org")).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    assert doh_metrics.METRICS.counts["rate_limited"] == 1


def test_the_limiter_keeps_no_raw_ip():
    lim = doh_metrics.WindowLimiter(limit=5, window_s=60)
    lim.check("203.0.113.7")
    assert all(len(k) == 8 and b"203" not in k for k in lim._counts)


# ── privacy ─────────────────────────────────────────────────────────

def test_no_name_or_ip_is_ever_logged(monkeypatch, caplog):
    fake = ArtifactRedis(LISTED)
    use_redis(monkeypatch, fake)
    asyncio.run(doh_filter.HOLDER.refresh_once())
    client = _client()
    with caplog.at_level(logging.DEBUG):
        _stub_upstream(monkeypatch)
        _post(client, query("login.phish.example"))
        _post(client, query("secret-site.example"))
        client.get("/dns-query", params={"dns": "AAAB"})  # malformed
        _stub_upstream(monkeypatch, fail=True)
        _post(client, query("another-secret.example"))
        fake.down = True
        _post(client, query("third-secret.example"))
    text = "\n".join(r.getMessage() + " " + str(r.__dict__) for r in caplog.records)
    for needle in ("phish", "secret", "testclient", "/dns-query"):
        assert needle not in text, f"{needle!r} leaked into logs"


def test_health_doh_reports_aggregates_only(monkeypatch):
    use_redis(monkeypatch, None)
    _stub_upstream(monkeypatch)
    client = _client()
    _post(client, query("example.org"))
    body = client.get("/health/doh").json()
    assert body["ok"] is True
    assert body["stats"]["counts"]["queries"] == 1
    assert "example" not in str(body)

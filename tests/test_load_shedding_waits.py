"""Load shedding bounds the work a worker does, not the time it waits on
someone else (api/services/load_shedding.py).

The review of PR #295 found slots held while nothing ran here:
  * a DNS miss waiting up to 4 s on the upstream held a DNS slot, so a slow
    Cloudflare — or one zone whose servers never answer, asked for random
    subdomains — got 503 for the names the cache answers at once;
  * a client that sent its headers and then its body slowly, or never, held
    a slot as long as it liked (uvicorn has no timeout for a body);
  * a slow reader of a big answer (the 2.6 MB phone blocklist on a slow
    mobile network) held one while uvicorn waited for the socket;
  * /health/doh, the DNS monitor's probe, shared its slots with /health and
    /health/deep, which can hang on Redis or queue behind a slow probe;
  * the middleware's 503 had no CORS headers: a browser saw a network error.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from api.services import load_shedding as ls
from tests.doh_helpers import ArtifactRedis, answer, b64url, query, use_redis


@pytest.fixture(autouse=True)
def _fresh_counters():
    ls._reset_for_tests()
    yield
    ls._reset_for_tests()


@pytest.fixture
def settings(monkeypatch):
    from api.config import get_settings

    s = get_settings()

    def _set(**kw):
        for key, value in kw.items():
            monkeypatch.setattr(s, key, value, raising=False)
        return s

    return _set


async def _until(condition, what: str) -> None:
    for _ in range(400):
        if condition():
            return
        await asyncio.sleep(0.005)
    raise AssertionError(f"timed out waiting for {what}")


def _rcode(wire: bytes) -> int:
    return wire[3] & 0x0F


# ── DNS: a query waiting on the upstream holds no DNS slot ──

@pytest.fixture
def slow_upstream(monkeypatch):
    """Names starting with "slow" wait until released; the rest answer."""
    import api.routers.doh as doh_router

    use_redis(monkeypatch, ArtifactRedis({"phish.example"}))
    state = {"release": None, "asked": []}

    async def _up(wire):
        name = doh_router.parse_qname(wire) or ""
        state["asked"].append(name)
        if name.startswith("slow"):
            await state["release"].wait()
            return None  # what a 4 s upstream timeout gives
        return answer(wire)

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)
    return state


def test_slow_misses_filling_the_upstream_budget_leave_cached_names_answering(settings, slow_upstream):
    from api.main import app

    settings(load_shed_dns_max_inflight=8, load_shed_dns_upstream_max_inflight=8)

    async def main():
        slow_upstream["release"] = asyncio.Event()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            def ask(name: str):
                return client.get("/dns-query", params={"dns": b64url(query(name))})

            warm = await ask("example.com")  # into the response cache
            held = [asyncio.ensure_future(ask(f"slow{i}.never-answers.example")) for i in range(8)]
            await _until(lambda: ls.DNS_UPSTREAM.in_flight == 8, "8 queries waiting on the upstream")
            # The DNS budget bounds work on our side: the waiting ones gave theirs back.
            dns_in_flight = ls.DNS.in_flight
            cached = await asyncio.wait_for(ask("example.com"), 2)
            # One more miss: no upstream slot — answered as a failed upstream, at once.
            refused = await asyncio.wait_for(ask("slow9.never-answers.example"), 2)
            slow_upstream["release"].set()
            return warm, cached, refused, await asyncio.gather(*held), dns_in_flight

    warm, cached, refused, held, dns_in_flight = asyncio.run(main())
    assert warm.status_code == 200
    assert dns_in_flight == 0
    assert cached.status_code == 200 and _rcode(cached.content) == 0
    assert cached.headers["content-type"] == "application/dns-message"
    assert refused.status_code == 200 and _rcode(refused.content) == 2  # SERVFAIL, never a 503
    assert all(r.status_code == 200 for r in held)
    assert "slow9.never-answers.example" not in slow_upstream["asked"]  # never forwarded
    snap = ls.snapshot()
    assert snap["dns_upstream"]["shed"] == 1 and snap["dns_upstream"]["in_flight"] == 0
    assert snap["dns"]["shed"] == 0 and snap["dns"]["in_flight"] == 0


def test_no_upstream_slot_serves_stale_before_servfail(settings, slow_upstream):
    """The same answer a failed upstream gets: the stale copy when there is one."""
    from api.routers import doh as doh_router
    from api.services import doh_metrics

    settings(load_shed_dns_upstream_max_inflight=1)

    async def main():
        await doh_router.resolve(query("example.org"))  # cached
        cache = doh_router.response_cache()
        key = next(iter(cache._data))
        cache._data[key] = cache._data[key]._replace(stored=cache._data[key].stored - 1000)  # expired
        ls.DNS_UPSTREAM.try_acquire()  # full
        return await doh_router.resolve(query("example.org")), await doh_router.resolve(query("other.example"))

    stale, never_seen = asyncio.run(main())
    assert stale.status == 200 and _rcode(stale.body) == 0
    assert never_seen.status == 200 and _rcode(never_seen.body) == 2
    counts = doh_metrics.METRICS.snapshot()["counts"]
    assert counts["upstream_shed"] == 2 and counts["served_stale"] == 1
    assert "upstream_failed" not in counts  # the upstream did not fail: we did not ask it
    assert slow_upstream["asked"] == ["example.org"]


def test_coalesced_misses_wait_for_their_leader_without_a_dns_slot(settings, slow_upstream):
    from api.main import app
    from api.services import doh_metrics

    settings(load_shed_dns_max_inflight=1)

    async def main():
        slow_upstream["release"] = asyncio.Event()
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            wire = b64url(query("slow.popular.example"))
            held = []
            for i in range(5):  # one leader on the upstream, four waiting for it
                held.append(asyncio.ensure_future(client.get("/dns-query", params={"dns": wire})))
                await _until(lambda: ls.DNS.in_flight == 0 and ls.DNS_UPSTREAM.in_flight == 1
                             and doh_metrics.METRICS.counts["coalesced"] == i, f"query {i} waiting")
            other = await asyncio.wait_for(
                client.get("/dns-query", params={"dns": b64url(query("example.net"))}), 2)
            slow_upstream["release"].set()
            return other, await asyncio.gather(*held)

    other, held = asyncio.run(main())
    assert other.status_code == 200 and _rcode(other.content) == 0
    assert all(r.status_code == 200 for r in held)
    assert ls.DNS.shed == 0


# ── Request bodies: up to 64 KiB read before the slot; all bounded in size and time ──

def _scope(method: str, path: str, headers: list[tuple[bytes, bytes]] = ()) -> dict:
    return {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "scheme": "http",
        "method": method, "path": path, "raw_path": path.encode(), "root_path": "",
        "query_string": b"", "headers": [(b"host", b"test"), *headers],
        "client": ("203.0.113.9", 50000), "server": ("test", 80),
    }


class _Client:
    """One ASGI request whose body arrives when (and if) the test says so."""

    def __init__(self, chunks: list[bytes] = ()) -> None:
        self.chunks = list(chunks)
        self.more = asyncio.Event()
        self.gone = asyncio.Event()
        self.sent: list[dict] = []

    async def receive(self) -> dict:
        if self.chunks:
            chunk = self.chunks.pop(0)
            return {"type": "http.request", "body": chunk, "more_body": True}
        waiter = asyncio.ensure_future(self.more.wait())
        gone = asyncio.ensure_future(self.gone.wait())
        await asyncio.wait({waiter, gone}, return_when=asyncio.FIRST_COMPLETED)
        waiter.cancel()
        gone.cancel()
        if self.gone.is_set():
            return {"type": "http.disconnect"}
        self.more.clear()
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(self, message: dict) -> None:
        self.sent.append(message)

    @property
    def status(self):
        return self.sent[0]["status"] if self.sent else None


def _echo_app(seen: list):
    async def app(scope, receive, send):
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        seen.append((body, ls.API.in_flight))
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": body})
    return app


def _post(length: int) -> list[tuple[bytes, bytes]]:
    return [(b"content-length", str(length).encode()), (b"content-type", b"application/json")]


def test_a_slow_body_holds_no_slot_and_the_app_gets_it_whole(settings):
    settings(load_shed_api_max_inflight=1)
    seen: list = []

    async def main():
        mw = ls.LoadShedding(_echo_app(seen))
        slow = _Client([b'{"a":', b' 1'])
        pending = asyncio.ensure_future(mw(_scope("POST", "/api/v1/x", _post(8)), slow.receive, slow.send))
        await asyncio.sleep(0.02)
        assert ls.API.in_flight == 0 and not seen  # waiting on the client: no slot, no app
        other = _Client()
        other.more.set()  # no body: the empty last message at once
        await asyncio.wait_for(mw(_scope("GET", "/api/v1/y"), other.receive, other.send), 2)
        slow.more.set()
        await pending
        return slow, other

    slow, other = asyncio.run(main())
    assert other.status == 200
    assert slow.status == 200 and slow.sent[1]["body"] == b'{"a": 1'
    assert seen[1] == (b'{"a": 1', 1)  # the app ran with the slot, after the whole body
    assert ls.API.in_flight == 0 and ls.API.shed == 0


def test_a_body_that_never_arrives_gets_408_and_never_a_slot(settings):
    settings(load_shed_api_max_inflight=1, load_shed_body_timeout_s=0.05)
    seen: list = []

    async def main():
        mw = ls.LoadShedding(_echo_app(seen))
        silent = _Client()
        await asyncio.wait_for(mw(_scope("POST", "/api/v1/x", _post(4000)), silent.receive, silent.send), 2)
        return silent

    silent = asyncio.run(main())
    assert silent.status == 408 and seen == []
    headers = dict(silent.sent[0]["headers"])
    assert headers[b"connection"] == b"close" and headers[b"cache-control"] == b"no-store"
    assert json.loads(silent.sent[1]["body"])["detail"]
    assert ls.API.in_flight == 0 and ls.API.peak == 0


def test_a_declared_oversized_body_is_413_before_a_slot(settings):
    from api.services.request_guards import DEFAULT_BODY_LIMIT

    settings(load_shed_api_max_inflight=1)
    seen: list = []

    async def main():
        mw = ls.LoadShedding(_echo_app(seen))
        declared = _Client()
        await asyncio.wait_for(
            mw(_scope("POST", "/api/v1/x", _post(DEFAULT_BODY_LIMIT + 1)), declared.receive, declared.send), 2)
        return declared

    declared = asyncio.run(main())
    assert declared.status == 413 and seen == []
    assert ls.API.peak == 0


# Audit 2026-10-25: the whole body — up to the route's cap, 26 MiB for the
# voice upload — used to be read into memory before the slot, before routing
# and auth. ~40 anonymous uploads stalled before their last chunk held ~1 GB
# for ~7 minutes each while no budget counted them. Now at most 64 KiB is
# read ahead; the rest is read as the route asks for it, capped and
# deadlined all the same.

class _Upload(_Client):
    """A body of `size` bytes, made `chunk` at a time only as it is asked
    for, up to `stall_at` bytes; after that it waits like _Client (more/gone).
    `pulled` is what was taken off the "socket", `peak_held` the most of it
    taken but not yet handed to the app (which reports it in `delivered`)."""

    def __init__(self, size: int, chunk: int = 16 * 1024, stall_at: int | None = None) -> None:
        super().__init__()
        self.size, self.chunk = size, chunk
        self.stall_at = size if stall_at is None else stall_at
        self.pulled = self.delivered = self.peak_held = 0
        self.pulled_before_app: int | None = None

    async def receive(self) -> dict:
        if self.pulled < self.stall_at:
            n = min(self.chunk, self.stall_at - self.pulled)
            self.pulled += n
            self.peak_held = max(self.peak_held, self.pulled - self.delivered)
            return {"type": "http.request", "body": b"x" * n, "more_body": self.pulled < self.size}
        return await super().receive()


def _counting_app(upload: _Upload, seen: list):
    """Reads the whole body (or until a disconnect), then answers 200."""
    async def app(scope, receive, send):
        upload.pulled_before_app = upload.pulled
        seen.append(ls.API.in_flight)
        while True:
            message = await receive()
            upload.delivered += len(message.get("body", b""))
            if message["type"] != "http.request" or not message.get("more_body"):
                seen.append(message["type"])
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    return app


def test_a_big_body_is_read_by_the_app_after_the_slot_never_held_whole(settings):
    settings(load_shed_api_max_inflight=1)
    seen: list = []
    upload = _Upload(1024 * 1024)

    async def main():
        mw = ls.LoadShedding(_counting_app(upload, seen))
        await asyncio.wait_for(mw(_scope("POST", "/api/v1/x", _post(upload.size)), upload.receive, upload.send), 2)

    asyncio.run(main())
    assert upload.status == 200 and upload.delivered == upload.size
    assert seen[0] == 1  # the app ran with the slot
    assert upload.pulled_before_app == ls._PRE_READ_BYTES  # read ahead without a slot: 64 KiB, no more
    assert upload.peak_held <= ls._PRE_READ_BYTES
    assert ls.API.in_flight == 0 and ls.API.shed == 0


def test_a_big_body_meeting_a_full_budget_gets_503_after_64_kib_and_a_closed_connection(settings):
    settings(load_shed_api_max_inflight=1)
    ls.API.try_acquire()  # full
    seen: list = []
    upload = _Upload(1024 * 1024)

    async def main():
        mw = ls.LoadShedding(_counting_app(upload, seen))
        await asyncio.wait_for(mw(_scope("POST", "/api/v1/x", _post(upload.size)), upload.receive, upload.send), 2)

    asyncio.run(main())
    assert upload.status == 503 and seen == []
    assert upload.pulled == ls._PRE_READ_BYTES
    headers = dict(upload.sent[0]["headers"])
    assert headers[b"retry-after"] and headers[b"connection"] == b"close"  # the rest of the body is unread


def test_a_whole_body_meeting_a_full_budget_keeps_the_connection(settings):
    settings(load_shed_api_max_inflight=1)
    ls.API.try_acquire()  # full
    small = _Client([b'{"a": 1}'])
    small.more.set()

    async def main():
        mw = ls.LoadShedding(_echo_app([]))
        await asyncio.wait_for(mw(_scope("POST", "/api/v1/x", _post(8)), small.receive, small.send), 2)

    asyncio.run(main())
    assert small.status == 503 and b"connection" not in dict(small.sent[0]["headers"])


def test_a_big_body_that_stalls_after_the_slot_gets_408_and_the_slot_back(settings, monkeypatch):
    settings(load_shed_api_max_inflight=1, load_shed_body_timeout_s=0.05)
    monkeypatch.setattr(ls, "_MIN_UPLOAD_BYTES_PER_S", 1 << 40)  # the deadline: the 0.05 s alone
    seen: list = []
    upload = _Upload(1024 * 1024, stall_at=128 * 1024)

    async def main():
        mw = ls.LoadShedding(_counting_app(upload, seen))
        await asyncio.wait_for(mw(_scope("POST", "/api/v1/x", _post(upload.size)), upload.receive, upload.send), 2)

    asyncio.run(main())
    assert upload.status == 408 and len(upload.sent) == 2  # the app's own answer is dropped
    assert dict(upload.sent[0]["headers"])[b"connection"] == b"close"
    assert seen == [1, "http.disconnect"]  # the app was told the client is gone
    assert ls.API.in_flight == 0 and ls.API.peak == 1


def test_a_chunked_body_is_413_the_moment_it_passes_the_cap(settings):
    from api.services.request_guards import DEFAULT_BODY_LIMIT

    settings(load_shed_api_max_inflight=1)
    seen: list = []
    upload = _Upload(DEFAULT_BODY_LIMIT + 64 * 1024)

    async def main():
        mw = ls.LoadShedding(_counting_app(upload, seen))
        await asyncio.wait_for(
            mw(_scope("POST", "/api/v1/x", [(b"transfer-encoding", b"chunked")]), upload.receive, upload.send), 2)

    asyncio.run(main())
    assert upload.status == 413 and len(upload.sent) == 2
    assert upload.pulled == DEFAULT_BODY_LIMIT + upload.chunk  # not a chunk past the one that crossed it
    assert upload.delivered <= DEFAULT_BODY_LIMIT and seen[-1] == "http.disconnect"
    assert upload.peak_held <= ls._PRE_READ_BYTES
    assert ls.API.in_flight == 0


def test_the_voice_upload_is_not_read_ahead_at_all(settings):
    """The voice route checks its caller before it reads the upload
    (api/routers/scam.py): nothing of it is read before the route asks."""
    settings(load_shed_api_max_inflight=1)
    upload = _Upload(26 * 1024 * 1024)

    async def unauthorized(scope, receive, send):
        await send({"type": "http.response.start", "status": 401, "headers": []})
        await send({"type": "http.response.body", "body": b"{}"})

    async def main():
        mw = ls.LoadShedding(unauthorized)
        await asyncio.wait_for(mw(_scope("POST", "/api/v1/scam/analyze_voice", _post(upload.size)),
                                  upload.receive, upload.send), 2)

    asyncio.run(main())
    assert upload.status == 401 and upload.pulled == 0
    assert ls.API.in_flight == 0 and ls.API.peak == 1


def test_an_anonymous_26_mib_voice_upload_is_401_with_none_of_it_in_memory(settings):
    """The audit's reproduction, through the real app: before, the 401 came
    after all 27 MB had been read into memory (traced peak ~34 MB)."""
    import tracemalloc

    from api.main import app

    upload = _Upload(26 * 1024 * 1024, chunk=64 * 1024)
    headers = [(b"content-length", str(upload.size).encode()),
               (b"content-type", b"multipart/form-data; boundary=b")]

    async def main():
        await asyncio.wait_for(app(_scope("POST", "/api/v1/scam/analyze_voice", headers),
                                   upload.receive, upload.send), 10)

    tracemalloc.start()
    try:
        asyncio.run(main())
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert upload.status == 401
    assert upload.pulled == 0  # not a byte of the upload taken off the socket
    assert peak < 8 * 1024 * 1024, peak
    assert ls.API.in_flight == 0


def test_a_client_gone_mid_body_costs_no_slot_and_gets_no_answer(settings):
    settings(load_shed_api_max_inflight=1)
    seen: list = []

    async def main():
        mw = ls.LoadShedding(_echo_app(seen))
        client = _Client([b"{"])
        pending = asyncio.ensure_future(mw(_scope("POST", "/api/v1/x", _post(10)), client.receive, client.send))
        await asyncio.sleep(0.01)
        client.gone.set()
        await pending
        return client

    client = asyncio.run(main())
    assert client.sent == [] and seen == [] and ls.API.peak == 0


def test_half_sent_bodies_do_not_take_the_real_app_down(settings, monkeypatch):
    """The review's reproduction: POSTs that declare a body and send none."""
    from api.main import app
    from api.routers import doh as doh_router

    settings(load_shed_api_max_inflight=2, load_shed_dns_max_inflight=2)

    async def _resolve(wire):
        return doh_router.DohAnswer(answer(wire), 200, 300)

    monkeypatch.setattr(doh_router, "resolve", _resolve)

    async def main():
        stuck = [_Client() for _ in range(6)]
        paths = ["/api/v1/feedback/report"] * 3 + ["/dns-query"] * 3
        pending = [asyncio.ensure_future(app(_scope("POST", p, _post(4000)), c.receive, c.send))
                   for p, c in zip(paths, stuck)]
        await asyncio.sleep(0.05)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            version = await asyncio.wait_for(client.get("/api/v1/mobile/version"), 2)
            dns = await asyncio.wait_for(client.get("/dns-query", params={"dns": b64url(query("example.com"))}), 2)
        for c in stuck:
            c.gone.set()
        await asyncio.wait_for(asyncio.gather(*pending), 2)
        return version, dns

    version, dns = asyncio.run(main())
    assert version.status_code == 200
    assert dns.status_code == 200 and dns.headers["content-type"] == "application/dns-message"
    assert ls.API.shed == 0 and ls.DNS.shed == 0
    assert ls.API.in_flight == 0 and ls.DNS.in_flight == 0


# ── Answers: the slot is given back when the answer starts going out ──

def test_a_slow_reader_holds_no_slot(settings):
    settings(load_shed_api_max_inflight=1)

    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"x" * 2_600_000})

    async def main():
        mw = ls.LoadShedding(app)
        drained = asyncio.Event()
        sent: list = []

        async def slow_socket(message):
            sent.append(message)
            if message["type"] == "http.response.body":
                await drained.wait()  # uvicorn waiting for the socket to drain

        reader = asyncio.ensure_future(mw(_scope("GET", "/api/v1/blocklist/dns"), _Client().receive, slow_socket))
        await _until(lambda: len(sent) == 2, "the answer handed to the socket")
        held = ls.API.in_flight
        other = _Client()
        await mw(_scope("GET", "/api/v1/y"), other.receive, other.send)
        drained.set()
        await reader
        return held, other

    held, other = asyncio.run(main())
    assert held == 0 and other.status == 200
    assert ls.API.in_flight == 0 and ls.API.shed == 0


def test_a_slow_reader_through_the_real_app_holds_no_slot(settings):
    """Through the BaseHTTPMiddleware layers the answer reaches the outermost
    send in chunks (more_body=True) — the slot must already be back by then."""
    from api.main import app

    settings(load_shed_api_max_inflight=1)

    async def main():
        drained = asyncio.Event()
        sent: list = []

        async def slow_socket(message):
            sent.append(message)
            if message["type"] == "http.response.body" and message.get("body"):
                await drained.wait()

        reader = asyncio.ensure_future(app(_scope("GET", "/api/v1/mobile/version"), _Client().receive, slow_socket))
        await _until(lambda: any(m["type"] == "http.response.body" for m in sent), "the answer on its way")
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            other = await asyncio.wait_for(client.get("/api/v1/mobile/version"), 2)
        drained.set()
        await reader
        return sent[0]["status"], other

    first, other = asyncio.run(main())
    assert first == 200 and other.status_code == 200
    assert ls.API.shed == 0 and ls.API.in_flight == 0


# ── /health/doh has its own budget ──

def test_health_doh_answers_while_health_and_deep_health_are_full(settings):
    from fastapi.testclient import TestClient

    from api.main import app

    settings(load_shed_health_max_inflight=1)
    ls.HEALTH.try_acquire()
    ls.HEALTH_DEEP.try_acquire()
    client = TestClient(app)
    assert client.get("/health").status_code == 503
    assert client.get("/health/deep").status_code == 503
    resp = client.get("/health/doh")
    assert resp.status_code == 200 and resp.json()["load_shed"]["health"]["shed"] == 1


@pytest.mark.parametrize("path,budget", [
    ("/health", "health"), ("/health/doh", "health_doh"), ("/health/deep", "health_deep"),
])
def test_each_health_probe_has_its_own_class(path, budget):
    assert ls.budget_for(path).name == budget


# ── CORS on a refusal ──

def test_a_shed_answer_carries_cors_for_an_allowed_origin(settings):
    from fastapi.testclient import TestClient

    from api.main import app

    settings(load_shed_api_max_inflight=1)
    ls.API.try_acquire()  # full
    client = TestClient(app)
    allowed = client.get("/api/v1/mobile/version", headers={"Origin": "https://cleanway.ai"})
    foreign = client.get("/api/v1/mobile/version", headers={"Origin": "https://evil.example"})
    assert allowed.status_code == foreign.status_code == 503
    assert allowed.headers["access-control-allow-origin"] == "https://cleanway.ai"
    assert allowed.headers["access-control-allow-credentials"] == "true"
    assert "retry-after" in allowed.headers["access-control-expose-headers"].lower()
    assert "origin" in allowed.headers["vary"].lower()
    assert "access-control-allow-origin" not in foreign.headers


def test_an_in_route_refusal_exposes_retry_after_too():
    """The other refusal path (Overloaded, inside CORSMiddleware): a browser
    reads the same Retry-After from both."""
    from fastapi.testclient import TestClient

    from api.main import app

    resp = TestClient(app).get("/api/v1/mobile/version", headers={"Origin": "https://cleanway.ai"})
    assert resp.status_code == 200
    assert "retry-after" in resp.headers["access-control-expose-headers"].lower()

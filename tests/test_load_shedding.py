"""Load shedding (docs/runbooks/capacity.md, measured 2026-10-22).

Past saturation the API refused nothing: requests piled up in memory (up to
917 MB of a 1 GB container), latency climbed to seconds, and the server kept
working on requests whose clients had long given up. Now each request class
has a bounded number of requests in flight per worker process, and past it a
request gets an immediate 503 with Retry-After. The classes are separate, so
a flood of public checks cannot take the slots DNS queries and health probes
need.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest

from api.services import load_shedding as ls
from tests.doh_helpers import answer, b64url, query


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


# ── Budget: non-blocking, per worker ──

def test_budget_grants_up_to_its_limit_then_refuses(settings):
    settings(load_shed_api_max_inflight=2)
    assert ls.API.try_acquire() == 1
    assert ls.API.try_acquire() == 1
    assert ls.API.try_acquire() == 0
    ls.API.release()
    assert ls.API.try_acquire() == 1
    assert ls.API.snapshot() == {"in_flight": 2, "limit": 2, "peak": 2, "shed": 1}


def test_a_batch_gets_what_is_free(settings):
    settings(load_shed_fresh_analysis_max_inflight=3)
    assert ls.FRESH_ANALYSES.try_acquire(5) == 3
    assert ls.FRESH_ANALYSES.try_acquire() == 0
    assert ls.FRESH_ANALYSES.snapshot()["shed"] == 3


def test_zero_limit_and_the_kill_switch_mean_no_limit(settings):
    settings(load_shed_api_max_inflight=0)
    assert all(ls.API.try_acquire() for _ in range(1000))
    ls._reset_for_tests()
    settings(load_shed_api_max_inflight=1, load_shed_enabled=False)
    assert ls.API.try_acquire() and ls.API.try_acquire()


def test_slot_raises_overloaded_and_is_released_on_error(settings):
    settings(load_shed_fresh_analysis_max_inflight=1, load_shed_retry_after_s=7)
    with pytest.raises(RuntimeError):
        with ls.FRESH_ANALYSES.slot():
            with pytest.raises(ls.Overloaded) as refused:
                with ls.FRESH_ANALYSES.slot():
                    pass  # pragma: no cover — never entered
            assert refused.value.budget == "fresh_analysis"
            raise RuntimeError("the work itself failed")
    assert ls.FRESH_ANALYSES.in_flight == 0
    resp = asyncio.run(ls.overloaded_response(None, refused.value))
    assert resp.status_code == 503
    assert resp.headers["retry-after"] == "7" and resp.headers["cache-control"] == "no-store"
    assert json.loads(resp.body) == {"detail": ls.BUSY_DETAIL}


def test_a_refusal_is_not_a_sentry_error_event():
    """Sentry's Starlette integration reports any handled exception with a
    5xx `status_code` as an error; a flood of refusals must not be one."""
    from fastapi import HTTPException

    refused = ls.Overloaded("fresh_analysis")
    assert not isinstance(refused, HTTPException)
    assert not hasattr(refused, "status_code")


def test_check_refuses_without_taking_a_slot(settings):
    settings(load_shed_fresh_analysis_max_inflight=1)
    ls.FRESH_ANALYSES.check()  # free: no exception, nothing taken
    assert ls.FRESH_ANALYSES.in_flight == 0
    ls.FRESH_ANALYSES.try_acquire()
    with pytest.raises(ls.Overloaded):
        ls.FRESH_ANALYSES.check()
    assert ls.FRESH_ANALYSES.in_flight == 1 and ls.FRESH_ANALYSES.shed == 1


def test_defaults_are_safe():
    from api.config import Settings
    from api.services import analyzer, licensed_intel

    s = Settings()
    assert s.load_shed_enabled
    assert s.load_shed_dns_max_inflight > s.load_shed_api_max_inflight > s.load_shed_fresh_analysis_max_inflight > 0
    # A slow upstream (4 s a miss) fills this one; it must hold at least as
    # many as the DNS budget itself.
    assert s.load_shed_dns_upstream_max_inflight >= s.load_shed_dns_max_inflight
    assert s.load_shed_health_max_inflight > 0
    assert 1 <= s.load_shed_body_timeout_s <= 60
    assert 0 < s.load_shed_llm_max_inflight <= s.load_shed_fresh_analysis_max_inflight
    # At the default analysis budget the outbound gate never makes a check wait.
    checks = licensed_intel.total_checks(analyzer.TOTAL_CHECKS)
    assert s.load_shed_outbound_max_inflight >= s.load_shed_fresh_analysis_max_inflight * checks
    assert 1 <= s.load_shed_retry_after_s <= 30


@pytest.mark.parametrize("path,budget", [
    ("/dns-query", "dns"),
    ("/health", "health"), ("/health/doh", "health_doh"), ("/health/deep", "health_deep"),
    ("/api/v1/public/check/example.ru", "api"), ("/api/v1/check", "api"), ("/", "api"),
    ("/dns-query/", "api"),
])
def test_request_classes(path, budget):
    assert ls.budget_for(path).name == budget


# ── Gate: the outbound calls of an analysis wait their turn ──

def test_gate_bounds_concurrency_and_queues_the_rest(settings):
    settings(load_shed_outbound_max_inflight=2)

    async def main():
        gate = ls.Gate("t", "load_shed_outbound_max_inflight")
        running = peak = 0

        async def work():
            nonlocal running, peak
            async with gate.slot():
                running += 1
                peak = max(peak, running)
                await asyncio.sleep(0.005)
                running -= 1

        await asyncio.gather(*[work() for _ in range(10)])
        return peak, gate.snapshot()

    peak, snap = asyncio.run(main())
    assert peak == 2
    assert snap == {"in_flight": 0, "limit": 2, "peak": 2, "waited": 8}


def test_a_cancelled_waiter_does_not_leak_a_slot(settings):
    settings(load_shed_outbound_max_inflight=1)

    async def main():
        gate = ls.Gate("t", "load_shed_outbound_max_inflight")
        hold = asyncio.Event()

        async def holder():
            async with gate.slot():
                await hold.wait()

        async def quick():
            async with gate.slot():
                return "ran"

        held = asyncio.ensure_future(holder())
        await asyncio.sleep(0)
        waiter = asyncio.ensure_future(quick())
        await asyncio.sleep(0)
        waiter.cancel()  # the analysis deadline
        with pytest.raises(asyncio.CancelledError):
            await waiter
        hold.set()
        await held
        return await asyncio.wait_for(quick(), timeout=1), gate.in_flight

    assert asyncio.run(main()) == ("ran", 0)


def test_gate_without_a_limit_never_waits(settings):
    settings(load_shed_outbound_max_inflight=0)

    async def main():
        gate = ls.Gate("t", "load_shed_outbound_max_inflight")
        hold = asyncio.Event()
        entered = 0

        async def work():
            nonlocal entered
            async with gate.slot():
                entered += 1
                await hold.wait()

        tasks = [asyncio.ensure_future(work()) for _ in range(50)]
        await asyncio.sleep(0.01)
        seen = entered
        hold.set()
        await asyncio.gather(*tasks)
        return seen

    assert asyncio.run(main()) == 50


# ── The middleware (pure ASGI) ──

def _scope(path: str, kind: str = "http") -> dict:
    return {"type": kind, "method": "GET", "path": path, "headers": [], "query_string": b""}


async def _call(app, path: str) -> list[dict]:
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        sent.append(message)

    await app(_scope(path), receive, send)
    return sent


def _slow_app(release: asyncio.Event, calls: list[str]):
    async def app(scope, receive, send):
        calls.append(scope["path"])
        await release.wait()
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    return app


def test_past_the_budget_an_immediate_503_without_reaching_the_app(settings):
    settings(load_shed_api_max_inflight=1, load_shed_retry_after_s=3)
    calls: list[str] = []

    async def main():
        release = asyncio.Event()
        mw = ls.LoadShedding(_slow_app(release, calls))
        first = asyncio.ensure_future(_call(mw, "/api/v1/pricing"))
        await asyncio.sleep(0)
        shed = await _call(mw, "/api/v1/pricing")
        release.set()
        return shed, await first, await _call(mw, "/api/v1/pricing")

    shed, first, again = asyncio.run(main())
    assert shed[0]["status"] == 503
    headers = dict(shed[0]["headers"])
    assert headers[b"retry-after"] == b"3"
    assert headers[b"cache-control"] == b"no-store"
    assert headers[b"content-type"] == b"application/json"
    assert json.loads(shed[1]["body"]) == {"detail": ls.BUSY_DETAIL}
    assert first[0]["status"] == 200 and again[0]["status"] == 200  # the slot came back
    assert calls == ["/api/v1/pricing", "/api/v1/pricing"]  # the shed one never got in


def test_classes_do_not_share_slots(settings):
    settings(load_shed_api_max_inflight=1, load_shed_dns_max_inflight=1, load_shed_health_max_inflight=1)
    calls: list[str] = []

    async def main():
        release = asyncio.Event()
        mw = ls.LoadShedding(_slow_app(release, calls))
        held = [asyncio.ensure_future(_call(mw, p)) for p in ("/api/v1/x", "/dns-query", "/health")]
        await asyncio.sleep(0)
        shed = [await _call(mw, p) for p in ("/api/v1/x", "/dns-query", "/health")]
        release.set()
        return shed, await asyncio.gather(*held)

    shed, held = asyncio.run(main())
    assert [m[0]["status"] for m in held] == [200, 200, 200]
    assert [m[0]["status"] for m in shed] == [503, 503, 503]
    # A DNS client gets no JSON body (the gateway's own errors have none).
    assert shed[1][1]["body"] == b""
    assert {name: ls.snapshot()[name]["shed"] for name in ("api", "dns", "health")} == {
        "api": 1, "dns": 1, "health": 1}


def test_slot_is_released_when_the_app_raises(settings):
    settings(load_shed_api_max_inflight=1)

    async def broken(scope, receive, send):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        asyncio.run(_call(ls.LoadShedding(broken), "/api/v1/x"))
    assert ls.API.in_flight == 0


def test_lifespan_and_websocket_scopes_pass_through(settings):
    settings(load_shed_api_max_inflight=1)
    ls.API.try_acquire()  # full
    seen = []

    async def app(scope, receive, send):
        seen.append(scope["type"])

    async def main():
        mw = ls.LoadShedding(app)
        for kind in ("lifespan", "websocket"):
            await mw(_scope("/", kind), None, None)

    asyncio.run(main())
    assert seen == ["lifespan", "websocket"]


def test_shedding_is_logged_as_one_aggregate_line(settings, caplog):
    settings(load_shed_api_max_inflight=1)
    ls.API.try_acquire()
    with caplog.at_level("WARNING", logger="cleanway.load_shed"):
        for _ in range(500):
            ls.API.try_acquire()
    lines = [r for r in caplog.records if r.getMessage() == "load_shed"]
    assert len(lines) == 1
    assert lines[0].budgets["api"]["shed"] >= 1


# ── Through the real app: a flood of public checks, DNS keeps answering ──

class _Redis:
    async def eval(self, *a, **k):
        return 1

    async def ttl(self, key):
        return 60

    async def get(self, key):
        return None

    async def setex(self, *a, **k):
        return True

    async def ping(self):
        return True


def test_real_app_busy_public_checks_leave_dns_and_health_answering(settings, monkeypatch):
    from api.main import app
    from api.models.schemas import DomainResult, RiskLevel
    from api.routers import doh as doh_router
    from api.routers import public as public_router
    from api.services import analyzer

    settings(load_shed_api_max_inflight=1, load_shed_retry_after_s=2)
    fake = _Redis()

    async def _get_redis():
        return fake

    async def _not_listed(domain):
        return None

    async def _resolve(wire):
        return doh_router.DohAnswer(answer(wire), 200, 300)

    monkeypatch.setattr("api.services.cache.get_redis", _get_redis)
    monkeypatch.setattr("api.services.rate_limiter.get_redis", _get_redis)
    monkeypatch.setattr(public_router, "listed_as", _not_listed)
    monkeypatch.setattr(doh_router, "resolve", _resolve)

    async def main():
        release = asyncio.Event()

        async def _analyze(domain, *a, **k):
            await release.wait()
            return DomainResult(domain=domain, score=5, level=RiskLevel.safe, reasons=[],
                                verdict_basis="heuristics")

        monkeypatch.setattr(analyzer, "analyze_domain", _analyze)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            slow = asyncio.ensure_future(client.get("/api/v1/public/check/slow-shop-1.ru"))
            for _ in range(200):
                if ls.API.in_flight:
                    break
                await asyncio.sleep(0.005)
            # Bounded: without shedding this would wait on the blocked analysis.
            busy = await asyncio.wait_for(client.get("/api/v1/public/check/other-shop-2.ru"), 5)
            health = await client.get("/health")
            dns = await client.get("/dns-query", params={"dns": b64url(query("example.com"))})
            release.set()
            return busy, health, dns, await slow

    busy, health, dns, slow = asyncio.run(main())
    assert busy.status_code == 503
    assert busy.headers["retry-after"] == "2"
    assert busy.json() == {"detail": ls.BUSY_DETAIL}
    assert health.status_code == 200
    assert dns.status_code == 200 and dns.headers["content-type"] == "application/dns-message"
    assert slow.status_code == 200 and slow.json()["domain"] == "slow-shop-1.ru"
    assert ls.API.in_flight == 0


def test_health_doh_reports_the_counters(monkeypatch):
    from fastapi.testclient import TestClient

    from api.main import app

    ls.API.shed = 4
    body = TestClient(app).get("/health/doh").json()
    assert body["load_shed"]["api"]["shed"] == 4
    assert set(body["load_shed"]) >= {"dns", "dns_upstream", "health", "health_doh", "health_deep", "api",
                                      "uploads", "fresh_analysis", "outbound"}

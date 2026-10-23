"""Load shedding inside the expensive paths (api/services/load_shedding.py).

  * a fresh analysis — the analyzer's full fan-out — needs a slot of the
    worker's fresh-analysis budget: /public/check answers 503 + Retry-After
    without one (and without spending the caller's fresh-check quota), the
    authenticated /check analyses what fits and says the rest is partial;
  * a live LLM call (the judge, the explainer) that does not fit is skipped:
    the verdict stands, the explainer serves its template;
  * the Cloudflare comparison is skipped when too many are waiting;
  * every outbound call of an analysis waits for the worker's outbound gate,
    and that wait is never counted against the source.
"""
from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, MagicMock

from api.main import app
from api.models.schemas import AuthUser, DomainResult, RiskLevel, UserTier
from api.routers import public as public_router
from api.services import analyzer
from api.services import load_shedding as ls


@pytest.fixture(autouse=True)
def _fresh_counters():
    ls._reset_for_tests()
    public_router._INFLIGHT.clear()
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


class _Redis:
    """Rate-limit INCRs (counted per key) and the public cache."""

    def __init__(self, cached=None):
        self.counts: dict[str, int] = {}
        self.kv = dict(cached or {})

    async def eval(self, _script, _numkeys, key, *args):
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key]

    async def ttl(self, key):
        return 60

    async def get(self, key):
        return self.kv.get(key)

    async def setex(self, key, ttl, value):
        self.kv[key] = value


@pytest.fixture
def public_env(monkeypatch, settings):
    settings(load_shed_fresh_analysis_max_inflight=1, benchmark_bypass_token="")
    fake = _Redis()

    async def _get():
        return fake

    async def _not_listed(domain):
        return None

    async def _no_competitors(domain, domain_exists=None):
        return []

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    monkeypatch.setattr("api.services.rate_limiter.get_redis", _get)
    monkeypatch.setattr(public_router, "listed_as", _not_listed)
    monkeypatch.setattr("api.services.competitor_verdicts.gather_competitor_verdicts", _no_competitors)
    return fake


def _verdict(domain: str) -> DomainResult:
    return DomainResult(domain=domain, score=5, level=RiskLevel.safe, reasons=[], verdict_basis="heuristics")


# ── /public/check ──

def test_fresh_check_past_the_budget_is_503_and_spends_no_quota(public_env, monkeypatch):
    analysed: list[str] = []

    async def main():
        release = asyncio.Event()

        async def _analyze(domain, *a, **k):
            analysed.append(domain)
            await release.wait()
            return _verdict(domain)

        monkeypatch.setattr(analyzer, "analyze_domain", _analyze)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
            first = asyncio.ensure_future(client.get("/api/v1/public/check/slow-shop-1.ru"))
            for _ in range(200):
                if ls.FRESH_ANALYSES.in_flight:
                    break
                await asyncio.sleep(0.005)
            # Bounded: without shedding this would wait on the blocked analysis.
            busy = await asyncio.wait_for(client.get("/api/v1/public/check/other-shop-2.ru"), 5)
            # The same domain joins the analysis already running: no slot needed.
            same = asyncio.ensure_future(client.get("/api/v1/public/check/slow-shop-1.ru"))
            await asyncio.sleep(0.05)
            assert not same.done()
            release.set()
            return busy, await first, await same

    busy, first, same = asyncio.run(main())
    assert busy.status_code == 503
    assert busy.headers["retry-after"] == "2"
    assert busy.json() == {"detail": ls.BUSY_DETAIL}
    assert first.status_code == same.status_code == 200
    assert analysed == ["slow-shop-1.ru"]
    fresh_counted = sum(n for key, n in public_env.counts.items() if key.startswith("public_rate:"))
    assert fresh_counted == 2  # the two that got an answer; the refused one spent nothing
    assert ls.FRESH_ANALYSES.in_flight == 0 and ls.FRESH_ANALYSES.shed == 1


def test_cached_verdicts_are_served_while_analyses_are_busy(public_env, monkeypatch):
    public_env.kv[public_router._PUBLIC_CACHE_PREFIX + "cached-shop-3.ru"] = _verdict("cached-shop-3.ru").model_dump_json()
    ls.FRESH_ANALYSES.try_acquire()  # full

    async def _boom(*a, **k):
        raise AssertionError("a cached verdict needs no analysis")

    monkeypatch.setattr(analyzer, "analyze_domain", _boom)
    resp = TestClient(app).get("/api/v1/public/check/cached-shop-3.ru")
    assert resp.status_code == 200 and resp.json()["domain"] == "cached-shop-3.ru"


# ── /check (authenticated batch) ──

@pytest.fixture
def check_env(monkeypatch, settings):
    from api.routers import check as check_router
    from api.services.auth import get_current_user_no_disposable

    settings(load_shed_fresh_analysis_max_inflight=2)
    calls = {"analysed": [], "charged": [], "cached": []}

    async def _none(*a, **k):
        return None

    async def _charge(user, num_domains=1):
        calls["charged"].append(num_domains)
        return 99

    async def _analyze(domain, *a, **k):
        calls["analysed"].append(domain)
        return _verdict(domain)

    async def _cache(result):
        calls["cached"].append(result.domain)

    async def _no_redis():
        raise ConnectionError("no redis")

    monkeypatch.setattr(check_router, "check_burst_only", _none)
    monkeypatch.setattr(check_router, "listed_as", _none)
    monkeypatch.setattr(check_router, "get_cached_result", _none)
    monkeypatch.setattr(check_router, "cache_result", _cache)
    monkeypatch.setattr(check_router, "check_rate_limit", _charge)
    monkeypatch.setattr(check_router, "analyze_domain", _analyze)
    monkeypatch.setattr("api.services.cache.get_redis", _no_redis)
    app.dependency_overrides[get_current_user_no_disposable] = lambda: AuthUser(
        id="u1", email="u@example.com", tier=UserTier.personal)
    yield calls
    app.dependency_overrides.clear()


def test_batch_analyses_what_fits_and_says_the_rest_is_partial(check_env):
    domains = ["obscure-a.ru", "obscure-b.ru", "obscure-c.ru"]
    resp = TestClient(app).post("/api/v1/check", json={"domains": domains})
    assert resp.status_code == 200
    results = resp.json()["results"]
    assert [r["domain"] for r in results] == domains
    partial = [r for r in results if r["checks_incomplete"] == ["analysis"]]
    assert len(partial) == 1 and partial[0]["domain"] not in check_env["analysed"]
    assert partial[0]["verdict_basis"]
    assert sorted(check_env["analysed"]) == sorted(set(domains) - {partial[0]["domain"]})
    assert check_env["charged"] == [2]  # the partial one is not counted
    assert partial[0]["domain"] not in check_env["cached"]  # nor kept
    assert ls.FRESH_ANALYSES.in_flight == 0


def test_batch_with_no_free_slot_is_503_before_any_quota(check_env):
    ls.FRESH_ANALYSES.try_acquire(2)
    resp = TestClient(app).post("/api/v1/check", json={"domains": ["obscure-a.ru"]})
    assert resp.status_code == 503 and resp.headers["retry-after"]
    assert check_env["charged"] == [] and check_env["analysed"] == []


# ── LLM calls ──

def _broken_redis(monkeypatch):
    async def _down():
        raise RuntimeError("no redis in test")

    monkeypatch.setattr("api.services.cache.get_redis", _down)


@pytest.mark.asyncio
async def test_judge_is_skipped_while_its_llm_budget_is_full(monkeypatch, settings):
    from api.services import llm_judge, paid_budget

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    settings(load_shed_llm_max_inflight=1)
    _broken_redis(monkeypatch)
    taken = []

    async def _take(source, limit):
        taken.append(source)
        return True

    async def _llm(_):
        raise AssertionError("no live call while the LLM budget is full")

    monkeypatch.setattr(paid_budget, "take", _take)
    monkeypatch.setattr(llm_judge, "_call_claude", _llm)
    ls.LLM_JUDGE.try_acquire()
    assert await llm_judge.judge_ambiguous_verdict({"blocklist_hits": 0}, 50, "caution") is None
    assert taken == []  # the day's paid budget is not spent on a call never made


@pytest.mark.asyncio
async def test_a_judge_call_keeps_its_slot_until_it_really_ends(monkeypatch, settings):
    """The analysis stops waiting at its deadline, but the live call goes on
    in the background (it fills the cache) — and so does its slot."""
    from api.services import llm_judge, paid_budget

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    settings(load_shed_llm_max_inflight=1)
    _broken_redis(monkeypatch)
    release = asyncio.Event()
    asked = []

    async def _take(source, limit):
        return True

    async def _llm(features):
        asked.append(features)
        await release.wait()
        return {"verdict": "caution", "confidence": 0.9, "one_line_reason": "Mixed signals."}

    monkeypatch.setattr(paid_budget, "take", _take)
    monkeypatch.setattr(llm_judge, "_call_claude", _llm)
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(llm_judge.judge_ambiguous_verdict({"blocklist_hits": 0}, 50, "caution"), 0.05)
    assert ls.LLM_JUDGE.in_flight == 1
    # Another pattern meanwhile: skipped, not queued.
    assert await llm_judge.judge_ambiguous_verdict({"blocklist_hits": 0}, 55, "caution") is None
    assert len(asked) == 1
    release.set()
    for _ in range(100):
        if not ls.LLM_JUDGE.in_flight:
            break
        await asyncio.sleep(0.005)
    assert ls.LLM_JUDGE.in_flight == 0


@pytest.mark.asyncio
async def test_explainer_serves_its_template_while_the_llm_budget_is_full(monkeypatch, settings):
    from api.services import scam_explainer

    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    settings(load_shed_llm_max_inflight=1)
    fake = MagicMock()
    fake.get = AsyncMock(return_value=None)
    fake.setex = AsyncMock()

    async def _get():
        return fake

    async def _llm(*a, **k):
        raise AssertionError("no live call while the LLM budget is full")

    async def _granted():
        raise AssertionError("the day's budget is not touched")

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    monkeypatch.setattr(scam_explainer, "_llm_explanation", _llm)
    monkeypatch.setattr(scam_explainer, "_llm_budget_granted", _granted)
    ls.LLM_EXPLAINER.try_acquire()
    result = await scam_explainer.explain_scam(["chase_brand"], "en")
    assert result["source"] == "template" and result["explanation"]
    fake.setex.assert_not_called()  # a busy minute is not cached for a week
    assert ls.LLM_EXPLAINER.in_flight == 1


# ── The Cloudflare comparison ──

@pytest.mark.asyncio
async def test_competitor_lookup_is_skipped_when_too_many_are_waiting(monkeypatch):
    from api.services import competitor_verdicts as cv

    called = []

    async def _families(domain, domain_exists=None):
        called.append(domain)
        return cv.CompetitorVerdict(name="cloudflare_families", verdict="safe", label="CF")

    monkeypatch.setattr(cv, "check_cloudflare_families", _families)
    assert [c["verdict"] for c in await cv.gather_competitor_verdicts("shop.ru")] == ["safe"]
    assert ls.COMPETITOR_LOOKUPS.in_flight == 0
    ls.COMPETITOR_LOOKUPS.try_acquire(ls.COMPETITOR_LOOKUPS.limit())
    assert await cv.gather_competitor_verdicts("shop.ru") == []
    assert called == ["shop.ru"]


# ── The analyzer's outbound gate ──

def _counting(monkeypatch, delay: float):
    """Every check of the plan, sleeping `delay`; returns the peak concurrency."""
    from tests.conftest import _OFFLINE_CHECKS, _REACHABLE_SITE

    state = {"running": 0, "peak": 0}
    clean = {attr: value for attr, value in _OFFLINE_CHECKS.values()}
    clean.update(_REACHABLE_SITE)

    def _make(value):
        async def _check(domain):
            state["running"] += 1
            state["peak"] = max(state["peak"], state["running"])
            try:
                await asyncio.sleep(delay)
                return value
            finally:
                state["running"] -= 1
        return _check

    for attr, value in clean.items():
        monkeypatch.setattr(analyzer, attr, _make(value))
    return state


def test_outbound_gate_bounds_one_analysis_fan_out(offline_analyzer, monkeypatch, settings):
    settings(load_shed_outbound_max_inflight=3)
    offline_analyzer(site="reachable")
    state = _counting(monkeypatch, 0.01)
    result = asyncio.run(analyzer.analyze_domain("plain-shop-example.ru", budget_s=5.0))
    assert state["peak"] == 3
    assert result.checks_incomplete == []


def test_waiting_for_the_gate_is_not_a_source_failure(offline_analyzer, monkeypatch, settings):
    """13 checks one at a time take ~0.4 s, each source's own limit is 0.1 s:
    the limit starts once the call may run, so none of them times out."""
    from api.services.circuit_breaker import CircuitBreaker

    settings(load_shed_outbound_max_inflight=1)
    offline_analyzer(site="reachable")
    monkeypatch.setattr(analyzer, "SOURCE_TIMEOUT_S", 0.1)
    failures = []
    monkeypatch.setattr(CircuitBreaker, "_on_failure", lambda self, error: failures.append(self.name))
    state = _counting(monkeypatch, 0.03)
    result = asyncio.run(analyzer.analyze_domain("plain-shop-example.ru", budget_s=5.0))
    assert state["peak"] == 1
    assert failures == []
    assert result.checks_incomplete == []


def test_rule_only_result_says_it_is_partial():
    out = analyzer.rule_only_result("obscure-a.ru")
    assert out.checks_incomplete == ["analysis"]
    assert out.verdict_basis
    assert any(r.signal == "checks_incomplete" for r in out.reasons)
    assert json.loads(out.model_dump_json())["domain"] == "obscure-a.ru"


# ── The published artifact, read by /health and every phone's sync ──

def test_concurrent_cold_loads_read_the_artifact_body_once(monkeypatch):
    """When the published sha changes (a new list, a cold worker), every
    /health probe and phone sync in flight used to pull its own copy of the
    artifact (~5 MB of base64) out of Redis: under a /health flood a worker
    went past 900 MB (docs/runbooks/capacity.md). One read per worker; the
    rest wait for it and share its copy."""
    import base64

    from api.routers import blocklist as blocklist_router
    from api.services.blocklist_artifact import REDIS_META_KEY, REDIS_TEXT_KEY, meta_for_v2, render_artifact_v2

    blob = render_artifact_v2({"phish.example"}, generated=1755530000)
    meta = meta_for_v2(blob)
    body_reads = []

    class _R:
        async def hgetall(self, key):
            return meta if key == REDIS_META_KEY else {}

        async def get(self, key):
            if key != REDIS_TEXT_KEY:
                return None
            body_reads.append(key)
            await asyncio.sleep(0.01)
            return base64.b64encode(blob).decode()

    fake = _R()

    async def _get():
        return fake

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    monkeypatch.setattr(blocklist_router, "_cached", None)

    async def main():
        return await asyncio.gather(*[blocklist_router.load_artifact() for _ in range(20)])

    loaded = asyncio.run(main())
    assert all(item is not None and item[0] == blob for item in loaded)
    assert len(body_reads) == 1

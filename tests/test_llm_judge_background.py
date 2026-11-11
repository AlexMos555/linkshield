"""A caution answer never waits for a live LLM judge call (2026-11-03).

Measured 2026-11-01/03: the judge almost never finished inside the fresh-check
budget (34 of 40 re-checks came back with checks_incomplete [llm_judge]), yet
every caution answer waited for it until the ~3 s budget ran out — 60 of 63
caution answers took over 3 s (p50 3224 ms, against 2170 ms for 'safe'). The
browser extension (Safari's on the iPhone too) gives a lookup 3 s, so it
timed out on exactly the sites people are unsure about.

Now the analysis applies the judge's opinion only when it is already cached.
Otherwise it answers with the scorer's verdict at once, says `llm_judge` is
not in it (checks_incomplete), and leaves a live call running in the
background — within the day's budget and the worker's LLM slots — whose
answer is cached for the next check of the same pattern.
"""
from __future__ import annotations

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from api import config
from api.models.schemas import RiskLevel
from api.services import analyzer, llm_judge
from api.services import load_shedding as ls

DOMAIN = "sberbank-bonus.ru"  # a lure name: caution on the name rules alone
SIGNALS = {"blocklist_hits": 0, "watchtower_matched": True}
SLACK = 0.4  # event-loop scheduling, as in test_analysis_budget


@pytest.fixture
def settings():
    return config.get_settings()


@pytest.fixture(autouse=True)
def _fresh_judge_state():
    ls._reset_for_tests()
    llm_judge._INFLIGHT.clear()
    yield
    ls._reset_for_tests()
    llm_judge._INFLIGHT.clear()


@pytest.fixture
def slow_claude(monkeypatch, fake_redis, settings):
    """Claude answers 'dangerous' after `delay` seconds; `calls` counts live calls."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    monkeypatch.setattr(settings, "llm_judge_daily_budget", 100, raising=False)
    state = {"calls": 0, "delay": 10.0}

    async def _claude(features):
        state["calls"] += 1
        await asyncio.sleep(state["delay"])
        return {"verdict": "dangerous", "confidence": 0.9, "one_line_reason": "kit pattern"}

    monkeypatch.setattr(llm_judge, "_call_claude", _claude)
    return state


@pytest.fixture
def caution_case(offline_analyzer, monkeypatch):
    """Wires a caution-band analysis (the only band the judge is asked about):
    a lure name on a domain `age_days` old, no ML opinion. Returns the
    configure function, so a test can make several distinct patterns."""
    import api.services.ml_scorer as ml_scorer

    def configure(age_days: int = 400):
        offline_analyzer(site="reachable", values={"whois": {"age_days": age_days}})
        monkeypatch.setattr(ml_scorer, "ml_predict", lambda domain: None)
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")  # offline_analyzer clears it

    configure()
    return configure


def _own_work_seconds(monkeypatch, settings) -> float:
    """The same analysis with the judge switched off: what its own work costs
    here, now (a cold first run is slow on a loaded machine)."""
    monkeypatch.setattr(settings, "llm_judge_daily_budget", 0, raising=False)
    t0 = time.monotonic()
    asyncio.run(analyzer.analyze_domain(DOMAIN, budget_s=3.0))
    elapsed = time.monotonic() - t0
    monkeypatch.setattr(settings, "llm_judge_daily_budget", 100, raising=False)
    return elapsed


# ── The analyzer ──

def test_a_caution_answer_does_not_wait_for_a_live_judge_call(slow_claude, caution_case, monkeypatch, settings):
    own_work = _own_work_seconds(monkeypatch, settings)

    async def _run():
        loop = asyncio.get_running_loop()
        t0 = loop.time()
        result = await analyzer.analyze_domain(DOMAIN, budget_s=3.0)
        elapsed = loop.time() - t0
        running = [t for t in llm_judge._INFLIGHT.values() if not t.done()]
        for t in running:
            t.cancel()
        return result, elapsed, len(running)

    result, elapsed, running = asyncio.run(_run())
    assert result.level == RiskLevel.caution
    # Not the 3 s budget: the scorer's verdict, at once.
    assert elapsed < own_work + SLACK
    # The judge's opinion is not in this answer, and the answer says so.
    assert "llm_judge" in result.checks_incomplete
    assert "llm_judge" not in {r.signal for r in result.reasons}
    # The live call was started and is still running in the background.
    assert slow_claude["calls"] == 1 and running == 1


def test_the_background_answer_serves_the_next_check(slow_claude, caution_case):
    slow_claude["delay"] = 0.1

    async def _run():
        first = await analyzer.analyze_domain(DOMAIN, budget_s=3.0)
        await asyncio.sleep(0.4)  # the call it started ends and is cached
        second = await analyzer.analyze_domain(DOMAIN, budget_s=3.0)
        return first, second

    first, second = asyncio.run(_run())
    assert "llm_judge" in first.checks_incomplete
    assert "llm_judge" not in {r.signal for r in first.reasons}
    judge = next(r for r in second.reasons if r.signal == "llm_judge")
    assert judge.weight > 0 and second.score == first.score + judge.weight
    assert "llm_judge" not in second.checks_incomplete
    assert slow_claude["calls"] == 1


def test_the_person_is_not_told_the_judge_did_not_finish(slow_claude, caution_case):
    """`llm_judge` stays in checks_incomplete (the machine-readable list, which
    also keeps the answer in the public cache for an hour, not a day), but no
    reason says a check "did not finish in time": the judge was not waited
    for, and its opinion moves the score only inside caution
    (tests/test_llm_judge_thresholds.py), so the level rests on every check."""
    async def _run():
        result = await analyzer.analyze_domain(DOMAIN, budget_s=3.0)
        await llm_judge.stop()
        return result

    result = asyncio.run(_run())
    assert result.checks_incomplete == ["llm_judge"]
    assert "checks_incomplete" not in {r.signal for r in result.reasons}


def test_a_check_really_cut_off_is_still_named_beside_the_judge(slow_claude, offline_analyzer, monkeypatch):
    import api.services.ml_scorer as ml_scorer

    offline_analyzer(site="reachable", values={"whois": {"age_days": 400}}, delays={"phishstats": 10})
    monkeypatch.setattr(ml_scorer, "ml_predict", lambda domain: None)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")

    async def _run():
        result = await analyzer.analyze_domain(DOMAIN, budget_s=1.0)
        await llm_judge.stop()
        return result

    result = asyncio.run(_run())
    assert result.checks_incomplete == ["llm_judge", "phishstats"]
    reason = next(r for r in result.reasons if r.signal == "checks_incomplete")
    assert reason.detail.startswith("1 check did not finish in time")


def test_a_pattern_already_being_judged_is_not_asked_again(slow_claude, caution_case):
    async def _run():
        first = await analyzer.analyze_domain(DOMAIN, budget_s=1.0)
        second = await analyzer.analyze_domain(DOMAIN, budget_s=1.0)
        for t in list(llm_judge._INFLIGHT.values()):
            t.cancel()
        return first, second

    first, second = asyncio.run(_run())
    assert slow_claude["calls"] == 1
    assert "llm_judge" in first.checks_incomplete and "llm_judge" in second.checks_incomplete


def test_a_judge_that_is_not_asked_is_not_reported_missing(slow_claude, caution_case, monkeypatch, settings):
    """The day's budget spent: the judge is no part of the verdict, as without
    a key — nothing is running that could complete it."""
    monkeypatch.setattr(settings, "llm_judge_daily_budget", 0, raising=False)
    result = asyncio.run(analyzer.analyze_domain(DOMAIN, budget_s=1.0))
    assert result.level == RiskLevel.caution
    assert "llm_judge" not in result.checks_incomplete
    assert slow_claude["calls"] == 0


def test_background_calls_stay_within_the_daily_budget(slow_claude, caution_case, monkeypatch, settings):
    monkeypatch.setattr(settings, "llm_judge_daily_budget", 2, raising=False)

    async def _run():
        results = []
        for age in (400, 401, 402):  # three patterns: the age is a feature
            caution_case(age)
            results.append(await analyzer.analyze_domain(DOMAIN, budget_s=1.0))
        for t in list(llm_judge._INFLIGHT.values()):
            t.cancel()
        return results

    results = asyncio.run(_run())
    assert slow_claude["calls"] == 2
    assert ["llm_judge" in r.checks_incomplete for r in results] == [True, True, False]


# ── The judge's own entry point ──

@pytest.mark.asyncio
async def test_opinion_now_starts_a_call_and_returns_without_it(slow_claude):
    state, opinion = await llm_judge.opinion_now(SIGNALS, 45, "caution")
    assert (state, opinion) == (llm_judge.STARTED, None)
    assert slow_claude["calls"] == 1 and ls.LLM_JUDGE.in_flight == 1
    # Asked again while it runs: the same call, not a second one.
    assert await llm_judge.opinion_now(SIGNALS, 45, "caution") == (llm_judge.STARTED, None)
    assert slow_claude["calls"] == 1
    await llm_judge.stop()


@pytest.mark.asyncio
async def test_opinion_now_returns_a_cached_opinion(slow_claude):
    slow_claude["delay"] = 0
    await llm_judge.opinion_now(SIGNALS, 45, "caution")
    for _ in range(20):
        await asyncio.sleep(0.01)
    state, opinion = await llm_judge.opinion_now(SIGNALS, 45, "caution")
    assert state == llm_judge.CACHED
    assert opinion["verdict"] == "dangerous" and opinion["score_shift"] == 20
    assert slow_claude["calls"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("signals, level", [(SIGNALS, "safe"), ({"blocklist_hits": 1}, "caution")])
async def test_opinion_now_skips_what_the_judge_is_never_asked(slow_claude, signals, level):
    assert await llm_judge.opinion_now(signals, 45, level) == (llm_judge.SKIPPED, None)
    assert slow_claude["calls"] == 0


# ── Shutdown ──

@pytest.mark.asyncio
async def test_stop_cancels_the_calls_still_running(slow_claude):
    await llm_judge.opinion_now(SIGNALS, 45, "caution")
    await llm_judge.opinion_now(SIGNALS, 55, "caution")
    assert len(llm_judge._INFLIGHT) == 2
    await llm_judge.stop()
    assert llm_judge._INFLIGHT == {}
    assert ls.LLM_JUDGE.in_flight == 0


def test_shutdown_stops_the_judge_before_redis_closes(monkeypatch):
    from api import main

    order = []

    async def _noop():
        return None

    async def _stop():
        order.append("judge")

    async def _close():
        order.append("redis")

    monkeypatch.setattr(main, "_warm_ml_model", _noop)
    monkeypatch.setattr(llm_judge, "stop", _stop)
    monkeypatch.setattr(main, "close_redis", _close)
    with TestClient(main.app):
        pass
    assert order == ["judge", "redis"]


# ── The public check: what the extension waits 3 s for ──

def test_public_check_answers_caution_without_waiting_for_the_judge(slow_claude, caution_case, monkeypatch, settings,
                                                                   fake_redis):
    from api import main
    from api.routers import public as public_router

    async def _noop(*a, **k):
        return None

    async def _redis():
        return fake_redis

    monkeypatch.setattr("api.services.rate_limiter.get_redis", _redis)
    monkeypatch.setattr(main, "_warm_ml_model", _noop)
    monkeypatch.setattr(public_router, "_enforce_fresh_check_budget", _noop)
    monkeypatch.setattr(public_router, "listed_as", _noop)
    monkeypatch.setattr(settings, "analysis_budget_seconds", 3.0, raising=False)
    own_work = _own_work_seconds(monkeypatch, settings)

    with TestClient(main.app) as client:
        t0 = time.monotonic()
        body = client.get(f"/api/v1/public/check/{DOMAIN}").json()
        elapsed = time.monotonic() - t0
    assert body["level"] == "caution"
    assert body["checks_incomplete"] == ["llm_judge"]
    assert elapsed < own_work + SLACK
    assert slow_claude["calls"] == 1

"""The paid sources of an analysis: bounded per day, and never paid for twice.

Review 2026-09-27:

  * The install id is unauthenticated, so one address rotating random ids
    reaches its per-IP ceiling — 1500 fresh analyses an hour instead of 60 —
    and every fresh analysis may call IPQualityScore (5,000 a month on the
    free plan) and, in the caution band, Claude. Per-caller limits cannot
    bound the sum; a service-wide daily budget per paid source does.
  * The LLM judge only gets what is left of the ~3 s analysis budget. An Opus
    call cut off there had been sent (and billed), was thrown away and never
    cached — so the next domain with the same pattern paid for it again. The
    call now finishes in the background, fills the cache, and concurrent
    callers with the same pattern share one call.
"""
from __future__ import annotations

import asyncio

import pytest

from api import config
from api.services import analyzer, llm_judge, paid_budget


@pytest.fixture
def settings():
    return config.get_settings()


# ── paid_budget ──

def test_budget_allows_up_to_the_daily_limit(fake_redis):
    async def _run():
        return [await paid_budget.take("ipqs", 3) for _ in range(5)]
    assert asyncio.run(_run()) == [True, True, True, False, False]


def test_budgets_are_per_source(fake_redis):
    async def _run():
        return await paid_budget.take("ipqs", 1), await paid_budget.take("llm_judge", 1)
    assert asyncio.run(_run()) == (True, True)


def test_zero_budget_turns_a_source_off(fake_redis):
    assert asyncio.run(paid_budget.take("ipqs", 0)) is False


@pytest.mark.parametrize("fail_closed, expected", [(True, False), (False, True)])
def test_budget_without_redis_follows_the_fail_closed_policy(redis_down, settings, monkeypatch,
                                                             fail_closed, expected):
    monkeypatch.setattr(settings, "rate_limit_fail_closed", fail_closed, raising=False)
    assert asyncio.run(paid_budget.take("ipqs", 100)) is expected


def test_ipqs_is_not_called_past_its_budget(fake_redis, settings, monkeypatch):
    monkeypatch.setattr(settings, "ipqualityscore_key", "test-key-not-real", raising=False)
    monkeypatch.setattr(settings, "ipqs_daily_budget", 0, raising=False)

    class _NoCalls:
        def __init__(self, *a, **k):
            raise AssertionError("IPQS called past its budget")

    monkeypatch.setattr(analyzer.httpx, "AsyncClient", _NoCalls)
    assert asyncio.run(analyzer.check_ipqualityscore("obscure-shop.ru")) == {}


# ── The LLM judge: a cut-off call still pays off ──

SIGNALS = {"domain": "obscure-shop.ru", "blocklist_hits": 0, "watchtower_matched": True}


@pytest.fixture
def slow_claude(monkeypatch, fake_redis, settings):
    """Claude answers after `delay` seconds; `calls` counts live calls."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    monkeypatch.setattr(settings, "llm_judge_daily_budget", 100, raising=False)
    state = {"calls": 0, "delay": 0.3}

    async def _claude(features):
        state["calls"] += 1
        await asyncio.sleep(state["delay"])
        return {"verdict": "dangerous", "confidence": 0.9, "one_line_reason": "kit pattern"}

    monkeypatch.setattr(llm_judge, "_call_claude", _claude)
    return state


def test_cut_off_call_finishes_in_the_background_and_is_cached(slow_claude):
    async def _run():
        with pytest.raises(asyncio.TimeoutError):
            await asyncio.wait_for(llm_judge.judge_ambiguous_verdict(SIGNALS, 45, "caution"), 0.05)
        await asyncio.sleep(0.5)  # the call it started completes meanwhile
        return await llm_judge.judge_ambiguous_verdict(SIGNALS, 45, "caution")

    later = asyncio.run(_run())
    assert slow_claude["calls"] == 1
    assert later["source"] == "cache" and later["verdict"] == "dangerous"


def test_same_pattern_in_parallel_is_one_call(slow_claude):
    async def _run():
        return await asyncio.gather(*[
            llm_judge.judge_ambiguous_verdict(SIGNALS, 45, "caution") for _ in range(4)
        ])

    answers = asyncio.run(_run())
    assert slow_claude["calls"] == 1
    assert all(a["verdict"] == "dangerous" for a in answers)


def test_live_calls_stop_at_the_daily_budget(slow_claude, settings, monkeypatch):
    monkeypatch.setattr(settings, "llm_judge_daily_budget", 1, raising=False)
    slow_claude["delay"] = 0

    async def _run():
        first = await llm_judge.judge_ambiguous_verdict(SIGNALS, 35, "caution")
        other = await llm_judge.judge_ambiguous_verdict(SIGNALS, 65, "caution")  # another pattern
        return first, other

    first, other = asyncio.run(_run())
    assert first is not None and other is None
    assert slow_claude["calls"] == 1


def test_analysis_still_answers_in_time_and_says_the_judge_was_cut(slow_claude, offline_analyzer, monkeypatch):
    offline_analyzer(site="reachable", values={"whois": {"age_days": 20}})
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")  # the fixture above cleared it
    slow_claude["delay"] = 5

    async def _run():
        loop = asyncio.get_event_loop()
        t0 = loop.time()
        result = await analyzer.analyze_domain("sberbank-bonus.ru", budget_s=0.5)
        return result, loop.time() - t0

    result, elapsed = asyncio.run(_run())
    assert elapsed < 1.2
    assert "llm_judge" in result.checks_incomplete
    assert slow_claude["calls"] == 1

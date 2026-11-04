"""A source that is down does not make every answer partial (2026-11-04).

PhishStats answered 0 of 235 calls on 2026-11-04 (its API hangs,
phishstats.info itself answers 502). Its breaker opened after three failures
and half-opened 60 s later — and at low traffic every check came after those
60 s, so every check was the half-open probe: it waited out PhishStats' own
limit and was named in `checks_incomplete`. Every fresh answer then told the
person «Часть проверок не успела завершиться», and the public cache kept it
an hour instead of a day.

Now:
  * a source whose breaker is open is not asked: the answer is not held for
    it, it is not named in `checks_incomplete` (nothing was cut — the source
    is down) and the cache keeps the answer as long as any other; the
    machine-readable `sources_down` names it, for logs and diagnostics;
  * a half-open breaker lets ONE probe through; the analyses that come while
    it is out skip the source as if it were open;
  * a probe that fails sends the breaker back to open for twice as long, up
    to max_cooldown_seconds (PhishStats and PhishTank: 1 h), so a source
    that stays dead is asked about once an hour, not on every check;
  * a source that WAS asked and ran out of time is still named, as before;
  * a hanging source still opens its breaker from a slow start: its own limit
    (analyzer.SOURCE_TIMEOUT_S) ends half a second before the deadline.
"""
from __future__ import annotations

import asyncio
import time

import pytest
from fastapi.testclient import TestClient

from api.services import analyzer
from api.services import circuit_breaker as cb
from api.services.circuit_breaker import CircuitBreaker, CircuitState

SLACK = 0.4  # event-loop scheduling, as in test_analysis_budget


def _timed(coro):
    t0 = time.monotonic()
    out = asyncio.run(coro)
    return out, time.monotonic() - t0


def _age(breaker: CircuitBreaker, seconds: float) -> None:
    """Pretend `seconds` passed since the breaker's last failure."""
    breaker._last_failure_time -= seconds


async def _fail():
    raise RuntimeError("502 Bad Gateway")


async def _ok():
    return "answer"


def _open(breaker: CircuitBreaker) -> None:
    for _ in range(breaker.failure_threshold):
        asyncio.run(breaker.call(_fail))
    assert breaker.state is CircuitState.OPEN


@pytest.fixture
def phishstats(monkeypatch):
    """The real PhishStats breaker, closed, with its state restored after."""
    breaker = cb.phishstats_breaker
    for attr in ("_state", "_failure_count", "_last_failure_time", "_last_success_time",
                 "_cooldown", "_probing"):
        monkeypatch.setattr(breaker, attr, getattr(breaker, attr))
    breaker._state, breaker._failure_count = CircuitState.CLOSED, 0
    breaker._cooldown, breaker._probing = breaker.cooldown_seconds, False
    return breaker


def _counting(monkeypatch, attr: str, delay: float, value=False) -> list:
    """Replace analyzer.<attr> with a source that answers `value` after
    `delay` s; the list collects one entry per call."""
    calls: list = []

    async def _source(domain):
        calls.append(domain)
        await asyncio.sleep(delay)
        return value

    monkeypatch.setattr(analyzer, attr, _source)
    return calls


# ── The breaker ──

def test_a_half_open_breaker_lets_one_probe_through_and_skips_the_rest():
    breaker = CircuitBreaker(name="t", failure_threshold=1, cooldown_seconds=60)
    _open(breaker)
    _age(breaker, 61)
    assert breaker.state is CircuitState.HALF_OPEN

    async def _run():
        release = asyncio.Event()
        asked = []

        async def _probe():
            asked.append("probe")
            await release.wait()
            return "back"

        async def _other():
            asked.append("other")
            return "back"

        probe = asyncio.ensure_future(breaker.call(_probe))
        await asyncio.sleep(0)
        during = await breaker.call(_other)
        release.set()
        return await probe, during, asked

    probe, during, asked = asyncio.run(_run())
    assert probe == ("back", True)
    assert during == (None, False) and asked == ["probe"]
    assert breaker.state is CircuitState.CLOSED
    assert asyncio.run(breaker.call(_ok)) == ("answer", True)


def test_a_failed_probe_doubles_the_wait_up_to_the_cap():
    breaker = CircuitBreaker(name="t", failure_threshold=1, cooldown_seconds=60, max_cooldown_seconds=240)
    _open(breaker)
    waits = []
    for _ in range(4):
        waited = 0
        while True:
            _age(breaker, 60)
            waited += 60
            if breaker.state is CircuitState.HALF_OPEN:
                break
        waits.append(waited)
        asyncio.run(breaker.call(_fail))  # the probe
        assert breaker.state is CircuitState.OPEN
    assert waits == [60, 120, 240, 240]


def test_a_probe_that_succeeds_resets_the_wait():
    breaker = CircuitBreaker(name="t", failure_threshold=1, cooldown_seconds=60, max_cooldown_seconds=240)
    _open(breaker)
    for _ in range(2):  # 60 s, then 120 s: the wait is 240 s now
        _age(breaker, 240)
        asyncio.run(breaker.call(_fail))
    _age(breaker, 240)
    assert asyncio.run(breaker.call(_ok)) == ("answer", True)
    _open(breaker)
    _age(breaker, 61)
    assert breaker.state is CircuitState.HALF_OPEN


def test_without_a_cap_the_wait_stays_the_same():
    """Every breaker but the dead-feed ones keeps its fixed cooldown: Redis,
    Supabase, Safe Browsing, OTX and the site probes come back as before."""
    breaker = CircuitBreaker(name="t", failure_threshold=1, cooldown_seconds=60)
    _open(breaker)
    for _ in range(3):
        _age(breaker, 61)
        assert breaker.state is CircuitState.HALF_OPEN
        asyncio.run(breaker.call(_fail))
    _age(breaker, 61)
    assert breaker.state is CircuitState.HALF_OPEN
    for name in ("safe_browsing_breaker", "alienvault_breaker", "tranco_breaker", "watchtower_breaker",
                 "whois_breaker", "ssl_breaker", "headers_breaker", "redirect_breaker", "favicon_breaker"):
        assert getattr(cb, name).max_cooldown_seconds is None, name


def test_a_cancelled_probe_frees_the_half_open_slot():
    """The deadline cancels a probe without a verdict: the next check probes."""
    breaker = CircuitBreaker(name="t", failure_threshold=1, cooldown_seconds=60)
    _open(breaker)
    _age(breaker, 61)

    async def _run():
        probe = asyncio.ensure_future(breaker.call(asyncio.sleep, 30))
        await asyncio.sleep(0)
        probe.cancel()
        with pytest.raises(asyncio.CancelledError):
            await probe
        return await breaker.call(_ok)

    assert asyncio.run(_run()) == ("answer", True)
    assert breaker.state is CircuitState.CLOSED


def test_a_dead_feed_is_asked_about_once_an_hour_at_low_traffic(phishstats):
    """One fresh check every 5 minutes, PhishStats dead for 4 hours: with a
    fixed 60 s cooldown every one of the 48 checks was a probe."""
    assert phishstats.max_cooldown_seconds == 60 * 60
    assert cb.phishtank_breaker.max_cooldown_seconds == 60 * 60
    _open(phishstats)
    asked = []
    for minute in range(5, 4 * 60 + 1, 5):
        _age(phishstats, 5 * 60)
        if phishstats.state is CircuitState.HALF_OPEN:
            asked.append(minute)
            asyncio.run(phishstats.call(_fail))
    assert len(asked) <= 9, asked
    assert all(b - a >= 60 for a, b in zip(asked[-3:], asked[-2:])), asked


# ── An analysis ──

def test_an_open_breaker_skips_its_source_quickly_and_only_sources_down_says_so(
        offline_analyzer, monkeypatch, phishstats):
    offline_analyzer(site="reachable")
    calls = _counting(monkeypatch, "check_phishstats", 30)
    _open(phishstats)

    result, elapsed = _timed(analyzer.analyze_domain("obscure-shop.ru"))
    assert calls == []
    assert elapsed < 0.5 + SLACK
    assert result.checks_incomplete == []
    assert not any(r.signal == "checks_incomplete" for r in result.reasons)
    assert result.sources_down == ["phishstats"]


def test_an_answer_without_a_down_source_is_kept_a_day(offline_analyzer, monkeypatch, fake_redis, phishstats):
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
    offline_analyzer(site="reachable")
    _counting(monkeypatch, "check_phishstats", 30)
    _open(phishstats)

    with TestClient(main.app) as client:
        body = client.get("/api/v1/public/check/obscure-shop.ru").json()
    assert body["checks_incomplete"] == []
    assert "checks_incomplete" not in body["reason_codes"]
    key = public_router._PUBLIC_CACHE_PREFIX + "obscure-shop.ru"
    assert fake_redis._ttls[key] == public_router._PUBLIC_CACHE_TTL_SECONDS
    assert '"sources_down":["phishstats"]' in fake_redis._kv[key]


def test_a_half_open_probe_that_runs_out_of_time_is_named(offline_analyzer, monkeypatch, phishstats):
    """It was asked and did not answer in time: the answer says so."""
    monkeypatch.setattr(analyzer, "SOURCE_TIMEOUT_S", 0.2)
    offline_analyzer(site="reachable")
    _counting(monkeypatch, "check_phishstats", 30)
    _open(phishstats)
    _age(phishstats, phishstats.cooldown_seconds + 1)

    result = asyncio.run(analyzer.analyze_domain("obscure-shop.ru", budget_s=3.0))
    assert result.checks_incomplete == ["phishstats"]
    assert result.sources_down == []
    assert phishstats.state is CircuitState.OPEN


def test_while_the_probe_is_out_other_analyses_skip_the_source(offline_analyzer, monkeypatch, phishstats):
    monkeypatch.setattr(analyzer, "SOURCE_TIMEOUT_S", 0.3)
    offline_analyzer(site="reachable")
    calls = _counting(monkeypatch, "check_phishstats", 30)
    _open(phishstats)
    _age(phishstats, phishstats.cooldown_seconds + 1)

    async def _both():
        first = asyncio.ensure_future(analyzer.analyze_domain("probe-shop.ru", budget_s=3.0))
        await asyncio.sleep(0.1)
        second = await analyzer.analyze_domain("other-shop.ru", budget_s=3.0)
        return await first, second

    probe, other = asyncio.run(_both())
    assert calls == ["probe-shop.ru"]
    assert probe.checks_incomplete == ["phishstats"]
    assert other.checks_incomplete == [] and other.sources_down == ["phishstats"]


def test_a_source_that_is_back_closes_its_breaker_on_the_probe(offline_analyzer, monkeypatch, phishstats):
    offline_analyzer(site="reachable")
    calls = _counting(monkeypatch, "check_phishstats", 0.05, value=True)
    _open(phishstats)
    _age(phishstats, phishstats.cooldown_seconds + 1)

    result = asyncio.run(analyzer.analyze_domain("listed-shop.ru"))
    assert calls == ["listed-shop.ru"]
    assert phishstats.state is CircuitState.CLOSED
    assert result.sources_down == [] and result.checks_incomplete == []
    assert any(r.signal == "phishstats" for r in result.reasons), result.reasons


def test_a_hanging_source_opens_its_breaker_from_a_slow_start(offline_analyzer, monkeypatch, phishstats):
    """The default budget, the existence and SSRF lookups taking 0.45 s (p83
    from Dubai through a home router, p59 through 1.1.1.1, 2026-11-04): the
    source's own limit still ends before the deadline, so its breaker counts
    the hang — with 2.0 s of 2.3 the deadline cancelled it first, which a
    breaker never sees. Three such checks open it; the next skips the source."""
    offline_analyzer(site="reachable", delays={"exists": 0.45, "resolution": 0.45})
    calls = _counting(monkeypatch, "check_phishstats", 30)

    async def _three():
        return await asyncio.gather(*(analyzer.analyze_domain(f"shop-{i}.ru") for i in range(3)))

    first = asyncio.run(_three())
    assert all(r.checks_incomplete == ["phishstats"] for r in first)
    assert phishstats.state is CircuitState.OPEN

    result, elapsed = _timed(analyzer.analyze_domain("shop-4.ru"))
    assert len(calls) == 3
    assert result.checks_incomplete == [] and result.sources_down == ["phishstats"]
    assert elapsed < 0.45 + 0.5 + SLACK

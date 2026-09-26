"""A fresh check answers within its time budget (report 2026-09-25 #6).

10 of 31 first checks took over 5 s and one 10.9 s, while the phone waits
5 s and the app 6 s — so people saw "the server did not answer" for checks
that were still running. The analysis now has one deadline; slow checks and
the LLM judge are cut off, the verdict names them in `checks_incomplete`,
and the router has a hard backstop on top. Slow sources are mocked here.
"""
from __future__ import annotations

import asyncio
import time
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from api.main import app
from api.models.schemas import DomainResult, RiskLevel
from api.routers import public as public_router
from api.services import analyzer, dns_checks
from api.services.analysis_budget import Deadline, run_within_budget

BUDGET = 0.5
SLACK = 0.6  # event-loop scheduling + scoring; far below any real-world source


def _timed(coro):
    t0 = time.monotonic()
    out = asyncio.run(coro)
    return out, time.monotonic() - t0


# ── The helper ──

def test_run_within_budget_cuts_off_stragglers():
    async def _after(delay, value):
        await asyncio.sleep(delay)
        return value

    async def _boom():
        raise RuntimeError("source down")

    (results, unfinished), elapsed = _timed(run_within_budget(
        {"fast": _after(0.01, 1), "slow": _after(5, 2), "broken": _boom()}, 0.2,
    ))
    assert results == {"fast": 1}
    assert sorted(unfinished) == ["broken", "slow"]
    assert elapsed < 1.0


def test_deadline_never_goes_negative():
    d = Deadline(0.0)
    assert d.remaining() == 0.0
    assert d.step(1.0) > 0  # a step always gets a minimal slice


# ── The analyzer ──

def test_slow_source_is_cut_and_named(offline_analyzer):
    offline_analyzer(site="reachable", delays={"whois": 10, "safe_browsing": 10})
    result, elapsed = _timed(analyzer.analyze_domain("obscure-shop.ru", budget_s=BUDGET))

    assert elapsed < BUDGET + SLACK
    assert {"whois", "safe_browsing"} <= set(result.checks_incomplete)
    reason = next(r for r in result.reasons if r.signal == "checks_incomplete")
    assert reason.weight == 0
    # The machine names are for clients; the person reads plain words.
    assert "safe_browsing" not in reason.detail and "did not finish in time" in reason.detail


def test_complete_analysis_reports_nothing_missing(offline_analyzer):
    offline_analyzer(site="reachable")
    result = asyncio.run(analyzer.analyze_domain("obscure-shop.ru", budget_s=5.0))
    assert result.checks_incomplete == []
    assert "checks_incomplete" not in {r.signal for r in result.reasons}


def test_slow_llm_judge_is_cut_off(offline_analyzer, monkeypatch):
    offline_analyzer(site="reachable", values={"whois": {"age_days": 20}})
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")
    from api.services import llm_judge

    async def _slow(*a, **k):
        await asyncio.sleep(10)

    monkeypatch.setattr(llm_judge, "judge_ambiguous_verdict", _slow)
    result, elapsed = _timed(analyzer.analyze_domain("sberbank-bonus.ru", budget_s=BUDGET))
    assert elapsed < BUDGET + SLACK
    assert "llm_judge" in result.checks_incomplete


def test_slow_ssrf_resolution_skips_the_site_probes(offline_analyzer):
    """Never connect to a site whose address we could not vet in time."""
    offline_analyzer(site="reachable", delays={"resolution": 10})
    result, elapsed = _timed(analyzer.analyze_domain("obscure-shop.ru", budget_s=BUDGET))
    assert elapsed < BUDGET + SLACK
    assert {"ssl", "headers", "redirect", "favicon"} <= set(result.checks_incomplete)
    assert result.has_ssl is None


def test_sources_give_up_before_the_budget(monkeypatch):
    """A source that hangs must fail on its OWN timeout — so its circuit
    breaker counts it and opens — rather than be cancelled at the deadline on
    every check forever (a hanging PhishStats held each check to 3 s)."""
    import httpx

    from api import config

    seen = []

    class _Client:
        def __init__(self, *a, timeout=None, **k):
            seen.append(timeout)

        async def __aenter__(self):
            raise httpx.ConnectTimeout("hang")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(analyzer.httpx, "AsyncClient", _Client)
    for check in (analyzer.check_phishtank, analyzer.check_urlhaus, analyzer.check_whois_age,
                  analyzer.check_phishstats, analyzer.check_threatfox, analyzer.check_malware_bazaar,
                  analyzer.check_alienvault_otx):
        try:
            asyncio.run(check("obscure-shop.ru"))
        except httpx.ConnectTimeout:
            pass
    budget = config.get_settings().analysis_budget_seconds
    assert len(seen) == 7 and all(t < budget for t in seen), seen


def test_hanging_source_fails_inside_its_breaker(offline_analyzer, monkeypatch):
    """httpx's timeout is per phase: a source that accepts the connection and
    then trickles never times out by itself, and a check cancelled at the
    deadline is invisible to its breaker (CancelledError is not an
    Exception). The source's TOTAL limit fires first, as a counted failure."""
    from api.services.circuit_breaker import CircuitState, phishstats_breaker

    monkeypatch.setattr(phishstats_breaker, "_failure_count", 0)
    monkeypatch.setattr(phishstats_breaker, "_state", CircuitState.CLOSED)
    monkeypatch.setattr(analyzer, "SOURCE_TIMEOUT_S", 0.2)
    offline_analyzer(site="reachable", delays={"phishstats": 30})
    result, elapsed = _timed(analyzer.analyze_domain("obscure-shop.ru", budget_s=1.0))
    assert elapsed < 1.0
    assert phishstats_breaker._failure_count == 1


def test_existence_and_ssrf_lookups_run_in_parallel(offline_analyzer):
    """Both resolve the same name, each capped at 1.5 s: in sequence a slow
    name server spent the whole 3 s budget before any check started."""
    offline_analyzer(site="reachable", delays={"exists": 1.0, "resolution": 1.0})
    result, elapsed = _timed(analyzer.analyze_domain("obscure-shop.ru", budget_s=3.0))
    assert elapsed < 1.6
    assert result.checks_incomplete == []


def test_nxdomain_does_not_wait_for_the_ssrf_lookup(offline_analyzer):
    offline_analyzer(exists=False, delays={"resolution": 10})
    result, elapsed = _timed(analyzer.analyze_domain("sbertank.ru", budget_s=3.0))
    assert result.exists is False
    assert elapsed < 0.5


def test_dns_enrichment_lookups_run_concurrently():
    def _slow_resolve(domain, rdtype):
        time.sleep(0.3)
        raise Exception("no answer")

    resolver = MagicMock()
    resolver.resolve.side_effect = _slow_resolve
    with patch.object(dns_checks, "_resolver", return_value=resolver):
        out, elapsed = _timed(dns_checks.check_dns("obscure-shop.ru"))
    assert elapsed < 0.75  # three sequential lookups would take 0.9 s
    assert out["has_mx"] is False and out["a_count"] == 0


# ── The router's backstop ──

def test_router_never_waits_past_the_backstop(monkeypatch, fake_redis):
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "analysis_budget_seconds", 0.2, raising=False)
    monkeypatch.setattr(public_router, "_BACKSTOP_GRACE_SECONDS", 0.2)

    async def _hang(domain, *a, **k):
        await asyncio.sleep(30)

    async def _noop(*a, **k):
        return None

    async def _not_listed(d):
        return None

    monkeypatch.setattr(analyzer, "analyze_domain", _hang)
    monkeypatch.setattr(public_router, "_enforce_fresh_check_budget", _noop)
    monkeypatch.setattr(public_router, "listed_as", _not_listed)

    t0 = time.monotonic()
    body = TestClient(app).get("/api/v1/public/check/obscure-shop.ru").json()
    assert time.monotonic() - t0 < 2.0
    assert body["checks_incomplete"] == ["analysis"]
    assert "checks_incomplete" in body["reason_codes"]
    # The degraded answer is not cached: the next request measures for real.
    assert not fake_redis._kv


def test_ml_model_is_loaded_before_serving(monkeypatch):
    """Loaded lazily, the model's ~7 s start-up landed on the FIRST fresh
    check after a deploy, synchronously, on the event loop."""
    from api import main

    started = []

    async def _warm():
        started.append(True)

    monkeypatch.setattr(main, "_warm_ml_model", _warm)
    with TestClient(main.app):
        assert started == [True]


def test_ml_warmup_runs_the_loader_and_never_fails_startup(monkeypatch):
    from api import main
    from api.services import ml_scorer

    calls = []
    monkeypatch.setattr(ml_scorer, "backend_status", lambda: calls.append(1) or "onnx")
    asyncio.run(main._warm_ml_model())
    assert calls == [1]

    def _broken():
        raise RuntimeError("onnxruntime missing")

    monkeypatch.setattr(ml_scorer, "backend_status", _broken)
    asyncio.run(main._warm_ml_model())  # logged, not raised


def test_partial_verdicts_are_cached_briefly():
    partial = DomainResult(domain="x.ru", score=10, level=RiskLevel.safe, reasons=[],
                           checks_incomplete=["whois"])
    full = partial.model_copy(update={"checks_incomplete": []})
    assert public_router._public_cache_ttl(partial) < public_router._public_cache_ttl(full)

"""A fresh check answers inside the browser extension's wait (2026-11-04).

The extension (and Safari's on the iPhone, the same code) gives
/api/v1/public/check 3000 ms (LOOKUP_TIMEOUT_MS) and then uses its offline
scorer. The analysis budget was those same 3 s, so an answer whose checks ran
to the deadline came back after the client had given up: 3.2-3.7 s measured
from Dubai on 2026-11-04. Since PhishStats stopped answering (its API accepts
the connection and never replies), every fresh check with its breaker closed
ran to PhishStats' own limit — and at low traffic every check is the
breaker's half-open probe.

The budget now leaves the network its share of the client's wait, every
source still gives up inside the budget (so a hang is a failure its breaker
counts), a site that never answers is still found unreachable inside it (the
probes' connection limit came down with it), and a source ended by its own
time limit is named in `checks_incomplete` like one the deadline cut: the
answer says it is partial and the public cache keeps it for an hour, not a
day.
"""
from __future__ import annotations

import asyncio
import re
import time
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from api import config
from api.services import analyzer, favicon_hash, site_probes

ROOT = Path(__file__).resolve().parent.parent
# Every build of the extension asks the same way: Chrome, Firefox, Safari.
EXTENSION_COPIES = ("extension", "extension-firefox", "extension-safari")
# Measured 2026-11-04 from Dubai to api.cleanway.ai/health (10 + 10 requests):
# a new connection (TCP + TLS + request) took 0.44-0.68 s, p50 0.54 s; a
# kept-alive one 0.26-0.35 s, p50 0.27 s. The budget is sized for the new one.
NETWORK_NEW_CONNECTION_S = 0.54
# What the analysis does after its deadline (scoring, the judge's cache
# lookup, the response): at most 0.03 s in the replay of 2026-11-04.
AFTER_DEADLINE_S = 0.05
# The existence and SSRF lookups before any source starts: p50 0.19 s, p75
# 0.30 s over 235 analyses in the same measurement. A source's own limit
# must end before the deadline from there, or a hang is cancelled instead
# of counted.
TYPICAL_START_S = 0.3
# A site probe that timed out reported p50 0.13 s, p90 0.26-0.29 s after its
# connection limit (its own name lookup, the TLS probe's thread), at most
# 0.5 s (the whole-probe limit): 55 sites that never answered from abroad,
# at both the old and the new limits, 2026-11-04.
PROBE_OVERHEAD_S = 0.4
SLACK = 0.4  # event-loop scheduling, as in test_analysis_budget


def _extension_timeout_s(copy: str) -> float:
    text = (ROOT / copy / "src" / "background" / "public-check.js").read_text()
    match = re.search(r"export const LOOKUP_TIMEOUT_MS = (\d+);", text)
    assert match, f"{copy}: LOOKUP_TIMEOUT_MS not found"
    return int(match.group(1)) / 1000


def _default_budget() -> float:
    return config.Settings.model_fields["analysis_budget_seconds"].default


def _timed(coro):
    t0 = time.monotonic()
    out = asyncio.run(coro)
    return out, time.monotonic() - t0


@pytest.fixture
def phishstats_breaker(monkeypatch):
    from api.services.circuit_breaker import CircuitState, phishstats_breaker as breaker

    monkeypatch.setattr(breaker, "_failure_count", 0)
    monkeypatch.setattr(breaker, "_state", CircuitState.CLOSED)
    return breaker


# ── The numbers ──

def test_every_extension_build_still_waits_3_s():
    """The fix is on the server: the extension's wait is not raised."""
    assert {_extension_timeout_s(c) for c in EXTENSION_COPIES} == {3.0}


def test_the_budget_leaves_the_network_its_share_of_the_extensions_wait():
    budget = _default_budget()
    wait = _extension_timeout_s("extension")
    # A tenth of a second to spare: a slower phone network, a busy worker.
    assert budget + AFTER_DEADLINE_S + NETWORK_NEW_CONNECTION_S <= wait - 0.1, budget


def test_the_running_config_uses_that_budget():
    assert config.get_settings().analysis_budget_seconds == _default_budget()


def test_a_source_gives_up_inside_the_budget_from_a_normal_start():
    """Below the budget is not enough: a source starts once existence and the
    SSRF lookup are done. From the usual start its own limit must still end
    first, so a hang is a failure its breaker counts (and opens on)."""
    assert analyzer.SOURCE_TIMEOUT_S + TYPICAL_START_S <= _default_budget()


def test_an_unreachable_site_is_still_measured_unreachable_inside_the_budget():
    """A site that never answers is 'unreachable' when its probe's connection
    limit ends first, 'cut off' when the deadline does — and only
    'unreachable' keeps the floor for a name nothing vouches for: cut off,
    a hidden phishing site came back 'safe' (sirimaneproperties.com, replay
    of 2026-11-04). The probe resolves the name itself and the TLS one runs
    in a thread, so it reports PROBE_OVERHEAD_S after its connection limit."""
    budget = _default_budget()
    for limit in (site_probes.SITE_PROBE_TIMEOUT_S, favicon_hash.FAVICON_FETCH_TIMEOUT):
        assert limit + TYPICAL_START_S + PROBE_OVERHEAD_S <= budget, limit


def test_a_probe_still_gets_past_one_lost_syn():
    """The connection limit is not cut to the bone: a SYN lost once is resent
    after 1 s (Linux's initial retransmission timeout), and a site behind a
    lossy link must still be reachable."""
    assert site_probes.SITE_PROBE_TIMEOUT_S >= 1.5
    assert site_probes.SITE_PROBE_TOTAL_S > site_probes.SITE_PROBE_TIMEOUT_S


# ── A source ended by its own limit says so ──

def test_a_source_ended_by_its_own_limit_is_named_incomplete(offline_analyzer, monkeypatch, phishstats_breaker):
    monkeypatch.setattr(analyzer, "SOURCE_TIMEOUT_S", 0.2)
    offline_analyzer(site="reachable", delays={"phishstats": 30})
    result, elapsed = _timed(analyzer.analyze_domain("obscure-shop.ru", budget_s=3.0))

    assert elapsed < 1.0  # its own limit, not the deadline
    assert phishstats_breaker._failure_count == 1  # still a failure the breaker counts
    assert result.checks_incomplete == ["phishstats"]
    reason = next(r for r in result.reasons if r.signal == "checks_incomplete")
    assert reason.weight == 0 and "1 check did not finish in time" in reason.detail


def test_a_connection_phase_timeout_is_named_too(offline_analyzer, monkeypatch):
    """httpx's per-phase limit can fire before the total one: the source did
    not finish in time either way."""
    offline_analyzer(site="reachable")

    async def _read_timeout(domain):
        raise httpx.ReadTimeout("no answer")

    monkeypatch.setattr(analyzer, "check_alienvault_otx", _read_timeout)
    result = asyncio.run(analyzer.analyze_domain("obscure-shop.ru", budget_s=3.0))
    assert result.checks_incomplete == ["alienvault"]


def test_a_source_that_fails_is_not_called_late(offline_analyzer, monkeypatch, phishstats_breaker):
    """An error answer (a 500, a 429, a page that is not JSON) is a failed
    check, not one that ran out of time: "did not finish in time" would be
    untrue, and the answer would not be better an hour later."""
    offline_analyzer(site="reachable")

    async def _broken(domain):
        raise ValueError("Expecting value: line 1 column 1 (char 0)")

    monkeypatch.setattr(analyzer, "check_phishstats", _broken)
    result = asyncio.run(analyzer.analyze_domain("obscure-shop.ru", budget_s=3.0))
    assert result.checks_incomplete == []
    assert phishstats_breaker._failure_count == 1


def test_one_analysis_does_not_name_another_ones_timeout(offline_analyzer, monkeypatch):
    """Two analyses at once on one worker: each names only its own checks."""
    monkeypatch.setattr(analyzer, "SOURCE_TIMEOUT_S", 0.2)
    offline_analyzer(site="reachable")
    real = analyzer.check_phishstats

    async def _slow_for_one(domain):
        if domain == "slow-shop.ru":
            await asyncio.sleep(30)
        return await real(domain)

    monkeypatch.setattr(analyzer, "check_phishstats", _slow_for_one)

    async def _both():
        return await asyncio.gather(
            analyzer.analyze_domain("slow-shop.ru", budget_s=3.0),
            analyzer.analyze_domain("quick-shop.ru", budget_s=3.0),
        )

    slow, quick = asyncio.run(_both())
    assert slow.checks_incomplete == ["phishstats"]
    assert quick.checks_incomplete == []


# ── With the default budget ──

def test_a_source_as_slow_as_otx_at_its_worst_is_cut_inside_the_default_budget(offline_analyzer):
    """Keyless OTX took 2.76 s and 2.85 s for 2 of 23 calls (2026-11-04):
    with the default budget the answer goes out without it, says so, and
    reaches the client inside its wait."""
    offline_analyzer(site="reachable")
    _, own_work = _timed(analyzer.analyze_domain("obscure-shop.ru", budget_s=5.0))
    offline_analyzer(site="reachable", delays={"alienvault": 2.8})
    result, elapsed = _timed(analyzer.analyze_domain("obscure-shop.ru"))
    assert elapsed < _default_budget() + own_work + SLACK
    assert result.checks_incomplete == ["alienvault"]


class _SlowUnreachableClient:
    """A site whose firewall drops our SYN: every request looks the name up
    (PinnedTransport does), then waits out the client's connection limit."""

    def __init__(self, *args, timeout=None, **kwargs):
        self._limit = timeout if isinstance(timeout, (int, float)) else timeout.connect

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def _wait_out(self, url, *args, **kwargs):
        await asyncio.sleep(PROBE_LOOKUP_S + self._limit)
        raise httpx.ConnectTimeout("timed out from abroad")

    get = head = _wait_out


PROBE_LOOKUP_S = 0.2  # the probe's own name lookup


def test_a_site_that_never_answers_is_found_unreachable_inside_the_default_budget(offline_analyzer, monkeypatch):
    """The case the replay of 2026-11-04 caught: with the probes' old 2.0 s
    connection limit, a hidden site's probes ended after the 2.3 s deadline,
    the verdict lost 'unreachable' and with it the floor for an unvouched
    name — a phishing host went from caution to 'safe'."""
    import socket

    from api.services import domain_validator
    from tests.conftest import PUBLIC_TEST_ADDRESS

    offline_analyzer(site="unreachable", delays={"exists": 0.25, "resolution": 0.25})

    def _slow_lookup(host, port):
        time.sleep(PROBE_LOOKUP_S)
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (PUBLIC_TEST_ADDRESS, port))]

    def _dropped(address, timeout=None, *args, **kwargs):
        time.sleep(timeout)
        raise socket.timeout("timed out from abroad")

    monkeypatch.setattr(domain_validator, "_getaddrinfo", _slow_lookup)
    monkeypatch.setattr(site_probes.socket, "create_connection", _dropped)
    monkeypatch.setattr(site_probes.httpx, "AsyncClient", _SlowUnreachableClient)

    result = asyncio.run(analyzer.analyze_domain("hidden-shop.ru"))
    assert result.verdict_basis == "unreachable"
    assert not set(result.checks_incomplete) & {"ssl", "headers", "redirect", "favicon"}
    assert result.level.value == "caution"  # nothing vouches for the name


# ── The public cache ──

def test_the_public_cache_keeps_an_answer_with_a_timed_out_source_for_an_hour(
        offline_analyzer, monkeypatch, fake_redis, phishstats_breaker):
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
    monkeypatch.setattr(analyzer, "SOURCE_TIMEOUT_S", 0.2)
    offline_analyzer(site="reachable", delays={"phishstats": 30})

    with TestClient(main.app) as client:
        body = client.get("/api/v1/public/check/obscure-shop.ru").json()
    assert body["checks_incomplete"] == ["phishstats"]
    assert "checks_incomplete" in body["reason_codes"]
    key = public_router._PUBLIC_CACHE_PREFIX + "obscure-shop.ru"
    assert fake_redis._ttls[key] == public_router._PARTIAL_CACHE_TTL_SECONDS

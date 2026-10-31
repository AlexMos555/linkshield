"""AlienVault OTX without a key: 100 lookups an hour per IP (2026-10-26).

Past that OTX answers 429 {"detail": "Over throttling limit (100/hour)"}.
check_alienvault_otx read every non-200 as {} — "no pulses" — and the breaker
saw a success, so the analyzer counted a measured check that measured
nothing. The weekly benchmark runs up to 1,400 checks an hour: whether OTX
took part in a verdict was down to where in the hour a name came. A non-2xx
answer is now a failed lookup, as for URLhaus and ThreatFox.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from api.config import get_settings
from api.services import analyzer
from api.services.circuit_breaker import CircuitState, alienvault_breaker

_THROTTLED = {"detail": "Over throttling limit (100/hour)"}


@pytest.fixture
def otx(monkeypatch):
    """Returns `answer(status, body)`: every OTX request gets that answer.
    The list it returns collects the URLs OTX was asked for. The breaker
    starts closed."""
    monkeypatch.setattr(alienvault_breaker, "_failure_count", 0)
    monkeypatch.setattr(alienvault_breaker, "_state", CircuitState.CLOSED)
    real = httpx.AsyncClient

    def answer(status: int, body: dict) -> list[str]:
        asked: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            asked.append(str(request.url))
            return httpx.Response(status, json=body)

        monkeypatch.setattr(analyzer.httpx, "AsyncClient",
                            lambda *a, **k: real(*a, transport=httpx.MockTransport(_handler), **k))
        return asked

    return answer


def _through_breaker(domain: str) -> tuple[dict, bool]:
    return asyncio.run(alienvault_breaker.call(analyzer.check_alienvault_otx, domain))


@pytest.mark.parametrize("status", [429, 403, 500, 503])
def test_a_refused_otx_lookup_is_not_a_measured_check(otx, status):
    otx(status, _THROTTLED)
    value, ok = _through_breaker("evil.example")
    assert (value, ok) == ({}, False)
    assert alienvault_breaker._failure_count == 1
    assert analyzer._measured_checks({"alienvault": (value, ok)}, site_reachable=None) == 0


def test_a_throttled_otx_opens_the_breaker_instead_of_being_asked_again(otx):
    asked = otx(429, _THROTTLED)
    for _ in range(5):
        _through_breaker("evil.example")
    # failure_threshold=3: the next two analyses skip OTX for the cooldown.
    assert len(asked) == 3
    assert alienvault_breaker.state is CircuitState.OPEN


def test_an_otx_answer_is_measured_as_before(otx):
    tags = ["phishing", "credential harvesting"]
    otx(200, {"pulse_info": {"count": 3, "pulses": [
        {"id": "a", "tags": tags, "indicator_count": 40},
        {"id": "b", "tags": tags, "indicator_count": 40},  # a copy of "a"
        {"id": "c", "tags": ["malspam"], "indicator_count": 7},
    ]}, "reputation": 0})
    value, ok = _through_breaker("evil.example")
    assert (value, ok) == ({"pulse_count": 3, "distinct_pulses": 2, "newest_report_days": None, "reputation": 0, "hit": True}, True)
    assert alienvault_breaker._failure_count == 0
    assert analyzer._measured_checks({"alienvault": (value, ok)}, site_reachable=None) == 1


def test_no_pulses_is_still_a_measured_not_listed(otx):
    otx(200, {"pulse_info": {"count": 0, "pulses": []}, "reputation": 0})
    value, ok = _through_breaker("fine.example")
    assert (value, ok) == ({"pulse_count": 0, "distinct_pulses": 0, "newest_report_days": None, "reputation": 0, "hit": False}, True)
    assert analyzer._measured_checks({"alienvault": (value, ok)}, site_reachable=None) == 1


# ── IP addresses ──
# OTX's domain endpoint answers 400 {"detail": "Invalid domain (8.8.8.8)",
# "error": "unable to parse domain or hostname"} for every IP literal
# (measured 2026-10-27). With raise_for_status each IP check was a breaker
# failure: three in a row switched OTX off for 60 s for every domain.

_INVALID_DOMAIN = {"error": "unable to parse domain or hostname"}
_REAL_OTX = analyzer.check_alienvault_otx


def _recent(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")


@pytest.fixture
def otx_like_the_real_one(monkeypatch, offline_analyzer):
    """The analyzer with the real check_alienvault_otx against an OTX that
    answers like the real one: 400 for an IP, four recent reports for a name.
    Returns the list of indicators OTX was asked about."""
    offline_analyzer(site="reachable")
    monkeypatch.setattr(analyzer, "check_alienvault_otx", _REAL_OTX)
    monkeypatch.setattr(alienvault_breaker, "_failure_count", 0)
    monkeypatch.setattr(alienvault_breaker, "_state", CircuitState.CLOSED)
    pulses = {"pulse_info": {"count": 4, "pulses": [
        {"id": f"p{i}", "tags": [f"phish-{i}"], "indicator_count": 10 + i, "created": _recent(3 + i)}
        for i in range(4)
    ]}, "reputation": 0}
    asked: list[str] = []
    real = httpx.AsyncClient

    def _handler(request: httpx.Request) -> httpx.Response:
        indicator = request.url.path.split("/")[-2]
        asked.append(indicator)
        if analyzer._is_ip_address(indicator):
            return httpx.Response(400, json={"detail": f"Invalid domain ({indicator})", **_INVALID_DOMAIN})
        return httpx.Response(200, json=pulses)

    monkeypatch.setattr(analyzer.httpx, "AsyncClient",
                        lambda *a, **k: real(*a, transport=httpx.MockTransport(_handler), **k))
    return asked


def test_ip_checks_do_not_switch_otx_off_for_the_next_domain(otx_like_the_real_one):
    for ip in ("185.199.108.153", "93.184.215.14", "104.21.3.7"):
        asyncio.run(analyzer.analyze_domain(ip))

    assert alienvault_breaker.state is CircuitState.CLOSED, alienvault_breaker.get_status()
    assert alienvault_breaker._failure_count == 0
    result = asyncio.run(analyzer.analyze_domain("phish-four-pulses.example"))
    assert any(r.signal == "alienvault_otx" for r in result.reasons), [r.signal for r in result.reasons]
    # The domain endpoint cannot answer for an IP, so OTX is not asked.
    assert otx_like_the_real_one == ["phish-four-pulses.example"]


def test_an_ip_check_is_measured_against_the_checks_that_apply(monkeypatch, offline_analyzer):
    """OTX is not asked about an IP, so it is not one of the checks the
    verdict's coverage is measured against either (as for a source switched
    off): an IP with every other check answered is a complete analysis."""
    offline_analyzer(site="reachable")
    seen: dict = {}
    real_calls, real_signals = analyzer._check_calls, analyzer._build_signals

    def _calls(domain, probes_allowed):
        plan = real_calls(domain, probes_allowed)
        seen[domain] = {"plan": set(plan)}
        return plan

    def _signals(domain, raw_url, is_ip, outcomes, total_checks=analyzer.TOTAL_CHECKS):
        seen[domain]["total"] = total_checks
        return real_signals(domain, raw_url, is_ip, outcomes, total_checks)

    monkeypatch.setattr(analyzer, "_check_calls", _calls)
    monkeypatch.setattr(analyzer, "_build_signals", _signals)
    for host in ("185.199.108.153", "fine.example"):
        asyncio.run(analyzer.analyze_domain(host))

    ip, name = seen["185.199.108.153"], seen["fine.example"]
    assert name["plan"] - ip["plan"] == {"alienvault"}
    assert name["total"] - ip["total"] == 1


# ── The account key ──
# Without a key OTX stops at 100 lookups an hour (the 429 above); the free
# account key lifts that and goes in the X-OTX-API-KEY header.

@pytest.fixture
def otx_headers(monkeypatch):
    """Every OTX request answers "no pulses"; returns the list of the
    requests' headers."""
    seen: list[httpx.Headers] = []
    real = httpx.AsyncClient

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers)
        return httpx.Response(200, json={"pulse_info": {"count": 0, "pulses": []}, "reputation": 0})

    monkeypatch.setattr(analyzer.httpx, "AsyncClient",
                        lambda *a, **k: real(*a, transport=httpx.MockTransport(_handler), **k))
    return seen


def test_the_otx_key_is_sent_when_set(otx_headers, monkeypatch):
    monkeypatch.setattr(get_settings(), "otx_api_key", "test-key-not-real", raising=False)
    asyncio.run(analyzer.check_alienvault_otx("fine.example"))
    assert otx_headers[0]["X-OTX-API-KEY"] == "test-key-not-real"


def test_no_key_header_without_a_key(otx_headers, monkeypatch):
    monkeypatch.setattr(get_settings(), "otx_api_key", "", raising=False)
    asyncio.run(analyzer.check_alienvault_otx("fine.example"))
    assert "X-OTX-API-KEY" not in otx_headers[0]

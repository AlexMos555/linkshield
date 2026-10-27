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

import httpx
import pytest

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

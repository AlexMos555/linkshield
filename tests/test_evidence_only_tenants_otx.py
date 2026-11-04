"""OTX on a Bluehost temporary address (scoring.EVIDENCE_ONLY_TENANT_ZONES)
since #404 (2026-11-04): asked as the hostname indicator it is.

Until #396 the allowlist answered 'safe 0' for every *.mybluehost.me name
without asking OTX; until #404 OTX was asked for a DOMAIN of that name and
answered 0 for every tenant. Together the two PRs make OTX's reports about a
customer's site evidence for the first time, so its rules must hold there as
they hold for any tenant: reports about the full host only (not about the
account's labels, nor the platform's), Bluehost's #11,072 waiving none of
them, more than five old ones not counting (scoring.otx_reports_are_history),
one to five old ones a weak signal, and the LLM judge not asked at all.

Keyless, 2026-11-03: /indicators/hostname/zrg.okx.mybluehost.me — the
PhishTank phish of #396 — had no pulses (OTX lists mybluehost.me as a
Majestic-whitelisted domain), so Web Risk stays what makes it 'dangerous'.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from api.models.schemas import RiskLevel
from api.services import analyzer, llm_judge
from api.services.circuit_breaker import CircuitState, alienvault_breaker

_REAL_OTX = analyzer.check_alienvault_otx
BLUEHOST_RANK = 11_072


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000000")


def _pulses(n: int, prefix: str = "p", age: int = 5) -> list[dict]:
    return [{"id": f"{prefix}{i}", "name": f"Phishing List {i}", "tags": [f"{prefix}-{i}"],
             "indicator_count": 100 + i, "created": _days_ago(age + i)} for i in range(n)]


@pytest.fixture
def otx_files(monkeypatch):
    """OTX as it answers (tests/test_otx_hostname_indicator.py): files[(type,
    indicator)] is the pulse list kept for that indicator; any other answers
    count 0. Returns (files, the (type, indicator) pairs asked)."""
    monkeypatch.setattr(alienvault_breaker, "_failure_count", 0)
    monkeypatch.setattr(alienvault_breaker, "_state", CircuitState.CLOSED)
    files: dict[tuple[str, str], list[dict]] = {}
    asked: list[tuple[str, str]] = []
    real = httpx.AsyncClient

    def _handler(request: httpx.Request) -> httpx.Response:
        kind, indicator = request.url.path.split("/")[-3:-1]
        asked.append((kind, indicator))
        pulses = files.get((kind, indicator), [])
        return httpx.Response(200, json={
            "indicator": indicator, "type": kind,
            "base_indicator": {"indicator": indicator, "type": kind} if pulses else {},
            "pulse_info": {"count": len(pulses), "pulses": pulses}, "reputation": 0,
        })

    monkeypatch.setattr(analyzer.httpx, "AsyncClient",
                        lambda *a, **k: real(*a, transport=httpx.MockTransport(_handler), **k))
    return files, asked


@pytest.fixture
def analyse(otx_files, offline_analyzer, monkeypatch):
    """run(host): analyze_domain with every source offline but OTX, the host
    unranked and its registrable domain (mybluehost.me) at Bluehost's rank.
    Answers (result, the scorer's signals)."""
    def run(host: str):
        offline_analyzer(site="reachable", values={"tranco": {
            "ranked": False, "rank": None, "weight": 0, "label": "", "registrable_rank": BLUEHOST_RANK}})
        monkeypatch.setattr(analyzer, "check_alienvault_otx", _REAL_OTX)
        seen: dict = {}
        real_calc = analyzer.calculate_score

        def _capture(signals):
            seen.update(signals)
            return real_calc(signals)

        monkeypatch.setattr(analyzer, "calculate_score", _capture)
        return asyncio.run(analyzer.analyze_domain(host, budget_s=5.0)), seen
    return run


def _weights(result) -> dict[str, int]:
    return {r.signal: r.weight for r in result.reasons if r.weight}


@pytest.mark.parametrize("host", [
    "zrg.okx.mybluehost.me",
    "alpineeagle-co-uk.lvj.wix.mybluehost.me",
    "www.website-fa76de8b.xva.vgj.mybluehost.me",   # www. of a tenant, not of mybluehost.me
])
def test_a_customers_site_is_asked_about_as_its_full_hostname(otx_files, host):
    _, asked = otx_files
    asyncio.run(analyzer.check_alienvault_otx(host))
    assert asked == [("hostname", host)]


def test_reports_about_an_account_label_or_the_platform_are_not_the_sites(otx_files, analyse):
    """esh.aws.mybluehost.me ('Avila Styles — Coming Soon'): the rank rules
    read 'aws.mybluehost.me' as the tenant's site (one account label,
    scoring._platform_tenant_site), but OTX is asked about the full host —
    what OTX files under the shorter name, or under mybluehost.me, is another
    account's or Bluehost's."""
    files, asked = otx_files
    files[("hostname", "aws.mybluehost.me")] = _pulses(8)
    files[("domain", "mybluehost.me")] = _pulses(8, prefix="apex")
    result, signals = analyse("esh.aws.mybluehost.me")
    assert asked == [("hostname", "esh.aws.mybluehost.me")]
    assert (result.level, result.score) == (RiskLevel.safe, 0)
    assert _weights(result) == {} and signals["blocklist_hits"] == 0


@pytest.mark.parametrize("reports,expected", [
    (3, (RiskLevel.caution, 30, {"alienvault_otx": 30})),
    (8, (RiskLevel.dangerous, 60, {"alienvault_otx_high": 60})),
])
def test_fresh_reports_count_in_full_whatever_bluehosts_rank(otx_files, analyse, reports, expected):
    files, _ = otx_files
    host = "fmf.dqm.mybluehost.me"
    files[("hostname", host)] = _pulses(reports)
    result, signals = analyse(host)
    assert signals["alienvault_indicator"] == "hostname"
    assert (result.level, result.score, _weights(result)) == expected
    assert signals["blocklist_hits"] == 1


def test_many_old_reports_about_a_customers_site_do_not_count(otx_files, analyse):
    """A sandbox or IOC dump that listed the address a year ago: no reason,
    no blocklist hit — the allowlist's 'safe 0', as on any tenant."""
    files, _ = otx_files
    host = "kawarthacottagevacations-ca.ryu.fke.mybluehost.me"
    files[("hostname", host)] = _pulses(22, age=423)
    result, signals = analyse(host)
    assert signals["alienvault_pulse_count"] == 22
    assert (result.level, result.score, _weights(result)) == (RiskLevel.safe, 0, {})
    assert signals["blocklist_hits"] == 0


def test_a_fresh_report_among_old_ones_makes_them_count(otx_files, analyse):
    files, _ = otx_files
    host = "kawarthacottagevacations-ca.ryu.fke.mybluehost.me"
    files[("hostname", host)] = _pulses(21, age=423) + _pulses(1, prefix="fresh", age=3)
    result, _ = analyse(host)
    assert (result.level, _weights(result)) == (RiskLevel.dangerous, {"alienvault_otx_high": 60})


def test_one_old_report_is_a_weak_caution_as_on_any_name(otx_files, analyse):
    """One to five old reports stay a weak signal for every name
    (scoring.WEAK_SIGNALS, #404): a caution, never 'dangerous' on its own."""
    files, _ = otx_files
    host = "fmf.dqm.mybluehost.me"
    files[("hostname", host)] = _pulses(1, prefix="certpl", age=400)
    result, _ = analyse(host)
    assert (result.level, result.score, _weights(result)) == (RiskLevel.caution, 30, {"alienvault_otx": 30})


def test_old_reports_do_not_turn_a_brand_caution_dangerous(otx_files, analyse):
    files, _ = otx_files
    host = "paypal-login.abc.def.mybluehost.me"
    files[("hostname", host)] = _pulses(22, age=423)
    result, _ = analyse(host)
    assert (result.level, result.score, _weights(result)) == (RiskLevel.caution, 30, {"brand_subdomain_abuse": 30})


def test_the_judge_is_not_asked_whatever_otx_says(otx_files, analyse, monkeypatch):
    asked_judge = []

    async def _opinion_now(signals, score, level):
        asked_judge.append(signals["domain"])
        return llm_judge.CACHED, {"verdict": "safe", "confidence": 0.9, "one_line_reason": "x", "score_shift": -20}

    monkeypatch.setattr(llm_judge, "opinion_now", _opinion_now)
    files, _ = otx_files
    host = "fmf.dqm.mybluehost.me"
    files[("hostname", host)] = _pulses(3)
    result, _ = analyse(host)
    assert (result.level, result.score) == (RiskLevel.caution, 30)
    assert asked_judge == [] and "llm_judge" not in result.checks_incomplete

"""LICENSED_INTEL (api/services/licensed_intel): the six non-commercial
lookups leave the analyzer's plan AND its total, or nothing changes.

Since 2026-10-21 the default is "licensed" (commercial-safe): abuse.ch's
APIs answer 401 without a personal Auth-Key — read as "not listed", a
silent miss — and their terms are not-for-profit only, as are the SURBL and
Spamhaus DBL public mirrors. "all" is an explicit opt-in.

Also the DNSBL answer codes (api/services/dnsbl_checks): an error code from
Spamhaus or SURBL is "not consulted", never "not listed" and never "listed".
"""
from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from api import config
from api.services import analyzer, dnsbl_checks, licensed_intel
from api.services.analyzer import analyze_domain
from api.services.circuit_breaker import CircuitState, spamhaus_breaker
from api.models.schemas import RiskLevel


RESTRICTED = {"surbl", "spamhaus", "urlhaus", "threatfox", "malware_bazaar", "feodo"}


@pytest.fixture
def intel(monkeypatch):
    """Set LICENSED_INTEL for one test: intel('licensed') / intel('all').
    Starts at the shipped default."""
    settings = config.get_settings()

    def _set(mode: str) -> None:
        monkeypatch.setattr(settings, "licensed_intel", mode, raising=False)

    _set(config.Settings.model_fields["licensed_intel"].default)
    return _set


def _record_plan(monkeypatch) -> dict:
    """What analyze_domain planned and measured against, captured on the way."""
    seen: dict = {}
    real_calls, real_signals = analyzer._check_calls, analyzer._build_signals

    def _calls(domain, probes_allowed):
        plan = real_calls(domain, probes_allowed)
        seen["checks"] = set(plan)
        return plan

    def _signals(domain, raw_url, is_ip, outcomes, total_checks=analyzer.TOTAL_CHECKS):
        seen["total"] = total_checks
        return real_signals(domain, raw_url, is_ip, outcomes, total_checks)

    monkeypatch.setattr(analyzer, "_check_calls", _calls)
    monkeypatch.setattr(analyzer, "_build_signals", _signals)
    return seen


# ── The setting ──────────────────────────────────────────────────────────────


def test_the_default_is_commercial_safe(intel, monkeypatch):
    monkeypatch.delenv("LICENSED_INTEL", raising=False)
    assert config.Settings().licensed_intel == "licensed"
    assert licensed_intel.skipped_checks() == RESTRICTED
    assert licensed_intel.total_checks(analyzer.TOTAL_CHECKS) == 13


def test_all_is_an_explicit_opt_in_that_consults_everything(intel):
    intel("all")
    assert licensed_intel.skipped_checks() == frozenset()
    assert licensed_intel.total_checks(analyzer.TOTAL_CHECKS) == 19


def test_the_restricted_checks_are_the_analyzers_names():
    assert licensed_intel.RESTRICTED_CHECKS == RESTRICTED
    assert RESTRICTED <= set(analyzer._check_calls("example.com", probes_allowed=True)) | RESTRICTED


def test_a_misspelt_setting_fails_at_load_time():
    with pytest.raises(ValidationError):
        config.Settings(licensed_intel="lisenced")
    assert config.Settings(licensed_intel="licensed").licensed_intel == "licensed"
    assert config.Settings(licensed_intel="all").licensed_intel == "all"


# ── The analyzer ─────────────────────────────────────────────────────────────


def test_with_all_a_surbl_listing_still_makes_a_threat_intel_verdict(intel, offline_analyzer, monkeypatch):
    intel("all")
    seen = _record_plan(monkeypatch)
    offline_analyzer(site="reachable", hits={"surbl": True, "spamhaus": True})
    result = asyncio.run(analyze_domain("p6ihks.casa", budget_s=5.0))
    assert result.level == RiskLevel.dangerous
    assert {"surbl", "spamhaus_dbl"} <= {r.signal for r in result.reasons}
    assert result.verdict_basis == "threat_intel"
    assert len(seen["checks"]) == 19 and seen["total"] == 19


def test_licensed_never_asks_the_six_and_measures_against_thirteen(intel, offline_analyzer, monkeypatch):
    intel("licensed")
    seen = _record_plan(monkeypatch)
    asked: list[str] = []
    offline_analyzer(site="reachable", hits={"surbl": True, "spamhaus": True, "threatfox": True,
                                             "urlhaus": True})
    for name in ("check_surbl", "check_spamhaus_dbl", "check_urlhaus", "check_threatfox",
                 "check_malware_bazaar", "check_feodo_tracker"):
        async def _asked(domain, _name=name):
            asked.append(_name)
            return True
        monkeypatch.setattr(analyzer, name, _asked)

    result = asyncio.run(analyze_domain("p6ihks.casa", budget_s=5.0))
    assert asked == [], "a switched-off source is not consulted at all"
    assert seen["checks"] == {
        "safe_browsing", "phishtank", "phishstats", "alienvault", "ipqs", "tranco", "favicon",
        "watchtower", "whois", "ssl", "headers", "dns", "redirect",
    }
    assert seen["total"] == 13
    assert not {"surbl", "spamhaus_dbl", "threatfox", "urlhaus"} & {r.signal for r in result.reasons}
    assert result.checks_incomplete == [], "not consulted is not incomplete"
    assert result.verdict_basis != "threat_intel"


def test_licensed_confidence_counts_thirteen_of_thirteen_not_thirteen_of_nineteen(intel, offline_analyzer):
    """The same evidence, the same answers: the switched-off sources must not
    read as six checks that did not answer."""
    intel("all")
    offline_analyzer(site="reachable", values={"whois": {"age_days": 3000}})
    full = asyncio.run(analyze_domain("obscure-shop.ru", budget_s=5.0))
    intel("licensed")
    offline_analyzer(site="reachable", values={"whois": {"age_days": 3000}})
    cut = asyncio.run(analyze_domain("obscure-shop.ru", budget_s=5.0))
    assert cut.confidence_pct == full.confidence_pct
    assert cut.confidence == full.confidence
    assert cut.score == full.score and cut.level == full.level


# ── DNSBL answer codes ───────────────────────────────────────────────────────


@pytest.mark.parametrize("answers,listed", [
    ([], False),
    (["127.0.1.2"], True),
    (["127.0.1.4"], True),
    (["127.0.1.104"], True),
    (["127.0.1.42"], False),
])
def test_spamhaus_listing_codes(answers, listed):
    assert dnsbl_checks.spamhaus_verdict(answers) is listed


@pytest.mark.parametrize("code", ["127.255.255.252", "127.255.255.254", "127.255.255.255", "127.0.1.255"])
def test_spamhaus_error_codes_are_not_a_verdict(code):
    with pytest.raises(dnsbl_checks.DnsblUnavailable):
        dnsbl_checks.spamhaus_verdict(["127.0.1.4", code])


@pytest.mark.parametrize("answers,listed", [
    ([], False),
    (["127.0.0.8"], True),      # PH
    (["127.0.0.80"], True),     # MW + ABUSE
    (["127.0.0.2"], True),
    (["not an ip"], False),
])
def test_surbl_listing_codes(answers, listed):
    assert dnsbl_checks.surbl_verdict(answers) is listed


def test_surbl_blocked_access_is_not_a_listing():
    """127.0.0.1 is 'your access is blocked' — the old startswith('127.')
    read it as a spam listing for every domain."""
    with pytest.raises(dnsbl_checks.DnsblUnavailable):
        dnsbl_checks.surbl_verdict(["127.0.0.1"])


class _Resolver:
    """dns.resolver.Resolver stand-in answering from a table."""
    table: dict = {}

    def __init__(self) -> None:
        self.timeout = self.lifetime = None

    def resolve(self, name, rtype):
        import dns.resolver as dns_resolver

        answer = self.table.get(name, "nxdomain")
        if answer == "nxdomain":
            raise dns_resolver.NXDOMAIN()
        if answer == "servfail":
            raise dns_resolver.NoNameservers()
        return [type("A", (), {"__str__": lambda self, ip=ip: ip})() for ip in answer]


@pytest.fixture
def dnsbl(monkeypatch):
    import dns.resolver as dns_resolver

    _Resolver.table = {}
    monkeypatch.setattr(dns_resolver, "Resolver", _Resolver)
    return _Resolver.table


def test_dnsbl_lookups_read_their_zones(dnsbl):
    dnsbl["evil.xyz.dbl.spamhaus.org"] = ["127.0.1.4"]
    dnsbl["evil.xyz.multi.surbl.org"] = ["127.0.0.8"]
    assert asyncio.run(dnsbl_checks.check_spamhaus_dbl("evil.xyz")) is True
    assert asyncio.run(dnsbl_checks.check_surbl("login.evil.xyz")) is True, "SURBL is asked about the base domain"
    assert asyncio.run(dnsbl_checks.check_spamhaus_dbl("fine.example")) is False


def test_a_refused_dbl_query_fails_inside_its_breaker_and_is_not_measured(dnsbl, monkeypatch):
    """The plan's case: through a public resolver the DBL answers
    127.255.255.254. That is a failure the breaker counts, so the check is
    not a measured 'not listed'."""
    dnsbl["evil.xyz.dbl.spamhaus.org"] = ["127.255.255.254"]
    monkeypatch.setattr(spamhaus_breaker, "_failure_count", 0)
    monkeypatch.setattr(spamhaus_breaker, "_state", CircuitState.CLOSED)
    value, ok = asyncio.run(spamhaus_breaker.call(dnsbl_checks.check_spamhaus_dbl, "evil.xyz"))
    assert (value, ok) == (False, False)
    assert spamhaus_breaker._failure_count == 1


def test_a_servfail_is_not_a_verdict_either(dnsbl):
    dnsbl["evil.xyz.dbl.spamhaus.org"] = "servfail"
    import dns.resolver as dns_resolver

    with pytest.raises(dns_resolver.NoNameservers):
        asyncio.run(dnsbl_checks.check_spamhaus_dbl("evil.xyz"))


# ── abuse.ch without a key (2026-10-21) ──────────────────────────────────────


class _Answer401:
    """httpx.AsyncClient stand-in: every abuse.ch API answers 401, as it
    does without a personal Auth-Key since 2026-10-21."""

    def __init__(self, *args, **kwargs) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc) -> None:
        return None

    async def post(self, url, **kwargs):
        import httpx
        return httpx.Response(401, json={"error": "Unauthorized"}, request=httpx.Request("POST", url))


@pytest.mark.parametrize("check", ["check_urlhaus", "check_threatfox", "check_malware_bazaar"])
def test_a_401_is_a_failed_lookup_never_not_listed(monkeypatch, check):
    """Read as JSON, {"error": "Unauthorized"} has no query_status — the old
    code returned False, a measured "not listed" on every check. Raising
    lets the breaker count it, and the check is not measured."""
    import httpx

    monkeypatch.setattr(analyzer.httpx, "AsyncClient", _Answer401)
    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(getattr(analyzer, check)("evil.example"))

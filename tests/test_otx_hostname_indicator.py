"""AlienVault OTX files a name under one of two indicator types (2026-11-03).

A registrable domain (example.com, example.co.uk, edgeone.dev) is a
"domain" indicator; any name below one (login.example.com, a customer's
site x.edgeone.dev, x.zapier.app) is a "hostname" indicator. Asked
/indicators/domain/<subdomain>, OTX answers that it has no such domain:
count 0 and an empty base_indicator. check_alienvault_otx asked the domain
endpoint for every name, so OTX was blind for every subdomain, every
hosting-platform tenant included. Measured 2026-11-03, keyless:

    /indicators/hostname/mailbox-dpr3yixp1qk1.edgeone.dev   5 pulses
    /indicators/domain/mailbox-dpr3yixp1qk1.edgeone.dev     0 (no such domain)
    /indicators/domain/edgeone.dev                          3 pulses

The three edgeone.dev pulses are the platform's own (one of them an article
about device-code phishing that mentions it), not its tenant's, and the
tenant's five are not the platform's: each name is looked up as what it is,
one request per check. www. in front of a registrable domain is that
domain's own site and reads the domain's reports.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from api.services import analyzer, llm_judge
from api.services.circuit_breaker import CircuitState, alienvault_breaker

_REAL_OTX = analyzer.check_alienvault_otx
_TENANT = "mailbox-dpr3yixp1qk1.edgeone.dev"


def _days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000000")


def _pulses(n: int, prefix: str = "p", age: int = 5) -> list[dict]:
    """`n` separate reports, the newest `age` days old (recent by default,
    as the phishing auto-feeds file them)."""
    return [{"id": f"{prefix}{i}", "name": f"Phishing List {i}", "tags": [f"{prefix}-{i}"],
             "indicator_count": 100 + i, "created": _days_ago(age + i)} for i in range(n)]


@pytest.fixture
def otx_files(monkeypatch):
    """OTX as it answers: `files[(type, indicator)]` is the pulse list OTX
    keeps for that indicator; one it does not keep answers count 0 with an
    empty base_indicator, as the real one does. Returns the list of
    (type, indicator) pairs OTX was asked about."""
    monkeypatch.setattr(alienvault_breaker, "_failure_count", 0)
    monkeypatch.setattr(alienvault_breaker, "_state", CircuitState.CLOSED)
    monkeypatch.setattr(analyzer, "check_alienvault_otx", _REAL_OTX)
    files: dict[tuple[str, str], list[dict]] = {}
    asked: list[tuple[str, str]] = []
    real = httpx.AsyncClient

    def _handler(request: httpx.Request) -> httpx.Response:
        # /api/v1/indicators/<type>/<indicator>/general
        kind, indicator = request.url.path.split("/")[-3:-1]
        asked.append((kind, indicator))
        pulses = files.get((kind, indicator), [])
        base = {"indicator": indicator, "type": kind} if pulses else {}
        return httpx.Response(200, json={
            "indicator": indicator, "type": kind, "base_indicator": base,
            "pulse_info": {"count": len(pulses), "pulses": pulses}, "reputation": 0,
        })

    monkeypatch.setattr(analyzer.httpx, "AsyncClient",
                        lambda *a, **k: real(*a, transport=httpx.MockTransport(_handler), **k))
    return files, asked


@pytest.mark.parametrize("host, asked", [
    # registrable domains: the domain indicator, as before
    ("edgeone.dev", ("domain", "edgeone.dev")),
    ("evil-example.com", ("domain", "evil-example.com")),
    ("example.co.uk", ("domain", "example.co.uk")),
    ("gov.spb.ru", ("domain", "gov.spb.ru")),               # the registered name under spb.ru
    ("paypal-login.ne.pw", ("domain", "paypal-login.ne.pw")),  # a 2-letter TLD's second level is a zone
    ("www.com", ("domain", "www.com")),                     # a registrable domain called www
    # www. in front of a registrable domain is that domain's site
    ("www.evil-example.com", ("domain", "evil-example.com")),
    ("www.example.co.uk", ("domain", "example.co.uk")),
    # any other name below a registrable domain: the hostname indicator
    (_TENANT, ("hostname", _TENANT)),
    ("divace-coinsquare.zapier.app", ("hostname", "divace-coinsquare.zapier.app")),
    ("tf-app.vercel.app", ("hostname", "tf-app.vercel.app")),
    ("www.tf-app.vercel.app", ("hostname", "www.tf-app.vercel.app")),   # www. of a tenant, not of vercel.app
    ("icy-lab-0431.guilherme-telecomunicacoes2024.workers.dev",
     ("hostname", "icy-lab-0431.guilherme-telecomunicacoes2024.workers.dev")),
    ("login.example.co.uk", ("hostname", "login.example.co.uk")),
    ("kvs.gov.spb.ru", ("hostname", "kvs.gov.spb.ru")),
    ("login.secureserver.net", ("hostname", "login.secureserver.net")),
    ("www.allegrolokalnie.pl-oferta-example.click", ("hostname", "www.allegrolokalnie.pl-oferta-example.click")),
])
def test_a_name_is_looked_up_as_the_indicator_otx_files_it_under(otx_files, host, asked):
    _, seen = otx_files
    asyncio.run(analyzer.check_alienvault_otx(host))
    assert seen == [asked]   # one request per check


def test_www_reads_the_registrable_domain_s_reports(otx_files, analyse):
    """Keyless, 2026-11-03: of 12 benchmark phishing www. hosts, OTX had
    reports for 11 of their registrable domains and for 3 of the www. names
    as hostnames. The www. site is the domain's own: it is judged by the
    domain's reports, as the bare name is."""
    files, asked = otx_files
    files[("domain", "evil-example.com")] = _pulses(3)
    files[("hostname", "www.evil-example.com")] = _pulses(1, prefix="h")
    result, signals = analyse("www.evil-example.com", registrable_rank=None)
    assert asked == [("domain", "evil-example.com")]
    assert signals["alienvault_pulse_count"] == 3 and signals["alienvault_indicator"] == "domain"
    assert _otx_reasons(result) == {"alienvault_otx": 30}


def test_a_tenant_reported_under_its_hostname_is_found(otx_files):
    files, _ = otx_files
    files[("hostname", _TENANT)] = _pulses(5)
    out = asyncio.run(analyzer.check_alienvault_otx(_TENANT))
    assert out["hit"] is True and out["pulse_count"] == 5 and out["distinct_pulses"] == 5
    assert out["newest_report_days"] == 5


def test_the_platform_s_own_pulses_do_not_reach_its_tenants(otx_files):
    files, _ = otx_files
    files[("domain", "edgeone.dev")] = _pulses(3, "apex")
    assert asyncio.run(analyzer.check_alienvault_otx(_TENANT))["hit"] is False


def test_a_tenant_s_pulses_do_not_reach_the_platform(otx_files):
    files, _ = otx_files
    files[("hostname", _TENANT)] = _pulses(5)
    assert asyncio.run(analyzer.check_alienvault_otx("edgeone.dev"))["hit"] is False


def test_a_registrable_domain_is_not_judged_by_a_hostname_entry_of_the_same_name(otx_files):
    """The registrable keeps the domain indicator: what OTX files under the
    hostname type for the same string is not asked for (one request)."""
    files, asked = otx_files
    files[("hostname", "evil-example.com")] = _pulses(2)
    assert asyncio.run(analyzer.check_alienvault_otx("evil-example.com"))["hit"] is False
    assert asked == [("domain", "evil-example.com")]


# ── Through the whole analysis: the popularity waiver ──

@pytest.fixture
def analyse(otx_files, offline_analyzer, monkeypatch):
    """Returns `run(host, registrable_rank)`: analyze_domain with every
    source offline but OTX (otx_files), the host unranked and its registrable
    at `registrable_rank`. Answers (result, the scorer's signals)."""
    def run(host: str, registrable_rank: int | None):
        offline_analyzer(site="reachable", values={"tranco": {
            "ranked": False, "rank": None, "weight": 0, "label": "", "registrable_rank": registrable_rank}})
        monkeypatch.setattr(analyzer, "check_alienvault_otx", _REAL_OTX)
        seen: dict = {}
        real_calc = analyzer.calculate_score

        def _capture(signals):
            seen.update(signals)
            return real_calc(signals)

        monkeypatch.setattr(analyzer, "calculate_score", _capture)
        return asyncio.run(analyzer.analyze_domain(host)), seen
    return run


def _otx_reasons(result) -> dict[str, int]:
    return {r.signal: r.weight for r in result.reasons if r.signal.startswith("alienvault")}


def test_a_tenant_s_reports_count_however_popular_its_platform_is(otx_files, analyse):
    """blogspot.com is top-10k (#24) and ranked; neither vouches for one of
    its blogs (scoring._platform_tenant_site), so four recent reports about
    the blog count in full."""
    files, asked = otx_files
    host = "rinconxboxrgh-example.blogspot.com"
    files[("hostname", host)] = _pulses(4)
    result, signals = analyse(host, registrable_rank=24)
    assert asked == [("hostname", host)]
    assert _otx_reasons(result) == {"alienvault_otx": 30}
    assert signals["blocklist_hits"] == 1


def test_reports_about_a_popular_name_s_own_host_are_still_waived(otx_files, analyse):
    """login.secureserver.net (GoDaddy's sign-in, an operator zone of a
    hosting platform) is analysed, not allowlisted, and now OTX answers for
    it — here 30 fresh reports. secureserver.net's rank and top-10k place
    waive them, as they waive reports about secureserver.net itself: no OTX
    reason, no blocklist hit."""
    files, asked = otx_files
    files[("hostname", "login.secureserver.net")] = _pulses(30)
    result, signals = analyse("login.secureserver.net", registrable_rank=4137)
    assert asked == [("hostname", "login.secureserver.net")]
    assert signals["alienvault_pulse_count"] == 30
    assert _otx_reasons(result) == {}
    assert signals["blocklist_hits"] == 0


def test_a_subdomain_s_reports_count_under_an_unranked_owner(otx_files, analyse):
    """A name under a registered domain nobody ranks: its own reports count."""
    files, _ = otx_files
    host = "ugygn.shartmag-example.bet"
    files[("hostname", host)] = _pulses(2)
    result, signals = analyse(host, registrable_rank=None)
    assert _otx_reasons(result) == {"alienvault_otx": 30}
    assert signals["blocklist_hits"] == 1


# ── Old reports about a hostname ──
# A tenant never has a rank of its own, so no popularity waiver can keep old
# sandbox and IOC-dump mentions off a popular one (2026-11-03, keyless:
# mozilla.github.io 22 distinct reports, the newest 423 days old;
# googleprojectzero.blogspot.com 27, 265 days). More than five old ones do
# not count; one to five stay a weak signal, as for any name.

def test_many_old_reports_about_a_hostname_do_not_count(otx_files, analyse):
    files, _ = otx_files
    host = "pdfjs-viewer-example.github.io"
    files[("hostname", host)] = _pulses(22, age=423)
    result, signals = analyse(host, registrable_rank=29)
    assert signals["alienvault_pulse_count"] == 22 and signals["alienvault_newest_report_days"] >= 423
    assert signals["alienvault_indicator"] == "hostname"
    assert _otx_reasons(result) == {}
    assert signals["blocklist_hits"] == 0


def test_one_fresh_report_among_old_ones_makes_a_hostname_s_reports_count(otx_files, analyse):
    files, _ = otx_files
    host = "pdfjs-viewer-example.github.io"
    files[("hostname", host)] = _pulses(21, age=423) + _pulses(1, prefix="fresh", age=3)
    result, signals = analyse(host, registrable_rank=29)
    assert _otx_reasons(result) == {"alienvault_otx_high": 60}
    assert signals["blocklist_hits"] == 1


def test_one_old_report_about_a_hostname_stays_a_weak_signal(otx_files, analyse):
    """CERT Polska's list, made 2023-10-29 and modified daily, is the only
    report about fresh allegrolokalnie.* lures: dated by when it was made."""
    files, _ = otx_files
    host = "allegrolokalnie.pl-oferta-example.lol"
    files[("hostname", host)] = _pulses(1, prefix="certpl", age=1099)
    result, signals = analyse(host, registrable_rank=None)
    assert _otx_reasons(result) == {"alienvault_otx": 30}
    otx = next(r for r in result.reasons if r.signal == "alienvault_otx")
    assert "1099 days old" in otx.detail
    assert signals["blocklist_hits"] == 1


def test_many_old_reports_about_a_registrable_domain_count_as_before(otx_files, analyse):
    files, _ = otx_files
    host = "old-reports-example.com"
    files[("domain", host)] = _pulses(8, age=423)
    result, signals = analyse(host, registrable_rank=None)
    assert signals["alienvault_indicator"] == "domain"
    assert _otx_reasons(result) == {"alienvault_otx_high": 60}


def test_the_judge_is_not_told_of_reports_the_scorer_does_not_count():
    old = {"alienvault_pulse_count": 22, "alienvault_distinct_pulses": 22, "alienvault_newest_report_days": 423}
    hostname = llm_judge._extract_judge_features({**old, "alienvault_indicator": "hostname"}, 40)
    domain = llm_judge._extract_judge_features({**old, "alienvault_indicator": "domain"}, 40)
    fresh = llm_judge._extract_judge_features(
        {**old, "alienvault_indicator": "hostname", "alienvault_newest_report_days": 3}, 40)
    assert hostname["alienvault_pulse_count"] == 0
    assert domain["alienvault_pulse_count"] == 22 and fresh["alienvault_pulse_count"] == 22
    assert "alienvault_indicator" not in hostname    # not a judge feature


# ── The boundaries of "old reports about a hostname" (review of #404) ──
# scoring.otx_reports_are_history: more than five distinct reports about a
# hostname whose newest is _OTX_STALE_DAYS (90) days old or more count
# nowhere; one to five old ones stay a weak +30. So the sixth old report
# takes the five's +30 away — a cliff on purpose (the comment in scoring
# says why).

_HOST = "pdfjs-viewer-example.github.io"


def _otx_scored(host: str, indicator: str, pulses: int, newest: int | None,
                distinct: int | None = None) -> dict[str, int]:
    """The OTX reasons calculate_score gives `host` for these OTX signals
    (the analyzer's alienvault_* keys), nothing else known about it."""
    from api.services.scoring import calculate_score
    signals = {"domain": host, "raw_url": host, "alienvault_indicator": indicator,
               "alienvault_pulse_count": pulses,
               "alienvault_distinct_pulses": pulses if distinct is None else distinct,
               "alienvault_newest_report_days": newest}
    _, _, reasons = calculate_score(signals)
    return {r.signal: r.weight for r in reasons if r.signal.startswith("alienvault")}


@pytest.mark.parametrize("pulses, newest, distinct, history, otx", [
    # 5 vs 6 old reports: five are a weak +30, six are history
    (5, 400, None, False, {"alienvault_otx": 30}),
    (6, 400, None, True, {}),
    # 89 vs 90 days: six reports, the newest made 89 days ago, are current
    (6, 89, None, False, {"alienvault_otx_high": 60}),
    (6, 90, None, True, {}),
    # many pulses, few distinct (clones): the distinct ones are what counts
    (50, 400, 3, False, {"alienvault_otx": 30}),
    (50, 400, 6, True, {}),
    # an unknown age counts as current, however many reports
    (6, None, None, False, {"alienvault_otx_high": 60}),
    (22, None, None, False, {"alienvault_otx_high": 60}),
])
def test_old_hostname_reports_at_the_boundaries(pulses, newest, distinct, history, otx):
    from api.services.scoring import otx_reports_are_history
    signals = {"alienvault_indicator": "hostname", "alienvault_pulse_count": pulses,
               "alienvault_distinct_pulses": pulses if distinct is None else distinct,
               "alienvault_newest_report_days": newest}
    assert otx_reports_are_history(signals) is history
    assert _otx_scored(_HOST, "hostname", pulses, newest, distinct) == otx


def test_five_old_hostname_reports_are_weak():
    """The five's +30 is a weak signal (calculate_score's weak_here): with
    only weak signals beside it (here 30 + 15 + 15) the verdict stops at the
    top of caution."""
    from api.services.scoring import DANGEROUS_ABOVE, calculate_score
    host = "my-bakery.netlify.app"
    signals = {"domain": host, "raw_url": host, "alienvault_indicator": "hostname",
               "alienvault_pulse_count": 5, "alienvault_distinct_pulses": 5,
               "alienvault_newest_report_days": 400, "dns_ttl": 30,
               "missing_security_headers": ["strict-transport-security", "content-security-policy",
                                            "x-frame-options", "x-content-type-options"]}
    score, level, reasons = calculate_score(signals)
    weights = {r.signal: r.weight for r in reasons}
    assert weights == {"alienvault_otx": 30, "missing_headers": 15, "low_dns_ttl": 15}
    assert (score, level.value) == (DANGEROUS_ABOVE, "caution")


@pytest.mark.parametrize("pulses, newest", [(6, 400), (6, 90), (50, 1000)])
def test_old_reports_about_a_registrable_domain_are_never_history(pulses, newest):
    """Only a hostname's old reports are dropped: a registrable domain can
    carry a rank of its own, and the popularity waiver is what keeps old
    victim references off a popular one."""
    from api.services.scoring import otx_reports_are_history
    signals = {"alienvault_indicator": "domain", "alienvault_pulse_count": pulses,
               "alienvault_distinct_pulses": pulses, "alienvault_newest_report_days": newest}
    assert otx_reports_are_history(signals) is False
    assert _otx_scored("old-reports-example.com", "domain", pulses, newest) == {"alienvault_otx_high": 60}


def _clones(originals: int, copies: int, age: int) -> list[dict]:
    """`originals` separate reports made `age` days ago and more, and `copies`
    recent clones of the first one. As OTX answers: every pulse carries
    `cloned_from`, null on an original."""
    return [{**p, "cloned_from": None} for p in _pulses(originals, prefix="orig", age=age)] + [
        {"id": f"copy{i}", "name": f"test clone {i}", "cloned_from": "orig0",
         "tags": [], "indicator_count": 100, "created": _days_ago(i % 30)} for i in range(copies)]


def test_clones_of_old_reports_are_not_more_reports(otx_files, analyse):
    """50 pulses about the host: three reports made 400+ days ago and 47
    recent clones of the first. Three old reports, a weak +30 — not history
    (that takes more than five) and not current (a clone is as old as its
    original)."""
    files, _ = otx_files
    files[("hostname", _HOST)] = _clones(3, 47, age=400)
    result, signals = analyse(_HOST, registrable_rank=29)
    assert signals["alienvault_pulse_count"] == 50 and signals["alienvault_distinct_pulses"] == 3
    assert signals["alienvault_newest_report_days"] == 400
    assert _otx_reasons(result) == {"alienvault_otx": 30}
    otx = next(r for r in result.reasons if r.signal == "alienvault_otx")
    assert "3 distinct, the rest are copies" in otx.detail and "400 days old" in otx.detail


def test_hostname_reports_of_unknown_age_count_as_current(otx_files, analyse):
    """Six reports OTX lists without a date: their age is not known, so they
    are not history (+60, a blocklist hit)."""
    files, _ = otx_files
    files[("hostname", _HOST)] = [{k: v for k, v in p.items() if k != "created"} for p in _pulses(6, age=400)]
    result, signals = analyse(_HOST, registrable_rank=29)
    assert signals["alienvault_distinct_pulses"] == 6 and signals["alienvault_newest_report_days"] is None
    assert _otx_reasons(result) == {"alienvault_otx_high": 60}
    assert signals["blocklist_hits"] == 1

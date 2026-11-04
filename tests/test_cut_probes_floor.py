"""A site whose probes all ran out of time is not 'safe' on trust (2026-11-04).

A site we could not open, whose name nothing vouches for, is caution, never
'safe' (analyzer._judge): phishing kits hide from foreign scanners, and the
ML model and the brand list both miss a fresh look-alike. That floor needed
the probes to SAY "unreachable". When the deadline cut them first — a slow
start, a shorter budget — the verdict knew nothing about the site and the
same hidden site came back 'safe': with the budget at 2.3 s the deadline cut
'unreachable' on 13 of 232 sites instead of 6, and 3-7 real sites moved from
caution to 'safe' that way (review of #407, 2026-11-04). None of the 23
phishing sites in that sample whose only signal was the closed door did, but
nothing stopped one from doing so.

So a site that no probe could see in time (the TLS, headers and redirect
probes, which decide reachability, all cut off — or skipped because the SSRF
lookup did not finish in time) gets the same floor, under the same
conditions: nothing vouches for the name and it is not an evidence-only
zone. The answer also says it is partial (`checks_incomplete`), so the public
cache keeps it an hour.
"""
from __future__ import annotations

import asyncio

from api.services import analyzer
from api.services import verdict_basis as vb

_REACHABILITY = {"check_ssl": 30, "check_security_headers": 30, "check_redirect_chain": 30}


def test_the_case_is_safe_when_its_site_is_seen(offline_analyzer):
    offline_analyzer(site="reachable")
    result = asyncio.run(analyzer.analyze_domain("obscure-shop.ru", budget_s=0.6))
    assert result.level.value == "safe" and result.checks_incomplete == []


def test_a_site_no_probe_saw_in_time_is_caution_when_nothing_vouches_for_it(offline_analyzer):
    offline_analyzer(site="reachable", delays={**_REACHABILITY, "favicon": 30})
    result = asyncio.run(analyzer.analyze_domain("obscure-shop.ru", budget_s=0.6))
    assert {"ssl", "headers", "redirect"} <= set(result.checks_incomplete)
    assert result.level.value == "caution"
    assert result.score >= vb.CANNOT_VOUCH_SCORE


def test_so_is_one_whose_ssrf_lookup_did_not_finish(offline_analyzer, monkeypatch):
    """No probe may connect then (we would not know where to): the site is
    as unseen as when the deadline cut every probe."""
    monkeypatch.setattr(analyzer, "RESOLUTION_TIMEOUT_S", 0.1)
    offline_analyzer(site="reachable", delays={"resolution": 5})
    result = asyncio.run(analyzer.analyze_domain("obscure-shop.ru", budget_s=0.8))
    assert {"ssl", "headers", "redirect", "favicon"} <= set(result.checks_incomplete)
    assert result.level.value == "caution"


def test_a_name_in_the_top_list_keeps_its_verdict(offline_analyzer):
    """The same exemption as for an unreachable site: the name is vouched for."""
    offline_analyzer(site="reachable", delays=_REACHABILITY, values={
        "tranco": {"ranked": True, "rank": 40_000, "weight": -15, "label": "top 50K"},
    })
    result = asyncio.run(analyzer.analyze_domain("obscure-shop.ru", budget_s=0.6))
    assert {"ssl", "headers", "redirect"} <= set(result.checks_incomplete)
    assert result.level.value == "safe"


def test_one_probe_that_saw_the_site_is_enough(offline_analyzer):
    """The TLS probe reached it: the site is known reachable, nothing to floor."""
    offline_analyzer(site="reachable", delays={"check_security_headers": 30, "check_redirect_chain": 30})
    result = asyncio.run(analyzer.analyze_domain("obscure-shop.ru", budget_s=0.6))
    assert {"headers", "redirect"} <= set(result.checks_incomplete)
    assert "ssl" not in result.checks_incomplete
    assert result.level.value == "safe"

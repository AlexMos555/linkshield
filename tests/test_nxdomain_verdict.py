"""A domain that does not exist gets an honest answer (report 2026-09-25 #18).

A typo — sbertank.ru — came back "Dangerous, 53: site without encryption, no
mail server", with "Cloudflare blocked it" beside it. Nothing about that was
true: the name simply is not registered, so every connection failed and
every resolver said NXDOMAIN. The same mistake inflated the published
comparison: 8 of the 13 Cloudflare "hits" in the June benchmark were domains
that no longer existed.

Now: `exists: false`, one reason `domain_not_found`, level 'caution' — not
'dangerous' (it can hurt no one today), not 'safe' (a misspelt bank name is
exactly what gets registered next; see verdict_basis.NOT_FOUND_SCORE) — and
the competitor comparison reports NXDOMAIN-everywhere as 'not_found'.
"""
from __future__ import annotations

import asyncio
import importlib
import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import dns.resolver
import pytest

from api.main import app  # noqa: F401 — imported before any asyncio.run()
from api.models.schemas import RiskLevel
from api.routers import public as public_router
from api.services import competitor_verdicts as cv
from api.services import dns_checks
from api.services.analyzer import analyze_domain


# ── The existence check: False only on a real NXDOMAIN ──

def _resolver_raising(exc):
    resolver = MagicMock()
    resolver.resolve.side_effect = exc
    return resolver


@pytest.mark.parametrize("exc, expected", [
    (dns.resolver.NXDOMAIN(), False),
    (dns.resolver.NoAnswer(), True),          # exists, just no IPv4
    (dns.resolver.LifetimeTimeout(), None),   # could not tell
    (dns.resolver.NoNameservers(), None),     # SERVFAIL: could not tell
])
def test_existence_is_false_only_on_nxdomain(exc, expected):
    with patch.object(dns_checks, "_resolver", return_value=_resolver_raising(exc)):
        assert asyncio.run(dns_checks.check_domain_exists("sbertank.ru")) is expected


def test_existence_true_when_it_resolves():
    resolver = MagicMock()
    resolver.resolve.return_value = ["1.2.3.4"]
    with patch.object(dns_checks, "_resolver", return_value=resolver):
        assert asyncio.run(dns_checks.check_domain_exists("sberbank.ru")) is True


# ── The analyzer: stops, and says so ──

def test_nonexistent_domain_is_not_dangerous_and_invents_nothing(offline_analyzer):
    offline_analyzer(exists=False)
    result = asyncio.run(analyze_domain("sbertank.ru", budget_s=5.0))

    assert result.exists is False
    assert result.level == RiskLevel.caution
    assert result.verdict_basis == "not_found"
    assert [r.signal for r in result.reasons] == ["domain_not_found"]
    assert result.reasons[0].weight == 0


def test_unknown_existence_runs_the_analysis(offline_analyzer):
    """A resolver that did not answer is not proof of absence."""
    offline_analyzer(exists=None, site="reachable")
    result = asyncio.run(analyze_domain("sberbank-partner.ru", budget_s=5.0))
    assert result.exists is None
    assert result.verdict_basis != "not_found"


# ── The public response ──

def test_public_response_for_nonexistent_domain(monkeypatch, offline_analyzer, fake_redis):
    from fastapi.testclient import TestClient

    offline_analyzer(exists=False)

    async def _noop(*a, **k):
        return None

    async def _not_listed(d):
        return False

    monkeypatch.setattr(public_router, "_enforce_fresh_check_budget", _noop)
    monkeypatch.setattr(public_router, "is_listed", _not_listed)
    body = TestClient(app).get("/api/v1/public/check/sbertank.ru").json()

    assert body["exists"] is False
    assert body["level"] == "caution" and body["safe"] is False
    assert body["verdict_basis"] == "not_found"
    assert body["reason_codes"] == ["domain_not_found"]
    assert "does not exist" in body["verdict"]
    assert not {"no_https", "no_mx_record", "missing_headers"} & set(body["reason_codes"])


def test_not_found_is_cached_briefly():
    """It can be registered at any moment — never kept for a day."""
    from api.services.verdict_basis import not_found_result
    assert public_router._public_cache_ttl(not_found_result("sbertank.ru")) <= 15 * 60


# ── The competitor comparison ──

def _doh_response(status, answers=()):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"Status": status, "Answer": list(answers)}
    return resp


def _client_answering(*responses):
    client = MagicMock()
    client.get = AsyncMock(side_effect=list(responses))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


def _families(domain_exists=None, *responses):
    with patch.object(cv.httpx, "AsyncClient", return_value=_client_answering(*responses)):
        return asyncio.run(cv.check_cloudflare_families("sbertank.ru", domain_exists))


def test_nxdomain_everywhere_is_not_a_cloudflare_block():
    out = _families(None, _doh_response(3), _doh_response(3))
    assert (out.verdict, out.detail) == ("not_found", "nxdomain")


def test_nxdomain_only_on_families_is_a_block():
    out = _families(None, _doh_response(3), _doh_response(0, [{"type": 1, "data": "1.2.3.4"}]))
    assert (out.verdict, out.detail) == ("dangerous", "blocked")


def test_our_own_existence_answer_skips_the_control_query():
    assert _families(False, _doh_response(3)).verdict == "not_found"
    assert _families(True, _doh_response(3)).verdict == "dangerous"


def test_sinkhole_is_still_a_block():
    out = _families(None, _doh_response(0, [{"type": 1, "data": "0.0.0.0"}]))
    assert (out.verdict, out.detail) == ("dangerous", "blocked")


def test_unverifiable_nxdomain_is_unknown():
    failed = MagicMock()
    failed.status_code = 503
    out = _families(None, _doh_response(3), failed)
    assert out.verdict == "unknown"


# ── The published benchmark ──

def _eval_module():
    scripts = Path(__file__).resolve().parent.parent / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    return importlib.import_module("eval_fresh_urls")


def test_benchmark_does_not_count_a_dead_domain_as_a_cloudflare_catch():
    ev = _eval_module()
    client = _client_answering(_doh_response(3), _doh_response(3))
    verdict = asyncio.run(ev.check_cloudflare_families(client, "http://dead-phish.top/login"))
    assert verdict.verdict == "unknown" and verdict.detail == "nxdomain"
    assert ev.classify([verdict], "dangerous")["tp"] == 0


def test_benchmark_still_counts_a_real_cloudflare_block():
    ev = _eval_module()
    client = _client_answering(_doh_response(3), _doh_response(0, [{"type": 1, "data": "5.6.7.8"}]))
    verdict = asyncio.run(ev.check_cloudflare_families(client, "http://live-phish.top/login"))
    assert verdict.verdict == "dangerous"


def test_benchmark_reads_cleanway_not_found_as_unknown():
    ev = _eval_module()
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"level": "caution", "score": 25, "exists": False}
    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    verdict = asyncio.run(ev.check_cleanway(client, "http://sbertank.ru/"))
    assert (verdict.verdict, verdict.detail) == ("unknown", "not_found")

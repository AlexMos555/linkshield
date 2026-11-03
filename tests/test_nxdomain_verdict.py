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
from api.services.verdict_basis import not_found_result


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
        return None

    monkeypatch.setattr(public_router, "_enforce_fresh_check_budget", _noop)
    monkeypatch.setattr(public_router, "listed_as", _not_listed)
    body = TestClient(app).get("/api/v1/public/check/sbertank.ru").json()

    assert body["exists"] is False
    assert body["level"] == "caution" and body["safe"] is False
    assert body["verdict_basis"] == "not_found"
    assert body["reason_codes"] == ["domain_not_found"]
    assert "does not work right now" in body["verdict"]
    assert not {"no_https", "no_mx_record", "missing_headers"} & set(body["reason_codes"])


@pytest.mark.parametrize("text", [
    lambda: not_found_result("sberbank-online.ru").reasons[0].detail,
    lambda: public_router._verdict_text(not_found_result("sberbank-online.ru")),
])
def test_not_found_never_claims_the_name_is_unregistered(text):
    """NXDOMAIN only says the name is not in DNS. sberbank-online.ru has been
    REGISTERED since 2019 and is merely not delegated — the shape of a phishing
    domain after a takedown. "Not registered" would be false; "does not work
    right now" is true either way."""
    words = text().lower()
    assert "registered" not in words and "does not exist" not in words
    assert "does not work right now" in words


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


def test_benchmark_does_not_count_an_unverified_nxdomain_as_a_block():
    """The control query answered SERVFAIL. That says nothing about the name,
    and it counted as Cloudflare's block: any answer but NXDOMAIN did."""
    ev = _eval_module()
    client = _client_answering(_doh_response(3), _doh_response(2))
    verdict = asyncio.run(ev.check_cloudflare_families(client, "http://maybe-dead.top/login"))
    assert (verdict.verdict, verdict.detail) == ("unknown", "nxdomain_unverified")


def test_benchmark_families_says_what_it_learned_about_existence():
    """Its answer is one of the row's existence witnesses
    (benchmark_method.row_existence)."""
    ev = _eval_module()

    def families(*responses):
        return asyncio.run(ev.check_cloudflare_families(_client_answering(*responses), "http://x.top/"))

    assert families(_doh_response(3), _doh_response(3)).exists is False
    assert families(_doh_response(3), _doh_response(0, [{"type": 1, "data": "5.6.7.8"}])).exists is True
    assert families(_doh_response(0, [{"type": 1, "data": "5.6.7.8"}])).exists is True
    # Families sinkholes a name it lists whether or not the name exists.
    assert families(_doh_response(0, [{"type": 1, "data": "0.0.0.0"}])).exists is None


def _failed_doh():
    resp = MagicMock()
    resp.status_code = 503
    return resp


@pytest.mark.parametrize("response, exists, detail", [
    (_doh_response(3), False, "nxdomain"),
    (_doh_response(0, [{"type": 1, "data": "1.2.3.4"}]), True, "noerror"),
    (_doh_response(0), True, "noerror"),          # the name exists, it has no A record
    (_doh_response(2), None, "status=2"),         # SERVFAIL: could not tell
    (_failed_doh(), None, "http=503"),
], ids=["nxdomain", "resolves", "no-a-record", "servfail", "http-error"])
def test_benchmark_existence_probe(response, exists, detail):
    """One question per URL to Cloudflare's unfiltered resolver, whatever the
    resolvers answered: the benchmark's own witness."""
    ev = _eval_module()
    out = asyncio.run(ev.probe_existence(_client_answering(response), "http://phish.top/login"))
    assert (out.exists, out.detail) == (exists, detail)


def test_benchmark_existence_probe_asks_nothing_for_an_ip_address():
    ev = _eval_module()
    client = _client_answering()
    out = asyncio.run(ev.probe_existence(client, "http://221.14.192.60/login"))
    assert (out.exists, out.detail) == (True, "ip_literal")
    client.get.assert_not_awaited()


def _probe(*responses):
    ev = _eval_module()
    client = _client_answering(*responses)
    return asyncio.run(ev.probe_existence(client, "http://phish.top/login")), client


def _row(out):
    return _eval_module().benchmark_method.row_existence(out.exists, [], addresses=out.addresses)


def test_benchmark_existence_probe_records_the_addresses():
    """A row was live on any NOERROR. The probe now keeps the A data (raw.existence),
    and asks AAAA too when every A address is non-public, so a name that
    leads nowhere a user can reach is told apart (benchmark_method.only_non_public)."""
    out, client = _probe(_doh_response(0, [{"type": 5, "data": "edge.cdn.example."},
                                           {"type": 1, "data": "1.2.3.4"}]))
    assert (out.exists, out.detail, out.addresses) == (True, "noerror", ["1.2.3.4"])
    assert client.get.await_count == 1          # a public address: no second question
    assert _row(out) == "resolves"

    out, client = _probe(_doh_response(0))     # NOERROR without an A record: live, as before
    assert (out.exists, out.addresses) == (True, [])
    assert client.get.await_count == 1 and _row(out) == "resolves"

    out, _ = _probe(_doh_response(3))
    assert (out.exists, out.addresses) == (False, None)


def test_benchmark_existence_probe_tells_a_takedown_from_a_live_name():
    # etransfer-accept.ddns.net on 2026-11-03: A 0.0.0.0, no AAAA.
    out, client = _probe(_doh_response(0, [{"type": 1, "data": "0.0.0.0"}]), _doh_response(0))
    assert (out.exists, out.detail, out.addresses) == (True, "noerror", ["0.0.0.0"])
    assert [c.kwargs["params"] for c in client.get.await_args_list] == [
        {"name": "phish.top", "type": "A"}, {"name": "phish.top", "type": "AAAA"}]
    assert _row(out) == "non_public"

    # A private A record, but a public AAAA one: reachable over IPv6.
    out, _ = _probe(_doh_response(0, [{"type": 1, "data": "10.0.0.7"}]),
                    _doh_response(0, [{"type": 28, "data": "2606:4700::1"}]))
    assert out.addresses == ["10.0.0.7", "2606:4700::1"] and _row(out) == "resolves"

    out, _ = _probe(_doh_response(0, [{"type": 1, "data": "127.0.0.1"}]),
                    _doh_response(0, [{"type": 28, "data": "::1"}]))
    assert out.addresses == ["127.0.0.1", "::1"] and _row(out) == "non_public"


def test_benchmark_existence_probe_cannot_tell_when_the_aaaa_question_fails():
    """Then the resolvers' answers decide, as for any question the probe could not settle."""
    out, _ = _probe(_doh_response(0, [{"type": 1, "data": "0.0.0.0"}]), _failed_doh())
    assert out.exists is None and out.addresses == ["0.0.0.0"]
    assert out.detail == "noerror aaaa=http=503"
    out, _ = _probe(_doh_response(0, [{"type": 1, "data": "0.0.0.0"}]), _doh_response(2))
    assert out.exists is None and out.detail == "noerror aaaa=status=2"


def test_benchmark_existence_probe_records_an_ip_address_as_its_own_address():
    ev = _eval_module()
    out = asyncio.run(ev.probe_existence(_client_answering(), "http://221.14.192.60/login"))
    assert out.addresses == ["221.14.192.60"] and _row(out) == "resolves"
    out = asyncio.run(ev.probe_existence(_client_answering(), "http://192.168.1.1/login"))
    assert (out.exists, out.addresses) == (True, ["192.168.1.1"]) and _row(out) == "non_public"


def test_benchmark_counts_a_dead_name_for_no_one_even_from_the_blocklist():
    """Cleanway's blocklist answers before any existence check (public_check
    step 3) and Families sinkholes a listed name that no longer exists."""
    ev = _eval_module()
    listed = ev.Verdict("cleanway", "dangerous", level="dangerous", verdict_basis="blocklist")
    sinkhole = ev.Verdict("cloudflare_families", "dangerous", detail="status=0 ip_block=True")
    for verdict in (listed, sinkhole):
        dead = ev.classify([verdict], "dangerous", existence=["nxdomain"])
        assert (dead["tp"], dead["not_found"], dead["unknown"]) == (0, 1, 1), verdict.name
        assert ev.classify([verdict], "dangerous", existence=["resolves"])["tp"] == 1, verdict.name

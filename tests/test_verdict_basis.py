"""Every check response says what its verdict rests on (`verdict_basis`).

The phone blocks a tapped link's site after a 'dangerous' answer, and that
block outlives the moment. So the phone must be able to tell a verdict
backed by a listing (block) from one inferred by heuristics (warn only) —
bankspb.ru was 'dangerous' on heuristics alone (report 2026-09-25 #1).
Only 'blocklist' and 'threat_intel' are blocking evidence; old fields stay.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from api.main import app  # imported before any asyncio.run(): see watchtower._throttle_lock
from api.models.schemas import DomainReason, DomainResult, RiskLevel
from api.routers import public as public_router
from api.services import verdict_basis as vb
from api.services.analyzer import analyze_domain

OLD_PUBLIC_FIELDS = {
    "domain", "safe", "score", "level", "confidence", "confidence_pct", "verdict",
    "signals", "reason_codes", "checked_at", "competitors", "cta", "install_url",
    "transparency_url",
}


def _result(level, *signals, **kw):
    return DomainResult(
        domain="example.ru", score={"safe": 0, "caution": 35, "dangerous": 80}[level],
        level=RiskLevel(level),
        reasons=[DomainReason(signal=s, detail=s, weight=10) for s in signals], **kw,
    )


# ── derive_verdict_basis ──

@pytest.mark.parametrize("result, expected", [
    (_result("dangerous", "cleanway_blocklist"), "blocklist"),
    (_result("dangerous", "urlhaus", "no_mx_record"), "threat_intel"),
    (_result("dangerous", "safe_browsing"), "threat_intel"),
    (_result("caution", "domain_not_found", exists=False), "not_found"),
    (_result("safe", "known_legitimate"), "allowlist"),
    (_result("safe", "user_whitelist"), "allowlist"),
    (_result("safe", "unreachable_from_scanner"), "unreachable"),
    (_result("dangerous", "ml_high_risk", "risky_tld_high"), "ml_and_heuristics"),
    (_result("caution", "llm_judge"), "ml_and_heuristics"),
    (_result("dangerous", "no_https", "missing_headers"), "heuristics"),
])
def test_basis_from_reasons(result, expected):
    assert vb.derive_verdict_basis(result) == expected


def test_otx_mention_is_not_threat_intel():
    """An AlienVault pulse that MENTIONS a domain is usually a victim
    reference — it put a national newspaper at 'dangerous'. Never a block."""
    assert vb.derive_verdict_basis(_result("dangerous", "alienvault_otx_high")) == "heuristics"


def test_threat_intel_needs_a_dangerous_verdict():
    # A single listing outweighed by other evidence is not blocking evidence.
    assert vb.derive_verdict_basis(_result("caution", "surbl")) == "heuristics"


def test_neutral_ml_opinion_still_counts_as_ml():
    assert vb.derive_verdict_basis(_result("safe"), ml_consulted=True) == "ml_and_heuristics"
    assert vb.derive_verdict_basis(_result("safe")) == "heuristics"


def test_only_listings_are_blocking_evidence():
    assert vb.BLOCKING_BASES == {"blocklist", "threat_intel"}
    assert vb.BLOCKING_BASES <= vb.ALL_BASES


def test_basis_of_prefers_stored_value():
    stored = _result("dangerous", "no_https", verdict_basis="threat_intel")
    assert vb.basis_of(stored) == "threat_intel"
    assert vb.basis_of(_result("dangerous", "no_https")) == "heuristics"


# ── The analyzer sets it ──

def test_analyzer_heuristic_dangerous_is_not_blocking(offline_analyzer):
    """A made-up phishing-shaped name with no listing: whatever the score,
    the basis must not let the phone block it."""
    offline_analyzer(site="reachable", values={"whois": {"age_days": 2}})
    result = asyncio.run(analyze_domain("sberbank-login-verify.xyz", budget_s=5.0))
    assert result.level == RiskLevel.dangerous
    assert result.verdict_basis in {"heuristics", "ml_and_heuristics"}
    assert result.verdict_basis not in vb.BLOCKING_BASES


def test_analyzer_listing_is_threat_intel(offline_analyzer):
    offline_analyzer(site="reachable", hits={"spamhaus": True, "urlhaus": True})
    result = asyncio.run(analyze_domain("p6ihks.casa", budget_s=5.0))
    assert result.verdict_basis == "threat_intel"


# ── The public response carries it, and keeps every old field ──

def _public(monkeypatch, domain, result=None, listed=False):
    async def _no_cache(d):
        return None

    async def _noop(*a, **k):
        return None

    async def _listed(d):
        return listed

    async def _analyze(d, *a, **kw):
        return result

    from api.services import analyzer as analyzer_mod
    monkeypatch.setattr(public_router, "_get_public_cache", _no_cache)
    monkeypatch.setattr(public_router, "_put_public_cache", _noop)
    monkeypatch.setattr(public_router, "_enforce_fresh_check_budget", _noop)
    monkeypatch.setattr(public_router, "is_listed", _listed)
    monkeypatch.setattr(analyzer_mod, "analyze_domain", _analyze)
    return TestClient(app).get(f"/api/v1/public/check/{domain}")


def test_public_response_has_basis_and_old_fields(monkeypatch, fake_redis):
    analyzed = _result("dangerous", "no_https", "missing_headers")
    analyzed = analyzed.model_copy(update={"domain": "obscure-shop.ru", "verdict_basis": "heuristics"})
    resp = _public(monkeypatch, "obscure-shop.ru", analyzed)
    body = resp.json()
    assert resp.status_code == 200
    assert OLD_PUBLIC_FIELDS <= body.keys()
    assert body["level"] == "dangerous"
    assert body["verdict_basis"] == "heuristics"
    assert body["exists"] is None
    assert body["checks_incomplete"] == []


def test_public_allowlist_basis(monkeypatch, fake_redis):
    body = _public(monkeypatch, "google.com").json()
    assert body["level"] == "safe"
    assert body["verdict_basis"] == "allowlist"


def test_cached_result_without_basis_gets_one(monkeypatch):
    """Results cached before the field existed still answer with a basis."""
    legacy = _result("dangerous", "urlhaus").model_dump()
    legacy.pop("verdict_basis")
    formatted = public_router._format_public_result(DomainResult(**legacy))
    assert formatted["verdict_basis"] == "threat_intel"

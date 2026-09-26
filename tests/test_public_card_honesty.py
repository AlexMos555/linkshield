"""What the public check SAYS about a verdict (review 2026-09-27).

  * "kaluga-gov.ru appears to be safe" for a site no connection ever reached,
    and under it, as the only "why": "the name looks randomly generated" — a
    risk signal on a safe card, because the informational reason was not
    counted when choosing which direction's reasons to show.
  * Android 1.0.1 (on phones today) shows the English detail of every code
    it does not know — and it knows none of the new ones, including the one
    reason on every red card for a listed host.
  * Every response still advertised "16 independent threat-intel sources"
    (a number /stats now calls unverifiable) and a Chrome listing that is
    not live.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.models.schemas import DomainReason, DomainResult, RiskLevel
from api.routers import public as public_router
from api.services import public_stats
from api.services import verdict_basis as vb

MODERN_APP = {"X-Cleanway-Install": "3f2b8c1e-7d4a-4b6e-9a0c-5e1f2d3c4b5a"}


def _reason(signal, weight=0):
    return DomainReason(signal=signal, detail=f"{signal} detail", weight=weight)


def _unreachable(level, score, *reasons):
    return DomainResult(
        domain="kaluga-gov.ru", score=score, level=level,
        reasons=list(reasons) + [vb.unreachable_reason("timeout")],
        verdict_basis=vb.BASIS_UNREACHABLE,
    )


# ── Which reasons a card shows ──

def test_safe_card_never_lists_a_risk_signal_as_its_reason():
    result = _unreachable(RiskLevel.safe, 10, _reason("unnatural_ngram", 5))
    body = public_router._format_public_result(result)
    assert body["reason_codes"] == ["unreachable_from_scanner"]


def test_card_without_informational_reasons_still_falls_back():
    """A verdict carried by odd weights alone still shows SOMETHING."""
    result = DomainResult(domain="x.ru", score=60, level=RiskLevel.dangerous,
                          reasons=[_reason("tranco_popularity", -10)])
    assert public_router._format_public_result(result)["reason_codes"] == ["tranco_popularity"]


def test_matching_reasons_come_first_then_informational():
    result = _unreachable(RiskLevel.caution, 25, _reason("unnatural_ngram", 5))
    assert public_router._format_public_result(result)["reason_codes"] == [
        "unnatural_ngram", "unreachable_from_scanner",
    ]


# ── The headline sentence ──

def test_unreachable_safe_verdict_does_not_claim_a_check_that_never_happened():
    text = public_router._format_public_result(_unreachable(RiskLevel.safe, 5))["verdict"]
    assert "appears to be safe" not in text
    assert "could not open kaluga-gov.ru" in text


def test_unreachable_caution_verdict_says_we_cannot_vouch():
    text = public_router._format_public_result(_unreachable(RiskLevel.caution, 25))["verdict"]
    assert "cannot vouch" in text and "suspicious characteristics" not in text


def test_reachable_verdicts_keep_their_text():
    ok = DomainResult(domain="shop.ru", score=5, level=RiskLevel.safe, reasons=[],
                      verdict_basis=vb.BASIS_HEURISTICS)
    assert public_router._format_public_result(ok)["verdict"] == "shop.ru appears to be safe."


# ── Android 1.0.1: codes it can translate ──

def test_installed_app_is_not_given_english_paragraphs_it_cannot_translate():
    """Without X-Cleanway-Install (1.0.1, the website), informational reasons
    appear only when nothing else explains the verdict."""
    result = _unreachable(RiskLevel.safe, 0, _reason("tranco_popularity", -10))
    legacy = public_router._format_public_result(result, modern_client=False)
    modern = public_router._format_public_result(result, modern_client=True)
    assert legacy["reason_codes"] == ["tranco_popularity"]
    assert modern["reason_codes"] == ["tranco_popularity", "unreachable_from_scanner"]


def test_installed_app_still_gets_an_explanation_when_it_is_the_only_one():
    body = public_router._format_public_result(vb.not_found_result("sbertank.ru"), modern_client=False)
    assert body["reason_codes"] == ["domain_not_found"]


def test_blocklist_reason_uses_a_code_the_installed_app_translates():
    legacy = public_router._format_public_result(vb.blocklist_result("gosuslugee.ru"), modern_client=False)
    modern = public_router._format_public_result(vb.blocklist_result("gosuslugee.ru"), modern_client=True)
    assert legacy["reason_codes"] == ["multi_blocklist"]
    assert modern["reason_codes"] == ["cleanway_blocklist"]
    assert legacy["verdict_basis"] == modern["verdict_basis"] == "blocklist"


def test_the_route_tells_the_two_apart(monkeypatch, fake_redis):
    from api.services import analyzer

    async def _none(*a, **k):
        return None

    async def _analyze(domain, *a, **k):
        return _unreachable(RiskLevel.safe, 0, _reason("tranco_popularity", -10)).model_copy(
            update={"domain": domain})

    monkeypatch.setattr(public_router, "listed_as", _none)
    monkeypatch.setattr(public_router, "_enforce_fresh_check_budget", _none)
    monkeypatch.setattr(analyzer, "analyze_domain", _analyze)
    client = TestClient(app)
    legacy = client.get("/api/v1/public/check/obscure-bank.ru").json()
    fake_redis._kv.clear()
    modern = client.get("/api/v1/public/check/obscure-bank.ru", headers=MODERN_APP).json()
    assert "unreachable_from_scanner" not in legacy["reason_codes"]
    assert "unreachable_from_scanner" in modern["reason_codes"]


# ── What every response advertises ──

def test_response_makes_no_unverifiable_claim_and_links_a_live_install():
    body = public_router._format_public_result(vb.allowlist_result("google.com"))
    assert "16" not in body["cta"] and "sources" not in body["cta"]
    assert body["install_url"] == "https://cleanway.ai/android"


# ── /stats notes follow the measured values ──

def _report(fp, tn, fpr, n_safe):
    return {"n_safe": n_safe, "safe": {"cleanway": {"fp": fp, "tn": tn, "fpr": fpr}}}


def test_false_positive_note_says_unmeasured_only_while_it_is():
    unmeasured = public_stats.notes_for(_report(0, 0, None, 50))
    measured = public_stats.notes_for(_report(1, 99, 0.01, 120))
    assert "not been measured" in unmeasured["false_positive_rate"]
    assert "not been measured" not in measured["false_positive_rate"]
    assert public_stats.measured_false_positive_rate(_report(1, 99, 0.01, 120)) == 0.01


@pytest.mark.parametrize("key", ["detection_rate", "false_positive_rate"])
def test_notes_are_a_copy(key):
    before = public_stats.NOTES[key]
    public_stats.notes_for({})
    assert public_stats.NOTES[key] == before

"""After the LLM judge's shift, the level comes from the scorer's own lines.

The scorer calls a score up to 20 'safe' and above 50 'dangerous'
(scoring.SAFE_AT_MOST, scoring.DANGEROUS_ABOVE). The analyzer re-mapped a
judge-shifted score with lines of its own, 30 and 70 — the caution band from
before the scorer moved — so a judge's "safe" took any caution score of 30-49
down to 29 and showed it 'safe'. On the 2026-11-01 benchmark two phishing
hosts ended exactly so: divace-coinsquare.zapier.app and
4ff9b103.jiebanyou.net, 'safe' at 29.

With the scorer's lines the judge, whose "safe" aims at 29, can no longer
clear a caution to 'safe'; its "dangerous" (+20 at most) makes a caution of
31-50 'dangerous', as a model's opinion may (scoring.WEAK_SIGNALS).
"""
from __future__ import annotations

import asyncio
import logging

import pytest

from api.models.schemas import DomainReason, DomainResult, RiskLevel
from api.services import analyzer, llm_judge, scoring
from api.services.analysis_budget import Deadline
from api.services.cache import is_retired
from api.services.scoring import DANGEROUS_ABOVE, SAFE_AT_MOST, level_for_score

CAUTION_SCORES = range(SAFE_AT_MOST + 1, DANGEROUS_ABOVE + 1)


def _cached_opinion(monkeypatch, verdict: str = "safe", shift=None):
    """The judge's cached opinion for every pattern; `shift` None = what the
    judge itself makes of `verdict` at that score."""
    async def _now(signals, score, level):
        return llm_judge.CACHED, {
            "verdict": verdict, "confidence": 0.9, "one_line_reason": "stub opinion",
            "score_shift": llm_judge._shift_for_verdict(verdict, score) if shift is None else shift,
            "source": "cache",
        }
    monkeypatch.setattr(llm_judge, "opinion_now", _now)


def _judged(score: int) -> tuple[int, RiskLevel]:
    new_score, level, _, finished = asyncio.run(
        analyzer._llm_judge_within({"blocklist_hits": 0}, score, RiskLevel.caution, Deadline(1.0)))
    assert finished
    return new_score, level


# ── The scorer's lines ──

def test_level_for_score_is_the_scorers_mapping():
    assert level_for_score(0) == RiskLevel.safe
    assert level_for_score(SAFE_AT_MOST) == RiskLevel.safe
    assert level_for_score(SAFE_AT_MOST + 1) == RiskLevel.caution
    assert level_for_score(DANGEROUS_ABOVE) == RiskLevel.caution
    assert level_for_score(DANGEROUS_ABOVE + 1) == RiskLevel.dangerous
    assert level_for_score(100) == RiskLevel.dangerous


@pytest.mark.parametrize("domain", ["sberbank-bonus.ru", "paypa1-login.top", "obscure-shop.ru", "gosuslugi-lk.ru"])
def test_calculate_score_uses_the_same_mapping(domain):
    score, level, _ = scoring.calculate_score({"domain": domain, "raw_url": domain})
    assert level == level_for_score(score)


# ── The judge's shift, mapped ──

@pytest.mark.parametrize("score, shift, expected", [
    (49, -20, RiskLevel.caution),  # 29: what the two phishing hosts were shown as 'safe'
    (41, -20, RiskLevel.caution),  # 21
    (40, -20, RiskLevel.safe),     # 20: the scorer's 'safe'
    (30, 20, RiskLevel.caution),   # 50: the top of caution
    (31, 20, RiskLevel.dangerous),  # 51: above it
    (50, 20, RiskLevel.dangerous),  # 70
])
def test_a_shifted_score_is_mapped_with_the_scorers_lines(monkeypatch, score, shift, expected):
    _cached_opinion(monkeypatch, shift=shift)
    assert _judged(score) == (score + shift, expected)


@pytest.mark.parametrize("score", CAUTION_SCORES)
def test_a_judges_safe_never_clears_a_caution(monkeypatch, score):
    _cached_opinion(monkeypatch, "safe")
    new_score, level = _judged(score)
    assert new_score <= score
    assert level == RiskLevel.caution


@pytest.mark.parametrize("score", CAUTION_SCORES)
def test_a_judges_dangerous_counts_once_past_the_scorers_line(monkeypatch, score):
    _cached_opinion(monkeypatch, "dangerous")
    new_score, level = _judged(score)
    assert level == (RiskLevel.dangerous if new_score > DANGEROUS_ABOVE else RiskLevel.caution)


def test_the_lines_are_the_scorers_not_a_copy(monkeypatch):
    """Moving the scorer's line moves the analyzer's with it."""
    _cached_opinion(monkeypatch, shift=20)
    assert _judged(35)[1] == RiskLevel.dangerous  # 55
    monkeypatch.setattr(scoring, "DANGEROUS_ABOVE", 60)
    assert _judged(35)[1] == RiskLevel.caution


# ── Whole analyses ──

def _young_shop(offline_analyzer, monkeypatch):
    """A 20-day-old name: caution 40 on the rules alone (domain_new 30, an
    unnatural n-gram 10), no ML opinion."""
    offline_analyzer(site="reachable", values={"whois": {"age_days": 20}})
    monkeypatch.setattr("api.services.ml_scorer.ml_predict", lambda domain: None)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key-not-real")


def test_a_caution_the_judge_calls_safe_stays_caution(offline_analyzer, monkeypatch):
    """The 2026-11-01 case: a caution score of 30-49 and a cached "safe"
    from the judge ended at 29 and was shown 'safe'."""
    _young_shop(offline_analyzer, monkeypatch)
    _cached_opinion(monkeypatch, "safe")
    result = asyncio.run(analyzer.analyze_domain("obscure-shop.ru", budget_s=3.0))
    assert result.score == 29
    assert result.level == RiskLevel.caution
    assert next(r for r in result.reasons if r.signal == "llm_judge").weight < 0


def test_the_applied_shift_is_logged(offline_analyzer, monkeypatch, caplog):
    """So how often a judge's opinion lands on which side of a line can be
    counted from the logs (no judge outcome was stored anywhere)."""
    _young_shop(offline_analyzer, monkeypatch)
    _cached_opinion(monkeypatch, "safe")
    with caplog.at_level(logging.INFO, logger="cleanway.analyzer"):
        result = asyncio.run(analyzer.analyze_domain("obscure-shop.ru", budget_s=3.0))
    record = next(r for r in caplog.records if r.getMessage() == "analysis_complete")
    judge = next(r for r in result.reasons if r.signal == "llm_judge")
    assert record.judge_shift == judge.weight
    assert record.score == result.score


# ── Answers cached under the old lines ──

def _cached(level: str, score: int, *signals: str) -> DomainResult:
    return DomainResult(domain="x.ru", score=score, level=RiskLevel(level),
                        reasons=[DomainReason(signal=s, weight=0, detail="d") for s in signals])


@pytest.mark.parametrize("cached", [
    _cached("safe", 29, "domain_new", "llm_judge"),         # the 2026-11-01 answers
    _cached("caution", 60, "typosquatting", "llm_judge"),   # 'dangerous' by the scorer's lines
])
def test_a_judged_answer_the_scorers_lines_disagree_with_is_not_served_from_cache(cached):
    """The public cache keeps a full verdict for a day: without this, a
    phishing host shown 'safe' at 29 stayed 'safe' for up to a day after
    the deploy."""
    assert is_retired(cached)


@pytest.mark.parametrize("cached", [
    _cached("caution", 29, "domain_new", "llm_judge"),  # mapped with the scorer's lines
    _cached("safe", 0, "known_legitimate"),
    _cached("caution", 0, "invalid"),                   # no judge: a level set on purpose
    _cached("caution", 25, "site_unreachable"),
])
def test_other_cached_answers_are_served(cached):
    assert not is_retired(cached)


def test_no_judge_logs_no_shift(offline_analyzer, caplog):
    offline_analyzer(site="reachable")
    with caplog.at_level(logging.INFO, logger="cleanway.analyzer"):
        asyncio.run(analyzer.analyze_domain("obscure-shop.ru", budget_s=3.0))
    record = next(r for r in caplog.records if r.getMessage() == "analysis_complete")
    assert record.judge_shift is None

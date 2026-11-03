"""After the LLM judge's shift, the level comes from the scorer's own lines.

The scorer calls a score up to 20 'safe' and above 50 'dangerous'
(scoring.SAFE_AT_MOST, scoring.DANGEROUS_ABOVE). The analyzer re-mapped a
judge-shifted score with lines of its own, 30 and 70 — the caution band from
before the scorer moved — so a judge's "safe" took any caution score of 30-49
down to 29 and showed it 'safe'. On the 2026-11-01 benchmark two phishing
hosts ended exactly so: divace-coinsquare.zapier.app and
4ff9b103.jiebanyou.net, 'safe' at 29.

With the scorer's lines the judge, whose "safe" aims at 29, can no longer
clear a caution to 'safe'. Its "dangerous" (+20 at most) stops at the top of
caution (scoring.DANGEROUS_ABOVE): on its own the judge never makes a caution
'dangerous'. Mapped with the scorer's lines alone it did, for any caution of
31-50 — real sites among them (the reviewer's cases below) — and the browser
extension blocks the page on any 'dangerous' from the API
(extension/src/content/index.js) and tells the family; Android warns.
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


def _judged(score: int, signals=None) -> tuple[int, RiskLevel]:
    new_score, level, _, finished = asyncio.run(analyzer._llm_judge_within(
        signals or {"blocklist_hits": 0}, score, RiskLevel.caution, Deadline(1.0)))
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
    (49, -20, (29, RiskLevel.caution)),  # what the two phishing hosts were shown as 'safe'
    (41, -20, (21, RiskLevel.caution)),
    (40, -20, (20, RiskLevel.safe)),     # the scorer's 'safe'
    (30, 20, (50, RiskLevel.caution)),   # the top of caution
    (35, 10, (45, RiskLevel.caution)),
    # These two were (51, 'dangerous') and (70, 'dangerous') here: they held
    # the judge's lift past the scorer's line in place, which is the bug.
    (31, 20, (50, RiskLevel.caution)),
    (50, 20, (50, RiskLevel.caution)),
])
def test_a_shifted_score_is_mapped_with_the_scorers_lines(monkeypatch, score, shift, expected):
    _cached_opinion(monkeypatch, shift=shift)
    assert _judged(score) == expected


@pytest.mark.parametrize("score", CAUTION_SCORES)
def test_a_judges_safe_never_clears_a_caution(monkeypatch, score):
    _cached_opinion(monkeypatch, "safe")
    new_score, level = _judged(score)
    assert new_score <= score
    assert level == RiskLevel.caution


@pytest.mark.parametrize("score", CAUTION_SCORES)
def test_a_judges_dangerous_never_makes_a_caution_dangerous(monkeypatch, score):
    """Replaces test_a_judges_dangerous_counts_once_past_the_scorers_line,
    which held 'dangerous' for any caution of 31-50 in place. The judge's
    "dangerous" still raises the score — up to the top of caution."""
    _cached_opinion(monkeypatch, "dangerous")
    new_score, level = _judged(score)
    assert new_score == min(score + llm_judge._shift_for_verdict("dangerous", score), DANGEROUS_ABOVE)
    assert score <= new_score <= DANGEROUS_ABOVE
    assert level == RiskLevel.caution


def test_the_lines_are_the_scorers_not_a_copy(monkeypatch):
    """Moving the scorer's lines moves the analyzer's with them. (The first
    check here was 'dangerous' at 55 — the bug — and is now the cap.)"""
    _cached_opinion(monkeypatch, shift=20)
    assert _judged(35) == (DANGEROUS_ABOVE, RiskLevel.caution)
    monkeypatch.setattr(scoring, "DANGEROUS_ABOVE", 60)
    assert _judged(35) == (55, RiskLevel.caution)
    _cached_opinion(monkeypatch, shift=-20)
    assert _judged(40) == (20, RiskLevel.safe)
    monkeypatch.setattr(scoring, "SAFE_AT_MOST", 15)
    assert _judged(40) == (20, RiskLevel.caution)


# ── The reviewer's cases (2026-11-03) ──

_HEADERS = ["strict-transport-security", "content-security-policy", "x-frame-options"]


def _ml(probability):
    return lambda domain: {"phishing_probability": probability, "prediction": "benign",
                           "confidence": 0.9, "backend": "onnx"}


# Real sites from data/benchmark_legit_ru.txt that the 2026-10-18..11-01
# benchmarks answered caution, with what the analyzer saw on them and the ML
# model's reading pinned (a weekly retrain moves it). With a cached
# "dangerous" from the judge they went 'dangerous' (+20) — a full-page block
# in the extension.
REAL_SITES = [
    # missing_headers 15, no_mx_record 8, unnatural_ngram 10, consonant_cluster
    # 6: weak signals only, which the scorer itself stops at caution.
    pytest.param("syktyvkar-sovet.ru", {"missing_security_headers": _HEADERS, "dns_has_mx": False},
                 0.37, 39, id="syktyvkar-sovet.ru"),
    # no_https 40, no_mx_record 8, the ML model's "safe" -10
    pytest.param("ognimos.ru", {"no_https": True, "dns_has_mx": False}, 0.04, 38, id="ognimos.ru"),
    # no_https 40, unnatural_ngram 10, the ML model's "safe" -10
    pytest.param("simaz-bus.ru", {"no_https": True}, 0.02, 40, id="simaz-bus.ru"),
]


def _scored(monkeypatch, domain, observed, ml_probability):
    monkeypatch.setattr("api.services.ml_scorer.ml_predict", _ml(ml_probability))
    signals = {"domain": domain, "raw_url": domain, "site_reachable": True, "checks_succeeded": 17,
               "total_checks": 19, "blocklist_hits": 0, **observed}
    score, level, _ = scoring.calculate_score(signals)
    return signals, score, level


@pytest.mark.parametrize("domain, observed, ml_probability, reviewers_score", REAL_SITES)
def test_a_real_sites_caution_stays_caution_on_a_judges_dangerous(monkeypatch, domain, observed, ml_probability,
                                                                   reviewers_score):
    signals, score, level = _scored(monkeypatch, domain, observed, ml_probability)
    assert (score, level) == (reviewers_score, RiskLevel.caution)
    assert score + llm_judge.LLM_MAX_SHIFT > DANGEROUS_ABOVE  # past the line without the cap
    _cached_opinion(monkeypatch, "dangerous")
    assert _judged(score, signals) == (DANGEROUS_ABOVE, RiskLevel.caution)


@pytest.mark.parametrize("domain, observed, ml_probability, reviewers_score", REAL_SITES)
def test_a_judges_safe_still_lowers_a_real_sites_score(monkeypatch, domain, observed, ml_probability,
                                                       reviewers_score):
    """The cap is on the way up only: a "safe" lowers the score as before, and
    the level comes from the scorer's 'safe' line (20), which the judge's
    target (29) stays above."""
    signals, score, _ = _scored(monkeypatch, domain, observed, ml_probability)
    _cached_opinion(monkeypatch, "safe")
    assert _judged(score, signals) == (29, RiskLevel.caution)


def test_a_bare_ip_at_the_top_of_caution_stays_caution(monkeypatch):
    """A bare IP whose signals are all weak on an address stops at caution 50
    (fix/ip-literal-not-dangerous-by-shape, #398): a cached "dangerous" took
    every such address to 70, 'dangerous'."""
    _cached_opinion(monkeypatch, "dangerous")
    signals = {"domain": "203.0.113.7", "raw_url": "203.0.113.7", "is_ip_based": True, "blocklist_hits": 0}
    assert _judged(DANGEROUS_ABOVE, signals) == (DANGEROUS_ABOVE, RiskLevel.caution)


def test_a_held_back_dangerous_is_logged(monkeypatch, caplog):
    """How often the cap holds a judge's "dangerous" back can be counted."""
    _cached_opinion(monkeypatch, "dangerous")
    with caplog.at_level(logging.INFO, logger="cleanway.analyzer"):
        _judged(39, {"domain": "syktyvkar-sovet.ru", "blocklist_hits": 0})
    record = next(r for r in caplog.records if r.getMessage() == "llm_judge_capped")
    assert (record.domain, record.score, record.judge_shift) == ("syktyvkar-sovet.ru", 39, 20)


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


def test_a_caution_the_judge_calls_dangerous_stays_caution(offline_analyzer, monkeypatch):
    _young_shop(offline_analyzer, monkeypatch)
    _cached_opinion(monkeypatch, "dangerous")
    result = asyncio.run(analyzer.analyze_domain("obscure-shop.ru", budget_s=3.0))
    assert (result.score, result.level) == (DANGEROUS_ABOVE, RiskLevel.caution)
    # The reason carries the shift applied (40 to 50), not the +20 proposed.
    assert next(r for r in result.reasons if r.signal == "llm_judge").weight == DANGEROUS_ABOVE - 40


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
    _cached("dangerous", 70, "domain_new", "llm_judge"),    # a caution of 50 the judge took past the line
])
def test_a_judged_answer_the_scorers_lines_disagree_with_is_not_served_from_cache(cached):
    """The public cache keeps a full verdict for a day: without this, a
    phishing host shown 'safe' at 29 stayed 'safe' for up to a day after
    the deploy — and a caution the judge alone made 'dangerous' (a full-page
    block in the extension) stayed blocked."""
    assert is_retired(cached)


@pytest.mark.parametrize("cached", [
    _cached("caution", 29, "domain_new", "llm_judge"),  # mapped with the scorer's lines
    _cached("caution", 50, "domain_new", "llm_judge"),  # a "dangerous" held at the top of caution
    _cached("dangerous", 90, "phishtank"),              # no judge: the scorer's own 'dangerous'
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

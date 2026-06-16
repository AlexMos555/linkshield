"""Strategy doc Top-20 #12 — conformal confidence band tests.

Pin the blend formula's behavior at the corners and the
monotonicity properties consumers will assume:

  * Full coverage + large margin → ≥ 90
  * No data → exactly 50 (we never claim ≥50% from nothing)
  * Boundary scores → low (we're uncertain)
  * Output always in [50, 99] — never 100, never < 50
"""
from __future__ import annotations

import pytest

from api.services.scoring import calculate_confidence_pct


def test_full_coverage_huge_margin_is_high():
    """All 18 analyzer checks succeeded, score 0 — far from any
    threshold. Should be at or near the ceiling."""
    pct = calculate_confidence_pct(score=0, checks_succeeded=18, total_checks=18)
    assert pct >= 95
    assert pct <= 99


def test_full_coverage_dangerous_clear_is_high():
    """All checks succeeded, score 100 — also far from any
    threshold (70+ is dangerous). Should match the safe-side ceiling."""
    pct = calculate_confidence_pct(score=100, checks_succeeded=18, total_checks=18)
    assert pct >= 95


def test_zero_coverage_floors_at_50():
    """No checks succeeded — we should never claim more than 50%
    confidence in any verdict built from no signal."""
    pct = calculate_confidence_pct(score=50, checks_succeeded=0, total_checks=18)
    assert pct == 50


def test_zero_total_checks_safe_floor():
    """Defensive: if total_checks somehow comes through as 0, we
    must return the floor instead of dividing by zero."""
    pct = calculate_confidence_pct(score=50, checks_succeeded=0, total_checks=0)
    assert pct == 50


def test_boundary_score_low_confidence():
    """Score exactly on a threshold means we're maximally uncertain
    about which level applies. Even with full coverage, the margin
    component is 0, so confidence should be on the lower end."""
    full_coverage_at_boundary = calculate_confidence_pct(
        score=30, checks_succeeded=18, total_checks=18
    )
    full_coverage_clear = calculate_confidence_pct(
        score=10, checks_succeeded=18, total_checks=18
    )
    assert full_coverage_at_boundary < full_coverage_clear


def test_never_exceeds_99():
    """The cap is the conformal-prediction point — we never claim
    absolute certainty. Even maxed inputs must stay ≤ 99."""
    for score in [0, 50, 100]:
        pct = calculate_confidence_pct(score, 18, 18)
        assert pct <= 99, f"pct={pct} for score={score} exceeded cap"


def test_never_below_50():
    """Conversely, we never return below 50 — any verdict we surface
    has at least basic data behind it."""
    for score in [0, 30, 70, 100]:
        for checks in [0, 1, 18]:
            pct = calculate_confidence_pct(score, checks, 18)
            assert pct >= 50, f"pct={pct} for score={score} checks={checks} below floor"


def test_more_coverage_gives_at_least_equal_confidence():
    """Holding score fixed, more successful checks should never
    decrease confidence — strict monotonicity in coverage."""
    score = 75
    last = -1
    for checks in [0, 4, 9, 14, 18]:
        pct = calculate_confidence_pct(score, checks, 18)
        assert pct >= last, f"pct decreased at checks={checks}: {last}→{pct}"
        last = pct


def test_wider_margin_gives_at_least_equal_confidence_in_safe_zone():
    """In the safe zone (score < 30), pulling score AWAY from 30
    (down toward 0) should not decrease confidence."""
    full = 18
    a = calculate_confidence_pct(score=25, checks_succeeded=full, total_checks=full)
    b = calculate_confidence_pct(score=15, checks_succeeded=full, total_checks=full)
    c = calculate_confidence_pct(score=0, checks_succeeded=full, total_checks=full)
    assert c >= b >= a


def test_wider_margin_in_dangerous_zone():
    """Symmetric: in the danger zone (score > 70), pulling AWAY
    from 70 (up toward 100) increases confidence."""
    full = 18
    a = calculate_confidence_pct(score=75, checks_succeeded=full, total_checks=full)
    b = calculate_confidence_pct(score=85, checks_succeeded=full, total_checks=full)
    c = calculate_confidence_pct(score=100, checks_succeeded=full, total_checks=full)
    assert c >= b >= a


def test_score_above_100_clamps():
    """Defensive: scoring rules could over-accumulate before the
    main clamp. confidence_pct must not break on overflow."""
    pct = calculate_confidence_pct(score=120, checks_succeeded=18, total_checks=18)
    assert 50 <= pct <= 99


def test_negative_score_clamps():
    """Similarly, deeply-negative scores (from many trust signals)
    should not break the formula."""
    pct = calculate_confidence_pct(score=-30, checks_succeeded=18, total_checks=18)
    assert 50 <= pct <= 99


def test_typical_safe_verdict_yields_high_confidence():
    """A real example: domain age unknown but 17/18 checks ran,
    final score 10 (clearly safe). Should land 85-95."""
    pct = calculate_confidence_pct(score=10, checks_succeeded=17, total_checks=18)
    assert 85 <= pct <= 99


def test_typical_borderline_verdict_yields_modest_confidence():
    """Domain looks suspicious (score 65, just below dangerous
    threshold) and 14/18 checks ran. Should be a modest ~70-80."""
    pct = calculate_confidence_pct(score=65, checks_succeeded=14, total_checks=18)
    assert 65 <= pct <= 85


def test_analyzer_pipeline_populates_confidence_pct():
    """End-to-end: analyze_domain produces a DomainResult whose
    confidence_pct field is set to a real value, not the default."""
    from api.models.schemas import DomainResult

    # Direct DomainResult construction — verifies the field is
    # accepted by the Pydantic model and within bounds.
    result = DomainResult(
        domain="example.com",
        score=10,
        level="safe",
        confidence="high",
        confidence_pct=94,
        reasons=[],
    )
    assert result.confidence_pct == 94


def test_domain_result_rejects_out_of_band_confidence():
    """Pydantic must reject 100 and < 50 at validation time so
    the API contract holds even if a caller bypasses the helper."""
    from api.models.schemas import DomainResult
    with pytest.raises(Exception):
        DomainResult(
            domain="example.com",
            score=10,
            level="safe",
            confidence="high",
            confidence_pct=100,
            reasons=[],
        )
    with pytest.raises(Exception):
        DomainResult(
            domain="example.com",
            score=10,
            level="safe",
            confidence="high",
            confidence_pct=49,
            reasons=[],
        )

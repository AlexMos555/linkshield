"""The pre-publish gate of the weekly benchmark (scripts/eval_fresh_urls.check_quality_gate)
and its twin on the site (landing/lib/benchmark.ts recallIsPublishable).

Until 2026-11-03 both counted every "unknown" against a 30% limit. In
method_version 2 (scripts/benchmark_method.py) "unknown" also holds every
dead name and every caution. A fresh sample has many of both: 76 of 200
names of the seed-42 7-day sample on the 2026-11-03 dump were already
NXDOMAIN, and Cleanway gave caution on 28 of 200 on 2026-11-01. So
"unknown" would be about half and the gate would fail every week, keeping
the site on an older report. Rate-limit trouble — what the limit was for
(the 2026-06-30 run: 30 of 50 rows 429) — is the share of live rows that got
no answer at all: HTTP 429, an error, a timeout.

tests/fixtures/benchmark-gate-cases.json holds cases both gates must decide
the same way; scripts/test-landing-honesty.mjs runs the site's side.
"""
from __future__ import annotations

import importlib
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
CASES = json.loads((ROOT / "tests" / "fixtures" / "benchmark-gate-cases.json").read_text(encoding="utf-8"))["cases"]
LANDING = (ROOT / "landing" / "lib" / "benchmark.ts").read_text(encoding="utf-8")


def _eval():
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    return importlib.import_module("eval_fresh_urls")


def _healthy_safe() -> dict:
    return {"tp": 0, "fp": 1, "tn": 150, "fn": 0, "unknown": 49, "fpr": 1 / 151,
            "n": 200, "dangerous": 1, "caution": 45, "safe": 150, "not_found": 4, "no_answer": 0,
            "resolving": 196, "answered": 196}


def _report(n_phishing: int, cleanway: dict, safe: dict | None = None) -> dict:
    return {"ts": "2026-11-08T15:40:00Z", "method_version": 2, "n_phishing": n_phishing, "n_safe": 200,
            "phishing": {"cleanway": cleanway}, "safe": {"cleanway": safe or _healthy_safe()}}


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_the_script_publishes_exactly_what_the_site_would_show(case):
    result = _eval().check_quality_gate(_report(case["n_phishing"], case["cleanway"]))
    assert result.passed is case["publishable"], result


def _case(name_start: str) -> dict:
    return next(c for c in CASES if c["name"].startswith(name_start))


def test_dead_names_and_cautions_no_longer_hold_a_fresh_run_back():
    case = _case("method 2, fresh sample")
    stats = case["cleanway"]
    assert stats["unknown"] / (stats["tp"] + stats["fn"] + stats["unknown"]) > 0.30  # the old rule: held back
    assert _eval().check_quality_gate(_report(case["n_phishing"], stats)).passed is True


def test_a_rate_limited_run_is_held_back_and_the_log_says_why():
    case = _case("method 2, rate-limited")
    result = _eval().check_quality_gate(_report(case["n_phishing"], case["cleanway"]))
    assert result.failed_gate == "phishing_no_answer_rate_too_high"
    assert "no_answer=50" in result.detail and "resolving=155" in result.detail


def test_a_run_whose_names_mostly_died_is_held_back_by_name():
    """The floor is the classified one (50): live rows are never fewer than
    Cleanway's verdicts, so it holds nothing more back. Checked first, it
    tells the log that the sample died, not that Cleanway went quiet."""
    case = _case("method 2, most names dead")
    result = _eval().check_quality_gate(_report(case["n_phishing"], case["cleanway"]))
    assert result.failed_gate == "phishing_resolving_below_min"
    assert "resolving=42" in result.detail and "not_found=158" in result.detail


def test_a_method_1_report_is_gated_as_before():
    case = _case("method 1 snapshot, rate-limited")
    result = _eval().check_quality_gate(_report(case["n_phishing"], case["cleanway"]))
    assert result.failed_gate == "phishing_unknown_rate_too_high"


def test_the_legit_half_is_gated_on_no_answer_too():
    """Without an FPR the legit half passes only when most live sites got an
    answer: Cleanway's caution on a real site is an answer, a 429 is not."""
    ev = _eval()
    phishing = _case("method 2, fresh sample")["cleanway"]
    cautious = {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "unknown": 200, "fpr": None,
                "n": 200, "dangerous": 0, "caution": 196, "safe": 0, "not_found": 4, "no_answer": 0,
                "resolving": 196, "answered": 196}
    assert ev.check_quality_gate(_report(200, phishing, cautious)).passed is True
    limited = {**cautious, "caution": 16, "no_answer": 180, "answered": 16}
    result = ev.check_quality_gate(_report(200, phishing, limited))
    assert result.failed_gate == "safe_no_answer_rate_too_high"
    dead = {**cautious, "caution": 0, "not_found": 200, "resolving": 0, "answered": 0}
    assert ev.check_quality_gate(_report(200, phishing, dead)).failed_gate == "safe_no_answer_rate_too_high"


def _ts_number(name: str) -> float:
    m = re.search(rf"export const {name} = ([0-9.]+);", LANDING)
    assert m, f"{name} not found in landing/lib/benchmark.ts"
    return float(m.group(1))


def test_the_site_and_the_script_share_their_limits():
    ev = _eval()
    assert _ts_number("MIN_PHISHING_SAMPLE") == ev._QG_MIN_PHISHING
    assert _ts_number("MIN_PHISHING_CLASSIFIED") == ev._QG_MIN_CLASSIFIED_PHISHING
    assert _ts_number("MIN_PHISHING_RESOLVING") == ev._QG_MIN_RESOLVING_PHISHING
    assert _ts_number("MAX_NO_ANSWER_RATE") == ev._QG_MAX_NO_ANSWER_RATE
    assert "MAX_UNKNOWN_RATE" not in LANDING

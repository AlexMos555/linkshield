"""The method_version 2 report the site's headline is tested on
(tests/fixtures/benchmark-headline-report.json) is one the script would write.

Since 2026-11-03 the landing quotes, from a method_version 2 report only, the
share of the live phishing links that got an answer and that Cleanway called
dangerous (dangerous_rate_answered), its Wilson interval, and the share that
got at least a warning (warned_rate_answered) — landing/lib/benchmark.ts
detectionFigures, pinned by scripts/test-landing-honesty.mjs on this fixture.
Here the fixture is held to scripts/benchmark_method.py: every summary is
summarize() over the fixture's own outcome counts, its window has the keys
recent_window() writes, and the script's gate would publish it. A field the
script renames, or a rounding it changes, fails here before the site reads a
key that no longer exists.
"""
from __future__ import annotations

import importlib
import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURE = json.loads((ROOT / "tests" / "fixtures" / "benchmark-headline-report.json").read_text(encoding="utf-8"))
ORDER = ("dangerous", "caution", "safe", "not_found", "no_answer")


def _module(name: str):
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    return importlib.import_module(name)


def _outcomes(counts: dict) -> list[str]:
    return [kind for kind in ORDER for _ in range(counts.get(kind, 0))]


@pytest.mark.parametrize("batch,expected", [("phishing", "dangerous"), ("safe", "safe")])
def test_every_summary_is_what_summarize_writes(batch, expected):
    method = _module("benchmark_method")
    outcomes = FIXTURE["_outcomes"][batch]
    assert set(outcomes) == set(FIXTURE[batch])
    for name, counts in outcomes.items():
        stored = dict(FIXTURE[batch][name])
        assert isinstance(stored.pop("latency_p50_ms"), float)
        assert stored == method.summarize(_outcomes(counts), expected), f"{batch}.{name}"
        assert stored["n"] == FIXTURE[f"n_{batch}"]


def test_the_report_is_method_2_with_the_window_the_script_writes():
    method = _module("benchmark_method")
    assert FIXTURE["method_version"] == method.METHOD_VERSION == 2
    _, window = method.recent_window(["2026-11-08T14:08:00+00:00"], method.WINDOW_DAYS)
    assert set(FIXTURE["sampling"]["window"]) == set(window)
    assert FIXTURE["sampling"]["window"]["days"] == method.WINDOW_DAYS
    assert FIXTURE["sampling"]["n"] == FIXTURE["n_phishing"]


def test_its_window_is_the_one_the_script_writes_for_its_newest_row_and_clock():
    """Not only the keys: the window recent_window() writes for a dump whose
    newest row is the fixture's `end`, downloaded at the fixture's `clock`."""
    method = _module("benchmark_method")
    stored = FIXTURE["sampling"]["window"]
    _, window = method.recent_window([stored["end"]], method.WINDOW_DAYS, now=datetime.fromisoformat(stored["clock"]))
    assert window == stored
    assert stored["clock"] >= stored["end"], "no row is newer than the download"


def test_its_existence_counts_have_the_keys_the_script_writes():
    """Since 2026-11-04 a name with no public address in A and AAAA together
    (none at all, or only 0.0.0.0 and private ranges: a takedown) is counted
    apart (non_public) and is not found for every resolver, as a missing one
    (benchmark_method.NOT_LIVE, no_public_address)."""
    method = _module("benchmark_method")
    for batch in ("phishing", "safe"):
        counts = FIXTURE["existence"][batch]
        assert set(counts) == set(method.existence_counts([])), batch
        assert sum(counts.values()) == FIXTURE[f"n_{batch}"], batch
        not_live = sum(counts[kind] for kind in method.NOT_LIVE)
        for name, stats in FIXTURE[batch].items():
            assert stats["not_found"] == not_live, f"{batch}.{name}"
    # The site's "not found" holds both kinds: the fixture has both.
    assert FIXTURE["existence"]["phishing"]["nxdomain"] > 0
    assert FIXTURE["existence"]["phishing"]["non_public"] > 0


def test_the_script_would_publish_it():
    gate = _module("eval_fresh_urls").check_quality_gate(FIXTURE)
    assert gate.passed, gate


def test_the_methodology_page_describes_the_sample_the_script_draws():
    """The page's method text is static: it names the window and the cap per
    site in words. A change to either in benchmark_method fails here until the
    copy (all 10 languages, packages/i18n-strings/src) says the new value."""
    method = _module("benchmark_method")
    en = json.loads((ROOT / "packages" / "i18n-strings" / "src" / "en.json").read_text(encoding="utf-8"))
    copy = en["landing"]["methodology"]
    for key in ("why_p2", "dataset_phishing_desc"):
        assert f"in the {method.WINDOW_DAYS} days before" in copy[key], key
    assert f"at most {method.MAX_PER_SITE} links from each" in copy["dataset_phishing_desc"]


def test_its_headline_is_not_its_recall():
    """The point of the fixture: dead names, cautions and no answer make the
    headline and the old recall differ, so a page that still printed recall
    fails scripts/test-landing-honesty.mjs."""
    ours = FIXTURE["phishing"]["cleanway"]
    assert ours["not_found"] > 0 and ours["caution"] > 0 and ours["no_answer"] > 0
    assert round(ours["dangerous_rate_answered"], 3) != round(ours["recall"], 3)

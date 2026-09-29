"""/api/v1/public/stats returns measured numbers or null, never hand-written
ones (report 2026-09-25 #12).

It used to serve "0.08% false positives" — typed into a fixture on
2026-06-16, before launch; false positives have never been measured — next
to "16 sources", "42 signals" and "100,000 domains protected". Every key
stays (the landing and the typed client read this shape); only the values
became honest, and `notes` says why a value is null.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.services import public_stats

OLD_KEYS = {
    "total_domains_protected", "threat_sources", "detection_signals", "ml_model_auc",
    "ml_backend", "detection_rate", "false_positive_rate", "brand_targets_monitored",
    "transparency_url",
}
HAND_WRITTEN = {100000, 16, 42, 0.0008, 125}


@pytest.fixture
def stats(monkeypatch, fake_redis):
    async def _no_limit(*a, **k):
        return None

    from api.services import rate_limiter
    monkeypatch.setattr(rate_limiter, "check_ip_rate_limit", _no_limit)
    return lambda: TestClient(app).get("/api/v1/public/stats").json()


def _report(n_phishing=24, n_safe=50, tp=8, fn=5, fp=0, tn=0, fpr=None, recall=0.615):
    return {
        "ts": "2026-06-30T13:12:11Z", "n_phishing": n_phishing, "n_safe": n_safe,
        "phishing": {"cleanway": {"tp": tp, "fn": fn, "recall": recall}},
        "safe": {"cleanway": {"fp": fp, "tn": tn, "fpr": fpr}},
    }


def test_keys_are_kept_and_nothing_is_hand_written(stats):
    body = stats()
    assert OLD_KEYS <= body.keys()
    for key in ("total_domains_protected", "threat_sources", "detection_signals"):
        assert body[key] is None, key
    for key, value in body.items():
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            assert value not in HAND_WRITTEN or key == "brand_targets_monitored", (key, value)


def test_every_null_is_explained(stats):
    body = stats()
    for key, value in body.items():
        if value is None and key != "benchmark_measured_at":
            assert key in body["notes"], key


def test_false_positive_rate_is_null_until_measured(stats, monkeypatch):
    """A benchmark with 50 legit sites, all 'unknown' — nothing was measured,
    so nothing is published. Given as a report, not read from the committed
    docs/benchmarks/latest.json: the weekly run of 2026-09-27 measured 130
    sites, and the rate it published is right to be there."""
    monkeypatch.setattr(public_stats, "benchmark", lambda: _report())
    assert stats()["false_positive_rate"] is None


def test_small_samples_are_not_published():
    report = _report(n_safe=50, fp=0, tn=50, fpr=0.0)
    assert public_stats.measured_false_positive_rate(report) is None
    assert public_stats.measured_detection_rate(_report(n_phishing=24)) is None


def test_a_real_measurement_is_published():
    report = _report(n_phishing=150, tp=90, fn=30, recall=0.75, n_safe=150, fp=3, tn=120, fpr=3 / 123)
    assert public_stats.measured_detection_rate(report) == 75.0
    assert public_stats.measured_false_positive_rate(report) == round(3 / 123, 4)


def test_a_rate_limited_legit_batch_publishes_nothing():
    """The 2026-09 runs: 60 of 60 legit sites rate-limited → fpr null."""
    report = _report(n_safe=120, fp=0, tn=0, fpr=None)
    assert public_stats.measured_false_positive_rate(report) is None


def test_brand_count_comes_from_the_loaded_lists():
    """A Russian brand counts once, not once per spelling (sber, sberbank,
    сбербанк are one bank)."""
    from api.services.scoring import GLOBAL_TYPOSQUAT_TARGETS, RU_BRAND_GROUPS, TYPOSQUAT_TARGETS
    assert RU_BRAND_GROUPS
    assert public_stats.brand_targets_monitored() == len(GLOBAL_TYPOSQUAT_TARGETS) + len(RU_BRAND_GROUPS)
    assert public_stats.brand_targets_monitored() < len(TYPOSQUAT_TARGETS)


def test_blocklist_entries_is_read_live(stats, fake_redis):
    """Absent artifact → null, not a made-up size."""
    assert stats()["blocklist_entries"] is None


def test_no_hand_written_rate_left_in_the_endpoint_source():
    from pathlib import Path
    src = (Path(__file__).resolve().parent.parent / "api" / "routers" / "public.py").read_text()
    assert "0.0008" not in src and "100000" not in src


def test_committed_benchmark_is_readable():
    with open(public_stats.LATEST_BENCHMARK) as f:
        assert isinstance(json.load(f), dict)

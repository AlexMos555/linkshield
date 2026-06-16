"""Transparency endpoint tests — Strategy doc Top-20 #16.

Verifies the shipped Q2 2026 fixture plus the empty-dir and
malformed-file failure modes. The contract is: GET /latest
ALWAYS returns either a complete report or 503 — never partial.
"""
from __future__ import annotations

import json
import pathlib

import pytest
from fastapi.testclient import TestClient

from api.main import app


client = TestClient(app)


def test_latest_returns_published_q2_2026():
    """The repo ships docs/transparency/2026-q2.json. The endpoint
    must surface it under /api/v1/transparency/latest."""
    resp = client.get("/api/v1/transparency/latest")
    assert resp.status_code == 200, resp.text
    data = resp.json()

    # Stable contract — every consumer (landing page, popup, mobile)
    # depends on these keys.
    for required in (
        "id", "period", "published_at", "checks", "verdicts",
        "false_positive_rate", "latency_ms", "intel_sources_active",
        "top_blocked_categories", "data_requests_received",
    ):
        assert required in data, f"missing field: {required}"

    assert data["id"] == "2026-q2"
    assert isinstance(data["checks"]["total"], int)
    assert 0.0 <= data["false_positive_rate"]["value"] < 1.0


def test_history_lists_at_least_q2():
    resp = client.get("/api/v1/transparency/history")
    assert resp.status_code == 200
    history = resp.json()
    assert isinstance(history, list)
    ids = {h.get("id") for h in history}
    assert "2026-q2" in ids


def test_fp_rate_denominator_matches_dangerous_count():
    """The FP rate's denominator MUST equal the dangerous_count for
    the period — otherwise the denominator is misleading."""
    resp = client.get("/api/v1/transparency/latest")
    data = resp.json()
    assert (
        data["false_positive_rate"]["denominator"]
        == data["verdicts"]["dangerous_count"]
    )


def test_intel_sources_includes_strategy_features():
    """We promised to publicly attribute every detection signal.
    The intel list MUST include the new Cleanway-original sources."""
    resp = client.get("/api/v1/transparency/latest")
    sources = resp.json()["intel_sources_active"]
    source_lower = " ".join(sources).lower()
    assert "tranco" in source_lower
    assert "favicon" in source_lower
    assert "credential-form" in source_lower or "credential form" in source_lower


def test_data_requests_field_present_for_compliance():
    """Government data-request transparency is THE most-cited reason
    enterprises ask for a transparency report. The field must be
    present even when zero — explicit-zero is the signal."""
    resp = client.get("/api/v1/transparency/latest")
    dr = resp.json()["data_requests_received"]
    assert "government" in dr
    assert "court_orders" in dr
    assert "note" in dr


def test_503_when_directory_missing(monkeypatch, tmp_path):
    """A misconfigured deploy where docs/transparency/ doesn't ship
    must 503 cleanly, not crash with a stack trace into the client."""
    import api.routers.transparency as mod
    monkeypatch.setattr(mod, "DATA_DIR", tmp_path / "definitely-missing")
    resp = client.get("/api/v1/transparency/latest")
    assert resp.status_code == 503


def test_503_when_no_reports_present(monkeypatch, tmp_path):
    """Directory exists but is empty — also 503 (we promised a
    report, the deploy can't fulfill that promise)."""
    import api.routers.transparency as mod
    monkeypatch.setattr(mod, "DATA_DIR", tmp_path)
    resp = client.get("/api/v1/transparency/latest")
    assert resp.status_code == 503


def test_503_when_report_unreadable(monkeypatch, tmp_path):
    """A malformed JSON file (bad ops upload) → 503, not 200 with
    truncated data."""
    bad = tmp_path / "2026-q3.json"
    bad.write_text("{ not valid json")
    import api.routers.transparency as mod
    monkeypatch.setattr(mod, "DATA_DIR", tmp_path)
    resp = client.get("/api/v1/transparency/latest")
    assert resp.status_code == 503


def test_history_skips_unreadable_files(monkeypatch, tmp_path):
    """One bad file in the directory must not break the listing."""
    good = tmp_path / "2026-q2.json"
    good.write_text(json.dumps({
        "id": "2026-q2", "period": "Apr-Jun 2026", "published_at": "2026-06-16",
    }))
    bad = tmp_path / "2026-q3.json"
    bad.write_text("garbage")
    import api.routers.transparency as mod
    monkeypatch.setattr(mod, "DATA_DIR", tmp_path)
    resp = client.get("/api/v1/transparency/history")
    assert resp.status_code == 200
    ids = {h["id"] for h in resp.json()}
    assert "2026-q2" in ids
    assert "2026-q3" not in ids


def test_underscore_files_are_skipped(monkeypatch, tmp_path):
    """Files starting with `_` are treated as metadata, not reports
    (so we can ship a _schema.json without it leaking into /latest)."""
    meta = tmp_path / "_schema.json"
    meta.write_text(json.dumps({"id": "_schema"}))
    good = tmp_path / "2026-q2.json"
    good.write_text(json.dumps({
        "id": "2026-q2", "period": "Apr-Jun 2026", "published_at": "2026-06-16",
    }))
    import api.routers.transparency as mod
    monkeypatch.setattr(mod, "DATA_DIR", tmp_path)
    resp = client.get("/api/v1/transparency/latest")
    assert resp.status_code == 200
    assert resp.json()["id"] == "2026-q2"


def test_data_dir_exists_in_production_repo():
    """The shipped repo must include docs/transparency/. This pins
    a deploy artifact — we should never accidentally remove it."""
    p = pathlib.Path(__file__).resolve().parent.parent / "docs" / "transparency"
    assert p.exists(), "docs/transparency/ must ship with the API"
    assert list(p.glob("*.json")), "at least one quarterly report must ship"

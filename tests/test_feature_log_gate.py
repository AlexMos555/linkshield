"""Feature-log privacy gate — the checked domain must not persist to disk
unless explicitly enabled.

The ML training feature log (api/services/url_features.log_features) writes
the domain + feature vector to data/feature_log.jsonl. The 2026-07-01
privacy-doc pass flagged that this ran unconditionally with no retention,
contradicting the domain-only/transient stance. It is now OFF by default and
size-capped when enabled.
"""
from __future__ import annotations

import importlib
import json
from pathlib import Path


def _load_url_features(tmp_data_dir: Path):
    import api.services.url_features as uf

    importlib.reload(uf)
    uf._DATA_DIR = str(tmp_data_dir)
    return uf


def test_feature_log_disabled_by_default(tmp_path, monkeypatch):
    """With FEATURE_LOG_ENABLED unset, nothing is written to disk."""
    monkeypatch.delenv("FEATURE_LOG_ENABLED", raising=False)
    uf = _load_url_features(tmp_path)
    uf.log_features("victim-bank.example.com", {"len": 22.0}, 90)
    assert not (tmp_path / "feature_log.jsonl").exists()


def test_feature_log_writes_when_enabled(tmp_path, monkeypatch):
    """With FEATURE_LOG_ENABLED=true, the entry is appended."""
    monkeypatch.setenv("FEATURE_LOG_ENABLED", "true")
    uf = _load_url_features(tmp_path)
    uf.log_features("phish.example.com", {"len": 17.0, "entropy": 3.1}, 80)
    log = tmp_path / "feature_log.jsonl"
    assert log.exists()
    row = json.loads(log.read_text().strip())
    assert row["domain"] == "phish.example.com"
    assert row["score"] == 80
    assert row["features"]["entropy"] == 3.1


def test_feature_log_rotates_at_size_cap(tmp_path, monkeypatch):
    """When the file exceeds the cap, it is trimmed to its most recent half
    rather than growing without bound."""
    monkeypatch.setenv("FEATURE_LOG_ENABLED", "true")
    # Tiny cap so a handful of writes trips rotation deterministically.
    monkeypatch.setenv("FEATURE_LOG_MAX_BYTES", "400")
    uf = _load_url_features(tmp_path)
    log = tmp_path / "feature_log.jsonl"
    for i in range(40):
        uf.log_features(f"d{i}.example.com", {"len": float(i)}, i % 100)
    # File exists, is bounded near the cap (not 40 full rows), and the most
    # recent domain survived the last rotation.
    assert log.exists()
    contents = log.read_text()
    assert "d39.example.com" in contents
    # Bounded: well under what 40 un-rotated rows would produce.
    assert log.stat().st_size < 2000

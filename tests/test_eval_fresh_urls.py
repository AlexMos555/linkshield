"""Regression tests for scripts/eval_fresh_urls.py.

The weekly fresh-URL benchmark cron failed silently every Monday from
2026-06-22 through 2026-06-29 because `fetch_tranco_legit` assumed
`data/top_100k.json` was a dict, but the file's schema had drifted to a
bare list during a routine data refresh. `list.keys()` raised
AttributeError, the cron crashed in 12 seconds, and the public
`docs/benchmarks/latest.json` stayed frozen on a stale snapshot.

These tests pin both supported shapes so the next schema drift can't
silently re-break the cron.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import ModuleType


def _load_eval_module() -> ModuleType:
    """Import scripts/eval_fresh_urls.py as a module without making
    `scripts/` a package (no __init__.py). Pytest's pythonpath = ["."]
    setting means `scripts.` imports are available even without the
    init file."""
    if "scripts.eval_fresh_urls" in sys.modules:
        return sys.modules["scripts.eval_fresh_urls"]
    # Add scripts/ to sys.path so direct module load works on systems
    # where the implicit-namespace-package path resolution doesn't
    # find it (Python 3.9 on some macOS builds, GitHub Actions).
    scripts_dir = Path(__file__).resolve().parent.parent / "scripts"
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))
    return importlib.import_module("eval_fresh_urls")


def _write_top_100k(path: Path, payload) -> None:
    path.write_text(json.dumps(payload), encoding="utf-8")


def test_fetch_tranco_legit_handles_list_shape(tmp_path, monkeypatch):
    """top_100k.json as a bare list (current shape, 2026-06+) must
    not crash. This is the regression: code did `.keys()` on a list."""
    eval_module = _load_eval_module()
    _write_top_100k(
        tmp_path / "top_100k.json",
        ["google.com", "facebook.com", "github.com", "wikipedia.org"],
    )
    monkeypatch.setattr(eval_module, "DATA", tmp_path)
    out = eval_module.fetch_tranco_legit(limit=3)
    assert len(out) == 3
    assert all(u.startswith("https://") for u in out)
    # Domains must come from the input set.
    hosts = {u.removeprefix("https://") for u in out}
    assert hosts.issubset({"google.com", "facebook.com", "github.com", "wikipedia.org"})


def test_fetch_tranco_legit_handles_dict_shape(tmp_path, monkeypatch):
    """top_100k.json as {domain: rank} (legacy shape) is still
    accepted — historical files committed to the repo before the
    schema drift used this layout."""
    eval_module = _load_eval_module()
    _write_top_100k(
        tmp_path / "top_100k.json",
        {"google.com": 1, "facebook.com": 2, "github.com": 3, "wikipedia.org": 4},
    )
    monkeypatch.setattr(eval_module, "DATA", tmp_path)
    out = eval_module.fetch_tranco_legit(limit=2)
    assert len(out) == 2
    hosts = {u.removeprefix("https://") for u in out}
    assert hosts.issubset({"google.com", "facebook.com", "github.com", "wikipedia.org"})


def test_fetch_tranco_legit_rejects_unknown_shape(tmp_path, monkeypatch):
    """A future schema drift that's neither list nor dict must fail
    loudly, not silently produce zero URLs. We want the cron to red
    on the next refresh, not stay green with empty samples."""
    import pytest

    eval_module = _load_eval_module()
    _write_top_100k(tmp_path / "top_100k.json", "google.com")  # bare string
    monkeypatch.setattr(eval_module, "DATA", tmp_path)
    with pytest.raises(ValueError, match="expected list or dict"):
        eval_module.fetch_tranco_legit(limit=1)


def test_fetch_tranco_legit_uses_top_1m_when_present(tmp_path, monkeypatch):
    """When data/top-1m.csv exists, prefer it over the JSON fallback —
    the JSON path is only a last-resort. (Sanity check that the
    fallback branch isn't accidentally taken when the canonical CSV
    is there.)"""
    eval_module = _load_eval_module()
    csv_path = tmp_path / "top-1m.csv"
    csv_path.write_text(
        "\n".join(
            [f"{i},rank{i}.example.com" for i in range(1, 200)]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(eval_module, "DATA", tmp_path)
    out = eval_module.fetch_tranco_legit(limit=5)
    assert len(out) == 5
    # Every domain must look like rankNN.example.com — confirms the
    # CSV branch ran, not the JSON fallback.
    for u in out:
        host = u.removeprefix("https://")
        assert host.startswith("rank") and host.endswith(".example.com")


# ─────────────────────────────────────────────────────────────────
# Quality gate — pre-publish gate that guards docs/benchmarks/latest.json
# ─────────────────────────────────────────────────────────────────

def _healthy_report() -> dict:
    """Baseline report that passes every gate — individual tests copy
    this and mutate one field to isolate what tripped the gate."""
    return {
        "ts": "2026-07-01T05:15:00Z",
        "n_phishing": 200,
        "n_safe": 200,
        "phishing": {
            "cleanway": {
                "tp": 120, "fp": 0, "tn": 0, "fn": 40, "unknown": 40,
                "recall": 0.75, "fpr": None,
                "precision": 1.0, "f1": 0.857,
            },
        },
        "safe": {
            "cleanway": {
                "tp": 0, "fp": 2, "tn": 190, "fn": 0, "unknown": 8,
                "recall": None, "fpr": 0.0104,
                "precision": None, "f1": None,
            },
        },
    }


def test_quality_gate_passes_healthy_run():
    """A well-formed 200-sample run with sane recall + FPR must pass —
    otherwise the gate is over-tuned and would starve latest.json."""
    eval_module = _load_eval_module()
    result = eval_module.check_quality_gate(_healthy_report())
    assert result.passed is True
    assert result.failed_gate is None


def test_quality_gate_blocks_low_sample_count():
    """A --sample 50 smoke run must not overwrite latest.json even
    though the numbers look reasonable — 50 URLs is too noisy to
    represent the public benchmark."""
    eval_module = _load_eval_module()
    report = _healthy_report()
    report["n_phishing"] = 50
    result = eval_module.check_quality_gate(report)
    assert result.passed is False
    assert result.failed_gate == "n_phishing_below_min"
    assert "50" in (result.detail or "")


def test_quality_gate_blocks_high_unknown_rate():
    """The 2026-06-30 blowout — most of the phishing batch came back
    `unknown` because Cleanway rate-limited us. classify() still
    computes a recall on the few classified samples but it's noise.
    The gate must catch this and refuse to publish."""
    eval_module = _load_eval_module()
    report = _healthy_report()
    # Move nearly everything into unknown: 10 classified, 190 unknown.
    report["phishing"]["cleanway"] = {
        "tp": 8, "fp": 0, "tn": 0, "fn": 2, "unknown": 190,
        "recall": 0.8, "fpr": None,
        "precision": 1.0, "f1": 0.888,
    }
    result = eval_module.check_quality_gate(report)
    assert result.passed is False
    # 190/(10+190) = 95%, well above the 30% ceiling — and 10<50 so the
    # classified-count gate also fires. Either failure is acceptable as
    # long as SOMETHING blocks; assert one of the two known failures.
    assert result.failed_gate in {
        "phishing_classified_below_min",
        "phishing_unknown_rate_too_high",
    }


def test_quality_gate_blocks_null_recall():
    """When every phishing sample came back as `unknown`, classify()
    returns recall=None. That's the exact 2026-06-30 signature and it
    MUST NOT flip the public pointer."""
    eval_module = _load_eval_module()
    report = _healthy_report()
    report["n_phishing"] = 200
    report["phishing"]["cleanway"] = {
        "tp": 0, "fp": 0, "tn": 0, "fn": 0, "unknown": 200,
        "recall": None, "fpr": None,
        "precision": None, "f1": None,
    }
    result = eval_module.check_quality_gate(report)
    assert result.passed is False
    # The 0 classified samples gate should trip first.
    assert result.failed_gate in {
        "phishing_classified_below_min",
        "phishing_recall_null",
    }


def test_quality_gate_blocks_safe_batch_unknown_blowout():
    """If the safe batch has FPR=None AND is mostly `unknown` (the
    2026-06-30 fingerprint — phishing batch drained the 5/min window
    just before the safe batch), we can't trust the FPR side and
    must not publish."""
    eval_module = _load_eval_module()
    report = _healthy_report()
    report["safe"]["cleanway"] = {
        "tp": 0, "fp": 0, "tn": 20, "fn": 0, "unknown": 180,
        "recall": None, "fpr": None,  # ← the fingerprint
        "precision": None, "f1": None,
    }
    result = eval_module.check_quality_gate(report)
    assert result.passed is False
    assert result.failed_gate == "safe_unknown_rate_too_high"


def test_quality_gate_allows_safe_batch_with_valid_fpr_even_if_noisy():
    """If FPR came back non-null we accept the safe batch even if the
    unknown rate is a bit high — a real FPR is what we publish, and
    we already gated on the phishing side for the recall claim."""
    eval_module = _load_eval_module()
    report = _healthy_report()
    # 40% unknown on safe — above the 30% ceiling — but FPR is set.
    report["safe"]["cleanway"] = {
        "tp": 0, "fp": 1, "tn": 119, "fn": 0, "unknown": 80,
        "recall": None, "fpr": 0.0083,
        "precision": None, "f1": None,
    }
    result = eval_module.check_quality_gate(report)
    assert result.passed is True


def test_min_interval_cleanway_bumped_to_16s():
    """The 5-per-minute cap needs >12s spacing; 13s was in-spec but
    left no room for network jitter. 16s (or more) is the value we
    ship — regression test in case anyone reverts to save wall-clock.
    """
    eval_module = _load_eval_module()
    assert eval_module.MIN_INTERVAL_S["cleanway"] >= 16.0


def test_batch_cooldown_is_at_least_60s():
    """The Cleanway rate-limit window is 60s; anything less would let
    the safe batch bleed into the phishing batch's window and start
    generating 429s again."""
    eval_module = _load_eval_module()
    assert eval_module.CLEANWAY_BATCH_COOLDOWN_S >= 60.0

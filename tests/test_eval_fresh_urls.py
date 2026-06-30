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

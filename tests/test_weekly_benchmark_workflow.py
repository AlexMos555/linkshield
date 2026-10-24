"""The "Detect recall regression" step of .github/workflows/weekly-benchmark.yml.

The step compares this week's fresh-URL run with the previous one. It
picked "the previous one" with glob('docs/benchmarks/2*.json'), so once
2026-10-04-ml-eval.json (scripts/eval_ml_model.py, no 'phishing' key) sat
in the folder it was the second-newest match, the step raised KeyError and
"Commit results" never ran. These tests run the step's inline script, as
the workflow has it, against a folder holding both kinds of report.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "weekly-benchmark.yml"


def _regression_script() -> str:
    text = WORKFLOW.read_text(encoding="utf-8")
    step = text.split("- name: Detect recall regression", 1)[1]
    body = re.search(r"python3 <<'PY'\n(.*?)\n\s*PY\n", step, re.DOTALL)
    assert body, "the step's inline Python script was not found"
    return textwrap.dedent(body.group(1))


def _fresh(recall: float) -> dict:
    return {"phishing": {"cleanway": {"recall": recall}}, "safe": {"cleanway": {}}}


def _run(tmp_path: Path, reports: dict[str, dict]) -> tuple[subprocess.CompletedProcess, str]:
    bench = tmp_path / "docs" / "benchmarks"
    bench.mkdir(parents=True)
    for name, payload in reports.items():
        (bench / name).write_text(json.dumps(payload), encoding="utf-8")
    output = tmp_path / "github_output"
    output.touch()
    proc = subprocess.run(
        [sys.executable, "-c", _regression_script()],
        cwd=tmp_path, env={**os.environ, "GITHUB_OUTPUT": str(output)},
        capture_output=True, text=True, timeout=30,
    )
    return proc, output.read_text(encoding="utf-8")


def test_an_ml_eval_report_beside_the_runs_is_not_the_previous_run(tmp_path):
    proc, output = _run(tmp_path, {
        "2026-10-04-fresh-urls.json": _fresh(0.98),
        "2026-10-04-ml-eval.json": {"ts": "2026-10-04", "model": {}, "auc": 0.99},
        "2026-10-11-fresh-urls.json": _fresh(0.80),
        "day-one-coverage-2026-10-04.json": {"schema": 1},
        "latest.json": _fresh(0.80),
    })
    assert proc.returncode == 0, proc.stderr
    assert output.strip() == "regression=true", "0.98 -> 0.80 against the previous fresh-URL run"


def test_a_steady_recall_is_no_regression(tmp_path):
    proc, output = _run(tmp_path, {
        "2026-10-04-fresh-urls.json": _fresh(0.98),
        "2026-10-04-ml-eval.json": {"ts": "2026-10-04"},
        "2026-10-11-fresh-urls.json": _fresh(0.97),
    })
    assert proc.returncode == 0, proc.stderr
    assert output.strip() == "regression=false"


def test_the_first_fresh_run_has_nothing_to_compare(tmp_path):
    proc, output = _run(tmp_path, {
        "2026-10-04-ml-eval.json": {"ts": "2026-10-04"},
        "2026-10-11-fresh-urls.json": _fresh(0.97),
    })
    assert proc.returncode == 0, proc.stderr
    assert output.strip() == "regression=false"


def test_the_weekly_run_asks_neither_virustotal_nor_safe_browsing():
    """Both free APIs bar a commercial product (scripts/eval_fresh_urls.py,
    NON_COMMERCIAL_RESOLVERS). The job hands the script neither key and says
    so in the command, so a later change of the script's default cannot bring
    them back unnoticed."""
    text = WORKFLOW.read_text(encoding="utf-8")
    for secret in ("VT_API_KEY", "GOOGLE_SAFE_BROWSING_KEY", "GOOGLE_SAFE_BROWSING_API_KEY", "WEB_RISK_API_KEY"):
        assert f"secrets.{secret}" not in text, secret
    run = text.split("- name: Run benchmark", 1)[1].split("\n      - name:", 1)[0]
    assert "--no-virustotal" in run and "--no-gsb" in run
    assert not re.search(r"--(virustotal|gsb)\b", run), "asks one of them by name"

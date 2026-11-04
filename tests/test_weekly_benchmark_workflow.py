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


def _fresh(recall: float, method_version: int | None = None) -> dict:
    report = {"phishing": {"cleanway": {"recall": recall}}, "safe": {"cleanway": {}}}
    if method_version is not None:
        report["method_version"] = method_version
    return report


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


def test_runs_counted_by_different_methods_are_not_compared(tmp_path):
    """method_version 2 (2026-11-03, scripts/benchmark_method.py) draws a
    different sample and counts dead names for no one: a drop between a
    method 1 run and a method 2 run is the method, not Cleanway. The step
    opened a "recall regression" PR on it (or hid a real drop)."""
    proc, output = _run(tmp_path, {
        "2026-11-01-fresh-urls.json": _fresh(0.93),                    # no method_version: 1
        "2026-11-08-fresh-urls.json": _fresh(0.70, method_version=2),
    })
    assert proc.returncode == 0, proc.stderr
    assert output.strip() == "regression=false"
    assert "method_version" in proc.stdout and "not comparable" in proc.stdout


def test_two_runs_of_the_same_method_are_compared(tmp_path):
    proc, output = _run(tmp_path, {
        "2026-11-01-fresh-urls.json": _fresh(0.93),
        "2026-11-08-fresh-urls.json": _fresh(0.90, method_version=2),
        "2026-11-15-fresh-urls.json": _fresh(0.80, method_version=2),
    })
    assert proc.returncode == 0, proc.stderr
    assert output.strip() == "regression=true"
    proc, output = _run(tmp_path / "v1", {
        "2026-10-25-fresh-urls.json": _fresh(0.98, method_version=1),
        "2026-11-01-fresh-urls.json": _fresh(0.80),                    # absent = 1
    })
    assert output.strip() == "regression=true"


def _counted(tp: int, fn: int, method_version: int | None = 2) -> dict:
    """A report as eval_fresh_urls.py writes it: the counts beside the recall."""
    report = _fresh(tp / (tp + fn), method_version)
    report["phishing"]["cleanway"].update(tp=tp, fn=fn)
    return report


def _method():
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import benchmark_method
    return benchmark_method


def test_the_noise_of_a_100_verdict_week_is_no_regression(tmp_path):
    """Since method_version 2 a week has about 100 verdicts, not about 156.
    Two simulated weeks at the same recall (0.88) then differ by more than 5
    points in about 15% of weeks, and the old rule opened a "recall
    regression" PR each time (review of #395). 92 of 104 (88.5%) and 82 of
    100 (82.0%) are 6.5 points apart, and their 95% intervals overlap."""
    proc, output = _run(tmp_path, {
        "2026-11-08-fresh-urls.json": _counted(92, 12),
        "2026-11-15-fresh-urls.json": _counted(82, 18),
    })
    assert proc.returncode == 0, proc.stderr
    assert output.strip() == "regression=false"


def test_a_drop_past_both_intervals_is_a_regression(tmp_path):
    proc, output = _run(tmp_path, {
        "2026-11-08-fresh-urls.json": _counted(92, 8),     # 92%: 95% CI 85.0–95.9%
        "2026-11-15-fresh-urls.json": _counted(60, 40),    # 60%: 95% CI 50.2–69.1%
    })
    assert proc.returncode == 0, proc.stderr
    assert output.strip() == "regression=true"
    assert "::warning::" in proc.stdout and "50.2–69.1%" in proc.stdout and "85.0–95.9%" in proc.stdout


def test_the_step_states_the_intervals_the_report_states(tmp_path):
    """Its interval is benchmark_method.wilson95 of tp and fn, the report's
    recall_wilson95, printed as the report prints it."""
    method = _method()
    proc, _output = _run(tmp_path, {
        "2026-11-08-fresh-urls.json": _counted(92, 12),
        "2026-11-15-fresh-urls.json": _counted(82, 18),
    })
    for tp, fn in ((92, 12), (82, 18)):
        assert method._interval(method.wilson95(tp, tp + fn)) in proc.stdout, (tp, fn)
    assert "::notice::" in proc.stdout


def test_a_method_1_report_is_compared_by_its_counts_too(tmp_path):
    """Every fresh-URL report since 2026-09 has tp and fn: 145 of 156 on
    2026-11-01 (92.9%) after 163 of 169 (96.4%) is within the noise."""
    proc, output = _run(tmp_path, {
        "2026-10-25-fresh-urls.json": _counted(163, 6, method_version=None),
        "2026-11-01-fresh-urls.json": _counted(145, 11, method_version=None),
    })
    assert proc.returncode == 0, proc.stderr
    assert output.strip() == "regression=false"


def test_a_report_without_counts_falls_back_to_the_five_point_rule(tmp_path):
    proc, output = _run(tmp_path, {
        "2026-11-08-fresh-urls.json": _counted(92, 12),
        "2026-11-15-fresh-urls.json": _fresh(0.80, method_version=2),
    })
    assert proc.returncode == 0, proc.stderr
    assert output.strip() == "regression=true"
    assert "no tp/fn" in proc.stdout


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

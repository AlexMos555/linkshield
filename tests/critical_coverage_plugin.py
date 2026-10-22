"""pytest hook: per-module coverage floors for critical code (see
scripts/check_critical_coverage.py for the list and the rationale).

Imported into tests/conftest.py so CI's existing
`pytest tests/ --cov=api --cov-report=xml --cov-fail-under=50` step enforces
the floors with no workflow change. It only acts when the run asked for a
coverage gate (`--cov-fail-under`): a developer running one test file with
`--cov` is not failed for the modules that file doesn't exercise.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _REPO_ROOT / "scripts" / "check_critical_coverage.py"


def load_checker():
    """scripts/ is not a package: load the checker by path (once)."""
    name = "check_critical_coverage"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses look the module up while executing it
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


def _xml_report_path(cov_plugin) -> "Path | None":
    reports = getattr(cov_plugin.options, "cov_report", None) or {}
    if "xml" not in reports:
        return None
    return Path(reports["xml"] or "coverage.xml")


# tryfirst on a wrapper = outermost, so the code after `yield` runs after
# pytest-cov's own wrapper has stopped coverage and written its reports.
@pytest.hookimpl(wrapper=True, tryfirst=True)
def pytest_runtestloop(session):
    result = yield
    cov_plugin = session.config.pluginmanager.getplugin("_cov")
    if cov_plugin is None or getattr(cov_plugin, "_disabled", True):
        return result
    if getattr(cov_plugin, "cov_controller", None) is None or getattr(cov_plugin, "cov_total", None) is None:
        return result  # xdist worker, or pytest-cov did not report
    # pytest-cov fills cov_fail_under from coverage config (default 0.0) when
    # the flag is absent, so "no gate requested" is falsy, not None.
    if not getattr(cov_plugin.options, "cov_fail_under", None) or session.config.option.collectonly:
        return result

    checker = load_checker()
    xml_path = _xml_report_path(cov_plugin)
    tmp = None
    if xml_path is None or not xml_path.is_file():
        fd, tmp = tempfile.mkstemp(suffix=".xml")
        os.close(fd)
        cov_plugin.cov_controller.cov.xml_report(outfile=tmp)
        xml_path = Path(tmp)
    try:
        results = checker.check(checker.parse_coverage_xml(xml_path, _REPO_ROOT))
    finally:
        if tmp:
            os.unlink(tmp)

    tr = session.config.pluginmanager.getplugin("terminalreporter")
    bad = checker.failures(results)
    if tr is not None:
        tr.write_sep("=", "critical module coverage floors")
        for line in checker.format_report(results):
            tr.write_line(line, red=bool(bad and "<--" in line))
    if bad:
        if tr is not None:
            tr.write_line(
                f"ERROR: {len(bad)} critical module(s) below their coverage floor "
                "(floors: scripts/check_critical_coverage.py)",
                red=True,
                bold=True,
            )
        session.testsfailed += 1  # -> exit code 1, like --cov-fail-under
    return result

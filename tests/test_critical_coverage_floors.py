"""The per-module coverage gate itself (scripts/check_critical_coverage.py)."""
from __future__ import annotations

from pathlib import Path

import pytest

from tests.critical_coverage_plugin import load_checker

REPO = Path(__file__).resolve().parent.parent
ccc = load_checker()


def _xml(tmp_path: Path, source: str, classes: dict) -> Path:
    """classes: filename -> list of (hits, condition) where condition is None or 'a/b'."""
    parts = [f'<?xml version="1.0" ?><coverage><sources><source>{source}</source></sources><packages><package><classes>']
    for filename, lines in classes.items():
        parts.append(f'<class filename="{filename}"><lines>')
        for n, (hits, cond) in enumerate(lines, 1):
            extra = f' branch="true" condition-coverage="x% ({cond})"' if cond else ""
            parts.append(f'<line number="{n}" hits="{hits}"{extra}/>')
        parts.append("</lines></class>")
    parts.append("</classes></package></packages></coverage>")
    p = tmp_path / "coverage.xml"
    p.write_text("".join(parts))
    return p


def test_cover_combines_lines_and_branches_like_coverage_py(tmp_path):
    # 4 lines (3 hit) + 4 branches (1 hit) -> (3 + 1) / 8 = 50%.
    xml = _xml(tmp_path, "/src/api", {"routers/x.py": [(1, "1/2"), (1, "0/2"), (1, None), (0, None)]})
    files = ccc.parse_coverage_xml(xml, REPO)
    assert set(files) == {"api/routers/x.py"}  # container path re-anchored on api/
    assert files["api/routers/x.py"].percent == pytest.approx(50.0)


def test_source_inside_the_repo_resolves_relative_to_it(tmp_path):
    xml = _xml(tmp_path, str(REPO / "api"), {"services/auth.py": [(1, None)]})
    assert set(ccc.parse_coverage_xml(xml, REPO)) == {"api/services/auth.py"}


def test_module_below_its_floor_fails_and_at_floor_passes(tmp_path):
    files = {
        "api/a.py": ccc.FileCoverage("api/a.py", 10, 9, 0, 0),   # 90%
        "api/b.py": ccc.FileCoverage("api/b.py", 10, 8, 0, 0),   # 80%
    }
    results = ccc.check(files, {"api/a.py": 90.0, "api/b.py": 90.0}, {})
    assert [r.path for r in ccc.failures(results)] == ["api/b.py"]
    assert any("below floor" in line for line in ccc.format_report(results))


def test_a_floor_that_matches_nothing_fails_so_renames_cannot_hide_a_module():
    results = ccc.check({}, {"api/renamed.py": 90.0}, {})
    (bad,) = ccc.failures(results)
    assert bad.percent is None
    assert any("not in coverage report" in line for line in ccc.format_report(results))


def test_glob_floors_most_specific_pattern_wins_and_exclusions_are_skipped():
    files = {
        "api/billing/a.py": ccc.FileCoverage("api/billing/a.py", 10, 9, 0, 0),
        "api/billing/store/pg.py": ccc.FileCoverage("api/billing/store/pg.py", 10, 0, 0, 0),
        "api/billing/strict.py": ccc.FileCoverage("api/billing/strict.py", 10, 9, 0, 0),
        "api/other.py": ccc.FileCoverage("api/other.py", 10, 0, 0, 0),
    }
    floors = {"api/billing/*.py": 85.0, "api/billing/strict.py": 95.0}
    results = ccc.check(files, floors, {"api/billing/store/pg.py": "needs postgres"})
    by_path = {r.path: r for r in results}
    assert set(by_path) == {"api/billing/a.py", "api/billing/strict.py"}  # pg excluded, other ungated
    assert by_path["api/billing/a.py"].ok and not by_path["api/billing/strict.py"].ok


def test_empty_module_counts_as_fully_covered():
    assert ccc.FileCoverage("api/__init__.py", 0, 0, 0, 0).percent == 100.0


def test_every_configured_floor_is_a_real_file_or_glob_and_exclusions_exist():
    for pattern in ccc.FLOORS:
        assert list(REPO.glob(pattern.replace("*.py", "**/*.py"))) or (REPO / pattern).is_file(), pattern
        assert 0 < ccc.FLOORS[pattern] <= 100
    for path in ccc.EXCLUDED:
        assert (REPO / path).is_file(), path


def test_cli_exit_codes(tmp_path, capsys):
    assert ccc.main(["x", str(tmp_path / "missing.xml")]) == 2
    xml = _xml(tmp_path, "/src/api", {"routers/x.py": [(1, None)]})
    # The real FLOORS don't match this toy report -> every floor is "missing".
    assert ccc.main(["x", str(xml)]) == 1
    assert "FAIL" in capsys.readouterr().out

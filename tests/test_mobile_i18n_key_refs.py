"""Every key the app asks i18next for is in the mobile files it ships with.

Until 2026-11-02 every namespace of packages/i18n-strings/src was flattened
into mobile/i18n, and scripts/check-mobile-i18n.py looked only at `mobile.*`
references. Now landing.* and email.* stay out of the mobile files
(scripts/i18n_mobile.py: App Review read their VPN strings in the iPhone's
bundle, docs/IOS.md §3.6), while the app reads extension.* too (the
locked-account modal). A reference outside mobile.* that did not resolve
showed the raw key on screen with the check green: t("landing.nav.features")
in AccountLockedModal, or "extension." added to the skipped namespaces.

Pinned here, running a copy of the check over copies of mobile/i18n and the
source, plus one app file written for the case:
  * a reference to a landing.* or email.* key fails by name, although the
    key is in the source;
  * an extension.* reference the mobile files lack fails;
  * extension.* and mobile.* references the files carry pass.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
CHECK = "check-mobile-i18n.py"
DATA = ("mobile/i18n", "packages/i18n-strings/src")


def _check(tmp_path: Path, app_source: str) -> subprocess.CompletedProcess:
    """The check, run over copies of DATA with `app_source` as the only app file."""
    (tmp_path / "scripts").mkdir()
    for path in [SCRIPTS / CHECK, *sorted(SCRIPTS.glob("i18n_*.py"))]:
        shutil.copy(path, tmp_path / "scripts")
    for rel in DATA:
        shutil.copytree(ROOT / rel, tmp_path / rel)
    app_file = tmp_path / "mobile" / "src" / "components" / "Probe.tsx"
    app_file.parent.mkdir(parents=True)
    app_file.write_text(app_source, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(tmp_path / "scripts" / CHECK)],
        capture_output=True, text=True, timeout=120,
    )


def _source_has(key: str) -> bool:
    node = json.loads((ROOT / "packages" / "i18n-strings" / "src" / "en.json").read_text(encoding="utf-8"))
    for part in key.split("."):
        if not isinstance(node, dict) or part not in node:
            return False
        node = node[part]
    return True


def test_references_the_mobile_files_carry_pass(tmp_path):
    source = 't("extension.popup.locked_title");\nt("mobile.home.hero.title_none");\n'
    result = _check(tmp_path, source)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 referenced keys resolve" in result.stdout, result.stdout


@pytest.mark.parametrize("key", ["landing.nav.features", "email.common.unsubscribe_link"])
def test_a_reference_to_a_namespace_left_out_of_the_mobile_files_fails(tmp_path, key):
    assert _source_has(key), f"{key} is not in the source"
    result = _check(tmp_path, f't("{key}");\n')
    assert result.returncode == 1, f"{key} passed: {result.stdout}"
    assert "keeps out of mobile/i18n" in result.stdout, result.stdout
    assert key in result.stdout


def test_an_extension_key_the_mobile_files_lack_fails(tmp_path):
    result = _check(tmp_path, 't("extension.popup.locked_title_v2");\n')
    assert result.returncode == 1, result.stdout
    assert "absent from en.json" in result.stdout
    assert "extension.popup.locked_title_v2" in result.stdout

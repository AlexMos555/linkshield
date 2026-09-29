"""The extension's copy of the server's name-rule data stays in sync.

packages/extension-core/src/utils/scorer-data.js (the brands, official
domains, exemptions, Russian public suffixes and rule constants) and
tests/data/extension_name_rules_parity.tsv (the server's answers the
extension's port is held to by scripts/test-local-scorer.mjs) are generated
by scripts/build_extension_scorer_data.py from api/services/scoring.py. A
change to data/typosquat_targets*.json, data/ru_public_suffixes.json or a
name rule that is not regenerated fails here; one that is regenerated but
not ported to name-rules.js fails the Node table test.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _builder():
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    return importlib.import_module("build_extension_scorer_data")


def test_generated_files_are_up_to_date():
    build = _builder()
    for path, render in build.OUTPUTS:
        assert path.read_text(encoding="utf-8") == render(), (
            f"{path.relative_to(ROOT)} is stale: run python3 scripts/build_extension_scorer_data.py "
            "and bash scripts/build-extensions.sh"
        )


def test_data_carries_every_brand_and_exemption_the_server_uses():
    from api.services import scoring

    data = _builder().scorer_data()
    assert dict(data["targets"]) == dict(scoring.TYPOSQUAT_TARGETS)
    assert [n for n, _ in data["targets"]] == list(scoring.TYPOSQUAT_TARGETS), "order decides which brand is named"
    assert set(data["officialDomains"]) | set(data["unrelatedDomains"]) == set(scoring._BRAND_LEGIT_DOMAINS)
    # Russian brands, their Cyrillic names and both spellings of an IDN domain.
    assert {"sberbank", "gosuslugi", "tinkoff", "wildberries", "сбербанк", "втб"} <= set(dict(data["targets"]))
    assert {"втб.рф", "xn--90ab2c.xn--p1ai", "51gosuslugi.ru", "yandex.kz"} <= set(data["officialDomains"])
    assert {"spb.ru", "gov.ru", "xn--h1aliz.xn--p1acf"} <= set(data["ruPublicSuffixes"])
    assert data["ruWildcardSuffixes"] == ["hosting.myjino.ru", "landing.myjino.ru", "spectrum.myjino.ru", "vps.myjino.ru"]


def test_rule_flags_are_the_servers():
    from api.services import scoring

    data = _builder().scorer_data()
    assert data["ruleFields"] == list(scoring._NameRule._fields)
    for name, (away, home) in data["rules"].items():
        assert tuple(c == "1" for c in away) == tuple(scoring._NAME_RULES[name]), name
        assert tuple(c == "1" for c in home) == tuple(scoring._NAME_RULES_AT_HOME[name]), name


def test_the_data_file_is_a_classic_script_setting_one_global():
    from api.services import scoring

    text = (ROOT / "packages/extension-core/src/utils/scorer-data.js").read_text(encoding="utf-8")
    marker = "root.cleanwayScorerData = "
    body = text[text.index(marker) + len(marker): text.rindex(";\n})")]
    data = json.loads(body)
    assert data == _builder().scorer_data()
    # brand_in_subdomain reads the global brands only: the first globalCount.
    assert [n for n, _ in data["targets"][: data["globalCount"]]] == list(scoring.GLOBAL_TYPOSQUAT_TARGETS)
    assert "import " not in text and "export " not in text, "must stay a classic script (content scripts cannot import)"


def test_parity_table_covers_the_labelled_sets_and_the_reported_hosts():
    rows = [
        line.split("\t")
        for line in (ROOT / "tests/data/extension_name_rules_parity.tsv").read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    by_host = {r[0]: r for r in rows}
    assert len(rows) > 5000
    assert all(len(r) == 7 for r in rows)
    build = _builder()
    for host in build._labelled_hosts():
        assert host in by_host, host
    # The rows the port has to get right, whatever else changes.
    assert by_host["kvs.gov.spb.ru"][1:] == ["-", "-", "-", "0", "1", "gov.spb.ru"]
    assert by_host["sberbamk.ru"][1].startswith("sberbank.ru|")
    assert by_host["vk.com.msk.ru"][3:6] == ["vk", "1", "2"]
    assert by_host["xn--90ab2c.xn--p1ai"][1] == "-"  # втб.рф is VTB's own

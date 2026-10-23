"""The served model reads the data files it was trained on.

Two features come from data files, not from the name: in_top_domains and
is_homograph from data/top_100k.json, and the tenant features
(is_hosting_subdomain, and the label every lexical feature reads) from
data/public_suffixes_in_top.json. When those files were swapped from
Tranco's list to the licensed one (2026-10-23), a model trained on Tranco's
would have scored real sites on inputs it never saw — with no error anywhere.
model_meta.json now records the sha256 of the files the model learned
(feature_data); ml_scorer serves the model those exact copies — the live
files, or their archive in data/feature_data/ — and serves no model at all
(rules only, backend_status 'feature_data_mismatch') when neither is there.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

import api.services.ml_scorer as ml_scorer
from api.services import scoring
from api.services.ml_features import (
    FEATURE_DATA_FILES,
    LIVE_FEATURE_DATA,
    FeatureData,
    archive_path,
    extract_ml_features,
    feature_data_record,
    file_sha256,
    resolve_feature_data,
)

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
META = json.loads((DATA / "model_meta.json").read_text())


# ── The committed model and its files agree ──

def test_the_committed_model_names_feature_files_that_are_in_the_repo():
    """Red on a PR that changes data/top_100k.json or
    data/public_suffixes_in_top.json without a model trained on them and
    without archiving the old ones (scripts/build_top_domains.py does both)."""
    data, where = resolve_feature_data(META, str(DATA))
    assert data is not None, where
    for key, file in FEATURE_DATA_FILES.items():
        sha = META["feature_data"][key]["sha256"]
        assert file_sha256(str(DATA / file)) == sha or file_sha256(archive_path(str(DATA), file, sha)) == sha


def test_the_served_model_is_served_its_feature_data():
    assert ml_scorer.is_serving(), ml_scorer.model_status()
    status = ml_scorer.model_status()
    assert status["loaded"] and status["feature_data_problem"] is None
    data, where = resolve_feature_data(META, str(DATA))
    assert status["feature_data"] == where
    assert set(ml_scorer._feature_data.top_domains) == set(data.top_domains)


def test_every_archived_copy_is_named_by_its_hash():
    """data/feature_data/ may hold a copy no model reads any more: the weekly
    retrain (retrain-ml.yml) writes a model trained on the live files and
    commits only the model files, so the copy the previous model read stays
    until the next list rebuild prunes it (scripts/build_top_domains.py,
    whose output a person commits). Harmless — resolve_feature_data()
    selects by hash — but every file there must BE the copy its name says."""
    archive = DATA / "feature_data"
    if not archive.exists():
        return
    for name in os.listdir(archive):
        stem, sha12, ext = name.rsplit(".", 2)
        assert f"{stem}.{ext}" in FEATURE_DATA_FILES.values(), name
        assert file_sha256(str(archive / name))[:12] == sha12, name


def test_a_list_rebuild_then_the_weekly_retrain_keeps_the_checks_green(tmp_path):
    """The path after a list refresh without a retrain: the rebuild archives
    what the served model reads, the weekly job trains on the live files and
    writes a model_meta.json naming them, and nothing prunes the archive
    (the job commits the three model files only). Every check this file runs
    on the committed tree must hold at each step."""
    import sys

    sys.path.insert(0, str(ROOT / "scripts"))
    import build_top_domains as btd

    data = _copy_world(tmp_path)
    meta_path = data / "model_meta.json"
    meta_path.write_text(json.dumps({"feature_data": feature_data_record(str(data))}))

    def check(meta):
        got, where = resolve_feature_data(meta, str(data))
        assert got is not None, where
        for name in (os.listdir(data / "feature_data") if (data / "feature_data").exists() else []):
            stem, sha12, ext = name.rsplit(".", 2)
            assert file_sha256(str(data / "feature_data" / name))[:12] == sha12
        return where

    # 1. The rebuild: a new top_100k.json, the served model's copy archived.
    new_top = json.loads((data / "top_100k.json").read_text())[:-1] + ["new-name.example"]
    files = {"top_100k.json": json.dumps(new_top, indent=0) + "\n"}
    assert btd.archive_model_feature_data(files, str(data), str(meta_path))
    assert btd.write_all(files, str(data))
    assert "feature_data/top_100k." in check(json.loads(meta_path.read_text()))

    # 2. The weekly retrain: a model trained on the live files.
    meta_path.write_text(json.dumps({"feature_data": feature_data_record(str(data))}))
    where = check(json.loads(meta_path.read_text()))
    assert where == "public_suffixes_in_top.json, top_100k.json"
    assert list((data / "feature_data").iterdir())  # the old copy lingers, harmlessly

    # 3. The next rebuild prunes what no model reads.
    assert btd.prune_feature_archive(str(data), str(meta_path))
    assert not (data / "feature_data").exists()


# ── Selection by hash ──

def _copy_world(tmp_path: Path) -> Path:
    data = tmp_path / "data"
    data.mkdir()
    for file in FEATURE_DATA_FILES.values():
        shutil.copyfile(DATA / file, data / file)
    return data


def test_live_files_are_chosen_when_their_hash_matches(tmp_path):
    data = _copy_world(tmp_path)
    meta = {"feature_data": feature_data_record(str(data))}
    got, where = resolve_feature_data(meta, str(data))
    assert where == "public_suffixes_in_top.json, top_100k.json"
    assert got.top_domains == frozenset(LIVE_FEATURE_DATA.top_domains)


def test_the_archived_copy_is_chosen_after_the_list_moved_on(tmp_path):
    data = _copy_world(tmp_path)
    meta = {"feature_data": feature_data_record(str(data))}
    sha = meta["feature_data"]["top_domains"]["sha256"]
    archived = Path(archive_path(str(data), "top_100k.json", sha))
    archived.parent.mkdir()
    shutil.copyfile(data / "top_100k.json", archived)
    (data / "top_100k.json").write_text(json.dumps(["only-the-new-list.example"]))

    got, where = resolve_feature_data(meta, str(data))
    assert "feature_data/top_100k." in where
    assert {"only-the-new-list.example"}.isdisjoint(got.top_domains)
    assert got.top_domains == frozenset(LIVE_FEATURE_DATA.top_domains)


def test_no_matching_file_means_no_model(tmp_path):
    data = _copy_world(tmp_path)
    meta = {"feature_data": feature_data_record(str(data))}
    (data / "top_100k.json").write_text(json.dumps(["changed.example"]))
    got, why = resolve_feature_data(meta, str(data))
    assert got is None and "top_100k.json" in why
    assert resolve_feature_data({}, str(data))[0] is None  # a meta that records nothing
    meta["feature_data"]["public_suffixes_in_top"]["file"] = "other.json"
    assert resolve_feature_data(meta, str(data))[0] is None


def test_the_record_is_what_training_writes():
    record = feature_data_record(str(DATA), "a source")
    assert set(record) == set(FEATURE_DATA_FILES)
    for key, file in FEATURE_DATA_FILES.items():
        assert record[key]["file"] == file
        assert record[key]["sha256"] == file_sha256(str(DATA / file))
        assert record[key]["source"] == "a source"


# ── The features read the data they are given ──

def test_in_top_domains_and_the_tenant_features_read_the_given_data():
    bare = FeatureData(frozenset(), scoring.HOSTING_PLATFORMS)
    assert extract_ml_features("google.com")["in_top_domains"] == 1.0
    assert extract_ml_features("google.com", bare)["in_top_domains"] == 0.0
    # us.org is a shared suffix only when the data says so.
    with_us_org = FeatureData(frozenset({"us.org"}), scoring.HOSTING_PLATFORMS | {"us.org"})
    assert extract_ml_features("gwcu.us.org", with_us_org)["is_hosting_subdomain"] == 1.0
    assert extract_ml_features("gwcu.us.org", bare)["is_hosting_subdomain"] == 0.0


def test_is_homograph_reads_the_given_top_list():
    host = "xn--wikipedi-86g.org"  # wikipediа.org with a Cyrillic а; not a brand-list name
    assert extract_ml_features(host)["is_homograph"] == 1.0
    assert extract_ml_features(host, FeatureData(frozenset(), scoring.HOSTING_PLATFORMS))["is_homograph"] == 0.0
    assert scoring._check_homograph(host) == "wikipedia.org"


# ── ml_scorer: the right file, or no model ──

@pytest.fixture
def fresh_scorer(monkeypatch, tmp_path):
    """ml_scorer as a new process sees it, reading model_meta.json and the
    feature files from a copy of data/ (the model files are the real ones)."""
    data = _copy_world(tmp_path)
    for name in ("phishing_model.onnx", "phishing_model.cbm"):
        if (DATA / name).exists():
            os.symlink(DATA / name, data / name)
    monkeypatch.setattr(ml_scorer, "_DATA_DIR", str(data))
    monkeypatch.setattr(ml_scorer, "_ONNX_PATH", str(data / "phishing_model.onnx"))
    monkeypatch.setattr(ml_scorer, "_CBM_PATH", str(data / "phishing_model.cbm"))
    monkeypatch.setattr(ml_scorer, "_META_PATH", str(data / "model_meta.json"))
    for name, value in {"_backend": None, "_onnx_session": None, "_onnx_input_name": None, "_cb_model": None,
                        "_feature_names": [], "_model_loaded": False, "_feature_data": None,
                        "_feature_data_problem": None, "_feature_data_source": None}.items():
        monkeypatch.setattr(ml_scorer, name, value)
    return data


def _write_meta(data: Path, feature_data: dict | None):
    meta = {k: v for k, v in META.items() if k != "feature_data"}
    if feature_data is not None:
        meta["feature_data"] = feature_data
    (data / "model_meta.json").write_text(json.dumps(meta))


def test_the_scorer_serves_the_archived_copy(fresh_scorer, monkeypatch):
    import api.services.ml_features as mf

    data = fresh_scorer
    record = feature_data_record(str(data))
    sha = record["top_domains"]["sha256"]
    archived = Path(archive_path(str(data), "top_100k.json", sha))
    archived.parent.mkdir()
    shutil.copyfile(data / "top_100k.json", archived)
    (data / "top_100k.json").write_text(json.dumps(["only-the-new-list.example"]))
    _write_meta(data, record)

    assert ml_scorer.backend_status() in ("onnx", "catboost")
    assert "feature_data/top_100k." in ml_scorer.model_status()["feature_data"]
    # What the scorer hands the extractor (it imports it at call time).
    seen = {}
    original = mf.extract_ml_features

    def spy(domain, data=None):
        seen["data"] = data
        return original(domain, data)

    monkeypatch.setattr(mf, "extract_ml_features", spy)
    assert ml_scorer.ml_predict("google.com") is not None
    assert {"only-the-new-list.example"}.isdisjoint(seen["data"].top_domains)
    assert {"google.com"} <= set(seen["data"].top_domains)


def test_the_scorer_serves_no_model_without_its_feature_data(fresh_scorer, caplog):
    data = fresh_scorer
    record = feature_data_record(str(data))
    (data / "top_100k.json").write_text(json.dumps(["changed.example"]))  # no archive
    _write_meta(data, record)

    assert ml_scorer.backend_status() == "feature_data_mismatch"
    assert ml_scorer.is_serving() is False
    assert ml_scorer.ml_predict("google.com") is None
    status = ml_scorer.model_status()
    assert status["loaded"] is False and "top_100k.json" in status["feature_data_problem"]
    assert any("ML scoring disabled" in r.getMessage() for r in caplog.records)


def test_a_meta_without_feature_data_serves_no_model(fresh_scorer):
    _write_meta(fresh_scorer, None)
    assert ml_scorer.backend_status() == "feature_data_mismatch"
    assert ml_scorer.ml_predict("google.com") is None


def test_rules_still_score_when_the_model_is_not_served(fresh_scorer):
    data = fresh_scorer
    record = feature_data_record(str(data))
    (data / "public_suffixes_in_top.json").write_text("[]")
    _write_meta(data, record)
    score, level, reasons = scoring.calculate_score({"domain": "paypal.account-verify.tk"})
    assert level.value != "safe"
    assert not any(r.signal.startswith("ml_") for r in reasons)

"""features_version 7: platform_abuse_rate and brand_region_number.

platform_abuse_rate gives the model the platform's record when a tenant's
own label says nothing (hp9316.craftum.io, a facebook-* blog): since
version 5 the model reads a tenant by its label and free-hosting phishing
fell from 0.93-0.99 to 0.3-0.8. brand_region_number marks the regional
state-service portal shape (gosuslugi26.ru, 51gosuslugi.ru), which the
2026-10-12 retrain flagged on all 14 held-out portals.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from api.services import ml_features, ml_scorer
from api.services.ml_features import (
    FEATURE_NAMES,
    PLATFORM_ABUSE_RATES,
    STATE_SERVICE_NAMES,
    brand_region_number,
    extract_ml_features,
    platform_abuse_rate,
    platform_of,
)
from api.services.scoring import calculate_score, registrable_domain

ROOT = Path(__file__).resolve().parent.parent
RATES_FILE = ROOT / "data" / "platform_abuse_rates.json"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "ml" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def rates_module():
    return _load("platform_abuse_rates")


@pytest.fixture(scope="module")
def train_model():
    return _load("train_model")


def test_the_new_features_close_the_vector():
    assert FEATURE_NAMES[-2:] == ["platform_abuse_rate", "brand_region_number"]
    assert len(FEATURE_NAMES) == 29


# ── platform_abuse_rate ──

@pytest.mark.parametrize("host, platform", [
    ("gedivan.duckdns.org", "duckdns.org"),
    ("hp9316.craftum.io", "craftum.io"),
    ("facebook-login.blogspot.com", "blogspot.com"),
    ("www.foo.github.io", "github.io"),
    ("evil.s3.amazonaws.com", "s3.amazonaws.com"),
    ("nas.ddns.net", "ddns.net"),
])
def test_a_platforms_customer_has_its_platform(host, platform):
    assert platform_of(host) == platform


@pytest.mark.parametrize("host", [
    "example.com", "www.example.com", "kvs.gov.spb.ru", "bbc.co.uk",
    "duckdns.org", "www.duckdns.org", "github.io", "app.netlify.com", "94.183.174.80",
])
def test_no_platform_no_rate(host):
    assert platform_of(host) is None
    assert platform_abuse_rate(host) == 0.0
    assert extract_ml_features(host)["platform_abuse_rate"] == 0.0


def test_the_rate_is_the_files(monkeypatch):
    monkeypatch.setitem(PLATFORM_ABUSE_RATES, "craftum.io", 3.25)
    assert platform_abuse_rate("hp9316.craftum.io") == 3.25
    assert extract_ml_features("hp9316.craftum.io")["platform_abuse_rate"] == 3.25
    monkeypatch.delitem(PLATFORM_ABUSE_RATES, "craftum.io")
    assert platform_abuse_rate("hp9316.craftum.io") == 0.0   # a platform without phishing


def test_the_shipped_file_is_well_formed():
    doc = json.loads(RATES_FILE.read_text())
    assert doc["_meta"]["smoothing"] > 0
    rates = doc["rates"]
    assert rates and all(isinstance(v, float) and v > 0 for v in rates.values())
    assert set(doc["counts_phishing_tranco"]) == set(rates) == set(doc["phishing_hosts"])
    for platform, (phish, tranco) in doc["counts_phishing_tranco"].items():
        assert rates[platform] == round(phish / (tranco + doc["_meta"]["smoothing"]), 4)
        assert len(doc["phishing_hosts"][platform]) == phish
        assert all(platform_of(h) == platform for h in doc["phishing_hosts"][platform])
        # every key is a platform the feature can find
        assert platform_of(f"tenant-name.{platform}") == platform, platform
    assert ml_features.load_platform_abuse_rates(str(RATES_FILE)) == PLATFORM_ABUSE_RATES


def test_the_model_was_trained_on_the_shipped_rates(rates_module):
    """The rates are part of the model: refreshing the file without a
    retrain serves values the model never saw."""
    meta = json.loads((ROOT / "data" / "model_meta.json").read_text())
    assert meta["platform_abuse_rates_sha256"] == rates_module.file_sha256(str(RATES_FILE))


def test_a_missing_file_leaves_every_rate_zero(tmp_path):
    assert ml_features.load_platform_abuse_rates(str(tmp_path / "nope.json")) == {}
    (tmp_path / "bad.json").write_text("{\"rates\": [1, 2]}")
    assert ml_features.load_platform_abuse_rates(str(tmp_path / "bad.json")) == {}


def test_compute_counts_unique_hosts_per_platform(rates_module):
    phishing = [
        "a.duckdns.org", "a.duckdns.org", "b.duckdns.org", "c.duckdns.org",   # 3 hosts
        "x.craftum.io",
        "evil.example.com", "94.183.174.80",                                  # no platform
        "held.github.io",                                                     # held out below
    ]
    benign = ["home.duckdns.org", "www.foo.github.io", "bar.github.io", "example.com"]
    held = frozenset({registrable_domain("held.github.io")})
    rates, counts, hosts = rates_module.compute(phishing, benign, held, smoothing=10)
    assert counts == {"duckdns.org": [3, 1], "craftum.io": [1, 0]}
    assert rates == {"duckdns.org": round(3 / 11, 4), "craftum.io": 0.1}
    assert hosts == {"craftum.io": ["x.craftum.io"], "duckdns.org": ["a.duckdns.org", "b.duckdns.org", "c.duckdns.org"]}


DOC = {
    "_meta": {"smoothing": 10},
    "rates": {"duckdns.org": round(3 / 11, 4), "craftum.io": 0.1},
    "counts_phishing_tranco": {"duckdns.org": [3, 1], "craftum.io": [1, 0]},
    "phishing_hosts": {"duckdns.org": ["a.duckdns.org", "b.duckdns.org", "c.duckdns.org"], "craftum.io": ["x.craftum.io"]},
}


@pytest.mark.parametrize("host, rate", [
    ("a.duckdns.org", round(2 / 11, 4)),   # its own host left out
    ("x.craftum.io", 0.0),                  # the platform's only phishing host
    ("z.duckdns.org", None),                # not counted: serving's rate stands
    ("example.com", None),
])
def test_a_training_host_is_left_out_of_its_own_platforms_rate(rates_module, host, rate):
    """Every phishing tenant in the feed is counted in its own platform's
    rate; trained on that, the model learned 'no phishing on record means
    benign' and scored secure-login.wasmer.app 0.05."""
    assert rates_module.leave_one_out(host, DOC) == rate


def test_training_rows_get_the_left_out_rate(train_model, monkeypatch):
    monkeypatch.setitem(PLATFORM_ABUSE_RATES, "duckdns.org", DOC["rates"]["duckdns.org"])
    monkeypatch.setitem(PLATFORM_ABUSE_RATES, "craftum.io", 0.1)
    hosts, rows = train_model.build_feature_matrix(["a.duckdns.org", "x.craftum.io", "z.duckdns.org", "example.com"])
    col = FEATURE_NAMES.index("platform_abuse_rate")
    assert [r[col] for r in rows] == [DOC["rates"]["duckdns.org"], 0.1, DOC["rates"]["duckdns.org"], 0.0]
    assert train_model.leave_own_host_out(hosts, rows, DOC) == 2
    assert [r[col] for r in rows] == [round(2 / 11, 4), 0.0, DOC["rates"]["duckdns.org"], 0.0]


def test_feed_and_tranco_readers(rates_module, tmp_path):
    (tmp_path / "phishtank.csv").write_text(
        "url\nhttp://A.duckdns.org/x\nhttps://a.duckdns.org/y\nhttp://94.183.174.80:80/i\nnot a url\n")
    (tmp_path / "top-1m-subdomains.csv").write_text("1,google.com\n2,Foo.GitHub.io\nbad line\n")
    assert rates_module.feed_hosts(str(tmp_path / "phishtank.csv")) == ["a.duckdns.org", "94.183.174.80"]
    assert rates_module.tranco_hosts(str(tmp_path / "top-1m-subdomains.csv")) == ["google.com", "foo.github.io"]
    out = tmp_path / "rates.json"
    rates = rates_module.refresh(str(tmp_path), frozenset(), str(out))
    assert rates == {"duckdns.org": 0.1}
    assert json.loads(out.read_text())["rates"] == rates


def test_training_keeps_the_committed_rates(train_model, tmp_path, monkeypatch):
    """A retrain that commits only the model must not change the rates it
    is served with, so training reads the committed file unless asked."""
    path = tmp_path / "rates.json"
    path.write_text(json.dumps({"rates": {"duckdns.org": 7.5}}))
    monkeypatch.setattr(train_model, "PLATFORM_ABUSE_RATES_PATH", str(path))
    called = []

    def fake_refresh(data_dir, held_out, out_path):
        called.append(out_path)
        Path(out_path).write_text(json.dumps({"rates": {}}))

    monkeypatch.setattr(train_model.platform_abuse_rates, "refresh", fake_refresh)
    monkeypatch.setattr(train_model, "reload_platform_abuse_rates", lambda: None)
    sha = train_model.ensure_platform_abuse_rates(frozenset())
    assert called == [] and len(sha) == 64
    assert json.loads(path.read_text())["rates"] == {"duckdns.org": 7.5}
    train_model.ensure_platform_abuse_rates(frozenset(), refresh=True)
    assert called == [str(path)]
    path.unlink()
    train_model.ensure_platform_abuse_rates(frozenset())
    assert called == [str(path)] * 2   # a missing file is computed


# ── brand_region_number ──

def test_the_state_service_names_come_from_the_brand_file():
    assert STATE_SERVICE_NAMES == {"gosuslugi", "госуслуги"}


@pytest.mark.parametrize("host", [
    "gosuslugi26.ru", "51gosuslugi.ru", "44gosuslugi.ru", "gosuslugi92.ru", "26gosuslugi.ru",
    "www.gosuslugi86.ru", "new.gosuslugi86.ru", "gosuslugi7.ru", "gosuslugi05.ru",
    "госуслуги74.рф".encode("idna").decode("ascii"),
])
def test_a_regional_portal_shape(host):
    assert brand_region_number(host) == 1.0
    assert extract_ml_features(host)["brand_region_number"] == 1.0


@pytest.mark.parametrize("host", [
    "gosuslugi.ru", "gosuslugi-26.ru", "gosuslugi100.ru", "gosuslugi00.ru", "gosuslugi0.ru",
    "gosuslugi26-vhod.ru", "vhod-gosuslugi26.ru", "gosuslugi26.tw1.ru", "gosuslugi26.github.io",
    "sberbank24.ru", "mfc66.ru", "26.ru", "example.com", "gosuslugl26.ru",
])
def test_not_the_shape(host):
    assert brand_region_number(host) == 0.0


def test_the_verified_portals_exclude_the_held_out_ones(train_model):
    held_out = train_model.load_held_out()
    portals = train_model.verified_regional_portals(held_out)
    assert portals == ["26gosuslugi.ru", "gosuslugi29.ru", "gosuslugi71.ru"]
    assert all(registrable_domain(p) not in held_out for p in portals)
    assert "gosuslugi26.ru" in train_model.verified_regional_portals(frozenset())


# ── The scorer does not let the model alone flag the shape ──

@pytest.fixture
def ml_says(monkeypatch):
    def set_prob(p):
        monkeypatch.setattr(ml_scorer, "ml_predict", lambda d: {
            "phishing_probability": p, "confidence": abs(p - 0.5) * 2, "prediction": "phishing", "backend": "x"})
    return set_prob


@pytest.mark.parametrize("host", ["gosuslugi26.ru", "51gosuslugi.ru", "gosuslugi29.ru"])
def test_the_model_is_not_what_flags_a_regional_portal(host, ml_says):
    ml_says(0.97)
    _, level, reasons = calculate_score({"domain": host, "raw_url": host})
    assert not [r for r in reasons if r.signal.startswith("ml_")]
    assert level.value == "safe"


def test_an_unofficial_portal_shape_is_still_judged_by_the_name_rules(ml_says):
    ml_says(0.97)
    _, level, reasons = calculate_score({"domain": "gosuslugi77.ru", "raw_url": "gosuslugi77.ru"})
    assert "typosquatting" in {r.signal for r in reasons}
    assert level.value != "safe"


def test_other_names_keep_the_models_weight(ml_says):
    ml_says(0.97)
    _, _, reasons = calculate_score({"domain": "gosuslugi-vhod.ru", "raw_url": "gosuslugi-vhod.ru"})
    assert "ml_high_risk" in {r.signal for r in reasons}

"""The model is served the vector it was trained on — features_version 5.

Training (ml/train_model.py) and serving (api.services.ml_scorer) both call
api.services.ml_features.extract_ml_features, but "both call the same
function" is a claim, not a check. These tests hold it three ways: the row
training builds for a host is the exact vector the server hands the model
for it; the shipped model's metadata and ONNX input match FEATURE_NAMES;
and the logged feature row (url_features.extract_features) gives the
structural features the model's values.

They also pin what version 4 changed: dot_count, subdomain_depth,
name_length, in_top_domains and the name the lexical features read are
counted from the PSL registrable domain (kvs.gov.spb.ru was three levels
under 'spb', and borrowed spb.ru's Tranco rank), and max_brand_similarity
reads the Russian brands. And what version 5 changed: a tenant of any shared
suffix the scorer knows (ledgerlogin-home.wasmer.app, abc.tw1.ru) is read by
the tenant's own label, where version 4 knew 26 platforms. And they pin the
training data rules: names before IP literals, the host-shape stratum with
its tenants, and the evaluation sets held out.

catboost and scikit-learn are not installed in CI; ml/train_model.py
imports them inside train(), so everything here runs without them.
"""
from __future__ import annotations

import importlib.util
import json
import os
from difflib import SequenceMatcher
from pathlib import Path

import pytest

import api.services.ml_scorer as ml_scorer
from api.services.ml_features import FEATURE_NAMES, extract_ml_features, host_shape, shared_tenant
from api.services.scoring import TYPOSQUAT_TARGETS, registrable_domain
from api.services.url_features import FEATURES_VERSION, _max_brand_similarity, extract_features

ROOT = Path(__file__).resolve().parent.parent
META = json.loads((ROOT / "data" / "model_meta.json").read_text())

HOSTS = [
    "kvs.gov.spb.ru", "zenit.kfis.gov.spb.ru", "herzen.spb.ru", "museum.vladimir.ru",
    "idg.chph.ras.ru", "bbc.co.uk", "www.bbc.co.uk", "example.com", "www.example.com",
    "paypal.account-verify.tk", "sberbamk.ru", "xn--80aswg.xn--p1ai", "foo.github.io",
    "94.183.174.80", "login.microsoftonline.com.evil.xyz", "localhost",
    # tenants of shared suffixes outside the 26 platforms version 4 knew
    "ledgerlogin-home.wasmer.app", "www.robinhoodlogin.webador.com", "facebook.github.io",
    "abc.tw1.ru", "evil.s3.amazonaws.com",
]


@pytest.fixture(scope="module")
def train_model():
    spec = importlib.util.spec_from_file_location("train_model", ROOT / "ml" / "train_model.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ── Training and serving build the same vector ──

def test_training_rows_are_what_the_server_feeds_the_model(train_model, monkeypatch):
    assert ml_scorer._load_model(), "the served model must load for this check"
    served: dict[str, list[float]] = {}
    current: list[str] = []

    def capture(vector):
        served[current[0]] = list(vector)
        return 0.5

    monkeypatch.setattr(ml_scorer, "_predict_proba_onnx", capture)
    monkeypatch.setattr(ml_scorer, "_predict_proba_catboost", capture)
    for host in HOSTS:
        current[:] = [host]
        assert ml_scorer.ml_predict(host) is not None

    kept, rows = train_model.build_feature_matrix(HOSTS)
    assert kept == HOSTS
    for host, row in zip(kept, rows):
        assert row == served[host], host


def test_training_and_serving_import_one_extractor(train_model):
    assert train_model.extract_ml_features is extract_ml_features
    assert train_model.FEATURE_NAMES is FEATURE_NAMES


def test_shipped_model_metadata_matches_the_extractor():
    assert META["feature_names"] == FEATURE_NAMES
    assert META["n_features"] == len(FEATURE_NAMES) == 27
    assert META["features_version"] == FEATURES_VERSION == 5


def test_onnx_input_is_as_wide_as_the_feature_vector():
    ort = pytest.importorskip("onnxruntime")
    session = ort.InferenceSession(str(ROOT / "data" / "phishing_model.onnx"), providers=["CPUExecutionProvider"])
    assert session.get_inputs()[0].shape[-1] == len(FEATURE_NAMES)


# The logged row keeps its own lexical features (on the registered name, not
# a hosting tenant's label), so only the ones defined identically are held;
# for a tenant that leaves out max_brand_similarity too.
_SHARED_WITH_THE_LOG = (
    "domain_length", "name_length", "dot_count", "hyphen_count", "special_char_count",
    "subdomain_depth", "has_fake_tld_subdomain", "is_url_shortener", "tld_high_risk",
    "tld_medium_risk", "in_top_domains", "max_brand_similarity",
)


@pytest.mark.parametrize("host", HOSTS)
def test_logged_structure_is_the_models_structure(host):
    model = extract_ml_features(host)
    logged = extract_features(host, {"domain": host})
    tenant = shared_tenant(host)[0] is not None
    for key in _SHARED_WITH_THE_LOG:
        if tenant and key == "max_brand_similarity":
            continue
        assert logged[key] == model[key], (host, key)


# ── features_version 4: the structure is read against the PSL ──

@pytest.mark.parametrize("host, registrable, name, subdomains", [
    ("kvs.gov.spb.ru", "gov.spb.ru", "gov", ["kvs"]),
    ("zenit.kfis.gov.spb.ru", "gov.spb.ru", "gov", ["zenit", "kfis"]),
    ("herzen.spb.ru", "herzen.spb.ru", "herzen", []),
    ("idg.chph.ras.ru", "chph.ras.ru", "chph", ["idg"]),
    ("bbc.co.uk", "bbc.co.uk", "bbc", []),
    ("www.bbc.co.uk", "bbc.co.uk", "bbc", ["www"]),
    ("paypal.account-verify.tk", "account-verify.tk", "account-verify", ["paypal"]),
])
def test_host_shape_counts_from_the_registrable_domain(host, registrable, name, subdomains):
    assert host_shape(host) == (registrable, name, subdomains)


@pytest.mark.parametrize("host, dots, depth, name_length", [
    ("example.com", 1, 0, 7),
    ("www.example.com", 2, 1, 7),
    ("herzen.spb.ru", 1, 0, 6),         # was 2 dots, depth 1, name 'spb'
    ("kvs.gov.spb.ru", 2, 1, 3),        # was 3 dots, depth 2
    ("zenit.kfis.gov.spb.ru", 3, 2, 3),  # was 4 dots, depth 3
    ("bbc.co.uk", 1, 0, 3),             # was 2 dots, depth 1, name 'co'
    ("94.183.174.80", 3, 2, 3),         # an IP literal reads as before
    ("localhost", 0, 0, 9),
])
def test_dots_and_depth_are_counted_above_the_public_suffix(host, dots, depth, name_length):
    f = extract_ml_features(host)
    assert (f["dot_count"], f["subdomain_depth"], f["name_length"]) == (dots, depth, name_length)


def test_a_name_under_a_regional_zone_is_read_as_its_own_name():
    """user_part was 'spb' for every *.spb.ru host, so all of them had one
    entropy, one bigram score, one brand similarity."""
    herzen, metro = extract_ml_features("herzen.spb.ru"), extract_ml_features("metro.spb.ru")
    assert herzen["user_part_length"] == 6 and metro["user_part_length"] == 5
    assert herzen["shannon_entropy"] != metro["shannon_entropy"]


def test_a_name_under_a_zone_does_not_borrow_the_zones_rank():
    assert "spb.ru" in ml_scorer_top_domains()
    assert extract_ml_features("kvs.gov.spb.ru")["in_top_domains"] == 0.0
    assert extract_ml_features("herzen.spb.ru")["in_top_domains"] == 0.0


def test_a_country_site_on_a_compound_suffix_keeps_its_rank():
    assert "bbc.co.uk" in ml_scorer_top_domains()
    assert extract_ml_features("bbc.co.uk")["in_top_domains"] == 1.0


def ml_scorer_top_domains():
    from api.services.scoring import TOP_DOMAINS
    return TOP_DOMAINS


@pytest.mark.parametrize("host, expected", [
    ("paypal-login.spb.ru", 1.0),        # was 'spb' to the last-two-labels rule
    ("vk-login.nov.ru", 1.0),
    ("bank-login.co.uk", 1.0),           # was 'co'
    ("paypal-login.com", 1.0),
    ("login.example.com", 0.0),          # a subdomain word, as before
    ("herzen.spb.ru", 0.0),
])
def test_the_keyword_feature_reads_the_registered_name(host, expected):
    assert extract_ml_features(host)["has_suspicious_keyword"] == expected


def test_hosting_tenants_still_read_the_tenants_label():
    f = extract_ml_features("paypal-login.github.io")
    assert f["is_hosting_subdomain"] == 1.0
    assert f["user_part_length"] == len("paypal-login")
    assert f["has_suspicious_keyword"] == 1.0   # was 0: version 4 read 'github'
    assert f["in_top_domains"] == 0.0


# ── features_version 5: a tenant of any shared suffix the scorer knows ──

@pytest.mark.parametrize("host, suffix, label", [
    ("ledgerlogin-home.wasmer.app", "wasmer.app", "ledgerlogin-home"),   # a PSL suffix in the Tranco top-100k
    ("www.robinhoodlogin.webador.com", "webador.com", "robinhoodlogin"),  # the label under the suffix, not 'www'
    ("abc.tw1.ru", "tw1.ru", "abc"),                                    # data/hosting_platforms.json
    ("evil.s3.amazonaws.com", "s3.amazonaws.com", "evil"),              # a three-label platform (version 4 read 'amazonaws')
    ("x.blob.core.windows.net", "blob.core.windows.net", "x"),
    ("foo.github.io", "github.io", "foo"),
    ("www.foo.github.io", "github.io", "foo"),
    ("gwcu.us.org", "us.org", "gwcu"),
])
def test_a_tenant_is_read_by_its_own_label(host, suffix, label):
    assert shared_tenant(host) == (suffix, label)
    f = extract_ml_features(host)
    assert f["is_hosting_subdomain"] == 1.0
    assert f["user_part_length"] == len(label)
    assert f["in_top_domains"] == 0.0


@pytest.mark.parametrize("host", [
    "kvs.gov.spb.ru", "herzen.spb.ru",        # spb.ru is a registry zone registrable_domain() reads
    "a.hosting.myjino.ru",                    # a PSL wildcard rule, read by host_shape
    "bbc.co.uk", "www.bbc.co.uk", "amazon.co.jp",
    "github.io", "www.github.io", "app.netlify.com",   # the platform's own hosts
    "docs.google.com", "forms.yandex.ru",     # user-content services: the name is the service's
    "www.example.com", "login.microsoftonline.com.evil.xyz", "paypal.account-verify.tk",
    "94.183.174.80", "localhost",
])
def test_a_registered_name_or_its_subdomain_is_not_a_tenant(host):
    assert shared_tenant(host) == (None, None)
    assert extract_ml_features(host)["is_hosting_subdomain"] == 0.0


def test_the_tenant_feature_knows_every_suffix_the_scorer_does():
    from api.services.hosting_platforms import TENANT_SUFFIXES
    from api.services.scoring import HOSTING_PLATFORMS, PUBLIC_SUFFIXES_IN_TOP, _SCORER_SHARED_SUFFIXES

    assert HOSTING_PLATFORMS <= _SCORER_SHARED_SUFFIXES
    assert set(PUBLIC_SUFFIXES_IN_TOP) <= _SCORER_SHARED_SUFFIXES
    assert len(_SCORER_SHARED_SUFFIXES | TENANT_SUFFIXES) == META["shared_suffixes"]
    for suffix in sorted(HOSTING_PLATFORMS | TENANT_SUFFIXES):
        if suffix.startswith("www.") or suffix in {"docs.google.com", "forms.google.com", "sites.google.com"}:
            continue  # operator and user-content hosts are not tenant suffixes
        assert shared_tenant(f"tenant-name.{suffix}")[0] == suffix, suffix


def test_the_lexical_features_read_the_tenants_label():
    """'wasmer' was the name of every site on wasmer.app; now each tenant has
    its own entropy, bigram score and brand similarity."""
    a, b = extract_ml_features("ledgerlogin-home.wasmer.app"), extract_ml_features("sberbank-online.wasmer.app")
    assert a["shannon_entropy"] != b["shannon_entropy"]
    assert b["max_brand_similarity"] == _max_brand_similarity("sberbank-online")
    assert extract_ml_features("secure-login.wasmer.app")["has_suspicious_keyword"] == 1.0
    assert extract_ml_features("wasmer.app")["has_suspicious_keyword"] == 0.0


def test_the_logged_row_does_not_give_a_tenant_its_platforms_rank():
    from api.services.scoring import TOP_DOMAINS

    assert "github.io" in TOP_DOMAINS
    assert extract_features("facebook.github.io", {})["in_top_domains"] == 0.0
    assert extract_features("github.io", {})["in_top_domains"] == 1.0


# ── max_brand_similarity reads the Russian brands ──

@pytest.mark.parametrize("name", ["sberbamk", "wildberies", "gosuslugl", "tinkof", "paypa1", "example"])
def test_brand_similarity_is_the_best_ratio_over_every_brand(name):
    expected = max(SequenceMatcher(None, name, b).ratio() for b in TYPOSQUAT_TARGETS if b != name)
    assert _max_brand_similarity(name) == round(expected, 3)


def test_a_russian_brand_typo_is_close_to_its_brand():
    assert _max_brand_similarity("sberbamk") >= 0.85
    assert _max_brand_similarity("wildberies") >= 0.9


def test_a_punycode_name_is_compared_in_the_script_it_spells():
    punycode = "сбербамк".encode("idna").decode("ascii")
    assert punycode.startswith("xn--")
    assert _max_brand_similarity(punycode) == _max_brand_similarity("сбербамк") >= 0.85


def test_the_brands_own_name_is_not_a_feature():
    assert _max_brand_similarity("sberbank") < 1.0


# ── The training data ──

def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def data_dir(tmp_path, train_model, monkeypatch):
    monkeypatch.setattr(train_model, "DATA_DIR", str(tmp_path))
    _write(tmp_path / "phishtank.csv", "\n".join([
        "url",
        "http://94.183.174.80:4000/i",
        "http://110.36.2.23/bin.sh",
        "https://paypal.account-verify.tk/login",
        "https://94.183.174.80/other",
        "https://evil.gov.spb.ru/x",
        "https://sberbamk.ru/",
        "http://[2001:db8::1]/i",
    ]) + "\n")
    _write(tmp_path / "top-1m.csv", "\n".join(
        [f"{i},famous{i}.com" for i in range(1, 41)]
        + [f"{10000 + i},tail{i}.org" for i in range(1, 121)]
        + ["20001,gov.spb.ru", "20002,paypal.account-verify.tk"]
    ) + "\n")
    _write(tmp_path / "top-1m-subdomains.csv", "\n".join(
        [f"{i},www.site{i}.com" for i in range(1, 61)]
        + [f"{100 + i},x{i}.spb.ru" for i in range(1, 11)]
        + [
            "200,1.2.3.4.in-addr.arpa",       # reverse DNS
            "201,someone.github.io",          # a hosting tenant
            "202,a.b.c.deep.com",             # three levels under deep.com
            "203,budget.gov.spb.ru",          # held out with kvs.gov.spb.ru
            "204,site1.com",                  # an apex, not a subdomain shape
            "205,malsup.github.io",           # tenants of the curated platforms
            "206,www.foo.github.io",          # two labels under the suffix: allowed
            "207,blog.wordpress.com",
            "208,a.b.foo.github.io",          # three labels under the suffix
            "209,forms.yandex.ru",            # a user-content host, not a tenant
            "210,x.wasmer.app",               # a PSL suffix, not a curated platform
        ]
    ) + "\n")
    return tmp_path


TENANT_FIXTURES = {"someone.github.io", "malsup.github.io", "www.foo.github.io", "blog.wordpress.com"}


def test_phishing_names_come_before_ip_literals(train_model, data_dir):
    hosts = train_model.load_phishing_domains(10)
    assert hosts == ["paypal.account-verify.tk", "evil.gov.spb.ru", "sberbamk.ru",
                     "94.183.174.80", "110.36.2.23", "2001:db8::1"]
    assert train_model.load_phishing_domains(2) == ["paypal.account-verify.tk", "evil.gov.spb.ru"]


def test_held_out_hosts_never_reach_either_class(train_model, data_dir):
    held_out = frozenset({registrable_domain("kvs.gov.spb.ru")})
    phishing = train_model.load_phishing_domains(10, held_out)
    assert "evil.gov.spb.ru" not in phishing
    benign = train_model.load_benign_domains(40, exclude=phishing, held_out=held_out)
    assert not [d for d in benign if registrable_domain(d) == "gov.spb.ru"]
    assert "paypal.account-verify.tk" not in benign


def test_the_benign_class_has_host_shapes(train_model, data_dir):
    benign = train_model.load_benign_domains(40, held_out=frozenset({"gov.spb.ru"}))
    assert len(benign) == 40
    shapes = [d for d in benign if d.startswith("www.site") or d.endswith(".spb.ru")]
    assert len(shapes) == int(40 * train_model.SHAPE_SHARE)
    zone = [d for d in shapes if d.endswith(".spb.ru")]
    assert 1 <= len(zone) <= int(len(shapes) * train_model.RU_ZONE_SHARE_OF_SHAPES)
    tenants = [d for d in benign if d in TENANT_FIXTURES]
    assert len(tenants) == int(40 * train_model.TENANT_SHARE)   # on top of the shapes
    for bad in ("1.2.3.4.in-addr.arpa", "a.b.c.deep.com", "budget.gov.spb.ru", "site1.com",
                "a.b.foo.github.io", "forms.yandex.ru", "x.wasmer.app"):
        assert bad not in benign


def test_the_tenant_pool_is_capped_per_platform(train_model, data_dir):
    import random

    _, _, tenants = train_model._shape_pool(
        train_model._read_tranco(str(data_dir / "top-1m-subdomains.csv")), set(), frozenset())
    assert set(tenants) == TENANT_FIXTURES
    pool = train_model._cap_per_platform(tenants, random.Random(0))
    assert sorted(pool) == sorted(tenants)   # under the cap, every tenant is in the pool
    cap = train_model.TENANTS_PER_PLATFORM
    train_model.TENANTS_PER_PLATFORM = 1
    try:
        pool = train_model._cap_per_platform(tenants, random.Random(0))
    finally:
        train_model.TENANTS_PER_PLATFORM = cap
    assert len(pool) == 2 and "blog.wordpress.com" in pool and sum(h.endswith(".github.io") for h in pool) == 1


def test_a_retrain_without_the_subdomain_list_stops(train_model, data_dir):
    (data_dir / "top-1m-subdomains.csv").unlink()
    with pytest.raises(FileNotFoundError, match="refresh_training_feeds"):
        train_model.load_benign_domains(40)


def test_the_evaluation_sets_are_held_out(train_model):
    held_out = train_model.load_held_out()
    for host in ("kvs.gov.spb.ru", "ako.ru", "museum.vladimir.ru", "sberbank-online.msk.ru", "adm44.ru"):
        assert registrable_domain(host) in held_out, host
    assert all(os.path.exists(p) for p in train_model.HELD_OUT_FILES)

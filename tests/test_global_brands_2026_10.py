"""Global brands added on 2026-10-05 with a measured false-positive pass
(data/typosquat_targets.json 'measured'; docs/benchmarks/2026-10-05-global-brands.md).

Most phishing in the 2026-10-04 PhishTank week imitated brands the global
list did not have: allegro.<random>.sbs and allegrolokalnie.<random>.cfd
(162 of 612 hosts), olx.<random>.shop, xfinity and AT&T pages on site
builders, mbway.online. These tests pin what the new names catch, and what
the pass cleared before they shipped:

  - the brands' own other domains (olx.ua, att.net, comcast.net, kucoin.plus)
    and other owners' sites of the same shape (dfinity.org, correos.es,
    allegro.cc), listed with their evidence in the Russian file's format;
  - the slip rule for the new names: under 8 letters one substitution has to
    be a slip of the hand, so nfinity.com, myway.com and comcash.com are not
    typos of xfinity, mbway and comcast;
  - 'trezor' is a shared name (the Czech word for a safe): trezor.cz sells
    safes, trezor.top is still TLD confusion;
  - the ML similarity feature leaves the new names out until a retrain.
"""
from __future__ import annotations

import json
from difflib import SequenceMatcher
from pathlib import Path

import pytest

from api.services import ru_brands, scoring
from api.services.scoring import (
    GLOBAL_TYPOSQUAT_TARGETS,
    MEASURED_GLOBAL_GROUPS,
    TYPOSQUAT_TARGETS,
    _check_brand_in_subdomain,
    _check_brand_on_hosting_tenant,
    _check_typosquatting_v2,
    calculate_score,
)
from api.services.url_features import _max_brand_similarity

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "typosquat_targets.json"
NEW_NAMES = {
    "allegro", "allegrolokalnie", "olx", "xfinity", "comcast", "att", "bellsouth", "nubank",
    "correios", "pichincha", "novobanco", "mbway", "kucoin", "trezor",
}
_BRAND_SIGNALS = {"typosquatting", "homograph_attack", "brand_subdomain_abuse"}


@pytest.fixture
def no_ml(monkeypatch):
    import api.services.ml_scorer as ml_scorer
    monkeypatch.setattr(ml_scorer, "ml_predict", lambda domain: None)


# ── The data file ──

def test_the_measured_brands_load_and_join_the_global_list():
    raw = json.loads(DATA.read_text(encoding="utf-8"))
    groups = tuple(ru_brands.parse_group(k, v) for k, v in raw["measured"].items() if not k.startswith("_"))
    assert groups == MEASURED_GLOBAL_GROUPS
    names = {n for g in groups for n in g.names}
    assert names == NEW_NAMES == set(scoring._NOT_IN_MODEL)
    for g in groups:
        for name, domain in g.names.items():
            assert GLOBAL_TYPOSQUAT_TARGETS[name] == TYPOSQUAT_TARGETS[name] == domain
    # The 125 names before this pass are untouched.
    assert len(GLOBAL_TYPOSQUAT_TARGETS) == 125 + len(NEW_NAMES)


def test_every_measured_brand_cites_the_week_and_every_exemption_its_evidence():
    raw = json.loads(DATA.read_text(encoding="utf-8"))["measured"]
    sources = raw["_sources"]
    for key, group in raw.items():
        if key.startswith("_"):
            continue
        assert group["fraud"] and set(group["fraud"]) <= set(sources), key
        for field in ("official", "unrelated", "not_typos", "shared_name"):
            for item, why in group.get(field, {}).items():
                assert why.strip(), (key, field, item)


def test_a_malformed_measured_entry_leaves_the_flat_list_working(tmp_path, monkeypatch):
    raw = json.loads(DATA.read_text(encoding="utf-8"))
    raw["measured"]["olx"]["names"]["olx"] = "olx.example"  # not what 'brands' says
    (tmp_path / "typosquat_targets.json").write_text(json.dumps(raw), encoding="utf-8")
    monkeypatch.setattr(scoring, "_DATA_DIR", str(tmp_path))
    assert scoring._load_measured_global_groups() == ((), frozenset())
    assert scoring._load_typosquat_targets()["olx"] == "olx.pl"


# ── What the new names catch (hosts from the 2026-10-04 PhishTank / TweetFeed week) ──

@pytest.mark.parametrize("host, brand", [
    ("allegro.pl-dyu8h.sbs", "allegro"),
    ("allegro.0132919hpho5i.skin", "allegro"),
    ("allegrolokalnie.oferta-0295748.cfd", "allegrolokalnie"),
    ("allegro-lokalnie.12gg92701bbbb.cfd", "allegrolokalnie"),
    ("www.allegrolokalnie.pl-5ufkc.sbs", "allegrolokalnie"),
    ("olx.pl-dyu8h.sbs", "olx"),
    ("novobanco.novoalerta.com", "novobanco"),
])
def test_the_brand_as_a_subdomain_label(host, brand):
    assert _check_brand_in_subdomain(host) == brand


@pytest.mark.parametrize("host, brand", [
    ("att-sign-in-1c41ac.webflow.io", "att"),
    ("sbc-att-verifier-sign-in-45a7a5.webflow.io", "att"),
    ("bellsouth-verifier-sign-in-17cc27.webflow.io", "bellsouth"),
    ("my-xfinitysignin.weebly.com", "xfinity"),
    ("xfinity-security-update.webflow.io", "xfinity"),
])
def test_the_brand_with_a_lure_word_on_a_site_builder(host, brand):
    assert _check_brand_on_hosting_tenant(host) == brand


@pytest.mark.parametrize("host, expected", [
    ("mbway.online", ("mbway.pt", "TLD confusion")),
    ("mbway.site", ("mbway.pt", "TLD confusion")),
    ("olx.top", ("olx.pl", "TLD confusion")),
    ("trezor.top", ("trezor.io", "TLD confusion")),
    ("xfinity-login.com", ("xfinity.com", "combosquatting")),
    ("att-login.com", ("att.com", "combosquatting")),
    ("xfimity.com", ("xfinity.com", "character substitution")),  # m for n: a look-alike
    ("nubamk.com", ("nubank.com.br", "character substitution")),
    ("kucoim.com", ("kucoin.com", "character substitution")),
    ("allegrro.pl", ("allegro.pl", "high similarity")),
    ("0lx.net", ("olx.pl", "character substitution")),
])
def test_typos_and_tld_confusion(host, expected):
    assert _check_typosquatting_v2(host) == expected


def test_a_week_host_now_scores_dangerous(no_ml):
    _, level, reasons = calculate_score({"domain": "allegrolokalnie.pl-ogloszenie01291471940.shop"})
    assert level.value == "dangerous"
    assert "brand_subdomain_abuse" in {r.signal for r in reasons}


# ── What the false-positive pass cleared ──

def _listed() -> list[str]:
    return sorted({d for g in MEASURED_GLOBAL_GROUPS for d in (g.official | g.unrelated)})


@pytest.mark.parametrize("host", _listed())
def test_every_listed_domain_has_no_brand_signal(host, no_ml):
    for h in (host, "www." + host):
        _, _, reasons = calculate_score({"domain": h})
        assert not {r.signal for r in reasons} & _BRAND_SIGNALS, (h, [(r.signal, r.detail) for r in reasons])


@pytest.mark.parametrize("host", [
    # one substitution that is not a slip of the hand (the Tranco top-1M)
    "nfinity.com", "ufinity.jp", "efinity.rs", "myway.com", "myway.be", "m-way.ch", "comcash.com",
    # the macOS dictionary as <word>.com
    "finity.com", "bellmouth.com", "corresol.com", "tremor.com", "trevor.com",
    # a shared name under a country's TLD
    "trezor.cz", "trezor.sk",
    # the brands' own hosts under their other domains
    "login.olx.ua", "m.olx.kz", "salescenter.allegro.com", "www.att.net",
])
def test_cleared_by_the_pass(host):
    assert _check_typosquatting_v2(host) is None


def test_the_slip_rule_covers_the_new_names_only():
    for name in NEW_NAMES:
        assert scoring._NAME_RULES[name].slips_only, name
    for name in ("paypal", "netflix", "dhl"):
        assert not scoring._NAME_RULES[name].slips_only, name


def test_trezor_is_a_shared_name():
    assert "trezor" in scoring._SHARED_NAMES
    assert not scoring._NAME_RULES["trezor"].generic_combos
    assert _check_typosquatting_v2("trezor-login.com") == ("trezor.io", "combosquatting")


# ── The ML feature keeps the list the model was trained with ──

@pytest.mark.parametrize("name", ["allegr0", "xfinlty", "kucoim", "paypa1", "sberbamk"])
def test_ml_similarity_leaves_out_names_the_model_was_not_trained_with(name):
    trained = [b for b in TYPOSQUAT_TARGETS if b not in NEW_NAMES and b != name]
    assert _max_brand_similarity(name) == round(max(SequenceMatcher(None, name, b).ratio() for b in trained), 3)

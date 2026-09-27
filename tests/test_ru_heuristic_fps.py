"""Russian false positives from the name-only rules (production, 2026-09-27).

  kvs.gov.spb.ru  100/dangerous — 'spb' read as a brand typo ("Impersonates
                  ups.com"), 'gov' as a fake TLD, three subdomain levels
                  counted where the PSL says there is one (spb.ru is a public
                  suffix; the site is gov.spb.ru's)
  ako.ru          dangerous — 'ako' two substitutions from 'aws'
  etsp.ru, ngpedia.ru, ikar.ru, ugpr.ru — short names one or two letters
                  from etsy / expedia / ikea / usps

These tests pin the fix: the typosquat check compares the PSL-aware
registrable label and needs a sane length before edit distance means
anything; fake_tld_subdomain and excessive_subdomains only look left of the
registrable domain. And that look-alikes stay caught. The ML model is stubbed
(as in test_scoring's ASCII guard) so a weekly retrain cannot move these —
its remaining false positives are reported, not fixed, here.
"""
from __future__ import annotations

import asyncio
import importlib
import json
import sys
from pathlib import Path

import pytest

from api.models.schemas import RiskLevel
from api.services import scoring
from api.services.scoring import (
    _check_brand_in_subdomain,
    _check_typosquatting_v2,
    _has_fake_tld_in_subdomain,
    calculate_score,
    registrable_domain,
)

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def no_ml(monkeypatch):
    import api.services.ml_scorer as ml_scorer
    monkeypatch.setattr(ml_scorer, "ml_predict", lambda domain: None)


def _signals(domain: str, **extra) -> set[str]:
    _, _, reasons = calculate_score({"domain": domain, **extra})
    return {r.signal for r in reasons if r.weight > 0}


def _eval_module():
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    return importlib.import_module("eval_ru_heuristics")


# ── The registrable domain, PSL-aware ──

@pytest.mark.parametrize("host, expected", [
    ("kvs.gov.spb.ru", "gov.spb.ru"),
    ("gov.spb.ru", "gov.spb.ru"),
    ("spb.ru", "spb.ru"),                        # a bare suffix answers itself
    ("adm.nov.ru", "adm.nov.ru"),
    ("museum.vladimir.ru", "museum.vladimir.ru"),  # not in public_suffixes_in_top
    ("idg.chph.ras.ru", "chph.ras.ru"),
    ("sc384.kirov.spb.ru", "kirov.spb.ru"),
    ("a.b.hosting.myjino.ru", "b.hosting.myjino.ru"),  # longest suffix wins
    ("rosreestr.gov.ru", "rosreestr.gov.ru"),
    ("www.kaluga-gov.ru", "kaluga-gov.ru"),
    ("login.example.co.uk", "example.co.uk"),    # compound-ccTLD heuristic kept
    ("a.b.evil.com", "evil.com"),
])
def test_registrable_domain_is_psl_aware(host, expected):
    assert registrable_domain(host) == expected


def test_registrable_domain_reads_the_decoded_form_too():
    # сочи.рус is a PSL rule; the scorer hands typosquatting the decoded name.
    assert registrable_domain("отель.сочи.рус") == "отель.сочи.рус"
    assert registrable_domain("www.отель.сочи.рус") == "отель.сочи.рус"


def test_ru_public_suffix_file_is_well_formed():
    rules = json.loads((ROOT / "data" / "ru_public_suffixes.json").read_text())
    assert rules == sorted(set(rules))
    for rule in rules:
        assert rule == rule.lower() and rule.isascii() and "." in rule, rule
        assert rule.rsplit(".", 1)[1] in {"ru", "su", "xn--p1ai", "xn--p1acf"}, rule
    for zone in ("spb.ru", "msk.ru", "nov.ru", "gov.ru", "mil.ru", "com.ru", "vladimir.ru"):
        assert zone in rules
    # tatarstan.ru is the republic's own domain, not a public suffix.
    assert "tatarstan.ru" not in rules


# ── The reported false positives ──

def test_kvs_gov_spb_ru_is_not_judged_by_its_public_suffix(no_ml):
    score, level, reasons = calculate_score({"domain": "kvs.gov.spb.ru"})
    fired = {r.signal for r in reasons}
    assert not fired & {"typosquatting", "fake_tld_subdomain", "excessive_subdomains"}, fired
    assert (score, level) == (0, RiskLevel.safe)


def test_every_gov_spb_ru_committee_is_safe_on_the_name_alone(no_ml):
    for host in ("gov.spb.ru", "kgiop.gov.spb.ru", "kga.gov.spb.ru", "tb.gov.spb.ru",
                 "budget.gov.spb.ru", "metro.spb.ru", "zdrav.spb.ru", "adm.nov.ru"):
        assert _signals(host) == set(), host


def test_ako_ru_is_not_an_aws_typo(no_ml):
    assert _check_typosquatting_v2("ako.ru") is None
    assert _signals("ako.ru") == set()
    # Production also saw 44 AlienVault OTX pulses. That signal is untouched
    # here; the typosquat half of the verdict is gone either way.
    assert "typosquatting" not in _signals("ako.ru", alienvault_pulse_count=44)


@pytest.mark.parametrize("host", ["etsp.ru", "ngpedia.ru", "ikar.ru", "ugpr.ru"])
def test_short_russian_names_are_not_brand_typos(host, no_ml):
    assert _check_typosquatting_v2(host) is None
    assert calculate_score({"domain": host})[1] == RiskLevel.safe


@pytest.mark.parametrize("host", ["ups.ru", "spb.ru", "aws.su", "nov.ru", "irs.ru"])
def test_labels_under_four_characters_are_never_compared(host):
    assert _check_typosquatting_v2(host) is None


# ── fake_tld_subdomain / excessive_subdomains look left of the registrable domain ──

@pytest.mark.parametrize("host, expected", [
    ("paypal.com.evil.xyz", True),
    ("login.gov.ru.evil.com", True),
    ("kvs.gov.spb.ru", False),   # 'gov' is the registered name under spb.ru
    ("edu.gov.ru", False),       # 'edu' is the registered name under gov.ru
    ("www.gov.spb.ru", False),
    ("evil.xyz", False),
])
def test_fake_tld_only_counts_subdomain_labels(host, expected):
    assert _has_fake_tld_in_subdomain(host) is expected


@pytest.mark.parametrize("host, expected", [
    ("a.b.evil.com", True),
    ("a.b.c.d.evil.com", True),
    ("sberbank.ru.secure-login.com", True),
    ("www.shop.co.uk", False),         # one level above shop.co.uk
    ("kvs.gov.spb.ru", False),         # one level above gov.spb.ru
    ("svki.rosguard.gov.ru", False),   # one level above rosguard.gov.ru
    ("sc384.kirov.spb.ru", False),
])
def test_excessive_subdomains_counts_levels_above_the_registrable_domain(host, expected, no_ml):
    assert ("excessive_subdomains" in _signals(host)) is expected


# ── Look-alikes stay caught ──

@pytest.mark.parametrize("host, brand", [
    ("paypa1.com", "paypal.com"),             # look-alike digit
    ("xn--ypal-43d9g.com", "paypal.com"),     # раypal.com, Cyrillic р and а
    ("xn--ggle-55da.com", "google.com"),      # gооgle.com, Cyrillic о о
    ("rnicrosoft-login.com", "microsoft.com"),
    ("vvhatsapp.com", "whatsapp.com"),
    ("paypal-login.com", "paypal.com"),
    ("ups-login.com", "ups.com"),             # a 3-letter brand in a combo still counts
    ("amazom.com", "amazon.com"),
    ("micorsoft.com", "microsoft.com"),
    ("xbox-verify.com", "xbox.com"),
    ("ub3r.com", "uber.com"),                 # a 4-letter name, exact look-alike
])
def test_lookalikes_are_still_typosquats(host, brand):
    result = _check_typosquatting_v2(scoring._decode_idn(host))
    assert result and result[0] == brand, (host, result)


@pytest.mark.parametrize("host, brand", [
    ("paypa1.msk.ru", "paypal.com"),
    ("netflix-billing.com.ru", "netflix.com"),
    ("apple-verify.pp.ru", "apple.com"),
    ("rnicrosoft.nov.ru", "microsoft.com"),
])
def test_lookalikes_registered_under_a_russian_zone_are_now_seen(host, brand):
    """The zone label used to be the one compared, so a look-alike registered
    under spb.ru / msk.ru / com.ru … was invisible to this check."""
    result = _check_typosquatting_v2(host)
    assert result and result[0] == brand, (host, result)


def test_brand_name_under_a_zone_is_reported_once(no_ml):
    """paypal.spb.ru: brand_subdomain_abuse reports it (it reads spb.ru as the
    registrable domain), as before; TLD confusion must not add a second hit."""
    assert _check_brand_in_subdomain("paypal.spb.ru") == "paypal"
    assert _check_typosquatting_v2("paypal.spb.ru") is None
    assert _signals("paypal.spb.ru") == {"brand_subdomain_abuse"}


@pytest.mark.parametrize("host", [
    "sberbank.ru.secure-login.com", "gosuslugi.ru.lk-vhod.xyz", "paypal.com.evil.xyz",
    "online.sberbank.ru.verify-client.top",
])
def test_brand_domain_as_a_subdomain_stays_dangerous(host, no_ml):
    assert calculate_score({"domain": host})[1] != RiskLevel.safe


def test_brand_country_sites_on_compound_cctlds_stay_safe(no_ml):
    for host in ("apple.com.cn", "hsbc.com.tr", "paypal.co.il", "telegraph.co.uk", "discovery.co.za"):
        assert _check_typosquatting_v2(host) is None, host


# ── The labelled sets, end to end (tests/data) ──

def test_labelled_sets_meet_their_size_contract():
    ev = _eval_module()
    legit, phish = ev.load(ev.LEGIT_PATH), ev.load(ev.PHISH_PATH)
    assert len(legit) >= 150 and len(phish) >= 80
    short = [h for h in legit if len(registrable_domain(h.host).split(".")[0]) <= 4]
    assert len(short) >= 40
    assert {h.category for h in legit} >= {"gov_spb", "regional_zone", "mos", "federal_gov", "university"}


def test_legit_set_has_no_dangerous_and_one_caution_on_the_name_alone(no_ml):
    """Before the fix: 18 dangerous, 73 caution (ML stubbed). The one caution
    left is zenit.kfis.gov.spb.ru — two subdomain levels above gov.spb.ru
    plus its hyphen/dot count, the rule working as designed."""
    ev = _eval_module()
    rows = ev.score_hosts(ev.load(ev.LEGIT_PATH))
    flagged = {r["host"]: r["level"] for r in rows if r["level"] != "safe"}
    assert flagged == {"zenit.kfis.gov.spb.ru": "caution"}


def test_phish_set_detections_do_not_drop(no_ml):
    """50 of 101 caught before the fix and after it (ML stubbed). Three were
    caught only through the bug — gosuslugi-lk.spb.ru ('spb' ~ ups),
    tinkoff-bonus.nov.ru and vk-login.nov.ru ('nov' ~ n26) — and three are
    caught because the registrable label is finally the one compared
    (paypa1.msk.ru, netflix-billing.com.ru, apple-verify.pp.ru)."""
    ev = _eval_module()
    rows = ev.score_hosts(ev.load(ev.PHISH_PATH))
    caught = {r["host"] for r in rows if r["level"] != "safe"}
    assert len(caught) >= 50
    for host in ("paypa1.msk.ru", "netflix-billing.com.ru", "apple-verify.pp.ru",
                 "sberbank.ru.secure-login.com", "paypal.com.evil.xyz", "xn--sberbnk-6fg.ru"):
        assert host in caught, host


def test_eval_parser_rejects_bad_lines():
    ev = _eval_module()
    with pytest.raises(ValueError, match="line 1"):
        ev.parse_hosts("Bad.Host.ru | x | y")
    with pytest.raises(ValueError, match="twice"):
        ev.parse_hosts("a.ru | x | y\na.ru | x | y")
    assert [h.host for h in ev.parse_hosts("# c\n\na.ru | short_name | s | n")] == ["a.ru"]


# ── The analyzer's vouch for a site it could not open ──

def test_regional_gov_label_is_not_a_government_registry():
    """'gov' is not reserved in the FAITID regional zones — gov.vladimir.ru
    was unregistered on 2026-09-27 — so only named sites are vouched for."""
    from api.services.analyzer import _government_name

    assert _government_name("kvs.gov.spb.ru") and _government_name("gov.spb.ru")
    assert _government_name("rosreestr.gov.ru")
    for host in ("gov.vladimir.ru", "x.gov.msk.ru", "gov.nov.ru", "evilgov.spb.ru", "gov.spb.ru.evil.com"):
        assert not _government_name(host), host


@pytest.mark.parametrize("host, zone, rank", [
    ("vozvrat-sredstv.msk.ru", "msk.ru", 6032),
    ("gosuslugi-lk.spb.ru", "spb.ru", 2605),
])
def test_a_zones_rank_does_not_vouch_for_names_under_it(host, zone, rank, offline_analyzer, no_ml):
    """Tranco ranks msk.ru and spb.ru as one name each. An unreachable host
    anyone registered under them borrowed that rank and came back 'safe'."""
    from api.services.analyzer import analyze_domain

    offline_analyzer(site="unreachable", ranks={zone: rank})
    result = asyncio.run(analyze_domain(host, budget_s=5.0))
    assert result.level == RiskLevel.caution, (result.score, [r.signal for r in result.reasons])
    detail = next(r for r in result.reasons if r.signal == "unreachable_from_scanner").detail
    assert "not a widely known site" in detail


def test_the_st_petersburg_government_is_vouched_for_when_unreachable(offline_analyzer, no_ml):
    from api.services.analyzer import analyze_domain

    offline_analyzer(site="unreachable")
    result = asyncio.run(analyze_domain("kvs.gov.spb.ru", budget_s=5.0))
    assert result.level == RiskLevel.safe, (result.score, [r.signal for r in result.reasons])
    detail = next(r for r in result.reasons if r.signal == "unreachable_from_scanner").detail
    assert "not a widely known site" not in detail

"""Russian false positives from the name-only rules (production, 2026-09-27).

  kvs.gov.spb.ru  100/dangerous — 'spb' read as a brand typo ("Impersonates
                  ups.com"), 'gov' as a fake TLD, three subdomain levels
                  counted where the PSL says there is one (spb.ru is a public
                  suffix; the site is gov.spb.ru's)
  ako.ru          dangerous — 'ako' two substitutions from 'aws'
  etsp.ru, ngpedia.ru, ikar.ru, ugpr.ru — short names one or two letters
                  from etsy / expedia / ikea / usps

These tests pin the fix: the typosquat check compares the PSL-aware
registrable label, only exact look-alikes below 5 letters and one edit below
8; fake_tld_subdomain and excessive_subdomains look left of the registrable
domain — and count the registered name too when it spells a TLD under an
open zone (vk.com.msk.ru). And that look-alikes stay caught: the PHISH set is
held to what the pre-fix code caught, host by host. The ML model is stubbed
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
    _check_brand_under_open_zone,
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


def _script(name: str):
    scripts = ROOT / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    return importlib.import_module(name)


def _eval_module():
    return _script("eval_ru_heuristics")


# ── The registrable domain, PSL-aware ──

@pytest.mark.parametrize("host, expected", [
    ("kvs.gov.spb.ru", "gov.spb.ru"),
    ("gov.spb.ru", "gov.spb.ru"),
    ("spb.ru", "spb.ru"),                        # a bare suffix answers itself
    ("adm.nov.ru", "adm.nov.ru"),
    ("museum.vladimir.ru", "museum.vladimir.ru"),  # not in public_suffixes_in_top
    ("idg.chph.ras.ru", "chph.ras.ru"),
    ("sc384.kirov.spb.ru", "kirov.spb.ru"),
    # '*.hosting.myjino.ru': b.hosting.myjino.ru is itself a suffix, so the
    # name registered under it is the whole host.
    ("a.b.hosting.myjino.ru", "a.b.hosting.myjino.ru"),
    ("www.a.b.hosting.myjino.ru", "a.b.hosting.myjino.ru"),
    ("b.hosting.myjino.ru", "b.hosting.myjino.ru"),  # a bare suffix answers itself
    ("hosting.myjino.ru", "hosting.myjino.ru"),      # a name under myjino.ru
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
        body = rule[2:] if rule.startswith("*.") else rule
        assert body == body.lower() and body.isascii() and "." in body and "*" not in body, rule
        assert body.rsplit(".", 1)[1] in {"ru", "su", "xn--p1ai", "xn--p1acf"}, rule
    for zone in ("spb.ru", "msk.ru", "nov.ru", "gov.ru", "mil.ru", "com.ru", "vladimir.ru"):
        assert zone in rules
    # Wildcards keep their '*.' (the PSL has '*.hosting.myjino.ru', no plain rule).
    assert "*.hosting.myjino.ru" in rules and "hosting.myjino.ru" not in rules
    # tatarstan.ru is the republic's own domain, not a public suffix.
    assert "tatarstan.ru" not in rules


def test_psl_builder_keeps_wildcards_and_refuses_exception_rules():
    build = _script("build_ru_public_suffixes")
    psl = "\n".join(["// c", "ru", "spb.ru", "*.vps.myjino.ru", "сочи.рус", "*.kawasaki.jp", "!city.kawasaki.jp"])
    assert build.parse(psl) == ["*.vps.myjino.ru", "spb.ru", "xn--h1aliz.xn--p1acf"]
    with pytest.raises(ValueError, match="exception rule"):
        build.parse(psl + "\n!www.spb.ru")


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


@pytest.mark.parametrize("host", ["ako.ru", "spb.ru", "nov.ru", "ugp.ru", "dhk.ru", "wax.ru", "pus.ru"])
def test_three_letter_names_are_not_compared_by_edit_distance(host):
    assert _check_typosquatting_v2(host) is None


@pytest.mark.parametrize("host, brand, method", [
    ("ups.ru", "ups.com", "TLD confusion"),         # the brand's own name elsewhere
    ("dhl.top", "dhl.com", "TLD confusion"),
    ("aws.help", "aws.amazon.com", "TLD confusion"),
    ("dh1.com", "dhl.com", "character substitution"),    # exact look-alikes
    ("up5.com", "ups.com", "character substitution"),
    ("1kea.com", "ikea.com", "character substitution"),  # '1' for i as well as l
    ("eb4y.com", "ebay.com", "character substitution"),  # '4' for a
    ("c1t1.com", "citi.com", "character substitution"),
    ("e8ay.com", "ebay.com", "character substitution"),
    ("dhll.com", "dhl.com", "doubled letter"),
    ("upss.com", "ups.com", "doubled letter"),
])
def test_short_brands_still_match_exactly(host, brand, method):
    """3-4 letter brands give up edit distance, not exact look-alikes: the
    brand's name under another TLD, spelled with digits, or a letter typed
    twice. None of these is one edit from an innocent name."""
    assert _check_typosquatting_v2(host) == (brand, method)


@pytest.mark.parametrize("host", ["hsbk.com", "ebey.com", "etsp.com", "ikar.com", "usbs.com"])
def test_four_letter_names_one_letter_off_are_not_typos(host):
    assert _check_typosquatting_v2(host) is None


def test_a_brands_own_digits_are_not_counted_as_differences():
    """office365: the name's digits used to be turned into letters before the
    comparison, so a two-substitution typo became four differences."""
    assert _check_typosquatting_v2("offige36m.com") == ("office.com", "character substitution")
    assert _check_typosquatting_v2("offlce365.com") == ("office.com", "character substitution")


# ── fake_tld_subdomain / excessive_subdomains look left of the registrable domain ──

@pytest.mark.parametrize("host, expected", [
    ("paypal.com.evil.xyz", True),
    ("login.gov.ru.evil.com", True),
    ("kvs.gov.spb.ru", False),   # gov.spb.ru: the St Petersburg government
    ("edu.gov.ru", False),       # 'edu' is the registered name under gov.ru
    ("docs.edu.gov.ru", False),  # … and gov.ru is a restricted registry
    ("www.gov.spb.ru", False),
    ("evil.xyz", False),
    ("ru.wikipedia.org", False),  # 'ru' as a subdomain label is a language
    # A TLD bought as the name under an open zone: com.msk.ru, ru.msk.ru and
    # gov.msk.ru are private persons' names, org.spb.ru is for sale.
    ("vk.com.spb.ru", True),
    ("vk.com.msk.ru", True),
    ("gosuslugi.gov.msk.ru", True),
    ("sberbank.ru.msk.ru", True),
    ("paypal.org.spb.ru", True),
    ("login.vk.com.co.uk", True),   # the same under a compound ccTLD
    ("com.msk.ru", False),          # the bare name dresses nothing up
    ("x.gov.uk", False),            # a restricted zone's names are not bought
])
def test_fake_tld_counts_subdomain_labels_and_tlds_bought_under_open_zones(host, expected):
    assert _has_fake_tld_in_subdomain(host) is expected


@pytest.mark.parametrize("host", [
    "vk.com.spb.ru", "sberbank.com.spb.ru", "gosuslugi.gov.msk.ru", "paypal.com.spb.ru",
    "apple.com.msk.ru", "login.vk.com.msk.ru", "sberbank.ru.msk.ru",
])
def test_a_tld_bought_under_a_zone_stays_dangerous(host, no_ml):
    """These scored 50-100 before the PSL fix; its first cut took them to 0
    by reading 'com' of com.msk.ru as just a registered name."""
    fired = _signals(host)
    assert {"fake_tld_subdomain", "excessive_subdomains"} <= fired, fired
    assert calculate_score({"domain": host})[1] == RiskLevel.dangerous


@pytest.mark.parametrize("host, expected", [
    ("a.b.evil.com", True),
    ("a.b.c.d.evil.com", True),
    ("sberbank.ru.secure-login.com", True),
    ("www.shop.co.uk", False),         # one level above shop.co.uk
    ("kvs.gov.spb.ru", False),         # one level above gov.spb.ru
    ("svki.rosguard.gov.ru", False),   # one level above rosguard.gov.ru
    ("sc384.kirov.spb.ru", False),
    ("vk.com.msk.ru", True),           # reads as vk.com: two above msk.ru
    ("www.a.b.hosting.myjino.ru", False),  # one above a.b.hosting.myjino.ru
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


@pytest.mark.parametrize("host, brand", [
    # The CT log for nov.ru alone lists the first four.
    ("vk.nov.ru", "vk"), ("mts.nov.ru", "mts"), ("ok.nov.ru", "ok"),
    ("kinopoisk.nov.ru", "kinopoisk"), ("gosuslugi.nov.ru", "gosuslugi"),
    ("sberbank.spb.ru", "sberbank"), ("avito.com.ru", "avito"), ("v-k.nov.ru", "vk"),
    ("gosuslugi-lk.spb.ru", "gosuslugi"), ("tinkoff-bonus.nov.ru", "tinkoff"),
    ("vk-login.nov.ru", "vk"), ("lk.sberbank.spb.ru", "sberbank"),
])
def test_russian_brand_bought_under_an_open_zone(host, brand, no_ml):
    assert _check_brand_under_open_zone(host) == brand
    assert "brand_subdomain_abuse" in _signals(host)
    assert calculate_score({"domain": host})[1] != RiskLevel.safe


@pytest.mark.parametrize("host", [
    "ok-stroy.spb.ru",       # a short brand as one part of a name
    "gook.spb.ru",           # … or glued to a word
    "sberbank.gov.ru",       # restricted registry
    "mts.gov.spb.ru",        # the St Petersburg government's own name
    "sberbank.ru",           # not under a zone at all
    "vk.com",
    "spb.ru",
    "linux.org.ru",
])
def test_russian_brand_check_stays_narrow(host):
    assert _check_brand_under_open_zone(host) is None


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


# PHISH hosts the pre-fix code caught that the fix gives up, and why. Each
# class was measured on the Tranco top-100k with scripts/eval_typo_variants.py
# and a scan for the shape: keeping it flags real sites at that rate, and in
# the long tail no allowlist spares them.
_JUSTIFIED_LOSSES = {
    # A 4-letter omission of a 5-letter brand is as dense as any 4-letter
    # name: 14 top-100k sites have that shape (mail.de, mail.bg, mail.ee ~
    # gmail; case.edu ~ chase; team.blue ~ steam).
    "gmai.com": "omission, 4 letters",
    "appl.com": "omission, 4 letters",
    "yaho.com": "omission, 4 letters",
    # Two substitutions under 8 letters: 415 top-100k sites (spotify ~
    # shopify, webex ~ fedex, chess ~ chase, slate ~ slack, moodle ~ google)
    # — and ngpedia.ru ~ expedia.
    "qooqle.com": "two substitutions, 6 letters",
    "prydal.com": "two substitutions, 6 letters",
    "yahuu.com": "two substitutions, 5 letters",
}


def test_phish_set_keeps_every_detection_but_the_justified_ones(no_ml):
    """Held host by host to what the pre-fix code caught
    (ru_heuristics_phish_caught_before.txt): a count would let a detection
    lost here hide behind one gained there."""
    ev = _eval_module()
    before_text = (ROOT / "tests" / "data" / "ru_heuristics_phish_caught_before.txt").read_text()
    before = {line.strip() for line in before_text.splitlines() if line.strip() and not line.startswith("#")}
    rows = ev.score_hosts(ev.load(ev.PHISH_PATH))
    caught = {r["host"] for r in rows if r["level"] != "safe"}
    assert before <= {r["host"] for r in rows}, "the baseline names a host the PHISH set lacks"
    assert before - caught == set(_JUSTIFIED_LOSSES)
    # Seen at last: look-alikes and brand names registered under a zone.
    for host in ("paypa1.msk.ru", "netflix-billing.com.ru", "apple-verify.pp.ru", "avito.com.ru",
                 "sberbank-online.msk.ru", "sberbank.ru.msk.ru"):
        assert host in caught - before, host


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
    assert _government_name("rosreestr.gov.ru") and _government_name("x.mil.ru")
    for host in ("gov.vladimir.ru", "x.gov.msk.ru", "gov.nov.ru", "evilgov.spb.ru", "gov.spb.ru.evil.com"):
        assert not _government_name(host), host


@pytest.mark.parametrize("host", ["gosuslugi.govt.ru", "lk.gob.ru", "esia.gouv.ru", "x.go.ru", "x.gov.su"])
def test_ru_names_that_only_look_governmental_are_not_vouched_for(host):
    """govt.ru, gob.ru and gouv.ru are private persons' names, go.ru an
    ordinary registration (whois.tcinet.ru, 2026-09-27): under .ru only
    gov.ru and mil.ru are government-only."""
    from api.services.analyzer import _government_name

    assert not _government_name(host)


@pytest.mark.parametrize("host", ["www.gov.uk", "x.gouv.fr", "x.gob.mx", "x.go.jp", "x.govt.nz", "x.gov"])
def test_other_countries_government_registries_are_still_vouched_for(host):
    from api.services.analyzer import _government_name

    assert _government_name(host)


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

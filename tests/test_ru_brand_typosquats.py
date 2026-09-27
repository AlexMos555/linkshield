"""Russian brands in the typosquat rule (data/typosquat_targets_ru.json).

The global list had no Russian brand: sberbamk.ru, t1nkoff.ru, 0zon.ru,
wildberies.ru and avlto.ru came back clean. These tests pin what the list
catches now, and what its false-positive pass cleared before it shipped:

  - the brand families' own sites (yandex.kz, wildberries.kz, sber-bank.by …)
    and other owners' sites of the same shape (mts.ca, avito.ma, candex.com),
    each listed with its evidence;
  - words and names one edit from a brand (ozone, zoon, aviso, mt5);
  - brands whose bare name other companies own abroad (Tele2 AB, Bell MTS);
  - two rule changes the pass forced, both measured on the Tranco top-1M:
    a name ending in the brand's generic word (bank, store) is compared by
    the part before it — swedbank is not sberbank, upstore not rustore — and
    the similarity fallback keeps #61's edit budget (one edit under 8
    letters), so aviator is not avito and kontakt not vkontakte.

The ML model is stubbed where a whole verdict is scored, as in
test_ru_heuristic_fps.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from api.models.schemas import RiskLevel
from api.services import ru_brands, scoring
from api.services.scoring import (
    GLOBAL_TYPOSQUAT_TARGETS,
    TYPOSQUAT_TARGETS,
    _check_brand_in_subdomain,
    _check_typosquatting_v2,
    _decode_idn,
    _edit_distance_at_most,
    _generic_tail,
    calculate_score,
)

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "typosquat_targets_ru.json"


@pytest.fixture
def no_ml(monkeypatch):
    import api.services.ml_scorer as ml_scorer
    monkeypatch.setattr(ml_scorer, "ml_predict", lambda domain: None)


def _typo(host: str):
    """The rule on the name as the scorer hands it over: decoded."""
    return _check_typosquatting_v2(_decode_idn(host))


def _group(**overrides) -> dict:
    base = {"owner": "x", "names": {"brandx": "brandx.ru"}, "official": {"brandx.ru": "evidence"}}
    return {**base, **overrides}


# ── The data file ──

def test_the_russian_list_loads_and_joins_the_targets():
    raw = json.loads(DATA.read_text(encoding="utf-8"))
    groups = ru_brands.parse(raw)
    assert groups == scoring.RU_BRAND_GROUPS
    names = {n for g in groups for n in g.names}
    assert {"sberbank", "gosuslugi", "tinkoff", "tbank", "vtb", "alfabank", "ozon", "wildberries",
            "avito", "yandex", "vkontakte", "mts", "beeline", "megafon", "tele2", "cdek"} <= names
    assert names <= set(TYPOSQUAT_TARGETS)
    # The global list is untouched, and wins where a name is in both.
    assert not names & set(GLOBAL_TYPOSQUAT_TARGETS)
    assert all(TYPOSQUAT_TARGETS[k] == v for k, v in GLOBAL_TYPOSQUAT_TARGETS.items())


def test_every_brand_cites_a_source_and_every_exemption_its_evidence():
    raw = json.loads(DATA.read_text(encoding="utf-8"))
    sources = raw["_meta"]["sources"]
    for key, group in raw["brands"].items():
        cited = set(group["fraud"])
        assert cited and cited <= set(sources), (key, cited - set(sources))
        for field in ("official", "unrelated", "not_typos", "no_fuzzy", "no_tld_confusion"):
            for item, why in group.get(field, {}).items():
                assert why.strip(), (key, field, item)


@pytest.mark.parametrize("bad, message", [
    ({"brands": {"x": _group(official={"other.ru": "e"})}}, "every name's domain"),
    ({"brands": {"x": _group(official={"brandx.ru": ""})}}, "needs its evidence"),
    ({"brands": {"x": _group(official=["brandx.ru"])}}, "must map each entry"),
    ({"brands": {"x": _group(unrelated={"brandx.ru": "e"})}}, "either official or unrelated"),
    ({"brands": {"x": _group(no_fuzzy={"other": "e"})}}, "switches must name a name"),
    ({"brands": {"x": _group(not_typos={"a.b": "e"})}}, "must be a label"),
    ({"brands": {"x": _group(names={"BrandX": "brandx.ru"})}}, "bad name"),
    ({"brands": {"x": _group(), "y": _group()}}, "also listed by x"),
    ({"brand": {}}, "'brands' must be an object"),
])
def test_the_parser_names_what_is_wrong(bad, message):
    with pytest.raises(ValueError, match=message):
        ru_brands.parse(bad)


def test_a_broken_file_leaves_the_global_list_working(tmp_path, caplog):
    broken = tmp_path / "typosquat_targets_ru.json"
    broken.write_text('{"brands": {"x": {"names": {}}}}', encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger="cleanway.ru_brands"):
        assert ru_brands.load(broken) == ()
    assert "Russian brands not compared" in caplog.text
    assert ru_brands.load(tmp_path / "absent.json") == ()


def test_official_domains_are_held_in_both_spellings():
    assert ru_brands.idn_forms("яндекс.рф") == {"яндекс.рф", "xn--d1acpjx3f.xn--p1ai"}
    assert ru_brands.idn_forms("xn--90ab2c.xn--p1ai") == {"втб.рф", "xn--90ab2c.xn--p1ai"}
    assert ru_brands.idn_forms("vtb.ru") == {"vtb.ru"}


# ── Look-alikes of Russian brands are caught ──

@pytest.mark.parametrize("host, site", [
    # The misses that motivated the list.
    ("sberbamk.ru", "sberbank.ru"), ("t1nkoff.ru", "tinkoff.ru"), ("gosuslugl.ru", "gosuslugi.ru"),
    ("0zon.ru", "ozon.ru"), ("wildberies.ru", "wildberries.ru"), ("avlto.ru", "avito.ru"),
    # One edit, a swap, a doubled letter, a look-alike, a glyph.
    ("sbrebank.ru", "sberbank.ru"), ("sberbnk.ru", "sberbank.ru"), ("gossuslugi.ru", "gosuslugi.ru"),
    ("g0suslugi.ru", "gosuslugi.ru"), ("tinkof.ru", "tinkoff.ru"), ("tbamk.ru", "tbank.ru"),
    ("alfabamk.ru", "alfabank.ru"), ("a1fabank.com", "alfabank.ru"), ("vvildberries.ru", "wildberries.ru"),
    ("av1to.ru", "avito.ru"), ("avitto.ru", "avito.ru"), ("oz0n.shop", "ozon.ru"), ("yanbex.ru", "yandex.ru"),
    ("gzprombank.ru", "gazprombank.ru"), ("pchtabank.ru", "pochtabank.ru"), ("sovkombank.xyz", "sovcombank.ru"),
    ("uralsb.ru", "uralsib.ru"), ("megaf0n.ru", "megafon.ru"), ("bee1ine.ru", "beeline.ru"),
    ("rust0re.ru", "rustore.ru"), ("odnoklasniki.com", "ok.ru"), ("russianpst.ru", "pochta.ru"),
    # Three-letter names: exact look-alikes only (#61).
    ("m7s.ru", "mts.ru"), ("vt8.ru", "vtb.ru"),
    # 'bank' is generic, but a look-alike of the rest is still the brand.
    ("7bank.ru", "tbank.ru"),
    # The brand's name under another TLD: F6's own cdek.nu, and the TLDs its
    # H1 2026 report found phishing moved to (.shop, .com, .pro).
    ("cdek.nu", "cdek.ru"), ("cdek.in", "cdek.ru"), ("sberbank.top", "sberbank.ru"),
    ("ozon.shop", "ozon.ru"), ("wildberries.pro", "wildberries.ru"), ("gosuslugi.com", "gosuslugi.ru"),
    ("avito.shop", "avito.ru"), ("vtb.top", "vtb.ru"),
    # Combos.
    ("tbank-login.ru", "tbank.ru"), ("gosuslugi-verify.com", "gosuslugi.ru"),
    ("alfabank-secure.net", "alfabank.ru"), ("vk-login.com", "vk.com"), ("mailru-account.com", "mail.ru"),
    # Cyrillic names, compared on the decoded form.
    ("сбербанкк.рф", "sberbank.ru"), ("госуслуги.онлайн", "gosuslugi.ru"), ("втб.рус", "vtb.ru"),
    ("вайлдбериз.рф", "wildberries.ru"), ("xn--d1acpjx3f.xn--p1acf", "yandex.ru"),  # яндекс.рус
])
def test_russian_brand_lookalikes_are_caught(host, site):
    result = _typo(host)
    assert result and result[0] == site, (host, result)


@pytest.mark.parametrize("host", ["sberbamk.ru", "t1nkoff.ru", "0zon.ru", "wildberies.ru", "gosuslugl.ru"])
def test_a_typo_alone_is_caution(host, no_ml):
    """Typosquatting is worth 25: on the name alone that is caution, and a
    new domain, a risky TLD or a blocklist hit takes it further."""
    _, level, reasons = calculate_score({"domain": host})
    assert level == RiskLevel.caution
    assert "typosquatting" in {r.signal for r in reasons}


@pytest.mark.parametrize("host, why", [
    ("alfabank.kz", "parked at PS.kz on 2026-09-27"),
    ("wildberries.au", "parked on Above.com name servers"),
    ("почтабанк.рф", "offered for sale at reg.ru — not Почта Банк's"),
    ("beellne.ru", "a copy of Beeline's page on a rented VDS"),
    ("sberbank.biz", "registered 2026-06-19 at a retail registrar, behind Cloudflare"),
    ("yandez.ru", "sends its visitors on to an affiliate"),
])
def test_names_the_pass_found_not_to_be_the_brands_stay_flagged(host, why):
    assert _typo(host), why


# ── The false-positive pass: none of these is anyone's typo ──

@pytest.mark.parametrize("host", [
    "yandex.kz", "yandex.md", "yandex.cloud", "yandexcom.net", "yandex-team.ru", "ya.ru",
    "wildberries.kz", "wildberries.by", "wildberries.cn", "ozon.travel", "ozon.kz", "ozon.com",
    "sber-bank.by", "sberbank.com", "sber.pro", "sbrf.ru", "t-bank.ru", "tinkoff.ai",
    "vtb.kz", "vtb.by", "vtb.am", "vtb.com", "alfa-bank.by", "alfa-bank.ru", "alfabank.com",
    "gazprombank.investments", "gazprombank.ch", "sovcombank.it", "sovkombank.ru", "uralsib.com",
    "avito.com", "avito.st", "avito.tech", "mailru.com", "vkontakte.ru", "vk.company", "vkteam.ru",
    "odnoklasniki.ru", "odnoklassniki.tj", "cdek.kz", "cdek.by", "cdek.kg", "tele2.ru", "mymts.ru",
    "26gosuslugi.ru", "gosuslugi29.ru", "gosuslugi71.ru",
    "xn--90ab2c.xn--p1ai", "xn--d1acpjx3f.xn--p1ai", "xn--80acbjgmges7ca.xn--p1ai",  # втб.рф, яндекс.рф, вайлдберриз.рф
    "xn----7sbza0acdlkaf3d.xn--p1ai",  # почта-россии.рф
])
def test_the_brand_families_own_sites_are_not_typos(host):
    assert _typo(host) is None


@pytest.mark.parametrize("host", [
    "mts.ca", "mymts.net", "mtsmail.ca", "mts.com", "mts.rs", "mtsnet.fi", "avito.ma", "tavito.net",
    "aviot.jp", "avinto.es", "avixo.co", "candex.com", "yaldex.com", "yande.re", "bser.io", "vtb.no",
    "ozon.rs", "ruscore.ru", "megaron.gr", "megabon.eu", "betline.nl", "deeline.de",
])
def test_other_owners_sites_of_the_same_shape_are_not_typos(host):
    assert _typo(host) is None


@pytest.mark.parametrize("host", [
    "ozone.ru", "ozone.net", "zoon.ru", "aviso.com", "avizo.cz", "adito.de", "adito.cloud",
    "kontakti.lv", "mkontakt.com", "mailu.io", "mt5.com", "saber.games", "sober.com", "siber.com",
    "sbert.net", "gozon.hu", "mozon.nl", "ozona.com", "megafoni.org",
])
def test_words_and_names_next_to_a_brand_are_not_typos(host):
    assert _typo(host) is None


@pytest.mark.parametrize("host", [
    # Tele2 AB and Tele2 Kazakhstan; VEON's Beeline and Beeline (US); Bell
    # MTS, MTS Systems, Telekom Srbija; Megafon in Danish, Norwegian, Hungarian.
    "tele2.se", "tele2.nl", "tele2.com", "tele2.kz", "beeline.com", "beeline.kz", "beeline.uz",
    "mts.net", "mts.pt", "megafon.dk", "megafon.no", "megafon.tj",
    # 'tele' plus a character is somebody else: TV channels, a news site.
    "tele5.de", "tele1.ch", "tele3.cz", "telex.hu",
])
def test_names_other_companies_own_abroad_are_not_typos(host):
    assert _typo(host) is None


@pytest.mark.parametrize("host", [
    # Other banks and stores: the part before 'bank' / 'store' is what differs.
    "swedbank.se", "swedbank.com", "altabank.ru", "oberbank.at", "enerbank.com", "fiberbank.net",
    "liberbank.es", "superbank.id", "gtbank.com", "mbank.pl", "dbank.com", "tdbank.com", "otpbank.ru",
    "mtsbank.ru", "tcsbank.ru", "tkbbank.ru", "sacombank.com", "doncombank.ru", "belgazprombank.by",
    "alphabank.ro", "upstore.net", "edrugstore.com", "restore.com", "icicibank.com", "vitabank.ru",
])
def test_other_banks_and_stores_are_not_typos(host):
    assert _typo(host) is None


@pytest.mark.parametrize("host", [
    # Two edits under 8 letters, which the similarity ratio used to let
    # through: aviator ~ avito, kontakt ~ vkontakte, rutor ~ rustore …
    "aviator.co", "gravito.net", "kontakt.io", "kontakt.ge", "rutor.org", "breezeline.com",
    "eyeline.mobi", "mailer.company", "mailup.com", "pochtamt.ru", "megaone.com", "megafonpro.ru",
    "yandexgo.com",
    # … and did for the global brands: 158 top-100k names, e.g.
    "express.de", "capital.com", "brookings.edu", "mediafire.com", "norton.com", "credit.com",
    "shopifycdn.com", "cloudflare-dns.com", "dropboxapi.com",
])
def test_two_edits_under_eight_letters_are_not_a_typo(host):
    assert _typo(host) is None


@pytest.mark.parametrize("host", [
    # Named in the task as brand-adjacent and legitimate.
    "mtsbank.ru", "mts-bank.ru", "sberbank-ast.ru", "tinkoffinsurance.ru", "tinkoff-insurance.ru",
    "ozon.travel", "vk.company", "yandex.cloud", "alfaforex.ru", "alfa-forex.ru", "gazprom-neft.ru",
    "gazpromneft.ru", "gazprom-media.com", "sberleasing.ru", "sberdevices.ru", "sbercloud.ru",
    "sberauto.com", "wbbank.ru", "avitoma.ru", "halvacard.ru", "t-j.ru",
])
def test_brand_adjacent_legitimate_names_are_not_typos(host):
    assert _typo(host) is None


def _eval_module():
    import importlib
    import sys

    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    return importlib.import_module("eval_ru_heuristics")


# PHISH hosts main @ ebb46e0 scored 'safe' on the name alone (ML stubbed)
# that the Russian list catches. test_ru_heuristic_fps holds the older
# detections host by host; this holds the new ones.
_CAUGHT_NOW = {
    "sberbamk.ru", "sbrebank.ru", "sberbnk.ru", "gosuslgi.ru", "gossuslugi.ru", "gosuslugii.ru",
    "gosusluga.ru", "tinkof.ru", "tinkkoff.ru", "tbamk.ru", "alfabamk.ru", "alfabnak.ru",
    "wildberies.ru", "wildberrise.ru", "avitto.ru", "yanbex.ru", "g0suslugi.ru", "t1nkoff.ru",
    "0zon.ru", "av1to.ru", "wi1dberries.ru", "vvildberries.ru", "gosuslugi-verify.com",
    "tbank-login.ru", "alfabank-secure.net", "megaf0n.ru", "bee1ine.ru", "m7s.ru", "gzprombank.ru",
    "pchtabank.ru", "uralsb.ru", "rust0re.ru", "russianpst.ru", "odnoklasniki.com",
    "wildberries.shop", "ozon.pro", "xn--80abap1arsf.xn--p1acf", "cdek.nu", "cdek.in", "cdek.at",
}


def test_the_phish_set_catches_the_russian_brand_typos(no_ml):
    ev = _eval_module()
    rows = ev.score_hosts(ev.load(ev.PHISH_PATH))
    caught = {r["host"] for r in rows if r["level"] != "safe"}
    assert _CAUGHT_NOW <= caught, sorted(_CAUGHT_NOW - caught)


def test_the_russian_legit_sets_stay_clean():
    """0 typosquat hits before, 0 after, on both Russian legit sets."""
    for path in (ROOT / "tests" / "data" / "ru_heuristics_legit.txt", ROOT / "data" / "benchmark_legit_ru.txt"):
        hosts = [ln.split(" | ")[0].strip() for ln in path.read_text(encoding="utf-8").splitlines()
                 if ln.strip() and not ln.startswith("#")]
        assert hosts
        assert [h for h in hosts if _typo(h)] == [], path.name


# ── The rule's helpers ──

@pytest.mark.parametrize("a, b, limit, expected", [
    ("avito", "avito", 0, True), ("avlto", "avito", 1, True), ("avitto", "avito", 1, True),
    ("aivto", "avito", 1, True),  # a swap is one edit
    ("aviator", "avito", 1, False), ("aviator", "avito", 2, True), ("rutor", "rustore", 1, False),
    ("kontakt", "vkontakte", 1, False), ("", "ab", 2, True), ("abc", "", 2, False),
])
def test_edit_distance_at_most(a, b, limit, expected):
    assert _edit_distance_at_most(a, b, limit) is expected


@pytest.mark.parametrize("name, brand, expected", [
    ("swedbank", "sberbank", 4), ("7bank", "tbank", 4), ("upstore", "rustore", 5),
    ("сбербанкк", "сбербанк", 0), ("sberbamk", "sberbank", 0), ("bank", "tbank", 0), ("tbank", "citibank", 4),
])
def test_generic_tail(name, brand, expected):
    assert _generic_tail(name, brand) == expected


def test_every_latin_russian_name_is_also_checked_under_open_zones():
    latin = {n for g in scoring.RU_BRAND_GROUPS for n in g.names if n.isascii()}
    assert latin <= scoring._RU_ZONE_BRANDS


@pytest.mark.parametrize("host, brand", [
    ("megafon.spb.ru", "megafon"), ("gazprombank-online.msk.ru", "gazprombank"), ("cdek.nov.ru", "cdek"),
])
def test_new_brands_bought_under_an_open_zone(host, brand, no_ml):
    assert scoring._check_brand_under_open_zone(host) == brand
    assert calculate_score({"domain": host})[1] != RiskLevel.safe


# ── What the Russian brands do NOT change ──

def test_brand_subdomain_abuse_keeps_to_the_global_brands():
    """'pochta' is what Russian companies call their webmail
    (pochta.<company>.ru), and seller tools put ozon. / wildberries. in front
    of their own names: Russian brands as subdomain labels have not had
    their false-positive pass. Under an open Russian zone the narrow
    _check_brand_under_open_zone still reports them."""
    assert _check_brand_in_subdomain("ozon.mpstats.io") is None
    assert _check_brand_in_subdomain("pochta.example.ru") is None
    assert _check_brand_in_subdomain("paypal.evil.com") == "paypal"


def test_the_ml_similarity_feature_reads_the_global_brands_only():
    """The served model was trained on this feature over the global list."""
    from difflib import SequenceMatcher

    from api.services.url_features import _max_brand_similarity

    for name in ("sberbank-ast", "wildberies", "mtsbank"):
        expected = max(SequenceMatcher(None, name, b).ratio() for b in GLOBAL_TYPOSQUAT_TARGETS if b != name)
        assert _max_brand_similarity(name) == round(expected, 3)

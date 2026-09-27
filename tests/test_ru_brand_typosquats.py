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
        for field in ("official", "unrelated", "not_typos", "no_fuzzy", "shared_name"):
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
    ("почтабанк.рф", "offered for sale at reg.ru — not Почта Банк's"),
    ("beellne.ru", "a copy of Beeline's page on a rented VDS"),
    ("sberbank.biz", "registered 2026-06-19 at a retail registrar, behind Cloudflare"),
    ("yandez.ru", "sends its visitors on to an affiliate"),
    # The second pass (after PR #62's review) read every registered
    # <brand>.<TLD> and one-edit .ru name; these were the brand's imitators.
    ("gosuslugi.ch", "a copy titled 'Портал государственных услуг Российской Федерации' on a Swiss host"),
    ("gosuslugiq.ru", "'Госуслуги Личный кабинет — Вход на Официальный сайт'"),
    ("sberbanc.ru", "'СберБанк и СберБанк Онлайн' on someone else's server"),
    ("yinkoff.ru", "titled 'Тинькофф Банк'"),
    ("avito.site", "'AVITA - Площадка объявлений' under a TLD phishing favours"),
    ("tinkoff.business", "sends visitors to tbank-online.com"),
    ("yandex.ru.com", "behind Cloudflare's 'Suspected Phishing' interstitial"),
    ("theozon.ru", "an 'Authorization' page on a Belarusian host"),
    ("tbankapp.ru", "'T-Bank — Ввод ключа'"),
    ("vtb-team.ru", "a copy of VTB's home page on justhost.ru"),
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


# ── The second pass, after PR #62's review ──

_BRAND_SIGNALS = {"typosquatting", "homograph_attack", "brand_subdomain_abuse"}


def _official_and_unrelated() -> list[str]:
    return sorted({d for g in scoring.RU_BRAND_GROUPS for d in (g.official | g.unrelated)})


@pytest.mark.parametrize("host", _official_and_unrelated())
def test_every_listed_domain_scores_safe_with_no_brand_signal(host, no_ml):
    """The whole verdict, not just the typo rule: втб.рф — VTB's own domain —
    came back 'dangerous 60' through the homograph check, which never saw the
    list's exemptions. Both IDN spellings, apex and www."""
    for h in (host, "www." + host):
        score, level, reasons = calculate_score({"domain": h})
        assert level == RiskLevel.safe, (h, score, [(r.signal, r.detail) for r in reasons])
        assert not {r.signal for r in reasons} & _BRAND_SIGNALS, h


@pytest.mark.parametrize("host", [
    "xn--90ab2c.xn--p1ai", "www.xn--90ab2c.xn--p1ai", "online.xn--90ab2c.xn--p1ai", "втб.рф",
])
def test_vtb_s_own_cyrillic_domain_is_no_homograph(host):
    """'р' of the .рф TLD is Cyrillic, not a disguise, and 'втб' maps to
    itself — which is VTB's Cyrillic name on the target list."""
    assert scoring._check_homograph(host) is None


@pytest.mark.parametrize("host, site", [
    ("p\u0430ypal.com", "paypal.com"), ("xn--pypal-4ve.com", "paypal.com"), ("\u0430vito.ru", "avito.ru"),
    ("\u043ezon.ru", "ozon.ru"), ("sb\u0435rbank.ru", "sberbank.ru"),  # Cyrillic а, о, е
])
def test_mixed_script_look_alikes_are_still_homographs(host, site):
    assert scoring._check_homograph(host) in (site, scoring.TYPOSQUAT_TARGETS.get(site.split(".")[0]))


@pytest.mark.parametrize("host", [
    # Regional portals of state services, on the regions' name servers or
    # linked from their governments' sites (data file has the evidence).
    "gosuslugi26.ru", "51gosuslugi.ru", "gosuslugi31.ru", "gosuslugi35.ru", "gosuslugi41.ru",
    "gosuslugi43.ru", "44gosuslugi.ru", "gosuslugi46.ru", "gosuslugi65.ru", "gosuslugi68.ru",
    "gosuslugi74.ru", "gosuslugi82.ru", "gosuslugi86.ru", "gosuslugi92.ru",
])
def test_regional_gosuslugi_portals_are_safe(host, no_ml):
    _, level, reasons = calculate_score({"domain": host})
    assert level == RiskLevel.safe
    assert "typosquatting" not in {r.signal for r in reasons}


@pytest.mark.parametrize("host", [
    # Registered NN-gosuslugi names that are no region's: a private person's
    # site that is down, one for sale, a private nginx, one expired.
    "23gosuslugi.ru", "gosuslugi24.ru", "gosuslugi52.ru", "gosuslugi01.ru",
])
def test_other_numbered_gosuslugi_names_stay_flagged(host):
    assert _typo(host) == ("gosuslugi.ru", "high similarity")


@pytest.mark.parametrize("host", [
    # A shared name under a country's or a legacy TLD is someone's own name:
    "ozon.pl", "ozon.cz", "ozon.fr", "ozon.jp", "ozon.hu", "tbank.com", "tbank.us", "tbank.co",
    "vtb.nl", "vtb.jp", "vtb.lv", "vtb.ge", "avito.at", "avito.pl", "avito.no", "avito.bg", "sber.fr",
    "sber.at", "wildberries.com", "wildberries.se",
    # … and T Bank N.A. and others under a lure TLD, listed as unrelated:
    "tbank.pro", "tbank.info", "tbank.biz", "vtb.info", "vtb.live", "avito.biz", "tele2.biz", "tele2.info",
    "mts.info", "megafon.biz", "megafon.live",
    # A distinctive name's other owners, listed:
    "sberbank.cz", "sberbank.hu", "tinkoff.ro", "tinkoff.com", "uralsib.by", "alfabank.kg",
])
def test_other_owners_of_a_brand_s_name_are_not_typos(host):
    assert _typo(host) is None


@pytest.mark.parametrize("host, site", [
    # Under a TLD phishing favours, a shared name is still the brand's.
    ("ozon.shop", "ozon.ru"), ("ozon.pro", "ozon.ru"), ("vtb.top", "vtb.ru"), ("avito.site", "avito.ru"),
    ("tbank.xyz", "tbank.ru"), ("wildberries.shop", "wildberries.ru"), ("mts.top", "mts.ru"),
    ("beeline.online", "beeline.ru"), ("sber.store", "sber.ru"),
    # A distinctive name is reported under any other TLD.
    ("yandex.jp", "yandex.ru"), ("gosuslugi.ch", "gosuslugi.ru"), ("cdek.nu", "cdek.ru"),
    ("tinkoff.de", "tinkoff.ru"), ("sberbank.pl", "sberbank.ru"),
])
def test_tld_confusion_on_shared_and_distinctive_names(host, site):
    assert _typo(host) == (site, "TLD confusion")


@pytest.mark.parametrize("host", [
    # One substitution under 8 letters that is no slip — not a neighbouring
    # key, a look-alike, a vowel or the other spelling of a sound — is
    # another word. Every one of these is a live business (2026-09-27).
    "megafox.ru", "megason.ru", "megafor.ru", "tirkoff.ru", "cinkoff.ru", "avico.ru", "aviko.ru",
    "avido.ru", "avits.ru", "bvito.ru", "beelink.ru", "beelike.ru", "keeline.ru", "uralgib.ru",
    "uralsiz.ru", "mailgu.ru", "landex.ru", "yanhex.ru", "megafog.ru", "megafol.ru",
])
def test_an_odd_letter_in_a_short_russian_name_is_another_word(host):
    assert _typo(host) is None


@pytest.mark.parametrize("host, site", [
    ("yandez.ru", "yandex.ru"), ("handex.ru", "yandex.ru"),  # neighbouring key
    ("timkoff.ru", "tinkoff.ru"), ("yandcx.ru", "yandex.ru"),  # m/n, c/e look alike
    ("magafon.ru", "megafon.ru"), ("yandax.ru", "yandex.ru"),  # a vowel for a vowel
    ("sovkombank.xyz", "sovcombank.ru"),  # к spelled k
    ("avlto.ru", "avito.ru"), ("sberbamk.ru", "sberbank.ru"), ("t1nkoff.ru", "tinkoff.ru"),
    ("megfon.ru", "megafon.ru"), ("avitto.ru", "avito.ru"), ("ayndex.ru", "yandex.ru"),  # unchanged shapes
    ("gosusluvi.ru", "gosuslugi.ru"), ("wildberrtes.ru", "wildberries.ru"),  # 8+ letters: unchanged
])
def test_slips_are_still_typos(host, site):
    assert _typo(host)[0] == site


def test_the_slip_rule_leaves_the_global_brands_alone():
    """paypal's neighbourhood has not been measured this way."""
    assert _typo("paypol.com") == ("paypal.com", "character substitution")
    assert _typo("amazin.com")  # n for o: no slip, still a global brand's typo


@pytest.mark.parametrize("a, b, slip", [
    ("f", "t", True), ("f", "c", True), ("q", "a", True), ("n", "x", False), ("s", "f", False),
    ("m", "n", True), ("l", "i", True), ("c", "k", True), ("o", "a", True), ("и", "я", True),
    ("ц", "ф", True), ("я", "м", False), ("0", "o", True),
])
def test_is_slip(a, b, slip):
    assert scoring._is_slip(a, b) is slip


@pytest.mark.parametrize("host", [
    # Words and names one edit from a brand (not_typos).
    "megaton.ru", "megafono.it", "megafoon.nl", "berline.ru", "kontakte.de", "kontakter.no",
    "xn--d1achkm1a.xn--p1ai",  # индекс.рф
])
def test_more_words_next_to_a_brand_are_not_typos(host):
    assert _typo(host) is None


@pytest.mark.parametrize("host", [
    # Glued combos of names under 4 letters are other words.
    "mtscom.ru", "vkweb.ru", "mtsweb.net", "gomts.com", "mtshelp.com", "usemts.com", "thevk.net",
    "vtbweb.com", "myvtb.com", "vkrf.org", "dhlweb.com", "upshelp.com",
    # Short and shared names with a generic word, abroad, are other firms.
    "mts-team.com", "vk-net.net", "try-mts.com", "beelinesupport.com", "trybeeline.com", "thebeeline.ca",
    "the-beeline.com", "ozonnet.com", "ozonweb.com", "trymegafon.com", "goozon.com",
])
def test_generic_combos_of_short_and_shared_names_abroad_are_not_typos(host):
    assert _typo(host) is None


@pytest.mark.parametrize("host, site", [
    # A lure word is still the brand, at any length.
    ("vk-login.com", "vk.com"), ("mts-secure.ru", "mts.ru"), ("vtb-verify.com", "vtb.ru"),
    ("dhl-login.com", "dhl.com"), ("dhl-help.com", "dhl.com"), ("dhllogin.com", "dhl.com"),
    ("vtbsecure.com", "vtb.ru"),  # a lure keyword counts glued too
    # Under .ru a shared name means the Russian brand, generic word or not.
    ("vtb-team.ru", "vtb.ru"), ("mts-help.ru", "mts.ru"), ("beeline-com.ru", "beeline.ru"),
    ("theozon.ru", "ozon.ru"), ("tbankapp.ru", "tbank.ru"), ("mysber.ru", "sber.ru"),
])
def test_combos_that_still_count(host, site):
    assert _typo(host) == (site, "combosquatting")


@pytest.mark.parametrize("host, site", [
    # The brand's .ru address with .com appended: ru.com and ru.net are
    # zones anyone can register in (PSL private suffixes).
    ("yandex.ru.com", "yandex.ru"), ("gosuslugi.ru.com", "gosuslugi.ru"), ("sberbank.ru.com", "sberbank.ru"),
    ("mail.ru.com", "mail.ru"), ("vk.ru.com", "vk.ru"), ("mts.ru.net", "mts.ru"), ("ozon.ru.net", "ozon.ru"),
    ("login.yandex.ru.com", "yandex.ru"),
])
def test_a_brand_s_address_under_ru_com_is_tld_confusion(host, site):
    assert _typo(host) == (site, "TLD confusion")


def test_ru_com_names_are_compared_like_any_name(no_ml):
    assert _typo("yandx.ru.com") == ("yandex.ru", "high similarity")
    # A global brand there is still brand_subdomain_abuse's, as before.
    assert _typo("paypal.ru.com") is None
    _, level, reasons = calculate_score({"domain": "paypal.ru.com"})
    assert "brand_subdomain_abuse" in {r.signal for r in reasons}


@pytest.mark.parametrize("host, site", [
    # The brand plus its country.
    ("avito-ru.com", "avito.ru"), ("ozon-ru.com", "ozon.ru"), ("sberbank-ru.com", "sberbank.ru"),
    ("gosuslugi-ru.com", "gosuslugi.ru"), ("wildberries-ru.com", "wildberries.ru"),
    ("tinkoff-ru.com", "tinkoff.ru"), ("megafon-ru.com", "megafon.ru"), ("cdek-ru.com", "cdek.ru"),
    ("avitoru.com", "avito.ru"), ("tinkoffru.com", "tinkoff.ru"), ("cdek-russia.ru", "cdek.ru"),
    ("vtb-ru.com", "vtb.ru"),
])
def test_a_brand_with_its_country_is_a_combo(host, site):
    assert _typo(host) == (site, "combosquatting")


@pytest.mark.parametrize("host", [
    "vtbru.com",  # a name under 4 letters needs the hyphen
    "vtb-russia.ru", "vtbrussia.com", "ozonru.com",  # the brands' own
    "paypal-ru.com",  # the global brands do not get the country word
])
def test_country_combos_that_do_not_count(host):
    assert _typo(host) is None


def test_an_open_zone_name_is_reported_without_claiming_intent(no_ml):
    """cdek.msk.ru calls itself CDEK's partner: the reason says what the name
    does to a reader. The block page reads the brand from the quotes."""
    _, level, reasons = calculate_score({"domain": "cdek.msk.ru"})
    detail = next(r.detail for r in reasons if r.signal == "brand_subdomain_abuse")
    assert level == RiskLevel.caution
    assert "'cdek' brand" in detail and "deceive" not in detail


def test_an_open_zone_name_the_list_vouches_for_is_not_reported(monkeypatch):
    assert scoring._check_brand_under_open_zone("megafon.msk.ru") == "megafon"
    monkeypatch.setattr(scoring, "_BRAND_LEGIT_DOMAINS", scoring._BRAND_LEGIT_DOMAINS | {"megafon.msk.ru"})
    assert scoring._check_brand_under_open_zone("megafon.msk.ru") is None


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


# Added by the second pass: live look-alikes it found, and the ru.com and
# country shapes the first cut missed.
_CAUGHT_BY_THE_SECOND_PASS = {
    "yandex.ru.com", "pochtabank.ru.com", "russianpost.ru.com", "gosuslugi.ch", "gosuslugiq.ru",
    "gosuslugirus.ru", "sberbanc.ru", "yinkoff.ru", "thinkoff.ru", "theozon.ru", "tbankapp.ru", "vtb-team.ru", "avito.site",
    "gosuslugi.ru.com", "sberbank.ru.com", "ozon.ru.net", "avito-ru.com", "ozon-ru.com", "sberbank-ru.com",
    "wildberries-ru.com",
}


def test_the_phish_set_catches_the_second_pass_finds(no_ml):
    ev = _eval_module()
    rows = {r["host"]: r for r in ev.score_hosts(ev.load(ev.PHISH_PATH))}
    assert _CAUGHT_BY_THE_SECOND_PASS <= set(rows)
    missed = sorted(h for h in _CAUGHT_BY_THE_SECOND_PASS if rows[h]["level"] == "safe")
    assert missed == []
    assert all("typosquatting" in rows[h]["signals"] for h in _CAUGHT_BY_THE_SECOND_PASS)


def test_the_russian_legit_sets_stay_clean():
    """No typosquat hit on either Russian legit set — including the 40
    hosts the second pass added: 14 regional Gosuslugi portals, brand-family
    domains such as втб.рф, and 23 businesses one letter or a word from a
    brand (megafox.ru, tirkoff.ru, индекс.рф …), which the first cut flagged."""
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

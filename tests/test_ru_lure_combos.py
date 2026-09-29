"""Russian brands next to a lure word (api/services/ru_lures.py).

After PR #62, 25 of the 34 hosts in tests/data/ru_heuristics_phish.txt that
scored 'safe' on the name alone were a Russian brand spelled right plus a
Russian or transliterated word:
sberbank-bonus, ozon-priz, avito-dostavka, tele2-podarok, gosuslugi-lk,
yandex-doctavym, госуслуги-лк.рф. These tests pin what the lure words catch
and what the false-positive pass cleared:

  - brands' own names with a lure word, on the brand's name servers
    (mts-bonus.ru, ozon-dostavka.ru, ozonbonus.ru), listed as official;
  - a brand that is only part of a word (vkusvill, ozone) is no brand;
  - 'online' lures only for Sber and VTB, whose internet banks are called
    'Онлайн' — vk-online.ru is a Perm news agency, beeline-online.info a
    Polish food blog;
  - 't2', 'wb' and 'сбер' are no names: t2gift.com, wbkabinet.ru and
    сбердоставка.рф are other businesses;
  - the global brands and the ML similarity feature are untouched.

The ML model is stubbed where a whole verdict is scored.
"""
from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

from api.models.schemas import RiskLevel
from api.services import ru_brands, ru_lures, scoring
from api.services.scoring import (
    _check_brand_under_open_zone,
    _check_lure_combo,
    _check_typosquatting_v2,
    _decode_idn,
    calculate_score,
)

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def no_ml(monkeypatch):
    import api.services.ml_scorer as ml_scorer
    monkeypatch.setattr(ml_scorer, "ml_predict", lambda domain: None)


def _typo(host: str):
    """The rule on the name as the scorer hands it over: decoded."""
    return _check_typosquatting_v2(_decode_idn(host))


# ── The vocabulary ──

@pytest.mark.parametrize("spellings", [
    # One Russian word, every way it is typed: transliterations, the Latin
    # 'c' for the Cyrillic 'с', a doubled letter, a digit for a letter.
    ("компенсация", "kompensaciya", "kompensatsiya", "kompensacija", "kompensacia"),
    ("защита", "zaschita", "zashchita", "zashita"),
    ("вход", "vhod", "vxod", "vkhod"),
    ("доставка", "dostavka", "doctavka"),
    ("бонус", "bonus", "bonuss", "b0nus"),
    ("гарантия", "garantiya", "garantia", "garantija"),
    ("акция", "akciya", "aktsiya", "akcia"),
    ("кешбэк", "кэшбэк", "keshbek"),
])
def test_one_word_has_one_skeleton_in_every_spelling(spellings):
    assert len({ru_lures.skeleton(s) for s in spellings}) == 1, [ru_lures.skeleton(s) for s in spellings]


@pytest.mark.parametrize("word", [
    "bonus", "bonusy", "бонусы", "priz", "prizy", "приз", "podarok", "podarki", "подарок", "vyplata",
    "vyplaty", "выплаты", "kompensaciya", "компенсация", "dostavka", "doctavka", "dostavkoy", "dostavkuy",
    "doctavym", "доставкой", "oplata", "оплата", "vozvrat", "возврат", "lk", "лк", "kabinet", "кабинет",
    "vhod", "вход", "voiti", "podtverdit", "подтверждение", "blokirovka", "razblokirovka", "блокировка",
    "zaschita", "защита", "garantiya", "гарантия", "promo", "promokod", "промокод", "akciya", "акция",
    "keshbek", "cashback", "vyigrysh", "выигрыш", "rozygrysh", "sdelka", "сделка", "bezopasnaya",
    "verifikaciya", "avtorizaciya", "proverka", "gift", "prize",
])
def test_lure_words_in_every_script(word):
    assert ru_lures.is_lure(word), word


@pytest.mark.parametrize("word", [
    # 'priz' is a word, not a stem: prism, recognition, conscription.
    "prizma", "призма", "priznanie", "prizyv",
    # Product and category words the pass left out: brands and their
    # partners use them (tbank-online.com, gazprombank-pay.ru, mts-pay.ru,
    # wb-pvz.ru), and 'online' lures for two banks only (see below).
    "online", "онлайн", "pay", "id", "bank", "pvz", "zaim", "kredit", "karta", "delivery", "track",
    # Nothing, and ordinary words ('gifs' is what 'gifts' folds to).
    "", "ru", "shop", "news", "market", "plus", "gifs",
])
def test_words_that_are_not_lures(word):
    assert not ru_lures.is_lure(word), word


def test_every_stem_is_long_enough_to_mean_one_thing():
    assert all(len(s) >= ru_lures.MIN_STEM for s in ru_lures.LURE_STEMS), ru_lures.LURE_STEMS


# ── Brand + lure word ──

# The misses from PR #62's 'Not fixed here', host by host.
@pytest.mark.parametrize("host, site", [
    ("sberbank-bonus.ru", "sberbank.ru"), ("ozon-priz.ru", "ozon.ru"), ("avito-dostavka.ru", "avito.ru"),
    ("tele2-podarok.ru", "t2.ru"), ("mts-podarok.ru", "mts.ru"), ("gosuslugi-lk.help", "gosuslugi.ru"),
    ("wildberries-promo.shop", "wildberries.ru"), ("cdek-dostavka.info", "cdek.ru"),
    ("yandex-doctavym.website", "yandex.ru"), ("yandex-dostavkoy.website", "yandex.ru"),
    ("yandex-dostavkuy.website", "yandex.ru"), ("yandex-pay-login.com", "yandex.ru"),
    ("vtb-online-bank.com", "vtb.ru"), ("sberbank-online-login.ru", "sberbank.ru"),
    ("sber-vozvrat.site", "sber.ru"), ("tinkoff-bonus.xyz", "tinkoff.ru"), ("vk-login-verify.com", "vk.com"),
    ("sberbank0nline.ru", "sberbank.ru"),
    ("xn----etbaulcdt1aavc.xn--p1ai", "gosuslugi.ru"),      # госуслуги-лк.рф
    ("xn----7sbbbax6afkrcdiwm.xn--p1ai", "sberbank.ru"),    # сбербанк-онлайн.рф
    ("xn----dtbbahvtxfyaxc6a.xn--p1ai", "gosuslugi.ru"),    # госуслуги-вход.рф
    ("xn----btbtiodec2abtha2i.xn--p1ai", "tinkoff.ru"),     # тинькофф-бонус.рф
])
def test_the_lure_combos_pr62_missed_are_caught(host, site):
    assert _typo(host) == (site, "combosquatting"), host


@pytest.mark.parametrize("host", [
    # The word before the brand, glued to it, or among several words.
    "bonus-sberbank.ru", "lk-gosuslugi.ru", "kabinet-mts.ru", "sberbankbonus.ru", "ozonpriz.shop",
    "gosuslugilk.ru", "tele2podarok.com", "avito-bezopasnaya-sdelka.ru", "lichnyj-kabinet-tele2.ru",
    "wildberries-vyplata-kompensacii.ru", "mts-bonusy-2026.ru", "vk-vhod.ru", "vkpodarok.ru",
    # A shared name is the brand's next to a lure word, under any TLD.
    "ozon-bonus.pl", "tbank-vhod.com", "beeline-bonus.de",
    # Cyrillic brands with Cyrillic words, and a Cyrillic word after a Latin name.
    "втб-онлайн.рф", "яндекс-доставка.рф", "почтароссии-оплата.рф", "sberbank-бонус.рф",
])
def test_word_order_glue_and_scripts(host):
    assert _typo(host) is not None, host


@pytest.mark.parametrize("name, brand, expected", [
    ("sberbank-bonus", "sberbank", True), ("bonus-sberbank", "sberbank", True),
    ("sberbankbonus", "sberbank", True), ("sberbank-x-bonus", "sberbank", True),
    # The brand has to be a whole word: VkusVill is not VK, ozone not Ozon.
    ("vkusvill-bonus", "vk", False), ("ozone-bonus", "ozon", False), ("mtsbank-bonus", "mts", False),
    # A word glued to the brand has to be the lure itself.
    ("sberbankclub-bonus", "sberbank", False), ("sberbank", "sberbank", False),
    # English keywords count too for a Russian brand among several words.
    ("vk-login-verify", "vk", True),
])
def test_check_lure_combo(name, brand, expected):
    assert _check_lure_combo(name, brand) is expected


def test_a_lure_combo_alone_is_caution(no_ml):
    _, level, reasons = calculate_score({"domain": "sberbank-bonus.ru"})
    assert level == RiskLevel.caution
    typo = [r for r in reasons if r.signal == "typosquatting"]
    assert typo and typo[0].detail == "Impersonates sberbank.ru (combosquatting)"


# ── 'online': a lure for Sber and VTB only ──

def test_online_lures_only_for_the_banks_named_online():
    groups = {g.key: g for g in scoring.RU_BRAND_GROUPS}
    with_words = {k for k, g in groups.items() if g.lure_words}
    assert with_words == {"sber", "vtb"}
    assert groups["sber"].lure_words == {"online", "онлайн"}


@pytest.mark.parametrize("host", [
    "sberbank-online.xyz", "sber-online.ru", "online-vtb.ru", "vtbonline.com", "сбербанк-онлайн.рф",
])
def test_sber_and_vtb_online_names_are_caught(host):
    assert _typo(host) is not None, host


@pytest.mark.parametrize("host", [
    # Other brands' 'online' names are not reported by the lure rule: some
    # are someone else's, and 'online' is no product of theirs.
    "vk-online.ru",          # ИА «Верхнекамье»: ВК is the region
    "mts-online.com",        # a German hotel-marketing agency
    "beeline-online.info",   # a Polish food blog
    "tbank-online.com",      # T-Bank's own (its ns2/ns3.tbank.ru addresses)
    "avitoonline.ru",        # 'Авторизация Avito' — a known miss, see the PHISH set
])
def test_online_is_no_lure_for_other_brands(host):
    assert _typo(host) is None, host


# ── The false-positive pass ──

@pytest.mark.parametrize("host", [
    # On the brand's own name servers (whois 2026-09-29), listed as official.
    "mts-bonus.ru", "mtsbonus.com", "mtscashback.ru", "ozon-dostavka.ru", "ozondostavka.ru", "ozonbonus.ru",
])
def test_brands_own_lure_names_are_exempt(host, no_ml):
    assert _typo(host) is None
    score, level, reasons = calculate_score({"domain": host})
    assert level == RiskLevel.safe, (host, score, [r.signal for r in reasons])


@pytest.mark.parametrize("host", [
    # 't2', 'wb' and 'сбер' are no listed names: next to a lure word they are
    # other businesses as often as not.
    "t2gift.com", "wbkabinet.ru", "wbdostavka.ru", "xn--80aabfif2b3aqhfm.xn--p1ai",  # сбердоставка.рф
    # A brand inside another word.
    "vkusvill-bonus.ru", "ozone-bonus.com", "mtsbank-bonus.ru",
])
def test_names_that_only_look_like_a_brand_and_a_lure(host):
    assert _typo(host) is None, host


@pytest.mark.parametrize("host, why", [
    # Businesses trading on the name stay caution, as dealers do since #62:
    # 'официальный партнёр' is the site's own claim.
    ("avito-promo.ru", "'Avito Promo — запуск и ведение бизнеса на Авито', a private person's"),
    ("mts-promo.com", "'Провайдер МТС - домашний интернет', a dealer"),
    ("cdek-dostavka.ru", "'Оформление договора со СДЭК для юридических лиц', an agent"),
    ("dostavka-yandex.ru", "courier recruitment by a partner"),
    ("lk-sberbank.ru", "'Личный кабинет Сбербанк — Не официальный сайт'"),
    ("oplata-tele2.ru", "a third party's top-up page"),
])
def test_businesses_trading_on_the_name_stay_flagged(host, why):
    assert _typo(host), why


def test_no_top_1m_name_but_ozon_s_own_is_a_new_hit():
    """The Tranco top-1M (2026-04) had two names the lure rule flags that
    main did not: ozon-dostavka.ru, Ozon's own (now listed), and
    prize-wildberries.online, gone by 2026-09-29. Pinned through the data:
    the first is official."""
    ozon = next(g for g in scoring.RU_BRAND_GROUPS if g.key == "ozon")
    assert "ozon-dostavka.ru" in ozon.official
    assert _typo("prize-wildberries.online") == ("wildberries.ru", "combosquatting")


# ── Under an open Russian zone ──

@pytest.mark.parametrize("host, brand", [
    ("mts-bonus.spb.ru", "mts"), ("vk-podarok.nov.ru", "vk"), ("ok-bonus.msk.ru", "ok"),
    ("t2-vyplata.spb.ru", "t2"), ("sberbankbonus.msk.ru", "sberbank"), ("lk-gosuslugi.nov.ru", "gosuslugi"),
])
def test_short_brands_with_a_lure_under_an_open_zone(host, brand, no_ml):
    assert _check_brand_under_open_zone(host) == brand
    assert calculate_score({"domain": host})[1] != RiskLevel.safe


@pytest.mark.parametrize("host", ["ok-stroy.msk.ru", "vk-group.spb.ru", "mts-bonus.gov.ru"])
def test_short_brands_without_a_lure_or_under_a_restricted_zone(host):
    assert _check_brand_under_open_zone(host) is None


# ── What the lure words do not change ──

@pytest.mark.parametrize("host", ["paypal-bonus.com", "amazon-podarok.com", "apple-dostavka.ru"])
def test_the_global_brands_keep_the_english_combo_list(host):
    """Russian lure words are measured for Russian brands only."""
    assert _typo(host) is None


def test_the_parser_checks_lure_words():
    base = {"owner": "x", "names": {"brandx": "brandx.ru"}, "official": {"brandx.ru": "e"}}
    group = ru_brands.parse_group("x", {**base, "lure_words": {"online": "its product"}})
    assert group.lure_words == {"online"}
    for bad in ({"on-line": "e"}, {"a.b": "e"}, {"online": ""}, ["online"]):
        with pytest.raises(ValueError):
            ru_brands.parse_group("x", {**base, "lure_words": bad})


# ── The recall script ──

def _script(name: str):
    scripts = str(ROOT / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    return importlib.import_module(name)


def test_the_recall_script_measures_every_name_and_lure():
    ev = _script("eval_ru_lure_combos")
    rows = ev.score_variants(list(ev.variants()))
    names = {r["brand"] for r in rows}
    assert names == set(ev.load_names())
    table = ev.table(rows, "lure")
    assert set(table) == set(ev.LURES)
    # The listed spellings are all caught; the 'misspelled' row is there to
    # show what the vocabulary does not generalise to.
    assert all(c == t for k, (c, t) in table.items() if k != "misspelled"), table
    caught, total = table["misspelled"]
    assert 0 < caught < total

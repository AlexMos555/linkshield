"""Lure words that turn a Russian brand's name into a phishing name.

sberbank-bonus, ozon-priz, avito-dostavka, tele2-podarok, gosuslugi-lk,
госуслуги-лк.рф, yandex-doctavym: the brand is spelled right, and the word
next to it is the scam. The typosquat rule's lure list (scoring's
_COMBOSQUAT_KEYWORDS) is English — login, verify, account — so after PR #62
25 of the 34 hosts in tests/data/ru_heuristics_phish.txt that scored 'safe'
on the name alone were a brand plus a Russian word, transliterated or in
Cyrillic.

A word here is what a scam's name promises or threatens. F6's «Мамонт»
report names the delivery fakes (cdek-dostavka.info,
yandex-doctavym.website); the reports behind data/typosquat_targets_ru.json
name copies of banks' and Gosuslugi's log-in pages; the rest are the
payout, giveaway, safe-deal and blocked-account lures of the same schemes:

  money and prizes   бонус, приз, подарок, выплата, компенсация, кешбэк,
                     выигрыш, розыгрыш, промокод, акция
  delivery           доставка (and its inflections: доставкой, доставим)
  payment            оплата, возврат, сделка, безопасная (сделка)
  log-in             лк (личный кабинет), кабинет, вход, войти, аккаунт,
                     авторизация, подтвердить, верификация, проверка
  threats            блокировка, разблокировка, защита, гарантия

A word is matched on a SKELETON of its spelling, so the transliterations of
one Russian word are one entry: компенсация, kompensaciya, kompensatsiya and
kompensacija are all 'kompensasia'; защита, zaschita, zashchita and zashita
all 'zashita'; вход, vhod, vxod and vkhod all 'vhod'. The skeleton also
folds the Latin 'c' an attacker types for the Cyrillic 'с' (doctavka), a
doubled letter (bonuss), and 0 / 3 for o / e (0plata).

Stems match the start of a word (доставк-а/-и/-ой, бонус-ы), and only stems
of five letters or more whose every continuation is still the lure: 'priz'
is a word, not a stem, because призма and признание are not prizes.

Left out, from the false-positive pass of 2026-09-29 (every registered
<brand>-<word>, <word>-<brand> and <brand><word> name, the Tranco top-1M):

  online    a product name for two banks, not a lure for the rest:
            vk-online.ru is a Perm news agency, beeline-online.info a Polish
            food blog, tbank-online.com T-Bank's own. For Sber and VTB, whose
            internet banks are called 'Онлайн', it is a lure_words entry of
            data/typosquat_targets_ru.json.
  pay, id   product names the brands register themselves (mts-pay.ru on
            MTS's name servers, gazprombank-pay.* on their own)
  credit, delivery, karta, zaim, pvz, track, bank
            ordinary business words next to the name: beelinedelivery.com
            is a Houston courier, mtsdelivery.com a medical-transport firm,
            ozon-credit.ru Ozon's own, karta-sovcombank.ru a card affiliate

Brands' own names with a lure word (mts-bonus.ru, ozon-dostavka.ru) are
listed as official there. Recall and cost: scripts/eval_ru_lure_combos.py.
"""
from __future__ import annotations

import re

# Cyrillic to Latin, one letter each, the way Russian names are most often
# spelled in domain names. Only the skeleton reads this: every Latin spelling
# of a sound folds to the same letters below.
_CYRILLIC_TO_LATIN = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e", "ж": "zh",
    "з": "z", "и": "i", "й": "i", "к": "k", "л": "l", "м": "m", "н": "n", "о": "o",
    "п": "p", "р": "r", "с": "s", "т": "t", "у": "u", "ф": "f", "х": "h", "ц": "c",
    "ч": "ch", "ш": "sh", "щ": "sh", "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu",
    "я": "ya",
}
# Latin spellings of one Russian sound, longest first; 'ch' (ч) is parked on
# a placeholder while 'c' folds into 's'. Then: щ as shch/sch, ж as zh, х as
# kh or x, ц as ts/tz/c, с typed as the look-alike Latin 'c', й/ы/и as
# j/y/i, в as w.
_LATIN_FOLDS: tuple[tuple[str, str], ...] = (
    ("shch", "sh"), ("sch", "sh"), ("tch", "\x01"), ("ch", "\x01"), ("zh", "z"), ("kh", "h"),
    ("ck", "k"), ("ts", "s"), ("tz", "s"), ("c", "s"), ("x", "h"), ("w", "v"), ("q", "k"),
    ("j", "i"), ("y", "i"), ("\x01", "ch"),
)
# Digits typed for the letter they look like (0plata, b0nus).
_DIGIT_LETTERS = str.maketrans({"0": "o", "3": "e"})
_DOUBLED = re.compile(r"(.)\1+")


def skeleton(word: str) -> str:
    """The spelling-independent form of one word: Cyrillic transliterated,
    Latin variants of one sound folded, doubled letters collapsed."""
    s = "".join(_CYRILLIC_TO_LATIN.get(ch, ch) for ch in word.lower()).translate(_DIGIT_LETTERS)
    for a, b in _LATIN_FOLDS:
        s = s.replace(a, b)
    return _DOUBLED.sub(r"\1", s)


# Words matched whole. Each row is one lure in the spellings seen or likely;
# the skeleton makes most variants redundant, and they are kept so the list
# reads as what it matches.
_WORDS: tuple[str, ...] = (
    # prizes: not a stem — призма, признание, призыв are other words
    "приз", "призы", "призов", "priz", "prizy", "prizov", "prize", "prizes",
    # not 'gifts': it folds to 'gifs', the images
    "подарок", "gift",
    "промо", "промокод", "promo", "promokod", "promocode",
    "акция", "akciya", "aktsiya", "akcia",
    "кешбэк", "кэшбэк", "кешбек", "keshbek", "keshbak", "cashback", "kashback",
    # log-in
    "лк", "lk", "кабинет", "kabinet", "cabinet",
    "вход", "vhod", "vxod", "vkhod", "войти", "voiti", "vojti",
    "аккаунт", "akkaunt",
    "проверка", "proverka",
)
# Word starts: every word that begins so is the lure.
_STEMS: tuple[str, ...] = (
    "бонус", "bonus",
    "подар", "podar",
    "выплат", "vyplat", "viplat",
    "компенсац", "kompensac", "kompensats", "compensat",
    # выигрыш, выиграй, выиграть ('выигр' folds to four letters)
    "выигрыш", "vyigrysh", "выигра", "vyigra", "розыгр", "rozygr", "rozigr",
    "достав", "dostav", "doctav",
    "оплат", "oplat",
    "возврат", "vozvrat",
    "сделк", "sdelk", "безопасн", "bezopasn",
    "авториз", "avtoriz", "верифик", "verifik", "подтвер", "podtver",
    "блокир", "blokir", "разблокир", "razblokir", "заблокир", "zablokir",
    "защит", "zashit", "zaschit", "zashchit",
    "гарант", "garant",
)
# A stem shorter than this starts other words too (tests hold every stem to it).
MIN_STEM = 5

LURE_WORDS: frozenset[str] = frozenset(skeleton(w) for w in _WORDS)
LURE_STEMS: tuple[str, ...] = tuple(sorted({skeleton(s) for s in _STEMS}))


def is_lure(word: str) -> bool:
    """`word` (one hyphen-free part of a name) is a Russian lure word, in any
    script or transliteration."""
    if not word:
        return False
    s = skeleton(word)
    return s in LURE_WORDS or s.startswith(LURE_STEMS)

"""Training and validation data of the SMS text model: loading, cleaning, provenance.

Training: ml/sms/data/train_{a,b,c}.tsv (three authors, see the headers) and,
as a fourth "author" k, the Kotlin dev corpora the rules were tuned on
(MessageCorpus.kt, MessageSchemeCorpus.kt, MessageGenericCorpus.kt).
Validation only, never trained on: the 2026-10 held-out set and the blind
sets 2026-10b/c/d under mobile/modules/cleanway-vpn/android/src/test/resources.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

import features as F

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / 'ml' / 'sms' / 'data'
MODULE = ROOT / 'mobile' / 'modules' / 'cleanway-vpn' / 'android' / 'src'
RULES = MODULE / 'main' / 'assets' / 'message_rules.json'
TEST_JAVA = MODULE / 'test' / 'java' / 'ai' / 'cleanway' / 'app'
TEST_RES = MODULE / 'test' / 'resources'

TRAIN_FILES = {'a': 'train_a.tsv', 'b': 'train_b.tsv', 'c': 'train_c.tsv'}
VALIDATION_FILES = {
    'heldout': 'message_heldout_2026-10.tsv',
    'blind_b': 'message_blind_2026-10b.tsv',
    'blind_c': 'message_blind_2026-10c.tsv',
    'blind_d': 'message_blind_2026-10d.tsv',
}
KOTLIN_CORPORA = {
    'MessageCorpus.kt': {
        'SCAMS_RU': 'scam', 'SCAMS_EN': 'scam', 'SCAM_VARIANTS': 'scam', 'SCAM_REVIEW': 'scam',
        'LEGIT_RU': 'legit', 'LEGIT_EN': 'legit', 'LEGIT_VARIANTS': 'legit',
        'SCAM_2026_10_DANGEROUS': 'scam', 'SCAM_2026_10_CAUTION': 'scam', 'LEGIT_2026_10': 'legit',
        'SCAM_2026_10_UPGRADES': 'scam', 'LEGIT_2026_10_UPGRADES': 'legit',
    },
    'MessageSchemeCorpus.kt': {'SCAM_DANGEROUS': 'scam', 'SCAM_CAUTION': 'scam', 'LEGIT': 'legit'},
    'MessageGenericCorpus.kt': {'SCAM_DANGEROUS': 'scam', 'SCAM_CAUTION': 'scam', 'LEGIT': 'legit'},
}

# train_b labels lone openers as scam ("привет, это ты?", "вы меня помните", a
# wrong-number text with no ask). Alone they are innocent, and a message-level
# model must not learn to flag them, so they are dropped from training.
DROPPED_SCAM_FAMILIES = frozenset({'first_contact', 'wrong_number'})

# A scam row is kept only when it carries a request, a link, money or a code:
# a special token (link, phone, card, handle, e-mail, file), a sum, or a word
# starting with one of these stems — money, a code or data, a link or an app,
# a call, a vote, a purchase, and an authority's orders or secrecy ("окажите
# содействие", "никому не говорите"); Russian typed in Latin has its own.
# A plea for help alone ("мне нужна помощь, напиши") is not a request here.
REQUEST_TOKENS = frozenset({'_url', '_phone', '_card', '_handle', '_email', '_apk', '_file'})
REQUEST_STEMS = tuple('''
руб тыс денег деньг денежк налич перев перечисл скин скидыв займ занять займи одолж долг карт счет реквизит
оплат оплач заплат плат взнос депозит инвест доход заработ прибыл выплат компенсац выигр приз бонус подар
кешбэк кэшбек крипт usdt кошел биткоин usd eur
код пароль смс sms цифр паспорт снилс данн подтверд подтвержд
ссылк перейд переход зайд зайти войд войти авториз установ скача прилож файл демонстрац экран доступ
проголос голосов перезвон наберит набери свяжит позвонит звонок звонка
фото интим видео работ ваканс подработ задани заказ покуп купи продаж инструкц указани
предоплат залог штраф вклад влож бакс содейств выполн следуйт разглаш никому
money pay card code link click transfer send cash bank gift prize win invest crypto password verify account job earn
perev oplat predoplat kart deng dolg zaym zaim kredit vznos ssylk kod prilozh ustanov skach nalich pribyl dohod
zarab rub kript krip invest vklad vlozh schet balans popoln kup prodayu bilet baks
'''.split())


@dataclass(frozen=True)
class Row:
    source: str      # a, b, c, k (Kotlin corpora), or a validation set name
    label: int       # 1 scam, 0 legit
    family: str
    text: str


def load_tsv(path: Path, source: str) -> list[Row]:
    rows = []
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip() or line.startswith('#') or line.startswith('label\t'):
            continue
        parts = line.split('\t')
        if len(parts) != 3 or parts[0] not in ('scam', 'legit') or not parts[2].strip():
            raise ValueError(f'{path.name}: bad line: {line!r}')
        rows.append(Row(source, 1 if parts[0] == 'scam' else 0, parts[1], parts[2]))
    return rows


_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
_ESCAPES = {'n': '\n', 't': '\t', 'r': '\r', '"': '"', '\\': '\\', '$': '$', "'": "'"}


def kotlin_list(source: str, name: str) -> list[str]:
    """The string literals of `val NAME = listOf(...)` in a Kotlin file (plain "..." literals only)."""
    start = re.search(r'\bval\s+' + name + r'\s*=\s*listOf\(', source)
    if not start:
        raise ValueError(f'list {name} not found')
    i = start.end()
    depth = 1
    out = []
    while depth:
        c = source[i]
        if c == '"':
            m = _STRING.match(source, i)
            out.append(re.sub(r'\\(.)', lambda e: _ESCAPES[e.group(1)], m.group(1)))
            i = m.end()
            continue
        if c == '/' and source[i + 1] == '/':
            i = source.index('\n', i)
            continue
        depth += {'(': 1, ')': -1}.get(c, 0)
        i += 1
    return out


def load_kotlin_corpora() -> list[Row]:
    rows = []
    for file, lists in KOTLIN_CORPORA.items():
        source = (TEST_JAVA / file).read_text(encoding='utf-8')
        for name, label in lists.items():
            for text in kotlin_list(source, name):
                rows.append(Row('k', 1 if label == 'scam' else 0, f'{file[:-3]}.{name}', text))
    return rows


def load_validation() -> dict[str, list[Row]]:
    return {name: load_tsv(TEST_RES / file, name) for name, file in VALIDATION_FILES.items()}


def config() -> F.Config:
    """The normaliser's lists, from the shipped vocabulary asset (frozen into the model at export)."""
    rules = json.loads(RULES.read_text(encoding='utf-8'))
    official = [d for org in rules['organisations'] for d in org.get('domains', [])]
    official += rules['trusted_domains'] + rules['app_stores']
    cyrillic_tlds = [t for t in rules['bare_tlds'] if any(F.is_cyrillic(c) for c in t)]
    return F.Config(official, rules['shorteners'], rules['messengers'], cyrillic_tlds, rules['translit_markers'])


def has_request(text: str, cfg: F.Config) -> bool:
    tokens, translit = F.tokenize(text, cfg)
    for stream in (tokens, translit or []):
        for t in stream:
            if t in REQUEST_TOKENS or t.startswith(REQUEST_STEMS) or amount(t):
                return True
    return False


def amount(token: str) -> bool:
    """A sum: a number of 3+ digits ("000", from 500 or 25 000) or one with a k ("00к" from 70к)."""
    digits = len(token) - len(token.lstrip('0'))
    return digits >= 1 and (digits == len(token) and digits >= 3 or token[digits:] in ('к', 'k', 'т', 'тыс', 'р', 'руб'))


def key(text: str, cfg: F.Config) -> str:
    """Two texts with the same tokens are the same message for leakage checks."""
    return ' '.join(F.tokenize(text, cfg)[0])


def training_rows(cfg: F.Config, with_corpora: bool, validation: dict[str, list[Row]]):
    """(kept rows, dropped rows with the reason) — the drops are reported, never silent."""
    raw = []
    for source, file in TRAIN_FILES.items():
        raw += load_tsv(DATA / file, source)
    if with_corpora:
        raw += load_kotlin_corpora()
    held = {key(r.text, cfg) for rows in validation.values() for r in rows}
    kept, dropped, seen = [], [], set()
    for r in raw:
        k = key(r.text, cfg)
        if r.label == 1 and r.family in DROPPED_SCAM_FAMILIES:
            dropped.append((r, 'family: a lone opener'))
        elif r.label == 1 and not has_request(r.text, cfg):
            dropped.append((r, 'scam with no request, link, money or code'))
        elif k in held:
            dropped.append((r, 'also in a validation set'))
        elif (k, r.label) in seen:
            dropped.append((r, 'duplicate'))
        elif (k, 1 - r.label) in seen:
            dropped.append((r, 'same text under both labels'))
        else:
            seen.add((k, r.label))
            kept.append(r)
    return kept, dropped


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def data_hashes(with_corpora: bool) -> dict[str, str]:
    files = [DATA / f for f in TRAIN_FILES.values()]
    if with_corpora:
        files += [TEST_JAVA / f for f in KOTLIN_CORPORA]
    files += [TEST_RES / f for f in VALIDATION_FILES.values()] + [RULES]
    return {str(p.relative_to(ROOT)): sha256(p) for p in files}

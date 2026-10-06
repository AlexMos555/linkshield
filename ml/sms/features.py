"""Text normalisation and hashed features of the on-device SMS text model.

This file has a Kotlin twin, MessageModel.kt (mobile/modules/cleanway-vpn/
android/src/main/java/ai/cleanway/app/). Both must produce the same features
for the same text, bit for bit: the parity fixture written by train.py
(message_model_parity.tsv) is checked by MessageModelTest. Change one, change
the other, retrain, and re-export.

Everything is defined char by char with explicit tables, never with the
platform's Unicode helpers (str.lower(), Char.isLetter(), \\w), because
Python and the JVM disagree on some of them.

Pipeline:
 1. the first MAX_CHARS code points; invisible characters dropped; an
    emoji (any code point above U+FFFF) becomes U+FFFD; currency signs are
    spelled (₽ → руб); lowercase through a fixed table (A-Z, А-Я, Ѐ-Џ), ё → е;
 2. split on whitespace into chunks; a chunk is a URL (http(s)://, www.,
    or a bare host on a known TLD), an e-mail or an @handle, or words;
 3. a URL becomes tokens for its class — official, shortener, messenger,
    unknown, IP — and its TLD; the host's own words are not kept;
 4. words are runs of letters and digits; a word mixing Latin and Cyrillic
    look-alikes is folded into one script; masks (XXX, ***, NN) and digits
    become 0; a run of numbers written as a phone number becomes _phone, a
    card number _card;
 5. a message with no Cyrillic letter and two Russian-in-Latin marker words
    also gets the Cyrillic reading of each Latin word (the first reading of
    MessageText.kt's Translit), as a second token stream.

Features (binary, de-duplicated by hash, per block):
 - char block: char n-grams (2..5) of " word " for every word token;
 - word block: token unigrams and adjacent bigrams (special tokens included).
Each block is scaled to unit L2 norm (times its weight), so a long message
does not score higher just for having more features.
"""

from __future__ import annotations

import math

MAX_CHARS = 4000
"""The model reads at most this many characters (the rules read 10 000)."""

INVISIBLE = frozenset('​‌‍⁠﻿­᠎‎‏')
WHITESPACE = frozenset(
    ' \t\n\r\x0b\x0c             '
    '    　'
)
LEAD = frozenset('([{<"\'«„“‘')
TRAIL = frozenset('.,;:!?)]}>"\'»”’…')
APOSTROPHES = frozenset('\'’ʼ')
# Mask characters people type for hidden digits: XXX, ХХХ, ***, NN.
MASK = frozenset('xх*n')
# Latin letters that look like Cyrillic ones (after lowercasing), and back.
TO_CYRILLIC = {'a': 'а', 'b': 'в', 'c': 'с', 'e': 'е', 'h': 'н', 'k': 'к', 'm': 'м', 'o': 'о',
               'p': 'р', 't': 'т', 'x': 'х', 'y': 'у'}
TO_LATIN = {v: k for k, v in TO_CYRILLIC.items()}
FILE_EXTENSIONS = frozenset(['apk', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'jpeg', 'png', 'txt', 'rtf', 'rar', 'mp3', 'mp4'])
PHONE_GAP = frozenset(' -(). ')
VOWELS = 'аеиоуыэюя'

# Russian typed in Latin letters: MessageText.kt's Translit table, first reading only.
TRANSLIT = [
    ('shch', 'щ'), ('sch', 'сч'), ('zh', 'ж'), ('kh', 'х'), ('ch', 'ч'), ('sh', 'ш'), ('ts', 'ц'), ('tz', 'ц'),
    ('yu', 'ю'), ('ju', 'ю'), ('ya', 'я'), ('ja', 'я'), ('yo', 'е'), ('jo', 'е'), ('ye', 'е'), ('je', 'е'),
    ('ck', 'к'), ('ph', 'ф'),
    ('a', 'а'), ('b', 'б'), ('c', 'ц'), ('d', 'д'), ('e', 'е'), ('f', 'ф'), ('g', 'г'), ('h', 'х'), ('i', 'и'),
    ('j', 'й'), ('k', 'к'), ('l', 'л'), ('m', 'м'), ('n', 'н'), ('o', 'о'), ('p', 'п'), ('q', 'к'), ('r', 'р'),
    ('s', 'с'), ('t', 'т'), ('u', 'у'), ('v', 'в'), ('w', 'в'), ('x', 'кс'), ('z', 'з'),
]
TRANSLIT_MAX_LENGTH = 32
TRANSLIT_MIN_MARKERS = 2


def is_latin(c: str) -> bool:
    return 'a' <= c <= 'z'


def is_cyrillic(c: str) -> bool:
    return 'а' <= c <= 'я' or 'ѐ' <= c <= 'џ'


def is_digit(c: str) -> bool:
    return '0' <= c <= '9'


def is_letter(c: str) -> bool:
    return is_latin(c) or is_cyrillic(c)


def lower_char(c: str) -> str:
    if 'A' <= c <= 'Z' or 'А' <= c <= 'Я':
        return chr(ord(c) + 32)
    if c == 'Ё' or c == 'ё':
        return 'е'
    if 'Ѐ' <= c <= 'Џ':
        return chr(ord(c) + 0x50)
    return c


# Currency signs are not letters; spelled as words (as MessageText.kt does) so "149₽" reads "000 руб".
CURRENCY = {'₽': ' руб ', '$': ' usd ', '€': ' eur ', '£': ' gbp '}


def prepare(text: str) -> str:
    """Step 1: cut, drop invisible characters, spell currency signs, lowercase."""
    out = []
    for c in text[:MAX_CHARS]:  # code points, as MessageModel.kt counts them
        if c in INVISIBLE:
            continue
        if ord(c) > 0xFFFF:
            # Emoji and other astral characters: one placeholder, so that every
            # length below is the same in UTF-16 (Kotlin) and in code points (Python).
            out.append('\ufffd')
            continue
        out.append(CURRENCY.get(c) or lower_char(c))
    return ''.join(out)


class Config:
    """The lists the normaliser needs; frozen into message_model.json at training time."""

    def __init__(self, official, shorteners, messengers, cyrillic_tlds, translit_markers):
        self.official = frozenset(official)
        self.shorteners = frozenset(shorteners)
        self.messengers = frozenset(messengers)
        self.cyrillic_tlds = frozenset(cyrillic_tlds)
        self.translit_markers = frozenset(translit_markers)

    def to_json(self) -> dict:
        return {k: sorted(getattr(self, k)) for k in
                ('official', 'shorteners', 'messengers', 'cyrillic_tlds', 'translit_markers')}

    @staticmethod
    def from_json(d: dict) -> 'Config':
        return Config(d['official'], d['shorteners'], d['messengers'], d['cyrillic_tlds'], d['translit_markers'])


def under(host: str, suffixes) -> bool:
    if host in suffixes:
        return True
    i = host.find('.')
    while i >= 0:
        if host[i + 1:] in suffixes:
            return True
        i = host.find('.', i + 1)
    return False


def strip_chunk(chunk: str) -> str:
    s, e = 0, len(chunk)
    while s < e and chunk[s] in LEAD:
        s += 1
    while e > s and chunk[e - 1] in TRAIL:
        e -= 1
    return chunk[s:e]


def host_label_ok(label: str) -> bool:
    return len(label) > 0 and all(is_latin(c) or is_digit(c) or c == '-' or is_cyrillic(c) for c in label)


def url_tokens(chunk: str, cfg: Config) -> list[str] | None:
    """The tokens of [chunk] when it is a link, else None."""
    rest = chunk
    scheme = False
    for prefix in ('https://', 'http://'):
        if rest.startswith(prefix):
            rest = rest[len(prefix):]
            scheme = True
            break
    if rest.startswith('www.'):
        scheme = True
    if not scheme and '@' in rest:
        return None
    end = len(rest)
    for k, c in enumerate(rest):
        if c == '/' or c == '?' or c == '#':
            end = k
            break
    host = rest[:end]
    path = rest[end:]
    colon = host.find(':')
    if colon >= 0:
        host = host[:colon]
    labels = host.split('.')
    if not scheme and not path and len(labels) >= 2 and labels[-1] in FILE_EXTENSIONS and labels[-2]:
        # "vozvrat.apk", "foto_party.apk", "scan.pdf": a file named in words, not a site.
        return ['_apk'] if labels[-1] == 'apk' else ['_file']
    if len(labels) < 2 or not all(host_label_ok(lab) for lab in labels):
        return None
    tld = labels[-1]
    ip = len(labels) == 4 and all(all(is_digit(c) for c in lab) and len(lab) <= 3 for lab in labels)
    name_latin = any(is_latin(c) for lab in labels[:-1] for c in lab)
    name_cyrillic = any(is_cyrillic(c) for lab in labels[:-1] for c in lab)
    if not ip:
        if not scheme:
            name = labels[-2]
            if all(is_cyrillic(c) for c in tld):
                # "госуслуги.рф": a Cyrillic TLD from the list, after a Cyrillic name.
                if tld not in cfg.cyrillic_tlds or not any(is_cyrillic(c) for c in name):
                    return None
            elif all(is_latin(c) for c in tld):
                # "sber-bonus.online": any Latin TLD of 2+ letters after a name with a Latin
                # letter or digit; a Cyrillic word before a Latin TLD ("отчет.pdf") only with a path.
                if len(tld) < 2 or all(is_digit(c) for c in name):
                    return None
                if not name_latin and not path.startswith('/'):
                    return None
            else:
                return None
        elif not any(is_letter(c) for c in tld):
            return None
    elif not scheme and not path.startswith('/'):
        return None
    out = ['_url']
    if ip:
        out.append('_url_ip')
    else:
        if under(host, cfg.official):
            out.append('_url_off')
        elif under(host, cfg.shorteners):
            out.append('_url_short')
        elif under(host, cfg.messengers):
            out.append('_url_msgr')
        else:
            out.append('_url_unk')
        out.append('_tld_' + tld)
        if name_cyrillic and (name_latin or all(is_latin(c) for c in tld)):
            out.append('_url_mixed')
    q = len(path)
    for k, c in enumerate(path):
        if c == '?' or c == '#':
            q = k
            break
    if path[:q].endswith('.apk'):
        out.append('_apk')
    return out


def fold_word(w: str) -> tuple[str, bool]:
    """A word mixing Latin and Cyrillic letters, folded into the script it imitates."""
    has_latin = any(is_latin(c) for c in w)
    has_cyrillic = any(is_cyrillic(c) for c in w)
    if not (has_latin and has_cyrillic):
        return w, False
    cyr = ''.join(TO_CYRILLIC.get(c, c) for c in w)
    if not any(is_latin(c) for c in cyr):
        return cyr, True
    lat = ''.join(TO_LATIN.get(c, c) for c in w)
    if not any(is_cyrillic(c) for c in lat):
        return lat, True
    return w, True


class Word:
    __slots__ = ('text', 'raw', 'start', 'end', 'number')

    def __init__(self, text, raw, start, end, number):
        self.text, self.raw, self.start, self.end, self.number = text, raw, start, end, number


def mask_run(run: str) -> bool:
    """XXX, ***, 9**, NN, 2200: a number, possibly masked."""
    if not all(is_digit(c) or c in MASK for c in run):
        return False
    if any(is_digit(c) for c in run):
        return True
    return len(run) >= 2


def tokenize(text: str, cfg: Config):
    """Steps 2-5: (tokens, translit tokens or None)."""
    s = prepare(text)
    n = len(s)
    tokens: list[str] = []
    words: list = []  # Word objects and plain special tokens, in order
    mixed = False
    i = 0
    while i < n:
        if s[i] in WHITESPACE:
            i += 1
            continue
        j = i
        while j < n and s[j] not in WHITESPACE:
            j += 1
        raw = s[i:j]
        chunk = strip_chunk(raw)
        special = None
        if chunk:
            special = url_tokens(chunk, cfg)
            if special is None and '@' in chunk:
                at = chunk.find('@')
                if at == 0 and len(chunk) > 2:
                    special = ['_handle']
                elif at > 0 and '.' in chunk[at + 1:]:
                    special = ['_email']
        if special is not None:
            words.extend(special)
        else:
            k = i
            while k < j:
                c = s[k]
                if not (is_letter(c) or is_digit(c) or c == '*'):
                    k += 1
                    continue
                m = k
                buf = []
                while m < j:
                    c = s[m]
                    if is_letter(c) or is_digit(c) or c == '*':
                        buf.append(c)
                        m += 1
                    elif c in APOSTROPHES and buf and m + 1 < j and is_letter(s[m + 1]):
                        m += 1
                    else:
                        break
                run = ''.join(buf)
                if mask_run(run):
                    words.append(Word('0' * len(run), run, k, m, True))
                else:
                    for part in run.split('*'):
                        if part:
                            folded, was_mixed = fold_word(part)
                            mixed = mixed or was_mixed
                            folded = ''.join('0' if is_digit(c) else c for c in folded)
                            words.append(Word(folded, part, k, m, False))
                k = m
        i = j
    # Phone and card numbers: number words joined only by spaces, dashes, brackets, dots.
    k = 0
    while k < len(words):
        w = words[k]
        if not isinstance(w, Word):
            tokens.append(w)
            k += 1
            continue
        if not w.number:
            tokens.append(w.text)
            k += 1
            continue
        m = k
        digits = len(w.text)
        while m + 1 < len(words) and isinstance(words[m + 1], Word) and words[m + 1].number:
            gap = s[words[m].end:words[m + 1].start]
            if not gap or len(gap) > 3 or not all(c in PHONE_GAP for c in gap):
                break
            m += 1
            digits += len(words[m].text)
        plus = w.start > 0 and s[w.start - 1] == '+'
        first = w.raw[0]
        if 10 <= digits <= 12 and (plus or first in '789' or first in MASK):
            tokens.append('_phone')
        elif 13 <= digits <= 19 and m > k:
            tokens.append('_card')
        else:
            tokens.extend(words[q].text for q in range(k, m + 1))
        k = m + 1
    if '!' in s:
        tokens.append('_excl')
    if mixed:
        tokens.append('_mixscript')
    translit = None
    if not any(is_cyrillic(c) for c in s):
        markers = {t for t in tokens if t in cfg.translit_markers}
        if len(markers) >= TRANSLIT_MIN_MARKERS:
            translit = [reading(t) if t and t[0] != '_' and all(is_latin(c) for c in t) else t for t in tokens]
    return tokens, translit


def reading(word: str) -> str:
    """The first Cyrillic reading of a Latin word (Translit.readings()[0] in MessageText.kt)."""
    if not word or len(word) > TRANSLIT_MAX_LENGTH or any(not is_latin(c) for c in word):
        return word
    out = []
    i = 0
    while i < len(word):
        for key, value in TRANSLIT:
            if word.startswith(key, i):
                out.append(value)
                i += len(key)
                break
        else:  # only "y" is not in the table: й after a vowel, ы elsewhere
            out.append('й' if out and out[-1] in VOWELS else 'ы')
            i += 1
    return ''.join(out)


def word_count(text: str, cfg: Config) -> int:
    """Word and number tokens (not links or other special tokens): the model abstains below min_words."""
    return sum(1 for t in tokenize(text, cfg)[0] if t[0] != '_')


# ── hashing ───────────────────────────────────────────────────────────────

FNV_OFFSET = 0x811C9DC5
FNV_PRIME = 0x01000193
M32 = 0xFFFFFFFF


def fnv_feed(h: int, s: str) -> int:
    """FNV-1a over UTF-16LE code units (all feature text is in the BMP)."""
    for ch in s:
        o = ord(ch)
        h = ((h ^ (o & 0xFF)) * FNV_PRIME) & M32
        h = ((h ^ (o >> 8)) * FNV_PRIME) & M32
    return h


def fmix(h: int) -> int:
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & M32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & M32
    h ^= h >> 16
    return h


def feature_hashes(text: str, cfg: Config, nmin: int = 2, nmax: int = 5):
    """(char n-gram hashes, word hashes): two sets of 32-bit hashes."""
    tokens, translit = tokenize(text, cfg)
    chars: set[int] = set()
    words: set[int] = set()
    for stream in (tokens, translit) if translit is not None else (tokens,):
        hw = fnv_feed(FNV_OFFSET, 'w')
        hb = fnv_feed(FNV_OFFSET, 'b')
        hc = fnv_feed(FNV_OFFSET, 'c')
        prev = None
        for t in stream:
            words.add(fmix(fnv_feed(hw, t)))
            if prev is not None:
                words.add(fmix(fnv_feed(hb, prev + ' ' + t)))
            prev = t
            if t[0] == '_':
                continue
            padded = ' ' + t + ' '
            for a in range(len(padded)):
                h = hc
                for b in range(a, min(len(padded), a + nmax)):
                    h = fnv_feed(h, padded[b])
                    if b - a + 1 >= nmin:
                        chars.add(fmix(h))
    return chars, words


def vector(text: str, cfg: Config, dim: int, char_weight: float, word_weight: float,
           char_floor: int = 1, word_floor: int = 1):
    """Sparse (bucket → value) of [text]: each block at unit norm times its weight.

    A block with fewer features than its floor is normalised as if it had the
    floor: a two-word text cannot reach the confidence of a whole message.
    """
    chars, words = feature_hashes(text, cfg)
    out: dict[int, float] = {}
    for block, weight, floor in ((chars, char_weight, char_floor), (words, word_weight, word_floor)):
        if not block:
            continue
        v = weight / math.sqrt(max(len(block), floor))
        for h in block:
            b = h & (dim - 1)
            out[b] = out.get(b, 0.0) + v
    return out

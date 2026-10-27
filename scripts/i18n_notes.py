"""Is a localized value a note to the translator instead of the string itself?

Shared by scripts/check-mobile-i18n.py (mobile.* in the generated
mobile/i18n files) and scripts/check-i18n-parity.py (every namespace of the
packages/i18n-strings source: landing, extension, email, mobile). Notes
shipped to users through mobile.*: ar `mobile.report.times_one` as
"times_one: «…» (and optionally add _two …)" until #303, then, until #310
(2026-10-27), ar `mobile.history.minutes_ago` as "Add Arabic plural variants:
… Single-string fallback: …" on every History row and it
`mobile.breach.found_body` as "found_body_one: \"…\" / found_body_other:
\"…\"" on the breach card.

Every rule below matched nothing in any of the 10 locales on 2026-10-27
(23,732 strings of the source).
"""
from __future__ import annotations

import re

PLURAL_SUFFIX_RE = "_(?:zero|one|two|few|many|other|plural)"
# A token ending in a CLDR plural suffix: the bare " _two «…»" / "keep _other
# as …" of a note, and the variant key it names, however it names it
# ("found_body_one", "\"found_body_one\":", "mobile.breach.found_body_one",
# "hours_ago_one «…», hours_ago_two «…»", "use minutes_ago_one …"). #310 had
# a lookbehind that skipped any _one right after a letter, so those four
# shapes passed the check (the #310 review, F1). UI text never carries one.
PLURAL_TOKEN = re.compile(PLURAL_SUFFIX_RE + r"\b")
# A note saying what it is ("Plural variants: …", "Single-string fallback: …").
NOTE_PHRASE = re.compile(r"plural (?:variant|form)s?|single[- ]string fallback|translator", re.IGNORECASE)
# A marker left in the value. Upper case and whole words only: "todo" is
# "all" in es/pt ("Todo lo que escribas…", "Excluir todo o histórico…") and
# sits inside id "metodologi".
MARKER = re.compile(r"\b(?:TODO|FIXME)\b")
# A dotted key mid-sentence ("see mobile.breach.title") is left alone: in a
# product about links, copy may name a host like email.mg.example.com or
# mobile.<brand>.com, which a namespace-prefix rule would flag. A key the
# value opens with is caught below, and any variant key by PLURAL_TOKEN.
#
# The leading token of a value, bare, quoted or dotted, followed by a colon.
OPENING_TOKEN = re.compile(r"[\"'«“]?([A-Za-z0-9_.]+)[\"'»”]?\s*:")
PLURAL_SUFFIX_END = re.compile(PLURAL_SUFFIX_RE + "$")
LIST_INDEX_END = re.compile(r"\[\d+\]$")


def _base(name: str) -> str:
    """found_body_one -> found_body; items[3] -> items."""
    return PLURAL_SUFFIX_END.sub("", LIST_INDEX_END.sub("", name))


def is_translator_note(key: str, value: str) -> bool:
    """`key` is the value's dotted key (list items as `[i]`)."""
    # The value opening with its own key, with or without a plural suffix,
    # then a colon: "times_one: …" on mobile.report.times_one,
    # "found_body_one: …" on mobile.breach.found_body,
    # "mobile.breach.found_body: …", "\"title\": …", "title_part1 : « … »".
    # One pattern and a string comparison, not a pattern per key: one per
    # string (23,732) against re's 512-entry cache took the parity check from
    # 0.3 s to 8-10 s (2026-10-27).
    opening = OPENING_TOKEN.match(value)
    own = _base(key.rsplit(".", 1)[-1])
    opens_with_key = bool(opening) and _base(opening.group(1).rsplit(".", 1)[-1]) == own
    return bool(
        PLURAL_TOKEN.search(value)
        or NOTE_PHRASE.search(value)
        or MARKER.search(value)
        or opens_with_key
    )

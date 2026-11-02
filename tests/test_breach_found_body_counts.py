"""The breach card reads right when the address turned up only once.

mobile/app/breach.tsx renders t("mobile.breach.found_body", { times }) with
no `count`, so i18next never picks a plural variant: the one string shows for
every number, and the card shows for any match.count > 0. Pwned Passwords
counts start at 1, so 1 is an ordinary result. #310 (2026-10-27) replaced
the it note with its found_body_other sentence, "comparso {{times}} volte",
which reads "comparso 1 volte"; en had read "turned up 1 times" all along.
The string has to read right for any number, the way es "({{times}} en
total)", ru "(совпадений: {{times}})" and ar "…: {{times}}" do.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SOURCE_DIR = ROOT / "packages" / "i18n-strings" / "src"

# A plural noun that is wrong right after "1", per language that has one.
WRONG_AFTER_ONE = {
    "en": ("1 times",),
    "it": ("1 volte",),
    "es": ("1 veces",),
    "pt": ("1 vezes",),
}


@pytest.mark.parametrize("locale", sorted(WRONG_AFTER_ONE))
def test_found_body_reads_right_for_one_match(locale):
    source = json.loads((SOURCE_DIR / f"{locale}.json").read_text(encoding="utf-8"))
    rendered = source["mobile"]["breach"]["found_body"].replace("{{times}}", "1")
    wrong = [form for form in WRONG_AFTER_ONE[locale] if form in rendered]
    assert not wrong, f"[{locale}] {rendered!r}"

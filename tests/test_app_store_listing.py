"""docs/APP_STORE_LISTING.md stays within App Store Connect limits and App Review 5.4."""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("check_app_store_listing", ROOT / "scripts" / "check_app_store_listing.py")
checker = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(checker)


def test_listing_fields_fit_apples_limits():
    assert checker.check(checker.LISTING.read_text(encoding="utf-8")) == []


def test_both_languages_have_every_field():
    ids = {m["id"] for m in checker.FIELD_RE.finditer(checker.LISTING.read_text(encoding="utf-8"))}
    fields = {"name", "subtitle", "promo", "keywords", "description", "whats_new"}
    assert ids == {f"{lang}.{f}" for lang in ("en", "ru") for f in fields}


def test_keywords_count_bytes_so_cyrillic_cannot_overflow():
    over = "мошенники," * 6  # 60 characters, 114 bytes
    md = f"<!-- field: ru.keywords max=100 -->\n```text\n{over}\n```\n"
    assert checker.check(md) == ["ru.keywords: 114 > 100"]


def test_vpn_is_refused_outside_the_disclaimer():
    md = "<!-- field: en.promo max=170 -->\n```text\nA fast VPN for scams.\n```\n"
    assert any("VPN" in p for p in checker.check(md))
    ok = "<!-- field: en.promo max=170 -->\n```text\nIt is not a VPN: your IP stays.\n```\n"
    assert checker.check(ok) == []

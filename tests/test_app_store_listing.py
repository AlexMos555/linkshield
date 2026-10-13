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


def _png(width: int, height: int, row: bytes) -> bytes:
    """A minimal RGB PNG whose every row is `row` (filter byte included)."""
    import struct
    import zlib

    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(row * height, 9)) + chunk(b"IEND", b"")


def test_every_screenshot_is_a_full_rendered_frame():
    # A frame captured before the UI rendered is a black screen with only the
    # status bar; it still has the right size, so the byte count is what tells.
    assert checker.check_screenshots(checker.SCREENSHOTS) == []
    assert len(sorted(checker.SCREENSHOTS.glob("*/*.png"))) == 10


def test_a_blank_frame_is_refused(tmp_path):
    (tmp_path / "en").mkdir()
    (tmp_path / "en" / "01-home.png").write_bytes(_png(1320, 2868, b"\x00" * (1 + 1320 * 3)))
    problems = checker.check_screenshots(tmp_path)
    assert len(problems) == 1 and "blank" in problems[0]


def test_a_frame_of_the_wrong_size_is_refused(tmp_path):
    (tmp_path / "ru").mkdir()
    (tmp_path / "ru" / "01-home.png").write_bytes(_png(1290, 2796, b"\x00" * (1 + 1290 * 3)))
    assert any("1290x2796" in p for p in checker.check_screenshots(tmp_path))

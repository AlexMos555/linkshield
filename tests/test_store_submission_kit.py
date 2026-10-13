"""docs/STORE_SUBMISSION_KIT.md fits Play / Chrome / Edge / AMO limits and matches the build."""
from __future__ import annotations

import importlib.util
import json
import struct
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "check_store_submission_kit", ROOT / "scripts" / "check_store_submission_kit.py"
)
kit = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(kit)

MANIFEST = json.loads(kit.MANIFEST.read_text(encoding="utf-8"))
RUSTORE_MD = kit.RUSTORE.read_text(encoding="utf-8")


def _field(fid: str, body: str, limit: int = 1000) -> str:
    return f"<!-- field: {fid} max={limit} -->\n```text\n{body}\n```\n"


def _png(path: Path, width: int, height: int, colour_type: int) -> None:
    ihdr = struct.pack(">IIBBBBB", width, height, 8, colour_type, 0, 0, 0)
    chunk = b"IHDR" + ihdr
    path.write_bytes(kit.PNG_SIGNATURE + struct.pack(">I", len(ihdr)) + chunk
                     + struct.pack(">I", zlib.crc32(chunk)))


def test_kit_passes_every_check():
    assert kit.check(kit.KIT.read_text(encoding="utf-8"), RUSTORE_MD, MANIFEST) == []


def test_kit_has_every_required_field():
    assert kit.REQUIRED <= kit.fields(kit.KIT.read_text(encoding="utf-8")).keys()


def test_over_limit_field_is_reported():
    md = _field("play.en.short", "x" * 81, 80)
    assert "play.en.short: 81 > 80" in kit.check_fields(kit.fields(md))


def test_release_notes_are_limited_per_language():
    body = "<en-US>\n" + "a" * 501 + "\n</en-US>\n<ru-RU>\nок\n</ru-RU>"
    problems = kit.check_fields(kit.fields(_field("play.release_notes", body, 2000)))
    assert "play.release_notes en-US: 501 > 500" in problems


def test_play_title_refuses_ranking_words():
    problems = kit.check_fields(kit.fields(_field("play.en.title", "Best Scam Blocker", 30)))
    assert any("Play refuses" in p for p in problems)


def test_russian_play_text_must_equal_rustore():
    md = _field("play.ru.full", "другой текст", 4000)
    assert kit.check_ru_matches_rustore(kit.fields(md), RUSTORE_MD) == [
        "play.ru.full differs from the RuStore full description — edit both"
    ]


def test_every_manifest_permission_needs_a_justification():
    manifest = dict(MANIFEST, permissions=MANIFEST["permissions"] + ["tabs"])
    found = kit.fields(kit.KIT.read_text(encoding="utf-8"))
    assert "no justification for permission: tabs" in kit.check_permissions(found, manifest)


def test_every_host_must_be_named():
    manifest = dict(MANIFEST, optional_host_permissions=["https://mail.example.com/*"])
    found = kit.fields(kit.KIT.read_text(encoding="utf-8"))
    assert "host field does not name https://mail.example.com/*" in kit.check_permissions(found, manifest)


def test_assets_are_checked_for_size_and_alpha(tmp_path):
    _png(tmp_path / "rgba.png", 1024, 500, 6)
    _png(tmp_path / "small.png", 1000, 500, 2)
    md = ("<!-- asset: rgba.png 1024x500 opaque -->\n"
          "<!-- asset: small.png 1024x500 opaque -->\n"
          "<!-- asset: gone.png 10x10 -->\n")
    assert kit.check_assets(md, tmp_path) == [
        "asset rgba.png: has an alpha channel, must be opaque",
        "asset small.png: 1000x500, expected 1024x500",
        "asset missing: gone.png",
    ]

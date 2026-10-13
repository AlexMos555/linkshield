#!/usr/bin/env python3
"""Check docs/STORE_SUBMISSION_KIT.md: Google Play and browser-store fields and assets.

Fields use the App Store listing format (scripts/check_app_store_listing.py):
a ```text block preceded by `<!-- field: <id> max=<n> -->`; the length counts
characters. On top of the limits, this checks what a console would reject
or what would drift silently:

- every field the kit promises is present (REQUIRED);
- a Play release-notes block keeps each `<xx-XX>` language within 500;
- the Play title carries no words Play's metadata policy refuses;
- the Russian Play description is the RuStore one, letter for letter
  (docs/RUSTORE_SUBMISSION.md, `<!-- count: rustore_full -->`);
- every permission in the built Chrome manifest (extension/manifest.json) has
  a `cws.perm.<name>` justification, and none is left over; every host in
  host_permissions / optional_host_permissions is named in the host field;
- every `<!-- asset: <path> <W>x<H> [opaque] -->` exists, is a PNG of that
  size and, when marked opaque, has no alpha channel (Play refuses alpha in
  the feature graphic and screenshots).

Run: python3 scripts/check_store_submission_kit.py
"""
from __future__ import annotations

import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from check_app_store_listing import FIELD_RE  # noqa: E402  (same field format)

ROOT = Path(__file__).resolve().parent.parent
KIT = ROOT / "docs" / "STORE_SUBMISSION_KIT.md"
RUSTORE = ROOT / "docs" / "RUSTORE_SUBMISSION.md"
MANIFEST = ROOT / "extension" / "manifest.json"

ASSET_RE = re.compile(r"<!-- asset: (?P<path>\S+) (?P<w>\d+)x(?P<h>\d+)(?P<opaque> opaque)? -->")
RUSTORE_FULL_RE = re.compile(r"<!-- count: rustore_full max=\d+ -->\n```text\n(.*?)\n```", re.S)
RELEASE_LANG_RE = re.compile(r"<(?P<lang>[a-z]{2}-[A-Z]{2})>\n(?P<body>.*?)\n</(?P=lang)>", re.S)
RELEASE_NOTES_MAX = 500
# Play metadata policy: no ranking or price claims, no "free"/"sale" in the title.
TITLE_BANNED = re.compile(r"\b(best|top|#1|no\.? ?1|free|sale|new|hot|download)\b|[\U0001F300-\U0001FAFF]", re.I)

REQUIRED = {
    *(f"play.{lang}.{f}" for lang in ("en", "ru") for f in ("title", "short", "full")),
    "play.release_notes", "play.vpn.short", "play.vpn.full", "play.fgs.short",
    "ext.en.description", "ext.ru.description",
    "cws.single_purpose", "cws.host_permissions", "cws.test_instructions",
    "edge.search_terms.en", "edge.search_terms.ru", "edge.cert_notes",
    "amo.en.summary", "amo.ru.summary", "amo.privacy_policy", "amo.reviewer_notes",
}

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
PNG_ALPHA_TYPES = {4, 6}  # grey+alpha, RGBA


def fields(markdown: str) -> dict[str, tuple[int, str]]:
    return {m["id"]: (int(m["max"]), m["body"]) for m in FIELD_RE.finditer(markdown)}


def png_header(path: Path) -> tuple[int, int, int] | None:
    """(width, height, colour type) from a PNG's IHDR, or None if not a PNG."""
    head = path.read_bytes()[:26]
    if len(head) < 26 or head[:8] != PNG_SIGNATURE or head[12:16] != b"IHDR":
        return None
    width, height = struct.unpack(">II", head[16:24])
    return width, height, head[25]


def check_fields(found: dict[str, tuple[int, str]]) -> list[str]:
    problems = [f"missing field: {fid}" for fid in sorted(REQUIRED - found.keys())]
    for fid, (limit, body) in found.items():
        if len(body) > limit:
            problems.append(f"{fid}: {len(body)} > {limit}")
        if fid.endswith("release_notes"):
            langs = list(RELEASE_LANG_RE.finditer(body))
            if not langs:
                problems.append(f"{fid}: no <xx-XX> language blocks")
            for m in langs:
                if len(m["body"]) > RELEASE_NOTES_MAX:
                    problems.append(f"{fid} {m['lang']}: {len(m['body'])} > {RELEASE_NOTES_MAX}")
        if fid.startswith("play.") and fid.endswith(".title") and TITLE_BANNED.search(body):
            problems.append(f"{fid}: Play refuses '{TITLE_BANNED.search(body)[0]}' in a title")
    return problems


def check_ru_matches_rustore(found: dict[str, tuple[int, str]], rustore_md: str) -> list[str]:
    m = RUSTORE_FULL_RE.search(rustore_md)
    if not m:
        return ["RuStore full description not found"]
    if "play.ru.full" in found and found["play.ru.full"][1] != m[1]:
        return ["play.ru.full differs from the RuStore full description — edit both"]
    return []


def check_permissions(found: dict[str, tuple[int, str]], manifest: dict) -> list[str]:
    problems = []
    declared = set(manifest.get("permissions", []))
    justified = {fid.split(".", 2)[2] for fid in found if fid.startswith("cws.perm.")}
    problems += [f"no justification for permission: {p}" for p in sorted(declared - justified)]
    problems += [f"justification for a permission the manifest lacks: {p}" for p in sorted(justified - declared)]
    hosts = manifest.get("host_permissions", []) + manifest.get("optional_host_permissions", [])
    host_text = found.get("cws.host_permissions", (0, ""))[1]
    problems += [f"host field does not name {h}" for h in hosts if h not in host_text]
    if any("<all_urls>" in cs.get("matches", []) for cs in manifest.get("content_scripts", [])) \
            and "<all_urls>" not in host_text:
        problems.append("host field does not justify the <all_urls> content scripts")
    return problems


def check_assets(markdown: str, root: Path) -> list[str]:
    problems = []
    for m in ASSET_RE.finditer(markdown):
        path, want = root / m["path"], (int(m["w"]), int(m["h"]))
        if not path.is_file():
            problems.append(f"asset missing: {m['path']}")
            continue
        head = png_header(path)
        if head is None:
            problems.append(f"asset is not a PNG: {m['path']}")
            continue
        if head[:2] != want:
            problems.append(f"asset {m['path']}: {head[0]}x{head[1]}, expected {want[0]}x{want[1]}")
        if m["opaque"] and head[2] in PNG_ALPHA_TYPES:
            problems.append(f"asset {m['path']}: has an alpha channel, must be opaque")
    return problems


def check(markdown: str, rustore_md: str, manifest: dict, root: Path = ROOT) -> list[str]:
    found = fields(markdown)
    return (check_fields(found) + check_ru_matches_rustore(found, rustore_md)
            + check_permissions(found, manifest) + check_assets(markdown, root))


def main() -> int:
    markdown = KIT.read_text(encoding="utf-8")
    problems = check(markdown, RUSTORE.read_text(encoding="utf-8"),
                     json.loads(MANIFEST.read_text(encoding="utf-8")))
    for fid, (limit, body) in fields(markdown).items():
        print(f"{fid:24} {len(body):5} / {limit}")
    print(f"assets: {len(ASSET_RE.findall(markdown))}")
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Check App Store listing fields in docs/APP_STORE_LISTING.md against Apple's limits.

Each field is a ```text block preceded by `<!-- field: <id> max=<n> -->`.
Keywords count UTF-8 bytes (App Store Connect limits the field to 100 bytes);
every other field counts characters. Also refuses the word "VPN" outside the
"honestly" disclaimer (App Review 5.4, docs/IOS.md §3.7).

Run: python3 scripts/check_app_store_listing.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LISTING = ROOT / "docs" / "APP_STORE_LISTING.md"
FIELD_RE = re.compile(r"<!-- field: (?P<id>[\w.]+) max=(?P<max>\d+) -->\s*```text\n(?P<body>.*?)\n```", re.S)
# The only allowed mention: the sentence that says Cleanway is NOT a VPN.
ALLOWED_VPN = ("It is not a VPN", "Это не VPN")


def field_length(field_id: str, text: str) -> int:
    if field_id.endswith(".keywords"):
        return len(text.encode("utf-8"))
    return len(text)


def check(markdown: str) -> list[str]:
    problems: list[str] = []
    fields = list(FIELD_RE.finditer(markdown))
    if not fields:
        return ["no fields found"]
    for m in fields:
        field_id, limit, body = m["id"], int(m["max"]), m["body"]
        size = field_length(field_id, body)
        if size > limit:
            problems.append(f"{field_id}: {size} > {limit}")
        for line in body.splitlines():
            if re.search(r"\bVPN\b", line) and not any(a in line for a in ALLOWED_VPN):
                problems.append(f"{field_id}: 'VPN' outside the disclaimer: {line[:60]}")
    return problems


def main() -> int:
    markdown = LISTING.read_text(encoding="utf-8")
    problems = check(markdown)
    for m in FIELD_RE.finditer(markdown):
        print(f"{m['id']:16} {field_length(m['id'], m['body']):5} / {m['max']}")
    if problems:
        print("\n".join(problems), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

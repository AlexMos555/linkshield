#!/usr/bin/env python3
"""Recall and cost of the brand-typo rule, _check_typosquatting_v2().

Recall: generates look-alike variants of every brand in
data/typosquat_targets.json — one class of edit at a time, deterministically
(fixed seed) — and counts how many the rule catches, per class and per brand
length. A threshold that clears a false positive also drops every variant of
that shape, and this is where that shows.

Cost (--top): runs the same rule over the Tranco top-100k names
(data/top_100k.json). Every one is a real site. The allowlist spares these
very names, but the long tail of real sites — millions of names nobody ranks
— has the same shapes and nothing to spare it, so the hit count per method
is the density of false positives each method buys.

Brands (--brands): the global list, the Russian one
(data/typosquat_targets_ru.json) or both. They are read from the data files,
not from the scorer, so a checkout whose scorer does not know a list still
gets that list's variants: that is its "before".

Usage:
    python3 scripts/eval_typo_variants.py                  # recall table
    python3 scripts/eval_typo_variants.py --brands ru      # Russian brands only
    python3 scripts/eval_typo_variants.py --top            # + top-100k hits (minutes)
    python3 scripts/eval_typo_variants.py --top --out after.json
    python3 scripts/eval_typo_variants.py --compare before.json after.json

No network access. Copy this file (and data/typosquat_targets_ru.json) into
an older checkout to get its "before".
"""
from __future__ import annotations

import argparse
import json
import random
import string
import sys
from collections import Counter
from pathlib import Path
from typing import Iterator, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SEED = 20260927
LETTERS = string.ascii_lowercase
CYRILLIC = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
# Digit look-alikes an attacker types for a letter.
DIGITS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "t": "7", "b": "8"}
GLYPHS = {"m": "rn", "w": "vv", "d": "cl"}
COMBO_WORDS = ("login", "verify", "secure", "account")
OTHER_TLDS = ("top", "help", "ru", "co")
CLASSES = (
    "omission", "doubled", "insertion", "substitution_1", "substitution_2",
    "transposition", "digit_lookalike", "glyph", "hyphen", "combo", "tld",
)
BUCKETS = ("3", "4", "5-7", "8+")


def bucket(brand: str) -> str:
    n = len(brand)
    return "3" if n <= 3 else "4" if n == 4 else "5-7" if n <= 7 else "8+"


def _alphabet(brand: str) -> str:
    """Letters a typo of `brand` is made of: its own script's."""
    return LETTERS if brand.isascii() else CYRILLIC


def _other(rng: random.Random, ch: str, alphabet: str = LETTERS) -> str:
    return rng.choice([c for c in alphabet if c != ch])


def variants(brand: str, legit_tld: str, rng: random.Random) -> Iterator[tuple[str, str]]:
    """(class, host) pairs for one brand. Labels get '.com' (the class is the
    edit, not the TLD); 'tld' puts the exact name under another TLD."""
    n = len(brand)
    abc = _alphabet(brand)
    for i in range(n):
        yield "omission", brand[:i] + brand[i + 1:]
        yield "doubled", brand[:i + 1] + brand[i:]
        yield "insertion", brand[:i] + rng.choice(abc) + brand[i:]
        yield "substitution_1", brand[:i] + _other(rng, brand[i], abc) + brand[i + 1:]
        if brand[i] in DIGITS:
            yield "digit_lookalike", brand[:i] + DIGITS[brand[i]] + brand[i + 1:]
        if brand[i] in GLYPHS:
            yield "glyph", brand[:i] + GLYPHS[brand[i]] + brand[i + 1:]
        if 0 < i:
            yield "hyphen", brand[:i] + "-" + brand[i:]
        if i < n - 1 and brand[i] != brand[i + 1]:
            yield "transposition", brand[:i] + brand[i + 1] + brand[i] + brand[i + 2:]
    pairs = [(i, j) for i in range(n) for j in range(i + 1, n)]
    for i, j in rng.sample(pairs, min(len(pairs), 2 * n)):
        s = list(brand)
        s[i], s[j] = _other(rng, s[i], abc), _other(rng, s[j], abc)
        yield "substitution_2", "".join(s)
    for word in COMBO_WORDS:
        yield "combo", f"{brand}-{word}"
    for tld in OTHER_TLDS:
        if "." + tld != legit_tld:
            yield "tld", f"{brand}.{tld}"


def load_brands(which: str = "all") -> dict[str, str]:
    """Brand name -> its site, from the data files: 'global', 'ru' or 'all'."""
    out: dict[str, str] = {}
    if which in ("global", "all"):
        data = json.loads((ROOT / "data" / "typosquat_targets.json").read_text(encoding="utf-8"))
        out.update({k.lower(): v.lower() for k, v in data.get("brands", data).items() if k != "_meta"})
    ru_path = ROOT / "data" / "typosquat_targets_ru.json"
    if which in ("ru", "all") and ru_path.exists():
        for group in json.loads(ru_path.read_text(encoding="utf-8"))["brands"].values():
            for name, domain in group["names"].items():
                out.setdefault(name, domain)
    return out


def build_variants(which: str = "all") -> list[dict]:
    from api.services.scoring import _extract_tld

    targets = load_brands(which)
    # A variant that spells ANY listed brand is not a typo, whichever list
    # is being measured.
    brands = set(load_brands("all"))
    rng = random.Random(SEED)
    out, seen = [], set()
    for brand in sorted(targets):
        legit_tld = _extract_tld(targets[brand])
        for cls, v in variants(brand, legit_tld, rng):
            label = v.split(".")[0]
            # A variant that spells the brand (outside 'tld') or another brand
            # is not a typo.
            if (label == brand and cls != "tld") or (label != brand and label in brands) or len(label) < 2:
                continue
            host = v if cls == "tld" else f"{v}.com"
            if host in seen:
                continue
            seen.add(host)
            out.append({"host": host, "brand": brand, "class": cls, "bucket": bucket(brand)})
    return out


def score_variants(rows: list[dict]) -> list[dict]:
    from api.services.scoring import _check_typosquatting_v2

    return [{**r, "caught": _check_typosquatting_v2(r["host"]) is not None} for r in rows]


def top_hits() -> dict:
    """Rule hits on the Tranco top-100k, by method and by the name's length,
    and which of them a Russian brand made."""
    from api.services.scoring import _check_typosquatting_v2, _extract_base_domain

    names = json.loads((ROOT / "data" / "top_100k.json").read_text())
    ru_sites = set(load_brands("ru").values())
    by_method: Counter = Counter()
    by_length: Counter = Counter()
    own = 0
    ru_hits: list[str] = []
    for domain in names:
        hit = _check_typosquatting_v2(domain)
        if not hit:
            continue
        legit, method = hit
        label = _extract_base_domain(domain).split(".")[0]
        if label == legit.split(".")[0]:
            own += 1  # the brand's own name under another TLD (amazon.de)
            continue
        by_method[method] += 1
        by_length[bucket(label)] += 1
        if legit in ru_sites:
            ru_hits.append(f"{domain} ~ {legit} ({method})")
    return {"n": len(names), "brand_own": own, "by_method": dict(by_method), "by_length": dict(by_length),
            "russian_brand_hits": ru_hits}


def summarize(rows: list[dict]) -> dict:
    table: dict[str, dict[str, list[int]]] = {}
    for r in rows:
        cell = table.setdefault(r["class"], {}).setdefault(r["bucket"], [0, 0])
        cell[0] += r["caught"]
        cell[1] += 1
    return table


def _cell(table: dict, cls: str, b: str) -> str:
    c = table.get(cls, {}).get(b)
    return f"{c[0]}/{c[1]}" if c else "–"


def print_recall(table: dict) -> None:
    print("| class | " + " | ".join(f"brands of {b}" for b in BUCKETS) + " |")
    print("|---|" + "---:|" * len(BUCKETS))
    for cls in CLASSES:
        print(f"| {cls} | " + " | ".join(_cell(table, cls, b) for b in BUCKETS) + " |")
    caught = sum(c[0] for t in table.values() for c in t.values())
    total = sum(c[1] for t in table.values() for c in t.values())
    print(f"\ncaught {caught}/{total}")


def _compare(before: dict, after: dict) -> None:
    b, a = summarize(before["rows"]), summarize(after["rows"])
    print("| class | " + " | ".join(f"brands of {x}" for x in BUCKETS) + " |")
    print("|---|" + "---|" * len(BUCKETS))
    for cls in CLASSES:
        cells = []
        for x in BUCKETS:
            cb, ca = b.get(cls, {}).get(x), a.get(cls, {}).get(x)
            cells.append(f"{cb[0]} → {ca[0]} of {ca[1]}" if cb and ca else "–")
        print(f"| {cls} | " + " | ".join(cells) + " |")
    tb = sum(r["caught"] for r in before["rows"])
    ta = sum(r["caught"] for r in after["rows"])
    print(f"\ncaught {tb} → {ta} of {len(after['rows'])}")
    b_rows = {r["host"]: r["caught"] for r in before["rows"]}
    lost = [r["host"] for r in after["rows"] if b_rows.get(r["host"]) and not r["caught"]]
    gained = [r["host"] for r in after["rows"] if b_rows.get(r["host"]) is False and r["caught"]]
    print(f"lost {len(lost)}: {', '.join(lost[:40])}{' …' if len(lost) > 40 else ''}")
    print(f"gained {len(gained)}: {', '.join(gained[:40])}{' …' if len(gained) > 40 else ''}")
    if before.get("top") and after.get("top"):
        print("\n| top-100k hits (not the brand's own name) | before | after |")
        print("|---|---:|---:|")
        methods = sorted({*before["top"]["by_method"], *after["top"]["by_method"]})
        for m in methods:
            print(f"| {m} | {before['top']['by_method'].get(m, 0)} | {after['top']['by_method'].get(m, 0)} |")
        for x in BUCKETS:
            print(f"| names of {x} letters | {before['top']['by_length'].get(x, 0)} | "
                  f"{after['top']['by_length'].get(x, 0)} |")
        print(f"| brand's own name under another TLD | {before['top']['brand_own']} | {after['top']['brand_own']} |")
        ru_after = after["top"].get("russian_brand_hits", [])
        print(f"\nRussian-brand hits after ({len(ru_after)}): {', '.join(ru_after) or 'none'}")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--brands", choices=("all", "global", "ru"), default="all",
                    help="whose variants to generate (default: all)")
    ap.add_argument("--top", action="store_true", help="also count hits on the Tranco top-100k (slow)")
    ap.add_argument("--out", help="write the full result as JSON")
    ap.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"), help="print the before/after table")
    args = ap.parse_args(argv)

    if args.compare:
        before, after = (json.loads(Path(p).read_text()) for p in args.compare)
        _compare(before, after)
        return 0
    rows = score_variants(build_variants(args.brands))
    print_recall(summarize(rows))
    result = {"rows": rows, "top": top_hits() if args.top else None}
    if result["top"]:
        print(f"\ntop-100k: {result['top']}")
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=0))
    return 0


if __name__ == "__main__":
    sys.exit(main())

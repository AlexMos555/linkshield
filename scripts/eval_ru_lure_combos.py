#!/usr/bin/env python3
"""Recall and cost of Russian brand + lure-word combos in the typosquat rule.

Recall: every Russian brand name in data/typosquat_targets_ru.json, combined
with lure words the way fraud reports show them — sberbank-bonus,
bonus-sberbank, sberbankbonus, sberbank-bonus-online, and the Cyrillic
names with Cyrillic words (госуслуги-лк) — and counted per lure and per
shape. The spellings below are written here, not read from the scorer
(api/services/ru_lures.py), and a 'misspelled' row holds spellings the
scorer does not list, so the table shows what the vocabulary does NOT
generalise to as well as what it does.

Cost (--names FILE …): the combo and open-zone hits a Russian brand makes on
real names — a Tranco csv (rank,domain), a 'host | …' list or one name per
line. Every one of them is a site, so each hit is a false positive to
explain or exempt.

Usage:
    python3 scripts/eval_ru_lure_combos.py                       # recall table
    python3 scripts/eval_ru_lure_combos.py --out after.json
    python3 scripts/eval_ru_lure_combos.py --names data/benchmark_legit_ru.txt
    python3 scripts/eval_ru_lure_combos.py --compare before.json after.json

No network access. Copy this file into an older checkout to get its "before".
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterator, Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Lure -> (Latin spellings, Cyrillic spellings). The first Latin spelling is
# the common one; the others are other transliterations and inflections.
LURES: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "bonus": (("bonus", "bonusy", "bonusi"), ("бонус", "бонусы")),
    "prize": (("priz", "prizy"), ("приз", "призы")),
    "gift": (("podarok", "podarki"), ("подарок", "подарки")),
    "payout": (("vyplata", "vyplaty", "viplata"), ("выплата", "выплаты")),
    "compensation": (("kompensaciya", "kompensatsiya", "kompensacija"), ("компенсация",)),
    "delivery": (("dostavka", "doctavka", "dostavkoy", "dostavim"), ("доставка", "доставкой")),
    "payment": (("oplata", "oplaty"), ("оплата",)),
    "refund": (("vozvrat",), ("возврат",)),
    "cabinet": (("lk", "kabinet", "lichnyj-kabinet"), ("лк", "кабинет")),
    "login": (("vhod", "vxod", "voiti"), ("вход", "войти")),
    "confirm": (("podtverdit", "podtverzhdenie"), ("подтвердить", "подтверждение")),
    "block": (("blokirovka", "razblokirovka"), ("блокировка", "разблокировка")),
    "protection": (("zaschita", "zashchita", "zashita"), ("защита",)),
    "guarantee": (("garantiya", "garantia"), ("гарантия",)),
    "promo": (("promokod", "akciya", "aktsiya"), ("промокод", "акция")),
    "safe_deal": (("bezopasnaya-sdelka", "sdelka"), ("безопасная-сделка", "сделка")),
    "win": (("vyigrysh", "rozygrysh"), ("выигрыш", "розыгрыш")),
    # Not listed by the scorer: phonetic misspellings, a dropped letter.
    "misspelled": (("bonuz", "podarog", "dostafka", "kompensaziya", "garantya"), ("бонуз", "подарог")),
}
SHAPES = ("brand-word", "word-brand", "brandword", "brand-word-online", "brand-online-word")
LATIN_TLD = "com"
CYRILLIC_TLD = "рф"


def _groups() -> list[dict]:
    return list(json.loads((ROOT / "data" / "typosquat_targets_ru.json").read_text(encoding="utf-8"))["brands"].values())


def load_names() -> list[str]:
    """Every Russian brand name (sberbank, сбербанк …), from the data file."""
    return sorted({n for g in _groups() for n in g["names"]})


def listed_domains() -> set[str]:
    """Domains the data file lists as a brand's own or someone else's
    (mtsbonus.com is MTS's): no variant, whatever its shape."""
    return {d for g in _groups() for field in ("official", "unrelated") for d in g.get(field, {})}


def _shape(shape: str, brand: str, word: str, online: str) -> Optional[str]:
    if shape == "brandword":
        return None if "-" in word else brand + word
    return shape.replace("brand", brand).replace("online", online).replace("word", word)


def variants() -> Iterator[dict]:
    listed = listed_domains()
    for brand in load_names():
        latin = brand.isascii()
        tld = LATIN_TLD if latin else CYRILLIC_TLD
        online = "online" if latin else "онлайн"
        for lure, (lat, cyr) in LURES.items():
            for word in lat if latin else cyr:
                for shape in SHAPES:
                    label = _shape(shape, brand, word, online)
                    if label and f"{label}.{tld}" not in listed:
                        yield {"host": f"{label}.{tld}", "brand": brand, "lure": lure, "shape": shape}


def score_variants(rows: list[dict]) -> list[dict]:
    from api.services.scoring import _check_typosquatting_v2

    return [{**r, "caught": _check_typosquatting_v2(r["host"]) is not None} for r in rows]


def _read_names(path: Path) -> Iterator[str]:
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        first = line.split(",", 1)
        if len(first) == 2 and first[0].isdigit():
            line = first[1]
        yield line.split(" | ")[0].split("\t")[0].strip().lower()


def cost(paths: list[str]) -> dict:
    """Combo and open-zone hits a Russian brand makes on real names."""
    from api.services.scoring import _check_brand_under_open_zone, _check_typosquatting_v2, _decode_idn

    ru_sites = {d for g in _groups() for d in g["names"].values()}
    hits: dict[str, str] = {}
    n = 0
    for p in paths:
        for host in _read_names(Path(p)):
            n += 1
            ascii_host = host if host.isascii() else host.encode("idna").decode("ascii")
            typo = _check_typosquatting_v2(_decode_idn(ascii_host))
            zone = _check_brand_under_open_zone(ascii_host)
            if typo and typo[0] in ru_sites and typo[1] == "combosquatting":
                hits[host] = f"combosquatting ~ {typo[0]}"
            elif zone:
                hits[host] = f"under an open zone: {zone}"
    return {"n": n, "hits": hits}


def table(rows: list[dict], key: str) -> dict[str, list[int]]:
    out: dict[str, list[int]] = {}
    for r in rows:
        cell = out.setdefault(r[key], [0, 0])
        cell[0] += r["caught"]
        cell[1] += 1
    return out


def _print(rows: list[dict]) -> None:
    for key in ("lure", "shape"):
        print(f"\n| {key} | caught |\n|---|---:|")
        for k, (c, t) in table(rows, key).items():
            print(f"| {k} | {c}/{t} |")
    print(f"\ncaught {sum(r['caught'] for r in rows)}/{len(rows)}")


def _compare(before: dict, after: dict) -> None:
    for key in ("lure", "shape"):
        b, a = table(before["rows"], key), table(after["rows"], key)
        print(f"\n| {key} | before | after |\n|---|---:|---:|")
        for k in a:
            print(f"| {k} | {b.get(k, [0])[0]} | {a[k][0]} of {a[k][1]} |")
    tb = sum(r["caught"] for r in before["rows"])
    ta = sum(r["caught"] for r in after["rows"])
    print(f"\ncaught {tb} → {ta} of {len(after['rows'])}")
    if before.get("cost") and after.get("cost"):
        hb, ha = before["cost"]["hits"], after["cost"]["hits"]
        print(f"\nhits on {after['cost']['n']} real names: {len(hb)} → {len(ha)}")
        for host in sorted(set(ha) - set(hb)):
            print(f"  new: {host}  ({ha[host]})")
        for host in sorted(set(hb) - set(ha)):
            print(f"  gone: {host}  ({hb[host]})")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--names", nargs="+", metavar="FILE", help="also count hits on these real names")
    ap.add_argument("--out", help="write the full result as JSON")
    ap.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"), help="print the before/after table")
    args = ap.parse_args(argv)

    if args.compare:
        before, after = (json.loads(Path(p).read_text(encoding="utf-8")) for p in args.compare)
        _compare(before, after)
        return 0
    rows = score_variants(list(variants()))
    _print(rows)
    result = {"rows": rows, "cost": cost(args.names) if args.names else None}
    if result["cost"]:
        print(f"\nhits on {result['cost']['n']} real names: {len(result['cost']['hits'])}")
        for host, why in sorted(result["cost"]["hits"].items()):
            print(f"  {host}  ({why})")
    if args.out:
        Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=0), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())

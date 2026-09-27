#!/usr/bin/env python3
"""Offline false-positive / detection measurement for the name-only rules.

Scores two labelled host lists with api.services.scoring.calculate_score(),
giving it the host and NOTHING else — no blocklists, no WHOIS, no TLS or
header probes, no Tranco lookup. What is left is exactly the part of a
verdict that the name alone produces: the allowlist short-circuit, the
lexical and brand heuristics, and the local ML model.

    tests/data/ru_heuristics_legit.txt   Russian sites that must not be flagged
    tests/data/ru_heuristics_phish.txt   look-alikes that must stay caught

Usage:
    python3 scripts/eval_ru_heuristics.py                  # report, ML on
    python3 scripts/eval_ru_heuristics.py --no-ml          # heuristics only
    python3 scripts/eval_ru_heuristics.py --out after.json
    python3 scripts/eval_ru_heuristics.py --compare before.json after.json
    python3 scripts/eval_ru_heuristics.py --no-ml --caught # PHISH hosts caught

No network access, no API key. --compare prints the before/after table that
goes into a PR description. --caught lists the PHISH hosts scored above
'safe', one per line: run on the pre-fix code, it is the baseline that
tests/test_ru_heuristic_fps.py holds the fix to
(tests/data/ru_heuristics_phish_caught_before.txt).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

LEGIT_PATH = ROOT / "tests" / "data" / "ru_heuristics_legit.txt"
PHISH_PATH = ROOT / "tests" / "data" / "ru_heuristics_phish.txt"
LEVELS = ("safe", "caution", "dangerous")


@dataclass(frozen=True)
class Host:
    host: str
    category: str


def parse_hosts(text: str) -> list[Host]:
    """'host | category | …' lines; '#' comments and blank lines skipped.
    Raises ValueError on a malformed or repeated host, naming the line."""
    hosts: list[Host] = []
    seen: set[str] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = [f.strip() for f in line.split(" | ")]
        if len(fields) < 3 or not fields[0] or not fields[1]:
            raise ValueError(f"line {number}: expected 'host | category | …'")
        host = fields[0]
        if host != host.lower() or not host.isascii() or "/" in host or "." not in host:
            raise ValueError(f"line {number}: {host!r} must be a lowercase ASCII (punycode) host")
        if host in seen:
            raise ValueError(f"line {number}: {host} is listed twice")
        seen.add(host)
        hosts.append(Host(host, fields[1]))
    return hosts


def load(path: Path) -> list[Host]:
    return parse_hosts(path.read_text(encoding="utf-8"))


def score_hosts(hosts: list[Host]) -> list[dict]:
    from api.services.scoring import calculate_score

    rows = []
    for h in hosts:
        score, level, reasons = calculate_score({"domain": h.host})
        rows.append({
            "host": h.host,
            "category": h.category,
            "score": score,
            "level": level.value,
            "signals": [r.signal for r in reasons if r.weight > 0],
        })
    return rows


def disable_ml() -> None:
    import api.services.ml_scorer as ml_scorer

    ml_scorer.ml_predict = lambda domain: None


def summarize(rows: list[dict]) -> dict:
    levels = Counter(r["level"] for r in rows)
    signals = Counter(s for r in rows for s in r["signals"])
    by_category: dict[str, Counter] = {}
    for r in rows:
        by_category.setdefault(r["category"], Counter())[r["level"]] += 1
    return {
        "n": len(rows),
        "levels": {lv: levels.get(lv, 0) for lv in LEVELS},
        "signals": dict(signals.most_common()),
        "by_category": {c: {lv: n.get(lv, 0) for lv in LEVELS} for c, n in sorted(by_category.items())},
    }


def run(ml: bool) -> dict:
    if not ml:
        disable_ml()
    legit = score_hosts(load(LEGIT_PATH))
    phish = score_hosts(load(PHISH_PATH))
    return {
        "ml": ml,
        "legit": {"summary": summarize(legit), "rows": legit},
        "phish": {"summary": summarize(phish), "rows": phish},
    }


def _print_report(result: dict) -> None:
    for name in ("legit", "phish"):
        s = result[name]["summary"]
        lv = s["levels"]
        print(f"\n== {name.upper()} ({s['n']} hosts, ML {'on' if result['ml'] else 'off'}) ==")
        print(f"  safe {lv['safe']}  caution {lv['caution']}  dangerous {lv['dangerous']}")
        print("  signals: " + ", ".join(f"{k} {v}" for k, v in s["signals"].items()))
        for cat, counts in s["by_category"].items():
            print(f"  {cat:<14} " + "  ".join(f"{k} {v}" for k, v in counts.items()))
    print("\nLEGIT not safe:")
    for r in result["legit"]["rows"]:
        if r["level"] != "safe":
            print(f"  {r['level']:<9} {r['score']:>3}  {r['host']:<32} {', '.join(r['signals'])}")
    print("\nPHISH missed (safe):")
    for r in result["phish"]["rows"]:
        if r["level"] == "safe":
            print(f"  {r['score']:>3}  {r['host']}")


def _compare(before: dict, after: dict) -> None:
    def caught(res: dict) -> int:
        lv = res["phish"]["summary"]["levels"]
        return lv["caution"] + lv["dangerous"]

    print("| set | metric | before | after |")
    print("|---|---|---:|---:|")
    for name in ("legit", "phish"):
        b, a = before[name]["summary"], after[name]["summary"]
        for lv in ("dangerous", "caution", "safe"):
            print(f"| {name.upper()} ({b['n']}) | {lv} | {b['levels'][lv]} | {a['levels'][lv]} |")
    print(f"| PHISH | caught (caution + dangerous) | {caught(before)} | {caught(after)} |")

    print("\n| signal | LEGIT before | LEGIT after | PHISH before | PHISH after |")
    print("|---|---:|---:|---:|---:|")
    names = sorted({*before["legit"]["summary"]["signals"], *after["legit"]["summary"]["signals"],
                    *before["phish"]["summary"]["signals"], *after["phish"]["summary"]["signals"]})
    for sig in names:
        vals = [res[s]["summary"]["signals"].get(sig, 0)
                for s in ("legit", "phish") for res in (before, after)]
        lb, la, pb, pa = vals[0], vals[1], vals[2], vals[3]
        print(f"| {sig} | {lb} | {la} | {pb} | {pa} |")

    b_rows = {r["host"]: r for r in before["phish"]["rows"]}
    lost = [r for r in after["phish"]["rows"] if r["level"] == "safe" and b_rows[r["host"]]["level"] != "safe"]
    gained = [r for r in after["phish"]["rows"] if r["level"] != "safe" and b_rows[r["host"]]["level"] == "safe"]
    print(f"\nPHISH lost: {[r['host'] for r in lost] or 'none'}")
    print(f"PHISH gained: {[r['host'] for r in gained] or 'none'}")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--no-ml", action="store_true", help="stub the ML model out (heuristics only)")
    ap.add_argument("--out", help="write the full result as JSON")
    ap.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"), help="print the before/after table")
    ap.add_argument("--caught", action="store_true", help="print the PHISH hosts caught, one per line")
    args = ap.parse_args(argv)

    if args.compare:
        before, after = (json.loads(Path(p).read_text()) for p in args.compare)
        _compare(before, after)
        return 0
    if args.caught:
        if args.no_ml:
            disable_ml()
        for r in score_hosts(load(PHISH_PATH)):
            if r["level"] != "safe":
                print(r["host"])
        return 0
    result = run(ml=not args.no_ml)
    _print_report(result)
    if args.out:
        Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""What the served ML model does to real sites and to look-alikes, offline.

The offline companion of scripts/eval_ml_model.py (the 2026-10 evaluation,
which downloads fresh feeds): local lists only, so it runs in CI and on a
plane, and its before/after table is what a retrain PR quotes.

Scores host lists with the model in data/ (api.services.ml_scorer, the
onnxruntime path production runs) and with calculate_score(), which is given
the host and nothing else — the part of a verdict the name alone produces.

    ru_legit    tests/data/ru_heuristics_legit.txt   must stay safe
    ru_phish    tests/data/ru_heuristics_phish.txt   must stay caught
    bench_ru    data/benchmark_legit_ru.txt          real Russian sites
    top100k     data/top_100k.json                   Tranco top-100k
    shapes      data/top-1m-subdomains.csv           Tranco hosts with a
                                                     subdomain (optional,
                                                     from refresh_training_feeds)

The three Russian sets are held out of training (ml/train_model.HELD_OUT_FILES).
The Tranco sets are NOT: some of their names are training negatives, so
their rates flatter any model trained on them. The allowlist answers every
top-100k name 'safe' before the model runs; --no-allowlist scores them as
the long tail of real sites is scored — same shapes, nothing to spare them.

Usage:
    python3 scripts/eval_ml_offline.py --out after.json [--no-allowlist] [--top N]
    python3 scripts/eval_ml_offline.py --compare before.json after.json

No network access. Copy this file into an older checkout to get its "before".
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

LEVELS = ("safe", "caution", "dangerous")
SHAPES_SAMPLE = 5000
SEED = 20260929


def _hosts(path: Path) -> list[str]:
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            out.append(line.split(" | ")[0].strip())
    return out


def _shape_hosts(n: int) -> list[str]:
    """A seeded sample of Tranco hosts one or two levels under a registered
    site — what 'has a subdomain' costs a real site."""
    from api.services.scoring import _subdomain_labels, is_hosting_platform_site

    path = ROOT / "data" / "top-1m-subdomains.csv"
    if not path.exists():
        return []
    pool = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        host = line.partition(",")[2].strip().lower()
        if host and not host.endswith(".arpa") and not is_hosting_platform_site(host) \
                and 1 <= len(_subdomain_labels(host)) <= 2:
            pool.append(host)
    return random.Random(SEED).sample(sorted(pool), min(n, len(pool)))


def load_sets(top_n: Optional[int]) -> dict[str, list[str]]:
    top = sorted(json.loads((ROOT / "data" / "top_100k.json").read_text()))
    if top_n:
        top = random.Random(SEED).sample(top, min(top_n, len(top)))
    return {
        "ru_legit": _hosts(ROOT / "tests" / "data" / "ru_heuristics_legit.txt"),
        "ru_phish": _hosts(ROOT / "tests" / "data" / "ru_heuristics_phish.txt"),
        "bench_ru": _hosts(ROOT / "data" / "benchmark_legit_ru.txt"),
        "top100k": top,
        "shapes": _shape_hosts(SHAPES_SAMPLE),
    }


def score_set(hosts: list[str], allowlist: bool) -> dict:
    from api.services import ml_scorer, scoring

    levels = dict.fromkeys(LEVELS, 0)
    ml_high = ml_susp = p60 = p85 = 0
    flagged: list[str] = []
    trusted = scoring.is_trusted_top_domain
    if not allowlist:
        scoring.is_trusted_top_domain = lambda domain: False
    try:
        for host in hosts:
            _, level, reasons = scoring.calculate_score({"domain": host})
            levels[level.value] += 1
            signals = {r.signal for r in reasons}
            ml_high += "ml_high_risk" in signals
            ml_susp += "ml_suspicious" in signals
            if level.value != "safe" and signals & {"ml_high_risk", "ml_suspicious"}:
                flagged.append(host)
            p = (ml_scorer.ml_predict(host) or {}).get("phishing_probability", 0.0)
            p60 += p > 0.6
            p85 += p > 0.85
    finally:
        scoring.is_trusted_top_domain = trusted
    return {
        "n": len(hosts), "levels": levels, "ml_high_risk": ml_high, "ml_suspicious": ml_susp,
        "p>0.6": p60, "p>0.85": p85, "not_safe_with_ml_signal": sorted(flagged),
    }


def run(allowlist: bool, top_n: Optional[int]) -> dict:
    from api.services import ml_scorer

    assert ml_scorer.backend_status() != "disabled", "no ML backend — nothing to measure"
    meta = json.loads((ROOT / "data" / "model_meta.json").read_text())
    result = {"allowlist": allowlist, "model": {k: meta.get(k) for k in (
        "features_version", "test_auc", "test_names_only", "total_samples")}}
    for name, hosts in load_sets(top_n).items():
        result[name] = score_set(hosts, allowlist)
    return result


def _compare(before: dict, after: dict) -> None:
    print("| set | metric | before | after |")
    print("|---|---|---:|---:|")
    for name in ("ru_legit", "ru_phish", "bench_ru", "top100k", "shapes"):
        b, a = before.get(name), after.get(name)
        if not b or not a:
            continue
        label = f"{name} ({a['n']})"
        if name == "ru_phish":
            caught = lambda s: s["levels"]["caution"] + s["levels"]["dangerous"]  # noqa: E731
            print(f"| {label} | caught | {caught(b)} | {caught(a)} |")
        else:
            for lv in ("dangerous", "caution"):
                print(f"| {label} | {lv} | {b['levels'][lv]} | {a['levels'][lv]} |")
        for key in ("ml_high_risk", "ml_suspicious", "p>0.6", "p>0.85"):
            print(f"| {label} | {key} | {b[key]} | {a[key]} |")


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", help="write the result as JSON")
    ap.add_argument("--no-allowlist", action="store_true", help="score top-100k names as the long tail is scored")
    ap.add_argument("--top", type=int, help="a seeded sample of N top-100k names instead of all")
    ap.add_argument("--compare", nargs=2, metavar=("BEFORE", "AFTER"))
    args = ap.parse_args(argv)
    if args.compare:
        before, after = (json.loads(Path(p).read_text()) for p in args.compare)
        _compare(before, after)
        return 0
    result = run(allowlist=not args.no_allowlist, top_n=args.top)
    for name in ("ru_legit", "ru_phish", "bench_ru", "top100k", "shapes"):
        s = result[name]
        print(f"{name:<9} n={s['n']:<6} {s['levels']}  ml_high {s['ml_high_risk']}  ml_susp {s['ml_suspicious']}  "
              f"p>0.6 {s['p>0.6']}  p>0.85 {s['p>0.85']}")
    if args.out:
        Path(args.out).write_text(json.dumps(result, ensure_ascii=False, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

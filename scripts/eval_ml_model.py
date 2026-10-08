#!/usr/bin/env python3
"""What the domain ML model says on names it never trained on — alone, and
inside the name-only pipeline.

The served model (data/phishing_model.onnx) is retrained weekly on URLhaus +
OpenPhish hosts against a Tranco sample (ml/train_model.py). Its test AUC in
data/model_meta.json is measured on a split of THAT corpus. This script asks
the question the founder needs answered instead: on Russian traffic and on
fresh phishing from sources the training never reads, is the model helping,
hurting or doing nothing?

Every host is scored three ways, offline (no network, no API key):

  ml          ml_scorer.ml_predict(host) — the probability alone;
  heuristics  calculate_score({"domain": host}) with the model stubbed out —
              the allowlist, the lexical and brand rules, nothing else;
  pipeline    the same call with the model on — what the name alone earns in
              production before any list, probe or threat-intel source.

The difference between `pipeline` and `heuristics` is exactly what the model
adds and what it costs. For the fresh phishing sample the published blocklist
(the list the phone blocks) is read too, so the report separates "a list
already covers it" from "only the model saw it".

Sets (each a held-out set for the model unless noted):

  tests/data/ru_heuristics_legit.txt     Russian sites that must stay safe
  tests/data/ru_heuristics_phish.txt     constructed Russian look-alikes
  data/benchmark_legit_ru.txt            the weekly benchmark's RU legit sample
  Tranco top-1M (--tranco)               four samples: rank 10k–100k split by
                                         the shipped allowlist (data/top_100k.json
                                         is another snapshot): the allowlisted
                                         part (in_top_domains=1 for the model —
                                         NOT held-out, reported for completeness)
                                         and the rest; rank 100k–1M; the same tail
                                         restricted to .ru/.su/.рф. Training
                                         draws its benign half from this list,
                                         so a tail sample overlaps training by
                                         roughly its sampling fraction (~1%).
  PhishTank online-valid (--phishtank)   verified phish submitted in the last
                                         --days days. PhishTank is never
                                         ingested by training or the blocklist.
  TweetFeed week.csv (--tweetfeed)       community-reported phishing domains of
                                         the last 7 days (CC0). In the
                                         blocklist, not in training.

Usage:
    python3 scripts/eval_ml_model.py                       # the three RU files only
    python3 scripts/eval_ml_model.py \
        --phishtank feeds/online-valid.csv.gz --tweetfeed feeds/week.csv \
        --tranco feeds/top-1m.csv.zip --blocklist feeds/blocklist-dns.txt \
        --out docs/benchmarks/2026-10-04-ml-eval.json

    curl -A Cleanway-benchmark/1.0 -o feeds/online-valid.csv.gz https://data.phishtank.com/data/online-valid.csv.gz
    curl -o feeds/week.csv https://raw.githubusercontent.com/0xDanielLopez/TweetFeed/master/week.csv
    curl -o feeds/top-1m.csv.zip https://tranco-list.eu/top-1m.csv.zip
    curl -o feeds/blocklist-dns.txt https://api.cleanway.ai/api/v1/blocklist/dns

PhishTank throttles repeated anonymous pulls (HTTP 404): download once and
pass the file. Prints Markdown tables; --out writes every per-host row.
"""
from __future__ import annotations

import argparse
import csv
import encodings.idna
import gzip
import ipaddress
import json
import random
import sys
import zipfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(ROOT / "scripts") not in sys.path:
    sys.path.insert(0, str(ROOT / "scripts"))

import benchmark_legit  # noqa: E402
from eval_ru_heuristics import load as load_rule_hosts  # noqa: E402

LEVELS = ("safe", "caution", "dangerous")
# The scorer's own thresholds (api/services/scoring.py, "ML Model prediction").
ML_SUSPICIOUS = 0.6   # +20 — alone this still reads 'safe' (score <= 20)
ML_HIGH_RISK = 0.85   # +35 — alone this reads 'caution', never 'dangerous'
ML_SAFE_OVERRIDE = 0.1  # -10 when the rules already scored above 30
BUCKETS = ((0.0, 0.1), (0.1, 0.5), (0.5, ML_SUSPICIOUS), (ML_SUSPICIOUS, ML_HIGH_RISK), (ML_HIGH_RISK, 0.9), (0.9, 1.01))
SAMPLE_SEED = 42
TLD_RU = ("ru", "su", "xn--p1ai")


def _host_of(url: str) -> Optional[str]:
    s = url.strip()
    if "://" not in s:
        s = "http://" + s
    try:
        host = (urlparse(s).hostname or "").lower().strip(".")
    except ValueError:
        return None
    if not host or "." not in host:
        return None
    if not host.isascii():
        # TweetFeed ships raw Unicode ('автозаим.рф'); the model, the scorer and
        # the blocklist hashes all see the punycode wire form, as production's
        # feed parser does (scripts/refresh_dangerous_domains._to_punycode).
        try:
            host = ".".join(
                label if label.isascii() else encodings.idna.ToASCII(label).decode("ascii")
                for label in host.split(".")
            )
        except (UnicodeError, ValueError):
            return None
    try:
        ipaddress.ip_address(host)
        return None  # the model is a name model; IP literals are reported apart
    except ValueError:
        return host


def _dedup(hosts: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for h in hosts:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


# ── sources ──────────────────────────────────────────────────────────────

def phishtank_recent(path: Path, days: int, now: datetime) -> tuple[list[str], dict]:
    """Hosts of verified-online phish submitted within `days` of `now`."""
    with gzip.open(path, "rt", encoding="utf-8", errors="ignore") as f:
        rows = list(csv.DictReader(f))
    since = now - timedelta(days=days)
    hosts: list[str] = []
    ips = 0
    newest = oldest = None
    for row in rows:
        stamp = (row.get("submission_time") or "").strip()
        try:
            when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except ValueError:
            continue
        if when < since:
            continue
        newest = max(newest, when) if newest else when
        oldest = min(oldest, when) if oldest else when
        host = _host_of(row.get("url") or "")
        if host is None:
            ips += 1
            continue
        hosts.append(host)
    unique = _dedup(hosts)
    return unique, {
        "rows_total": len(rows), "rows_in_window": len(hosts) + ips, "ip_or_bad": ips,
        "unique_hosts": len(unique), "window_days": days,
        "oldest": oldest.isoformat() if oldest else None, "newest": newest.isoformat() if newest else None,
    }


def tweetfeed_week(path: Path) -> tuple[list[str], dict]:
    """TweetFeed week.csv: date,user,type,value,tags,tweet — phishing domains and URL hosts."""
    hosts: list[str] = []
    rows = 0
    with open(path, encoding="utf-8", errors="ignore", newline="") as f:
        for row in csv.reader(f):
            if len(row) < 5:
                continue
            rows += 1
            kind, value, tags = row[2].strip(), row[3].strip(), row[4].lower()
            if "phishing" not in tags or kind not in ("domain", "url"):
                continue
            host = _host_of(value)
            if host:
                hosts.append(host)
    unique = _dedup(hosts)
    return unique, {"rows_total": rows, "unique_hosts": len(unique)}


def tranco_samples(path: Path, n: int, seed: int = SAMPLE_SEED,
                   allowlisted: Optional[Callable[[str], bool]] = None) -> dict[str, tuple[list[str], dict]]:
    """`allowlisted` decides the head split; default: the production allowlist
    (data/top_100k.json), which is a different Tranco snapshot than the file."""
    if allowlisted is None:
        from api.services.scoring import is_trusted_top_domain as allowlisted
    with zipfile.ZipFile(path) as zf:
        member = next(m for m in zf.namelist() if m.endswith(".csv"))
        text = zf.read(member).decode("utf-8", "ignore")
    head: list[str] = []
    head_unlisted: list[str] = []
    tail: list[str] = []
    tail_ru: list[str] = []
    for line in text.splitlines():
        parts = line.strip().split(",", 1)
        if len(parts) != 2:
            continue
        try:
            rank = int(parts[0])
        except ValueError:
            continue
        dom = parts[1].lower()
        if 10_000 < rank <= 100_000:
            (head if allowlisted(dom) else head_unlisted).append(dom)
        elif rank > 100_000:
            tail.append(dom)
            if dom.rsplit(".", 1)[-1] in TLD_RU:
                tail_ru.append(dom)
    rng = random.Random(seed)

    def pick(pool: list[str]) -> list[str]:
        return sorted(rng.sample(pool, min(n, len(pool))))

    return {
        "tranco_10k_100k": (pick(head), {"pool": len(head), "note": "allowlisted in production; in_top_domains=1 for the model — not held-out"}),
        "tranco_10k_100k_unlisted": (pick(head_unlisted), {"pool": len(head_unlisted), "note": "rank 10k–100k in this snapshot but not in the shipped allowlist — scored like the long tail"}),
        "tranco_100k_1m": (pick(tail), {"pool": len(tail), "note": "training samples its benign half from this range (~1% overlap)"}),
        "tranco_100k_1m_ru": (pick(tail_ru), {"pool": len(tail_ru), "note": ".ru/.su/.рф names below the allowlist — the Russian long tail"}),
    }


def blocklist_hashes(path: Path) -> tuple[set[int], dict]:
    from api.services.blocklist_artifact import parse_artifact_v2

    header, hashes = parse_artifact_v2(path.read_bytes())
    return set(hashes), {"count": header.get("count"), "generated": header.get("generated")}


# ── scoring ──────────────────────────────────────────────────────────────

def _score_once(host: str) -> dict:
    from api.services.scoring import calculate_score

    score, level, reasons = calculate_score({"domain": host})
    return {"score": score, "level": level.value, "signals": [r.signal for r in reasons if r.weight > 0]}


def score_hosts(hosts: list[str], listed: Optional[Callable[[str], bool]] = None) -> list[dict]:
    """ML probability, heuristics-only and pipeline verdicts for every host."""
    import api.services.ml_scorer as ml_scorer
    from api.services.ml_features import extract_ml_features
    from api.services.scoring import is_trusted_top_domain

    real_predict = ml_scorer.ml_predict
    if ml_scorer.backend_status() == "disabled":
        raise SystemExit("no ML backend: pip install onnxruntime numpy")
    rows: list[dict] = []
    for host in hosts:
        ml = real_predict(host)
        prob = ml["phishing_probability"] if ml else None
        ml_scorer.ml_predict = lambda domain: None
        try:
            heur = _score_once(host)
        finally:
            ml_scorer.ml_predict = real_predict
        pipe = _score_once(host)
        row = {
            "host": host, "ml": prob, "trusted": is_trusted_top_domain(host),
            "heuristics": heur, "pipeline": pipe,
        }
        if listed is not None:
            row["listed"] = listed(host)
        if prob is not None and prob > ML_SUSPICIOUS:
            feats = extract_ml_features(host)
            row["features"] = {k: feats[k] for k in (
                "dot_count", "subdomain_depth", "has_fake_tld_subdomain", "is_typosquat",
                "brand_in_subdomain", "max_brand_similarity", "name_length", "tld_high_risk",
                "tld_medium_risk", "in_top_domains", "has_suspicious_keyword",
            )}
        rows.append(row)
    return rows


# ── summaries ────────────────────────────────────────────────────────────

def _levels(rows: list[dict], key: str) -> dict[str, int]:
    c = Counter(r[key]["level"] for r in rows)
    return {lv: c.get(lv, 0) for lv in LEVELS}


def _bucket_counts(probs: list[float]) -> dict[str, int]:
    return {f"{lo:g}-{min(hi, 1.0):g}": sum(1 for p in probs if lo <= p < hi) for lo, hi in BUCKETS}


def summarize(rows: list[dict], expected: str) -> dict:
    """`expected` is 'legit' or 'phish' — decides what counts as a mistake."""
    probs = [r["ml"] for r in rows if r["ml"] is not None]
    n = len(rows)
    out: dict = {
        "n": n,
        "trusted_by_allowlist": sum(1 for r in rows if r["trusted"]),
        "ml": {
            "scored": len(probs),
            "buckets": _bucket_counts(probs),
            "gt_0.6": sum(1 for p in probs if p > ML_SUSPICIOUS),
            "gt_0.85": sum(1 for p in probs if p > ML_HIGH_RISK),
            "gt_0.9": sum(1 for p in probs if p > 0.9),
            "lt_0.1": sum(1 for p in probs if p < ML_SAFE_OVERRIDE),
            "lt_0.5": sum(1 for p in probs if p < 0.5),
            "median": sorted(probs)[len(probs) // 2] if probs else None,
        },
        "heuristics": _levels(rows, "heuristics"),
        "pipeline": _levels(rows, "pipeline"),
    }
    if expected == "legit":
        out["ml_cost"] = [  # a name the rules let through that the model pushes out of 'safe'
            {"host": r["host"], "ml": r["ml"], "pipeline": r["pipeline"]["level"], "score": r["pipeline"]["score"],
             "signals": r["pipeline"]["signals"], "category": r.get("category")}
            for r in rows if r["heuristics"]["level"] == "safe" and r["pipeline"]["level"] != "safe"
        ]
        out["ml_rescue"] = [  # the opposite: ml_safe_override pulls a rule-flagged name back to 'safe'
            {"host": r["host"], "ml": r["ml"], "heuristics": r["heuristics"]["level"], "category": r.get("category")}
            for r in rows if r["heuristics"]["level"] != "safe" and r["pipeline"]["level"] == "safe"
        ]
        if any("category" in r for r in rows):
            cats: dict[str, dict] = {}
            for r in rows:
                c = cats.setdefault(r.get("category") or "?", {"n": 0, "ml_gt_0.85": 0, "ml_gt_0.6": 0,
                                                              "pipeline_not_safe": 0, "heuristics_not_safe": 0})
                c["n"] += 1
                if r["ml"] is not None and r["ml"] > ML_HIGH_RISK:
                    c["ml_gt_0.85"] += 1
                if r["ml"] is not None and r["ml"] > ML_SUSPICIOUS:
                    c["ml_gt_0.6"] += 1
                if r["pipeline"]["level"] != "safe":
                    c["pipeline_not_safe"] += 1
                if r["heuristics"]["level"] != "safe":
                    c["heuristics_not_safe"] += 1
            out["by_category"] = dict(sorted(cats.items()))
    else:
        caught = lambda r, k: r[k]["level"] != "safe"  # noqa: E731
        out["caught"] = {
            "heuristics": sum(1 for r in rows if caught(r, "heuristics")),
            "pipeline": sum(1 for r in rows if caught(r, "pipeline")),
            "pipeline_dangerous": sum(1 for r in rows if r["pipeline"]["level"] == "dangerous"),
        }
        out["ml_gain"] = [
            {"host": r["host"], "ml": r["ml"], "pipeline": r["pipeline"]["level"], "listed": r.get("listed")}
            for r in rows if not caught(r, "heuristics") and caught(r, "pipeline")
        ]
        out["ml_loss"] = [
            {"host": r["host"], "ml": r["ml"], "heuristics": r["heuristics"]["level"]}
            for r in rows if caught(r, "heuristics") and not caught(r, "pipeline")
        ]
        out["ml_missed"] = [{"host": r["host"], "ml": r["ml"]} for r in rows if r["ml"] is not None and r["ml"] < ML_SAFE_OVERRIDE]
        if any("listed" in r for r in rows):
            listed = [r for r in rows if r.get("listed")]
            unlisted = [r for r in rows if not r.get("listed")]
            out["lists"] = {
                "listed": len(listed),
                "unlisted": len(unlisted),
                "unlisted_caught_by_heuristics": sum(1 for r in unlisted if caught(r, "heuristics")),
                "unlisted_caught_by_pipeline": sum(1 for r in unlisted if caught(r, "pipeline")),
                "unlisted_ml_gt_0.85": sum(1 for r in unlisted if r["ml"] is not None and r["ml"] > ML_HIGH_RISK),
                "unlisted_only_ml_saw": [r["host"] for r in unlisted if not caught(r, "heuristics") and caught(r, "pipeline")],
            }
    return out


def auc(pos: list[float], neg: list[float]) -> Optional[float]:
    """Rank AUC (Mann–Whitney), ties count half. No sklearn on purpose."""
    if not pos or not neg:
        return None
    wins = 0.0
    for p in pos:
        for q in neg:
            wins += 1.0 if p > q else 0.5 if p == q else 0.0
    return wins / (len(pos) * len(neg))


# ── report ───────────────────────────────────────────────────────────────

def _pct(k: int, n: int) -> str:
    return f"{k} ({100.0 * k / n:.1f}%)" if n else "—"


def render_md(report: dict) -> str:
    lines = ["| set | n | ML >0.6 | ML >0.85 | ML >0.9 | ML <0.1 | rules not safe | rules+ML not safe | ML cost / gain |",
             "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name, s in report["sets"].items():
        n = s["n"]
        if n == 0:
            continue
        ml = s["ml"]
        h, p = s["heuristics"], s["pipeline"]
        not_safe = lambda lv: lv["caution"] + lv["dangerous"]  # noqa: E731
        delta = len(s.get("ml_cost", s.get("ml_gain", []))) - len(s.get("ml_rescue", s.get("ml_loss", [])))
        lines.append(f"| {name} | {n} | {_pct(ml['gt_0.6'], n)} | {_pct(ml['gt_0.85'], n)} | {_pct(ml['gt_0.9'], n)} "
                     f"| {_pct(ml['lt_0.1'], n)} | {_pct(not_safe(h), n)} | {_pct(not_safe(p), n)} | {delta:+d} |")
    lines.append("")
    for name, s in report["sets"].items():
        if "by_category" in s:
            lines += [f"**{name} by category** (n / ML >0.85 / rules not safe / rules+ML not safe)", ""]
            lines += [f"- {c}: {v['n']} / {v['ml_gt_0.85']} / {v['heuristics_not_safe']} / {v['pipeline_not_safe']}"
                      for c, v in s["by_category"].items()]
            lines.append("")
        if s.get("lists"):
            L = s["lists"]
            lines += [f"**{name} vs the published blocklist**: listed {L['listed']}, unlisted {L['unlisted']}; of the unlisted, "
                      f"rules catch {L['unlisted_caught_by_heuristics']}, rules+ML {L['unlisted_caught_by_pipeline']}, "
                      f"ML >0.85 on {L['unlisted_ml_gt_0.85']}; only the model saw: {len(L['unlisted_only_ml_saw'])}", ""]
    if report.get("auc"):
        lines += ["**ML-alone AUC on held-out pairs**", ""]
        lines += [f"- {k}: {v:.4f}" if v is not None else f"- {k}: —" for k, v in report["auc"].items()]
        lines.append("")
    return "\n".join(lines)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--phishtank", type=Path, help="PhishTank online-valid.csv.gz")
    ap.add_argument("--tweetfeed", type=Path, help="TweetFeed week.csv")
    ap.add_argument("--tranco", type=Path, help="Tranco top-1m.csv.zip")
    ap.add_argument("--blocklist", type=Path, help="published blocklist artifact (v2 binary)")
    ap.add_argument("--days", type=int, default=7, help="PhishTank window in days (default 7)")
    ap.add_argument("--sample", type=int, default=1000, help="hosts per Tranco sample (default 1000)")
    ap.add_argument("--out", type=Path, help="write the full report (per-host rows included) as JSON")
    args = ap.parse_args(argv)

    now = datetime.now(timezone.utc)
    meta = json.loads((ROOT / "data" / "model_meta.json").read_text())
    report: dict = {
        "ts": now.isoformat(timespec="seconds"),
        "model": {k: meta.get(k) for k in ("n_features", "train_samples", "total_samples", "test_auc")},
        "thresholds": {"ml_suspicious": ML_SUSPICIOUS, "ml_high_risk": ML_HIGH_RISK, "ml_safe_override": ML_SAFE_OVERRIDE},
        "sources": {}, "sets": {}, "rows": {},
    }

    listed_fn: Optional[Callable[[str], bool]] = None
    if args.blocklist:
        from api.services.blocklist_artifact import artifact_covers

        hashes, info = blocklist_hashes(args.blocklist)
        report["sources"]["blocklist"] = info
        listed_fn = lambda h: artifact_covers(hashes, h)  # noqa: E731

    sets: list[tuple[str, str, list[dict]]] = []  # name, expected, rows-with-category

    def add(name: str, expected: str, hosts: list[str], categories: Optional[dict[str, str]] = None,
            with_lists: bool = False, info: Optional[dict] = None) -> None:
        rows = score_hosts(hosts, listed_fn if with_lists else None)
        if categories:
            for r in rows:
                r["category"] = categories.get(r["host"])
        sets.append((name, expected, rows))
        if info:
            report["sources"][name] = info

    legit = load_rule_hosts(ROOT / "tests" / "data" / "ru_heuristics_legit.txt")
    phish = load_rule_hosts(ROOT / "tests" / "data" / "ru_heuristics_phish.txt")
    bench = benchmark_legit.load_legit_sample()
    add("ru_heuristics_legit", "legit", [h.host for h in legit], {h.host: h.category for h in legit})
    add("ru_heuristics_phish", "phish", [h.host for h in phish], {h.host: h.category for h in phish})
    add("benchmark_legit_ru", "legit", [s.host for s in bench], {s.host: s.category for s in bench})
    if args.tranco:
        for name, (hosts, info) in tranco_samples(args.tranco, args.sample).items():
            add(name, "legit", hosts, info=info)
    if args.phishtank:
        hosts, info = phishtank_recent(args.phishtank, args.days, now)
        add("phishtank_recent", "phish", hosts, with_lists=True, info=info)
    if args.tweetfeed:
        hosts, info = tweetfeed_week(args.tweetfeed)
        add("tweetfeed_week", "phish", hosts, with_lists=True, info=info)

    for name, expected, rows in sets:
        report["sets"][name] = summarize(rows, expected)
        report["rows"][name] = rows

    def probs(name: str) -> list[float]:
        return [r["ml"] for r in report["rows"].get(name, []) if r["ml"] is not None]

    report["auc"] = {
        "ru_phish vs ru_legit": auc(probs("ru_heuristics_phish"), probs("ru_heuristics_legit")),
        "ru_phish vs benchmark_legit_ru": auc(probs("ru_heuristics_phish"), probs("benchmark_legit_ru")),
    }
    if "phishtank_recent" in report["rows"]:
        report["auc"]["phishtank vs benchmark_legit_ru"] = auc(probs("phishtank_recent"), probs("benchmark_legit_ru"))
        if "tranco_100k_1m" in report["rows"]:
            report["auc"]["phishtank vs tranco_100k_1m"] = auc(probs("phishtank_recent"), probs("tranco_100k_1m"))
            report["auc"]["phishtank vs tranco_100k_1m_ru"] = auc(probs("phishtank_recent"), probs("tranco_100k_1m_ru"))

    print(render_md(report))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, ensure_ascii=False, indent=1))
        print(f"written: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

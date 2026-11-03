"""Numbers for GET /api/v1/public/stats — measured, or null with a note.

The endpoint used to return hand-written figures: "0.08% false positives",
"16 threat sources", "42 signals", "100,000 domains protected". The 0.08%
was typed into a fixture on 2026-06-16, before launch; false positives have
never actually been measured (the weekly benchmark's legit batch came back
rate-limited, 60 of 60 — report 2026-09-25 #12). A journalist or Tele2 reads
this endpoint as fact.

Rule: every number here is either read from something that measured it
(the weekly benchmark, the model's held-out test, the live blocklist, the
brand list the watchtower actually loads) or it is null, and NOTES says why.
The response keeps every old key, so the landing and the typed client keep
working; only the values became honest.
"""

from __future__ import annotations

import functools
import json
import os
from typing import Optional

_ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
LATEST_BENCHMARK = os.path.join(_ROOT, "docs", "benchmarks", "latest.json")
MODEL_META = os.path.join(_ROOT, "data", "model_meta.json")

# The size floors of the benchmark's quality gate (landing/lib/benchmark.ts
# MIN_PHISHING_SAMPLE / MIN_PHISHING_CLASSIFIED): below them a rate is
# statistically meaningless and is not published. Since 2026-11 the landing
# quotes another figure (of the live links that got an answer, the share
# called dangerous; method_version 2 reports only — detectionFigures), while
# detection_rate here is still recall. TODO(founder): decide whether it follows.
MIN_BATCH = 100
MIN_CLASSIFIED = 50

# The benchmark's current method (scripts/benchmark_method.py METHOD_VERSION,
# since 2026-11-03). A report without method_version is method 1: its
# "unknown" mixes cautions, dead links and links without an answer, a dead
# name its blocklist still listed counted as caught, and one campaign could
# fill a quarter of its sample. The site quotes none of its numbers
# (landing/lib/benchmark.ts detectionFigures, falsePositiveRateIsPublishable),
# so this endpoint does not either: the 2026-11-01 report's recall (92.9) and
# "0% of 137" stayed here while every page said there was no trustworthy
# number yet. Not imported from scripts/: the API does not load them.
CURRENT_METHOD = 2

NOTES = {
    "total_domains_protected": (
        "Not a measurement, so not published. For the live size of the list "
        "phones block, see blocklist_entries."
    ),
    "threat_sources": (
        "Not published as a count: a hand-kept number drifted from the sources the "
        "analyzer really queries (some need keys that may not be configured)."
    ),
    "detection_signals": "Not a measurement, so not published.",
    "detection_rate": (
        "Fresh-URL recall from the weekly benchmark: of the phishing links Cleanway called "
        "dangerous or safe, the share called dangerous (a caution, a link whose domain no "
        "longer existed and a link without an answer are not counted). Only from a report "
        f"made by the current method (method_version {CURRENT_METHOD}, since 2026-11-03); null "
        f"for an older report, and until a run has at least {MIN_BATCH} phishing URLs with "
        f"{MIN_CLASSIFIED}+ classified. Not the figure cleanway.ai quotes, which is of the live "
        "links that got an answer, cautions included (cleanway.ai/transparency)."
    ),
    "false_positive_rate": (
        "Share of legitimate sites called dangerous among those Cleanway called dangerous or "
        "safe in the weekly benchmark (a caution on a real site is not counted; "
        "cleanway.ai/transparency shows it). Only from a report made by the current method "
        f"(method_version {CURRENT_METHOD}, since 2026-11-03); null for an older report, and until "
        f"a run has at least {MIN_BATCH} legitimate sites with {MIN_CLASSIFIED}+ classified."
    ),
    "ml_model_auc": "Held-out test AUC of the deployed model (data/model_meta.json).",
    "blocklist_entries": "Entries in the blocklist phones download right now; null if it is unavailable.",
    "brand_targets_monitored": (
        "Brands the typosquat rule compares names against: the global list's entries "
        "(data/typosquat_targets.json) plus the Russian brand groups (data/typosquat_targets_ru.json), "
        "each group counted once however many spellings it lists (sber, sberbank, сбербанк)."
    ),
}


_NOT_MEASURED_YET = " It has not been measured on a large enough sample yet."
_OLD_METHOD = (
    " The latest published report was made by the old method (before 2026-11-03); its "
    "numbers are not comparable with the current method's, so none is published."
)


def is_current_method(report: dict) -> bool:
    """True for a report made by the current method (CURRENT_METHOD or later)."""
    version = report.get("method_version")
    return isinstance(version, int) and not isinstance(version, bool) and version >= CURRENT_METHOD


def notes_for(report: dict) -> dict:
    """NOTES for this response: a rate that is null says why — an old-method
    report, or not measured yet — and stops saying so the moment the gate
    lets it through."""
    notes = dict(NOTES)
    old_method = bool(report) and not is_current_method(report)
    for key, measured in (
        ("detection_rate", measured_detection_rate(report)),
        ("false_positive_rate", measured_false_positive_rate(report)),
    ):
        if measured is None:
            notes[key] += _OLD_METHOD if old_method else _NOT_MEASURED_YET
    return notes


def _read_json(path: str) -> Optional[dict]:
    try:
        with open(path, "r") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


@functools.lru_cache(maxsize=1)
def model_auc() -> Optional[float]:
    """Live ML model AUC read from data/model_meta.json — never hardcoded, so
    it stays honest as the weekly retrain changes it."""
    meta = _read_json(MODEL_META) or {}
    try:
        return float(meta["test_auc"])
    except (KeyError, TypeError, ValueError):
        return None


@functools.lru_cache(maxsize=1)
def benchmark() -> dict:
    """The latest weekly benchmark (docs/benchmarks/latest.json), or {}.
    Cached: it only changes on redeploy / the weekly cron."""
    return _read_json(LATEST_BENCHMARK) or {}


def measured_detection_rate(report: Optional[dict] = None) -> Optional[float]:
    """Fresh-URL recall in percent, gated (see NOTES); null for an old-method report."""
    d = benchmark() if report is None else report
    if not is_current_method(d):
        return None
    cw = (d.get("phishing") or {}).get("cleanway") or {}
    classified = (cw.get("tp") or 0) + (cw.get("fn") or 0)
    recall = cw.get("recall")
    if recall is None or (d.get("n_phishing") or 0) < MIN_BATCH or classified < MIN_CLASSIFIED:
        return None
    return round(recall * 100, 1)


def measured_false_positive_rate(report: Optional[dict] = None) -> Optional[float]:
    """Share (0..1) of legitimate sites called dangerous, gated (see NOTES); null for an old-method report."""
    d = benchmark() if report is None else report
    if not is_current_method(d):
        return None
    cw = (d.get("safe") or {}).get("cleanway") or {}
    classified = (cw.get("fp") or 0) + (cw.get("tn") or 0)
    fpr = cw.get("fpr")
    if fpr is None or (d.get("n_safe") or 0) < MIN_BATCH or classified < MIN_CLASSIFIED:
        return None
    return round(fpr, 4)


def brand_targets_monitored() -> Optional[int]:
    """Global entries plus Russian brand groups — not TYPOSQUAT_TARGETS,
    which also holds every other spelling of a Russian brand (sber,
    sberbank, сбербанк; tinkoff, tbank, тинькофф) and would count one bank
    three times."""
    try:
        from api.services.scoring import GLOBAL_TYPOSQUAT_TARGETS, RU_BRAND_GROUPS
        return (len(GLOBAL_TYPOSQUAT_TARGETS) + len(RU_BRAND_GROUPS)) or None
    except Exception:
        return None


async def blocklist_entries() -> Optional[int]:
    """Entries in the published phone blocklist, from its Redis metadata."""
    try:
        from api.services.blocklist_artifact import REDIS_META_KEY
        from api.services.cache import get_redis
        r = await get_redis()
        count = await r.hget(REDIS_META_KEY, "count")
        return int(count) if count is not None else None
    except Exception:
        return None

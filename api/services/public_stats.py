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

# Same gate as the landing's live-recall.ts and the benchmark's quality gate:
# below this a rate is statistically meaningless and is not published.
MIN_BATCH = 100
MIN_CLASSIFIED = 50

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
        "Fresh-URL recall from the weekly benchmark; null until a run has at least "
        f"{MIN_BATCH} phishing URLs with {MIN_CLASSIFIED}+ classified."
    ),
    "false_positive_rate": (
        "Share of legitimate sites called dangerous in the weekly benchmark; null until "
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


def notes_for(report: dict) -> dict:
    """NOTES for this response: a rate that is null says it has not been
    measured yet — and stops saying so the moment the gate lets it through."""
    notes = dict(NOTES)
    for key, measured in (
        ("detection_rate", measured_detection_rate(report)),
        ("false_positive_rate", measured_false_positive_rate(report)),
    ):
        if measured is None:
            notes[key] += _NOT_MEASURED_YET
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
    """Fresh-URL recall in percent, gated (see NOTES)."""
    d = benchmark() if report is None else report
    cw = (d.get("phishing") or {}).get("cleanway") or {}
    classified = (cw.get("tp") or 0) + (cw.get("fn") or 0)
    recall = cw.get("recall")
    if recall is None or (d.get("n_phishing") or 0) < MIN_BATCH or classified < MIN_CLASSIFIED:
        return None
    return round(recall * 100, 1)


def measured_false_positive_rate(report: Optional[dict] = None) -> Optional[float]:
    """Share (0..1) of legitimate sites called dangerous, gated (see NOTES)."""
    d = benchmark() if report is None else report
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

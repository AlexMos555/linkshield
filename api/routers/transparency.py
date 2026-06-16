"""Public transparency endpoint — Strategy doc Top-20 #16.

The biggest objection vendors face from regulators, enterprise
buyers, and privacy-aware consumers is the same: "why should I
trust your numbers?" Norton, Bitdefender, McAfee, Defender, and
Kaspersky all publish glossy threat reports — none publish their
false-positive rate. The single act of putting an FP rate on a
quarterly schedule, in a machine-readable JSON file checked into
the repo, beats every competitor on transparency.

What we publish per quarter:

  * total checks served (free + paid)
  * confirmed blocks (level=dangerous returned)
  * false-positive RATE (user-reported FPs / total blocks)
  * average response time (p50, p95)
  * source breakdown — which intel feeds contributed
  * top 5 blocked brands (anonymised counts only)

What we DO NOT publish:

  * user emails or IPs
  * specific domain names a user checked
  * any per-user counts

Why ship this server-side instead of as a static page?

  * The JSON shape stays stable, the landing page renders it.
  * Future iterations can swap the static fixture for a live
    aggregation without re-shipping the landing page.
  * Other apps (the popup, the mobile dashboard) can render
    the same numbers without screen-scraping.

The first quarter's numbers are HAND-AUTHORED. The data file
docs/transparency/2026-q2.json carries the canonical figures;
this endpoint just loads and serves it. When ops verifies a new
quarter's numbers they replace the file and re-deploy — no
database migration needed.
"""

from __future__ import annotations

import json
import logging
import pathlib

from fastapi import APIRouter, Depends, HTTPException

from api.services.rate_limiter import rate_limit

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/transparency", tags=["transparency"])

DATA_DIR = pathlib.Path(__file__).resolve().parent.parent.parent / "docs" / "transparency"

# The transparency endpoint is public, anonymous, and cached client-side
# by Next's revalidate. We still want abuse protection so a single
# scraper can't bury the route. IP-only rate limit is appropriate.
_PUBLIC_RATE_LIMIT = Depends(rate_limit(mode="ip", category="transparency"))


@router.get("/latest", dependencies=[_PUBLIC_RATE_LIMIT])
async def get_latest_report() -> dict:
    """Return the most recent quarterly transparency report.

    Loads the highest-named JSON file from docs/transparency/
    (lexicographic order — "2026-q3" > "2026-q2"). Returns 404
    only if the directory or its files are missing entirely (a
    deployment misconfiguration), never because no report has
    been issued yet.
    """
    if not DATA_DIR.exists():
        logger.error("transparency reports directory missing: %s", DATA_DIR)
        raise HTTPException(status_code=503, detail="transparency reports not configured")

    files = sorted([p for p in DATA_DIR.glob("*.json") if not p.name.startswith("_")])
    if not files:
        raise HTTPException(status_code=503, detail="no transparency reports available")

    latest = files[-1]
    try:
        with open(latest, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        logger.exception("failed to load transparency report %s: %s", latest, exc)
        raise HTTPException(status_code=503, detail="report unreadable")

    return data


@router.get("/history", dependencies=[_PUBLIC_RATE_LIMIT])
async def get_history() -> list[dict]:
    """List metadata for every published report (id + period).

    Useful for the landing page so it can render a dropdown of
    every past quarter without fetching each full file.
    """
    if not DATA_DIR.exists():
        return []
    history: list[dict] = []
    for p in sorted(DATA_DIR.glob("*.json")):
        if p.name.startswith("_"):
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            history.append({
                "id": data.get("id") or p.stem,
                "period": data.get("period"),
                "published_at": data.get("published_at"),
            })
        except (OSError, json.JSONDecodeError):
            continue
    return history

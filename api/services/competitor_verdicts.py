"""Competitor verdict adapters — used by public /check to show
the side-by-side comparison ('Cleanway said X, Cloudflare 1.1.1.1
for Families said Y') on every scorecard.

This is the credibility moat for go-to-market: nobody else
publishes per-domain comparison vs the default DNS resolvers
that users already have. Showing it inline turns every
cleanway.ai/check/<domain> page into a shareable demo.

Privacy invariant: the same as the analyzer — we send the DOMAIN
to Cloudflare's family resolver, never a full URL. That's exactly
what a regular DNS lookup sends; no incremental data exposure.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

CLOUDFLARE_FAMILIES_URL = "https://family.cloudflare-dns.com/dns-query"
TIMEOUT_S = 3.0


@dataclass
class CompetitorVerdict:
    name: str            # 'cloudflare_families'
    verdict: str         # 'safe' | 'dangerous' | 'unknown'
    detail: str = ""     # human-readable status
    label: str = ""      # display name for UI


async def check_cloudflare_families(domain: str) -> CompetitorVerdict:
    """Query Cloudflare 1.1.1.1 for Families (security tier) for `domain`.

    Cloudflare's family resolver returns NXDOMAIN or sinks to
    0.0.0.0 / :: for known-malicious. We treat both as 'dangerous'.
    A clean resolved answer is 'safe'. Failure / timeout -> 'unknown'.

    All exceptions are caught — never breaks the calling endpoint.
    """
    out = CompetitorVerdict(
        name="cloudflare_families",
        verdict="unknown",
        label="Cloudflare 1.1.1.1 for Families",
    )
    if not domain:
        out.detail = "bad_domain"
        return out
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_S) as client:
            resp = await client.get(
                CLOUDFLARE_FAMILIES_URL,
                params={"name": domain, "type": "A"},
                headers={"Accept": "application/dns-json"},
            )
            if resp.status_code != 200:
                out.detail = f"status={resp.status_code}"
                return out
            data = resp.json()
            status = int(data.get("Status", 0))
            answers = data.get("Answer", []) or []
            sinkhole = {"0.0.0.0", "::"}
            ip_blocked = any(
                (a.get("data") or "").strip() in sinkhole
                for a in answers if a.get("type") in (1, 28)
            )
            if status == 3 or ip_blocked:
                out.verdict = "dangerous"
                out.detail = "blocked"
            elif status == 0 and answers:
                out.verdict = "safe"
                out.detail = "resolved"
            else:
                out.detail = f"status={status}"
    except Exception as exc:
        logger.debug("cloudflare_families check failed for %s: %s", domain, exc)
        out.detail = f"err:{type(exc).__name__}"
    return out


async def gather_competitor_verdicts(domain: str) -> list[dict]:
    """Run all competitor checks concurrently. Returns a list of
    dicts ready to JSON-serialise into the public-check response.

    Currently: Cloudflare 1.1.1.1 for Families. Future additions
    (Google Safe Browsing, Norton ConnectSafe etc.) plug in here
    with the same shape — UI doesn't need to change.

    Bounded by TIMEOUT_S — if a competitor doesn't answer in 3s,
    we move on with 'unknown' so the user's page renders quickly.
    """
    tasks = [check_cloudflare_families(domain)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    out: list[dict] = []
    for r in results:
        if isinstance(r, Exception):
            continue
        out.append({
            "name": r.name,
            "label": r.label,
            "verdict": r.verdict,
            "detail": r.detail,
        })
    return out

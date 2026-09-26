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
# The same operator's UNFILTERED resolver: the control that tells "Families
# blocked it" apart from "nobody can resolve it".
CLOUDFLARE_UNFILTERED_URL = "https://cloudflare-dns.com/dns-query"
TIMEOUT_S = 3.0
_NXDOMAIN = 3
_SINKHOLE = {"0.0.0.0", "::"}  # nosec B104 — sinkhole-IP set, not a bind address


@dataclass
class CompetitorVerdict:
    name: str            # 'cloudflare_families'
    verdict: str         # 'safe' | 'dangerous' | 'not_found' | 'unknown'
    detail: str = ""     # human-readable status
    label: str = ""      # display name for UI


async def _doh_get(client: httpx.AsyncClient, url: str, domain: str) -> httpx.Response:
    return await client.get(
        url,
        params={"name": domain, "type": "A"},
        headers={"Accept": "application/dns-json"},
    )


async def _nxdomain_everywhere(client: httpx.AsyncClient, domain: str) -> Optional[bool]:
    """Does the unfiltered resolver ALSO say NXDOMAIN? None if it did not answer."""
    try:
        resp = await _doh_get(client, CLOUDFLARE_UNFILTERED_URL, domain)
        if resp.status_code != 200:
            return None
        return int(resp.json().get("Status", 0)) == _NXDOMAIN
    except Exception:
        return None


async def check_cloudflare_families(
    domain: str, domain_exists: Optional[bool] = None,
) -> CompetitorVerdict:
    """Query Cloudflare 1.1.1.1 for Families (security tier) for `domain`.

    Families blocks by answering 0.0.0.0 / ::  → 'dangerous'. A clean
    resolved answer → 'safe'. NXDOMAIN is ambiguous, and treating it as a
    block was wrong: for a domain that simply does not exist every resolver
    says NXDOMAIN, and the comparison then showed "Cloudflare blocked it"
    for a typo — 8 of the 13 Cloudflare "hits" in the June benchmark were
    domains that did not exist (report 2026-09-25 #18). So NXDOMAIN is only
    a block when the domain exists; when it does not, the verdict is
    'not_found'. `domain_exists` is our own DNS answer when we have one;
    otherwise the unfiltered resolver is asked. Failure / timeout →
    'unknown'.

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
            resp = await _doh_get(client, CLOUDFLARE_FAMILIES_URL, domain)
            if resp.status_code != 200:
                out.detail = f"status={resp.status_code}"
                return out
            data = resp.json()
            status = int(data.get("Status", 0))
            answers = data.get("Answer", []) or []
            ip_blocked = any(
                (a.get("data") or "").strip() in _SINKHOLE
                for a in answers if a.get("type") in (1, 28)
            )
            if ip_blocked:
                out.verdict, out.detail = "dangerous", "blocked"
            elif status == _NXDOMAIN:
                exists = domain_exists
                if exists is None:
                    everywhere = await _nxdomain_everywhere(client, domain)
                    exists = None if everywhere is None else not everywhere
                if exists is False:
                    out.verdict, out.detail = "not_found", "nxdomain"
                elif exists is True:
                    out.verdict, out.detail = "dangerous", "blocked"
                else:
                    out.detail = "nxdomain_unverified"
            elif status == 0 and answers:
                out.verdict, out.detail = "safe", "resolved"
            else:
                out.detail = f"status={status}"
    except Exception as exc:
        logger.debug("cloudflare_families check failed for %s: %s", domain, exc)
        out.detail = f"err:{type(exc).__name__}"
    return out


async def gather_competitor_verdicts(
    domain: str, domain_exists: Optional[bool] = None,
) -> list[dict]:
    """Run all competitor checks concurrently. Returns a list of
    dicts ready to JSON-serialise into the public-check response.

    Currently: Cloudflare 1.1.1.1 for Families. Future additions
    (Google Safe Browsing, Norton ConnectSafe etc.) plug in here
    with the same shape — UI doesn't need to change.

    Bounded by TIMEOUT_S per query — if a competitor doesn't answer
    in 3s, we move on with 'unknown' so the user's page renders quickly.
    """
    tasks = [check_cloudflare_families(domain, domain_exists)]
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

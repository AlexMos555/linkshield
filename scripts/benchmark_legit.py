"""The benchmark's legitimate-site sample: real Russian sites OUTSIDE our allowlist.

data/benchmark_legit_ru.txt holds the list and how it was built. This module
reads it, re-checks it (--verify-legit-sample), draws the weekly sample, and
breaks Cleanway's answers on it down by reachability and category — so a
false-positive rate is published with what it is made of.

Only httpx and the standard library at import time: the weekly workflow runs
on a bare runner. The allowlist rule is imported from the API package when it
can be (it needs pydantic); without it the sample cannot be shown to sit
outside the allowlist, and the report says so.
"""
from __future__ import annotations

import asyncio
import logging
import random
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

import httpx

ROOT = Path(__file__).resolve().parent.parent
LEGIT_SAMPLE_PATH = ROOT / "data" / "benchmark_legit_ru.txt"
CATEGORIES = frozenset({
    "regional_gov", "city", "university", "rf", "bank", "business", "museum", "theatre",
})
REACHABILITY = ("reachable-abroad", "blocked-abroad")
MIN_SITES = 150
SAMPLE_SEED = 42
PUBLIC_DOH_JSON = "https://cloudflare-dns.com/dns-query"

log = logging.getLogger("eval_fresh_urls.legit")


@dataclass(frozen=True)
class LegitSite:
    host: str
    category: str
    reachability: str
    source: str
    name: str


def _host_problem(host: str) -> Optional[str]:
    if not host or host != host.strip().lower():
        return "host must be lowercase, without spaces"
    if not host.isascii():
        return "host must be punycode (xn--), not Unicode"
    if "://" in host or "/" in host:
        return "host only — no scheme, no path"
    if host.startswith("www."):
        return "no www. — the benchmark sends the bare host"
    if "." not in host:
        return "not a domain name"
    return None


def parse_legit_sample(text: str) -> list[LegitSite]:
    """Parse the list. Raises ValueError naming the line on anything malformed
    or repeated — a half-read sample would publish a rate about other sites."""
    sites: list[LegitSite] = []
    seen: set[str] = set()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = [f.strip() for f in line.split(" | ")]
        if len(fields) != 5 or not all(fields):
            raise ValueError(f"line {number}: expected 'host | category | reachability | source | name'")
        host, category, reachability, source, name = fields
        problem = _host_problem(host)
        if problem:
            raise ValueError(f"line {number}: {host}: {problem}")
        if category not in CATEGORIES:
            raise ValueError(f"line {number}: unknown category {category!r}")
        if reachability not in REACHABILITY:
            raise ValueError(f"line {number}: unknown reachability {reachability!r}")
        if host in seen:
            raise ValueError(f"line {number}: {host} listed twice")
        seen.add(host)
        sites.append(LegitSite(host, category, reachability, source, name))
    return sites


def load_legit_sample(path: Path = LEGIT_SAMPLE_PATH) -> list[LegitSite]:
    return parse_legit_sample(path.read_text(encoding="utf-8"))


def allowlist_rule() -> Optional[Callable[[str], bool]]:
    """The server's own instant-safe rule (api.services.scoring.
    is_trusted_top_domain), or None when the API package cannot be imported
    in this environment."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    try:
        from api.services.scoring import is_trusted_top_domain
    except Exception as exc:  # noqa: BLE001 — reported, and it changes the report
        log.warning("allowlist rule unavailable (%s: %s) — the legit sample cannot be shown "
                    "to sit outside the allowlist", type(exc).__name__, exc)
        return None
    return is_trusted_top_domain


def select_legit_sample(
    sites: Iterable[LegitSite],
    limit: int,
    is_trusted: Optional[Callable[[str], bool]],
) -> list[LegitSite]:
    """A fixed-seed random sample of `limit` sites, never one the server would
    auto-trust (if a list refresh put one in the top 100k, it is dropped here,
    loudly, instead of quietly scoring a free 'safe')."""
    pool = list(sites)
    if is_trusted is not None:
        trusted = [s.host for s in pool if is_trusted(s.host)]
        if trusted:
            log.warning("dropping %d listed site(s) the server now auto-trusts: %s",
                        len(trusted), ", ".join(trusted[:10]))
        pool = [s for s in pool if not is_trusted(s.host)]
    random.Random(SAMPLE_SEED).shuffle(pool)
    return pool[:max(0, limit)]


def cleanway_outcome(verdict: str, detail: str) -> str:
    """One bucket per Cleanway answer: safe / caution / dangerous / not_found /
    no_answer (rate-limited, HTTP error, timeout)."""
    if verdict in ("safe", "dangerous"):
        return verdict
    if detail in ("caution", "not_found"):
        return detail
    return "no_answer"


OUTCOMES = ("safe", "caution", "dangerous", "not_found", "no_answer")


def _counts(outcomes: Iterable[str]) -> dict:
    c = Counter(outcomes)
    return {k: c.get(k, 0) for k in OUTCOMES}


def legit_breakdown(outcomes: list[str], sites: list[LegitSite]) -> dict:
    """Cleanway's answers on the legit sample, overall and by reachability and
    category. `outcomes[i]` is the answer for `sites[i]`."""
    if len(outcomes) != len(sites):
        raise ValueError("one outcome per site")
    pairs = list(zip(sites, outcomes))
    return {
        "overall": _counts(outcomes),
        "by_reachability": {
            r: _counts(o for s, o in pairs if s.reachability == r) for r in REACHABILITY
        },
        "by_category": {
            c: _counts(o for s, o in pairs if s.category == c)
            for c in sorted({s.category for s in sites})
        },
    }


def render_breakdown_md(breakdown: dict) -> list[str]:
    lines = [
        "## Cleanway on the legitimate sample",
        "",
        "Every site here is real and outside the list our server trusts without "
        "analysis. 'dangerous' is a false positive; 'caution' is not counted in "
        "the FPR above but is shown, because a warning on a bank's or a "
        "government's own site is a harm too.",
        "",
        "| Slice | safe | caution | dangerous | not found | no answer |",
        "|---|---|---|---|---|---|",
    ]

    def row(label: str, c: dict) -> str:
        return (f"| {label} | {c['safe']} | {c['caution']} | {c['dangerous']} "
                f"| {c['not_found']} | {c['no_answer']} |")

    lines.append(row("all", breakdown["overall"]))
    for reach, c in breakdown["by_reachability"].items():
        lines.append(row(reach, c))
    for cat, c in breakdown["by_category"].items():
        lines.append(row(f"category: {cat}", c))
    lines.append("")
    return lines


async def _resolves(client: httpx.AsyncClient, host: str) -> bool:
    for _ in range(2):
        try:
            r = await client.get(PUBLIC_DOH_JSON, params={"name": host, "type": "A"},
                                 headers={"Accept": "application/dns-json"}, timeout=8.0)
            data = r.json()
            answers = [a for a in data.get("Answer") or [] if a.get("type") == 1]
            return data.get("Status") == 0 and bool(answers)
        except Exception:  # noqa: BLE001 — retried once, then reported
            await asyncio.sleep(1.0)
    return False


async def verify_legit_sample(path: Path = LEGIT_SAMPLE_PATH) -> int:
    """Exit status for --verify-legit-sample: 0 when the list parses, holds at
    least MIN_SITES sites, none of them auto-trusted, and every host resolves."""
    problems: list[str] = []
    try:
        sites = load_legit_sample(path)
    except (OSError, ValueError) as exc:
        print(f"LEGIT SAMPLE BROKEN: {exc}")
        return 1
    if len(sites) < MIN_SITES:
        problems.append(f"only {len(sites)} sites (need {MIN_SITES})")
    rule = allowlist_rule()
    if rule is None:
        problems.append("cannot import api.services.scoring — install pydantic to check the allowlist")
    else:
        problems += [f"{s.host}: auto-trusted by the server (Tranco top 100k)" for s in sites if rule(s.host)]
    sem = asyncio.Semaphore(16)
    async with httpx.AsyncClient() as client:
        async def check(site: LegitSite) -> Optional[str]:
            async with sem:
                return None if await _resolves(client, site.host) else f"{site.host}: does not resolve"
        problems += [p for p in await asyncio.gather(*[check(s) for s in sites]) if p]
    for p in problems:
        print(p)
    print(f"legit sample: {len(sites)} sites, {len(problems)} problem(s)")
    return 1 if problems else 0

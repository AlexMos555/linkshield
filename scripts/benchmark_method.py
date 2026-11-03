"""How the fresh-URL benchmark (eval_fresh_urls.py) draws its phishing sample
and counts every answer: method_version 2, since 2026-11-03.

Until then (method_version 1, every report before 2026-11-03):
  * the sample was the first rows of PhishTank's online-valid dump (the
    first sample x 3), with repeated hostnames dropped, while the report said
    "deduplicated by registrable domain". One campaign's burst filled a
    quarter of a week (allegro 50 of 200 rows on 2026-11-01, bradesco 39 on
    2026-10-25), and each random subdomain of one name counted as a phishing
    site of its own;
  * a "dangerous" for a name that does not resolve counted as a catch when it
    came from Cleanway's blocklist or Cloudflare's 0.0.0.0 sinkhole (both
    answer before any existence check), but not when Cleanway itself found
    the name dead;
  * the summary had one "unknown" for a caution, a dead name and no answer.

Now:
  SAMPLE   a fixed-seed random draw over the whole dump (sample_phishing). Each
           host is kept once, because Cleanway checks a domain, not a URL. A
           site keeps at most MAX_PER_SITE hosts. A site is the registrable
           domain by the server's own Public Suffix List code, and a hosting
           platform's tenant is a site of its own, as the server reads it
           (site_rule). So two pages on vercel.app are two customers, and two
           random subdomains of one .cfd name are one attacker.
  EXISTS   one fact per row, the same for every resolver (row_existence).
           "nxdomain" when some answer says the name does not exist and none
           says it does. The witnesses are the benchmark's own probe of
           Cloudflare's unfiltered resolver, Cleanway's `exists`, and Families'
           control query. "resolves" when any witness resolved it, else
           "unknown".
  OUTCOME  per resolver and row (outcome): not_found for an "nxdomain" row,
           whatever the resolver said; its raw answer stays in the JSON.
           Otherwise dangerous or safe as answered, caution for Cleanway's
           middle band, and no_answer for the rest (rate-limited, not indexed,
           error).

The summary (summarize) keeps the fields landing/lib/benchmark.ts reads, with
their old meaning: recall = tp / (tp + fn), and caution, not_found and no_answer
all count as "unknown". It adds the counts and two rates with Wilson 95%
intervals: dangerous / all rows, and dangerous / resolving rows. "resolving"
is every row not shown dead; a row the witnesses could not settle counts as
resolving, which can only lower that rate.

Only the standard library and benchmark_legit (httpx) at import time: the
weekly workflow runs on a bare runner. site_rule() imports the API package
when it is called, as benchmark_legit.allowlist_rule does.
"""
from __future__ import annotations

import logging
import math
import random
import sys
from collections import Counter
from pathlib import Path
from typing import Callable, Iterable, Optional

from benchmark_legit import OUTCOMES

log = logging.getLogger("eval_fresh_urls.method")

ROOT = Path(__file__).resolve().parent.parent

METHOD_VERSION = 2
# One seed every week: the dump changes, the draw over it is reproducible.
PHISHING_SAMPLE_SEED = 42
MAX_PER_SITE = 2

RESOLVES, NXDOMAIN, UNKNOWN = "resolves", "nxdomain", "unknown"
EXISTENCE = (RESOLVES, NXDOMAIN, UNKNOWN)

# z for a two-sided 95% interval.
_Z95 = 1.959963984540054


# ── Where one site ends ──

def site_rule() -> tuple[Callable[[str], str], str]:
    """(site_of, its description): the registrable domain by
    api/services/public_suffix.py, a hosting platform's tenant its own site
    (scoring._platform_tenant_site: the customer's own name under a shared
    suffix, PSL-derived ones included). The scorer needs pydantic; without it,
    the plain registrable domain, and the description says so."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    try:
        from api.services.scoring import _platform_tenant_site, registrable_domain
    except Exception as exc:  # noqa: BLE001 — reported, and it changes the report
        from api.services.public_suffix import registrable_domain as psl_registrable

        log.warning("tenant rule unavailable (%s: %s): one site per registrable domain, "
                    "hosting tenants not split", type(exc).__name__, exc)
        return psl_registrable, ("registrable domain by api/services/public_suffix.py; hosting tenants "
                                 "not split, because api.services.scoring did not import")

    def site_of(host: str) -> str:
        return _platform_tenant_site(host) or registrable_domain(host)

    return site_of, ("registrable domain by api/services/public_suffix.py; a hosting platform's tenant "
                     "is a site of its own (scoring._platform_tenant_site)")


# ── The phishing sample ──

def sample_phishing(
    urls: list[str],
    limit: int,
    *,
    seed: int,
    host_of: Callable[[str], str],
    site_of: Callable[[str], str],
    max_per_site: int = MAX_PER_SITE,
) -> tuple[list[int], dict]:
    """(indices into `urls`, in the dump's order; what the draw saw).

    The rows are shuffled with `seed` and walked in that order. A row is kept
    when its host is new and its site has fewer than `max_per_site` hosts.
    The walk stops at `limit` rows."""
    hosts = [host_of(u) for u in urls]
    sites: dict[str, str] = {h: site_of(h) for h in set(hosts) if h}
    order = list(range(len(urls)))
    random.Random(seed).shuffle(order)
    seen: set[str] = set()
    per_site: Counter = Counter()
    picked: list[int] = []
    for i in order:
        if len(picked) >= limit:
            break
        host = hosts[i]
        if not host or host in seen or per_site[sites[host]] >= max_per_site:
            continue
        seen.add(host)
        per_site[sites[host]] += 1
        picked.append(i)
    picked.sort()
    return picked, {
        "seed": seed,
        "max_per_site": max_per_site,
        "pool_rows": len(urls),
        "pool_hosts": len(sites),
        "pool_sites": len(set(sites.values())),
        "n": len(picked),
        "sites": len(per_site),
    }


def submitted_span(times: Iterable[Optional[str]]) -> Optional[dict]:
    """Oldest, median and newest submission time of the sampled rows (ISO
    strings sort as times), or None when the dump gave none."""
    ordered = sorted(t for t in times if t)
    if not ordered:
        return None
    return {"oldest": ordered[0], "median": ordered[(len(ordered) - 1) // 2], "newest": ordered[-1]}


# ── One existence fact per row ──

def row_existence(answers: Iterable[Optional[bool]]) -> str:
    """'resolves' when any witness resolved the name, 'nxdomain' when one
    found it missing and none resolved it, else 'unknown'."""
    seen = {a for a in answers if a is not None}
    if True in seen:
        return RESOLVES
    if False in seen:
        return NXDOMAIN
    return UNKNOWN


def existence_counts(rows: Iterable[str]) -> dict:
    c = Counter(rows)
    return {k: c.get(k, 0) for k in EXISTENCE}


def outcome(verdict: str, level: Optional[str], existence: str) -> str:
    """One bucket of benchmark_legit.OUTCOMES for one resolver's answer on one
    row. `level` is the resolver's own band (Cleanway's level), if it has
    one."""
    if existence == NXDOMAIN:
        return "not_found"
    if verdict in ("dangerous", "safe"):
        return verdict
    if level == "caution":
        return "caution"
    return "no_answer"


# ── The summary ──

def wilson95(k: int, n: int) -> Optional[list[float]]:
    """The Wilson score interval (95%) for k successes in n, rounded to 4
    places; None for n = 0. At n ≈ 200 a rate is only good to about ±6 points."""
    if n <= 0:
        return None
    p = k / n
    denom = 1 + _Z95 ** 2 / n
    centre = (p + _Z95 ** 2 / (2 * n)) / denom
    half = _Z95 * math.sqrt(p * (1 - p) / n + _Z95 ** 2 / (4 * n * n)) / denom
    return [round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)]


def _ratio(k: int, n: int) -> Optional[float]:
    return k / n if n > 0 else None


def summarize(outcomes: list[str], expected: str) -> dict:
    """The summary of one resolver on one batch; `expected` is 'dangerous'
    (phishing) or 'safe' (legit)."""
    c = Counter(outcomes)
    counts = {k: c.get(k, 0) for k in OUTCOMES}
    n = len(outcomes)
    hit, passed = counts["dangerous"], counts["safe"]
    tp, fn, fp, tn = (hit, passed, 0, 0) if expected == "dangerous" else (0, 0, hit, passed)
    recall, fpr, precision = _ratio(tp, tp + fn), _ratio(fp, fp + tn), _ratio(tp, tp + fp)
    f1 = (2 * precision * recall / (precision + recall)
          if recall is not None and precision is not None and precision + recall > 0 else None)
    resolving = n - counts["not_found"]
    return {
        # landing/lib/benchmark.ts ResolverStats, meaning unchanged
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "unknown": n - tp - fn - fp - tn,
        "recall": recall, "fpr": fpr, "precision": precision, "f1": f1,
        # method_version 2
        "n": n, **counts, "resolving": resolving,
        "dangerous_rate_all": _ratio(hit, n),
        "dangerous_rate_resolving": _ratio(hit, resolving),
        "recall_wilson95": wilson95(tp, tp + fn),
        "fpr_wilson95": wilson95(fp, fp + tn),
        "dangerous_rate_all_wilson95": wilson95(hit, n),
        "dangerous_rate_resolving_wilson95": wilson95(hit, resolving),
    }


def _pct(x: Optional[float]) -> str:
    return f"{x * 100:.1f}%" if x is not None else "—"


def _interval(ci: Optional[list[float]]) -> str:
    return f"{ci[0] * 100:.1f}–{ci[1] * 100:.1f}%" if ci else "—"


def render_outcomes_md(report: dict) -> list[str]:
    """Every answer by kind, per batch and resolver. Empty for a report
    written before these counts existed."""
    rows = [(label, name, m) for label, batch in (("phishing", "phishing"), ("legit", "safe"))
            for name, m in (report.get(batch) or {}).items() if "not_found" in m]
    if not rows:
        return []
    lines = [
        "## Every answer, by kind",
        "",
        "One row per URL, counted the same way for every resolver: a name that "
        "does not resolve is 'not found' for all of them (see Methodology). "
        "'dangerous / resolving' leaves those rows out; on the legit batch it is "
        "the false-alarm rate.",
        "",
        "| Batch | Resolver | dangerous | caution | safe | not found | no answer "
        "| dangerous / all | dangerous / resolving (95% CI) |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for label, name, m in rows:
        lines.append(
            f"| {label} | {name} | {m['dangerous']} | {m['caution']} | {m['safe']} "
            f"| {m['not_found']} | {m['no_answer']} | {_pct(m['dangerous_rate_all'])} "
            f"| {_pct(m['dangerous_rate_resolving'])} ({_interval(m['dangerous_rate_resolving_wilson95'])}) |"
        )
    lines.append("")
    return lines


def methodology_md(report: dict) -> list[str]:
    """The Methodology bullets about the sample and the count."""
    sampling = report.get("sampling") or {}
    if not sampling:
        return []
    span = sampling.get("submitted")
    submitted = (f" Submitted to PhishTank {span['oldest'][:10]} – {span['newest'][:10]} "
                 f"(median {span['median'][:10]})." if span else "")
    return [
        f"- The phishing sample is a random sample (seed={sampling['seed']}) of the whole dump, not its "
        f"first rows: each host once, at most {sampling['max_per_site']} hosts per site. A site is the "
        f"{sampling['site_rule']}. {sampling['n']} rows from {sampling['sites']} sites, drawn from "
        f"{sampling['pool_rows']} rows on {sampling['pool_sites']} sites.{submitted}",
        "- A name that does not resolve is 'not found' for every resolver, whatever it answered: "
        "Cleanway's blocklist, Cloudflare's 0.0.0.0 and PhishTank's listing included. 'Does not resolve' "
        "means some witness found it missing (NXDOMAIN on Cloudflare's unfiltered resolver, asked once "
        "per URL, or Cleanway's own `exists: false`) and none resolved it. The raw JSON keeps every answer "
        "and how it was counted.",
        f"- method_version {report.get('method_version', METHOD_VERSION)}. Runs before 2026-11-03 "
        "(method_version 1) took the dump's first rows, dropped repeated hostnames only, and counted a "
        "dead name's blocklist hit or 0.0.0.0 as a catch. They are not comparable with this one.",
    ]

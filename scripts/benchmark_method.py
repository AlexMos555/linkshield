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
  WINDOW   the pool is the dump's rows submitted in the WINDOW_DAYS before its
           newest row (recent_window). The dump is newest-first and goes back
           to 2012: a draw over all of it measures links years old. A row
           dated after the run's clock is left out, counted and logged: no row
           can have been submitted after the download, and as the newest it
           would move the window past every real row.
  SAMPLE   a fixed-seed draw over the pool's SITES (sample_phishing): the sites
           in a random order, from each up to MAX_PER_SITE of its hosts, each
           host once (Cleanway checks a domain, not a URL), at its first row in
           the dump. Every site has the same chance, however many rows or hosts
           it has. A site is the registrable domain by the server's own Public
           Suffix List code, and a hosting platform's tenant is a site of its
           own, as the server reads it (site_rule). So two pages on vercel.app
           are two customers, and two random subdomains of one .cfd name are
           one attacker.
  EXISTS   one fact per row, the same for every resolver (row_existence). The
           benchmark's own probe decides: one A query per URL to Cloudflare's
           unfiltered resolver at the start of the run, and an AAAA query
           when no A address is public (no A record at all included); the A
           and AAAA addresses are judged together. NXDOMAIN: "nxdomain". An
           answer with no public address by the server's own rule
           (no_public_address: neither an A nor an AAAA record, or only
           0.0.0.0 and private ranges — a takedown, a sinkhole, a Cloudflare
           tunnel's private IPv6, nothing a user can reach): "non_public". Any
           other answer: "resolves". Only when the probe cannot tell
           (SERVFAIL, a timeout, an HTTP error, its AAAA question failing) do
           the resolvers' answers decide: any resolved name "resolves", else
           an NXDOMAIN from Families' control query or Cleanway's
           `exists: false` "nxdomain". Cleanway's `exists: false` is weaker
           evidence: its SSRF guard gives the same answer for a name that
           resolves into a blocked or private network, and its answers may
           come from its public cache.
  OUTCOME  per resolver and row (outcome): not_found for an "nxdomain" or a
           "non_public" row, whatever the resolver said; its raw answer stays
           in the JSON.
           Otherwise dangerous or safe as answered, caution for Cleanway's
           middle band (its not-found answer on a row the probe resolved
           included: a user sees a caution), and no_answer for the rest
           (rate-limited, not indexed, error, timeout).

The summary (summarize) keeps the fields landing/lib/benchmark.ts reads, with
their old meaning: recall = tp / (tp + fn), and caution, not_found and no_answer
all count as "unknown". It adds the counts and two rates with Wilson 95%
intervals, both over the answered rows (n - not_found - no_answer): dangerous,
and warned = dangerous or caution. A rate never counts a row nobody judged.

Only the standard library and benchmark_legit (httpx) at import time: the
weekly workflow runs on a bare runner. site_rule() imports the API package
when it is called, as benchmark_legit.allowlist_rule does.
"""
from __future__ import annotations

import ipaddress
import logging
import math
import random
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable, Optional

from benchmark_legit import OUTCOMES

log = logging.getLogger("eval_fresh_urls.method")

ROOT = Path(__file__).resolve().parent.parent

METHOD_VERSION = 2
# One seed every week: the dump changes, the draw over it is reproducible.
PHISHING_SAMPLE_SEED = 42
MAX_PER_SITE = 2
# The pool: the rows submitted in this many days before the dump's newest row.
# On the 2026-11-03 dump that is 678 rows on 544 sites, enough for 200.
WINDOW_DAYS = 7

RESOLVES, NXDOMAIN, NON_PUBLIC, UNKNOWN = "resolves", "nxdomain", "non_public", "unknown"
EXISTENCE = (RESOLVES, NXDOMAIN, NON_PUBLIC, UNKNOWN)
# Existence facts whose row nobody can reach: not found for every resolver.
NOT_LIVE = (NXDOMAIN, NON_PUBLIC)

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

def _parse_time(value: Optional[str]) -> Optional[datetime]:
    try:
        t = datetime.fromisoformat((value or "").strip())
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def recent_window(
    submitted: Optional[list[Optional[str]]], days: int, now: Optional[datetime] = None,
) -> tuple[list[int], dict]:
    """(indices of the rows submitted in the `days` before the newest row, the
    window). A row without a readable time is never in it, nor one dated
    after `now`, the run's clock (a time without a zone is UTC): no row can
    have been submitted after the download, and as the newest it would move
    the window past every real row (one dated 2099 left a pool of one). Those
    are counted (`future_rows`) and logged, and `clock` says which clock.
    days = 0: every row, no window, no clock. No usable time at all: no row —
    the run then stops rather than draw links of unknown age."""
    times = [_parse_time(t) for t in submitted or []]
    window = {"days": days, "start": None, "end": None, "undated_rows": sum(1 for t in times if t is None),
              "future_rows": 0, "clock": None}
    if days <= 0:
        return list(range(len(times))), {**window, "undated_rows": 0}
    if now is not None:
        now = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
        future = [i for i, t in enumerate(times) if t is not None and t > now]
        window.update(future_rows=len(future), clock=now.isoformat())
        if future:
            shown = ", ".join(f"row {i} at {submitted[i]}" for i in future[:5])
            log.warning("PhishTank: %d row%s dated after the run's clock %s, left out of the window "
                        "(no row can have been submitted after the download): %s%s",
                        len(future), "" if len(future) == 1 else "s", now.isoformat(), shown,
                        " …" if len(future) > 5 else "")
    dated = [t for t in times if t is not None and (now is None or t <= now)]
    if not dated:
        return [], window
    end = max(dated)
    start = end - timedelta(days=days)
    window.update(start=start.isoformat(), end=end.isoformat())
    return [i for i, t in enumerate(times) if t is not None and start <= t <= end], window


def sample_phishing(
    urls: list[str],
    limit: int,
    *,
    seed: int,
    host_of: Callable[[str], str],
    site_of: Callable[[str], str],
    max_per_site: int = MAX_PER_SITE,
    pool: Optional[Iterable[int]] = None,
) -> tuple[list[int], dict]:
    """(indices into `urls`, in the dump's order; what the draw saw).

    `pool` is the rows to draw from (recent_window), every row by default.
    Each host stands for its first row in the pool. The sites are shuffled
    with `seed`; from each in turn, up to `max_per_site` of its hosts, drawn
    with the same generator, until `limit` rows."""
    first_row: dict[str, int] = {}
    rows = list(range(len(urls))) if pool is None else list(pool)
    for i in rows:
        host = host_of(urls[i])
        if host and host not in first_row:
            first_row[host] = i
    hosts_of: dict[str, list[str]] = {}
    for host in sorted(first_row):
        hosts_of.setdefault(site_of(host), []).append(host)
    rng = random.Random(seed)
    order = sorted(hosts_of)
    rng.shuffle(order)
    picked: list[int] = []
    sites = 0
    for site in order:
        if len(picked) >= limit:
            break
        hosts = hosts_of[site]
        take = rng.sample(hosts, min(max_per_site, len(hosts), limit - len(picked)))
        picked += [first_row[h] for h in take]
        sites += 1
    picked.sort()
    return picked, {
        "seed": seed,
        "max_per_site": max_per_site,
        "pool_rows": len(rows),
        "pool_hosts": len(first_row),
        "pool_sites": len(hosts_of),
        "n": len(picked),
        "sites": sites,
    }


def submitted_span(times: Iterable[Optional[str]]) -> Optional[dict]:
    """Oldest, median and newest submission time of the sampled rows (ISO
    strings sort as times), or None when the dump gave none."""
    ordered = sorted(t for t in times if t)
    if not ordered:
        return None
    return {"oldest": ordered[0], "median": ordered[(len(ordered) - 1) // 2], "newest": ordered[-1]}


# ── One existence fact per row ──

def _public_address_rule() -> Callable[[ipaddress.IPv4Address | ipaddress.IPv6Address], bool]:
    """The server's own rule, api/services/domain_validator.is_public_address:
    the addresses its SSRF guard lets it connect to. That module needs only
    the standard library, so the bare weekly runner imports it too."""
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from api.services.domain_validator import is_public_address

    return is_public_address


def only_non_public(addresses: Optional[Iterable[str]]) -> bool:
    """True when the name has an address and none is public (_public_address_rule):
    0.0.0.0, a private, loopback or link-local range, an IPv6 form of one — a
    takedown or a sinkhole, nothing a user's browser can reach. No address at
    all is not enough (the name may only carry other records), and a string
    that is not an address proves nothing."""
    listed = [a.strip().strip("[]") for a in addresses or []]
    if not listed:
        return False
    is_public = _public_address_rule()
    for text in listed:
        try:
            address = ipaddress.ip_address(text)
        except ValueError:
            return False
        if is_public(address):
            return False
    return True


def no_public_address(addresses: Optional[Iterable[str]]) -> bool:
    """The existence probe's rule for a name that answered: True when its
    addresses (A and AAAA together) hold no public one — none at all, or
    only_non_public. A name with neither an A nor an AAAA record has nothing
    a browser can connect to, and on 2026-11-03 four seed-42 names led only
    to a Cloudflare tunnel's private fd10:aec2:5dae:: (third review of #395).
    None means nobody recorded the addresses: not this rule's call."""
    if addresses is None:
        return False
    listed = list(addresses)
    return not listed or only_non_public(listed)


def row_existence(
    probe: Optional[bool], others: Iterable[Optional[bool]] = (), addresses: Optional[Iterable[str]] = None,
) -> str:
    """The row's existence. `probe` (the benchmark's own lookup) decides when
    it can tell, with the `addresses` it got (A and AAAA): 'non_public' when
    none is public, none at all included (no_public_address), else
    'resolves'; 'nxdomain' when it found the name missing. Else the
    resolvers' answers (`others`): 'resolves' when any resolved the name,
    'nxdomain' when one found it missing, else 'unknown'."""
    if probe is not None:
        if not probe:
            return NXDOMAIN
        return NON_PUBLIC if no_public_address(addresses) else RESOLVES
    seen = {a for a in others if a is not None}
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
    if existence in NOT_LIVE:
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
    answered = resolving - counts["no_answer"]
    warned = hit + counts["caution"]
    return {
        # landing/lib/benchmark.ts ResolverStats, meaning unchanged
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "unknown": n - tp - fn - fp - tn,
        "recall": recall, "fpr": fpr, "precision": precision, "f1": f1,
        # method_version 2
        "n": n, **counts, "resolving": resolving, "answered": answered,
        "dangerous_rate_answered": _ratio(hit, answered),
        "warned_rate_answered": _ratio(warned, answered),
        "recall_wilson95": wilson95(tp, tp + fn),
        "fpr_wilson95": wilson95(fp, fp + tn),
        "dangerous_rate_answered_wilson95": wilson95(hit, answered),
        "warned_rate_answered_wilson95": wilson95(warned, answered),
    }


def _pct(x: Optional[float]) -> str:
    return f"{x * 100:.1f}%" if x is not None else "—"


def _interval(ci: Optional[list[float]]) -> str:
    return f"{ci[0] * 100:.1f}–{ci[1] * 100:.1f}%" if ci else "—"


def render_outcomes_md(report: dict) -> list[str]:
    """Every answer by kind, per batch and resolver. Empty for a report
    written before these counts existed."""
    rows = [(label, name, m) for label, batch in (("phishing", "phishing"), ("legit", "safe"))
            for name, m in (report.get(batch) or {}).items() if "answered" in m]
    if not rows:
        return []
    lines = [
        "## Every answer, by kind",
        "",
        "One row per URL, counted the same way for every resolver: a name that "
        "does not exist, or has no public address (none, or only non-public ones), is 'not found' for "
        "all of them (see Methodology). 'answered' = n − not found − no answer: the "
        "live rows that got an answer. 'warned' = dangerous or caution (only Cleanway has a "
        "caution band). Both rates are over the answered rows, so a resolver that "
        "was rate-limited is not shown as missing links it never judged. On the "
        "legit batch, 'dangerous / answered' is how often a real site was called "
        "dangerous, and 'warned / answered' how often its users saw any warning.",
        "",
        "| Batch | Resolver | n | dangerous | caution | safe | not found | no answer | answered "
        "| dangerous / answered (95% CI) | warned / answered (95% CI) |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for label, name, m in rows:
        lines.append(
            f"| {label} | {name} | {m['n']} | {m['dangerous']} | {m['caution']} | {m['safe']} "
            f"| {m['not_found']} | {m['no_answer']} | {m['answered']} "
            f"| {_pct(m['dangerous_rate_answered'])} ({_interval(m['dangerous_rate_answered_wilson95'])}) "
            f"| {_pct(m['warned_rate_answered'])} ({_interval(m['warned_rate_answered_wilson95'])}) |"
        )
    lines.append("")
    return lines


def _minute(iso: str) -> str:
    return iso[:16].replace("T", " ")


def methodology_md(report: dict) -> list[str]:
    """The Methodology bullets about the sample and the count."""
    sampling = report.get("sampling") or {}
    if not sampling:
        return []
    window = sampling.get("window") or {}
    if window.get("start"):
        pool = (f"the {sampling['pool_rows']} rows submitted {_minute(window['start'])} – "
                f"{_minute(window['end'])} UTC, the {window['days']} days before the dump's newest row")
    else:
        pool = f"all {sampling['pool_rows']} rows of the dump, links of any age"
    span = sampling.get("submitted")
    submitted = (f" They were submitted to PhishTank {span['oldest'][:10]} – {span['newest'][:10]} "
                 f"(median {span['median'][:10]})." if span else "")
    future = window.get("future_rows") or 0
    if future:
        submitted += (f" {future} row{'' if future == 1 else 's'} dated after the run's clock "
                      f"({_minute(window['clock'])} UTC) {'was' if future == 1 else 'were'} left out: "
                      "no row can have been submitted after the download.")
    return [
        f"- The phishing sample is a random sample (seed={sampling['seed']}) of {pool} "
        f"({sampling['pool_sites']} sites): the sites in a random order, from each up to "
        f"{sampling['max_per_site']} of its hosts, each host once, so every site has the same chance "
        f"however many rows it has. A site is the {sampling['site_rule']}. {sampling['n']} rows from "
        f"{sampling['sites']} sites.{submitted}",
        "- Whether a name exists is the benchmark's own probe: one A query per URL to Cloudflare's "
        "unfiltered resolver, at the start of the run, and an AAAA query when no A address is public "
        "(no A record at all included); the A and AAAA addresses are judged together. NXDOMAIN there "
        "makes the row 'not found' for every resolver, whatever it answered (Cleanway's blocklist, "
        "Cloudflare's 0.0.0.0 and PhishTank's listing included), and so does an answer with no public "
        "address by the server's own rule: neither an A nor an AAAA record, or only non-public ones "
        "(0.0.0.0, a private range such as a Cloudflare tunnel's private IPv6 address: a takedown or "
        "a dead end, nothing a user can reach); any other answer makes it a live row. The resolvers' own "
        "answers decide only when the "
        "probe cannot tell (SERVFAIL, a timeout, an HTTP error): a name any of them resolved is live, else "
        "an NXDOMAIN from Families' control query or Cleanway's `exists: false` makes it not found. "
        "Cleanway's `exists: false` is the weaker witness: its SSRF guard gives the same answer for a name "
        "that resolves into a blocked network (a private address), and the public check may answer from "
        "its cache (up to 15 minutes for a not-found answer, a day for a full verdict). On a live row, "
        "Cleanway's not-found answer counts as 'caution', which is what a user sees. The raw JSON keeps "
        "every answer, the probe's, and how each row was counted.",
        f"- method_version {report.get('method_version', METHOD_VERSION)}. Runs before 2026-11-03 "
        "(method_version 1) took the dump's first rows, dropped repeated hostnames only, and counted a "
        "dead name's blocklist hit or 0.0.0.0 as a catch. They are not comparable with this one.",
    ]

#!/usr/bin/env python3
"""Fresh-URL benchmark against Cleanway + public competitors.

Strategy doc reference: "Validation as step-zero" — measure
real-world recall and FPR against URLs the model has NEVER seen
at training time, side-by-side with PhishTank and Cloudflare
1.1.1.1 for Families. Until 2026-10-24 also Google Safe Browsing
and VirusTotal's 70-vendor aggregate, whose free APIs bar a
commercial product (NON_COMMERCIAL_RESOLVERS): they now run only
when asked for by name, and such a run is never published. Neither
is a --local-analyzer run whose in-process analyzer asks Safe
Browsing v4 (non_commercial_asked).

Output goes to docs/benchmarks/<YYYY-MM-DD>-fresh-urls.json (raw)
and .md (human-readable table). This is the source-of-truth
for any "X% detection rate" claim on the landing page. A run that
is not published, on a day whose report latest.json already points
to, goes to <YYYY-MM-DD>T<HHMMSS>Z-fresh-urls.json instead.

Usage:
    # The published run (Cleanway + PhishTank + Cloudflare):
    python3 scripts/eval_fresh_urls.py

    # A non-commercial rerun that also asks VirusTotal and Google Safe
    # Browsing, with your own keys (never becomes latest.json):
    VT_API_KEY=... GOOGLE_SAFE_BROWSING_KEY=... \\
        python3 scripts/eval_fresh_urls.py --virustotal --gsb

    # Small smoke run (50 URLs each side):
    python3 scripts/eval_fresh_urls.py --sample 50

    # Re-check the curated legitimate sample (resolves, outside the allowlist):
    python3 scripts/eval_fresh_urls.py --verify-legit-sample

Each competitor is wrapped in a small async adapter that returns a
Verdict: "safe"|"dangerous"|"unknown", its latency, and what else the
answer said (Cleanway's verdict_basis, reason codes, existence).
Adapters fail open — if a service errors out we record "unknown"
and don't count it against recall.

How the phishing sample is drawn and how every answer is counted
(method_version 2, since 2026-11-03: a fixed-seed draw over the sites
of the dump's last 7 days, at most 2 hosts per site, and one existence
fact per URL, the same for every resolver) is scripts/benchmark_method.py.
Reports before 2026-11-03 are counted by the old rules and are not
comparable with later ones.

This file is INTENTIONALLY long and verbose — the report is the
moat. Anyone in the world should be able to read this script and
reproduce our numbers within ±2%.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import gzip
import hashlib
import io
import ipaddress
import json
import logging
import os
import random
import statistics
import sys
import time
import uuid
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncIterator, Awaitable, Callable, Optional
from urllib.parse import urlparse

import httpx

if str(Path(__file__).resolve().parent) not in sys.path:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
import benchmark_legit  # noqa: E402
import benchmark_method  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs" / "benchmarks"
DATA = ROOT / "data"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s | %(message)s",
)
log = logging.getLogger("eval_fresh_urls")

CLEANWAY_API = os.environ.get("CLEANWAY_API_BASE", "https://api.cleanway.ai")
# When set, sent as X-Cleanway-Benchmark on every cleanway request so the
# server skips the 5/min IP rate-limit for this benchmark run. This lets the
# weekly CI job measure a large sample fast (no 16s throttle / 65s cooldown)
# instead of overrunning the CI timeout. Must match api/config benchmark_bypass_token.
BENCHMARK_BYPASS_TOKEN = os.environ.get("BENCHMARK_BYPASS_TOKEN", "").strip()
GSB_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_KEY")
PHISHTANK_KEY = os.environ.get("PHISHTANK_API_KEY")  # optional
VT_KEY = os.environ.get("VT_API_KEY")
# The phishing sample is PhishTank's online-valid dump alone since 2026-10-21:
# URLhaus's csv_recent/ (the other half until then) answers 410 Gone without a
# personal Auth-Key, and abuse.ch's terms are not-for-profit only. PhishTank is
# held out from the blocklist unless PHISHTANK_API_KEY makes it a source there
# (scripts/refresh_dangerous_domains.py), and its FAQ allows commercial use.
PHISHTANK_FEED_URL = "https://data.phishtank.com/data/online-valid.csv.gz"

# Services whose free API bars a commercial product, with the clause that
# does (both read 2026-10-24). Cleanway sells plans, so the published run
# asks neither: until 2026-10-24 a key in the environment was enough to bring
# them in, and the weekly job had both keys. They stay available by name
# (--virustotal / --gsb) for a non-commercial rerun with your own key, and a
# report holding either never becomes docs/benchmarks/latest.json
# (check_quality_gate). Cloudflare 1.1.1.1 for Families stays, pending the
# founder: its terms (the Website and Online Services Terms of Use,
# cloudflare.com/website-terms, effective 2025-08-01) name the resolver as an
# Online Service and carry no non-commercial clause, but their §6 bars use of
# the services' "information, data" except as Cloudflare authorizes, and
# whether a published block rate is such a use they do not say
# (docs/THIRD_PARTY_FEEDS.md §2b). PhishTank's FAQ allows commercial use.
NON_COMMERCIAL_RESOLVERS: dict[str, tuple[str, str]] = {
    "virustotal": ("VirusTotal",
                   'its public API "must not be used in commercial products or services" '
                   "— docs.virustotal.com/reference/public-vs-premium-api"),
    "gsb": ("Google Safe Browsing",
            'its v4 API is "for non-commercial use only", Google sells the same lookup '
            "as Web Risk — developers.google.com/safe-browsing/v4"),
}

# report["sources"] key: which Google lookup the --local-analyzer row made
# (local_google_lookup). Absent from a run without that row.
LOCAL_GOOGLE_LOOKUP = "cleanway_local_google_lookup"


def non_commercial_asked(report: dict) -> list[str]:
    """The NON_COMMERCIAL_RESOLVERS a report asked: as a column of their own,
    or Safe Browsing v4 inside the --local-analyzer row. That row is the
    server's own analyzer, which asks v4 whenever a v4 key is set and Web
    Risk's is not (safe_browsing.get_client). A row whose lookup the report
    does not record counts as having asked it."""
    asked = set(report.get("phishing") or {}) | set(report.get("safe") or {})
    if ("cleanway_local" in asked
            and (report.get("sources") or {}).get(LOCAL_GOOGLE_LOOKUP) not in ("web_risk", "none")):
        asked.add("gsb")
    return [name for name in NON_COMMERCIAL_RESOLVERS if name in asked]

# Rough per-request budget. Cleanway is hot and on-network so we
# can run it concurrently with -c 20; Google SB has tight quotas;
# Cloudflare 1.1.1.1 for Families is generous; VirusTotal free
# tier is 4 req/min (both of those two only when asked for by name).
CONCURRENCY = {
    "cleanway": 1,
    "gsb": 4,
    "phishtank": 4,
    "cloudflare_families": 8,
    "virustotal": 1,
}

# Minimum interval between consecutive requests for a resolver (seconds).
# Cleanway's public endpoint caps fresh-domain checks at 5/min/IP — without
# this throttle, a benchmark with N>5 fresh URLs gets HTTP 429 on most
# requests and shows 0% recall as an artifact of rate-limiting, not
# detection. (Caught by the 2026-06-29 audit: published benchmark file
# showed 0 TP because the benchmark itself rate-limited the cleanway
# adapter.)
MIN_INTERVAL_S = {
    # 5 fresh checks/min cap → 12s spacing + 4.0s headroom. Bumped from 13.0s
    # to 16.0s on 2026-07-01: the 1s cushion wasn't enough under real network
    # jitter and the safe batch was drifting into the phishing batch's
    # rate-limit window, poisoning latest.json with `unknown` verdicts.
    #
    # When BENCHMARK_BYPASS_TOKEN is set the server skips the IP limit for us,
    # so the 16s throttle is unnecessary — drop to a light 0.3s spacing (still
    # polite, avoids hammering). Without the token this is the pace of EACH
    # virtual install (see "Rate-limit identity" below).
    "cleanway": 0.3 if BENCHMARK_BYPASS_TOKEN else 16.0,
    # VT free tier: 4 lookups a minute and 500 a day. At 16 s a lookup, VT is
    # the slowest resolver by far — 2 x 200 URLs take ~105 min (measured
    # 15.75 s a URL on 2026-09-21) — which is why resolvers run side by side
    # (main). The weekly run no longer asks it (NON_COMMERCIAL_RESOLVERS).
    "virustotal": 16.0,
}

# Every resolver sees the phishing and the legitimate URLs INTERLEAVED, in one
# run (interleave_batches). Two reasons:
#   * A fresh Cleanway check may spend one call of the service-wide daily
#     budgets for paid sources (IPQS 150, LLM judge 300 per UTC day). Run
#     phishing first and it spends them, so the false-positive rate would be
#     measured mostly without those sources. Interleaved, both batches meet
#     the same budget state at the same moments.
#   * The same holds for any resolver's quota running out mid-run (VT's 500
#     lookups a day): both batches lose the same share, not the legit one.
# The old 65 s cooldown between a phishing and a legit batch drained a 5/min
# per-IP window; with per-install pacing (or the bypass token) there is no
# such window, and no second batch.

# ── Rate-limit identity without the bypass token ──
#
# Without BENCHMARK_BYPASS_TOKEN the run is one IP: 60 public checks an hour
# and 5 fresh ones a minute. A 200 + 200 benchmark cannot fit — the legit
# half of every run came back `rate_limited`, so the false-positive rate was
# never measured. The public check also takes the header the Android app
# sends, X-Cleanway-Install: a random per-install UUID
# (api/services/rate_limiter.install_key). Limits then apply per install —
# 600 checks an hour, 5 fresh a minute — under per-IP ceilings of 15,000
# checks an hour, 1,500 fresh an hour and 60 fresh a minute (api/config.py).
#
# Why this is legitimate for our own benchmark:
#   * The id is unauthenticated and random by design; the server keeps only
#     its hash, as a rate-limit key that expires with its window.
#   * The per-IP ceilings are the server's explicit bound for ONE address that
#     presents many ids — a Tele2 CGNAT gateway, or this runner. The run stays
#     under them: at most IP_HOURLY_BUDGET checks an hour, and
#     PARALLEL_INSTALLS installs each paced at MIN_INTERVAL_S["cleanway"]
#     (15 a minute, against 60). It never gets more than one busy carrier
#     address may.
#   * Each virtual install behaves like a phone: REQUESTS_PER_INSTALL checks
#     (under its 600 an hour), one per MIN_INTERVAL_S (under its 5 fresh a
#     minute), then a new id. On a 429 the same install waits and retries
#     once (check_cleanway holds it through the wait): a limit is never
#     dodged by switching ids. The other installs go on meanwhile.
#   * It needs no secret, so anyone re-running this script measures what we
#     measure — the point of a public benchmark.
# Cost: a fresh analysis may spend one call of the service-wide daily budgets
# for paid sources (api/services/paid_budget.py: IPQS 150, LLM judge 300 per
# UTC day). The weekly workflow starts on Sunday afternoon UTC and skips a
# start so late that these checks would reach Monday (UTC), so it spends
# Sunday's budget, never a whole Monday's; checks past a cap run without that
# source — exactly as a user's would at that moment. The report records when
# the Cleanway checks ran (cleanway_window_utc).
INSTALL_HEADER = "X-Cleanway-Install"
PARALLEL_INSTALLS = 4
REQUESTS_PER_INSTALL = 50
# The tighter per-IP hourly ceiling for these (mostly fresh) checks:
# api/config.py public_fresh_ip_ceiling_per_window.
IP_HOURLY_CEILING = 1500
IP_HOURLY_BUDGET = 1400    # what one run allows itself, under that ceiling
_HOUR_S = 3600.0


@dataclass(frozen=True)
class _Install:
    id: str
    used: int = 0
    last: Optional[float] = None


class _Lease:
    """One install, held for one URL (both attempts on a 429). `ready()` before
    each request: the install's own pacing and the run's hourly budget."""

    def __init__(self, pool: "InstallPool", inst: _Install) -> None:
        self._pool = pool
        self.inst = inst

    @property
    def headers(self) -> dict:
        return {INSTALL_HEADER: self.inst.id}

    async def ready(self) -> None:
        self.inst = await self._pool._pace(self.inst)


class _TokenLease:
    """The bypass token: the server applies no per-IP limit, nothing to pace."""

    def __init__(self, token: str) -> None:
        self.headers = {"X-Cleanway-Benchmark": token}

    async def ready(self) -> None:
        return None


class InstallPool:
    """Virtual app installs for the Cleanway adapter (see the block above).

    `identity()` lends one install (a `_Lease`); each `lease.ready()` waits
    until that install may ask again and until the run is under its hourly
    budget. An install is retired after `per_install` checks."""

    def __init__(
        self,
        size: int = PARALLEL_INSTALLS,
        per_install: int = REQUESTS_PER_INSTALL,
        min_interval: Optional[float] = None,
        hourly_budget: int = IP_HOURLY_BUDGET,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        new_id: Callable[[], str] = lambda: str(uuid.uuid4()),
    ) -> None:
        self._per_install = per_install
        self._min_interval = MIN_INTERVAL_S["cleanway"] if min_interval is None else min_interval
        self._hourly_budget = hourly_budget
        self._clock, self._sleep, self._new_id = clock, sleep, new_id
        self._free: asyncio.Queue = asyncio.Queue()
        for _ in range(size):
            self._free.put_nowait(_Install(new_id()))
        self._sent: deque = deque()
        self._budget_lock = asyncio.Lock()
        self.installs_used = size
        self.requests = 0

    async def _take_hourly_slot(self) -> None:
        async with self._budget_lock:
            while True:
                now = self._clock()
                while self._sent and now - self._sent[0] >= _HOUR_S:
                    self._sent.popleft()
                if len(self._sent) < self._hourly_budget:
                    self._sent.append(now)
                    return
                await self._sleep(_HOUR_S - (now - self._sent[0]) + 0.5)

    async def _pace(self, inst: _Install) -> _Install:
        if inst.last is not None:
            wait = self._min_interval - (self._clock() - inst.last)
            if wait > 0:
                await self._sleep(wait)
        await self._take_hourly_slot()
        self.requests += 1
        return replace(inst, used=inst.used + 1, last=self._clock())

    @asynccontextmanager
    async def identity(self) -> AsyncIterator[_Lease]:
        lease = _Lease(self, await self._free.get())
        try:
            yield lease
        finally:
            inst = lease.inst
            if inst.used >= self._per_install:
                inst = _Install(self._new_id())
                self.installs_used += 1
            self._free.put_nowait(inst)


_POOL: Optional[InstallPool] = None


def _install_pool() -> InstallPool:
    global _POOL
    if _POOL is None:
        _POOL = InstallPool()
    return _POOL


@asynccontextmanager
async def _cleanway_identity() -> AsyncIterator["_Lease | _TokenLease"]:
    """Who asks about one URL: the bypass token when configured, otherwise
    one of the rotating virtual installs, held until the URL is done."""
    if BENCHMARK_BYPASS_TOKEN:
        yield _TokenLease(BENCHMARK_BYPASS_TOKEN)
        return
    async with _install_pool().identity() as lease:
        yield lease


def cleanway_identity_note() -> str:
    if BENCHMARK_BYPASS_TOKEN:
        return "benchmark bypass token (X-Cleanway-Benchmark)"
    return (f"{PARALLEL_INSTALLS} rotating installs (X-Cleanway-Install), a new id every "
            f"{REQUESTS_PER_INSTALL} checks, one check per install every "
            f"{MIN_INTERVAL_S['cleanway']:.0f}s, at most {IP_HOURLY_BUDGET} an hour from one IP")


# ─────────────────────────────────────────────────────────────────
# URL helpers
# ─────────────────────────────────────────────────────────────────

def _hostname(url: str) -> str:
    s = url.strip()
    if "://" not in s:
        s = "http://" + s
    try:
        host = urlparse(s).hostname or ""
    except Exception:
        host = ""
    return host.lower().strip()


def url_host(url: str) -> str:
    """The URL's own hostname, as a browser asks for it: lowercased, a
    trailing dot removed, "www." kept. Every DNS and API question of a run is
    about this name — the existence probe, Cleanway, the in-process analyzer,
    Families and its control query — as the extension sends a page's hostname
    (extension/src/background/index.js). Until the fourth review of #395 they
    were asked domain_of's shortened name: www.ershoujian.com had public A and
    AAAA addresses while ershoujian.com had only an SOA, so a page anyone
    could open was 'non_public', not found for every resolver."""
    return _hostname(url).rstrip(".")


def domain_of(url: str) -> str:
    """The hostname without "www.": the sample's dedup and nothing else
    (sample_phishing's host_of) — never a name to ask about (url_host).

    NB: do NOT use str.lstrip('www.') — it strips any CHARACTERS
    from {w, ., space}, so 'wsj.com' becomes 'sj.com'. Use
    removeprefix() which is exact-prefix matching.
    """
    return _hostname(url).removeprefix("www.")


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


# ─────────────────────────────────────────────────────────────────
# Sample sources
# ─────────────────────────────────────────────────────────────────

@dataclass
class PhishtankDump:
    """Every row of the online-valid dump that has a URL, in the dump's order.
    `submitted[i]` is row i's submission_time; `sha256` fingerprints the
    decompressed CSV, so whoever holds the same file can check they draw the
    same sample (benchmark_method.sample_phishing)."""
    urls: list[str]
    sha256: str = ""
    submitted: Optional[list[str]] = None


async def fetch_phishtank_dump(client: Optional[httpx.AsyncClient] = None) -> PhishtankDump:
    """PhishTank online-valid.csv.gz — ALL active verified phish, every row
    (until 2026-11-03 only the first sample x 3, from which the sample was the
    top). Anonymous download works; PHISHTANK_API_KEY is optional and only
    raises rate limits. The dump is 1-3 MB gzipped."""
    log.info("fetching PhishTank online-valid feed …")
    if client is None:
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as own:
            return await fetch_phishtank_dump(own)
    # Anonymous download still works — but they politely ask for a
    # User-Agent so we don't look like a bot. They also redirect to a
    # signed CDN URL — follow_redirects is required.
    r = await client.get(PHISHTANK_FEED_URL, headers={"User-Agent": "Cleanway-benchmark/1.0"})
    r.raise_for_status()
    # Gzipped CSV with header row: phish_id,url,phish_detail_url,submission_time,...
    raw = gzip.decompress(r.content)
    urls: list[str] = []
    submitted: list[str] = []
    for row in csv.DictReader(io.StringIO(raw.decode("utf-8", errors="ignore"))):
        u = (row.get("url") or "").strip()
        if u:
            urls.append(u)
            submitted.append((row.get("submission_time") or "").strip())
    log.info("PhishTank: %d rows", len(urls))
    return PhishtankDump(urls, hashlib.sha256(raw).hexdigest(), submitted)


def fetch_tranco_legit(limit: int) -> list[str]:
    """Random sample of the allowlist the server answers without analysis
    (data/top_100k.json: the Majestic Million + Chrome UX Report top 100k
    since 2026-10-23, Tranco's before), or a ranked `rank,domain` CSV
    placed at data/top-1m.csv by hand. Nothing writes that file since
    2026-10-22, so the JSON is the usual source. Evaluation only — this
    sample is never a training row. (The name and the `tranco` legit
    source are kept for old reports and their readers.)

    Skips the top-100 (too easily 'safe' by reputation; we want
    moderately-popular but not famous sites in the control group).
    """
    src = DATA / "top-1m.csv"
    if not src.exists():
        log.info("no data/top-1m.csv — sampling the allowlist, data/top_100k.json")
        with open(DATA / "top_100k.json", "r") as f:
            raw = json.load(f)
        # top_100k.json schema has drifted historically — accept both shapes:
        #   - bare list of domains: ["google.com", "facebook.com", ...]
        #   - dict keyed by domain: {"google.com": <rank>, ...}
        if isinstance(raw, list):
            domains = list(raw)
        elif isinstance(raw, dict):
            domains = list(raw.keys())
        else:
            raise ValueError(
                f"top_100k.json: expected list or dict, got {type(raw).__name__}"
            )
        random.seed(42)
        random.shuffle(domains)
        out = [f"https://{d}" for d in domains[:limit]]
        return out
    candidates: list[str] = []
    with open(src, "r") as f:
        for i, line in enumerate(f):
            parts = line.strip().split(",")
            if len(parts) < 2:
                continue
            rank, domain = parts[0], parts[1]
            try:
                rank_n = int(rank)
            except ValueError:
                continue
            if rank_n < 100 or rank_n > 100_000:
                continue
            candidates.append(f"https://{domain}")
            if len(candidates) >= limit * 4:
                break
    random.seed(42)
    random.shuffle(candidates)
    out = candidates[:limit]
    log.info("Tranco legit (rank 100-100000): %d urls", len(out))
    return out


def pick_legit(
    source: str,
    limit: int,
    path: Optional[Path] = None,
    is_trusted: Optional[Callable[[str], bool]] = None,
) -> tuple[list[str], Optional[list["benchmark_legit.LegitSite"]], dict]:
    """(urls, sites or None, report `sources` fields) for the legit batch.

    `legit_outside_allowlist` is True only for the curated list AND only when
    the server's own allowlist rule was available to prove it — the landing
    shows a false-positive rate on nothing less. `is_trusted` defaults to
    that rule (benchmark_legit.allowlist_rule)."""
    if source == "tranco":
        urls = fetch_tranco_legit(limit)
        return urls, None, {
            "legit": "The allowlist's top 100,000 (data/top_100k.json), random sample (seed=42).",
            # The public check answers every top-100k domain "safe" without
            # analysing it (is_trusted_top_domain): no FP measurement.
            "legit_outside_allowlist": False,
        }
    sites = benchmark_legit.load_legit_sample(path or benchmark_legit.LEGIT_SAMPLE_PATH)
    rule = is_trusted if is_trusted is not None else benchmark_legit.allowlist_rule()
    picked = benchmark_legit.select_legit_sample(sites, limit, rule)
    blocked = sum(1 for s in picked if s.reachability == "blocked-abroad")
    log.info("curated legit: %d of %d sites (%d unreachable from abroad)", len(picked), len(sites), blocked)
    return [f"https://{s.host}" for s in picked], picked, {
        "legit": (f"data/benchmark_legit_ru.txt: {len(picked)} of {len(sites)} real Russian sites "
                  "outside the allowlist's top 100,000 (Majestic Million + Chrome UX Report; "
                  "regional and city government, universities, .рф, "
                  "small banks and businesses, museums, theatres), random sample "
                  f"(seed={benchmark_legit.SAMPLE_SEED}); {blocked} were unreachable from outside "
                  "Russia when listed."),
        "legit_outside_allowlist": rule is not None,
    }


# ─────────────────────────────────────────────────────────────────
# Competitor adapters
# ─────────────────────────────────────────────────────────────────

@dataclass
class Verdict:
    name: str
    verdict: str  # "safe" | "dangerous" | "unknown"
    score: Optional[float] = None
    latency_ms: float = 0.0
    detail: str = ""
    # What Cleanway's answer said besides its level (check_cleanway). Only
    # Cleanway's rows carry them in the raw JSON (_raw_rows).
    level: Optional[str] = None
    verdict_basis: Optional[str] = None
    reason_codes: Optional[list[str]] = None
    checks_incomplete: Optional[list[str]] = None
    # Does the name exist, as far as this answer tells: True = it resolved,
    # False = NXDOMAIN (for Cleanway: its not-found answer, which its SSRF
    # guard also gives for a name resolving into a blocked network), None =
    # the answer says nothing about it. The existence probe's decides the row;
    # the resolvers' only when it could not tell (benchmark_method.row_existence).
    exists: Optional[bool] = None
    # The A (and AAAA) addresses the existence probe got: a name with no
    # public address among them, none at all included, is not live
    # (benchmark_method.no_public_address).
    # Only the probe's rows carry them (raw.existence).
    addresses: Optional[list[str]] = None


def _str_list(value: object) -> Optional[list[str]]:
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return list(value)
    return None


async def check_cleanway(client: httpx.AsyncClient, url: str) -> Verdict:
    """GET /api/v1/public/check/{host} on api.cleanway.ai: what a user of
    the site or the app gets for the URL's host name (url_host: only the
    host name is sent, "www." kept, as the extension sends a page's).

    The public check answers in this order (api/routers/public.py
    public_check): the allowlist of the top 100,000 — 'safe' without
    analysis, unless its age gate holds a young registration back; then
    Cleanway's own blocklist — 'dangerous' at once, before any existence
    check, so a listed name that no longer resolves is still 'dangerous';
    then a user-content service host (disk.yandex.ru, onedrive.live.com) —
    a fixed caution, verdict_basis 'user_content', no analysis; then its
    public cache — an earlier answer for the domain, kept a day for a full
    verdict, an hour for a partial one, 15 minutes for a not-found one; and
    only then the full analyzer — threat-intel sources (as LICENSED_INTEL
    allows), site probes, ML, the LLM judge — inside a ~3 s budget.

    The Verdict is 'dangerous' / 'safe' for those levels and 'unknown'
    otherwise; `detail` is the level, 'not_found' when the answer says
    exists: false, or why there was no answer. The answer's own fields are
    kept, per URL, in the raw JSON:
      level              safe / caution / dangerous
      verdict_basis      what the verdict rests on: blocklist, threat_intel,
                         allowlist, ml_and_heuristics, heuristics,
                         unreachable, not_found, user_content
      reason_codes       the reasons shown, as codes (published without
                         the third-party ones: THIRD_PARTY_SOURCE_CODES)
      checks_incomplete  checks the time budget cut off
      exists             false: the analyzer's not-found answer — an NXDOMAIN,
                         or a name that resolves into a blocked or private
                         network (the SSRF guard gives the same answer on
                         purpose, so the two cannot be told apart); null: not
                         checked (an allowlist, blocklist or user-content
                         answer) or no answer
    How the row is then counted — the benchmark's own probe says whether the
    name exists, and a name that does not is 'not_found' whatever Cleanway
    said; on a live row Cleanway's not-found answer is a 'caution', as a user
    sees it — is benchmark_method.row_existence and .outcome.

    On HTTP 429 the same identity waits (Retry-After, at most 60 s; 25 s
    when the server sent none) and asks once more; a second 429 is
    'unknown' (rate_limited). Without the token, the same virtual install
    waits out the 429 (the other installs go on meanwhile) — a per-install
    limit is never dodged by switching ids.

    `latency_ms` is time spent in requests only — never our own pacing
    or a 429 wait, which say nothing about how fast Cleanway answers.
    """
    d = url_host(url)
    if not d:
        return Verdict("cleanway", "unknown", detail="bad_domain")
    spent = 0.0
    started: Optional[float] = None
    try:
        async with _cleanway_identity() as ident:
            for attempt in (1, 2):
                await ident.ready()  # this install's pacing, the hourly budget
                started = time.monotonic()
                r = await client.get(
                    f"{CLEANWAY_API}/api/v1/public/check/{d}",
                    headers=ident.headers,
                    timeout=8.0,
                )
                spent += time.monotonic() - started
                started = None
                if r.status_code == 429 and attempt == 1:
                    # Honour Retry-After if the server sent one, else
                    # default to a full 5/min window plus headroom.
                    ra = r.headers.get("retry-after")
                    try:
                        wait_s = max(1.0, float(ra)) if ra else 25.0
                    except ValueError:
                        wait_s = 25.0
                    await asyncio.sleep(min(wait_s, 60.0))
                    continue
                break
        elapsed = spent * 1000
        if r.status_code != 200:
            tag = "rate_limited" if r.status_code == 429 else f"status={r.status_code}"
            return Verdict("cleanway", "unknown", latency_ms=elapsed, detail=tag)
        data = r.json()
        level = (data.get("level") or "").lower()
        score = data.get("score")
        exists = data.get("exists")
        facts = {
            "level": level or None,
            "verdict_basis": data.get("verdict_basis") if isinstance(data.get("verdict_basis"), str) else None,
            "reason_codes": _str_list(data.get("reason_codes")),
            "checks_incomplete": _str_list(data.get("checks_incomplete")),
            "exists": exists if isinstance(exists, bool) else None,
        }
        if exists is False:
            # The domain no longer exists — nobody can block or miss it.
            return Verdict("cleanway", "unknown", score=score,
                           latency_ms=elapsed, detail="not_found", **facts)
        v = "dangerous" if level == "dangerous" else (
            "safe" if level == "safe" else "unknown"
        )
        return Verdict("cleanway", v, score=score,
                       latency_ms=elapsed, detail=level, **facts)
    except Exception as exc:
        if started is not None:  # the request itself failed (timeout, reset)
            spent += time.monotonic() - started
        return Verdict("cleanway", "unknown", latency_ms=spent * 1000,
                       detail=f"err:{exc}")


# Lazy-imported analyzer entry-point so the script can run without
# the full repo dependencies installed when only public-mode is used.
_analyze_domain = None


def _repo_on_path() -> None:
    """Put the repo root on sys.path so 'api.*' imports resolve."""
    repo_root = str(ROOT)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)


def _load_analyzer():
    global _analyze_domain
    if _analyze_domain is not None:
        return _analyze_domain
    _repo_on_path()
    from api.services.analyzer import analyze_domain  # noqa: E402
    _analyze_domain = analyze_domain
    return _analyze_domain


def local_google_lookup() -> str:
    """The Google lookup the in-process analyzer will make, by the rule
    safe_browsing.get_client() applies to the same settings (environment or
    .env): "web_risk" with WEB_RISK_API_KEY, else "safe_browsing_v4" with
    GOOGLE_SAFE_BROWSING_API_KEY or GOOGLE_SAFE_BROWSING_KEY, else "none"."""
    _repo_on_path()
    from api.config import get_settings  # noqa: E402

    settings = get_settings()
    if settings.web_risk_api_key:
        return "web_risk"
    if settings.google_safe_browsing_key:
        return "safe_browsing_v4"
    return "none"


async def check_cleanway_local(client: httpx.AsyncClient, url: str) -> Verdict:
    """Run the FULL analyzer in-process — what authed
    /api/v1/check would return. Calls all 18 parallel checks
    including 16 threat-intel sources.

    Free sources (Cloudflare DoH / crt.sh / RDAP) work without keys;
    the non-commercial ones (URLhaus / ThreatFox / MalwareBazaar / Feodo,
    SURBL, Spamhaus) are only asked with LICENSED_INTEL=all. Paid sources
    (Safe Browsing / PhishTank API / IPQS / AlienVault) fail
    silently through the circuit breakers and return False —
    so this is a LOWER-BOUND on the full authed-endpoint
    performance (in production those keys are set).

    No Redis needed — cache is opt-in and falls through cleanly
    on connection failure.
    """
    d = url_host(url)
    if not d:
        return Verdict("cleanway_local", "unknown", detail="bad_domain")
    t0 = time.monotonic()
    try:
        analyze = _load_analyzer()
        result = await analyze(d, raw_url=url)
        elapsed = (time.monotonic() - t0) * 1000
        level = (result.level.value if hasattr(result.level, "value")
                 else str(result.level)).lower()
        score = result.score
        v = "dangerous" if level == "dangerous" else (
            "safe" if level == "safe" else "unknown"
        )
        from api.services.verdict_basis import basis_of  # noqa: E402 — the analyzer loaded the package
        exists = getattr(result, "exists", None)
        return Verdict("cleanway_local", v, score=score,
                       latency_ms=elapsed, detail=level, level=level,
                       verdict_basis=basis_of(result),
                       checks_incomplete=list(getattr(result, "checks_incomplete", None) or []),
                       exists=exists if isinstance(exists, bool) else None)
    except Exception as exc:
        return Verdict("cleanway_local", "unknown",
                       latency_ms=(time.monotonic() - t0) * 1000,
                       detail=f"err:{type(exc).__name__}:{str(exc)[:80]}")


async def check_gsb(client: httpx.AsyncClient, url: str) -> Verdict:
    """Google Safe Browsing v4 threatMatches.find. Requires
    GOOGLE_SAFE_BROWSING_KEY. If missing the adapter returns
    'unknown' for every URL — the report will note GSB N/A."""
    if not GSB_KEY:
        return Verdict("gsb", "unknown", detail="no_key")
    t0 = time.monotonic()
    payload = {
        "client": {"clientId": "cleanway-benchmark", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        r = await client.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}",
            json=payload, timeout=10.0,
        )
        elapsed = (time.monotonic() - t0) * 1000
        if r.status_code != 200:
            return Verdict("gsb", "unknown", latency_ms=elapsed,
                           detail=f"status={r.status_code}")
        data = r.json()
        matches = data.get("matches") or []
        return Verdict("gsb",
                       "dangerous" if matches else "safe",
                       latency_ms=elapsed,
                       detail=f"matches={len(matches)}")
    except Exception as exc:
        return Verdict("gsb", "unknown",
                       latency_ms=(time.monotonic() - t0) * 1000,
                       detail=f"err:{exc}")


async def check_phishtank(client: httpx.AsyncClient, url: str) -> Verdict:
    """PhishTank checkurl endpoint. Key is optional but lifts rate
    limits. NOTE: PhishTank's API has been deprecated multiple
    times historically; the adapter degrades gracefully."""
    t0 = time.monotonic()
    payload = {"url": url, "format": "json"}
    headers = {"User-Agent": "phishtank/cleanway-benchmark"}
    if PHISHTANK_KEY:
        payload["app_key"] = PHISHTANK_KEY
    try:
        r = await client.post(
            "https://checkurl.phishtank.com/checkurl/",
            data=payload, headers=headers, timeout=10.0,
        )
        elapsed = (time.monotonic() - t0) * 1000
        if r.status_code != 200:
            return Verdict("phishtank", "unknown", latency_ms=elapsed,
                           detail=f"status={r.status_code}")
        # Body is JSON or XML depending on version; we try JSON first.
        try:
            data = r.json()
            results = data.get("results", {})
            in_db = results.get("in_database", False)
            phish = results.get("valid", False)
        except Exception:
            in_db, phish = False, False
        if not in_db:
            return Verdict("phishtank", "unknown", latency_ms=elapsed,
                           detail="not_in_db")
        return Verdict("phishtank",
                       "dangerous" if phish else "safe",
                       latency_ms=elapsed,
                       detail=f"valid={phish}")
    except Exception as exc:
        return Verdict("phishtank", "unknown",
                       latency_ms=(time.monotonic() - t0) * 1000,
                       detail=f"err:{exc}")


CLOUDFLARE_UNFILTERED_DOH = "https://cloudflare-dns.com/dns-query"


async def _unfiltered_query(
    client: httpx.AsyncClient, d: str, rtype: str = "A",
) -> tuple[Optional[object], list[str], Optional[str]]:
    """One question to Cloudflare's UNFILTERED resolver: (the DNS status, the
    A/AAAA addresses in the answer, why there is no answer — None when it
    came: an HTTP error, a timeout). CNAME records are not addresses."""
    try:
        r = await client.get(
            CLOUDFLARE_UNFILTERED_DOH,
            params={"name": d, "type": rtype},
            headers={"Accept": "application/dns-json"},
            timeout=8.0,
        )
        if r.status_code != 200:
            return None, [], f"http={r.status_code}"
        data = r.json()
    except Exception as exc:
        return None, [], f"err:{type(exc).__name__}"
    addresses = [str(a.get("data") or "").strip() for a in data.get("Answer") or []
                 if isinstance(a, dict) and a.get("type") in (1, 28)]
    return data.get("Status"), addresses, None


async def _unfiltered_lookup(client: httpx.AsyncClient, d: str) -> tuple[Optional[bool], str]:
    """(does the name exist, why we say so) by Cloudflare's UNFILTERED
    resolver: True on NOERROR (with an answer or without one: the name is
    there), False on NXDOMAIN, None when it could not tell — SERVFAIL, an
    HTTP error, a timeout. Until 2026-11-03 Families' control query read any
    answer but NXDOMAIN, SERVFAIL included, as "the name exists"."""
    status, _addresses, failed = await _unfiltered_query(client, d)
    if failed:
        return None, failed
    if status == 0:
        return True, "noerror"
    if status == 3:
        return False, "nxdomain"
    return None, f"status={status}"


EXISTENCE_PROBE = "existence"


async def probe_existence(client: httpx.AsyncClient, url: str) -> Verdict:
    """The benchmark's own existence witness, asked once for every URL at the
    start of the run, whatever the resolvers answered, about the URL's own
    host name (url_host, "www." kept): Cloudflare's unfiltered
    resolver (_unfiltered_query), an A question, and an AAAA one too when no
    A address is public — no A record at all included: a CNAME to a
    Cloudflare tunnel has only a private IPv6 address (third review of #395).
    The A and AAAA addresses are judged together. An IP address exists
    without DNS and is its own address. Not a resolver: its Verdict is always
    'unknown', its answer is `exists` and `addresses`. It decides the row —
    not live when no address is public, none at all included (a takedown, a
    dead end) — and the resolvers' own answers only when `exists` is None,
    the AAAA question failing included (benchmark_method.row_existence)."""
    d = url_host(url)
    if not d:
        return Verdict(EXISTENCE_PROBE, "unknown", detail="bad_domain")
    if is_ip_address(d):
        return Verdict(EXISTENCE_PROBE, "unknown", detail="ip_literal", exists=True, addresses=[d.strip("[]")])
    t0 = time.monotonic()

    def done(detail: str, exists: Optional[bool], addresses: Optional[list[str]]) -> Verdict:
        return Verdict(EXISTENCE_PROBE, "unknown", latency_ms=(time.monotonic() - t0) * 1000,
                       detail=detail, exists=exists, addresses=addresses)

    status, addresses, failed = await _unfiltered_query(client, d, "A")
    if failed:
        return done(failed, None, None)
    if status == 3:
        return done("nxdomain", False, None)
    if status != 0:
        return done(f"status={status}", None, None)
    if benchmark_method.no_public_address(addresses):  # none, or only non-public ones
        status6, more, failed6 = await _unfiltered_query(client, d, "AAAA")
        if failed6 or status6 != 0:
            return done(f"noerror aaaa={failed6 or f'status={status6}'}", None, addresses)
        addresses = addresses + more
    return done("noerror", True, addresses)


async def check_cloudflare_families(client: httpx.AsyncClient, url: str) -> Verdict:
    """Cloudflare 1.1.1.1 for Families (security). We do a DoH lookup
    against family.cloudflare-dns.com and check the answer.

    Families blocks with a 0.0.0.0 / :: sinkhole. NXDOMAIN is only a
    block when the name exists: a phishing domain that has already been
    taken down is NXDOMAIN on EVERY resolver, and counting it as a
    Cloudflare catch inflated the published comparison — 8 of the 13
    Cloudflare "hits" in the 2026-06 run were domains that no longer
    existed (report 2026-09-25 #18). So an NXDOMAIN is re-asked of the
    unfiltered resolver; if that one says NXDOMAIN too, the verdict is
    'unknown' (detail 'nxdomain') and counts for no one, and if it cannot
    tell (SERVFAIL, an error) it is 'unknown' ('nxdomain_unverified').

    The 0.0.0.0 sinkhole comes before any such check: Families answers it
    for a name it lists whether or not the name still exists (12 of the 16
    names Cleanway found dead on 2026-11-01). That 'dangerous' stays the raw
    answer; the benchmark's own existence probe makes the row 'not_found'
    for every resolver (benchmark_method.outcome). `exists` says what this
    answer learned: True when a resolver answered for the name, False on
    NXDOMAIN everywhere, None for the sinkhole or a control query that could
    not tell. It counts only when the probe could not tell.
    """
    d = url_host(url)
    if not d:
        return Verdict("cloudflare_families", "unknown", detail="bad_domain")
    t0 = time.monotonic()
    try:
        r = await client.get(
            "https://family.cloudflare-dns.com/dns-query",
            params={"name": d, "type": "A"},
            headers={"Accept": "application/dns-json"},
            timeout=8.0,
        )
        elapsed = (time.monotonic() - t0) * 1000
        if r.status_code != 200:
            return Verdict("cloudflare_families", "unknown",
                           latency_ms=elapsed,
                           detail=f"status={r.status_code}")
        data = r.json()
        status = data.get("Status", 0)
        answers = data.get("Answer", []) or []
        blocked_ips = {"0.0.0.0", "::"}
        ip_blocked = any(
            (a.get("data") or "").strip() in blocked_ips
            for a in answers if a.get("type") in (1, 28)
        )
        if ip_blocked:
            return Verdict("cloudflare_families", "dangerous",
                           latency_ms=elapsed,
                           detail=f"status={status} ip_block=True")
        if status == 3:
            exists, _why = await _unfiltered_lookup(client, d)
            if exists:
                return Verdict("cloudflare_families", "dangerous",
                               latency_ms=elapsed, detail="status=3 blocked", exists=True)
            return Verdict("cloudflare_families", "unknown", latency_ms=elapsed,
                           detail="nxdomain" if exists is False else "nxdomain_unverified",
                           exists=exists)
        if status == 0 and answers:
            return Verdict("cloudflare_families", "safe",
                           latency_ms=elapsed, detail="resolved", exists=True)
        return Verdict("cloudflare_families", "unknown",
                       latency_ms=elapsed,
                       detail=f"status={status}")
    except Exception as exc:
        return Verdict("cloudflare_families", "unknown",
                       latency_ms=(time.monotonic() - t0) * 1000,
                       detail=f"err:{exc}")


async def check_virustotal(client: httpx.AsyncClient, url: str) -> Verdict:
    """VirusTotal /urls/{id} — aggregates 70+ AVs (Bitdefender,
    Norton, Kaspersky, McAfee, Avast, ...). Free tier is 4 req/min
    so the adapter sleeps if needed.

    URL id is url-safe-base64 of SHA-256, per VT spec. We treat
    a URL as 'dangerous' if ≥2 vendors flag it (single-vendor
    false positives are common in VT's set)."""
    if not VT_KEY:
        return Verdict("virustotal", "unknown", detail="no_key")
    t0 = time.monotonic()
    import base64 as _b64
    url_id = _b64.urlsafe_b64encode(url.encode("utf-8")).rstrip(b"=").decode("ascii")
    try:
        r = await client.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_KEY},
            timeout=15.0,
        )
        elapsed = (time.monotonic() - t0) * 1000
        if r.status_code == 404:
            return Verdict("virustotal", "unknown",
                           latency_ms=elapsed,
                           detail="not_indexed")
        if r.status_code != 200:
            return Verdict("virustotal", "unknown",
                           latency_ms=elapsed,
                           detail=f"status={r.status_code}")
        data = r.json()
        stats = (((data or {}).get("data") or {}).get("attributes")
                 or {}).get("last_analysis_stats") or {}
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        flagged = malicious + suspicious
        verdict = "dangerous" if flagged >= 2 else "safe"
        return Verdict("virustotal", verdict, score=float(flagged),
                       latency_ms=elapsed,
                       detail=f"mal={malicious} susp={suspicious}")
    except Exception as exc:
        return Verdict("virustotal", "unknown",
                       latency_ms=(time.monotonic() - t0) * 1000,
                       detail=f"err:{exc}")


ADAPTERS = {
    "cleanway": check_cleanway,
    "cleanway_local": check_cleanway_local,
    "gsb": check_gsb,
    "phishtank": check_phishtank,
    "cloudflare_families": check_cloudflare_families,
    "virustotal": check_virustotal,
    EXISTENCE_PROBE: probe_existence,
}

CONCURRENCY["cleanway_local"] = 4  # 18 parallel checks per URL, easy on the analyzer
CONCURRENCY[EXISTENCE_PROBE] = 8   # the same unfiltered resolver Families re-asks


# ─────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────

async def run_resolver(name: str, urls: list[str]) -> list[Verdict]:
    """Run a resolver across all URLs, respecting its concurrency
    limit AND the per-resolver MIN_INTERVAL_S throttle. Returns a
    Verdict per URL, same order as the input list."""
    adapter = ADAPTERS[name]
    concurrency = CONCURRENCY[name]
    min_interval = MIN_INTERVAL_S.get(name, 0.0)
    if name == "cleanway" and not BENCHMARK_BYPASS_TOKEN:
        # The install pool paces each virtual install itself; a run-wide
        # throttle on top would serialise them back into one IP's pace.
        concurrency, min_interval = PARALLEL_INSTALLS, 0.0
    sem = asyncio.Semaphore(concurrency)
    last_call_at = [0.0]  # mutable closure cell
    lock = asyncio.Lock()
    async with httpx.AsyncClient() as client:
        async def _one(u):
            async with sem:
                if min_interval > 0:
                    async with lock:
                        wait = min_interval - (time.monotonic() - last_call_at[0])
                        if wait > 0:
                            await asyncio.sleep(wait)
                        last_call_at[0] = time.monotonic()
                return await adapter(client, u)
        log.info(
            "running %s on %d URLs (concurrency=%d, min_interval=%.1fs) …",
            name, len(urls), concurrency, min_interval,
        )
        results = await asyncio.gather(*[_one(u) for u in urls])
    return results


def interleave_batches(phishing: list[str], legit: list[str]) -> list[tuple[str, int]]:
    """The order a resolver sees both batches in: ("phishing", i) and
    ("legit", i) alternating, the longer batch's tail at the end. Why: the
    "INTERLEAVED" note right after MIN_INTERVAL_S."""
    order: list[tuple[str, int]] = []
    for i in range(max(len(phishing), len(legit))):
        if i < len(phishing):
            order.append(("phishing", i))
        if i < len(legit):
            order.append(("legit", i))
    return order


async def run_resolver_on_both(
    name: str, phishing: list[str], legit: list[str],
    run: Callable[[str, list[str]], Awaitable[list[Verdict]]] = run_resolver,
) -> tuple[list[Verdict], list[Verdict]]:
    """One interleaved run of `name` over both batches, split back into
    (phishing verdicts, legit verdicts), each in its batch's order."""
    order = interleave_batches(phishing, legit)
    batches = {"phishing": phishing, "legit": legit}
    verdicts = await run(name, [batches[b][i] for b, i in order])
    by_slot = dict(zip(order, verdicts, strict=True))
    return (
        [by_slot[("phishing", i)] for i in range(len(phishing))],
        [by_slot[("legit", i)] for i in range(len(legit))],
    )


def _utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _run_clock() -> datetime:
    """The run's clock when the dump has arrived: no row of it can be newer
    (benchmark_method.recent_window)."""
    return datetime.now(timezone.utc)


def outcomes_of(verdicts: list[Verdict], existence: Optional[list[str]] = None) -> list[str]:
    """How each answer is counted (benchmark_method.outcome). `existence` is
    the row's fact, one per verdict; without it, each answer's own `exists`."""
    if existence is None:
        existence = [benchmark_method.row_existence(None, [v.exists]) for v in verdicts]
    return [benchmark_method.outcome(v.verdict, v.level, e) for v, e in zip(verdicts, existence, strict=True)]


def existence_of_rows(probe: list[Verdict], results: dict[str, list[Verdict]]) -> list[str]:
    """Each row's existence: the probe's answer, the resolvers' when it had none."""
    return [benchmark_method.row_existence(p.exists, [rows[i].exists for rows in results.values()],
                                           addresses=p.addresses)
            for i, p in enumerate(probe)]


# Fields only Cleanway's answer has (check_cleanway): other rows leave them out.
_CLEANWAY_FIELDS = ("level", "verdict_basis", "reason_codes", "checks_incomplete")

# Reason codes that name a third-party source (api/services/scoring.py). The
# weekly report is committed to this public repo, and Cleanway's answer can
# rest on Google Web Risk ('safe_browsing'), whose terms let a product show a
# warning from Google's list only while the list is fresh and with Google's
# notice. So a published row says THAT an external feed listed the host
# (verdict_basis 'threat_intel'), never WHICH: with every other feed named, a
# row naming none would name Google's by elimination. For the same reason a
# row that had one loses its score, which the public weights would decode
# (80 is safe_browsing's). The counts do not use either field.
THIRD_PARTY_SOURCE_CODES = frozenset({
    "safe_browsing", "phishtank", "urlhaus", "phishstats", "threatfox", "spamhaus_dbl", "surbl",
    "malware_bazaar", "feodo", "alienvault_otx", "alienvault_otx_high", "ipqs_phishing",
    "ipqs_high_risk", "multi_blocklist",
})
# The same sources as checks_incomplete names them: the analyzer's check names
# (api/services/analyzer._check_calls), not the reason codes. Kept there, they
# name Google by elimination too: under LICENSED_INTEL=licensed only
# safe_browsing, phishtank and phishstats of the hard listings are asked, so a
# 'threat_intel' row with ["phishstats", "phishtank"] cut off is a Google hit.
# The degraded-answers count (degraded_answers) reads the answers, not the rows.
THIRD_PARTY_CHECK_NAMES = frozenset({
    "safe_browsing", "phishtank", "urlhaus", "phishstats", "threatfox", "spamhaus", "surbl",
    "alienvault", "ipqs", "malware_bazaar", "feodo",
})


def _unnamed_sources(row: dict) -> None:
    """A Cleanway row as published: no third-party source named
    (THIRD_PARTY_SOURCE_CODES, THIRD_PARTY_CHECK_NAMES)."""
    codes = row.get("reason_codes")
    named = any(c in THIRD_PARTY_SOURCE_CODES for c in codes or ())
    if codes is not None:
        row["reason_codes"] = [c for c in codes if c not in THIRD_PARTY_SOURCE_CODES]
    if row.get("checks_incomplete") is not None:
        row["checks_incomplete"] = [c for c in row["checks_incomplete"] if c not in THIRD_PARTY_CHECK_NAMES]
    if named or row.get("verdict_basis") == "threat_intel":
        row["score"] = None


def _raw_rows(resolver: str, verdicts: list[Verdict], outcomes: list[str]) -> list[dict]:
    rows = []
    for v, outcome in zip(verdicts, outcomes, strict=True):
        row = asdict(v)
        row.pop("addresses")  # the existence probe's alone (_probe_rows)
        if resolver.startswith("cleanway"):
            _unnamed_sources(row)
        else:
            for key in _CLEANWAY_FIELDS:
                row.pop(key)
        row["outcome"] = outcome
        rows.append(row)
    return rows


def _probe_rows(probe: list[Verdict], existence: list[str]) -> list[dict]:
    """The probe's answer per row, the row's existence ("status") and who
    settled it: the probe, the resolvers (the probe could not tell), or nobody."""
    def decided_by(p: Verdict, status: str) -> Optional[str]:
        if p.exists is not None:
            return "probe"
        return "resolvers" if status != benchmark_method.UNKNOWN else None

    return [{"exists": p.exists, "addresses": p.addresses, "detail": p.detail, "latency_ms": p.latency_ms,
             "status": status, "decided_by": decided_by(p, status)}
            for p, status in zip(probe, existence, strict=True)]


def classify(verdicts: list[Verdict], expected: str, existence: Optional[list[str]] = None) -> dict:
    """expected ∈ {'dangerous', 'safe'}.

    The summary of benchmark_method.summarize — TP/FP/TN/FN/unknown, recall,
    FPR, precision, F1 as before (recall = TP/(TP+FN) on the 'dangerous'
    batch, FPR on the 'safe' one; caution, not found and no answer are all
    'unknown'), every kind of answer counted apart, the rates over all and
    over resolving rows with Wilson 95% intervals — plus latency. A row whose
    name resolves nowhere (`existence`) is not found, whatever the answer.
    """
    latencies = [v.latency_ms for v in verdicts if v.latency_ms > 0]
    return {
        **benchmark_method.summarize(outcomes_of(verdicts, existence), expected),
        "latency_p50_ms": (statistics.median(latencies) if latencies else None),
        "latency_p95_ms": (sorted(latencies)[int(0.95 * len(latencies))]
                           if len(latencies) >= 20 else None),
    }


def render_md(report: dict) -> str:
    lines: list[str] = []
    lines.append("# Cleanway fresh-URL benchmark")
    lines.append("")
    lines.append(f"**Run**: {report['ts']}  •  **Sample**: "
                 f"{report['n_phishing']} phishing + {report['n_safe']} legit")
    lines.append("")
    lines.append("## Sources")
    for k, v in report["sources"].items():
        lines.append(f"- **{k}**: {v}")
    lines.append("")
    lines.append("## Phishing batch (expected: dangerous)")
    lines.append("")
    lines.append(
        "| Resolver | Recall | Precision | F1 | FP | TP | FN | Unknown | p50 ms |"
    )
    lines.append(
        "|---|---|---|---|---|---|---|---|---|"
    )
    def _ci(ci):
        return f" ({ci[0]*100:.1f}–{ci[1]*100:.1f}%)" if ci else ""
    for name, m in report["phishing"].items():
        def _pct(x):
            return f"{x*100:.1f}%" if x is not None else "—"
        def _n(x):
            return f"{x:.0f}" if x is not None else "—"
        lines.append(
            f"| {name} | {_pct(m['recall'])}{_ci(m.get('recall_wilson95'))} | {_pct(m['precision'])} "
            f"| {_pct(m['f1'])} | {m['fp']} | {m['tp']} | {m['fn']} "
            f"| {m['unknown']} | {_n(m['latency_p50_ms'])} |"
        )
    lines.append("")
    lines.append("## Safe batch (expected: safe → measure FPR)")
    lines.append("")
    lines.append(
        "| Resolver | FPR | FP | TN | Unknown | p50 ms |"
    )
    lines.append(
        "|---|---|---|---|---|---|"
    )
    for name, m in report["safe"].items():
        def _pct(x):
            return f"{x*100:.2f}%" if x is not None else "—"
        def _n(x):
            return f"{x:.0f}" if x is not None else "—"
        lines.append(
            f"| {name} | {_pct(m['fpr'])}{_ci(m.get('fpr_wilson95'))} | {m['fp']} | {m['tn']} "
            f"| {m['unknown']} | {_n(m['latency_p50_ms'])} |"
        )
    lines.append("")
    lines += benchmark_method.render_outcomes_md(report)
    if report.get("cleanway_on_legit"):
        lines += benchmark_legit.render_breakdown_md(report["cleanway_on_legit"])
    lines.append("## Methodology")
    lines.append("")
    lines.append("- Phishing samples come from PhishTank's online-valid dump (until 2026-10-21 "
                 "also URLhaus, which then closed anonymous downloads — earlier runs are a "
                 "different mix); the Cleanway ML model has NOT been trained on these specific URLs.")
    lines += benchmark_method.methodology_md(report)
    if report.get("sources", {}).get("legit_outside_allowlist"):
        lines.append("- Legit samples are real Russian sites OUTSIDE the top 100,000 the server "
                     "trusts on sight (Majestic Million + Chrome UX Report; Tranco's until 2026-10-23) — "
                     "regional and city government, universities, .рф, small banks and "
                     "businesses, museums, theatres (data/benchmark_legit_ru.txt, each "
                     "with its source). The server analyses every one of them; none gets "
                     "the instant 'safe' popular sites get.")
    else:
        lines.append("- Legit samples are random entries of the top 100,000 the server trusts on sight. "
                     "The server answers those 'safe' without analysis, so this run's "
                     "false-positive rate is NOT a measurement.")
    resolvers = set(report["phishing"])
    full_url = [label for name, label in (("gsb", "GSB"), ("phishtank", "PhishTank"), ("virustotal", "VT"))
                if name in resolvers]
    receive = "receives" if len(full_url) == 1 else "receive"
    lines.append("- We send only the URL's host name ('www.' kept, as the extension sends a page's) "
                 "to Cleanway (server-blind invariant) and to Cloudflare (a DNS lookup)." + (f" {' / '.join(full_url)} {receive} the full URL." if full_url else ""))
    window = report.get("cleanway_window_utc") or {}
    ran = (f" The Cleanway checks ran {window['start']} – {window['end']}."
           if window.get("start") and window.get("end") else "")
    lines.append("- Cleanway requests identify as: "
                 f"{report.get('sources', {}).get('cleanway_identity', 'one IP')}. "
                 "Each check may use the service's daily paid-source budgets; "
                 "checks past a cap run without that source, as a user's would. "
                 "Phishing and legitimate URLs are interleaved, so both batches "
                 f"meet the same budget state.{ran}")
    lines.append("- 'Unknown' = no definitive verdict: Cleanway's caution, a name that does not "
                 "exist, or no answer (rate-limited, not indexed, error, timeout). 'Unknown' is NOT "
                 "counted as either correct or incorrect in recall and FPR; 'Every answer, by kind' "
                 "counts each apart. Intervals are Wilson 95%.")
    lines.append(f"- The site (docs/benchmarks/latest.json) moves to a run only when it has at least "
                 f"{_QG_MIN_PHISHING} phishing rows, {_QG_MIN_RESOLVING_PHISHING} of them live, "
                 f"{_QG_MIN_CLASSIFIED_PHISHING} Cleanway verdicts on them, and no answer (HTTP 429, an "
                 f"error, a timeout) on at most {_QG_MAX_NO_ANSWER_RATE:.0%} of the live rows. Dead names "
                 "and cautions do not hold a run back: they are measurements, not trouble.")
    if "virustotal" in resolvers:
        lines.append("- VirusTotal verdict is 'dangerous' iff ≥2 vendors out of 70+ flag the URL.")
    asked_names = non_commercial_asked(report)
    asked = [f"{label}{'' if name in resolvers else ' through the in-process analyzer'} ({clause})"
             for name, (label, clause) in NON_COMMERCIAL_RESOLVERS.items() if name in asked_names]
    left_out = [f"{label} ({clause})" for name, (label, clause) in NON_COMMERCIAL_RESOLVERS.items()
                if name not in asked_names]
    if asked:
        lines.append(f"- This run also asked {' and '.join(asked)}. That makes it a non-commercial "
                     "rerun, not a Cleanway publication: it never becomes latest.json.")
    if left_out:
        lines.append(f"- Not compared: {' and '.join(left_out)}. Cleanway is a commercial product. "
                     "Earlier runs in docs/benchmarks/ include them.")
    lines.append("- Cloudflare 1.1.1.1 for Families is treated as 'dangerous' on a "
                 "0.0.0.0 sinkhole, or on NXDOMAIN only when Cloudflare's unfiltered "
                 "resolver still resolves the name. A domain that no longer exists "
                 "is 'not found' for every resolver, not a catch — the sinkhole included.")
    lines.append("- Cleanway's 'caution' band is reported as 'unknown' in recall and FPR so the "
                 "binary comparison is apples-to-apples; 'Every answer, by kind' counts it. The raw "
                 "JSON keeps each Cleanway answer's level, verdict_basis, reason codes, "
                 "checks_incomplete and exists, but names no third-party source per URL: verdict_basis "
                 "'threat_intel' says an external feed listed the host, not which one. Cleanway's "
                 "answer can rest on Google Web Risk, whose results are not ours to republish, and "
                 "naming every other feed would name Google's by elimination; a row that had one also "
                 "leaves out its score.")
    lines.append("")
    lines.append("**Reproduce**: `python3 scripts/eval_fresh_urls.py`.")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# Observability + quality gate
# ─────────────────────────────────────────────────────────────────

def degraded_answers(verdicts: list[Verdict]) -> dict:
    """Of Cleanway's answers (the rows where it gave a level), how many rest
    on checks its time budget cut off (`checks_incomplete`) and how many on a
    site it could not reach (`verdict_basis` 'unreachable'). The gate counts
    only rows with no answer, so a week of cautions from expired keys or open
    circuit breakers passes it; the gate's log line shows these instead."""
    answers = [v for v in verdicts if v.level]
    return {
        "answers": len(answers),
        "checks_incomplete": sum(1 for v in answers if v.checks_incomplete),
        "unreachable": sum(1 for v in answers if v.verdict_basis == "unreachable"),
    }


def degraded_note(counts: dict) -> str:
    n = counts["answers"]

    def share(k: int) -> str:
        return f"{k} ({k / n:.1%})" if n else f"{k} (—)"

    return (f"{n} answers — checks_incomplete {share(counts['checks_incomplete'])}, "
            f"verdict_basis unreachable {share(counts['unreachable'])}")


def _log_unknown_rate(resolver: str, batch: str, verdicts: list[Verdict]) -> None:
    """Emit a one-line summary of classified vs unknown for a batch.

    A high unknown rate on the `cleanway` batch is the fingerprint of
    rate-limit trouble (HTTP 429 → adapter records `unknown`), so
    reading a cron log at 3am should let you eyeball the failure fast.
    """
    total = len(verdicts)
    if total == 0:
        return
    unknown = sum(1 for v in verdicts if v.verdict == "unknown")
    classified = total - unknown
    pct = 100.0 * unknown / total
    log.info(
        "%s %s classified=%d/%d (unknown=%.1f%%)",
        resolver, batch, classified, total, pct,
    )


# Minimum sample sizes / maximum no-answer rate for a benchmark run to be
# considered publishable (i.e. worth flipping latest.json to). These are
# calibrated so a healthy weekly cron always passes but a rate-limit blown
# run — like 2026-06-30's 30/50 unknown, FPR=null — is caught and dropped.
# landing/lib/benchmark.ts recallIsPublishable applies the same numbers
# (tests/test_benchmark_quality_gate.py holds both to the same cases).
_QG_MIN_PHISHING = 100
_QG_MIN_CLASSIFIED_PHISHING = 50
# Live rows (n - not found). The same 50 as the verdicts: a live row is never
# fewer than Cleanway's verdicts on them, so this holds nothing more back, and
# checked first it tells the log the sample died, not that Cleanway went quiet.
# Not 100: 86 of the 200 names of the seed-42 sample on the 2026-11-03 dump
# were already not live (77 NXDOMAIN, 9 with no public address: the probe of
# the fourth review of #395), so a 200-row run has about 114 live rows; 100 would fail
# the week once more than half the sample is dead and keep the site on an
# older report, for a reason its "not publishable" text cannot name.
_QG_MIN_RESOLVING_PHISHING = 50
# Share of live rows that got no answer at all (HTTP 429, an error, a
# timeout): the rate-limit signal. Until 2026-11-03 the limit was on
# "unknown", which since method_version 2 also holds every dead name and
# every caution — measurements, not trouble — and a fresh week's sample is
# about half of those. A report without these counts (method_version 1) is
# still gated on its "unknown".
_QG_MAX_NO_ANSWER_RATE = 0.30
NON_COMMERCIAL_GATE = "non_commercial_resolver"


def _no_answer_rate(stats: dict) -> tuple[Optional[float], str, bool]:
    """(share of rows without an answer, how it was counted, method 2?).
    Method 2: no_answer / resolving, None when nothing resolves. Older
    reports: unknown / (classified + unknown), as before."""
    if isinstance(stats.get("no_answer"), int) and isinstance(stats.get("resolving"), int):
        no_answer, resolving = stats["no_answer"], stats["resolving"]
        rate = no_answer / resolving if resolving > 0 else None
        return rate, f"no_answer={no_answer} of resolving={resolving}", True
    classified = (stats.get("tp", 0) or 0) + (stats.get("fn", 0) or 0) + \
        (stats.get("tn", 0) or 0) + (stats.get("fp", 0) or 0)
    unknown = stats.get("unknown", 0) or 0
    rate = unknown / (classified + unknown) if classified + unknown > 0 else None
    return rate, f"unknown={unknown} of {classified + unknown}", False


@dataclass(frozen=True)
class QualityGateResult:
    """Outcome of the pre-publish quality gate for a benchmark report."""

    passed: bool
    failed_gate: str | None
    detail: str | None


def check_quality_gate(report: dict) -> QualityGateResult:
    """Decide whether a benchmark report is healthy enough to overwrite
    docs/benchmarks/latest.json.

    A single failing check aborts the publish and returns the gate name
    for logging. Runs that fail the gate are still written to their
    dated file — we lose no history, we just don't poison the public
    pointer with junk.

    A report that asked a NON_COMMERCIAL_RESOLVERS service fails first
    (non_commercial_asked, the --local-analyzer row included), and main()
    honours that one even under --no-enforce-quality-gate: latest.json is
    what the site publishes.
    """
    columns = set(report.get("phishing") or {}) | set(report.get("safe") or {})
    non_commercial = [name if name in columns else f"{name} (through cleanway_local)"
                      for name in non_commercial_asked(report)]
    if non_commercial:
        return QualityGateResult(
            passed=False,
            failed_gate=NON_COMMERCIAL_GATE,
            detail=f"asked {', '.join(non_commercial)}, whose free API bars a commercial product",
        )

    n_phishing = report.get("n_phishing", 0)
    if n_phishing < _QG_MIN_PHISHING:
        return QualityGateResult(
            passed=False,
            failed_gate="n_phishing_below_min",
            detail=f"n_phishing={n_phishing} < {_QG_MIN_PHISHING}",
        )

    cleanway_phish = (report.get("phishing") or {}).get("cleanway") or {}
    phish_rate, phish_counted, method_two = _no_answer_rate(cleanway_phish)
    if method_two and cleanway_phish["resolving"] < _QG_MIN_RESOLVING_PHISHING:
        return QualityGateResult(
            passed=False,
            failed_gate="phishing_resolving_below_min",
            detail=(
                f"cleanway phishing resolving={cleanway_phish['resolving']} < {_QG_MIN_RESOLVING_PHISHING} "
                f"(not_found={cleanway_phish.get('not_found')} of n={cleanway_phish.get('n')})"
            ),
        )

    tp = cleanway_phish.get("tp", 0) or 0
    fn = cleanway_phish.get("fn", 0) or 0
    unknown_phish = cleanway_phish.get("unknown", 0) or 0
    classified_phish = tp + fn
    if classified_phish < _QG_MIN_CLASSIFIED_PHISHING:
        return QualityGateResult(
            passed=False,
            failed_gate="phishing_classified_below_min",
            detail=(
                f"cleanway phishing classified={classified_phish} "
                f"< {_QG_MIN_CLASSIFIED_PHISHING} (unknown={unknown_phish})"
            ),
        )

    if phish_rate is not None and phish_rate > _QG_MAX_NO_ANSWER_RATE:
        return QualityGateResult(
            passed=False,
            failed_gate="phishing_no_answer_rate_too_high" if method_two else "phishing_unknown_rate_too_high",
            detail=(
                f"cleanway phishing {'no_answer' if method_two else 'unknown'}_rate={phish_rate:.1%} "
                f"> {_QG_MAX_NO_ANSWER_RATE:.0%} ({phish_counted})"
            ),
        )

    if cleanway_phish.get("recall") is None:
        return QualityGateResult(
            passed=False,
            failed_gate="phishing_recall_null",
            detail="cleanway phishing recall is null (no classified samples)",
        )

    # Safe batch: allow either a real FPR or a low no-answer rate. If we got
    # rate-limited on the safe batch but the FPR came out non-null anyway,
    # that's fine — we just can't trust a safe batch with no FPR and mostly
    # no answer to represent our false-positive rate. Cautions on real sites
    # are answers (the report counts them apart), not rate-limit trouble.
    cleanway_safe = (report.get("safe") or {}).get("cleanway") or {}
    fpr = cleanway_safe.get("fpr")
    n_safe = report.get("n_safe", 0) or 0
    if fpr is None:
        if n_safe <= 0:
            return QualityGateResult(
                passed=False,
                failed_gate="safe_fpr_null_no_samples",
                detail="cleanway safe fpr is null and no safe samples were fetched",
            )
        safe_rate, safe_counted, safe_two = _no_answer_rate(cleanway_safe)
        if not safe_two:  # method 1: as before, every unknown over the batch
            safe_rate = (cleanway_safe.get("unknown", 0) or 0) / n_safe
            safe_counted = f"unknown={cleanway_safe.get('unknown', 0) or 0} of n_safe={n_safe}"
        if safe_rate is None or safe_rate > _QG_MAX_NO_ANSWER_RATE:
            return QualityGateResult(
                passed=False,
                failed_gate="safe_no_answer_rate_too_high" if safe_two else "safe_unknown_rate_too_high",
                detail=(
                    f"cleanway safe fpr=None and {'no_answer' if safe_two else 'unknown'}_rate="
                    f"{'n/a' if safe_rate is None else f'{safe_rate:.1%}'} "
                    f"> {_QG_MAX_NO_ANSWER_RATE:.0%} ({safe_counted})"
                ),
            )

    return QualityGateResult(passed=True, failed_gate=None, detail=None)


def _update_latest_pointer(json_out: Path) -> None:
    """Point docs/benchmarks/latest.json at the just-written report.

    Uses os.replace() for atomicity — the pointer never observably
    references a nonexistent file, even mid-refresh. A symlink is
    preferred (matches historical shell behaviour) but plain file copy
    is the fallback on systems where symlinks aren't available.
    """
    latest = json_out.parent / "latest.json"
    tmp = json_out.parent / "latest.json.tmp"
    try:
        if tmp.exists() or tmp.is_symlink():
            tmp.unlink()
        try:
            tmp.symlink_to(json_out.name)
        except (OSError, NotImplementedError):
            # Fall back to a plain copy on FSes that don't allow symlinks.
            tmp.write_text(json_out.read_text(encoding="utf-8"), encoding="utf-8")
        os.replace(tmp, latest)
    finally:
        if tmp.exists() or tmp.is_symlink():
            try:
                tmp.unlink()
            except OSError:
                pass


def _is_published(json_out: Path) -> bool:
    """True when latest.json, next to `json_out`, points to it.

    latest.json is a symlink (_update_latest_pointer), so rewriting the file it
    names changes what the site shows exactly as moving the pointer would. The
    plain-copy fallback is a file of its own: rewriting the original leaves it be.
    """
    latest = json_out.parent / "latest.json"
    try:
        return latest.exists() and json_out.exists() and os.path.samefile(latest, json_out)
    except OSError:
        return False


async def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--sample", type=int, default=500,
                   help="URLs per side (phishing + legit). Default 500.")
    p.add_argument("--seed", type=int, default=benchmark_method.PHISHING_SAMPLE_SEED,
                   help="Seed of the random phishing sample drawn from PhishTank's dump "
                        f"(default {benchmark_method.PHISHING_SAMPLE_SEED}; recorded in the report).")
    p.add_argument("--window-days", type=int, default=benchmark_method.WINDOW_DAYS,
                   help="Draw the phishing sample from the rows submitted in this many days "
                        f"before the dump's newest row (default {benchmark_method.WINDOW_DAYS}; "
                        "recorded in the report). 0 = the whole dump, links of any age.")
    p.add_argument("--out-tag", default=None,
                   help="Tag appended to output filename. Default: timestamp.")
    p.add_argument("--virustotal", action=argparse.BooleanOptionalAction, default=False,
                   help="Also ask VirusTotal (needs VT_API_KEY). Off by default: its public API "
                        "bars commercial products (NON_COMMERCIAL_RESOLVERS), so such a run "
                        "never becomes latest.json.")
    p.add_argument("--gsb", action=argparse.BooleanOptionalAction, default=False,
                   help="Also ask Google Safe Browsing v4 (needs GOOGLE_SAFE_BROWSING_KEY). Off by "
                        "default, for the same reason as --virustotal.")
    p.add_argument("--local-analyzer", action="store_true",
                   help="ALSO run full in-process analyzer (16 sources). "
                        "Requires repo dependencies + free intel sources. "
                        "Doubles wall-clock but gives authed-endpoint baseline. "
                        "It is the server's own code: it asks Safe Browsing v4 when "
                        "GOOGLE_SAFE_BROWSING_API_KEY/_KEY is set, Web Risk with WEB_RISK_API_KEY. "
                        "A run whose analyzer asked Safe Browsing v4 never becomes latest.json, "
                        "like --gsb.")
    p.add_argument("--enforce-quality-gate", dest="enforce_quality_gate",
                   action="store_true", default=True,
                   help="Only update docs/benchmarks/latest.json if the run "
                        "passes the pre-publish quality gate (default: on). "
                        "The dated JSON+MD are always written, regardless.")
    p.add_argument("--no-enforce-quality-gate", dest="enforce_quality_gate",
                   action="store_false",
                   help="Skip the pre-publish quality gate — always flip "
                        "latest.json to today's run. Useful for local smoke "
                        "runs where you don't care about the pointer.")
    p.add_argument("--legit-source", choices=("curated", "tranco"), default="curated",
                   help="Legitimate sample: 'curated' (default) = real Russian sites "
                        "outside our allowlist, data/benchmark_legit_ru.txt — the only "
                        "source that can measure false positives; 'tranco' = the old "
                        "Tranco sample the server answers without analysis.")
    p.add_argument("--verify-legit-sample", action="store_true",
                   help="Only re-check data/benchmark_legit_ru.txt (parses, big enough, "
                        "outside the allowlist, every host resolves) and exit.")
    p.add_argument("--out-dir", type=Path, default=DOCS,
                   help="Where the dated JSON+MD (and, if the gate passes, latest.json) "
                        "go. Default docs/benchmarks; point a local smoke run elsewhere.")
    args = p.parse_args()
    if args.window_days < 0:
        p.error("--window-days must be 0 (the whole dump) or more")

    if args.verify_legit_sample:
        return await benchmark_legit.verify_legit_sample()

    out_dir: Path = args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)

    # ── Fetch samples ────────────────────────────────────────────
    try:
        dump = await fetch_phishtank_dump()
    except Exception as exc:
        log.error("PhishTank fetch failed: %s", exc)
        dump = PhishtankDump([])
    site_of, site_rule = benchmark_method.site_rule()
    pool, window = benchmark_method.recent_window(
        dump.submitted if dump.submitted is not None else [None] * len(dump.urls), args.window_days,
        now=_run_clock())
    if dump.urls and not pool:
        log.error("PhishTank: no row of %d has a readable submission_time at or before the run's clock "
                  "(%d undated, %d dated after it), so none is known to be from the last %d days — "
                  "no phishing sample", len(dump.urls), window["undated_rows"], window["future_rows"],
                  args.window_days)
    picked, sampling = benchmark_method.sample_phishing(
        dump.urls, args.sample, seed=args.seed, host_of=domain_of, site_of=site_of, pool=pool)
    phishing_urls = [dump.urls[i] for i in picked]
    sampling.update({
        "window": window,
        "dump_rows": len(dump.urls),
        "site_rule": site_rule,
        "dump_sha256": dump.sha256 or None,
        "submitted": (benchmark_method.submitted_span(dump.submitted[i] for i in picked)
                      if dump.submitted else None),
    })
    log.info("phishing sample: %d rows from %d sites (seed=%d; of %d rows on %d sites, %s – %s)",
             sampling["n"], sampling["sites"], args.seed, sampling["pool_rows"], sampling["pool_sites"],
             window["start"] or "the oldest row", window["end"] or "the newest")
    legit_urls, legit_sites, legit_sources = pick_legit(args.legit_source, args.sample)

    if not phishing_urls or not legit_urls:
        log.error("not enough samples to benchmark (phish=%d legit=%d)",
                  len(phishing_urls), len(legit_urls))
        return 1

    log.info("Final samples: %d phishing, %d legit",
             len(phishing_urls), len(legit_urls))

    # ── Run each resolver against both batches ───────────────────
    # A key in the environment no longer brings a NON_COMMERCIAL_RESOLVERS
    # service in: only its flag does, and then only with its key.
    resolvers = ["cleanway", "phishtank", "cloudflare_families"]
    for name, wanted, key, env in (("gsb", args.gsb, GSB_KEY, "GOOGLE_SAFE_BROWSING_KEY"),
                                   ("virustotal", args.virustotal, VT_KEY, "VT_API_KEY")):
        if wanted and not key:
            log.warning("--%s without %s: %s skipped", name, env, name)
        elif wanted:
            log.warning("asking %s: %s — a non-commercial rerun, it never becomes latest.json",
                        name, NON_COMMERCIAL_RESOLVERS[name][1])
            # The historical column order: cleanway, gsb, phishtank, cloudflare, virustotal.
            if name == "gsb":
                resolvers.insert(1, name)
            else:
                resolvers.append(name)
    # Read before the run, so settings that do not load stop it before any lookup.
    local_lookup: dict[str, str] = {}
    if args.local_analyzer:
        resolvers.insert(1, "cleanway_local")
        local_lookup[LOCAL_GOOGLE_LOOKUP] = local_google_lookup()
        if local_lookup[LOCAL_GOOGLE_LOOKUP] == "safe_browsing_v4":
            log.warning("--local-analyzer asks Safe Browsing v4 (a v4 key is set, WEB_RISK_API_KEY "
                        "is not): %s — a non-commercial rerun, it never becomes latest.json",
                        NON_COMMERCIAL_RESOLVERS["gsb"][1])

    # Resolvers run side by side: each paces itself and talks to a different
    # service, so the run takes as long as the slowest one (Cleanway's paced
    # installs; VirusTotal, at 16 s a lookup, when asked) instead of the sum
    # of all of them. Within a resolver the two batches are interleaved
    # (interleave_batches). The existence probe runs beside them: one
    # question per URL, the same for every resolver's row.
    async def _both(r: str) -> tuple[list[Verdict], list[Verdict], dict[str, str]]:
        start = _utc_now()
        phish, safe = await run_resolver_on_both(r, phishing_urls, legit_urls)
        if r != EXISTENCE_PROBE:
            _log_unknown_rate(r, "phishing", phish)
            _log_unknown_rate(r, "safe", safe)
        return phish, safe, {"start": start, "end": _utc_now()}

    asked = [*resolvers, EXISTENCE_PROBE]
    runs = dict(zip(asked, await asyncio.gather(*[_both(r) for r in asked])))
    probe = runs.pop(EXISTENCE_PROBE)
    phishing_results: dict[str, list[Verdict]] = {r: o[0] for r, o in runs.items()}
    safe_results: dict[str, list[Verdict]] = {r: o[1] for r, o in runs.items()}
    windows: dict[str, dict[str, str]] = {r: o[2] for r, o in runs.items()}
    existence = {"phishing": existence_of_rows(probe[0], phishing_results),
                 "safe": existence_of_rows(probe[1], safe_results)}
    log.info("existence: phishing %s, legit %s",
             benchmark_method.existence_counts(existence["phishing"]),
             benchmark_method.existence_counts(existence["safe"]))

    # ── Classify + build report ──────────────────────────────────
    results = {"phishing": phishing_results, "safe": safe_results}
    counted = {batch: {r: outcomes_of(results[batch][r], existence[batch]) for r in resolvers}
               for batch in results}
    report: dict = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        # 2 since 2026-11-03 (benchmark_method): reports without it are
        # counted by the old rules and are not comparable.
        "method_version": benchmark_method.METHOD_VERSION,
        "n_phishing": len(phishing_urls),
        "n_safe": len(legit_urls),
        "sources": {
            "phishing": (f"PhishTank online-valid ({len(dump.urls)} URLs): {sampling['n']} "
                         + (f"of the {sampling['pool_rows']} submitted in the {window['days']} days before "
                            "its newest row" if window["start"] else "of all its rows, links of any age")
                         + f", a random sample (seed={args.seed}) of their sites, each site equally "
                         f"likely: each host once, at most {sampling['max_per_site']} per site, a site "
                         "being a registrable domain or a hosting platform's tenant (details: `sampling`)."),
            # `legit` and `legit_outside_allowlist`: see pick_legit. The
            # landing publishes a false-positive rate only when the latter is
            # True (landing/lib/benchmark.ts falsePositiveRateIsPublishable).
            **legit_sources,
            "existence": ("one question per URL, about its own host name ('www.' kept), to "
                          "Cloudflare's unfiltered resolver "
                          f"({CLOUDFLARE_UNFILTERED_DOH}, A record; AAAA too when no A address is "
                          "public, no A record at all included) at the start of the run: an NXDOMAIN "
                          "there is 'not found' for every resolver, and so is an answer with no public "
                          "address in A and AAAA together (neither record, or only non-public ones: "
                          "0.0.0.0, a private range — a takedown); any other answer is a live row. Only "
                          "when it cannot tell (SERVFAIL, a timeout) do the resolvers' own answers "
                          "decide (Families' control query, Cleanway's `exists`)."),
            "cleanway_api": CLEANWAY_API,
            "cleanway_identity": cleanway_identity_note(),
            **local_lookup,
        },
        # How the phishing sample was drawn: seed, cap, the dump it came from.
        "sampling": sampling,
        "existence": {batch: benchmark_method.existence_counts(rows) for batch, rows in existence.items()},
        # When the Cleanway checks ran: the UTC day whose paid-source budgets
        # (IPQS, LLM judge) they could spend.
        "cleanway_window_utc": windows.get("cleanway"),
        # How Cleanway answered each real site, by slice — null for a Tranco run.
        "cleanway_on_legit": (
            benchmark_legit.legit_breakdown(counted["safe"]["cleanway"], legit_sites)
            if legit_sites is not None else None
        ),
        "phishing": {
            r: classify(phishing_results[r], "dangerous", existence["phishing"]) for r in resolvers
        },
        "safe": {
            r: classify(safe_results[r], "safe", existence["safe"]) for r in resolvers
        },
        "raw": {
            # Every answer as given, and how it was counted ("outcome").
            "phishing": {r: _raw_rows(r, phishing_results[r], counted["phishing"][r]) for r in resolvers},
            "safe": {r: _raw_rows(r, safe_results[r], counted["safe"][r]) for r in resolvers},
            # The probe's answer and each row's existence ("status").
            "existence": {
                "phishing": _probe_rows(probe[0], existence["phishing"]),
                "safe": _probe_rows(probe[1], existence["safe"]),
            },
            "phishing_urls": phishing_urls,
            "legit_urls": legit_urls,
        },
    }

    # ── Pre-publish quality gate ─────────────────────────────────
    # The dated files are always written — history is cheap. `latest.json`
    # is what the landing page + methodology page render, so we only flip
    # it when the run is trustworthy. A rate-limit blowout that shows
    # 30/50 unknown and FPR=null must NOT become the public number.
    gate = check_quality_gate(report)
    publish = gate.passed or (not args.enforce_quality_gate and gate.failed_gate != NON_COMMERCIAL_GATE)

    tag = args.out_tag or time.strftime("%Y-%m-%d", time.gmtime())
    json_out = out_dir / f"{tag}-fresh-urls.json"
    if not publish and _is_published(json_out):
        # A second run the same UTC day, whose tag names the very file
        # latest.json points to: writing it would publish the run the gate
        # just refused (or a VirusTotal / Safe Browsing rerun) through the
        # pointer it never moved. It keeps the day's tag plus the time, a name
        # that sorts after the published one.
        tag = f"{tag}T{time.strftime('%H%M%S', time.gmtime())}Z"
        log.warning("latest.json points to %s, and this run is not published: writing it as %s instead",
                    json_out.name, f"{tag}-fresh-urls.json")
        json_out = out_dir / f"{tag}-fresh-urls.json"
    md_out = out_dir / f"{tag}-fresh-urls.md"
    with open(json_out, "w") as f:
        json.dump(report, f, indent=2)
    with open(md_out, "w") as f:
        f.write(render_md(report))

    log.info("wrote %s", json_out)
    log.info("wrote %s", md_out)

    if not args.enforce_quality_gate and gate.failed_gate != NON_COMMERCIAL_GATE:
        log.warning(
            "quality gate DISABLED via --no-enforce-quality-gate — "
            "flipping latest.json regardless of result (passed=%s)",
            gate.passed,
        )
        _update_latest_pointer(json_out)
        log.info("updated %s → %s", out_dir / "latest.json", json_out.name)
    elif gate.passed:
        _update_latest_pointer(json_out)
        log.info(
            "quality gate PASSED — updated %s → %s",
            out_dir / "latest.json", json_out.name,
        )
        print(f"QUALITY_GATE=pass json={json_out.name}")
    else:
        log.warning(
            "QUALITY GATE FAILED gate=%s detail=%s — "
            "keeping existing latest.json (dated file %s was still written)",
            gate.failed_gate, gate.detail, json_out.name,
        )
        print(
            f"QUALITY_GATE=fail gate={gate.failed_gate} "
            f"detail={gate.detail} json={json_out.name}"
        )
    # Beside the gate's decision, not part of it: how many of Cleanway's
    # answers rest on cut-off checks or an unreachable site, so a degraded
    # week that passes the gate is still seen (degraded_answers).
    log.info("cleanway answers degraded (not gated): %s",
             "; ".join(f"{label} {degraded_note(degraded_answers(results[batch]['cleanway']))}"
                       for label, batch in (("phishing", "phishing"), ("legit", "safe"))))

    # ── Console summary ──────────────────────────────────────────
    print()
    print(render_md({k: v for k, v in report.items() if k != "raw"}))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

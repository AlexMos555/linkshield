#!/usr/bin/env python3
"""Fresh-URL benchmark against Cleanway + 4 public competitors.

Strategy doc reference: "Validation as step-zero" — measure
real-world recall and FPR against URLs the model has NEVER seen
at training time, side-by-side with Google Safe Browsing,
PhishTank, Cloudflare 1.1.1.1 for Families and VirusTotal's
70-vendor aggregate.

Output goes to docs/benchmarks/<YYYY-MM>-fresh-urls.json (raw)
and .md (human-readable table). This is the source-of-truth
for any "X% detection rate" claim on the landing page.

Usage:
    # Free-tier run (Cleanway + GSB + PhishTank + Cloudflare):
    python3 scripts/eval_fresh_urls.py

    # Include VirusTotal aggregate (needs free API key):
    VT_API_KEY=... python3 scripts/eval_fresh_urls.py

    # Small smoke run (50 URLs each side):
    python3 scripts/eval_fresh_urls.py --sample 50

Each competitor is wrapped in a small async adapter that returns
{"verdict": "safe"|"dangerous"|"unknown", "latency_ms": float}.
Adapters fail open — if a service errors out we record "unknown"
and don't count it against recall.

This file is INTENTIONALLY long and verbose — the report is the
moat. Anyone in the world should be able to read this script and
reproduce our numbers within ±2%.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import io
import json
import logging
import os
import random
import statistics
import sys
import time
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

import httpx

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
URLHAUS_RECENT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
PHISHTANK_FEED_URL = "https://data.phishtank.com/data/online-valid.csv.gz"

# Rough per-request budget. Cleanway is hot and on-network so we
# can run it concurrently with -c 20; Google SB has tight quotas;
# Cloudflare 1.1.1.1 for Families is generous; VirusTotal free
# tier is 4 req/min.
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
    # so the 16s throttle + 65s cooldown are unnecessary — drop to a light
    # 0.3s spacing (still polite, avoids hammering) so a 200-sample run fits
    # comfortably inside the CI timeout.
    "cleanway": 0.3 if BENCHMARK_BYPASS_TOKEN else 16.0,
    "virustotal": 16.0,  # VT free tier 4 req/min
}

# Cooldown between resolver batches (phishing → safe). The Cleanway public
# endpoint enforces a 5/min/IP window; if we start the safe batch before the
# window drains, we get HTTP 429 on the first ~5 URLs and record them as
# `unknown`. 60s drains the window; +5s gives clock-skew headroom.
CLEANWAY_BATCH_COOLDOWN_S = 65.0


# ─────────────────────────────────────────────────────────────────
# URL helpers
# ─────────────────────────────────────────────────────────────────

def domain_of(url: str) -> str:
    """Extract bare hostname from a URL or domain string.

    NB: do NOT use str.lstrip('www.') — it strips any CHARACTERS
    from {w, ., space}, so 'wsj.com' becomes 'sj.com'. Use
    removeprefix() which is exact-prefix matching.
    """
    s = url.strip()
    if "://" not in s:
        s = "http://" + s
    try:
        host = urlparse(s).hostname or ""
    except Exception:
        host = ""
    host = host.lower().strip()
    if host.startswith("www."):
        host = host[4:]
    return host


def dedup_urls(urls: list[str]) -> list[str]:
    """Keep first occurrence per registrable-ish key. Cheaper than
    proper eTLD+1 parsing — for benchmarking it's good enough."""
    seen = set()
    out = []
    for u in urls:
        h = domain_of(u)
        if not h or h in seen:
            continue
        seen.add(h)
        out.append(u)
    return out


# ─────────────────────────────────────────────────────────────────
# Sample sources
# ─────────────────────────────────────────────────────────────────

async def fetch_urlhaus_recent(limit: int) -> list[str]:
    """URLhaus daily CSV: ~500-1000 recent malicious URLs. No auth."""
    log.info("fetching URLhaus recent feed …")
    async with httpx.AsyncClient(timeout=30.0) as client:
        r = await client.get(URLHAUS_RECENT_URL)
        r.raise_for_status()
        # CSV is gzipped + has comment lines starting with '#'.
        text = r.text
    out = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        # columns: id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter
        parts = next(csv.reader(io.StringIO(line), quotechar='"'))
        if len(parts) < 3:
            continue
        url = parts[2].strip().strip('"')
        if not url:
            continue
        out.append(url)
        if len(out) >= limit:
            break
    log.info("URLhaus: %d urls", len(out))
    return out


async def fetch_phishtank_recent(limit: int) -> list[str]:
    """PhishTank online-valid.csv.gz — ALL active verified phish.
    Anonymous download works; PHISHTANK_API_KEY is optional and
    only raises rate limits. The dump is 1-3 MB gzipped."""
    log.info("fetching PhishTank online-valid feed …")
    async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
        # Anonymous download still works — but they politely ask
        # for a User-Agent so we don't look like a bot. They also
        # redirect to a signed CDN URL — follow_redirects is required.
        r = await client.get(
            PHISHTANK_FEED_URL,
            headers={"User-Agent": "Cleanway-benchmark/1.0"},
        )
        r.raise_for_status()
        body = r.content
    # Gzipped CSV with header row: phish_id,url,phish_detail_url,...
    import gzip
    text = gzip.decompress(body).decode("utf-8", errors="ignore")
    out = []
    rows = csv.DictReader(io.StringIO(text))
    for row in rows:
        u = (row.get("url") or "").strip()
        if u:
            out.append(u)
        if len(out) >= limit * 3:  # over-fetch, dedup later
            break
    out = dedup_urls(out)[:limit]
    log.info("PhishTank: %d urls", len(out))
    return out


def fetch_tranco_legit(limit: int) -> list[str]:
    """Random sample from local Tranco top-1M CSV.

    Skips the top-100 (too easily 'safe' by reputation; we want
    moderately-popular but not famous sites in the control group).
    """
    src = DATA / "top-1m.csv"
    if not src.exists():
        log.warning("data/top-1m.csv missing — using top_100k.json fallback")
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


async def check_cleanway(client: httpx.AsyncClient, url: str) -> Verdict:
    """GET /api/v1/public/check/{domain} on api.cleanway.ai.
    Lightweight public endpoint — rule + ML scoring, NO threat-
    intel API fan-out (intentional per api/routers/public.py:80).

    On HTTP 429 (rate-limited): wait 25s (one full rate-limit
    window + 5s slack) and retry once. Without this retry, a
    benchmark batch that drifts past the 5/min IP cap records the
    affected URLs as 'unknown', which artificially deflates recall.
    A single retry per URL caps the worst-case batch time at
    2 × (N × MIN_INTERVAL_S + N × 25s).
    """
    d = domain_of(url)
    if not d:
        return Verdict("cleanway", "unknown", detail="bad_domain")
    t0 = time.monotonic()
    last_status: int | None = None
    try:
        headers = (
            {"X-Cleanway-Benchmark": BENCHMARK_BYPASS_TOKEN}
            if BENCHMARK_BYPASS_TOKEN
            else None
        )
        for attempt in (1, 2):
            r = await client.get(
                f"{CLEANWAY_API}/api/v1/public/check/{d}",
                headers=headers,
                timeout=8.0,
            )
            last_status = r.status_code
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
        elapsed = (time.monotonic() - t0) * 1000
        if r.status_code != 200:
            tag = "rate_limited" if r.status_code == 429 else f"status={r.status_code}"
            return Verdict("cleanway", "unknown", latency_ms=elapsed, detail=tag)
        data = r.json()
        level = (data.get("level") or "").lower()
        score = data.get("score")
        v = "dangerous" if level == "dangerous" else (
            "safe" if level == "safe" else "unknown"
        )
        return Verdict("cleanway", v, score=score,
                       latency_ms=elapsed, detail=level)
    except Exception as exc:
        return Verdict("cleanway", "unknown",
                       latency_ms=(time.monotonic() - t0) * 1000,
                       detail=f"err:{exc}")


# Lazy-imported analyzer entry-point so the script can run without
# the full repo dependencies installed when only public-mode is used.
_analyze_domain = None


def _load_analyzer():
    global _analyze_domain
    if _analyze_domain is not None:
        return _analyze_domain
    # Ensure repo root is on sys.path so 'api.*' imports resolve.
    repo_root = str(ROOT)
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from api.services.analyzer import analyze_domain  # noqa: E402
    _analyze_domain = analyze_domain
    return _analyze_domain


async def check_cleanway_local(client: httpx.AsyncClient, url: str) -> Verdict:
    """Run the FULL analyzer in-process — what authed
    /api/v1/check would return. Calls all 18 parallel checks
    including 16 threat-intel sources.

    Free sources (URLhaus / ThreatFox / MalwareBazaar / Feodo /
    Cloudflare DoH / crt.sh) work without keys. Paid sources
    (Safe Browsing / PhishTank API / IPQS / AlienVault) fail
    silently through the circuit breakers and return False —
    so this is a LOWER-BOUND on the full authed-endpoint
    performance (in production those keys are set).

    No Redis needed — cache is opt-in and falls through cleanly
    on connection failure.
    """
    d = domain_of(url)
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
        return Verdict("cleanway_local", v, score=score,
                       latency_ms=elapsed, detail=level)
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


async def check_cloudflare_families(client: httpx.AsyncClient, url: str) -> Verdict:
    """Cloudflare 1.1.1.1 for Families (security): NXDOMAIN on
    known-malicious. We do a DoH lookup against family.cloudflare-
    dns.com and check the response code."""
    d = domain_of(url)
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
        # Status 3 = NXDOMAIN. Cloudflare's family resolver returns
        # 0.0.0.0 for blocked domains; we treat both as 'dangerous'.
        status = data.get("Status", 0)
        answers = data.get("Answer", []) or []
        blocked_ips = {"0.0.0.0", "::"}
        ip_blocked = any(
            (a.get("data") or "").strip() in blocked_ips
            for a in answers if a.get("type") in (1, 28)
        )
        if status == 3 or ip_blocked:
            return Verdict("cloudflare_families", "dangerous",
                           latency_ms=elapsed,
                           detail=f"status={status} ip_block={ip_blocked}")
        if status == 0 and answers:
            return Verdict("cloudflare_families", "safe",
                           latency_ms=elapsed, detail="resolved")
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
}

CONCURRENCY["cleanway_local"] = 4  # 18 parallel checks per URL, easy on the analyzer


# ─────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────

async def run_resolver(name: str, urls: list[str]) -> list[Verdict]:
    """Run a resolver across all URLs, respecting its concurrency
    limit AND the per-resolver MIN_INTERVAL_S throttle. Returns a
    Verdict per URL, same order as the input list."""
    adapter = ADAPTERS[name]
    sem = asyncio.Semaphore(CONCURRENCY[name])
    min_interval = MIN_INTERVAL_S.get(name, 0.0)
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
            name, len(urls), CONCURRENCY[name], min_interval,
        )
        results = await asyncio.gather(*[_one(u) for u in urls])
    return results


def classify(verdicts: list[Verdict], expected: str) -> dict:
    """expected ∈ {'dangerous', 'safe'}.

    Returns a dict with TP/FP/TN/FN/unknown counts + recall, FPR,
    precision, F1 assuming the resolver claims to detect the
    expected class. For the 'dangerous' batch, recall = TP/(TP+FN);
    for the 'safe' batch we care about FPR.
    """
    tp = fp = tn = fn = unk = 0
    for v in verdicts:
        if v.verdict == "unknown":
            unk += 1
            continue
        if expected == "dangerous":
            if v.verdict == "dangerous":
                tp += 1
            else:
                fn += 1
        else:
            if v.verdict == "dangerous":
                fp += 1
            else:
                tn += 1
    recall = tp / (tp + fn) if (tp + fn) > 0 else None
    fpr = fp / (fp + tn) if (fp + tn) > 0 else None
    precision = tp / (tp + fp) if (tp + fp) > 0 else None
    f1 = None
    if recall is not None and precision is not None and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)
    latencies = [v.latency_ms for v in verdicts if v.latency_ms > 0]
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "unknown": unk,
        "recall": recall, "fpr": fpr,
        "precision": precision, "f1": f1,
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
    for name, m in report["phishing"].items():
        def _pct(x):
            return f"{x*100:.1f}%" if x is not None else "—"
        def _n(x):
            return f"{x:.0f}" if x is not None else "—"
        lines.append(
            f"| {name} | {_pct(m['recall'])} | {_pct(m['precision'])} "
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
            f"| {name} | {_pct(m['fpr'])} | {m['fp']} | {m['tn']} "
            f"| {m['unknown']} | {_n(m['latency_p50_ms'])} |"
        )
    lines.append("")
    lines.append("## Methodology")
    lines.append("")
    lines.append("- Phishing samples are fresh URLhaus + PhishTank entries; "
                 "the Cleanway ML model has NOT been trained on these specific URLs.")
    lines.append("- Legit samples are random Tranco top-100k entries (rank 100-100000), "
                 "skipping the top-100 to avoid 'too easy' baseline reputation.")
    lines.append("- We send DOMAIN only to Cleanway (server-blind invariant). "
                 "GSB / PhishTank / VT receive the full URL.")
    lines.append("- 'Unknown' = the resolver didn't return a definitive verdict "
                 "(rate-limited, not indexed, error). 'Unknown' is NOT counted as "
                 "either correct or incorrect — it's reported separately.")
    lines.append("- VirusTotal verdict is 'dangerous' iff ≥2 vendors out of 70+ flag the URL.")
    lines.append("- Cloudflare 1.1.1.1 for Families is treated as 'dangerous' on "
                 "NXDOMAIN or 0.0.0.0 sinkhole response.")
    lines.append("- Cleanway's 'caution' band is reported as 'unknown' here so the "
                 "binary comparison is apples-to-apples. The raw JSON shows the per-"
                 "resolver level distribution.")
    lines.append("")
    lines.append("**Reproduce**: `python3 scripts/eval_fresh_urls.py` "
                 "(set `VT_API_KEY` for VirusTotal).")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# Observability + quality gate
# ─────────────────────────────────────────────────────────────────

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


# Minimum sample sizes / maximum unknown rate for a benchmark run to be
# considered publishable (i.e. worth flipping latest.json to). These are
# calibrated so a healthy weekly cron always passes but a rate-limit blown
# run — like 2026-06-30's 30/50 unknown, FPR=null — is caught and dropped.
_QG_MIN_PHISHING = 100
_QG_MIN_CLASSIFIED_PHISHING = 50
_QG_MAX_UNKNOWN_RATE = 0.30


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
    """
    n_phishing = report.get("n_phishing", 0)
    if n_phishing < _QG_MIN_PHISHING:
        return QualityGateResult(
            passed=False,
            failed_gate="n_phishing_below_min",
            detail=f"n_phishing={n_phishing} < {_QG_MIN_PHISHING}",
        )

    cleanway_phish = (report.get("phishing") or {}).get("cleanway") or {}
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

    denom_phish = classified_phish + unknown_phish
    if denom_phish > 0:
        rate_phish = unknown_phish / denom_phish
        if rate_phish > _QG_MAX_UNKNOWN_RATE:
            return QualityGateResult(
                passed=False,
                failed_gate="phishing_unknown_rate_too_high",
                detail=(
                    f"cleanway phishing unknown_rate={rate_phish:.1%} "
                    f"> {_QG_MAX_UNKNOWN_RATE:.0%}"
                ),
            )

    if cleanway_phish.get("recall") is None:
        return QualityGateResult(
            passed=False,
            failed_gate="phishing_recall_null",
            detail="cleanway phishing recall is null (no classified samples)",
        )

    # Safe batch: allow either a real FPR or a low unknown rate. If we got
    # rate-limited on the safe batch (unknown-heavy) but the FPR came out
    # non-null anyway, that's fine — we just can't trust an all-unknown
    # safe batch with no FPR to represent our false-positive rate.
    cleanway_safe = (report.get("safe") or {}).get("cleanway") or {}
    fpr = cleanway_safe.get("fpr")
    n_safe = report.get("n_safe", 0) or 0
    unknown_safe = cleanway_safe.get("unknown", 0) or 0
    if fpr is None:
        if n_safe <= 0:
            return QualityGateResult(
                passed=False,
                failed_gate="safe_fpr_null_no_samples",
                detail="cleanway safe fpr is null and no safe samples were fetched",
            )
        rate_safe = unknown_safe / n_safe
        if rate_safe > _QG_MAX_UNKNOWN_RATE:
            return QualityGateResult(
                passed=False,
                failed_gate="safe_unknown_rate_too_high",
                detail=(
                    f"cleanway safe fpr=None and unknown_rate={rate_safe:.1%} "
                    f"> {_QG_MAX_UNKNOWN_RATE:.0%}"
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


async def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--sample", type=int, default=500,
                   help="URLs per side (phishing + legit). Default 500.")
    p.add_argument("--out-tag", default=None,
                   help="Tag appended to output filename. Default: timestamp.")
    p.add_argument("--no-virustotal", action="store_true",
                   help="Skip VT even if VT_API_KEY is set.")
    p.add_argument("--local-analyzer", action="store_true",
                   help="ALSO run full in-process analyzer (16 sources). "
                        "Requires repo dependencies + free intel sources. "
                        "Doubles wall-clock but gives authed-endpoint baseline.")
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
    args = p.parse_args()

    DOCS.mkdir(parents=True, exist_ok=True)

    # ── Fetch samples ────────────────────────────────────────────
    try:
        urlhaus = await fetch_urlhaus_recent(args.sample)
    except Exception as exc:
        log.error("URLhaus fetch failed: %s", exc)
        urlhaus = []
    try:
        phishtank = await fetch_phishtank_recent(args.sample)
    except Exception as exc:
        log.error("PhishTank fetch failed: %s", exc)
        phishtank = []
    phishing_urls = dedup_urls(urlhaus + phishtank)[:args.sample]
    legit_urls = fetch_tranco_legit(args.sample)

    if not phishing_urls or not legit_urls:
        log.error("not enough samples to benchmark (phish=%d legit=%d)",
                  len(phishing_urls), len(legit_urls))
        return 1

    log.info("Final samples: %d phishing, %d legit",
             len(phishing_urls), len(legit_urls))

    # ── Run each resolver against both batches ───────────────────
    resolvers = ["cleanway", "gsb", "phishtank", "cloudflare_families"]
    if args.local_analyzer:
        resolvers.insert(1, "cleanway_local")
    if VT_KEY and not args.no_virustotal:
        resolvers.append("virustotal")

    phishing_results: dict[str, list[Verdict]] = {}
    safe_results: dict[str, list[Verdict]] = {}
    for r in resolvers:
        phishing_results[r] = await run_resolver(r, phishing_urls)
        _log_unknown_rate(r, "phishing", phishing_results[r])
        # Drain the Cleanway 5/min/IP window before the safe batch. Without
        # this cooldown the first ~5 safe URLs get HTTP 429 and are recorded
        # as `unknown`, which nulls FPR and poisons latest.json. See
        # 2026-06-30 audit: safe batch had 30/50 unknown, FPR=null.
        # The cooldown only matters when we're being rate-limited. With the
        # benchmark bypass token the server skips the IP cap entirely, so
        # there is no window to drain — skip the 65s wait.
        if r == "cleanway" and not BENCHMARK_BYPASS_TOKEN:
            log.info("draining cleanway rate-limit window (%.0fs) before safe batch",
                     CLEANWAY_BATCH_COOLDOWN_S)
            await asyncio.sleep(CLEANWAY_BATCH_COOLDOWN_S)
        safe_results[r] = await run_resolver(r, legit_urls)
        _log_unknown_rate(r, "safe", safe_results[r])

    # ── Classify + build report ──────────────────────────────────
    report: dict = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "n_phishing": len(phishing_urls),
        "n_safe": len(legit_urls),
        "sources": {
            "phishing": f"URLhaus daily feed ({len(urlhaus)} URLs) + "
                        f"PhishTank online-valid ({len(phishtank)} URLs), "
                        "deduplicated by registrable domain.",
            "legit": f"Tranco top-1M rank 100-100000, "
                     f"random sample (seed=42).",
            "cleanway_api": CLEANWAY_API,
        },
        "phishing": {
            r: classify(phishing_results[r], "dangerous") for r in resolvers
        },
        "safe": {
            r: classify(safe_results[r], "safe") for r in resolvers
        },
        "raw": {
            "phishing": {
                r: [asdict(v) for v in phishing_results[r]] for r in resolvers
            },
            "safe": {
                r: [asdict(v) for v in safe_results[r]] for r in resolvers
            },
            "phishing_urls": phishing_urls,
            "legit_urls": legit_urls,
        },
    }

    tag = args.out_tag or time.strftime("%Y-%m-%d", time.gmtime())
    json_out = DOCS / f"{tag}-fresh-urls.json"
    md_out = DOCS / f"{tag}-fresh-urls.md"
    with open(json_out, "w") as f:
        json.dump(report, f, indent=2)
    with open(md_out, "w") as f:
        f.write(render_md(report))

    log.info("wrote %s", json_out)
    log.info("wrote %s", md_out)

    # ── Pre-publish quality gate ─────────────────────────────────
    # The dated files above are always written — history is cheap and
    # nothing external reads dated files by mistake. `latest.json` is
    # what the landing page + methodology page render, so we only flip
    # it when the run is trustworthy. A rate-limit blowout that shows
    # 30/50 unknown and FPR=null must NOT become the public number.
    gate = check_quality_gate(report)
    if not args.enforce_quality_gate:
        log.warning(
            "quality gate DISABLED via --no-enforce-quality-gate — "
            "flipping latest.json regardless of result (passed=%s)",
            gate.passed,
        )
        _update_latest_pointer(json_out)
        log.info("updated %s → %s", DOCS / "latest.json", json_out.name)
    elif gate.passed:
        _update_latest_pointer(json_out)
        log.info(
            "quality gate PASSED — updated %s → %s",
            DOCS / "latest.json", json_out.name,
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

    # ── Console summary ──────────────────────────────────────────
    print()
    print(render_md({k: v for k, v in report.items() if k != "raw"}))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

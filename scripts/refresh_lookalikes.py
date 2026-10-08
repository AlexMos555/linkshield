#!/usr/bin/env python3
"""Russian-brand lookalikes from Certificate Transparency, and in-app reports,
verified and promoted into Cleanway's own blocklist sources.

What one run does (api/services/lookalike_generator.py has the rules):

  1. CT      Read the new data tiles of each selected tiled log (Let's
             Encrypt by default, picked from Google's log list so a shard
             roll-over needs no deploy) from the position the last run left,
             extract every certificate name, and keep the names the scorer's
             own rules say imitate a Russian brand. Those are CANDIDATES
             (lookalike:candidates), with evidence.
  2. Verify  For up to --max-verify pending candidates: is the host already
             on our list (then: status 'listed', nothing to add); what does
             the analyzer say (verdict_basis, recorded); does the page serve
             a password form naming the brand (fetched from the server
             through the SSRF guard). That evidence of our own promotes the
             host into dangerous_domains:lookalike; a third party's listing
             alone does not (lookalike_generator: a licence question).
  3. Reports Hosts people reported in the app (reports:queue, filled by
             POST /api/v1/feedback/report) go through the same verification
             and, when confirmed, into dangerous_domains:reports.
  4. Summary One log line with the day's counts, so the workflow log is
             the daily report.

The blocklist refresh (scripts/refresh_dangerous_domains.py) publishes both
sets to the phones through every false-positive gate a feed host passes —
only while LOOKALIKE_GENERATOR_ENABLED is set there too. Off (the default),
this job promotes nothing and exits 0 after saying so; --dry-run runs the
whole pipeline against a state file and writes a JSON report instead. A dry
run writes to no store but its own files: it never opens Redis (every
in-process get_redis raises, and the analyzer fails open), never asks the
production API, and adds to the report what the publisher's gates would keep
(`publisher_gates`, `would_publish`). With `--verify none --max-fetch 0` it
contacts no suspected site either: only the CT logs, Google's log list and
the PSL.

Usage:
    python scripts/refresh_lookalikes.py                       # needs REDIS_URL and the switch
    python scripts/refresh_lookalikes.py --dry-run --hours 1   # one hour of real CT entries, no Redis
        --report-json out.json --artifact live_list.bin        # measurement mode
    python scripts/refresh_lookalikes.py --dry-run --verify none --max-tiles 200

Env:
    REDIS_URL                     state, candidates, queues (not needed with --dry-run)
    LOOKALIKE_GENERATOR_ENABLED   1/true to promote (default off)
    LOOKALIKE_CT_OPERATORS        comma-separated log operators (default "Let's Encrypt")
    CLEANWAY_API_BASE             with BENCHMARK_BYPASS_TOKEN: verify through the
                                  production /public/check (the full verdict;
                                  never in --dry-run)
    BENCHMARK_BYPASS_TOKEN        optional, see above

Exit codes: 0 done (or switched off); 2 no CT log readable; 3 lock held.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Awaitable, Callable, Optional

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from api.services import ct_tiles, own_sources  # noqa: E402
from api.services import lookalike_generator as lg  # noqa: E402
from api.services.blocklist_artifact import artifact_covers, parse_artifact_v2  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per tile is not a log
logger = logging.getLogger("lookalikes")

LOCK_KEY = "lock:lookalike_refresh"
LOCK_TTL_SECONDS = 50 * 60
# Let's Encrypt's busiest shard (Sycamore/Willow 2027h1, where today's 90-day
# certificates land) grew ~570k leaves an hour on 2026-10-05; the 2026h2
# shards ~94k. Used only to pick a starting point on a log we have never
# read; from then on the stored position is the truth.
LEAVES_PER_HOUR_ESTIMATE = 600_000
DEFAULT_MAX_TILES = 2_600   # ≈ 665k leaves ≈ one hour of the busiest shard, with room
TILE_CONCURRENCY = 8
DEFAULT_MAX_VERIFY = 60
DEFAULT_MAX_FETCH = 40
DEFAULT_MAX_REPORTS = 100
VERIFY_TIMEOUT_S = 12.0
EXIT_NO_LOG = 2
EXIT_LOCKED = 3


@dataclass
class Counters:
    logs_read: int = 0
    tiles: int = 0
    tiles_failed: int = 0
    leaves: int = 0
    names: int = 0
    hosts: int = 0
    skipped_gap_leaves: int = 0
    matched: int = 0
    candidates_new: int = 0
    candidates_seen_again: int = 0
    verified: int = 0
    already_listed: int = 0
    promoted: int = 0
    rejected: int = 0
    pages_fetched: int = 0
    reports_taken: int = 0
    reports_promoted: int = 0
    by_method: dict = field(default_factory=dict)
    by_brand: dict = field(default_factory=dict)


@dataclass
class Found:
    host: str
    brand: str
    imitates: str
    method: str
    log: str
    leaf_index: int
    cert_time: int


# ── State: Redis or a JSON file (dry-run) ──

class FileState:
    """Positions and candidates in a JSON file, for --dry-run without Redis.
    Mirrors the slice of own_sources the job uses."""

    def __init__(self, path: Optional[str]) -> None:
        self.path = path
        self.data: dict[str, Any] = {"positions": {}, "candidates": {}, "promoted": {}}
        if path and os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self.data.update(json.load(f))

    def save(self) -> None:
        if self.path:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, ensure_ascii=False, indent=1, sort_keys=True)


async def _positions(r, state: FileState) -> dict[str, int]:
    if r is not None:
        return await own_sources.positions(r)
    return {k: int(v) for k, v in state.data["positions"].items()}


async def _set_position(r, state: FileState, log: str, index: int) -> None:
    if r is not None:
        await own_sources.set_position(r, log, index)
    state.data["positions"][log] = index


async def _candidates(r, state: FileState) -> dict[str, dict]:
    if r is not None:
        return await own_sources.all_candidates(r)
    return dict(state.data["candidates"])


async def _put_candidate(r, state: FileState, host: str, record: dict) -> None:
    if r is not None:
        await own_sources.put_candidate(r, host, record)
    state.data["candidates"][host] = record


# ── Stage 1: CT ──

def _bootstrap_start(size: int, hours: float) -> int:
    return max(0, size - int(hours * LEAVES_PER_HOUR_ESTIMATE))


def plan_range(size: int, stored: Optional[int], hours: float, max_tiles: int) -> tuple[int, int, int]:
    """(start, end, skipped) leaves to read now. A log never read starts
    `hours` back; a run that is further behind than `max_tiles` tiles skips
    ahead and says how much it did not read — a stale position must not
    make every later run chase a backlog forever."""
    start = _bootstrap_start(size, hours) if stored is None else min(stored, size)
    budget = max_tiles * ct_tiles.TILE_WIDTH
    skipped = 0
    if size - start > budget:
        skipped = size - start - budget
        start = size - budget
    return start, size, skipped


Seen = dict[str, tuple[str, int, int]]  # host → (log, leaf index, cert time) of its first appearance


async def read_log(http: httpx.AsyncClient, log: ct_tiles.TiledLog, start: int, end: int,
                   counters: Counters, seen: Seen) -> int:
    """Read leaves [start, end) of `log` and collect every host name; returns
    the next position (the first leaf of the first tile that failed, else
    `end`). Matching happens afterwards, for all logs at once, on every core."""
    tiles = ct_tiles.tiles_covering(start, end)
    semaphore = asyncio.Semaphore(TILE_CONCURRENCY)
    results: dict[int, Optional[bytes]] = {}

    async def _one(index: int, width: int) -> None:
        async with semaphore:
            results[index] = await ct_tiles.fetch_tile(http, log, index, width)

    await asyncio.gather(*(_one(i, w) for i, w in tiles))
    next_position = end
    for index, width in tiles:
        blob = results.get(index)
        if blob is None:
            counters.tiles_failed += 1
            next_position = min(next_position, index * ct_tiles.TILE_WIDTH)
            continue
        counters.tiles += 1
        first_leaf = index * ct_tiles.TILE_WIDTH
        try:
            leaves = list(ct_tiles.iter_leaves(blob))
        except ct_tiles.TileFormatError as exc:
            logger.warning("tile %s/%d unreadable: %s", log.name, index, exc)
            counters.tiles_failed += 1
            next_position = min(next_position, first_leaf)
            continue
        for offset, leaf in enumerate(leaves):
            if first_leaf + offset < start or first_leaf + offset >= end:
                continue
            counters.leaves += 1
            for name in ct_tiles.dns_names(leaf.certificate):
                counters.names += 1
                host = lg.normalise(name)
                if host and host not in seen:
                    seen[host] = (log.name, first_leaf + offset, leaf.timestamp_ms // 1000)
    return next_position


async def scan_ct(http: httpx.AsyncClient, logs: list[ct_tiles.TiledLog], r, state: FileState,
                  hours: float, max_tiles: int, counters: Counters) -> dict[str, Found]:
    seen: Seen = {}
    stored = await _positions(r, state)
    for log in logs:
        checkpoint = await ct_tiles.fetch_checkpoint(http, log)
        if checkpoint is None:
            continue
        counters.logs_read += 1
        start, end, skipped = plan_range(checkpoint.size, stored.get(log.name), hours, max_tiles)
        counters.skipped_gap_leaves += skipped
        if skipped:
            logger.warning("%s: %d leaves behind the budget were skipped (position %s, size %d)",
                           log.name, skipped, stored.get(log.name), checkpoint.size)
        logger.info("%s: reading leaves %d..%d (%d tiles)", log.name, start, end,
                    len(ct_tiles.tiles_covering(start, end)))
        next_position = await read_log(http, log, start, end, counters, seen)
        await _set_position(r, state, log.name, next_position)
    counters.hosts = len(seen)
    started = time.monotonic()
    matches = await asyncio.get_running_loop().run_in_executor(None, lg.match_many, list(seen))
    logger.info("matched %d of %d hosts in %.0f s", len(matches), len(seen), time.monotonic() - started)
    matched = {h: Found(h, m.brand, m.imitates, m.method, *seen[h]) for h, m in matches.items()}
    counters.matched = len(matched)
    for found in matched.values():
        counters.by_method[found.method] = counters.by_method.get(found.method, 0) + 1
        counters.by_brand[found.brand] = counters.by_brand.get(found.brand, 0) + 1
    return matched


async def record_candidates(matched: dict[str, Found], r, state: FileState, now: float,
                            counters: Counters) -> None:
    known = await _candidates(r, state)
    for host, found in matched.items():
        record = known.get(host)
        if record:
            counters.candidates_seen_again += 1
            await _put_candidate(r, state, host, {**record, "last_seen": int(now), "log": found.log,
                                                  "leaf_index": found.leaf_index})
            continue
        counters.candidates_new += 1
        await _put_candidate(r, state, host, {
            "brand": found.brand, "imitates": found.imitates, "method": found.method,
            "log": found.log, "leaf_index": found.leaf_index, "cert_time": found.cert_time,
            "first_seen": int(now), "last_seen": int(now), "status": own_sources.Status.new.value,
        })


# ── Stage 2: verification ──

Verdict = tuple[Optional[str], Optional[str]]  # (level, verdict_basis)
Verifier = Callable[[str], Awaitable[Verdict]]
Listed = Callable[[str], Awaitable[Optional[str]]]


async def verify_local(host: str) -> Verdict:
    """The in-process analyzer: DNS, TLS, headers, name rules, whatever
    threat intel the environment has keys for."""
    from api.services.analyzer import analyze_domain
    try:
        result = await asyncio.wait_for(analyze_domain(host), VERIFY_TIMEOUT_S)
    except Exception as exc:  # noqa: BLE001
        logger.info("local verification failed", extra={"host": host, "error": type(exc).__name__})
        return None, None
    return result.level.value, result.verdict_basis


def verify_via_api(api_base: str, token: str) -> Verifier:
    """The production verdict, with every lookup the API has keys for."""
    async def _verify(host: str) -> Verdict:
        try:
            async with httpx.AsyncClient(timeout=VERIFY_TIMEOUT_S) as http:
                resp = await http.get(f"{api_base.rstrip('/')}/api/v1/public/check/{host}",
                                      headers={"X-Cleanway-Benchmark": token, "User-Agent": ct_tiles.USER_AGENT})
            if resp.status_code != 200:
                return None, None
            body = resp.json()
            return body.get("level"), body.get("verdict_basis")
        except (httpx.HTTPError, ValueError):
            return None, None
    return _verify


async def verify_none(_host: str) -> Verdict:
    return None, None


def listed_in_artifact(path: str) -> Listed:
    with open(path, "rb") as f:
        _, hashes = parse_artifact_v2(f.read())
    table = set(hashes)

    async def _listed(host: str) -> Optional[str]:
        return host if artifact_covers(table, host) else None
    return _listed


def listed_in_redis() -> Listed:
    from api.services.cleanway_blocklist import listed_as
    return listed_as


async def not_listed(_host: str) -> Optional[str]:
    return None


@dataclass
class Verification:
    host: str
    signals: tuple
    listed: Optional[str]
    level: Optional[str]
    verdict_basis: Optional[str]
    page_fetched: bool


async def verify_host(host: str, brand: str, imitates: str, method: str, *, verifier: Verifier, listed: Listed,
                      pages: httpx.AsyncClient, fetch_budget: list[int], counters: Counters) -> Verification:
    already = await listed(host)
    level, basis = await verifier(host)
    match = lg.Match(host, brand, imitates, method)
    found = lg.signals(match, listed=already, level=level, verdict_basis=basis, page_html=None)
    html = None
    fetched = False
    # The page is fetched only when it can still decide: not for a host the
    # list already covers, nor for one threat intel already confirmed.
    if not lg.covered(found) and not lg.publishable(found) and fetch_budget[0] > 0:
        fetch_budget[0] -= 1
        html = await lg.fetch_page(host, pages)
        fetched = True
        counters.pages_fetched += 1
        found = lg.signals(match, listed=already, level=level, verdict_basis=basis, page_html=html)
    return Verification(host, found, already, level, basis, fetched)


def decide(found: tuple) -> own_sources.Status:
    """Covered by the published list → nothing to add; an independent
    signal → promoted; otherwise rejected (re-checked when seen again)."""
    if lg.covered(found):
        return own_sources.Status.listed
    return own_sources.Status.promoted if lg.publishable(found) else own_sources.Status.rejected


async def verify_candidates(r, state: FileState, now: float, *, verifier: Verifier, listed: Listed,
                            max_verify: int, max_fetch: int, promote: bool, counters: Counters) -> list[dict]:
    candidates = await _candidates(r, state)
    due = own_sources.pending(candidates, max_verify)
    fetch_budget = [max_fetch]
    outcomes: list[dict] = []
    async with lg.page_client() as pages:
        for host in due:
            record = candidates[host]
            v = await verify_host(host, record["brand"], record["imitates"], record["method"], verifier=verifier,
                                  listed=listed, pages=pages, fetch_budget=fetch_budget, counters=counters)
            counters.verified += 1
            status = decide(v.signals)
            if status is own_sources.Status.listed:
                counters.already_listed += 1
            elif status is own_sources.Status.promoted:
                counters.promoted += 1
                evidence = {"brand": record["brand"], "imitates": record["imitates"], "method": record["method"],
                            "signals": list(v.signals), "level": v.level, "verdict_basis": v.verdict_basis,
                            "log": record.get("log"), "leaf_index": record.get("leaf_index")}
                if promote and r is not None:
                    await own_sources.promote(r, "lookalike", host, now, evidence)
                state.data["promoted"][host] = evidence
            else:
                counters.rejected += 1
            await _put_candidate(r, state, host, {**record, "status": status.value, "checked_at": int(now),
                                                  "level": v.level, "verdict_basis": v.verdict_basis,
                                                  "signals": list(v.signals), "listed": v.listed})
            outcomes.append({"host": host, **{k: record.get(k) for k in ("brand", "imitates", "method")},
                             "signals": list(v.signals), "listed": v.listed, "level": v.level,
                             "verdict_basis": v.verdict_basis, "page_fetched": v.page_fetched, "status": status.value})
    return outcomes


# ── Stage 3: in-app reports ──

async def process_reports(r, now: float, *, verifier: Verifier, listed: Listed, max_reports: int, max_fetch: int,
                          promote: bool, counters: Counters) -> None:
    if r is None:
        return
    taken = await own_sources.take_reports(r, max_reports)
    counters.reports_taken = len(taken)
    fetch_budget = [max_fetch]
    async with lg.page_client() as pages:
        for reported, first_reported in taken:
            host = lg.normalise(reported)
            if not host or lg.skip_reason(host):
                continue
            match = lg.match(host)
            brand = match.brand if match else ""
            imitates = match.imitates if match else ""
            method = match.method if match else "reported"
            v = await verify_host(host, brand, imitates, method, verifier=verifier, listed=listed, pages=pages,
                                  fetch_budget=fetch_budget, counters=counters)
            # A report is one person's word, and so are a hundred: it is never
            # a signal. It needs the same independent evidence as a
            # certificate name; the brand-page signal needs a brand.
            if decide(v.signals) is not own_sources.Status.promoted:
                continue
            counters.reports_promoted += 1
            if promote:
                votes = await own_sources.report_votes(r, reported)
                await own_sources.promote(r, "reports", host, now, {
                    "brand": brand, "imitates": imitates, "method": method, "signals": list(v.signals),
                    "level": v.level, "verdict_basis": v.verdict_basis, "votes": votes,
                    "first_reported": int(first_reported),
                })


# ── Summary ──

def summarize(candidates: dict[str, dict], now: float) -> dict:
    day_ago = now - 86_400
    recent = {h: c for h, c in candidates.items() if float(c.get("last_seen", 0)) >= day_ago}
    by_status: dict[str, int] = {}
    for c in recent.values():
        by_status[c.get("status", "?")] = by_status.get(c.get("status", "?"), 0) + 1
    return {"candidates_24h": len(recent), "by_status_24h": by_status, "candidates_total": len(candidates)}


# ── Main ──

def _pick_verifier(mode: str, dry_run: bool = False) -> Verifier:
    api_base, token = os.environ.get("CLEANWAY_API_BASE", ""), os.environ.get("BENCHMARK_BYPASS_TOKEN", "")
    if dry_run and (mode == "api" or (mode == "auto" and api_base and token)):
        # The production check caches its verdicts and may record confirmed
        # threats: a dry run writes to no production store, so it never asks.
        logger.warning("--dry-run never verifies through the production API — %s",
                       "verifying with nothing" if mode == "api" else "verifying in-process")
        return verify_none if mode == "api" else verify_local
    if mode == "api" or (mode == "auto" and api_base and token):
        if not (api_base and token):
            logger.error("--verify api needs CLEANWAY_API_BASE and BENCHMARK_BYPASS_TOKEN")
            return verify_none
        logger.info("verifying through %s", api_base)
        return verify_via_api(api_base, token)
    if mode == "none":
        return verify_none
    return verify_local


async def _open_redis(redis_url: Optional[str]):
    if not redis_url:
        return None
    import redis.asyncio as redis
    return redis.from_url(redis_url, decode_responses=True)


class DryRunRedisError(ConnectionError):
    """What every Redis access raises during --dry-run."""


async def _no_redis():
    raise DryRunRedisError("--dry-run: no Redis")


def isolate_from_redis() -> None:
    """--dry-run: no code path of this process may reach Redis. The job's own
    stages already take `r=None`; this covers the in-process analyzer
    (verify_local), whose caches and confirmed-threat records would otherwise
    go to whatever REDIS_URL the shell has. Every loaded module's reference
    to api.services.cache.get_redis is replaced — modules imported later bind
    the replacement — and the cached client is dropped. They all fail open."""
    from api.services import cache
    original = cache.get_redis
    if original is _no_redis:
        return
    for module in list(sys.modules.values()):
        if getattr(module, "get_redis", None) is original:
            setattr(module, "get_redis", _no_redis)
    cache.get_redis = _no_redis
    if hasattr(cache, "_redis_client"):
        cache._redis_client = None


# ── Dry run: the publisher's gates on every match ──

def _publisher():
    """scripts/refresh_dangerous_domains.py, for its build_blockset — the
    gates every own-source host meets at publish time."""
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "refresh_dangerous_domains.py")
    spec = importlib.util.spec_from_file_location("refresh_dangerous_domains", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def publisher_gate_pass(hosts: list[str], public_suffixes: Optional[set[str]] = None,
                              publisher=None) -> set[str]:
    """The hosts that would survive the blocklist publisher's guards as own-
    source hosts (exact, never promoting a registrable): shared and path-
    shared hosts, hosting-platform apexes, operator suffixes, zones, the
    bundled top-100k and the brand-owned veto. Tranco-1M needs prod Redis
    and is not applied here — the publisher applies it on top."""
    rdd = publisher or _publisher()
    if public_suffixes is None:
        public_suffixes = await rdd._fetch_psl()
    names = sorted({rdd._norm_host(h) for h in hosts} - {""})
    kept = rdd.build_blockset(names, rdd._load_top_100k(), public_suffixes=public_suffixes,
                              exact_only=set(names))
    return kept & set(names)


async def run(args: argparse.Namespace) -> int:
    now = time.time()
    switched_on = own_sources.enabled()
    if not args.dry_run and not switched_on:
        logger.info("%s is not set — nothing to do (use --dry-run to exercise the pipeline)", own_sources.ENABLE_ENV)
        return 0
    redis_url = None if args.dry_run else os.environ.get("REDIS_URL")
    if not args.dry_run and not redis_url:
        logger.error("REDIS_URL not set")
        return 1
    if args.dry_run:
        isolate_from_redis()
    r = await _open_redis(redis_url)
    state = FileState(args.state_file)
    counters = Counters()
    locked = False
    try:
        if r is not None:
            locked = bool(await r.set(LOCK_KEY, "1", nx=True, ex=LOCK_TTL_SECONDS))
            if not locked:
                logger.warning("another run holds the lock — exiting %d", EXIT_LOCKED)
                return EXIT_LOCKED
        operators = [o.strip() for o in os.environ.get("LOOKALIKE_CT_OPERATORS", "").split(",") if o.strip()]
        async with ct_tiles.client() as http:
            log_list = await ct_tiles.fetch_log_list(http)
            logs = ct_tiles.select_tiled_logs(log_list or {}, operators or ct_tiles.DEFAULT_OPERATORS)
            if args.logs:
                logs = [log for log in logs if any(n.lower() in log.name.lower() for n in args.logs)]
            if not logs:
                logger.error("no usable tiled CT log selected — exit %d", EXIT_NO_LOG)
                return EXIT_NO_LOG
            logger.info("logs: %s", ", ".join(log.name for log in logs))
            matched = await scan_ct(http, logs, r, state, args.hours, args.max_tiles, counters)
        if counters.logs_read == 0:
            logger.error("no CT log answered — exit %d", EXIT_NO_LOG)
            return EXIT_NO_LOG
        await record_candidates(matched, r, state, now, counters)
        verifier = _pick_verifier(args.verify, dry_run=args.dry_run)
        listed = listed_in_artifact(args.artifact) if args.artifact else (listed_in_redis() if r is not None else not_listed)
        promote = switched_on and not args.dry_run
        outcomes = await verify_candidates(r, state, now, verifier=verifier, listed=listed, max_verify=args.max_verify,
                                           max_fetch=args.max_fetch, promote=promote, counters=counters)
        await process_reports(r, now, verifier=verifier, listed=listed, max_reports=args.max_reports,
                              max_fetch=args.max_fetch, promote=promote, counters=counters)
        candidates = await _candidates(r, state)
        if r is not None:
            await own_sources.trim_candidates(r, candidates)
        summary = {"counters": asdict(counters), "summary": summarize(candidates, now), "promoting": promote}
        logger.info("daily summary: %s", json.dumps(summary, ensure_ascii=False, sort_keys=True))
        state.save()
        if args.report_json:
            report = {**summary, "outcomes": outcomes, "matched": [asdict(m) for m in matched.values()]}
            if args.dry_run:
                # What the publisher would do with these names: its gates on
                # every match, and the promoted ones that pass them.
                gated = await publisher_gate_pass(list(matched))
                promoted = {o["host"] for o in outcomes if o["status"] == own_sources.Status.promoted.value}
                report["publisher_gates"] = {"passed": len(gated), "vetoed": sorted(set(matched) - gated)}
                report["would_publish"] = sorted(promoted & gated)
                for row in report["matched"]:
                    row["passes_publisher_gates"] = row["host"] in gated
            with open(args.report_json, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=1)
            logger.info("report written to %s", args.report_json)
        return 0
    finally:
        if r is not None:
            try:
                if locked:
                    await r.delete(LOCK_KEY)
                await r.aclose()
            except Exception:  # noqa: BLE001
                pass


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--dry-run", action="store_true", help="no Redis, no promotion; state in --state-file")
    p.add_argument("--hours", type=float, default=1.0, help="how far back a never-read log starts (default 1)")
    p.add_argument("--max-tiles", type=int, default=DEFAULT_MAX_TILES, help="tiles per log per run")
    p.add_argument("--max-verify", type=int, default=DEFAULT_MAX_VERIFY)
    p.add_argument("--max-fetch", type=int, default=DEFAULT_MAX_FETCH, help="page fetches per stage")
    p.add_argument("--max-reports", type=int, default=DEFAULT_MAX_REPORTS)
    p.add_argument("--verify", choices=("auto", "local", "api", "none"), default="auto")
    p.add_argument("--logs", nargs="*", help="only logs whose name contains one of these")
    p.add_argument("--artifact", help="a downloaded phone artifact to answer 'already listed' (dry-run)")
    p.add_argument("--state-file", help="positions/candidates for --dry-run")
    p.add_argument("--report-json", help="write the run's outcomes here")
    args = p.parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())

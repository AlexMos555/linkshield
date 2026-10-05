"""Cleanway's own sources for the phone's blocklist: hosts the lookalike
generator confirmed, and in-app reports that passed verification.

OFF unless LOOKALIKE_GENERATOR_ENABLED is set (see `enabled`), on the API,
the generator job and the blocklist refresh alike. Off, the API queues no
report, the job promotes nothing, and the publisher drops any host still
stored — the same shape as api/services/confirmed_threats.py, for the same
reason: a name in these sets becomes a DNS block on every phone.

Why these exist: every third-party feed we may legally ship is slow on
Russian-brand phishing (docs/THIRD_PARTY_FEEDS.md in PR #67, the 2026-09-21
licence audit), and the licence cut removes the fast ones. A lookalike of
Sber or Gosuslugi with a fresh certificate and a password form is evidence
we gather ourselves and owe no one a licence for.

Storage — Redis, one sorted set per source:
  dangerous_domains:lookalike   member = host, score = unix time last confirmed
  dangerous_domains:reports     the same, for in-app reports
A host stays listed WINDOW_SECONDS after its last confirmation, then leaves
(the publisher counts an expired one as present so retention does not hold
it for another window). Each set is capped at MAX_MEMBERS, oldest first.

Beside them:
  own_sources:evidence          hash host → JSON: why it was promoted (brand,
                                method, signals, when) — for the review
                                workflow and the daily summary
  lookalike:candidates          hash host → JSON: every match the CT reader
                                found, its status and its last verdict
  lookalike:ct:position         hash log name → next leaf index to read
  reports:queue                 sorted set host → first report time
  reports:installs:<host>       set of install keys that reported it (24 h)
  reports:install:<key>:<day>   per-install counter (abuse limit)
  reports:day:<day>             global counter (abuse limit)

No user, IP or URL is stored anywhere here: a report keeps the host and a
hashed, daily-rotating install number (api/services/rate_limiter.install_key).
"""
from __future__ import annotations

import json
import logging
import os
import time
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping, Optional

logger = logging.getLogger("cleanway.own_sources")

ENABLE_ENV = "LOOKALIKE_GENERATOR_ENABLED"

LOOKALIKE_KEY = "dangerous_domains:lookalike"
REPORTS_KEY = "dangerous_domains:reports"
SOURCE_KEYS: Mapping[str, str] = MappingProxyType({"lookalike": LOOKALIKE_KEY, "reports": REPORTS_KEY})
EVIDENCE_KEY = "own_sources:evidence"

# A confirmed lookalike stays listed two weeks after its last confirmation —
# the publisher's own retention window for a feed departure. The generator
# re-confirms a host it sees again (a renewed certificate, a new report).
WINDOW_SECONDS = 14 * 86_400
MAX_MEMBERS = 20_000
EXPIRED_GRACE_SECONDS = 2 * 86_400
KEY_TTL_SECONDS = WINDOW_SECONDS + EXPIRED_GRACE_SECONDS + 86_400
# ~0.5 KB of JSON per candidate; 50k is the cap, oldest first.
CANDIDATES_KEY = "lookalike:candidates"
CANDIDATES_MAX = 50_000
CANDIDATES_TTL_SECONDS = 30 * 86_400
POSITION_KEY = "lookalike:ct:position"

REPORT_QUEUE_KEY = "reports:queue"
REPORT_QUEUE_MAX = 10_000
REPORT_QUEUE_TTL_SECONDS = 7 * 86_400
REPORTS_PER_INSTALL_PER_DAY = 5
REPORTS_PER_DAY = 2_000
REPORT_INSTALLS_TTL_SECONDS = 86_400


class Status(str, Enum):
    new = "new"            # matched, not verified yet
    promoted = "promoted"  # verified with an independent signal → in a published set
    rejected = "rejected"  # verified, no independent signal (re-checked when seen again)
    skipped = "skipped"    # a pre-gate said never (brand-owned, popular)


class ReportOutcome(str, Enum):
    queued = "queued"
    repeated = "repeated"          # this install already reported this host today
    install_limit = "install_limit"
    daily_limit = "daily_limit"
    disabled = "disabled"
    invalid = "invalid"


def enabled(environ: Optional[Mapping[str, str]] = None) -> bool:
    """True only when LOOKALIKE_GENERATOR_ENABLED is 1/true/yes/on."""
    raw = (os.environ if environ is None else environ).get(ENABLE_ENV, "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def normalize_host(host: str) -> str:
    return (host or "").strip().lower().rstrip(".")


def _forget_before(now: float) -> str:
    return f"({int(now) - WINDOW_SECONDS - EXPIRED_GRACE_SECONDS}"


def _key(source: str) -> str:
    try:
        return SOURCE_KEYS[source]
    except KeyError:
        raise ValueError(f"unknown own source {source!r}") from None


# ── Published sets ──

async def promote(r, source: str, host: str, now: float, evidence: Mapping[str, Any]) -> None:
    """Upsert `host` into the source's set with `now`, keep its evidence,
    forget expired entries, trim to the cap, refresh TTLs — one MULTI/EXEC."""
    key = _key(source)
    record = {**evidence, "source": source, "promoted_at": int(now)}
    pipe = r.pipeline(transaction=True)
    pipe.zadd(key, {host: int(now)})
    pipe.zremrangebyscore(key, "-inf", _forget_before(now))
    pipe.zremrangebyrank(key, 0, -(MAX_MEMBERS + 1))
    pipe.expire(key, KEY_TTL_SECONDS)
    pipe.hset(EVIDENCE_KEY, mapping={host: json.dumps(record, ensure_ascii=False, sort_keys=True)})
    pipe.expire(EVIDENCE_KEY, KEY_TTL_SECONDS)
    await pipe.execute()


async def load(r, source: str) -> dict[str, float]:
    rows = await r.zrange(_key(source), 0, -1, withscores=True)
    return {str(name): float(score) for name, score in rows}


def split(entries: Mapping[str, float], now: float, window_seconds: int = WINDOW_SECONDS) -> tuple[set, set]:
    """(active, expired): confirmed inside the window vs. before it."""
    cutoff = now - window_seconds
    active = {name for name, seen in entries.items() if seen >= cutoff}
    return active, set(entries) - active


async def prune(r, source: str, now: float) -> None:
    await r.zremrangebyscore(_key(source), "-inf", _forget_before(now))


async def evidence_for(r, host: str) -> Optional[dict]:
    raw = await r.hget(EVIDENCE_KEY, host)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


# ── Candidates (the CT reader's matches) ──

async def put_candidate(r, host: str, record: Mapping[str, Any]) -> None:
    pipe = r.pipeline(transaction=True)
    pipe.hset(CANDIDATES_KEY, mapping={host: json.dumps(dict(record), ensure_ascii=False, sort_keys=True)})
    pipe.expire(CANDIDATES_KEY, CANDIDATES_TTL_SECONDS)
    await pipe.execute()


async def get_candidate(r, host: str) -> Optional[dict]:
    raw = await r.hget(CANDIDATES_KEY, host)
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


async def all_candidates(r) -> dict[str, dict]:
    rows = await r.hgetall(CANDIDATES_KEY)
    out: dict[str, dict] = {}
    for host, raw in rows.items():
        try:
            data = json.loads(raw)
        except ValueError:
            continue
        if isinstance(data, dict):
            out[str(host)] = data
    return out


def pending(candidates: Mapping[str, dict], limit: int) -> list[str]:
    """Hosts still to verify, oldest first: new ones, then rejected ones
    seen again since their last check."""
    def due(rec: dict) -> bool:
        status = rec.get("status")
        if status == Status.new.value:
            return True
        return status == Status.rejected.value and float(rec.get("last_seen", 0)) > float(rec.get("checked_at", 0))

    rows = [(float(rec.get("first_seen", 0)), host) for host, rec in candidates.items() if due(rec)]
    return [host for _, host in sorted(rows)[:limit]]


async def trim_candidates(r, candidates: Mapping[str, dict]) -> int:
    """Drop the oldest candidates past the cap. Returns how many left."""
    excess = len(candidates) - CANDIDATES_MAX
    if excess <= 0:
        return 0
    oldest = sorted(candidates, key=lambda h: float(candidates[h].get("first_seen", 0)))[:excess]
    await r.hdel(CANDIDATES_KEY, *oldest)
    return len(oldest)


# ── CT positions ──

async def positions(r) -> dict[str, int]:
    rows = await r.hgetall(POSITION_KEY)
    out = {}
    for name, value in rows.items():
        try:
            out[str(name)] = int(value)
        except (TypeError, ValueError):
            continue
    return out


async def set_position(r, log_name: str, next_index: int) -> None:
    await r.hset(POSITION_KEY, mapping={log_name: str(int(next_index))})


# ── In-app reports ──

def _day(now: float) -> str:
    return time.strftime("%Y%m%d", time.gmtime(now))


async def enqueue_report(r, host: str, install: Optional[str], now: float) -> ReportOutcome:
    """Queue `host` for verification. Limits per install and per day; a
    repeat from the same install does not count twice. The caller has
    already decided the switch is on."""
    name = normalize_host(host)
    if not name or "." not in name or len(name) > 253:
        return ReportOutcome.invalid
    day = _day(now)
    global_count = await r.incr(f"reports:day:{day}")
    await r.expire(f"reports:day:{day}", 2 * 86_400)
    if global_count > REPORTS_PER_DAY:
        return ReportOutcome.daily_limit
    if install:
        if not await r.sadd(f"reports:installs:{name}", install):
            return ReportOutcome.repeated
        await r.expire(f"reports:installs:{name}", REPORT_INSTALLS_TTL_SECONDS)
        own = await r.incr(f"reports:install:{install}:{day}")
        await r.expire(f"reports:install:{install}:{day}", 2 * 86_400)
        if own > REPORTS_PER_INSTALL_PER_DAY:
            return ReportOutcome.install_limit
    pipe = r.pipeline(transaction=True)
    pipe.zadd(REPORT_QUEUE_KEY, {name: int(now)}, nx=True)
    pipe.zremrangebyrank(REPORT_QUEUE_KEY, 0, -(REPORT_QUEUE_MAX + 1))
    pipe.expire(REPORT_QUEUE_KEY, REPORT_QUEUE_TTL_SECONDS)
    await pipe.execute()
    return ReportOutcome.queued


async def report_votes(r, host: str) -> int:
    """How many distinct installs reported `host` in the last day."""
    return int(await r.scard(f"reports:installs:{normalize_host(host)}"))


async def take_reports(r, limit: int) -> list[tuple[str, float]]:
    """The oldest queued reports, removed from the queue."""
    rows = await r.zrange(REPORT_QUEUE_KEY, 0, max(0, limit - 1), withscores=True)
    if rows:
        await r.zrem(REPORT_QUEUE_KEY, *[name for name, _ in rows])
    return [(str(name), float(score)) for name, score in rows]

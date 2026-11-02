"""The registration of a top-100k name, for the allowlist's age gate
(ALLOWLIST_AGE_GATE in api/config.py).

A name in data/top_100k.json is answered "safe" before any analysis — both
/check routes, through scoring.is_trusted_top_domain — so no registry is
asked about it, and a popular name someone else registered right after it
dropped keeps that answer. The weekly dead-name sweep (dead_top_names) only
sees a name that stays NXDOMAIN until a weekly run; a drop-catch registers
it again within minutes of its release.

What happens to a name the allowlist would answer:
  * its registrable's last known record is read from Redis (KEY + name, one
    MGET for a batch); the age is worked out when read;
  * not known yet: it is queued and answered as before. One worker per event
    loop asks the registry (rdap.record), one name at a time, at most one a
    second, and keeps the answer;
  * a registration younger than popularity_min_age_days (the rank gate's
    limit), or a name the registry has no record of while DNS has no such
    name either: "shadow" logs it (allowlist_age_gate_shadow) and still
    answers "safe"; "on" sends it to the full analysis, which then gives it
    neither the allowlist nor its rank (analyzer: allowlist_withheld).

A record is kept 30 days and asked again when due: a week after it was read,
a day for a name expired, expiring within 30 days or in auto-renew grace, an
hour for one in redemption or pending delete or absent from the registry —
the hours a drop-catch happens in. A registry's 404 counts as "absent" only
when DNS says NXDOMAIN too: Nominet answers 404 for ox.ac.uk and nhs.uk,
zones it does not run (264 entries under ac.uk, nhs.uk, police.uk); a 404
for a name it knew, or for one right under its TLD (google.com), while the
name still resolves or DNS cannot tell, is asked again hourly. A zone
with no RDAP server in IANA's bootstrap file can never be gated: 23,377 of
the 95,529 entries the gate reads (24%; .ru, .jp, .de, .cn, .edu, .it, .io,
.es … on 2026-11-01). When asking again fails, the last answer stays and is
asked again in an hour, unless another process stored a newer one; a 429 or
5xx leaves that RDAP server alone — every process, through Redis — for its
Retry-After (300 s if none, 1 min to 6 h), five failures in a row for 15
minutes. A worker asks first the name the most different users and addresses
checked, and one requester may queue or move forward 20 names a minute (per
process), so nobody keeps the queue busy with names of their choosing while
the one victims check waits.

Everything that goes wrong answers from the allowlist as before (in "on" not
cached as trusted): Redis down or slow, the queue full, a lookup failing,
the analyzer's whois breaker open. "off" reads and asks nothing.

Not covered: the DNS blocklist's never-block guard and the lookalike skip
(offline batches, no per-name age: bulk RDAP is against Verisign's terms),
the phone's popular_veto.txt (in the app), the ML feature in_top_domains
(train/serve parity), and a name sold without a drop (its date stays).
"""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from collections import OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Optional

import httpx

from api.config import get_settings
from api.services import dns_checks, load_shedding, rdap

logger = logging.getLogger("cleanway.allowlist_age")

TRUST = "trust"                    # answer from the allowlist, as before
TRUST_UNCACHED = "trust_uncached"  # "on", nothing certain yet: answer, but do not cache the answer
WITHHOLD = "withhold"              # "on": young, or no registration — analyse instead

KEY = "rdap:reg:v1:"
PAUSE_KEY = "rdap:pause:v1:"  # + RDAP server: some process was told to slow down
KEEP_S = 30 * 86400        # how long Redis keeps a record
EVERY_DATED_S = 7 * 86400  # when it is asked again
EVERY_EXPIRING_S = 86400
EVERY_LEAVING_S = 3600
EVERY_UNKNOWABLE_S = 7 * 86400
EVERY_FAILED_S = 3600
EXPIRING_STATUS = frozenset({"auto renew period"})
LEAVING_STATUS = frozenset({"redemption period", "pending delete", "pending restore"})
EXPIRING_DAYS = 30

LOOKUP_TIMEOUT_S = 2.5
MIN_INTERVAL_S = 1.0       # after every registry lookup of a worker
MAX_QUEUED = 256
MAX_NEW_PER_REQUESTER = 20  # names one requester may queue or move forward a minute, per process
MAX_VOTERS = 32             # requesters counted per queued name
PAUSE_S = 300.0            # a 429 / 5xx without a readable Retry-After
MIN_PAUSE_S, MAX_PAUSE_S = 60.0, 6 * 3600.0
FAILURES_TO_PAUSE = 5
FAILURE_PAUSE_S = 900.0
REDIS_GET_TIMEOUT_S = 0.2  # on the request path
REDIS_SET_TIMEOUT_S = 0.5
LOCAL_TTL_S = 600.0        # this process's copy of a record it read
LOCAL_MAX = 8192
SHADOW_EVERY_S = 86400.0   # one shadow line per entry per process a day
STATS_EVERY_S = 600.0

# Seams for tests.
_lookup = rdap.record
_server = rdap.server
_exists = dns_checks.check_domain_exists
_sleep = asyncio.sleep
_monotonic = time.monotonic


def _clock() -> datetime:
    return datetime.now(timezone.utc)


def gated_entry(domain: str) -> Optional[str]:
    """The allowlist entry whose registration the gate reads for `domain`,
    or None when the gate has nothing to say: the allowlist does not answer
    it, a government name (registered by a state only), or an entry whose
    registrable is another name (amazon.com.be: the registry would be asked
    about com.be)."""
    from api.services.analyzer import _government_name
    from api.services.scoring import is_trusted_top_domain, top_domain_key

    if not is_trusted_top_domain(domain):
        return None
    entry = top_domain_key(domain)
    if entry is None or _government_name(entry) or rdap.registered_name(entry) != entry:
        return None
    return entry


async def gate(domain: str, requester: Optional[str] = None) -> str:
    """TRUST, TRUST_UNCACHED or WITHHOLD for a name the allowlist answers."""
    return (await gate_many([domain], requester))[domain]


async def gate_many(domains: list[str], requester: Optional[str] = None) -> dict[str, str]:
    """gate() for each of `domains`, with one Redis round trip. `requester`
    (a user, an address) is who checks: the worker asks first the name the
    most different requesters checked, and one requester may queue or move
    forward MAX_NEW_PER_REQUESTER names a minute — nobody keeps the queue
    busy with names of their choosing while the one victims check waits."""
    out = dict.fromkeys(domains, TRUST)
    mode = get_settings().allowlist_age_gate
    if mode not in ("shadow", "on"):
        return out
    unsure = TRUST_UNCACHED if mode == "on" else TRUST
    entries = {d: gated_entry(d) for d in domains}
    # One look at this process's copy: one that expires during the read
    # below must not turn into a miss.
    known = {e: _local.get(e) for e in set(entries.values()) if e is not None}
    wanted = sorted(e for e, stored in known.items() if stored is None)
    read: Optional[dict] = {}
    if wanted:
        try:
            read = await _read(wanted)
        except Exception:
            read = None  # Redis down or slow: as before, and nothing asked
    now = _clock()
    for domain, entry in entries.items():
        if entry is None:
            continue
        stored = known[entry]
        if stored is None:
            if read is None:
                out[domain] = unsure
                continue
            stored = read.get(entry)
            if stored is None:
                _filler.add(entry, None, requester)  # fifty subdomains: still one requester
                out[domain] = unsure
                continue
            known[entry] = stored
            _local.put(entry, stored, LOCAL_TTL_S)
        if _due(stored, now):
            _filler.add(entry, stored, requester)
        out[domain] = _decide(domain, entry, stored, mode, now, unsure)
    return out


def _decide(domain: str, entry: str, stored: dict, mode: str, now: datetime, unsure: str) -> str:
    if stored.get("failed"):
        return unsure
    young, age = _reading(stored, now)
    if young:
        if mode == "shadow":
            _shadow(domain, entry, age)
            return TRUST
        return WITHHOLD
    # A name on its way out: not cached as trusted past the record's next ask.
    return unsure if stored.get("leaving") else TRUST


def _reading(stored: dict, now: datetime) -> tuple[bool, Optional[int]]:
    """(young, age_days); a name with no registration is young, age None."""
    if stored.get("absent"):
        return True, None
    registered = rdap._parse_date(stored.get("registered"))
    if registered is None:
        return False, None
    age = max(0, (now - registered).days)
    limit = get_settings().popularity_min_age_days
    return 0 < limit and age < limit, age


def _due(stored: dict, now: datetime) -> bool:
    try:
        return now.timestamp() - float(stored["at"]) >= float(stored["every"])
    except (KeyError, TypeError, ValueError):
        return True


def _shadow(domain: str, entry: str, age: Optional[int]) -> None:
    now = _monotonic()
    last = _shadowed.get(entry)
    if last is not None and now - last < SHADOW_EVERY_S:
        return
    _shadowed[entry] = now
    _shadowed.move_to_end(entry)
    while len(_shadowed) > LOCAL_MAX:
        _shadowed.popitem(last=False)
    from api.services.scoring import TOP_10K_RANKS
    logger.info("allowlist_age_gate_shadow", extra={
        "domain": domain, "entry": entry, "age_days": age,
        "outcome": "absent" if age is None else "young", "rank": TOP_10K_RANKS.get(entry),
    })


# ── Redis ──

async def _read(entries: list[str]) -> dict[str, dict]:
    from api.services import cache  # at call time: tests patch cache.get_redis

    r = await asyncio.wait_for(cache.get_redis(), REDIS_GET_TIMEOUT_S)
    raws = await asyncio.wait_for(r.mget([KEY + e for e in entries]), REDIS_GET_TIMEOUT_S)
    out = {}
    for entry, raw in zip(entries, raws):
        stored = _decode(raw)
        if stored is not None:
            out[entry] = stored
    return out


async def _read_one(entry: str) -> Optional[dict]:
    """The shared record of `entry` now, or None (none, or Redis failing)."""
    try:
        return (await _read([entry])).get(entry)
    except Exception:
        return None


async def _paused_everywhere(host: str) -> bool:
    """Another process got a 429 / 5xx from `host` and left it alone."""
    from api.services import cache

    try:
        r = await asyncio.wait_for(cache.get_redis(), REDIS_GET_TIMEOUT_S)
        return await asyncio.wait_for(r.get(PAUSE_KEY + host), REDIS_GET_TIMEOUT_S) is not None
    except Exception:
        return False


async def _pause_everywhere(host: str, seconds: float) -> None:
    from api.services import cache

    try:
        r = await asyncio.wait_for(cache.get_redis(), REDIS_SET_TIMEOUT_S)
        await asyncio.wait_for(r.setex(PAUSE_KEY + host, max(1, int(seconds)), "1"), REDIS_SET_TIMEOUT_S)
    except Exception:
        pass


def _decode(raw) -> Optional[dict]:
    """A stored record, or None (a miss) for nothing or anything unreadable."""
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


async def _write(entry: str, stored: dict, ttl: int) -> bool:
    from api.services import cache

    try:
        r = await asyncio.wait_for(cache.get_redis(), REDIS_SET_TIMEOUT_S)
        await asyncio.wait_for(r.setex(KEY + entry, ttl, json.dumps(stored)), REDIS_SET_TIMEOUT_S)
        return True
    except Exception:
        return False


class _Local:
    """This process's copy of records, bounded."""

    def __init__(self) -> None:
        self._items: OrderedDict[str, tuple[dict, float]] = OrderedDict()

    def get(self, entry: str) -> Optional[dict]:
        item = self._items.get(entry)
        if item is None:
            return None
        if item[1] <= _monotonic():
            del self._items[entry]
            return None
        return item[0]

    def put(self, entry: str, stored: dict, ttl: float) -> None:
        self._items[entry] = (stored, _monotonic() + ttl)
        self._items.move_to_end(entry)
        while len(self._items) > LOCAL_MAX:
            self._items.popitem(last=False)


# ── The worker ──

class _Filler:
    def __init__(self) -> None:
        # entry → [who checked it while queued, its last record]: the name the
        # most different requesters checked is asked first
        self.queued: OrderedDict[str, list] = OrderedDict()
        self.current: Optional[str] = None
        self.task: Optional[asyncio.Task] = None
        self.paused: dict[str, float] = {}       # RDAP server → monotonic time it may be asked again
        self.failures: dict[str, int] = defaultdict(int)
        self.counts: dict[str, int] = defaultdict(int)
        self.stats_at = _monotonic()

    def add(self, entry: str, last: Optional[dict], requester: Optional[str] = None) -> None:
        who = requester or "-"
        queued = self.queued.get(entry)
        if queued is not None:
            # Checked by someone else while it waits: asked sooner. A vote
            # counts against the requester's minute like a new name.
            voters = queued[0]
            if who not in voters and len(voters) < MAX_VOTERS and (requester is None or _admit(requester)):
                voters.add(who)
            return
        if entry == self.current:
            return
        if requester is not None and not _admit(requester):
            self.counts["refused"] += 1
            return
        while len(self.queued) >= MAX_QUEUED:
            # The name the fewest checked goes (the oldest of those): one
            # many check is the one a campaign's victims are checking.
            del self.queued[min(self.queued, key=lambda e: len(self.queued[e][0]))]
            self.counts["dropped"] += 1
        self.queued[entry] = [{who}, last]
        loop = asyncio.get_running_loop()
        if self.task is None or self.task.done() or self.task.get_loop() is not loop:
            self.task = loop.create_task(self._run())

    async def _run(self) -> None:
        while self.queued:
            entry = max(self.queued, key=lambda e: len(self.queued[e][0]))
            _, last = self.queued.pop(entry)
            self.current = entry
            try:
                asked = await self._fill(entry, last)
            except Exception as exc:  # never let one name stop the worker
                logger.warning("allowlist_age_fill_failed", extra={"error": type(exc).__name__})
                asked = True
            finally:
                self.current = None
            self._stats()
            if asked:
                await _sleep(MIN_INTERVAL_S)

    async def _fill(self, entry: str, last: Optional[dict]) -> bool:
        """Ask the registry about `entry` and keep the answer; False when no
        registry was asked."""
        from api.services.circuit_breaker import CircuitState, whois_breaker

        now = _clock()
        known = _local.get(entry)
        if known is not None and not _due(known, now):
            return False  # asked meanwhile, here
        shared = await _read_one(entry)
        if shared is not None:
            if not _due(shared, now):
                _local.put(entry, shared, LOCAL_TTL_S)
                return False  # asked meanwhile, by another process
            last = shared
        try:
            host = await _server(entry, LOOKUP_TIMEOUT_S)
        except Exception as exc:  # the bootstrap file could not be read
            await self._keep(entry, last, now, failed=exc, host=None)
            return False
        if host is None:
            await self._keep(entry, {"unknowable": True}, now, every=EVERY_UNKNOWABLE_S)
            return False
        if (self.paused.get(host, 0.0) > _monotonic() or whois_breaker.state == CircuitState.OPEN
                or await _paused_everywhere(host)):
            self.counts["paused"] += 1
            return False  # nothing stored: a later check queues it again
        try:
            async with load_shedding.OUTBOUND.slot():
                record = await asyncio.wait_for(_lookup(entry, LOOKUP_TIMEOUT_S), LOOKUP_TIMEOUT_S + 0.5)
        except Exception as exc:
            await self._keep(entry, last, now, failed=exc, host=host)
            return True
        self.failures.pop(host, None)  # the registry answered
        if record == {}:
            # 404. A dropped name has no delegation either; a zone the TLD's
            # registry does not run (ac.uk, nhs.uk) still resolves. The
            # resolver's trouble is not the registry's: no host is charged.
            try:
                exists = await asyncio.wait_for(_exists(entry), LOOKUP_TIMEOUT_S + 0.5)
            except Exception:
                exists = None
            if exists is not False:
                knew = bool(last and last.get("found"))
                # Right under its TLD (google.com), the name is that registry's
                # to hold: a 404 while DNS still answers is a deletion or a new
                # registration on its way, not a zone it does not run.
                own = "." not in entry.split(".", 1)[1]
                if knew:
                    kept = {**_record_of(last), "leaving": True}
                elif exists and (own or (last and last.get("absent"))):
                    kept = {"unknowable": True, "leaving": True}
                else:
                    kept = None
                if exists is None:
                    await self._keep(entry, kept or last, now, failed=LookupError("404, and DNS could not tell"),
                                     seen=last)
                elif kept is not None:
                    await self._keep(entry, kept, now, every=EVERY_LEAVING_S)  # asked hourly, not cached as trusted
                else:
                    await self._keep(entry, {"unknowable": True}, now, every=EVERY_UNKNOWABLE_S)
                    self.counts["unknowable"] += 1
                return True
        stored, every = _stored(record, now)
        self.counts[next(k for k in ("registered", "absent", "unknowable") if k in stored)] += 1
        await self._keep(entry, stored, now, every=every)
        if get_settings().allowlist_age_gate == "shadow":
            young, age = _reading(stored, now)
            if young:
                _shadow(entry, entry, age)
        return True

    async def _keep(self, entry: str, stored: Optional[dict], now: datetime, every: float = EVERY_FAILED_S,
                    failed: Optional[BaseException] = None, host: Optional[str] = None,
                    seen: Optional[dict] = None) -> None:
        """Store `stored` to be asked again in `every` seconds. A failed ask
        keeps the last record (asked again in an hour) or stores "failed" —
        unless another process stored a record newer than the one this ask
        started from (`seen`, by default `stored`)."""
        if failed is not None:
            await self._failed(host, failed)
            seen = stored if seen is None else seen
            current = await _read_one(entry)
            if current is not None and not current.get("failed") and (
                    not seen or float(current.get("at", 0)) > float(seen.get("at", 0))):
                _local.put(entry, current, LOCAL_TTL_S)
                return
            stored = _record_of(stored) if stored and not stored.get("failed") else {"failed": True}
            every = EVERY_FAILED_S
        stored = {**_record_of(stored or {}), "at": now.timestamp(), "every": every}
        ttl = EVERY_FAILED_S if stored.get("failed") else KEEP_S
        if await _write(entry, stored, int(ttl)):
            _local.put(entry, stored, min(every, LOCAL_TTL_S))
        else:
            # Kept here until it is due: a store refusing writes must not
            # send every check of the name to the registry.
            self.counts["store_failed"] += 1
            _local.put(entry, stored, every)

    async def _failed(self, host: Optional[str], exc: BaseException) -> None:
        self.counts["failed"] += 1
        if host is None:
            return
        if isinstance(exc, httpx.HTTPStatusError) and (exc.response.status_code == 429 or exc.response.status_code >= 500):
            await self._pause(host, _retry_after(exc.response))
            return
        self.failures[host] += 1
        if self.failures[host] >= FAILURES_TO_PAUSE:
            await self._pause(host, FAILURE_PAUSE_S)

    async def _pause(self, host: str, seconds: float) -> None:
        self.paused[host] = _monotonic() + seconds
        self.failures.pop(host, None)
        await _pause_everywhere(host, seconds)  # every process leaves it alone, not only this one

    def _stats(self) -> None:
        now = _monotonic()
        if now - self.stats_at < STATS_EVERY_S or not self.counts:
            return
        c = self.counts
        logger.info(
            "allowlist_age_fills registered=%d absent=%d unknowable=%d failed=%d paused=%d "
            "dropped=%d refused=%d store_failed=%d queued=%d",
            c["registered"], c["absent"], c["unknowable"], c["failed"], c["paused"],
            c["dropped"], c["refused"], c["store_failed"], len(self.queued),
        )
        self.counts = defaultdict(int)
        self.stats_at = now


def _record_of(stored: dict) -> dict:
    """A stored record without its bookkeeping."""
    return {k: v for k, v in stored.items() if k not in ("at", "every")}


def _admit(requester: str) -> bool:
    """May `requester` queue one more name this minute?"""
    now = _monotonic()
    window = _requesters.get(requester)
    if window is None or now - window[0] >= 60.0:
        window = [now, 0]
    _requesters[requester] = window
    _requesters.move_to_end(requester)
    while len(_requesters) > LOCAL_MAX:
        _requesters.popitem(last=False)
    if window[1] >= MAX_NEW_PER_REQUESTER:
        return False
    window[1] += 1
    return True


def _stored(record: Optional[dict], now: datetime) -> tuple[dict, float]:
    """What is kept of the registry's answer, and when it is asked again."""
    if not record:
        return ({"unknowable": True}, EVERY_UNKNOWABLE_S) if record is None else ({"absent": True}, EVERY_LEAVING_S)
    registered = record.get("registered")
    # "found": the registry answered with a record, so a later 404 means it
    # no longer has one.
    base = {"registered": registered} if rdap._parse_date(registered) is not None else {"unknowable": True}
    base["found"] = True
    status = set(record.get("status") or ())
    expires = rdap._parse_date(record.get("expires"))
    if status & LEAVING_STATUS:
        return {**base, "leaving": True}, EVERY_LEAVING_S
    if status & EXPIRING_STATUS or (expires is not None and expires - now < timedelta(days=EXPIRING_DAYS)):
        return {**base, "leaving": True}, EVERY_EXPIRING_S
    return base, EVERY_DATED_S if "registered" in base else EVERY_UNKNOWABLE_S


def _retry_after(response: httpx.Response) -> float:
    """Retry-After in seconds or as an HTTP date (RFC 9110 §10.2.3)."""
    value = response.headers.get("retry-after", "").strip()
    try:
        seconds = float(value)
    except ValueError:
        try:
            seconds = (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
        except (TypeError, ValueError, IndexError):
            seconds = PAUSE_S
    if not math.isfinite(seconds):
        seconds = PAUSE_S
    return min(max(seconds, MIN_PAUSE_S), MAX_PAUSE_S)


_local = _Local()
_shadowed: OrderedDict[str, float] = OrderedDict()
_requesters: OrderedDict[str, list] = OrderedDict()  # requester → [minute's start, names queued]
_filler = _Filler()


async def drain() -> None:
    """Wait for the worker of this event loop to finish (tests)."""
    task = _filler.task
    if task is not None and not task.done() and task.get_loop() is asyncio.get_running_loop():
        await task


async def stop() -> None:
    """Cancel the worker before Redis closes (shutdown)."""
    task = _filler.task
    if task is None or task.done() or task.get_loop() is not asyncio.get_running_loop():
        return
    task.cancel()
    try:
        await asyncio.wait_for(task, 1.0)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass


def reset_for_tests() -> None:
    global _local, _filler
    _local = _Local()
    _shadowed.clear()
    _requesters.clear()
    _filler = _Filler()

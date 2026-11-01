"""The allowlist's age gate (ALLOWLIST_AGE_GATE, api/services/allowlist_age.py).

A top-100k name is answered "safe" before any analysis, so until this gate
no registry was asked about it: a popular name someone else registered
after it dropped kept the instant "safe". What the tests pin:
  * "off" (the default) reads and asks nothing;
  * a name not known yet is queued and answered as before (in "on" not
    cached as trusted); one worker asks the registry, one name at a time and
    one a second, and keeps the record 30 days, asked again when due;
  * a registration younger than popularity_min_age_days, or a name neither
    the registry nor DNS knows, is logged in "shadow" and sent to the full
    analysis in "on" — where neither the allowlist nor the rank vouches;
  * a registry's 404 for a zone it does not run (ox.ac.uk) is no "absent";
  * failures answer as before and keep the last record: Redis down or slow,
    a lookup failing, an RDAP server that asked us to slow down;
  * nothing is asked for a name the allowlist does not answer, a government
    name, or an entry whose registrable is another (amazon.com.be → com.be).
"""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest

from api.config import get_settings
from api.models.schemas import RiskLevel
from api.services import allowlist_age, analyzer, scoring
from api.services.circuit_breaker import CircuitState, whois_breaker

NOW = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
AT = NOW.timestamp()


def _iso(days_ago: float) -> str:
    return (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


@pytest.fixture
def mode(monkeypatch):
    def _set(value: str, min_age: int = 365) -> None:
        monkeypatch.setattr(get_settings(), "allowlist_age_gate", value, raising=False)
        monkeypatch.setattr(get_settings(), "popularity_min_age_days", min_age, raising=False)
    return _set


class _Registry:
    """The registry as the gate sees it.

    answers  entry → rdap.record's answer: a record, {} (404), None, or an
             exception to raise; default: registered 4000 days ago
    dns      entry → check_domain_exists's answer after a 404 (default True)
    servers  the RDAP server of each zone; .ru has none"""

    SERVERS = {"com": "rdap.verisign.com", "net": "rdap.verisign.com", "shop": "rdap.gmoregistry.net",
               "org": "rdap.publicinterestregistry.org", "uk": "rdap.nominet.uk"}

    def __init__(self) -> None:
        self.answers: dict = {}
        self.dns: dict = {}
        self.asked: list[str] = []
        self.clock = [0.0]
        self.sleeps: list[float] = []

    async def lookup(self, name: str, timeout: float):
        self.asked.append(name)
        answer = self.answers.get(name, {"found": True, "registered": _iso(4000)})
        if isinstance(answer, BaseException):
            raise answer
        return answer

    async def server(self, name: str, timeout: float):
        return self.SERVERS.get(name.rsplit(".", 1)[-1])

    async def exists(self, name: str):
        return self.dns.get(name, True)

    async def sleep(self, seconds: float):
        self.sleeps.append(seconds)


@pytest.fixture
def registry(monkeypatch) -> _Registry:
    reg = _Registry()
    monkeypatch.setattr(allowlist_age, "_lookup", reg.lookup)
    monkeypatch.setattr(allowlist_age, "_server", reg.server)
    monkeypatch.setattr(allowlist_age, "_exists", reg.exists)
    monkeypatch.setattr(allowlist_age, "_sleep", reg.sleep)
    monkeypatch.setattr(allowlist_age, "_clock", lambda: NOW)
    monkeypatch.setattr(allowlist_age, "_monotonic", lambda: reg.clock[0])
    return reg


def _gate(domain: str) -> str:
    return asyncio.run(allowlist_age.gate(domain))


def _gate_and_fill(*domains: str) -> list[str]:
    """Each domain's answer, then the worker's lookups to the end."""
    async def go():
        out = [await allowlist_age.gate(d) for d in domains]
        await allowlist_age.drain()
        return out
    return asyncio.run(go())


def _stored(fake_redis, entry: str):
    raw = fake_redis._kv.get(allowlist_age.KEY + entry)
    return None if raw is None else json.loads(raw)


def _ttl(fake_redis, entry: str):
    return fake_redis._ttls.get(allowlist_age.KEY + entry)


def _store(fake_redis, entry: str, record: dict, at: float = AT, every: float = allowlist_age.EVERY_DATED_S) -> None:
    fake_redis._kv[allowlist_age.KEY + entry] = json.dumps({**record, "at": at, "every": every})


def _young(days: int = 40) -> dict:
    return {"registered": _iso(days)}


# ── "off" ──

def test_off_reads_nothing_and_asks_nothing(mode, registry, fake_redis, monkeypatch):
    mode("off")
    _store(fake_redis, "google.com", _young())
    reads = []

    async def _counting():
        reads.append(1)
        return fake_redis

    monkeypatch.setattr("api.services.cache.get_redis", _counting)
    assert _gate_and_fill("google.com", "github.com") == [allowlist_age.TRUST, allowlist_age.TRUST]
    assert reads == [] and registry.asked == []
    assert allowlist_age._filler.task is None and not allowlist_age._filler.queued


def test_the_gate_is_off_unless_switched_on():
    from api.config import Settings
    assert Settings.model_fields["allowlist_age_gate"].default == "off"


# ── A name not known yet ──

def test_a_name_not_known_yet_is_answered_as_before_and_looked_up_once(mode, registry, fake_redis):
    mode("shadow")
    assert _gate_and_fill("google.com", "www.google.com") == [allowlist_age.TRUST, allowlist_age.TRUST]
    assert registry.asked == ["google.com"]  # www. reads its entry's record; one lookup for both
    assert _stored(fake_redis, "google.com") == {"registered": _iso(4000), "found": True, "at": AT,
                                                 "every": allowlist_age.EVERY_DATED_S}
    assert _ttl(fake_redis, "google.com") == allowlist_age.KEEP_S


def test_when_on_a_name_not_known_yet_is_trusted_but_not_for_the_cache(mode, registry, fake_redis):
    mode("on")
    assert _gate_and_fill("google.com") == [allowlist_age.TRUST_UNCACHED]
    assert _gate("google.com") == allowlist_age.TRUST  # known now: 4000 days


def test_a_batch_is_read_in_one_round_trip(mode, registry, fake_redis, monkeypatch):
    mode("on")
    _store(fake_redis, "google.com", _young())
    _store(fake_redis, "github.com", {"registered": _iso(4000)})
    calls = []
    real = fake_redis.mget

    async def _mget(keys):
        calls.append(list(keys))
        return await real(keys)

    monkeypatch.setattr(fake_redis, "mget", _mget)
    out = asyncio.run(allowlist_age.gate_many(["google.com", "www.google.com", "github.com", "example-unlisted-name.com"]))
    assert out == {"google.com": allowlist_age.WITHHOLD, "www.google.com": allowlist_age.WITHHOLD,
                   "github.com": allowlist_age.TRUST, "example-unlisted-name.com": allowlist_age.TRUST}
    assert calls == [[allowlist_age.KEY + "github.com", allowlist_age.KEY + "google.com"]]


def test_a_name_already_queued_or_being_asked_is_not_queued_twice(mode, registry, fake_redis):
    mode("shadow")
    _gate_and_fill("google.com", "google.com", "github.com", "google.com")
    assert registry.asked == ["google.com", "github.com"]


def test_a_full_queue_drops_its_oldest_name_not_the_newest(mode, registry, fake_redis, monkeypatch):
    mode("shadow")
    monkeypatch.setattr(allowlist_age, "MAX_QUEUED", 2)

    async def go():
        for d in ("google.com", "github.com", "wikipedia.org"):
            allowlist_age._filler.add(d, None)  # no await in between: the worker has not started
        await allowlist_age.drain()

    asyncio.run(go())
    assert registry.asked == ["github.com", "wikipedia.org"]


def test_the_name_checked_most_is_asked_first_and_kept_when_the_queue_is_full(mode, registry, fake_redis, monkeypatch):
    """A flood of names checked once must not push out the one a campaign's
    victims keep checking."""
    mode("shadow")
    monkeypatch.setattr(allowlist_age, "MAX_QUEUED", 3)

    async def go():
        q = allowlist_age._filler
        q.add("google.com", None, "ip:a")
        q.add("github.com", None, "ip:a")
        q.add("wikipedia.org", None, "ip:a")
        q.add("wikipedia.org", None, "ip:b")    # checked by someone else while it waits
        q.add("google.com", None, "ip:b")
        q.add("google.com", None, "ip:c")
        q.add("bing.com", None, "ip:a")         # full: github.com (one requester, the oldest of those) goes
        await allowlist_age.drain()

    asyncio.run(go())
    assert registry.asked == ["google.com", "wikipedia.org", "bing.com"]


def test_the_name_checked_most_is_asked_first(mode, registry, fake_redis):
    mode("shadow")

    async def go():
        q = allowlist_age._filler
        for d, who in (("github.com", "ip:a"), ("google.com", "ip:a"), ("wikipedia.org", "ip:a"),
                       ("wikipedia.org", "ip:b"), ("google.com", "ip:b"), ("google.com", "ip:c")):
            q.add(d, None, who)
        await allowlist_age.drain()

    asyncio.run(go())
    assert registry.asked == ["google.com", "wikipedia.org", "github.com"]


def test_one_requester_checking_again_or_in_subdomains_does_not_move_a_name_forward(mode, registry, fake_redis, monkeypatch):
    """Fifty subdomains in one batch are one name, and the same account
    checking it again is still one requester."""
    mode("on")

    async def _idle(self):  # the worker stays out of it: the queue is what is looked at
        return None

    monkeypatch.setattr(allowlist_age._Filler, "_run", _idle)

    async def go():
        await allowlist_age.gate_many([f"s{i}.wikipedia.org" for i in range(50)], requester="user:a")
        await allowlist_age.gate_many(["wikipedia.org"], requester="user:a")
        await allowlist_age.gate_many(["google.com"], requester="user:b")
        await allowlist_age.gate_many(["google.com"], requester="user:c")
        voters = {e: set(v[0]) for e, v in allowlist_age._filler.queued.items()}
        return voters, allowlist_age._requesters["user:a"][1]

    voters, used = asyncio.run(go())
    assert voters == {"wikipedia.org": {"user:a"}, "google.com": {"user:b", "user:c"}}
    assert used == 1


def test_a_vote_for_a_queued_name_counts_against_the_requesters_minute(mode, registry, fake_redis):
    mode("on")
    q = allowlist_age._filler

    async def go():
        for i in range(allowlist_age.MAX_NEW_PER_REQUESTER):
            q.add(f"name{i}.example", None, f"ip:other{i}")
        for i in range(allowlist_age.MAX_NEW_PER_REQUESTER + 5):
            q.add(f"name{i}.example" if i < allowlist_age.MAX_NEW_PER_REQUESTER else "google.com", None, "ip:flood")
        return {e: len(v[0]) for e, v in q.queued.items()}

    counts = asyncio.run(go())
    assert all(counts[f"name{i}.example"] == 2 for i in range(allowlist_age.MAX_NEW_PER_REQUESTER))
    assert "google.com" not in counts  # the minute's twenty went on votes


def test_one_requester_queues_at_most_twenty_names_a_minute(mode, registry, fake_redis):
    mode("on")
    names = sorted(d for d in scoring.TOP_DOMAINS if d.endswith(".org") and allowlist_age.gated_entry(d) == d)[:25]

    async def go():
        await allowlist_age.gate_many(names, requester="user:flood")
        flooded = len(allowlist_age._filler.queued) + (allowlist_age._filler.current is not None)
        await allowlist_age.gate_many(["google.com"], requester="user:victim")
        return flooded, "google.com" in allowlist_age._filler.queued

    flooded, victim_queued = asyncio.run(go())
    assert flooded == allowlist_age.MAX_NEW_PER_REQUESTER == 20
    assert victim_queued
    registry.clock[0] = 61.0
    assert allowlist_age._admit("user:flood")  # a new minute


def test_one_lookup_a_second_and_no_wait_for_nothing_asked(mode, registry, fake_redis):
    mode("shadow")
    registry.answers["github.com"] = httpx.ConnectError("no route")
    _gate_and_fill("google.com", "github.com", "sberbank.ru")  # .ru: no RDAP server, nobody asked
    assert registry.asked == ["google.com", "github.com"]
    assert registry.sleeps == [allowlist_age.MIN_INTERVAL_S] * 2
    assert allowlist_age.MIN_INTERVAL_S == 1.0


# ── Young, old, absent ──

@pytest.mark.parametrize("days, young", [(10, True), (364, True), (365, False), (4000, False)])
def test_a_registration_younger_than_the_limit_is_withheld_when_on(mode, registry, fake_redis, days, young):
    mode("on")
    _store(fake_redis, "google.com", {"registered": _iso(days)})
    assert _gate("google.com") == (allowlist_age.WITHHOLD if young else allowlist_age.TRUST)
    assert registry.asked == []


def test_a_name_neither_the_registry_nor_dns_knows_is_withheld_and_asked_hourly(mode, registry, fake_redis):
    """404 and NXDOMAIN: deleted — a drop-catch can come any minute."""
    mode("on")
    registry.answers["google.com"] = {}
    registry.dns["google.com"] = False
    _gate_and_fill("google.com")
    assert _stored(fake_redis, "google.com") == {"absent": True, "at": AT, "every": allowlist_age.EVERY_LEAVING_S}
    assert _gate("google.com") == allowlist_age.WITHHOLD


def test_a_404_for_a_zone_the_registry_does_not_run_is_no_absent(mode, registry, fake_redis):
    """Nominet answers 404 for ox.ac.uk, www.nhs.uk, met.police.uk (live,
    2026-11-01): those zones are not Nominet's, and the names resolve."""
    mode("on")
    assert allowlist_age.gated_entry("ox.ac.uk") == "ox.ac.uk"
    registry.answers["ox.ac.uk"] = {}
    _gate_and_fill("ox.ac.uk")
    assert _stored(fake_redis, "ox.ac.uk")["unknowable"] is True
    assert _gate("ox.ac.uk") == allowlist_age.TRUST


def test_a_404_for_a_name_the_registry_knew_while_it_still_resolves_is_asked_hourly(mode, registry, fake_redis):
    """Deleted moments ago, or about to be registered again: not a week of trust."""
    mode("on")
    _store(fake_redis, "google.com", {"registered": _iso(4000), "found": True, "leaving": True}, at=AT - 7200,
           every=allowlist_age.EVERY_LEAVING_S)
    registry.answers["google.com"] = {}
    _gate_and_fill("google.com")
    assert _stored(fake_redis, "google.com") == {"registered": _iso(4000), "found": True, "leaving": True, "at": AT,
                                                 "every": allowlist_age.EVERY_LEAVING_S}
    assert _gate("google.com") == allowlist_age.TRUST_UNCACHED


def test_a_dateless_record_the_registry_had_then_a_404_while_it_resolves_is_asked_hourly(mode, registry, fake_redis):
    mode("on")
    _store(fake_redis, "google.com", {"unknowable": True, "found": True, "leaving": True}, at=AT - 7200,
           every=allowlist_age.EVERY_LEAVING_S)
    registry.answers["google.com"] = {}
    _gate_and_fill("google.com")
    assert _stored(fake_redis, "google.com")["every"] == allowlist_age.EVERY_LEAVING_S
    assert _gate("google.com") == allowlist_age.TRUST_UNCACHED


def test_a_name_gone_before_that_resolves_again_is_no_longer_absent(mode, registry, fake_redis):
    """Absent once (404 + NXDOMAIN); now it resolves and the registry has no
    record yet: neither withheld for good nor trusted for a week."""
    mode("on")
    _store(fake_redis, "ox.ac.uk", {"absent": True}, at=AT - 7200, every=allowlist_age.EVERY_LEAVING_S)
    registry.answers["ox.ac.uk"] = {}
    _gate_and_fill("ox.ac.uk")
    assert _stored(fake_redis, "ox.ac.uk") == {"unknowable": True, "leaving": True, "at": AT,
                                               "every": allowlist_age.EVERY_LEAVING_S}
    assert _gate("ox.ac.uk") == allowlist_age.TRUST_UNCACHED


def test_a_404_for_a_name_right_under_its_tld_while_it_resolves_is_asked_hourly_every_time(mode, registry, fake_redis):
    """google.com is Verisign's to hold: a 404 while it still resolves is a
    deletion or a new registration on its way — hour after hour, not a week."""
    mode("on")
    registry.answers["google.com"] = {}
    for hour in range(3):
        if hour:
            _store(fake_redis, "google.com", _record_of_stored(fake_redis, "google.com"), at=AT - 7200,
                   every=allowlist_age.EVERY_LEAVING_S)
            allowlist_age.reset_for_tests()
        _gate_and_fill("google.com")
        assert _stored(fake_redis, "google.com")["every"] == allowlist_age.EVERY_LEAVING_S
        assert _gate("google.com") == allowlist_age.TRUST_UNCACHED


def test_a_404_for_a_known_name_while_dns_cannot_tell_is_not_cached_as_trusted(mode, registry, fake_redis):
    mode("on")
    _store(fake_redis, "bbc.co.uk", {"registered": _iso(4000), "found": True}, at=AT - 8 * 86400)
    registry.answers["bbc.co.uk"] = {}
    registry.dns["bbc.co.uk"] = None
    _gate_and_fill("bbc.co.uk")
    assert _stored(fake_redis, "bbc.co.uk")["leaving"] is True
    assert _gate("bbc.co.uk") == allowlist_age.TRUST_UNCACHED


def _record_of_stored(fake_redis, entry: str) -> dict:
    return {k: v for k, v in _stored(fake_redis, entry).items() if k not in ("at", "every")}


def test_dns_trouble_after_a_404_does_not_pause_the_registry(mode, registry, fake_redis):
    mode("shadow")
    names = sorted(d for d in scoring.TOP_DOMAINS if d.endswith(".ac.uk") and allowlist_age.gated_entry(d) == d)[:6]
    for n in names:
        registry.answers[n] = {}
        registry.dns[n] = None
    _gate_and_fill(*names)
    assert registry.asked == names
    assert not allowlist_age._filler.paused and not allowlist_age._filler.failures


def test_a_404_dns_cannot_settle_is_a_failed_lookup(mode, registry, fake_redis):
    mode("on")
    registry.answers["google.com"] = {}
    registry.dns["google.com"] = None
    _gate_and_fill("google.com")
    assert _stored(fake_redis, "google.com")["failed"] is True
    assert _gate("google.com") == allowlist_age.TRUST_UNCACHED


def test_a_found_record_without_a_date_is_not_gated(mode, registry, fake_redis):
    mode("on")
    registry.answers["google.com"] = {"found": True, "status": ["active"]}
    _gate_and_fill("google.com")
    assert _stored(fake_redis, "google.com")["unknowable"] is True
    assert _gate("google.com") == allowlist_age.TRUST


@pytest.mark.parametrize("record, every", [
    ({"status": ["active", "pending delete"]}, allowlist_age.EVERY_LEAVING_S),
    ({"status": ["redemption period"]}, allowlist_age.EVERY_LEAVING_S),
    ({"status": ["auto renew period"]}, allowlist_age.EVERY_EXPIRING_S),
    ({"expires": _iso(-10)}, allowlist_age.EVERY_EXPIRING_S),   # expires in 10 days
    ({"expires": _iso(3)}, allowlist_age.EVERY_EXPIRING_S),     # expired 3 days ago
])
def test_a_name_on_its_way_out_is_asked_again_sooner_and_not_cached_as_trusted(mode, registry, fake_redis, record, every):
    mode("on")
    registry.answers["google.com"] = {"found": True, "registered": _iso(4000), **record}
    _gate_and_fill("google.com")
    assert _stored(fake_redis, "google.com") == {"registered": _iso(4000), "found": True, "leaving": True,
                                                 "at": AT, "every": every}
    assert _gate("google.com") == allowlist_age.TRUST_UNCACHED


def test_a_record_being_deleted_without_a_date_is_asked_hourly_and_not_cached_as_trusted(mode, registry, fake_redis):
    mode("on")
    registry.answers["google.com"] = {"found": True, "status": ["pending delete"]}
    _gate_and_fill("google.com")
    assert _stored(fake_redis, "google.com") == {"unknowable": True, "found": True, "leaving": True, "at": AT,
                                                 "every": allowlist_age.EVERY_LEAVING_S}
    assert _gate("google.com") == allowlist_age.TRUST_UNCACHED


def test_a_healthy_name_is_asked_again_in_a_week(mode, registry, fake_redis):
    mode("on")
    registry.answers["google.com"] = {"found": True, "registered": _iso(4000), "expires": _iso(-200),
                                      "status": ["client transfer prohibited"]}
    _gate_and_fill("google.com")
    assert _stored(fake_redis, "google.com")["every"] == allowlist_age.EVERY_DATED_S
    assert _gate("google.com") == allowlist_age.TRUST


def test_a_zone_without_rdap_is_remembered_and_never_gated(mode, registry, fake_redis):
    """.ru has no RDAP server: sberbank.ru can never be gated (docs)."""
    mode("on")
    assert _gate_and_fill("sberbank.ru") == [allowlist_age.TRUST_UNCACHED]
    assert _stored(fake_redis, "sberbank.ru")["unknowable"] is True
    assert _gate("sberbank.ru") == allowlist_age.TRUST
    assert registry.asked == []


# ── Asked again ──

def test_a_record_that_is_due_is_asked_again_and_still_read_meanwhile(mode, registry, fake_redis):
    mode("on")
    _store(fake_redis, "google.com", _young(), at=AT - 8 * 86400)
    registry.answers["google.com"] = {"found": True, "registered": _iso(41)}
    assert _gate_and_fill("google.com") == [allowlist_age.WITHHOLD]
    assert registry.asked == ["google.com"]
    assert _stored(fake_redis, "google.com")["registered"] == _iso(41)


def test_asking_again_and_failing_keeps_the_last_record(mode, registry, fake_redis):
    """A young name whose refresh fails is not trusted again for that."""
    mode("on")
    _store(fake_redis, "vivastore.shop", _young(), at=AT - 8 * 86400)
    registry.answers["vivastore.shop"] = httpx.ReadTimeout("slow")
    _gate_and_fill("vivastore.shop")
    assert _stored(fake_redis, "vivastore.shop") == {"registered": _iso(40), "at": AT, "every": allowlist_age.EVERY_FAILED_S}
    assert _ttl(fake_redis, "vivastore.shop") == allowlist_age.KEEP_S
    allowlist_age.reset_for_tests()
    assert _gate("vivastore.shop") == allowlist_age.WITHHOLD


# ── Several processes ──

def test_a_name_another_process_just_asked_about_is_not_asked_again(mode, registry, fake_redis):
    mode("on")
    _store(fake_redis, "google.com", {"registered": _iso(4000)}, at=AT - 8 * 86400)

    async def go():
        await allowlist_age.gate("google.com")  # due: queued
        _store(fake_redis, "google.com", _young())  # meanwhile another process asked
        await allowlist_age.drain()

    asyncio.run(go())
    assert registry.asked == []
    assert _gate("google.com") == allowlist_age.WITHHOLD


@pytest.mark.parametrize("last", [None, {"registered": _iso(4000)}])
def test_a_failed_ask_never_overwrites_a_newer_record_of_another_process(mode, registry, fake_redis, monkeypatch, last):
    mode("on")
    registry.answers["vivastore.shop"] = _status_error(429)
    real = registry.lookup

    async def _lookup_while_another_stores(name, timeout):
        _store(fake_redis, name, _young(), at=AT + 1)  # the other process's answer lands first
        return await real(name, timeout)

    monkeypatch.setattr(allowlist_age, "_lookup", _lookup_while_another_stores)
    stale = None if last is None else {**last, "at": AT - 8 * 86400, "every": allowlist_age.EVERY_DATED_S}

    async def go():
        allowlist_age._filler.add("vivastore.shop", stale)
        await allowlist_age.drain()

    asyncio.run(go())
    assert _stored(fake_redis, "vivastore.shop")["registered"] == _iso(40)
    allowlist_age.reset_for_tests()
    assert _gate("vivastore.shop") == allowlist_age.WITHHOLD


def test_one_copy_per_batch_a_copy_expiring_during_the_read_is_still_read(mode, registry, fake_redis, monkeypatch):
    mode("on")
    _store(fake_redis, "google.com", _young())
    assert _gate("google.com") == allowlist_age.WITHHOLD  # now in this process's copy
    real = fake_redis.mget

    async def _mget_while_the_copy_expires(keys):
        registry.clock[0] = allowlist_age.LOCAL_TTL_S + 1
        return await real(keys)

    monkeypatch.setattr(fake_redis, "mget", _mget_while_the_copy_expires)
    out = asyncio.run(allowlist_age.gate_many(["google.com", "github.com"]))
    assert out["google.com"] == allowlist_age.WITHHOLD


# ── Failures answer as before ──

def test_redis_down_trusts_without_caching_and_asks_nothing(mode, registry, redis_down):
    mode("on")
    assert _gate_and_fill("google.com") == [allowlist_age.TRUST_UNCACHED]
    assert registry.asked == []


def test_a_slow_redis_is_not_waited_for(mode, registry, fake_redis, monkeypatch):
    mode("on")
    _store(fake_redis, "google.com", {"registered": _iso(4000)})

    async def _slow(keys):
        await asyncio.sleep(allowlist_age.REDIS_GET_TIMEOUT_S + 0.2)
        return [None for _ in keys]

    monkeypatch.setattr(fake_redis, "mget", _slow)
    assert _gate_and_fill("google.com") == [allowlist_age.TRUST_UNCACHED]
    assert registry.asked == []


def test_an_unreadable_record_is_a_miss(mode, registry, fake_redis):
    mode("on")
    fake_redis._kv[allowlist_age.KEY + "google.com"] = "{not json"
    assert _gate_and_fill("google.com") == [allowlist_age.TRUST_UNCACHED]
    assert registry.asked == ["google.com"]


def test_a_failed_lookup_is_asked_again_in_an_hour_and_not_trusted_for_the_cache(mode, registry, fake_redis):
    mode("on")
    registry.answers["google.com"] = httpx.ConnectError("no route")
    _gate_and_fill("google.com")
    assert _stored(fake_redis, "google.com") == {"failed": True, "at": AT, "every": allowlist_age.EVERY_FAILED_S}
    assert _ttl(fake_redis, "google.com") == allowlist_age.EVERY_FAILED_S
    assert _gate("google.com") == allowlist_age.TRUST_UNCACHED


def _status_error(status: int, headers=None) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://rdap.example/domain/x")
    return httpx.HTTPStatusError("x", request=request, response=httpx.Response(status, headers=headers, request=request))


@pytest.mark.parametrize("status", [429, 503])
def test_a_server_asking_to_slow_down_is_left_alone_for_every_zone_it_serves(mode, registry, fake_redis, status):
    mode("shadow")
    registry.answers["google.com"] = _status_error(status, {"Retry-After": "120"})
    _gate_and_fill("google.com", "cnet.com", "slideshare.net", "wikipedia.org")
    assert registry.asked == ["google.com", "wikipedia.org"]  # Verisign's .com and .net paused, .org asked
    assert allowlist_age._filler.paused["rdap.verisign.com"] == 120.0
    assert _stored(fake_redis, "cnet.com") is None  # not stored: asked on a later check
    pause_key = allowlist_age.PAUSE_KEY + "rdap.verisign.com"
    assert fake_redis._ttls[pause_key] == 120  # every process leaves it alone
    registry.clock[0] = 119.0
    _gate_and_fill("cnet.com")
    assert registry.asked == ["google.com", "wikipedia.org"]
    registry.clock[0] = 121.0
    fake_redis._kv.pop(pause_key)  # FakeRedis does not expire keys: the pause ends here
    _gate_and_fill("cnet.com")
    assert registry.asked == ["google.com", "wikipedia.org", "cnet.com"]


def test_a_pause_another_process_was_told_stops_this_one_too(mode, registry, fake_redis):
    mode("shadow")
    fake_redis._kv[allowlist_age.PAUSE_KEY + "rdap.verisign.com"] = "1"
    _gate_and_fill("google.com", "wikipedia.org")
    assert registry.asked == ["wikipedia.org"]


@pytest.mark.parametrize("header, pause", [
    ({}, allowlist_age.PAUSE_S),
    ({"Retry-After": "nan"}, allowlist_age.PAUSE_S),
    ({"Retry-After": "5"}, allowlist_age.MIN_PAUSE_S),
    ({"Retry-After": "99999"}, allowlist_age.MAX_PAUSE_S),
    ({"Retry-After": "an hour from now, as an HTTP date"}, 3600.0),
])
def test_retry_after_in_seconds_or_as_a_date(header, pause):
    if header.get("Retry-After", "").startswith("an hour"):
        header = {"Retry-After": format_datetime(datetime.now(timezone.utc) + timedelta(hours=1), usegmt=True)}
    response = httpx.Response(429, headers=header)
    assert allowlist_age._retry_after(response) == pytest.approx(pause, abs=5)


def _shop_names(n: int) -> list[str]:
    return sorted(d for d in scoring.TOP_DOMAINS if d.endswith(".shop") and allowlist_age.gated_entry(d) == d)[:n]


def test_five_failures_in_a_row_leave_the_server_alone_for_15_minutes(mode, registry, fake_redis):
    mode("shadow")
    names = _shop_names(7)
    for n in names:
        registry.answers[n] = httpx.ReadTimeout("slow")
    _gate_and_fill(*names)
    assert registry.asked == names[:5]
    assert allowlist_age._filler.paused["rdap.gmoregistry.net"] == allowlist_age.FAILURE_PAUSE_S


def test_a_success_starts_the_count_of_failures_again(mode, registry, fake_redis):
    mode("shadow")
    names = _shop_names(7)
    for i, n in enumerate(names):
        if i != 2:
            registry.answers[n] = httpx.ReadTimeout("slow")
    _gate_and_fill(*names)
    assert registry.asked == names  # fail, fail, ok, then four: never five in a row


def test_an_open_whois_breaker_asks_nothing_and_stores_nothing(mode, registry, fake_redis, monkeypatch):
    mode("shadow")
    monkeypatch.setattr(whois_breaker, "_state", CircuitState.OPEN)
    monkeypatch.setattr(whois_breaker, "_last_failure_time", 10**12)
    _gate_and_fill("google.com")
    assert registry.asked == [] and _stored(fake_redis, "google.com") is None


def test_a_store_that_fails_does_not_send_every_check_to_the_registry(mode, registry, fake_redis, monkeypatch):
    mode("shadow")

    async def _refuse(*a, **k):
        raise ConnectionError("OOM command not allowed")

    monkeypatch.setattr(fake_redis, "setex", _refuse)
    _gate_and_fill("google.com")
    registry.clock[0] = allowlist_age.LOCAL_TTL_S + 60  # past the usual local copy, before it is due
    _gate_and_fill("google.com")
    assert registry.asked == ["google.com"]


def test_this_processs_copy_expires_and_redis_is_read_again(mode, registry, fake_redis):
    mode("on")
    _store(fake_redis, "google.com", {"registered": _iso(4000)})
    assert _gate("google.com") == allowlist_age.TRUST
    _store(fake_redis, "google.com", _young())  # another worker learned better
    assert _gate("google.com") == allowlist_age.TRUST
    registry.clock[0] = allowlist_age.LOCAL_TTL_S + 1
    assert _gate("google.com") == allowlist_age.WITHHOLD


def test_stop_cancels_the_worker(mode, registry, fake_redis, monkeypatch):
    mode("shadow")

    async def _hang(name, timeout):
        await asyncio.sleep(30)

    monkeypatch.setattr(allowlist_age, "_lookup", _hang)

    async def go():
        await allowlist_age.gate("google.com")
        await asyncio.sleep(0)
        await allowlist_age.stop()
        return allowlist_age._filler.task.done()

    assert asyncio.run(go())


def test_the_api_stops_the_worker_before_redis_closes():
    import inspect

    from api import main
    source = inspect.getsource(main.lifespan)
    assert source.index("allowlist_age.stop()") < source.index("await close_redis()")


# ── What is never asked ──

@pytest.mark.parametrize("domain", [
    "example-unlisted-name.com",  # not in the list
    "x.blogspot.com",             # a tenant of a shared platform: the allowlist does not answer it
    "irs.gov",                    # a government name: registered only by a state
    "amazon.com.be",              # its registrable is com.be: the registry would be asked about com.be
])
def test_nothing_is_asked_where_the_gate_has_nothing_to_say(mode, registry, fake_redis, domain):
    mode("on")
    assert _gate_and_fill(domain) == [allowlist_age.TRUST]
    assert registry.asked == []


# ── Shadow ──

def test_shadow_logs_a_young_name_once_a_day_and_never_withholds(mode, registry, fake_redis, caplog):
    mode("shadow")
    _store(fake_redis, "google.com", _young())
    with caplog.at_level(logging.INFO, logger="cleanway.allowlist_age"):
        assert _gate("www.google.com") == allowlist_age.TRUST
        assert _gate("google.com") == allowlist_age.TRUST
        registry.clock[0] = allowlist_age.SHADOW_EVERY_S + 1
        assert _gate("google.com") == allowlist_age.TRUST
    lines = [r for r in caplog.records if r.getMessage() == "allowlist_age_gate_shadow"]
    assert len(lines) == 2
    assert (lines[0].domain, lines[0].entry, lines[0].age_days, lines[0].outcome) == ("www.google.com", "google.com", 40, "young")


def test_shadow_logs_a_young_name_the_worker_just_found(mode, registry, fake_redis, caplog):
    """The check that queued it would have been gated had its record been known."""
    mode("shadow")
    registry.answers["google.com"] = {"found": True, "registered": _iso(40)}
    with caplog.at_level(logging.INFO, logger="cleanway.allowlist_age"):
        _gate_and_fill("google.com")
    assert [r.outcome for r in caplog.records if r.getMessage() == "allowlist_age_gate_shadow"] == ["young"]


def test_on_logs_nothing_per_check(mode, registry, fake_redis, caplog):
    mode("on")
    _store(fake_redis, "google.com", _young())
    with caplog.at_level(logging.INFO, logger="cleanway.allowlist_age"):
        assert _gate("google.com") == allowlist_age.WITHHOLD
    assert not [r for r in caplog.records if r.getMessage() == "allowlist_age_gate_shadow"]


# ── The analysis of a withheld name ──

RANKED = {"ranked": True, "rank": 5, "weight": -8, "label": "Top 1K", "registrable_rank": 5}


def _signals(domain: str, age, *, withheld: bool = False, tranco=RANKED) -> dict:
    outcomes = {
        "whois": ({"age_days": age} if age is not None else {}, True),
        "tranco": (tranco, True),
    }
    signals = analyzer._build_signals(domain, domain, False, outcomes, 18, allowlist_withheld=withheld)
    signals.update(checks_succeeded=18, total_checks=18)
    return signals


def test_a_withheld_name_gets_neither_the_allowlist_nor_its_rank(mode):
    mode("shadow")  # the router's word is enough, whatever the analysis's own lookup says
    for age in (None, 4000):
        signals = _signals("google.com", age, withheld=True)
        assert signals["allowlist_withheld"] and signals["popularity_withheld"]
        assert signals["tranco_ranked"] is False
        _, _, reasons = scoring.calculate_score(signals)
        assert "known_legitimate" not in {r.signal for r in reasons}
        assert "tranco_popularity" not in {r.signal for r in reasons}


@pytest.mark.parametrize("rank_gate", ["off", "shadow"])
def test_when_on_the_analysis_withholds_a_young_listed_names_allowlist_and_rank(mode, monkeypatch, rank_gate):
    mode("on")
    monkeypatch.setattr(get_settings(), "popularity_age_gate", rank_gate, raising=False)
    signals = _signals("google.com", 40)
    assert signals["allowlist_withheld"] and signals["popularity_withheld"]
    assert signals["tranco_ranked"] is False
    _, _, reasons = scoring.calculate_score(signals)
    assert not {"known_legitimate", "tranco_popularity"} & {r.signal for r in reasons}


def test_when_on_the_analysis_withholds_a_young_listed_name_itself(mode):
    mode("on")
    assert _signals("google.com", 40)["allowlist_withheld"]
    assert not _signals("google.com", 4000)["allowlist_withheld"]
    assert not _signals("google.com", None)["allowlist_withheld"]  # unknown age: as before
    assert not _signals("irs.gov", 40)["allowlist_withheld"]


@pytest.mark.parametrize("gate", ["off", "shadow"])
def test_unless_on_a_young_listed_name_keeps_the_allowlist(mode, gate):
    mode(gate)
    signals = _signals("google.com", 40)
    assert not signals["allowlist_withheld"]
    score, level, reasons = scoring.calculate_score(signals)
    assert (score, level) == (0, RiskLevel.safe) and reasons[0].signal == "known_legitimate"


def test_analyze_domain_carries_the_withholding_to_the_verdict(mode, offline_analyzer):
    """End to end: the router's flag reaches the scorer through _judge."""
    mode("shadow")
    offline_analyzer(site="reachable", values={"tranco": RANKED, "whois": {"age_days": 4000}})
    plain = asyncio.run(analyzer.analyze_domain("google.com", budget_s=5.0))
    withheld = asyncio.run(analyzer.analyze_domain("google.com", budget_s=5.0, allowlist_withheld=True))
    assert "known_legitimate" in {r.signal for r in plain.reasons}
    assert not {"known_legitimate", "tranco_popularity"} & {r.signal for r in withheld.reasons}
    assert withheld.verdict_basis != "allowlist"


def test_the_rule_only_answer_keeps_the_withholding():
    """No capacity left for the analysis: the address alone, still not the allowlist."""
    plain = analyzer.rule_only_result("google.com")
    assert plain.verdict_basis == "allowlist"
    withheld = analyzer.rule_only_result("google.com", allowlist_withheld=True)
    assert withheld.verdict_basis != "allowlist"
    assert "known_legitimate" not in {r.signal for r in withheld.reasons}


# ── The routers ──

class _RouterRedis:
    """FakeRedis plus the blocklist's pipelined SISMEMBER (nothing listed)."""

    def __init__(self, fake):
        self._fake = fake

    def __getattr__(self, name):
        return getattr(self._fake, name)

    def pipeline(self):
        class _Pipe:
            def __init__(self):
                self.names = []

            def sismember(self, key, name):
                self.names.append(name)

            async def execute(self):
                return [False for _ in self.names]

        return _Pipe()


@pytest.fixture
def router_redis(monkeypatch, fake_redis):
    wrapped = _RouterRedis(fake_redis)

    async def _get():
        return wrapped

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    return fake_redis


@pytest.fixture
def analysed(monkeypatch):
    """The analyses the routers ran: (domain, allowlist_withheld)."""
    from api.models.schemas import DomainResult
    from api.routers import check as check_router
    from api.services import competitor_verdicts

    calls: list = []

    async def _analyze(domain, *a, allowlist_withheld=False, **k):
        calls.append((domain, allowlist_withheld))
        return DomainResult(domain=domain, score=30, level=RiskLevel.caution, reasons=[],
                            verdict_basis="heuristics")

    async def _no_competitors(*a, **k):
        return []

    monkeypatch.setattr(analyzer, "analyze_domain", _analyze)
    monkeypatch.setattr(check_router, "analyze_domain", _analyze)
    monkeypatch.setattr(competitor_verdicts, "gather_competitor_verdicts", _no_competitors)
    return calls


def _public(domain: str) -> dict:
    from fastapi.testclient import TestClient

    from api.main import app
    return TestClient(app).get(f"/api/v1/public/check/{domain}").json()


def _authed(monkeypatch, *domains: str) -> list[dict]:
    from fastapi.testclient import TestClient

    from api.main import app
    from api.models.schemas import AuthUser, UserTier
    from api.routers import check as check_router
    from api.services.auth import get_current_user_no_disposable

    async def _no_burst(user):
        return None

    async def _quota(user, num_domains=1):
        return 99

    monkeypatch.setattr(check_router, "check_burst_only", _no_burst)
    monkeypatch.setattr(check_router, "check_rate_limit", _quota)
    app.dependency_overrides[get_current_user_no_disposable] = lambda: AuthUser(
        id="u1", email="u@example.com", tier=UserTier.free)
    try:
        resp = TestClient(app).post("/api/v1/check", json={"domains": list(domains)})
    finally:
        app.dependency_overrides.clear()
    return resp.json()["results"]


def test_public_check_analyses_a_withheld_name(mode, registry, router_redis, analysed):
    mode("on")
    _store(router_redis, "google.com", _young())
    body = _public("www.google.com")
    assert analysed == [("www.google.com", True)]
    assert body["verdict_basis"] != "allowlist"


@pytest.mark.parametrize("gate", ["off", "shadow"])
def test_public_check_still_answers_a_young_name_from_the_allowlist_unless_on(mode, registry, router_redis, analysed, gate):
    mode(gate)
    _store(router_redis, "google.com", _young())
    assert _public("google.com")["verdict_basis"] == "allowlist"
    assert analysed == []


def test_public_check_falls_back_without_the_allowlist_when_the_analysis_fails(mode, registry, router_redis, monkeypatch):
    from api.services import competitor_verdicts

    async def _boom(*a, **k):
        raise RuntimeError("analysis failed")

    async def _no_competitors(*a, **k):
        return []

    mode("on")
    _store(router_redis, "google.com", _young())
    monkeypatch.setattr(analyzer, "analyze_domain", _boom)
    monkeypatch.setattr(competitor_verdicts, "gather_competitor_verdicts", _no_competitors)
    body = _public("google.com")
    assert body["verdict_basis"] != "allowlist", body


def test_authenticated_check_analyses_a_withheld_name(mode, registry, router_redis, analysed, monkeypatch):
    mode("on")
    _store(router_redis, "google.com", _young())
    _store(router_redis, "github.com", {"registered": _iso(4000)})
    results = _authed(monkeypatch, "google.com", "github.com")
    assert analysed == [("google.com", True)]
    assert [r["domain"] for r in results] == ["google.com", "github.com"]
    assert results[1]["verdict_basis"] == "allowlist"


def test_authenticated_check_answers_a_withheld_name_it_had_no_time_for_without_the_allowlist(
        mode, registry, router_redis, monkeypatch):
    from api.routers import check as check_router

    async def _no_time(domains, slots, withheld=frozenset()):
        return [None for _ in domains]

    mode("on")
    _store(router_redis, "google.com", _young())
    monkeypatch.setattr(check_router, "_analyse_batch", _no_time)
    result = _authed(monkeypatch, "google.com")[0]
    assert result["verdict_basis"] != "allowlist"
    assert "known_legitimate" not in {r["signal"] for r in result["reasons"]}


def test_authenticated_check_does_not_cache_a_name_whose_age_is_not_known_yet(mode, registry, router_redis, analysed, monkeypatch):
    mode("on")
    _store(router_redis, "github.com", {"registered": _iso(4000)})
    results = _authed(monkeypatch, "google.com", "github.com")
    assert [r["verdict_basis"] for r in results] == ["allowlist", "allowlist"]
    assert "check:google.com" not in router_redis._kv  # the next check reads the age
    assert "check:github.com" in router_redis._kv


def test_shadow_caches_the_allowlist_answer_as_before(mode, registry, router_redis, analysed, monkeypatch):
    mode("shadow")
    _authed(monkeypatch, "google.com")
    assert "check:google.com" in router_redis._kv

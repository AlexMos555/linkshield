"""confirmed_threats: which analyzer verdicts may reach every phone's blocklist.

Only a DANGEROUS verdict that rests on a threat-intel listing qualifies — a
heuristic guess must never become a DNS block on every phone. The publisher
side (guards, expiry) is pinned in test_refresh_dangerous_domains.py.
"""
from __future__ import annotations

import pytest

from api.services import confirmed_threats as ct

NOW = 1_790_000_000.0


@pytest.mark.parametrize("signal", ct.INTEL_SIGNALS)
def test_each_intel_source_qualifies_a_dangerous_verdict(signal):
    assert ct.should_record("dangerous", {signal: True})


@pytest.mark.parametrize("signals", [
    {},                                                   # heuristics only
    {"phishstats_hit": True},                             # substring match
    {"spamhaus_hit": True, "surbl_hit": True},            # spam lists
    {"alienvault_pulse_count": 12, "ipqs_phishing": True},
    {"watchtower_matched": True, "favicon_cloned": True},  # lookalike guesses
])
def test_heuristics_and_noisy_sources_never_qualify(signals):
    assert not ct.should_record("dangerous", signals)


@pytest.mark.parametrize("level", ["caution", "safe"])
def test_an_intel_hit_that_did_not_end_dangerous_does_not_qualify(level):
    # e.g. a Safe Browsing hit on a site our scorer still called caution.
    assert not ct.should_record(level, {"safe_browsing_hit": True})


def test_split_by_window():
    entries = {"new.example": NOW - 3600, "old.example": NOW - ct.CONFIRMED_WINDOW_SECONDS - 1}
    assert ct.split(entries, NOW) == ({"new.example"}, {"old.example"})


class _Pipe:
    def __init__(self, r):
        self.r, self.calls = r, []

    def __getattr__(self, name):
        def queue(*a, **kw):
            self.calls.append((name, a, kw))
            return self
        return queue

    async def execute(self):
        for name, a, kw in self.calls:
            await getattr(self.r, name)(*a, **kw)


class _Redis:
    def __init__(self):
        self.z: dict = {}
        self.ttl = None

    def pipeline(self, transaction=True):
        return _Pipe(self)

    async def zadd(self, key, mapping):
        self.z.update(mapping)

    async def zremrangebyrank(self, key, start, end):
        rows = sorted(self.z.items(), key=lambda kv: (kv[1], kv[0]))
        stop = len(rows) + end + 1 if end < 0 else end + 1  # Redis ranks are inclusive
        for name, _ in rows[start:max(stop, 0)]:
            del self.z[name]

    async def zremrangebyscore(self, key, low, high):
        cutoff = float(str(high).lstrip("("))
        for name in [n for n, s in self.z.items() if s < cutoff]:
            del self.z[name]

    async def expire(self, key, seconds):
        self.ttl = seconds

    async def zrange(self, key, start, end, withscores=False):
        return sorted(self.z.items(), key=lambda kv: kv[1])


@pytest.mark.asyncio
async def test_record_keeps_the_newest_up_to_the_cap_and_sets_a_ttl(monkeypatch):
    monkeypatch.setattr(ct, "CONFIRMED_MAX", 3)
    r = _Redis()
    for i in range(5):
        await ct.record(r, f"h{i}.example", NOW + i)
    assert set(r.z) == {"h2.example", "h3.example", "h4.example"}
    assert r.ttl == ct.KEY_TTL_SECONDS
    # A re-confirmation moves a host to the front of the line.
    await ct.record(r, "h2.example", NOW + 10)
    await ct.record(r, "h5.example", NOW + 11)
    assert set(r.z) == {"h2.example", "h4.example", "h5.example"}


@pytest.mark.asyncio
async def test_record_if_confirmed_normalises_and_records(monkeypatch):
    r = _Redis()

    async def _get():
        return r

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    assert await ct.record_if_confirmed("Login.Evil.Example.", "dangerous", {"safe_browsing_hit": True}, now=NOW)
    assert r.z == {"login.evil.example": int(NOW)}
    assert not await ct.record_if_confirmed("guess.example", "dangerous", {}, now=NOW)
    assert "guess.example" not in r.z


@pytest.mark.asyncio
async def test_record_if_confirmed_never_raises_and_never_waits_long(monkeypatch):
    import asyncio

    async def _down():
        raise ConnectionError("redis down")

    monkeypatch.setattr("api.services.cache.get_redis", _down)
    assert not await ct.record_if_confirmed("evil.example", "dangerous", {"urlhaus_hit": True})

    class _Slow(_Redis):
        async def zadd(self, key, mapping):
            await asyncio.sleep(5)

    async def _slow():
        return _Slow()

    monkeypatch.setattr("api.services.cache.get_redis", _slow)
    loop = asyncio.get_running_loop()
    started = loop.time()
    assert not await ct.record_if_confirmed("evil.example", "dangerous", {"urlhaus_hit": True})
    assert loop.time() - started < 1.0


@pytest.mark.asyncio
async def test_prune_forgets_only_what_is_past_window_and_grace():
    r = _Redis()
    r.z = {"keep.example": NOW - ct.CONFIRMED_WINDOW_SECONDS - 3600,
           "drop.example": NOW - ct.CONFIRMED_WINDOW_SECONDS - ct.EXPIRED_GRACE_SECONDS - 3600}
    await ct.prune(r, NOW)
    assert set(r.z) == {"keep.example"}

"""Post-publish verification waits for the gateway to load the new list.

2026-10-21: every refresh from 11:58 UTC on was rolled back with
"listed 0-105.com is NOT blocked after publish (rcode 0)". 0-105.com was a
name new in that build. Since 2026-10-09 each API worker answers from an
in-process copy of the phone artifact (api/services/doh_filter.py) that it
re-reads every DOH_FILTER_REFRESH_S (30 s); the check ran ~3 s after the
publish, against the list the workers still held. While the first names in
sort order happened to be on both lists it passed by luck; once a new name
sorted first it failed every run, and each rollback froze the blocklist.

The guard checks (github.com must resolve, …) had the same blind spot: run
against the old list they prove nothing about the new one. So the check now
waits until the gateway blocks the sampled names — the proof it serves the
new list — and only then judges the guards.
"""
from __future__ import annotations

import pytest
from test_refresh_dangerous_domains import rdd

NXDOMAIN, NOERROR = 3, 0


class _Gateway:
    """A live gateway that picks up the new list after `lag` seconds of
    (fake) time; `bad` names are NXDOMAIN once it has."""

    def __init__(self, listed, lag: float, bad=frozenset()) -> None:
        self.listed = set(listed)
        self.lag = lag
        self.bad = set(bad)
        self.now = 0.0
        self.asked: list[tuple[float, str]] = []

    def loaded(self) -> bool:
        return self.now >= self.lag

    async def rcode(self, _client, name):
        self.asked.append((self.now, name))
        if not self.loaded():
            return NOERROR
        return NXDOMAIN if name in self.listed or name in self.bad else NOERROR

    async def sleep(self, seconds):
        self.now += seconds


def _wire(monkeypatch, gw: _Gateway) -> None:
    monkeypatch.setattr(rdd, "_live_rcode", gw.rcode)
    monkeypatch.setattr(rdd, "_sleep", gw.sleep)
    monkeypatch.setattr(rdd, "_monotonic", lambda: gw.now)


SAMPLE = ["0-105.com", "0-106.com", "0-107.com"]


@pytest.mark.asyncio
async def test_a_gateway_that_loads_the_list_within_its_refresh_interval_is_healthy(monkeypatch):
    gw = _Gateway(SAMPLE, lag=25)
    _wire(monkeypatch, gw)
    assert await rdd.verify_published(SAMPLE) == []
    assert gw.now >= 25


@pytest.mark.asyncio
async def test_guards_are_judged_only_once_the_new_list_is_live(monkeypatch):
    """Before the reload github.com resolves whatever the new set says —
    judging it then would pass a set that darkens it."""
    gw = _Gateway(SAMPLE, lag=25, bad={"github.com"})
    _wire(monkeypatch, gw)
    problems = await rdd.verify_published(SAMPLE)
    assert problems == ["github.com is NXDOMAIN after publish"]
    guard_times = [t for t, name in gw.asked if name == "github.com"]
    assert guard_times and min(guard_times) >= 25


@pytest.mark.asyncio
async def test_a_list_the_gateway_never_loads_is_a_failure(monkeypatch):
    gw = _Gateway(SAMPLE, lag=10_000)
    _wire(monkeypatch, gw)
    problems = await rdd.verify_published(SAMPLE)
    assert problems and all("NOT blocked after publish" in p for p in problems)
    assert gw.now <= rdd.VERIFY_WAIT_SECONDS + rdd.VERIFY_POLL_SECONDS


@pytest.mark.asyncio
async def test_an_unreachable_gateway_is_not_a_failure(monkeypatch):
    async def _down(_client, _name):
        return None

    gw = _Gateway(SAMPLE, lag=0)
    _wire(monkeypatch, gw)
    monkeypatch.setattr(rdd, "_live_rcode", _down)
    assert await rdd.verify_published(SAMPLE) == []


@pytest.mark.asyncio
async def test_every_worker_gets_a_refresh_interval_before_the_guards(monkeypatch):
    """Several workers each reload on their own 30 s clock: one answering
    with the new list does not mean the next query's worker has it."""
    gw = _Gateway(SAMPLE, lag=5)
    _wire(monkeypatch, gw)
    assert await rdd.verify_published(SAMPLE) == []
    first_blocked = min(t for t, name in gw.asked if name in SAMPLE and t >= 5)
    guard_times = [t for t, name in gw.asked if name == "github.com"]
    assert min(guard_times) - first_blocked >= rdd.VERIFY_SETTLE_SECONDS


def test_the_sample_prefers_names_new_in_this_publish():
    previous = {"0-001.com", "0-002.com", "0-003.com", "zz-old.com"}
    blockset = previous | {"m-new.com", "a-new.com", rdd.LIST_CANARY}
    assert rdd.verify_sample(blockset, previous) == ["a-new.com", "m-new.com", "0-001.com"]


def test_the_sample_without_a_previous_set_is_the_first_names():
    blockset = {"b.com", "a.com", "c.com", "d.com", rdd.LIST_CANARY}
    assert rdd.verify_sample(blockset, None) == ["a.com", "b.com", "c.com"]

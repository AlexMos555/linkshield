"""The daily popularity refresh loads the licensed ranking, never Tranco's.

scripts/refresh_tranco.py (run by .github/workflows/refresh-tranco.yml)
downloaded tranco-list.eu into the Redis hash tranco:ranks until 2026-10-23.
It now loads the first 1,000,000 names of scripts/build_top_domains.py's
ranking (Majestic Million + Chrome UX Report) under the same key, with the
same flags and exit codes the workflow relies on: 0 loaded, 1 the ranking
could not be built (yesterday's cache stays), 2 no REDIS_URL or a refused
URL, 3 another run holds the lock.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import build_top_domains as btd  # noqa: E402
import refresh_tranco as rt  # noqa: E402


class FakePipeline:
    def __init__(self, store):
        self.store, self.ops = store, []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    def hset(self, key, field, value):
        self.ops.append((key, field, value))

    async def execute(self):
        for key, field, value in self.ops:
            self.store.setdefault(key, {})[field] = value
        self.ops = []


class FakeRedis:
    def __init__(self, store=None, lock=None):
        self.store = store if store is not None else {}
        if lock:
            self.store[rt.LOCK_KEY] = lock
        self.closed = False

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.store:
            return False
        self.store[key] = value
        return True

    async def get(self, key):
        return self.store.get(key)

    async def delete(self, key):
        self.store.pop(key, None)

    async def exists(self, key):
        return int(key in self.store)

    async def rename(self, src, dst):
        self.store[dst] = self.store.pop(src)

    async def unlink(self, key):
        self.store.pop(key, None)

    def pipeline(self, transaction=False):
        return FakePipeline(self.store)

    async def close(self):
        self.closed = True


@pytest.fixture
def ranking(monkeypatch):
    calls = []

    def fake_ranked(fetch=None, cache=None, limit=btd.REDIS_N):
        calls.append(fetch)
        return [("google.com", 1), ("gosuslugi.ru", 2), ("example.org", 3)]

    monkeypatch.setattr(rt.build_top_domains, "ranked_domains", fake_ranked)
    return calls


@pytest.fixture
def redis_world(monkeypatch):
    fake = FakeRedis(store={rt.REDIS_KEY: {"tranco-only.example": "5"}})
    monkeypatch.setattr(rt.redis, "from_url", lambda *_a, **_kw: fake)
    monkeypatch.setenv("REDIS_URL", "redis://fake")
    monkeypatch.delenv("TRANCO_LIST_URL", raising=False)
    return fake


def test_the_default_source_is_the_majestic_million_not_tranco():
    assert "tranco" not in rt.DEFAULT_URL
    assert rt.DEFAULT_URL == btd.MAJESTIC
    assert rt.refused("https://tranco-list.eu/top-1m.csv.zip")
    assert not rt.refused(btd.MAJESTIC)


@pytest.mark.parametrize("url", ["https://tranco-list.eu/top-1m.csv.zip", "https://www.tranco-list.eu/x",
                                 "http://TRANCO-LIST.EU/download/ABC/1000000"])
def test_a_tranco_url_is_refused_from_the_flag_and_the_environment(url, monkeypatch, redis_world, ranking):
    assert rt.main(["--url", url]) == 2
    monkeypatch.setenv("TRANCO_LIST_URL", url)
    assert rt.main([]) == 2
    assert ranking == []  # nothing fetched
    assert redis_world.store[rt.REDIS_KEY] == {"tranco-only.example": "5"}


def test_a_run_replaces_the_hash_atomically_and_releases_the_lock(redis_world, ranking):
    assert rt.main([]) == 0
    assert redis_world.store[rt.REDIS_KEY] == {"google.com": "1", "gosuslugi.ru": "2", "example.org": "3"}
    assert rt.LOCK_KEY not in redis_world.store
    assert [k for k in redis_world.store if k != rt.REDIS_KEY] == []  # no staging or tombstone left
    assert redis_world.closed


def test_a_failed_ranking_keeps_yesterdays_cache(redis_world, monkeypatch):
    def broken(**_kw):
        raise ValueError("Majestic Million: 12 rows, need 900000")

    monkeypatch.setattr(rt.build_top_domains, "ranked_domains", broken)
    assert rt.main([]) == 1
    assert redis_world.store[rt.REDIS_KEY] == {"tranco-only.example": "5"}


def test_a_held_lock_exits_3_and_touches_nothing(monkeypatch, ranking):
    fake = FakeRedis(store={rt.REDIS_KEY: {"old.example": "1"}}, lock="other-run")
    monkeypatch.setattr(rt.redis, "from_url", lambda *_a, **_kw: fake)
    monkeypatch.setenv("REDIS_URL", "redis://fake")
    assert rt.main([]) == 3
    assert fake.store[rt.REDIS_KEY] == {"old.example": "1"}
    assert fake.store[rt.LOCK_KEY] == "other-run"


def test_without_redis_url_only_a_dry_run_runs(monkeypatch, ranking):
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.delenv("TRANCO_LIST_URL", raising=False)
    assert rt.main([]) == 2
    assert rt.main(["--dry-run"]) == 0


def test_a_mirror_stands_in_for_the_majestic_million_only(monkeypatch):
    fetched = []

    def fake_get(url, timeout=180.0):
        fetched.append(url)
        raise RuntimeError("stop")

    monkeypatch.setattr(btd, "fetch_sources", lambda fetch=None, cache=None: (fetch(btd.MAJESTIC), fetch(btd.PSL_URL)))
    with pytest.raises(RuntimeError):
        rt.build_pairs("https://mirror.example/majestic_million.csv", fake_get)
    assert fetched == ["https://mirror.example/majestic_million.csv"]

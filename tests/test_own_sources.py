"""Cleanway's own sources: the lookalike job and the in-app report queue.

Pinned here:
  * LOOKALIKE_GENERATOR_ENABLED is off unless set, and off means nothing
    happens: the API queues no report, the job exits before reading a log
    or opening Redis, the app hides the report button;
  * a report — one, or a hundred — never publishes a site: it is queued, and
    the job publishes only on evidence of its own;
  * every candidate meets the publisher's false-positive gates (brand-owned
    hosts, top domains, hosting platforms) — the publisher side, with Redis,
    is in test_refresh_dangerous_domains.py;
  * a dry run writes to no store.
"""
from __future__ import annotations

import argparse
import asyncio
import importlib.util
import json
import pathlib
import sys

import pytest
from fastapi.testclient import TestClient

from api.services import lookalike_generator as lg
from api.services import own_sources

_SCRIPT = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "refresh_lookalikes.py"
_spec = importlib.util.spec_from_file_location("refresh_lookalikes", _SCRIPT)
rl = importlib.util.module_from_spec(_spec)
sys.modules["refresh_lookalikes"] = rl  # its dataclasses look their module up
_spec.loader.exec_module(rl)

NOW = 1_791_200_000.0
INSTALL = "3f2b9c1e-8a4d-4c2b-9e1f-0a1b2c3d4e5f"
LOGIN = '<form><input type="password"></form><title>СберБанк Онлайн</title>'


class FakeRedis:
    """The Redis surface own_sources and the job use, in memory."""

    def __init__(self) -> None:
        self.data: dict = {}
        self.ttl: dict = {}
        self.calls: list = []

    def pipeline(self, transaction: bool = True):
        redis = self

        class _Pipe:
            def __init__(self):
                self.ops = []

            def __getattr__(self, name):
                def queue(*a, **kw):
                    self.ops.append((name, a, kw))
                    return self
                return queue

            async def execute(self):
                return [await getattr(redis, n)(*a, **kw) for n, a, kw in self.ops]
        return _Pipe()

    def _log(self, name):
        self.calls.append(name)

    async def set(self, key, value, nx=False, ex=None):
        self._log("set")
        if nx and key in self.data:
            return None
        self.data[key] = value
        return True

    async def delete(self, *keys):
        self._log("delete")
        return sum(self.data.pop(k, None) is not None for k in keys)

    async def expire(self, key, seconds):
        self.ttl[key] = seconds
        return 1

    async def incr(self, key):
        self.data[key] = int(self.data.get(key, 0)) + 1
        return self.data[key]

    async def sadd(self, key, *members):
        s = self.data.setdefault(key, set())
        before = len(s)
        s.update(members)
        return len(s) - before

    async def scard(self, key):
        return len(self.data.get(key, set()))

    async def hset(self, key, mapping):
        self.data.setdefault(key, {}).update(mapping)
        return len(mapping)

    async def hget(self, key, field):
        return self.data.get(key, {}).get(field)

    async def hgetall(self, key):
        return dict(self.data.get(key, {}))

    async def hdel(self, key, *fields):
        h = self.data.get(key, {})
        return sum(h.pop(f, None) is not None for f in fields)

    async def zadd(self, key, mapping, nx=False):
        z = self.data.setdefault(key, {})
        fresh = {m: s for m, s in mapping.items() if not (nx and m in z)}
        z.update(fresh)
        return len(fresh)

    async def zrange(self, key, start, end, withscores=False):
        rows = sorted(self.data.get(key, {}).items(), key=lambda kv: (kv[1], kv[0]))
        rows = rows[start:] if end == -1 else rows[start:end + 1]
        return rows if withscores else [m for m, _ in rows]

    async def zrem(self, key, *members):
        z = self.data.get(key, {})
        return sum(z.pop(m, None) is not None for m in members)

    async def zremrangebyscore(self, key, low, high):
        z = self.data.get(key, {})
        cut = float(str(high).lstrip("("))
        doomed = [m for m, s in z.items() if s < cut]
        for m in doomed:
            del z[m]
        return len(doomed)

    async def zremrangebyrank(self, key, start, end):
        rows = sorted(self.data.get(key, {}).items(), key=lambda kv: (kv[1], kv[0]))
        stop = len(rows) + end + 1 if end < 0 else end + 1
        doomed = [m for m, _ in rows[start:max(stop, 0)]]
        for m in doomed:
            del self.data[key][m]
        return len(doomed)

    async def aclose(self):
        return None


def run(coro):
    return asyncio.run(coro)


# ── The switch ──

@pytest.mark.parametrize("raw, on", [("1", True), ("true", True), (" Yes ", True), ("on", True),
                                     ("", False), ("0", False), ("false", False), ("off", False)])
def test_off_unless_explicitly_switched_on(raw, on):
    assert own_sources.enabled({own_sources.ENABLE_ENV: raw}) is on
    assert own_sources.enabled({}) is False


def test_the_default_environment_is_off(monkeypatch):
    monkeypatch.delenv(own_sources.ENABLE_ENV, raising=False)
    assert own_sources.enabled() is False


# ── Published sets ──

def test_promote_keeps_the_host_and_its_evidence_and_the_window_expires_it():
    r = FakeRedis()
    run(own_sources.promote(r, "lookalike", "sberbank-bonus.ru", NOW, {"brand": "sber", "signals": ["credential_form"]}))
    entries = run(own_sources.load(r, "lookalike"))
    assert entries == {"sberbank-bonus.ru": NOW}
    assert run(own_sources.evidence_for(r, "sberbank-bonus.ru"))["signals"] == ["credential_form"]
    active, expired = own_sources.split(entries, NOW + own_sources.WINDOW_SECONDS - 1)
    assert active == {"sberbank-bonus.ru"} and expired == set()
    active, expired = own_sources.split(entries, NOW + own_sources.WINDOW_SECONDS + 1)
    assert active == set() and expired == {"sberbank-bonus.ru"}
    with pytest.raises(ValueError):
        run(own_sources.promote(r, "somebody-elses-feed", "x.ru", NOW, {}))


def test_pending_rechecks_rejected_and_listed_hosts_only_when_seen_again():
    cands = {
        "new.ru": {"status": "new", "first_seen": 3},
        "rejected-seen-again.ru": {"status": "rejected", "first_seen": 1, "last_seen": 20, "checked_at": 10},
        "rejected-quiet.ru": {"status": "rejected", "first_seen": 2, "last_seen": 10, "checked_at": 10},
        "listed-seen-again.ru": {"status": "listed", "first_seen": 4, "last_seen": 20, "checked_at": 10},
        "promoted.ru": {"status": "promoted", "first_seen": 0, "last_seen": 20, "checked_at": 10},
    }
    assert own_sources.pending(cands, 10) == ["rejected-seen-again.ru", "new.ru", "listed-seen-again.ru"]
    assert own_sources.pending(cands, 1) == ["rejected-seen-again.ru"]


# ── The report queue ──

def test_a_report_is_queued_with_the_host_only():
    r = FakeRedis()
    out = run(own_sources.enqueue_report(r, "https://Sberbank-Bonus.ru/login?token=secret&email=a@b.ru", "k1", NOW))
    assert out is own_sources.ReportOutcome.queued
    assert r.data[own_sources.REPORT_QUEUE_KEY] == {"sberbank-bonus.ru": int(NOW)}
    stored = json.dumps({k: sorted(v) if isinstance(v, set) else v for k, v in r.data.items()})
    assert "secret" not in stored and "a@b.ru" not in stored and "login" not in stored


@pytest.mark.parametrize("raw", ["", "localhost", "evil.ru/path", "a b.ru", "user@evil.ru", "javascript:alert(1)",
                                 "x" * 300 + ".ru", "evil..ru"])
def test_what_is_not_a_host_is_never_queued(raw):
    r = FakeRedis()
    assert run(own_sources.enqueue_report(r, raw, "k1", NOW)) is own_sources.ReportOutcome.invalid
    assert own_sources.REPORT_QUEUE_KEY not in r.data


def test_one_install_counts_once_and_is_limited_per_day():
    r = FakeRedis()
    assert run(own_sources.enqueue_report(r, "a-phish.ru", "k1", NOW)) is own_sources.ReportOutcome.queued
    assert run(own_sources.enqueue_report(r, "a-phish.ru", "k1", NOW)) is own_sources.ReportOutcome.repeated
    assert run(own_sources.report_votes(r, "a-phish.ru")) == 1
    outcomes = [run(own_sources.enqueue_report(r, f"phish{i}.ru", "k1", NOW))
                for i in range(own_sources.REPORTS_PER_INSTALL_PER_DAY)]
    assert outcomes[-1] is own_sources.ReportOutcome.install_limit


def test_the_global_daily_limit_holds(monkeypatch):
    monkeypatch.setattr(own_sources, "REPORTS_PER_DAY", 3)
    r = FakeRedis()
    outcomes = [run(own_sources.enqueue_report(r, f"phish{i}.ru", None, NOW)) for i in range(4)]
    assert outcomes[-1] is own_sources.ReportOutcome.daily_limit
    assert len(r.data[own_sources.REPORT_QUEUE_KEY]) == 3


# ── The API: the report button and the queue ──

@pytest.fixture
def client():
    from api.main import app
    return TestClient(app)


@pytest.fixture
def queue_redis(monkeypatch):
    r = FakeRedis()

    async def _get():
        return r
    monkeypatch.setattr("api.services.cache.get_redis", _get)
    return r


def _report(client, report_type="false_negative", domain="sberbank-bonus.ru"):
    return client.post("/api/v1/feedback/report", json={"domain": domain, "report_type": report_type},
                       headers={"X-Cleanway-Install": INSTALL})


def test_with_the_switch_off_a_report_is_not_queued(client, queue_redis, monkeypatch):
    monkeypatch.delenv(own_sources.ENABLE_ENV, raising=False)
    assert _report(client).status_code == 200
    assert own_sources.REPORT_QUEUE_KEY not in queue_redis.data


def test_with_the_switch_on_a_phishing_report_is_queued(client, queue_redis, monkeypatch):
    monkeypatch.setenv(own_sources.ENABLE_ENV, "1")
    assert _report(client).status_code == 200
    assert "sberbank-bonus.ru" in queue_redis.data[own_sources.REPORT_QUEUE_KEY]
    # The install is stored hashed, never as sent.
    assert INSTALL not in json.dumps({k: sorted(v) if isinstance(v, set) else v
                                      for k, v in queue_redis.data.items()}, default=str)


def test_a_false_positive_report_never_enters_the_queue(client, queue_redis, monkeypatch):
    monkeypatch.setenv(own_sources.ENABLE_ENV, "1")
    assert _report(client, report_type="false_positive").status_code == 200
    assert own_sources.REPORT_QUEUE_KEY not in queue_redis.data


def test_a_redis_blip_does_not_fail_the_report(client, monkeypatch):
    monkeypatch.setenv(own_sources.ENABLE_ENV, "1")

    async def _down():
        raise ConnectionError("down")
    monkeypatch.setattr("api.services.cache.get_redis", _down)
    assert _report(client).status_code == 200


@pytest.mark.parametrize("raw, shown", [("", False), ("1", True)])
def test_the_app_shows_the_report_button_only_while_the_queue_is_read(client, monkeypatch, raw, shown):
    monkeypatch.setenv(own_sources.ENABLE_ENV, raw)
    assert client.get("/api/v1/mobile/version").json()["features"] == {"report_sites": shown}


# ── The job: reports never publish on their own ──

def _verifier(level=None, basis=None):
    async def _v(_host):
        return level, basis
    return _v


async def _not_listed(_host):
    return None


def _pages(monkeypatch, html_by_host: dict):
    async def _fetch(host, _http):
        return html_by_host.get(host)
    monkeypatch.setattr(lg, "fetch_page", _fetch)


def _queue(r, *hosts, installs=1):
    for host in hosts:
        for i in range(installs):
            run(own_sources.enqueue_report(r, host, f"install-{i}", NOW))


def _process(r, *, verifier=None, promote=True):
    counters = rl.Counters()
    run(rl.process_reports(r, NOW, verifier=verifier or _verifier(), listed=_not_listed, max_reports=100,
                           max_fetch=10, promote=promote, counters=counters))
    return counters


def test_a_single_report_without_evidence_never_publishes(monkeypatch):
    _pages(monkeypatch, {})
    r = FakeRedis()
    _queue(r, "sberbank-bonus.ru")
    counters = _process(r)
    assert counters.reports_taken == 1 and counters.reports_promoted == 0
    assert own_sources.REPORTS_KEY not in r.data


def test_a_hundred_reports_without_evidence_never_publish(monkeypatch):
    _pages(monkeypatch, {})
    monkeypatch.setattr(own_sources, "REPORTS_PER_DAY", 1_000)
    r = FakeRedis()
    _queue(r, "sberbank-bonus.ru", installs=100)
    assert run(own_sources.report_votes(r, "sberbank-bonus.ru")) == 100
    assert _process(r).reports_promoted == 0
    assert own_sources.REPORTS_KEY not in r.data


def test_a_third_party_listing_does_not_publish_a_report_either(monkeypatch):
    _pages(monkeypatch, {})
    r = FakeRedis()
    _queue(r, "sberbank-bonus.ru")
    assert _process(r, verifier=_verifier("dangerous", "threat_intel")).reports_promoted == 0


def test_a_reported_lookalike_serving_a_branded_login_is_published_with_its_evidence(monkeypatch):
    _pages(monkeypatch, {"sberbank-bonus.ru": LOGIN})
    r = FakeRedis()
    _queue(r, "sberbank-bonus.ru", installs=2)
    assert _process(r).reports_promoted == 1
    assert "sberbank-bonus.ru" in r.data[own_sources.REPORTS_KEY]
    evidence = run(own_sources.evidence_for(r, "sberbank-bonus.ru"))
    assert evidence["signals"] == ["credential_form"] and evidence["votes"] == 2 and evidence["brand"] == "sber"


def test_a_report_of_a_brand_owned_or_popular_site_is_dropped_unverified(monkeypatch):
    fetched: list = []

    async def _fetch(host, _http):
        fetched.append(host)
        return LOGIN
    monkeypatch.setattr(lg, "fetch_page", _fetch)
    r = FakeRedis()
    _queue(r, "online.sberbank.ru", "mail.google.com", "vercel.app")
    assert _process(r).reports_promoted == 0
    assert fetched == []


def test_a_report_without_a_brand_cannot_be_confirmed_by_a_login_form(monkeypatch):
    # The page signal needs a brand the host imitates; any site has a login.
    _pages(monkeypatch, {"some-shop.ru": '<input type="password"> Сбербанк'})
    r = FakeRedis()
    _queue(r, "some-shop.ru")
    assert _process(r).reports_promoted == 0


# ── The job: candidates ──

def _state(tmp_path, candidates: dict):
    state = rl.FileState(str(tmp_path / "state.json"))
    state.data["candidates"] = candidates
    return state


def _cand(brand="sber", imitates="sberbank.ru", method="combosquatting, lure word"):
    return {"brand": brand, "imitates": imitates, "method": method, "status": "new", "first_seen": 1,
            "last_seen": 1}


def test_candidates_are_promoted_listed_or_rejected_on_the_evidence(tmp_path, monkeypatch):
    _pages(monkeypatch, {"sberbank-bonus.ru": LOGIN})
    state = _state(tmp_path, {"sberbank-bonus.ru": _cand(), "sberbamk.ru": _cand(method="character substitution"),
                              "gosuslugi-lk.help": _cand("gosuslugi", "gosuslugi.ru")})

    async def _listed(host):
        return host if host == "gosuslugi-lk.help" else None

    counters = rl.Counters()
    outcomes = run(rl.verify_candidates(None, state, NOW, verifier=_verifier("dangerous", "threat_intel"),
                                        listed=_listed, max_verify=10, max_fetch=10, promote=False,
                                        counters=counters))
    status = {o["host"]: o["status"] for o in outcomes}
    assert status == {"sberbank-bonus.ru": "promoted", "sberbamk.ru": "rejected", "gosuslugi-lk.help": "listed"}
    assert (counters.promoted, counters.rejected, counters.already_listed) == (1, 1, 1)
    # Threat intel was recorded with the evidence, not acted on.
    assert state.data["candidates"]["sberbamk.ru"]["signals"] == ["threat_intel"]


def test_promotion_writes_to_redis_only_when_promoting(tmp_path, monkeypatch):
    _pages(monkeypatch, {"sberbank-bonus.ru": LOGIN})
    for promote in (False, True):
        r = FakeRedis()
        run(own_sources.put_candidate(r, "sberbank-bonus.ru", _cand()))
        run(rl.verify_candidates(r, rl.FileState(None), NOW, verifier=_verifier(), listed=_not_listed,
                                 max_verify=10, max_fetch=10, promote=promote, counters=rl.Counters()))
        assert (own_sources.LOOKALIKE_KEY in r.data) is promote


def test_a_host_the_list_covers_is_not_fetched(tmp_path, monkeypatch):
    fetched: list = []

    async def _fetch(host, _http):
        fetched.append(host)
        return LOGIN
    monkeypatch.setattr(lg, "fetch_page", _fetch)

    async def _listed(host):
        return host
    state = _state(tmp_path, {"sberbank-bonus.ru": _cand()})
    run(rl.verify_candidates(None, state, NOW, verifier=_verifier(), listed=_listed, max_verify=10, max_fetch=10,
                             promote=False, counters=rl.Counters()))
    assert fetched == []


# ── The publisher's gates on every candidate ──

PSL = {"ru", "com", "app", "vercel.app", "io", "github.io", "br", "com.br", "help", "xn--p1ai"}


def test_brand_owned_top_domains_and_hosting_platforms_never_pass_the_publisher_gates():
    hosts = [
        "walmart.com.br", "americanexpress.io",      # data/brand_owned_hosts.txt
        "google.com", "vk.com", "sberbank.ru",       # top domains (bundled top-100k)
        "vercel.app", "github.io", "github.com",     # hosting platform apexes, a path-shared host
        "sberbank-bonus.ru", "xn----etbaulcdt1aavc.xn--p1ai", "gosuslugi-lk.help",
        "sberbank-bonus.vercel.app",                 # one tenant: exactly that host, never the platform
    ]
    passed = run(rl.publisher_gate_pass(hosts, public_suffixes=PSL))
    assert passed == {"sberbank-bonus.ru", "xn----etbaulcdt1aavc.xn--p1ai", "gosuslugi-lk.help",
                      "sberbank-bonus.vercel.app"}


def test_an_own_source_host_never_promotes_its_registrable():
    passed = run(rl.publisher_gate_pass(["login.sberbank-bonus.ru", "www.sberbank-bonus.ru"], public_suffixes=PSL))
    assert passed == {"login.sberbank-bonus.ru", "www.sberbank-bonus.ru"}


def test_every_brand_owned_host_in_the_veto_file_is_vetoed():
    rdd = rl._publisher()
    owned = sorted(rdd.load_brand_owned_hosts())
    assert owned  # the file is read
    assert run(rl.publisher_gate_pass(owned, public_suffixes=PSL, publisher=rdd)) == set()


# ── The job, end to end: off, locked, dry ──

def _args(**kw):
    base = dict(dry_run=False, hours=1.0, max_tiles=4, max_verify=10, max_fetch=0, max_reports=10, verify="none",
                logs=None, artifact=None, state_file=None, report_json=None)
    return argparse.Namespace(**{**base, **kw})


@pytest.fixture
def no_network(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("the job reached for the network")
    monkeypatch.setattr(rl.ct_tiles, "client", _boom)


def test_with_the_switch_off_the_job_does_nothing(monkeypatch, no_network):
    monkeypatch.delenv(own_sources.ENABLE_ENV, raising=False)
    monkeypatch.setenv("REDIS_URL", "redis://never-opened")

    async def _open(_url):
        raise AssertionError("opened Redis while switched off")
    monkeypatch.setattr(rl, "_open_redis", _open)
    assert run(rl.run(_args())) == 0


def test_a_held_lock_is_left_to_its_owner(monkeypatch, no_network):
    monkeypatch.setenv(own_sources.ENABLE_ENV, "1")
    monkeypatch.setenv("REDIS_URL", "redis://fake")
    r = FakeRedis()
    r.data[rl.LOCK_KEY] = "1"

    async def _open(_url):
        return r
    monkeypatch.setattr(rl, "_open_redis", _open)
    assert run(rl.run(_args())) == rl.EXIT_LOCKED
    assert r.data[rl.LOCK_KEY] == "1"


class _FakeCT:
    """ct_tiles' fetch surface over one in-memory log: a checkpoint and tiles
    with a Sber lookalike, Sber's own name and the recorded leaves."""

    def __init__(self):
        from tests.test_ct_tiles import LEAVES, precert_record, san_extension, tbs
        self.blob = (precert_record(tbs(san_extension("sberbank-bonus.ru", "www.sberbank-bonus.ru")))
                     + precert_record(tbs(san_extension("www.sberbank.ru"))) + LEAVES)
        self.leaves = 7

    def install(self, monkeypatch):
        log = rl.ct_tiles.TiledLog("Test 'Log2026h2'", "https://ct.example/2026h2/")

        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        async def _log_list(_http):
            return {}

        async def _checkpoint(_http, _log):
            return rl.ct_tiles.Checkpoint("ct.example/2026h2", self.leaves, "x")

        async def _tile(_http, _log, index, width=256):
            assert (index, width) == (0, self.leaves)
            return self.blob

        monkeypatch.setattr(rl.ct_tiles, "client", lambda: _Client())
        monkeypatch.setattr(rl.ct_tiles, "fetch_log_list", _log_list)
        monkeypatch.setattr(rl.ct_tiles, "select_tiled_logs", lambda *_a, **_k: [log])
        monkeypatch.setattr(rl.ct_tiles, "fetch_checkpoint", _checkpoint)
        monkeypatch.setattr(rl.ct_tiles, "fetch_tile", _tile)


def test_a_dry_run_reads_ct_matches_and_writes_only_its_own_files(tmp_path, monkeypatch):
    from api.services import cache
    original_get_redis = cache.get_redis
    monkeypatch.setenv("REDIS_URL", "redis://production.example:6379")
    monkeypatch.setenv(own_sources.ENABLE_ENV, "1")  # even switched on, a dry run promotes nothing

    async def _open(url):
        assert url is None, "a dry run opened Redis"
        return None
    monkeypatch.setattr(rl, "_open_redis", _open)

    async def _psl():
        return PSL
    publisher = rl._publisher()
    monkeypatch.setattr(publisher, "_fetch_psl", _psl)
    monkeypatch.setattr(rl, "_publisher", lambda: publisher)
    # isolate_from_redis rebinds every module's get_redis for the process;
    # registering each binding with monkeypatch restores them after the test.
    for module in list(sys.modules.values()):
        if getattr(module, "get_redis", None) is original_get_redis:
            monkeypatch.setattr(module, "get_redis", original_get_redis)
    monkeypatch.setattr(cache, "_redis_client", getattr(cache, "_redis_client", None), raising=False)
    _FakeCT().install(monkeypatch)

    report = tmp_path / "report.json"
    state = tmp_path / "state.json"
    code = run(rl.run(_args(dry_run=True, state_file=str(state), report_json=str(report))))
    assert code == 0

    # Every in-process Redis access now fails (the analyzer fails open).
    with pytest.raises(rl.DryRunRedisError):
        run(cache.get_redis())

    body = json.loads(report.read_text())
    assert body["promoting"] is False
    assert body["counters"]["leaves"] == 7
    assert sorted(m["host"] for m in body["matched"]) == ["sberbank-bonus.ru", "www.sberbank-bonus.ru"]
    assert all(m["passes_publisher_gates"] for m in body["matched"])
    assert body["would_publish"] == []  # no evidence was gathered (verify none, no fetch)
    saved = json.loads(state.read_text())
    assert saved["positions"] == {"Test 'Log2026h2'": 7}
    assert set(saved["candidates"]) == {"sberbank-bonus.ru", "www.sberbank-bonus.ru"}


def test_a_dry_run_never_verifies_through_the_production_api(monkeypatch):
    monkeypatch.setenv("CLEANWAY_API_BASE", "https://api.example")
    monkeypatch.setenv("BENCHMARK_BYPASS_TOKEN", "t")
    assert rl._pick_verifier("api", dry_run=True) is rl.verify_none
    assert rl._pick_verifier("auto", dry_run=True) is rl.verify_local
    assert rl._pick_verifier("none", dry_run=True) is rl.verify_none

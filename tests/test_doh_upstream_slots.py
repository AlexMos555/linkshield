"""DoH upstream slots: names nobody answers must not take the slots the other
cache misses need (api/services/doh_upstream.py, MAX_IN_FLIGHT and
ZONE_MAX_IN_FLIGHT; docs/runbooks/doh-gateway.md, «A zone that never
answers»).

Random subdomains of a zone whose servers never answer each wait the whole
budget. The gateway sends no request it cannot keep open until answered (a
cancelled HTTP/2 stream stays open at the upstream), so these tests pin down
who gets a slot, when a hedge is sent, and that every slot comes back.
"""
from __future__ import annotations

import asyncio
import random
import time

import httpx
import pytest
import pytest_asyncio

from api.services import doh_metrics, doh_upstream
from api.services.doh_gateway import parse_qname
from tests.doh_helpers import answer, query

A, B = "https://a.test/dns-query", "https://b.test/dns-query"
PTR = 12


class _Resp:
    def __init__(self, status, body):
        self.status_code, self.content = status, body


def _dead_zone(name: str) -> bool:
    return name.split(".")[-2].startswith("dead")


class _HoldingClient:
    """httpx.AsyncClient stand-in for upstreams where the names `hold` picks
    never answer on their own: each such request waits until the test
    releases it (oldest first unless told otherwise). Every other name is
    answered at once."""
    hold = staticmethod(_dead_zone)
    held: list = []    # (url, name, future), in the order sent
    posted: list = []  # names, in the order sent
    sent: list = []    # (url, name), in the order sent

    def __init__(self, *a, **kw):
        self.is_closed = False

    async def post(self, url, content=b"", **_kw):
        cls = type(self)
        name = parse_qname(content)
        cls.posted.append(name)
        cls.sent.append((url, name))
        if cls.hold(name):
            fut = asyncio.get_running_loop().create_future()
            cls.held.append((url, name, fut))
            exc = await fut
            if exc is not None:
                raise exc
        return _Resp(200, answer(content))

    @classmethod
    def release(cls, pred=lambda url, name: True, exc=None) -> None:
        for i, (url, name, fut) in enumerate(cls.held):
            if not fut.done() and pred(url, name):
                del cls.held[i]
                fut.set_result(exc)
                return
        raise AssertionError("no held request matches")

    @classmethod
    def release_one(cls) -> None:
        while cls.held:
            fut = cls.held.pop(0)[2]
            if not fut.done():
                fut.set_result(None)
                return

    @classmethod
    def release_all(cls) -> None:
        for _, _, fut in cls.held:
            if not fut.done():
                fut.set_result(None)
        cls.held = []

    async def aclose(self):
        self.is_closed = True


def _use(monkeypatch, urls: list[str]):
    from api import config
    monkeypatch.setattr(config.get_settings(), "doh_upstreams", ",".join(urls))
    monkeypatch.setattr(doh_upstream.httpx, "AsyncClient", _HoldingClient)
    _HoldingClient.hold = staticmethod(_dead_zone)
    _HoldingClient.held, _HoldingClient.posted, _HoldingClient.sent = [], [], []
    doh_upstream._reset_upstream_client_for_tests()
    return _HoldingClient


def _assert_idle() -> None:
    """Every slot back, nobody waiting, no zone entry left: a lost slot is
    lost until the process restarts, and they add up until every cache miss
    gets SERVFAIL."""
    for up in doh_upstream.status():
        assert (up["in_flight"], up["waiting"]) == (0, 0), up
    assert doh_upstream._zones == {}
    assert doh_upstream.slots_status() == {"zones_full": 0, "zone_waiting": 0, "abandoned": 0, "dropping": 0}


async def _settle(fake) -> None:
    """Answer whatever is still held, let the requests nobody waits for
    finish, then check that everything came back."""
    for _ in range(200):
        fake.release_all()
        if not doh_upstream._abandoned and not doh_upstream._closing:
            break
        await asyncio.sleep(0.005)
    _assert_idle()


@pytest_asyncio.fixture
async def holding_upstream(monkeypatch):
    fake = _use(monkeypatch, [A])
    yield fake
    await _settle(fake)


@pytest_asyncio.fixture
async def holding_upstreams(monkeypatch):
    """Two upstreams, as in production (Cloudflare by name and by IP)."""
    fake = _use(monkeypatch, [A, B])
    yield fake
    await _settle(fake)


def _ask(name: str, qtype: int = 1) -> asyncio.Task:
    return asyncio.create_task(doh_upstream.proxy_to_upstream(query(name, qtype=qtype)))


async def _ask_many(names: list[str]) -> list[asyncio.Task]:
    tasks = [_ask(n) for n in names]
    await asyncio.sleep(0.05)  # every one of them has reached the upstream or a queue
    return tasks


async def _fill(n: int, tag: str = "o") -> list[asyncio.Task]:
    """`n` slots taken by names nobody answers, one zone each: past its
    ZONE_MAX_IN_FLIGHT a zone only gets half of its upstream's free slots, so
    a test that needs a zone at its limit takes most of the slots first."""
    return await _ask_many([f"{tag}{i}.dead{tag}{i}.example" for i in range(n)])


# ── a zone that never answers ───────────────────────────────────────

@pytest.mark.asyncio
async def test_queries_held_by_a_dead_zone_do_not_hold_up_other_names(holding_upstream, monkeypatch):
    """Random subdomains of a zone whose servers never answer: each one waits
    the whole budget. A name in another zone must not queue behind them."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    held = await _ask_many([f"r{i}.dead.example" for i in range(120)])
    assert len(holding_upstream.posted) < 120  # the zone is at its limit
    started = time.monotonic()
    out = await doh_upstream.proxy_to_upstream(query("example.org"))
    assert out is not None
    assert time.monotonic() - started < 0.1
    assert await asyncio.gather(*held) == [None] * 120  # still nothing from the dead zone


@pytest.mark.asyncio
async def test_dead_names_spread_over_many_zones_still_leave_room_for_the_rest(holding_upstream, monkeypatch):
    """No zone limit helps when every dead name is a zone of its own — only
    room does. On the stand (2026-10-27, a fresh API per run) 2 % dead names
    over 200 zones made main's healthy cache misses slow (p50 1.2-2.4 s), not
    SERVFAIL; the first version of this fix, with 96 slots shared by both
    upstreams, gave 5-23 % of them SERVFAIL there."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    held = await _ask_many([f"r{i}.dead{i}.example" for i in range(48)])
    started = time.monotonic()
    assert await doh_upstream.proxy_to_upstream(query("example.org")) is not None
    assert time.monotonic() - started < 0.1
    assert await asyncio.gather(*held) == [None] * 48


@pytest.mark.asyncio
async def test_a_slow_zone_answers_every_query_once_it_answers(holding_upstream, monkeypatch):
    """The queries over a zone's share wait without being sent, and are sent
    as soon as the zone answers — none of them is dropped."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 2.0)
    tasks = await _ask_many([f"r{i}.dead.example" for i in range(100)])
    assert len(holding_upstream.posted) < 100  # the zone is at its limit
    while not all(t.done() for t in tasks):
        holding_upstream.release_one()
        await asyncio.sleep(0.001)
    assert all(t.result() is not None for t in tasks)
    assert sorted(holding_upstream.posted) == sorted(f"r{i}.dead.example" for i in range(100))


@pytest.mark.asyncio
async def test_a_query_that_gave_up_waiting_for_its_turn_does_not_count_against_the_upstream(
        holding_upstream, monkeypatch):
    """It never reached the upstream, so it says nothing about the upstream's
    health — counted, a few of them in a row would open the breaker."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 2.0)
    held = await _ask_many([f"r{i}.dead.example" for i in range(100)])
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 0.1)
    impatient = await _ask_many([f"s{i}.dead.example" for i in range(10)])
    assert await asyncio.gather(*impatient) == [None] * 10
    assert not any(n.startswith("s") for n in holding_upstream.posted)
    assert doh_upstream.status()[0]["failed"] == 0
    while not all(t.done() for t in held):
        holding_upstream.release_one()
        await asyncio.sleep(0.001)


@pytest.mark.asyncio
async def test_a_request_nobody_waits_for_stays_open_until_the_upstream_answers(holding_upstream, monkeypatch):
    """Cancelled, its HTTP/2 stream would stay open at the upstream all the
    same (httpcore sends no RST_STREAM), outside our count."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 0.1)
    assert await doh_upstream.proxy_to_upstream(query("r1.dead.example")) is None
    assert len(holding_upstream.held) == 1 and not holding_upstream.held[0][2].done()
    holding_upstream.release_one()
    await asyncio.sleep(0.01)
    # counted once, as a failure, when the query gave up — not again as a success
    assert doh_upstream.status()[0]["ok"] == 0 and doh_upstream.status()[0]["failed"] == 1


@pytest.mark.asyncio
async def test_requests_left_open_never_exceed_the_connections_100_streams(holding_upstream, monkeypatch):
    """Cloudflare and Quad9 allow 100 open streams per HTTP/2 connection; at
    100, every new request on it fails at once (stand, 2026-10-23 and -27:
    84-90 % of main's healthy cache misses SERVFAIL while one zone was not
    answering)."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 0.05)
    for wave in range(5):
        await asyncio.gather(*[doh_upstream.proxy_to_upstream(query(f"w{wave}.dead{i}.example"))
                               for i in range(60)])
    assert len(holding_upstream.held) <= 100  # sent and not answered, whatever the client gave up on


@pytest.mark.asyncio
@pytest.mark.parametrize("zone,counter", [("dead.example", "upstream_zone_wait"),
                                          ("dead{i}.example", "upstream_slot_wait")],
                         ids=["one zone", "many zones"])
async def test_waits_and_abandoned_requests_show_in_the_counters(holding_upstream, monkeypatch, zone, counter):
    """/health/doh and the doh_stats line say how often a query had to wait for
    its turn, and how many requests were left to finish with nobody waiting."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 0.2)
    n = doh_upstream.MAX_IN_FLIGHT + 16
    held = await _ask_many([f"r{i}.{zone.format(i=i)}" for i in range(n)])
    sent = len(holding_upstream.posted)
    assert await asyncio.gather(*held) == [None] * n
    counts = doh_metrics.METRICS.counts
    assert counts[counter] == n - sent
    assert counts["upstream_abandoned"] == sent


@pytest.mark.asyncio
@pytest.mark.parametrize("zone", ["dead.example", "dead{i}.example"], ids=["one zone", "many zones"])
async def test_a_freed_slot_goes_to_the_query_with_the_most_time_left(holding_upstream, monkeypatch, zone):
    """When a slot frees, the newest waiting query is sent: the oldest is the
    closest to its deadline, and a request nobody waits for still occupies the
    upstream connection until the upstream answers it."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    names = [f"r{i}.{zone.format(i=i)}" for i in range(doh_upstream.MAX_IN_FLIGHT + 16)]
    held = await _ask_many(names)
    waiting = [n for n in names if n not in holding_upstream.posted]
    assert waiting  # the slots, or the zone's room, are full
    holding_upstream.release_one()
    await asyncio.sleep(0.01)
    assert holding_upstream.posted[-1] == waiting[-1]
    await asyncio.gather(*held)


# ── review 2026-10-27: who gets a freed slot ────────────────────────

@pytest.mark.asyncio
async def test_a_busy_zone_is_not_passed_over_while_none_of_its_requests_is_at_the_upstream(
        holding_upstream, monkeypatch):
    """Every slot is held by dead names, one per zone; a busy healthy zone
    (a CDN's hostnames) has queries waiting for a slot. Its newest query must
    win a freed slot like anyone's newest query: the zone's share counts
    requests at the upstream, not queries waiting for a slot (the first
    version counted those, and handed every freed slot to other zones)."""
    holding_upstream.hold = staticmethod(lambda name: True)
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    share = doh_upstream.ZONE_MAX_IN_FLIGHT
    tasks = await _ask_many([f"r{i}.dead{i}.example" for i in range(doh_upstream.MAX_IN_FLIGHT)])
    tasks += await _ask_many([f"h{i}.cdn.example" for i in range(share)])
    try:
        winners = []
        for k in range(5):
            tasks.append(_ask(f"u{k}.solo{k}.example"))
            await asyncio.sleep(0.01)
            tasks.append(_ask(f"h{share + k}.cdn.example"))
            await asyncio.sleep(0.01)
            holding_upstream.release(lambda url, name: ".dead" in name)
            await asyncio.sleep(0.01)
            winners.append(holding_upstream.posted[-1])
        cdn_at_upstream = [n for _, n, _ in holding_upstream.held if n.endswith(".cdn.example")]
        assert winners == [f"h{share + k}.cdn.example" for k in range(5)], (
            f"freed slots went to {winners}; cdn.example requests at the upstream: {cdn_at_upstream}")
    finally:
        holding_upstream.release_all()
        await asyncio.gather(*tasks)


@pytest.mark.asyncio
async def test_a_query_waiting_on_our_side_is_not_hedged_before_its_first_request_is_sent(
        holding_upstreams, monkeypatch):
    """The hedge timer measures the upstream, not our queue: a query that
    waited for a slot is hedged HEDGE_AFTER_S after its request was sent,
    not at once because it has been waiting longer than that. Timed from
    the query's start, the hedge went out together with the request, and the
    primary was charged a lost hedge it never had."""
    holding_upstreams.hold = staticmethod(lambda name: True)
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 2.0)
    monkeypatch.setattr(doh_upstream, "HEDGE_AFTER_S", 100.0)  # the fillers: no hedges
    fillers = await _fill(2 * doh_upstream.MAX_IN_FLIGHT)  # every slot of A, then of B
    monkeypatch.setattr(doh_upstream, "HEDGE_AFTER_S", 0.2)
    q = _ask("q.slow.example")  # waits for a slot of A
    try:
        await asyncio.sleep(0.1)
        for _ in range(doh_upstream.MAX_IN_FLIGHT):  # B is free now: room for a hedge
            holding_upstreams.release(lambda url, name: url == B)
        await asyncio.sleep(0.2)  # q has waited past HEDGE_AFTER_S without being sent
        assert not [s for s in holding_upstreams.sent if s[1] == "q.slow.example"]
        holding_upstreams.release(lambda url, name: url == A)  # q gets this slot
        await asyncio.sleep(0.01)
        first = [s for s in holding_upstreams.sent if s[1] == "q.slow.example"]
        await asyncio.sleep(0.3)
        sent = [s for s in holding_upstreams.sent if s[1] == "q.slow.example"]
        holding_upstreams.release(lambda url, name: name == "q.slow.example" and url == A)
        assert await q is not None
        failed = {s["url"]: s["failed"] for s in doh_upstream.status()}
        assert first == [(A, "q.slow.example")], f"first request for q: {first}; all sent: {sent}"
        assert sent == [(A, "q.slow.example"), (B, "q.slow.example")]  # the hedge, once due
        assert failed[A] == 0, f"primary charged {failed[A]} lost hedge(s); sent: {sent}"
    finally:
        holding_upstreams.release_all()
        await asyncio.gather(*fillers, q)


@pytest.mark.asyncio
async def test_answers_arriving_together_are_each_counted_once_as_answers(holding_upstreams, monkeypatch):
    """The request and its hedge answered in the same wait round: both
    answered, so neither is a lost hedge. Counted again in the query's
    cleanup, the loser showed ok=1 and failed=1, and was counted abandoned
    though nothing was left running (final review 2026-10-27)."""
    holding_upstreams.hold = staticmethod(lambda name: True)
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    monkeypatch.setattr(doh_upstream, "HEDGE_AFTER_S", 0.05)
    q = _ask("q.slow.example")
    await asyncio.sleep(0.1)
    assert [url for url, _ in holding_upstreams.sent] == [A, B]
    holding_upstreams.release(lambda url, name: url == A)
    holding_upstreams.release(lambda url, name: url == B)
    assert await q is not None
    counts = {s["url"]: (s["ok"], s["failed"]) for s in doh_upstream.status()}
    assert counts == {A: (1, 0), B: (1, 0)}
    assert doh_metrics.METRICS.counts.get("upstream_abandoned", 0) == 0


@pytest.mark.asyncio
async def test_a_hedge_is_not_sent_to_an_upstream_with_half_its_slots_in_use(holding_upstreams, monkeypatch):
    """Both default upstreams are one resolver: a hedge helps when a
    connection stalls, not when a name is slow, so it only uses spare room.
    With hedges, every dead name held two slots (review 2026-10-27)."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    monkeypatch.setattr(doh_upstream, "HEDGE_AFTER_S", 100.0)
    a, b = doh_upstream.upstreams()
    a.skip_until = time.monotonic() + 60  # b first: fill it past half
    held = await _ask_many([f"r{i}.dead{i}.example" for i in range(doh_upstream.MAX_IN_FLIGHT // 2 + 1)])
    a.skip_until = 0.0
    monkeypatch.setattr(doh_upstream, "HEDGE_AFTER_S", 0.05)
    held += await _ask_many(["q.deadq.example"])
    await asyncio.sleep(0.15)
    assert [s for s in holding_upstreams.sent if s[1] == "q.deadq.example"] == [(A, "q.deadq.example")]
    await asyncio.gather(*held)


@pytest.mark.asyncio
async def test_a_hedge_does_not_take_room_its_zone_is_using(holding_upstreams, monkeypatch):
    """A zone with half its share at the upstreams gets no hedges: they would
    take the room its next queries need."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    monkeypatch.setattr(doh_upstream, "HEDGE_AFTER_S", 100.0)
    held = await _ask_many([f"r{i}.dead.example" for i in range(doh_upstream.ZONE_MAX_IN_FLIGHT // 2)])
    monkeypatch.setattr(doh_upstream, "HEDGE_AFTER_S", 0.05)
    held += await _ask_many(["q.dead.example"])
    await asyncio.sleep(0.15)
    assert [s for s in holding_upstreams.sent if s[1] == "q.dead.example"] == [(A, "q.dead.example")]
    await asyncio.gather(*held)


@pytest.mark.asyncio
async def test_each_upstream_connection_has_slots_of_its_own(holding_upstreams, monkeypatch):
    """The 100-stream ceiling is per HTTP/2 connection, and each upstream has
    one: a query goes to the next healthy upstream when the first has no free
    slot. Shared, 96 slots held two requests per dead name (with the hedge) —
    ~9 dead names a second per worker were enough to SERVFAIL the rest."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    monkeypatch.setattr(doh_upstream, "HEDGE_AFTER_S", 100.0)
    n = doh_upstream.MAX_IN_FLIGHT + 54
    held = await _ask_many([f"r{i}.dead{i}.example" for i in range(n)])
    per_url = {u: sum(1 for url, _, _ in holding_upstreams.held if url == u) for u in (A, B)}
    assert per_url == {A: doh_upstream.MAX_IN_FLIGHT, B: 54}
    started = time.monotonic()
    assert await doh_upstream.proxy_to_upstream(query("example.org")) is not None
    assert time.monotonic() - started < 0.1
    await asyncio.gather(*held)


# ── review 2026-10-27: what counts as one zone ─────────────────────

@pytest.mark.parametrize("name,zone", [
    ("r1f.dead.example", "dead.example"),
    ("www.example.com", "example.com"),
    ("example.com", "example.com"),
    ("img.cdn.example.com", "cdn.example.com"),
    ("shop.x.eu.org", "x.eu.org"),
    ("www.bbc.co.uk", "bbc.co.uk"),
    ("4.3.2.1.in-addr.arpa", "3.2.1.in-addr.arpa"),
    ("foo.github.io", "github.io"),
])
def test_a_zone_is_the_names_parent_never_shorter_than_its_registrable_domain(name, zone):
    assert doh_upstream._zone_of(query(name)) == zone


def test_reverse_lookups_of_different_networks_are_different_zones():
    a = doh_upstream._zone_of(query("4.3.2.1.in-addr.arpa", qtype=PTR))
    b = doh_upstream._zone_of(query("8.8.8.8.in-addr.arpa", qtype=PTR))
    assert a != b, f"both PTR queries map to zone {a!r}"


@pytest.mark.asyncio
@pytest.mark.parametrize("dead,healthy", [
    ("r{i}.evil.eu.org", "www.other.eu.org"),
    ("r{i}.old.bank.com", "www.bank.com"),
    ("{i}.113.0.203.in-addr.arpa", "8.8.8.8.in-addr.arpa"),
], ids=["eu.org", "bank.com", "in-addr.arpa"])
async def test_a_dead_subzone_does_not_block_its_siblings(holding_upstreams, monkeypatch, dead, healthy):
    """A subzone that no longer answers (old.bank.com), a free subdomain
    service's tenant (x.eu.org) or a lame reverse zone must not cap every name
    under the same registrable domain (in-addr.arpa: every reverse lookup)."""
    holding_upstreams.hold = staticmethod(lambda name: name.endswith(
        (".evil.eu.org", ".old.bank.com", ".113.0.203.in-addr.arpa")))
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    held = await _ask_many([dead.format(i=i) for i in range(doh_upstream.ZONE_MAX_IN_FLIGHT)])
    started = time.monotonic()
    out = await doh_upstream.proxy_to_upstream(query(healthy))
    took = time.monotonic() - started
    assert healthy in holding_upstreams.posted, f"{healthy} was never forwarded (took {took:.2f} s)"
    assert out is not None and took < 0.1
    await asyncio.gather(*held)


# ── review 2026-10-27: zones that are slow but answer ───────────────

def _timed_client(latency):
    class _Timed:
        open: dict = {}

        def __init__(self, *a, **kw):
            self.is_closed = False

        async def post(self, url, content=b"", **_kw):
            if self.open.get(url, 0) >= 100:
                raise httpx.LocalProtocolError("Max outbound streams is 100")
            self.open[url] = self.open.get(url, 0) + 1
            try:
                await asyncio.sleep(latency(parse_qname(content)))
            finally:
                self.open[url] -= 1
            return _Resp(200, answer(content))

        async def aclose(self):
            self.is_closed = True
    return _Timed


@pytest.mark.asyncio
async def test_a_slow_but_alive_zone_is_fully_answered(monkeypatch):
    """0.3 s answers at 30 queries/s from one worker, unique names in one zone
    (timings scaled by 1/4). The zone limit is for zones that do not answer:
    at 8 such a zone lost ~13-18 % of its queries (review 2026-10-27)."""
    from api import config
    monkeypatch.setattr(config.get_settings(), "doh_upstreams", f"{A},{B}")
    rng = random.Random(7)
    monkeypatch.setattr(doh_upstream.httpx, "AsyncClient", _timed_client(lambda n: 0.075 * rng.uniform(0.8, 1.2)))
    doh_upstream._reset_upstream_client_for_tests()
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    monkeypatch.setattr(doh_upstream, "HEDGE_AFTER_S", 0.1)
    loop = asyncio.get_running_loop()
    end = loop.time() + 3.0
    tasks, i = [], 0
    while loop.time() < end:
        tasks.append(_ask(f"u{i}.cdn-slow.example"))
        i += 1
        await asyncio.sleep(rng.expovariate(120))
    out = await asyncio.gather(*tasks)
    answered = sum(o is not None for o in out) / len(out)
    assert answered >= 0.99, f"{answered:.1%} of {len(out)} answered"


@pytest.mark.asyncio
async def test_a_zone_answering_in_one_second_is_answered_while_its_upstream_has_free_slots(monkeypatch):
    """1 s answers at 36 unique names a second from one worker, one
    upstream (timings scaled by 1/4): ~36 requests at the upstream at once,
    the upstream's other 60 slots free. A fixed share of 16 answered ~16 a
    second of them and gave the rest SERVFAIL (stand, row e 1 s: 62 %; final
    review 2026-10-27), where main's 32 slots answered up to 32."""
    from api import config
    monkeypatch.setattr(config.get_settings(), "doh_upstreams", A)
    rng = random.Random(5)
    monkeypatch.setattr(doh_upstream.httpx, "AsyncClient", _timed_client(lambda n: 0.25 * rng.uniform(0.9, 1.1)))
    doh_upstream._reset_upstream_client_for_tests()
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    loop = asyncio.get_running_loop()
    end = loop.time() + 2.5
    tasks, i = [], 0
    while loop.time() < end:
        tasks.append(_ask(f"u{i}.cdn-slow.example"))
        i += 1
        await asyncio.sleep(rng.expovariate(36 * 4))
    out = await asyncio.gather(*tasks)
    answered = sum(o is not None for o in out) / len(out)
    assert answered >= 0.99, f"{answered:.1%} of {len(out)} answered"


@pytest.mark.asyncio
async def test_a_zone_nobody_answers_leaves_more_than_half_of_its_upstreams_slots_to_the_rest(
        holding_upstreams, monkeypatch):
    """Past its 16, a zone takes only half of what its upstream has free:
    alone, a zone nobody answers ends up with less than half of the slots,
    and only on the upstream it was sent to."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    held = await _ask_many([f"r{i}.dead.example" for i in range(200)])
    a, b = doh_upstream.status()
    assert a["in_flight"] > doh_upstream.ZONE_MAX_IN_FLIGHT  # it did get more than its share...
    assert a["in_flight"] < doh_upstream.MAX_IN_FLIGHT // 2  # ...but not half of the upstream
    assert b["in_flight"] == 0
    started = time.monotonic()
    assert await doh_upstream.proxy_to_upstream(query("example.org")) is not None
    assert time.monotonic() - started < 0.1
    await asyncio.gather(*held)


@pytest.mark.asyncio
async def test_a_zone_gets_only_its_share_once_its_upstream_is_short_of_slots(holding_upstream, monkeypatch):
    """With the upstream's slots mostly taken by other names, a zone's
    requests stop at ZONE_MAX_IN_FLIGHT."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    others = doh_upstream.MAX_IN_FLIGHT - doh_upstream.ZONE_MAX_IN_FLIGHT
    held = await _ask_many([f"o{i}.dead{i}.example" for i in range(others)])
    held += await _ask_many([f"r{i}.dead.example" for i in range(40)])
    assert sum(n.endswith(".dead.example") for n in holding_upstream.posted) == doh_upstream.ZONE_MAX_IN_FLIGHT
    await asyncio.gather(*held)


@pytest.mark.asyncio
async def test_dead_names_spread_over_many_zones_slow_the_rest_down_at_most(monkeypatch):
    """12 dead names a second per worker over 200 zones, answered by the
    upstream after 5.4 s as Cloudflare does (measured 2026-10-23), plus
    healthy cache misses; timings scaled by 1/4. main's semaphore made the
    healthy misses late (p50 ~2.6 s); the first version of this fix, its
    96 slots shared by both upstreams and every dead name holding two of
    them, gave half of them SERVFAIL (review 2026-10-27)."""
    s = 0.25
    from api import config
    monkeypatch.setattr(config.get_settings(), "doh_upstreams", f"{A},{B}")
    monkeypatch.setattr(doh_upstream.httpx, "AsyncClient",
                        _timed_client(lambda n: (5.4 if n.startswith("r") else 0.020) * s))
    doh_upstream._reset_upstream_client_for_tests()
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 4.0 * s)
    monkeypatch.setattr(doh_upstream, "HEDGE_AFTER_S", 0.4 * s)
    rng = random.Random(3)
    loop = asyncio.get_running_loop()
    t0 = loop.time()
    healthy: list[bool] = []
    tasks: list[asyncio.Task] = []

    async def one(name: str, measure: bool) -> None:
        out = await doh_upstream.proxy_to_upstream(query(name))
        if measure:
            healthy.append(out is not None)

    async def gen(rate: float, make, is_healthy: bool) -> None:
        while (now := loop.time() - t0) < 20 * s:
            await asyncio.sleep(rng.expovariate(rate / s))
            tasks.append(asyncio.create_task(one(make(), is_healthy and now > 8 * s)))

    await asyncio.gather(
        gen(50, lambda: f"h{rng.getrandbits(32):08x}.z{rng.randrange(50)}.example.com", True),
        gen(12, lambda: f"r{rng.getrandbits(32):08x}.dead{rng.randrange(200)}.net", False),
    )
    await asyncio.gather(*tasks)
    failed = 100 * healthy.count(False) / len(healthy)
    assert failed <= 1.0, f"{failed:.1f}% of {len(healthy)} healthy cache misses got SERVFAIL"


# ── review 2026-10-27: requests nobody waits for ───────────────────

@pytest.mark.asyncio
async def test_a_request_nobody_waits_for_is_not_sent_again_after_a_goaway(holding_upstream, monkeypatch):
    """A pooled connection the upstream closes (GOAWAY) fails its open
    streams; a request the query still waits for is re-sent once, one nobody
    waits for is not: re-sent, it would hold a slot for another whole answer
    time (stand 2026-10-27: 5.4 % vs 0 % SERVFAIL with and without the
    stub's connection recycling)."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 0.1)
    assert await doh_upstream.proxy_to_upstream(query("r1.dead.example")) is None
    holding_upstream.release(exc=httpx.RemoteProtocolError("ConnectionTerminated"))
    await asyncio.sleep(0.05)
    assert holding_upstream.posted.count("r1.dead.example") == 1
    assert not holding_upstream.held


@pytest.mark.asyncio
async def test_over_http_1_1_the_cap_is_the_connection_pool(holding_upstream, monkeypatch):
    """Without `h2` every request needs a connection of its own: past the
    pool's size, a request counted as sent would only queue inside httpcore."""
    monkeypatch.setattr(doh_upstream, "HTTP2_AVAILABLE", False)
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 0.5)
    held = await _ask_many([f"r{i}.dead{i}.example" for i in range(40)])
    assert len(holding_upstream.posted) == doh_upstream._UPSTREAM_MAX_CONNECTIONS
    await asyncio.gather(*held)


async def _h2c_upstream():
    """A real HTTP/2 DoH upstream over plain TCP (prior knowledge): names
    under `.dead.example` are never answered, every other name at once."""
    import h2.config
    import h2.connection
    import h2.events

    async def handle(reader, writer):
        conn = h2.connection.H2Connection(config=h2.config.H2Configuration(client_side=False))
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        bodies: dict = {}
        try:
            while data := await reader.read(65535):
                for ev in conn.receive_data(data):
                    if isinstance(ev, h2.events.RequestReceived):
                        bodies[ev.stream_id] = b""
                    elif isinstance(ev, h2.events.DataReceived):
                        bodies[ev.stream_id] = bodies.get(ev.stream_id, b"") + ev.data
                        conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                    elif isinstance(ev, h2.events.StreamEnded):
                        body = bodies.pop(ev.stream_id, b"")
                        if parse_qname(body).endswith(".dead.example"):
                            continue
                        resp = answer(body)
                        conn.send_headers(ev.stream_id, [(":status", "200"),
                                                         ("content-type", "application/dns-message"),
                                                         ("content-length", str(len(resp)))])
                        conn.send_data(ev.stream_id, resp, end_stream=True)
                writer.write(conn.data_to_send())
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
    return await asyncio.start_server(handle, "127.0.0.1", 0)


@pytest.mark.asyncio
async def test_a_request_the_upstream_never_answers_gives_its_slot_back_after_request_timeout(monkeypatch):
    """httpx's read timeout times one network read on the shared HTTP/2
    connection, and every other stream's data starts it again: a stream the
    upstream never answers stayed open, its slot held, for as long as the
    connection carried traffic (review 2026-10-27; stand: every slot gone in
    ~9 s with 2 % such names). Past REQUEST_TIMEOUT_S the request is dropped
    with its connection, and the queries on it are answered on a new one."""
    server = await _h2c_upstream()
    port = server.sockets[0].getsockname()[1]
    from api import config
    monkeypatch.setattr(config.get_settings(), "doh_upstreams", f"http://127.0.0.1:{port}/dns-query")
    real = httpx.AsyncClient
    monkeypatch.setattr(doh_upstream.httpx, "AsyncClient", lambda *a, **kw: real(*a, http1=False, **kw))
    monkeypatch.setattr(doh_upstream, "REQUEST_TIMEOUT_S", 1.0)
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 0.3)
    doh_upstream._reset_upstream_client_for_tests()
    try:
        assert await doh_upstream.proxy_to_upstream(query("warm.example.org")) is not None
        assert await doh_upstream.proxy_to_upstream(query("r1.dead.example")) is None
        assert len(doh_upstream._abandoned) == 1
        started = time.monotonic()
        i = 0
        while time.monotonic() - started < 3.0:  # traffic on the same connection, 3 x REQUEST_TIMEOUT_S
            assert await doh_upstream.proxy_to_upstream(query(f"live{i}.example.org")) is not None
            i += 1
            await asyncio.sleep(0.1)
        assert doh_metrics.METRICS.counts["upstream_dropped"] == 1
        await asyncio.sleep(0.05)  # the dropped client finishes closing
        _assert_idle()
    finally:
        await doh_upstream.close_upstream_client()
        server.close()
        await server.wait_closed()


def _droppable_client():
    """Names in dead zones never answered, the rest after 0.2 s. Closing a
    client fails what is still pending on it with LocalProtocolError — what
    httpcore raises for a request caught mid-send by the close."""
    class _Droppable:
        made: list = []

        def __init__(self, *a, **kw):
            self.is_closed = False
            self.pending: list = []
            type(self).made.append(self)

        async def post(self, url, content=b"", **_kw):
            loop = asyncio.get_running_loop()
            fut = loop.create_future()
            self.pending.append(fut)
            if not _dead_zone(parse_qname(content)):
                loop.call_later(0.2, lambda: fut.done() or fut.set_result(None))
            exc = await fut
            if exc is not None:
                raise exc
            return _Resp(200, answer(content))

        async def aclose(self):
            self.is_closed = True
            for fut in self.pending:
                if not fut.done():
                    fut.set_result(httpx.LocalProtocolError("connection closed"))
    return _Droppable


@pytest.mark.asyncio
async def test_a_query_whose_request_was_on_a_dropped_connection_is_answered_on_a_new_one(monkeypatch):
    """Dropping a connection fails every request on it, with a ReadError or,
    caught mid-send, a LocalProtocolError (stand 2026-10-27). Those a query
    still waits for are re-sent once on a new connection, whatever the error."""
    from api import config
    monkeypatch.setattr(config.get_settings(), "doh_upstreams", A)
    client = _droppable_client()
    monkeypatch.setattr(doh_upstream.httpx, "AsyncClient", client)
    doh_upstream._reset_upstream_client_for_tests()
    monkeypatch.setattr(doh_upstream, "REQUEST_TIMEOUT_S", 0.6)
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.5)
    dead = _ask("r1.dead.example")  # unanswered: dropped with its connection at 0.6 s
    await asyncio.sleep(0.5)
    live = _ask("www.example.org")  # on the same connection, answer due at 0.7 s
    assert await live is not None
    assert await dead is None
    assert len(client.made) == 2
    assert doh_metrics.METRICS.counts["upstream_dropped"] == 1


@pytest.mark.asyncio
async def test_shutdown_cancels_the_requests_nobody_waits_for(holding_upstream, monkeypatch, caplog):
    """Closing the clients would fail them, and each would log an upstream
    failure (5-9 warnings per API restart on the stand, 2026-10-27)."""
    import logging
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 0.05)
    assert await asyncio.gather(*[doh_upstream.proxy_to_upstream(query(f"r{i}.dead.example"))
                                  for i in range(3)]) == [None] * 3
    assert len(doh_upstream._abandoned) == 3
    with caplog.at_level(logging.WARNING, logger="api.services.doh_gateway"):
        await doh_upstream.close_upstream_client()
    _assert_idle()
    assert not [r for r in caplog.records if "upstream" in r.getMessage()]


# ── every slot comes back ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_a_slot_handed_to_a_waiter_that_gives_up_is_passed_on():
    slots = doh_upstream._Slots(1)
    await slots.acquire()
    waiter = asyncio.create_task(slots.acquire())
    await asyncio.sleep(0)
    slots.release()   # handed to the waiter...
    waiter.cancel()   # ...which gives up before it runs
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert slots.free == 1 and not slots.waiting()


@pytest.mark.asyncio
async def test_room_in_a_zone_freed_for_a_waiter_that_gives_up_goes_to_the_next(holding_upstream, monkeypatch):
    """The zone's newest waiter is woken for a freed place and gives up
    before it runs: the place must go to the next one, not be left unused
    while the zone's other queries wait."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    share = doh_upstream.ZONE_MAX_IN_FLIGHT
    held = await _fill(doh_upstream.MAX_IN_FLIGHT - share)
    held += await _ask_many([f"r{i}.dead.example" for i in range(share + 2)])
    assert sum(n.endswith(".dead.example") for n in holding_upstream.posted) == share
    newest = held[-1]
    # Room for one: the newest waiter is woken, and gives up before it runs.
    holding_upstream.release(lambda url, name: name.endswith(".dead.example"))
    newest.cancel()
    await asyncio.sleep(0.02)
    assert f"r{share}.dead.example" in holding_upstream.posted
    assert f"r{share + 1}.dead.example" not in holding_upstream.posted
    await asyncio.gather(*held, return_exceptions=True)


@pytest.mark.asyncio
async def test_room_in_a_zone_is_handed_on_when_the_query_woken_for_it_gives_up_waiting_for_a_slot(
        holding_upstream, monkeypatch):
    """Woken for a freed place in its zone, a query found every slot taken
    and gave up while waiting for one: the place must go to the zone's next
    waiter, or that one waits for a slot it never asks for."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 1.0)
    share = doh_upstream.ZONE_MAX_IN_FLIGHT
    held = await _ask_many([f"r{i}.dead.example" for i in range(share)]
                           + [f"o{i}.dead{i}.example" for i in range(doh_upstream.MAX_IN_FLIGHT - share)])
    held += await _ask_many([f"r{share}.dead.example", f"r{share + 1}.dead.example"])  # wait for the zone
    woken = held[-1]
    held += await _ask_many(["s.deadx.example"])  # waits for a slot
    holding_upstream.release(lambda url, name: name == "r0.dead.example")
    await asyncio.sleep(0.01)  # the slot went to s; the zone's newest waiter now waits for one
    woken.cancel()
    await asyncio.sleep(0.01)
    holding_upstream.release(lambda url, name: name == "o0.dead0.example")
    await asyncio.sleep(0.01)
    assert f"r{share}.dead.example" in holding_upstream.posted
    await asyncio.gather(*held, return_exceptions=True)


def _flaky_client():
    rng = random.Random(11)

    class _Flaky:
        def __init__(self, *a, **kw):
            self.is_closed = False

        async def post(self, url, content=b"", **_kw):
            label = parse_qname(content).split(".")[-2]
            await asyncio.sleep(0.3 if label.startswith("slow") else rng.uniform(0, 0.01))
            r = rng.random()
            if r < 0.05:
                raise httpx.RemoteProtocolError("ConnectionTerminated")
            if r < 0.08:
                return _Resp(500, b"")
            return _Resp(200, answer(content))

        async def aclose(self):
            self.is_closed = True
    return _Flaky


@pytest.mark.asyncio
async def test_every_slot_and_zone_entry_comes_back(monkeypatch):
    """Two upstreams, hedges, deadlines, GOAWAYs, HTTP 500s, queries the
    caller cancels, more queries than slots."""
    from api import config
    monkeypatch.setattr(config.get_settings(), "doh_upstreams", f"{A},{B}")
    monkeypatch.setattr(doh_upstream.httpx, "AsyncClient", _flaky_client())
    doh_upstream._reset_upstream_client_for_tests()
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 0.2)
    monkeypatch.setattr(doh_upstream, "HEDGE_AFTER_S", 0.05)
    names = ([f"r{i}.slow{i % 40}.example" for i in range(300)]
             + [f"f{i}.fast{i % 5}.example" for i in range(300)])
    random.Random(5).shuffle(names)
    tasks = [_ask(n) for n in names]
    loop = asyncio.get_running_loop()
    for t in tasks[::10]:
        loop.call_later(0.1, t.cancel)
    await asyncio.gather(*tasks, return_exceptions=True)
    for _ in range(100):
        if not doh_upstream._abandoned:
            break
        await asyncio.sleep(0.01)
    _assert_idle()


# ── what /health/doh shows ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_slot_gauges_show_slots_in_use_and_queries_waiting(holding_upstream, monkeypatch):
    """Counters say that queries waited at some point since start; these say
    what is held now — all slots taken by requests nobody waits for looks
    different from a slow upstream."""
    monkeypatch.setattr(doh_upstream, "UPSTREAM_TIMEOUT_S", 0.3)
    share = doh_upstream.ZONE_MAX_IN_FLIGHT
    held = await _fill(doh_upstream.MAX_IN_FLIGHT - share)
    held += await _ask_many([f"r{i}.dead.example" for i in range(share + 4)])
    held += await _ask_many([f"r{i}.dead{i}.example" for i in range(6)])
    up = doh_upstream.status()[0]
    assert (up["in_flight"], up["waiting"]) == (doh_upstream.MAX_IN_FLIGHT, 6)
    assert doh_upstream.slots_status() == {"zones_full": 1, "zone_waiting": 4, "abandoned": 0, "dropping": 0}
    await asyncio.gather(*held)
    assert doh_upstream.slots_status()["abandoned"] == doh_upstream.MAX_IN_FLIGHT




def test_every_upstream_counter_is_explained_in_the_runbook():
    """/health/doh and the doh_stats line show every counter; the runbook's
    table says what each one means and when to worry (review 2026-10-27: the
    first version's three counters were in neither)."""
    import re
    from pathlib import Path
    names = set(re.findall(r'METRICS\.inc\("([a-z_.]+)"\)', Path(doh_upstream.__file__).read_text()))
    runbook = (Path(__file__).resolve().parents[1] / "docs" / "runbooks" / "doh-gateway.md").read_text()
    assert names
    assert [n for n in sorted(names) if f"| `{n}` |" not in runbook] == []

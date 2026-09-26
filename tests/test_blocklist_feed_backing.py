"""blocklist_feed_backing: the per-feed record the outage guard carries from.

A missing member would drop a real phishing name during an outage (never
allowed); an extra one only carries a name another feed dropped, at about the
configured false-positive rate. The publisher side is pinned in
test_refresh_dangerous_domains.py.
"""
from __future__ import annotations

import pytest

from api.services import blocklist_feed_backing as fb

NOW = 1_790_000_000.0


def test_every_member_is_found():
    names = {f"phish{i}.top" for i in range(5_000)}
    backing = fb.build(names, NOW)
    assert all(name in backing for name in names)


def test_non_members_are_rarely_found_and_the_record_is_small():
    backing = fb.build({f"phish{i}.top" for i in range(5_000)}, NOW)
    strangers = [f"legit{i}.example" for i in range(20_000)]
    rate = sum(name in backing for name in strangers) / len(strangers)
    assert rate < 2 * fb.FALSE_POSITIVE_RATE
    assert len(backing.bits) < 1.3 * 5_000  # ~1.2 bytes a name, not ~22 for the text


def test_an_empty_record_holds_nothing():
    backing = fb.build(set(), NOW)
    assert "anything.example" not in backing


def test_a_record_survives_the_round_trip_through_redis_text():
    backing = fb.build({"a.top", "b.top"}, NOW)
    back = fb.decode(fb.encode(backing))
    assert back == backing
    assert "a.top" in back and "b.top" in back


@pytest.mark.parametrize("text", ["", "v1 1 2", "v2 1790000000 64 7 AAAAAAAAAAA=", "v1 x 64 7 AAAAAAAAAAA=",
                                  "v1 1790000000 640 7 AAAAAAAAAAA=", "v1 1790000000 64 7 not-base64!"])
def test_a_malformed_record_is_no_record(text):
    assert fb.decode(text) is None


def _registrable(host: str) -> str:
    return ".".join(host.split(".")[-2:])


def test_a_feed_backs_its_own_published_hosts_and_the_registrables_it_promoted():
    published = {"a.shared.top", "b.shared.top", "shared.top", "own.top", "x.top"}
    inputs = {"a.shared.top", "b.shared.top", "own.top", "x.top", "gone.top"}
    backed = fb.names_backed(published, inputs, {"a.shared.top", "own.top", "gone.top"}, True, _registrable)
    # gone.top was not published (a guard dropped it): nothing to carry.
    assert backed == {"a.shared.top", "own.top", "shared.top"}


def test_an_exact_only_feed_never_backs_a_registrable():
    published = {"a.shared.top", "b.shared.top", "shared.top"}
    inputs = {"a.shared.top", "b.shared.top"}
    assert fb.names_backed(published, inputs, {"a.shared.top"}, False, _registrable) == {"a.shared.top"}


def test_a_carried_or_retained_registrable_is_nobodys_promotion():
    """oneshot.top came into the build as a name of its own (carried from an
    old one-subdomain promotion): recording it as OpenPhish's would carry it
    again on OpenPhish's next outage, forever."""
    published = {"login.oneshot.top", "oneshot.top"}
    inputs = {"login.oneshot.top", "oneshot.top"}
    assert fb.names_backed(published, inputs, {"login.oneshot.top"}, True, _registrable) == {"login.oneshot.top"}


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
            if name == "hset":
                self.r.h.update(kw["mapping"])
            elif name == "hdel":
                for field in a[1:]:
                    self.r.h.pop(field, None)
            elif name == "expire":
                self.r.ttl = a[1]


class _Redis:
    def __init__(self):
        self.h: dict = {}
        self.ttl = None

    def pipeline(self, transaction=True):
        return _Pipe(self)

    async def hgetall(self, key):
        return dict(self.h)

    async def hkeys(self, key):
        return list(self.h)


@pytest.mark.asyncio
async def test_save_keeps_other_records_and_drops_feeds_that_no_longer_exist():
    r = _Redis()
    await fb.save(r, {"phishing.army": fb.build({"a.top"}, NOW), "Removed feed": fb.build({"b.top"}, NOW)},
                  sources={"phishing.army", "Removed feed", "OpenPhish"})
    await fb.save(r, {"OpenPhish": fb.build({"c.top"}, NOW + 3600)}, sources={"phishing.army", "OpenPhish"})
    loaded = await fb.load(r, NOW + 3600)
    assert set(loaded) == {"phishing.army", "OpenPhish"}
    assert "a.top" in loaded["phishing.army"]
    assert r.ttl == fb.KEY_TTL_SECONDS


@pytest.mark.asyncio
async def test_load_ignores_stale_and_unreadable_records():
    r = _Redis()
    r.h = {"old": fb.encode(fb.build({"a.top"}, NOW - fb.MAX_AGE_SECONDS - 1)),
           "broken": "garbage",
           "fresh": fb.encode(fb.build({"b.top"}, NOW))}
    assert set(await fb.load(r, NOW)) == {"fresh"}

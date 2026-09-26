"""blocklist_feed_health: which feeds are down this run, pure decisions.

The refresh job's end-to-end behaviour (carrying names, exit codes) is
pinned in test_refresh_dangerous_domains.py; this file pins the rules.
"""
from __future__ import annotations

import pytest

from api.services import blocklist_feed_health as fh

NOW = 1_790_000_000.0


def test_a_failed_download_is_degraded_whatever_the_feed_size():
    health = fh.assess({"OpenPhish": None}, {}, {}, NOW)
    assert health.degraded == {"OpenPhish": "unavailable (download or read failed)"}
    assert health.down_since == {"OpenPhish": NOW}
    assert not health.healthy_counts


def test_an_unsized_source_is_judged_on_availability_alone():
    """The server-confirmed set can be empty on a quiet week; it is down
    only when it cannot be read."""
    ok = fh.assess({"Cleanway checks": 0}, {"Cleanway checks": 5_000}, {}, NOW,
                   unsized=frozenset({"Cleanway checks"}))
    assert not ok.degraded
    down = fh.assess({"Cleanway checks": None}, {}, {}, NOW, unsized=frozenset({"Cleanway checks"}))
    assert set(down.degraded) == {"Cleanway checks"}


def test_a_big_feed_under_half_its_last_size_is_degraded():
    health = fh.assess({"phishing.army": 70_000}, {"phishing.army": 160_000}, {}, NOW)
    assert health.degraded == {"phishing.army": "shrank from 160000 to 70000 hosts"}


def test_ordinary_movement_is_healthy_and_becomes_the_new_baseline():
    health = fh.assess({"phishing.army": 150_000}, {"phishing.army": 160_000}, {}, NOW)
    assert not health.degraded
    assert health.healthy_counts == {"phishing.army": 150_000}


@pytest.mark.parametrize("baseline,count", [(300, 40), (fh.MIN_BASELINE - 1, 3)])
def test_a_small_rolling_feed_is_not_judged_by_how_much_it_moved(baseline, count):
    health = fh.assess({"OpenPhish": count}, {"OpenPhish": baseline}, {}, NOW)
    assert not health.degraded


def test_any_feed_that_suddenly_parses_to_nothing_is_degraded():
    # e.g. an HTML error or challenge page served with 200 OK.
    health = fh.assess({"OpenPhish": 0, "Phishunt": 0, "CSIRT Italia": 0},
                       {"OpenPhish": 280, "CSIRT Italia": fh.EMPTY_MIN_BASELINE - 1}, {}, NOW)
    assert health.degraded == {"OpenPhish": "returned no hosts (had 280)"}
    # Never had any, or a handful: an empty day is plausible, nothing to judge.
    assert health.healthy_counts == {"Phishunt": 0, "CSIRT Italia": 0}


def test_a_feed_without_a_recorded_size_is_accepted():
    assert not fh.assess({"TweetFeed": 5}, {}, {}, NOW).degraded


def test_accept_sizes_takes_a_shrink_but_never_a_failed_download():
    health = fh.assess({"phishing.army": 10, "URLhaus": None},
                       {"phishing.army": 160_000}, {}, NOW, accept_sizes=True)
    assert health.degraded == {"URLhaus": "unavailable (download or read failed)"}
    assert health.healthy_counts == {"phishing.army": 10}


def test_an_ongoing_outage_keeps_its_first_timestamp():
    health = fh.assess({"URLhaus": None}, {}, {"URLhaus": NOW - 7200, "Gone": NOW - 99}, NOW)
    assert health.down_since == {"URLhaus": NOW - 7200}
    assert health.outage_seconds(NOW) == 7200
    assert fh.assess({"URLhaus": 5}, {}, {}, NOW).outage_seconds(NOW) == 0


PREVIOUS = {"army1.top", "army2.top", "op-dropped.top", "csirt.example", "listed.top",
            "list-canary.cleanway.ai"}
LISTED = {"listed.top"}
CANARY = frozenset({"list-canary.cleanway.ai"})


def test_the_carry_keeps_only_what_the_missing_feed_backed():
    plan = fh.plan_carry(PREVIOUS, LISTED, {"phishing.army": NOW - 3600}, NOW,
                         {"phishing.army": {"army1.top", "army2.top"}}, protected=CANARY)
    assert plan.carried == {"army1.top", "army2.top"}
    assert plan.backed == {"army1.top", "army2.top"}
    # op-dropped.top left a HEALTHY feed: not carried, and free to be
    # recorded as an ordinary departure (nothing blind).
    assert not plan.blind and not plan.expired


def test_the_window_is_judged_per_feed_not_on_the_oldest_outage():
    weeks = NOW - fh.CARRY_MAX_SECONDS - 86_400
    plan = fh.plan_carry(PREVIOUS, LISTED, {"CSIRT Italia": weeks, "phishing.army": NOW - 3600}, NOW,
                         {"CSIRT Italia": {"csirt.example"}, "phishing.army": {"army1.top", "army2.top"}},
                         protected=CANARY)
    assert plan.carried == {"army1.top", "army2.top"}
    # The dead feed's names leave — but are not departures either, or
    # retention would hold them another 14 days.
    assert plan.backed == {"army1.top", "army2.top", "csirt.example"}
    assert plan.expired == ("CSIRT Italia",)


def test_without_a_record_the_carry_keeps_every_unlisted_name_and_blocks_departures():
    plan = fh.plan_carry(PREVIOUS, LISTED, {"phishing.army": NOW - 3600}, NOW, {}, protected=CANARY)
    assert plan.carried == PREVIOUS - LISTED - CANARY
    assert plan.blind == ("phishing.army",)


def test_a_dead_feed_without_a_record_stops_blocking_departures_once_its_names_left():
    settling = NOW - fh.CARRY_MAX_SECONDS - fh.CARRY_SETTLE_SECONDS + 3600
    settled = NOW - fh.CARRY_MAX_SECONDS - fh.CARRY_SETTLE_SECONDS - 3600
    assert fh.plan_carry(PREVIOUS, LISTED, {"CSIRT Italia": settling}, NOW, {}).blind == ("CSIRT Italia",)
    plan = fh.plan_carry(PREVIOUS, LISTED, {"CSIRT Italia": settled}, NOW, {})
    assert plan.blind == () and plan.carried == frozenset()


def test_an_uncarried_source_is_counted_but_never_kept():
    """The server-confirmed set: a host it cannot vouch for must not outlive
    its 7-day window — not even through another feed's blind carry."""
    records = {"Cleanway checks": {"csirt.example"}}
    only = fh.plan_carry(PREVIOUS, LISTED, {"Cleanway checks": NOW - 3600}, NOW, records,
                         uncarried=frozenset({"Cleanway checks"}), protected=CANARY)
    assert only.carried == frozenset() and only.backed == {"csirt.example"}
    both = fh.plan_carry(PREVIOUS, LISTED, {"Cleanway checks": NOW - 3600, "phishing.army": NOW - 3600},
                         NOW, records, uncarried=frozenset({"Cleanway checks"}), protected=CANARY)
    assert "csirt.example" not in both.carried
    assert "army1.top" in both.carried


class _Pipe:
    def __init__(self, store):
        self.store, self.calls = store, []

    def __getattr__(self, name):
        def queue(*a, **kw):
            self.calls.append((name, a, kw))
            return self
        return queue

    async def execute(self):
        for name, a, kw in self.calls:
            if name == "hset":
                self.store.setdefault(a[0], {}).update(kw["mapping"])
            elif name == "hdel":
                for f in a[1:]:
                    self.store.get(a[0], {}).pop(f, None)


class _Redis:
    def __init__(self):
        self.store: dict = {}

    def pipeline(self, transaction=True):
        return _Pipe(self.store)

    async def hgetall(self, key):
        return dict(self.store.get(key, {}))


@pytest.mark.asyncio
async def test_state_round_trip_keeps_a_broken_run_out_of_the_baseline():
    r = _Redis()
    await fh.save_state(r, fh.assess({"phishing.army": 160_000, "URLhaus": 5_000}, {}, {}, NOW))
    health = fh.assess({"phishing.army": 1_000, "URLhaus": 5_100}, *await fh.load_state(r), NOW + 3600)
    await fh.save_state(r, health)
    baselines, down_since = await fh.load_state(r)
    assert baselines == {"phishing.army": 160_000, "URLhaus": 5_100}
    assert down_since == {"phishing.army": NOW + 3600}
    # Back to normal: the outage is closed.
    await fh.save_state(r, fh.assess({"phishing.army": 158_000}, baselines, down_since, NOW + 7200))
    assert (await fh.load_state(r))[1] == {}

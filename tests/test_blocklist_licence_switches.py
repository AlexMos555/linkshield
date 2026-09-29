"""The blocklist's licence switches (plan §4): prepared, not flipped.

  * BLOCKLIST_LICENSED_ONLY=1 leaves URLhaus, OpenPhish and phishing.army out
    of the build; unset, every feed is fetched exactly as before.
  * A feed left out is not an outage: nothing is carried for it, its stored
    health state goes, and the names only it backed leave with that publish
    instead of lingering in retention.
  * PhishTank joins the feeds only with PHISHTANK_API_KEY, downloaded at most
    once a day through a Redis cache (api/services/phishtank_feed.py).

The end-to-end harness (_FakeRedis, _stub_world) is the one
test_refresh_dangerous_domains.py builds; it is imported, not copied.
"""
from __future__ import annotations

import gzip
import logging

import pytest
from test_refresh_dangerous_domains import (
    BASE, DAY, T0, _FakeRedis, _phone_blocks, _published, _stub_world, rdd,
)

from api.services import blocklist_feed_health as feed_health
from api.services import blocklist_retention as retention
from api.services import phishtank_feed

ARMY = [f"army{i}.top" for i in range(165)]
ENV_KEYS = (rdd.LICENSED_ONLY_ENV, rdd.EXCLUDE_FEEDS_ENV, phishtank_feed.KEY_ENV)
PHISHTANK_CSV = (
    "phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target\n"
    "1,https://www.tank-phish.com/login,https://www.phishtank.com/phish_detail.php?phish_id=1,"
    "2026-09-28T10:00:00+00:00,yes,2026-09-28T11:00:00+00:00,yes,Other\n"
    "2,https://tank-phish.com/,https://www.phishtank.com/phish_detail.php?phish_id=2,"
    "2026-09-28T10:00:00+00:00,yes,2026-09-28T11:00:00+00:00,yes,Other\n"
    "3,,https://www.phishtank.com/phish_detail.php?phish_id=3,2026-09-28T10:00:00+00:00,yes,,yes,Other\n"
)


def _world(monkeypatch, fake, extra=None, env=None) -> None:
    _stub_world(monkeypatch, fake, [], frozenset(), extra)
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)


async def _refresh(monkeypatch, fake, now, extra=None, env=None, dry_run=False, force=False) -> int:
    _world(monkeypatch, fake, extra, env)
    return await rdd.refresh("redis://fake", dry_run=dry_run, now=now, force=force)


def _requested(monkeypatch) -> list[str]:
    """Every URL the run asks _fetch for."""
    seen: list[str] = []
    real = rdd._fetch

    async def _fetch(url):
        seen.append(url)
        return await real(url)

    monkeypatch.setattr(rdd, "_fetch", _fetch)
    return seen


# ── The switch itself ────────────────────────────────────────────────────────


def test_defaults_keep_every_feed_and_no_phishtank():
    assert rdd.excluded_feeds({}) == frozenset()
    assert [spec[0] for spec in rdd._feed_specs()] == [
        "URLhaus", "OpenPhish", "Phishing.Database", "phishing.army", "Phishunt", "TweetFeed", "CERT Polska",
    ]
    assert rdd.phishtank_key({}) == ""


@pytest.mark.parametrize("raw", ["1", "true", "YES", " on "])
def test_licensed_only_reads_the_usual_truthy_spellings(raw):
    assert rdd.excluded_feeds({rdd.LICENSED_ONLY_ENV: raw}) == rdd.NON_COMMERCIAL_FEEDS


@pytest.mark.parametrize("raw", ["", "0", "false", "off"])
def test_licensed_only_is_off_unless_asked(raw):
    assert rdd.excluded_feeds({rdd.LICENSED_ONLY_ENV: raw}) == frozenset()


def test_exclude_env_takes_feed_names_and_ignores_typos(caplog):
    env = {rdd.EXCLUDE_FEEDS_ENV: "TweetFeed, CSIRT Italia,tweetfeed"}
    assert rdd.excluded_feeds(env) == frozenset({"TweetFeed", "CSIRT Italia"})
    assert "'tweetfeed' is not a feed name" in caplog.text
    assert [spec[0] for spec in rdd._feed_specs(frozenset({"TweetFeed"}))] == [
        "URLhaus", "OpenPhish", "Phishing.Database", "phishing.army", "Phishunt", "CERT Polska",
    ]


@pytest.mark.asyncio
async def test_by_default_the_three_feeds_are_fetched_as_before(monkeypatch):
    fake = _FakeRedis()
    _world(monkeypatch, fake, extra={rdd.PHISHING_ARMY: "\n".join(ARMY)})
    seen = _requested(monkeypatch)

    async def _never(url, headers):
        raise AssertionError("PhishTank must not be downloaded without a key")

    monkeypatch.setattr(rdd, "_fetch_conditional", _never)
    assert await rdd.refresh("redis://fake", dry_run=False, now=T0) == 0
    assert {rdd.URLHAUS_CSV, rdd.OPENPHISH_FEED, rdd.PHISHING_ARMY} <= set(seen)
    assert set(ARMY) <= _published(fake)


@pytest.mark.asyncio
async def test_licensed_only_leaves_the_three_feeds_out_of_the_build(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    fake = _FakeRedis()
    _world(monkeypatch, fake, extra={rdd.PHISHING_ARMY: "\n".join(ARMY)}, env={rdd.LICENSED_ONLY_ENV: "1"})
    seen = _requested(monkeypatch)
    assert await rdd.refresh("redis://fake", dry_run=False, now=T0) == 0
    assert not {rdd.URLHAUS_CSV, rdd.OPENPHISH_FEED, rdd.PHISHING_ARMY} & set(seen)
    assert "licence switch: leaving out OpenPhish, URLhaus, phishing.army" in caplog.text
    assert set(BASE) <= _published(fake)
    assert not set(ARMY) & _published(fake)
    assert "FEED DEGRADED" not in caplog.text


@pytest.mark.asyncio
async def test_an_explicit_exclusion_overrides_the_environment(monkeypatch):
    """A measurement (eval_day_one_coverage) names the set itself."""
    fake = _FakeRedis()
    _world(monkeypatch, fake, extra={rdd.PHISHING_ARMY: "\n".join(ARMY)}, env={rdd.LICENSED_ONLY_ENV: "1"})
    assert await rdd.refresh("redis://fake", dry_run=False, now=T0, excluded=frozenset()) == 0
    assert set(ARMY) <= _published(fake)


# ── A feed left out is not an outage ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_an_excluded_feed_is_not_an_outage_and_takes_its_names_with_it(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    fake = _FakeRedis()
    army = {rdd.PHISHING_ARMY: "\n".join(ARMY)}
    assert await _refresh(monkeypatch, fake, T0, extra=army) == 0
    assert set(ARMY) <= _published(fake)

    # The feed goes down: carried, and the run would go red past 12 h.
    _world(monkeypatch, fake, extra=army)
    healthy = rdd._fetch

    async def _down(url):
        if url == rdd.PHISHING_ARMY:
            raise ConnectionError("phishing.army down")
        return await healthy(url)

    monkeypatch.setattr(rdd, "_fetch", _down)
    assert await rdd.refresh("redis://fake", dry_run=False, now=T0 + 6 * 3600) == 0
    assert set(ARMY) <= _published(fake)
    assert "phishing.army" in fake.data[feed_health.FEED_DOWN_SINCE_KEY]

    # Switched off 13 h later: not degraded, not red, not carried, state gone.
    caplog.clear()
    code = await _refresh(monkeypatch, fake, T0 + 19 * 3600, extra=army, env={rdd.LICENSED_ONLY_ENV: "1"},
                          force=True)
    assert code == 0
    assert "FEED DEGRADED" not in caplog.text
    assert "OpenPhish, URLhaus, phishing.army not a source this run — forgetting their state" in caplog.text
    assert "phishing.army" not in fake.data.get(feed_health.FEED_DOWN_SINCE_KEY, {})
    assert "phishing.army" not in fake.data.get(feed_health.FEED_COUNTS_KEY, {})
    assert not set(ARMY) & _published(fake)
    assert not _phone_blocks(fake, ARMY[0])
    assert set(BASE) <= _published(fake)


@pytest.mark.asyncio
async def test_excluded_feed_names_leave_at_once_while_ordinary_departures_are_retained(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    fake = _FakeRedis()
    extra = {rdd.PHISHING_ARMY: "\n".join(ARMY), rdd.PHISHUNT_FEED: "https://phishunt-phish.com/x"}
    assert await _refresh(monkeypatch, fake, T0, extra=extra) == 0
    assert "phishunt-phish.com" in _published(fake)

    # Next run: phishing.army switched off, Phishunt merely forgot its host.
    code = await _refresh(monkeypatch, fake, T0 + 6 * 3600, extra={rdd.PHISHING_ARMY: "\n".join(ARMY)},
                          env={rdd.LICENSED_ONLY_ENV: "1"}, force=True)
    assert code == 0
    assert "phishunt-phish.com" in _published(fake), "an ordinary departure is still retained"
    assert not set(ARMY) & _published(fake), "the switched-off feed's names leave now"
    assert not set(ARMY) & set(fake.data.get(retention.LAST_SEEN_KEY, {})), "…and are not recorded as departures"
    assert "165 published names only phishing.army backed leave with this publish" in caplog.text


def test_plan_retention_lets_leaving_names_go_without_a_window():
    stored = {"old-army.top": T0 - DAY, "old-phishunt.top": T0 - DAY}
    previous = {"old-army.top", "old-phishunt.top", "army-now.top", "phishunt-now.top", "still.top"}
    present = {"still.top"}
    plan = retention.plan_retention(stored, previous, present, T0, 14 * DAY,
                                    leaving={"old-army.top", "army-now.top", "still.top"})
    assert plan.departed == frozenset({"phishunt-now.top"})
    assert plan.retained == frozenset({"old-phishunt.top", "phishunt-now.top"})
    assert "old-army.top" in plan.returned, "a stored name that leaves is forgotten"
    assert not plan.skipped


@pytest.mark.asyncio
async def test_forget_drops_one_sources_state_and_keeps_the_rest():
    fake = _FakeRedis()
    await fake.hset(feed_health.FEED_COUNTS_KEY, {"phishing.army": "150000", "OpenPhish": "300"})
    await fake.hset(feed_health.FEED_DOWN_SINCE_KEY, {"phishing.army": str(T0)})
    await feed_health.forget(fake, {"phishing.army"})
    assert fake.data[feed_health.FEED_COUNTS_KEY] == {"OpenPhish": "300"}
    assert feed_health.FEED_DOWN_SINCE_KEY not in fake.data
    await feed_health.forget(fake, set())  # nothing to do, nothing raised


# ── PhishTank as a source ────────────────────────────────────────────────────


class _Tank:
    """A canned PhishTank: answers by status, records every request."""

    def __init__(self, answers) -> None:
        self.answers = list(answers)
        self.calls: list[tuple[str, dict]] = []

    async def __call__(self, url, headers):
        self.calls.append((url, dict(headers)))
        status, resp_headers = self.answers.pop(0)
        body = gzip.compress(PHISHTANK_CSV.encode("utf-8")) if status == 200 else b""
        return status, resp_headers, body


def _tank(monkeypatch, *answers) -> _Tank:
    tank = _Tank(answers)
    monkeypatch.setattr(rdd, "_fetch_conditional", tank)
    return tank


def test_phishtank_parser_reads_the_url_column_and_skips_empty_rows():
    assert phishtank_feed.parse_hosts("﻿" + PHISHTANK_CSV) == ["www.tank-phish.com", "tank-phish.com"]
    assert phishtank_feed.parse_hosts("phish_id,url\n") == []


def test_phishtank_cache_record_survives_a_round_trip_and_rejects_garbage():
    cached = phishtank_feed.CachedDump(("a.example", "b.example"), T0, etag='"e"', last_modified="lm", max_age=7200)
    assert phishtank_feed.decode(phishtank_feed.encode(cached)) == cached
    assert phishtank_feed.decode({"hosts": "not base64!", "fetched_at": "x"}) is None
    assert phishtank_feed.decode({}) is None
    assert cached.next_fetch_at() == T0 + phishtank_feed.FETCH_INTERVAL_SECONDS
    assert phishtank_feed.parse_max_age("public, max-age=172800") == 172800
    assert phishtank_feed.parse_max_age(None) == 0
    assert phishtank_feed.conditional_headers(None) == {"User-Agent": phishtank_feed.USER_AGENT}
    assert phishtank_feed.conditional_headers(cached)["If-None-Match"] == '"e"'


@pytest.mark.asyncio
async def test_phishtank_joins_the_feeds_with_a_key_and_downloads_once_a_day(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    fake = _FakeRedis()
    env = {phishtank_feed.KEY_ENV: "k3y"}
    tank = _tank(monkeypatch, (200, {"ETag": '"v1"', "Last-Modified": "Mon, 28 Sep 2026 10:00:00 GMT"}),
                 (304, {}))
    assert await _refresh(monkeypatch, fake, T0, env=env) == 0
    assert "www.tank-phish.com" in _published(fake)
    assert "tank-phish.com" in _published(fake), "a URL feed promotes the registrable, like OpenPhish"
    assert tank.calls[0][0] == phishtank_feed.feed_url("k3y")
    assert tank.calls[0][1]["User-Agent"] == phishtank_feed.USER_AGENT
    assert "k3y" not in caplog.text, "the key never reaches a log line"

    # An hour later: served from the cache, no request.
    assert await _refresh(monkeypatch, fake, T0 + 3600, env=env) == 0
    assert len(tank.calls) == 1
    assert "PhishTank: cached dump" in caplog.text
    assert "www.tank-phish.com" in _published(fake)

    # A day later: one conditional request; 304 keeps the hosts.
    assert await _refresh(monkeypatch, fake, T0 + DAY + 60, env=env) == 0
    assert len(tank.calls) == 2
    assert tank.calls[1][1]["If-None-Match"] == '"v1"'
    assert tank.calls[1][1]["If-Modified-Since"] == "Mon, 28 Sep 2026 10:00:00 GMT"
    assert "www.tank-phish.com" in _published(fake)
    assert "PhishTank: dump unchanged" in caplog.text


@pytest.mark.asyncio
async def test_phishtank_throttle_uses_the_cache_for_three_days_then_is_an_outage(monkeypatch, caplog):
    caplog.set_level(logging.INFO)
    fake = _FakeRedis()
    env = {phishtank_feed.KEY_ENV: "k3y"}
    _tank(monkeypatch, (200, {}), (404, {}), (404, {}))
    assert await _refresh(monkeypatch, fake, T0, env=env) == 0
    # PhishTank throttles with 404: the cached dump carries the day.
    assert await _refresh(monkeypatch, fake, T0 + DAY + 60, env=env) == 0
    assert "download answered HTTP 404 — using the cached dump" in caplog.text
    assert "FEED DEGRADED" not in caplog.text
    assert "www.tank-phish.com" in _published(fake)
    # Past the stale window the source is down like any other feed, and the
    # outage guard keeps the names it backed.
    assert await _refresh(monkeypatch, fake, T0 + 4 * DAY, env=env) == 0
    assert "FEED DEGRADED: PhishTank" in caplog.text
    assert "www.tank-phish.com" in _published(fake)


@pytest.mark.asyncio
async def test_a_dry_run_downloads_phishtank_but_writes_no_cache(monkeypatch):
    fake = _FakeRedis()
    tank = _tank(monkeypatch, (200, {}))
    assert await _refresh(monkeypatch, fake, T0, env={phishtank_feed.KEY_ENV: "k3y"}, dry_run=True) == 0
    assert len(tank.calls) == 1
    assert phishtank_feed.CACHE_KEY not in fake.data


@pytest.mark.asyncio
async def test_phishtank_can_be_left_out_by_name_even_with_a_key(monkeypatch):
    fake = _FakeRedis()
    tank = _tank(monkeypatch, (200, {}))
    env = {phishtank_feed.KEY_ENV: "k3y", rdd.EXCLUDE_FEEDS_ENV: "PhishTank"}
    assert await _refresh(monkeypatch, fake, T0, env=env) == 0
    assert tank.calls == []
    assert "www.tank-phish.com" not in _published(fake)


@pytest.mark.asyncio
async def test_an_empty_phishtank_dump_is_a_failed_fetch_not_an_empty_feed():
    async def _empty(url, headers):
        return 200, {}, gzip.compress(b"phish_id,url\n")

    with pytest.raises(ValueError, match="parsed to no hosts"):
        await phishtank_feed.fetch_hosts(None, "k3y", T0, _empty)

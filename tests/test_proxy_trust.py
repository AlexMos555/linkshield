"""Aggregate proxy-peer telemetry that tells us what TRUSTED_PROXY_CIDRS must be."""
from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from api.services import proxy_trust
from api.services.rate_limiter import _extract_client_ip


@pytest.fixture(autouse=True)
def _clean():
    proxy_trust.reset_for_tests()
    yield
    proxy_trust.reset_for_tests()


def _req(peer, xff=None):
    req = MagicMock()
    req.headers = {"x-forwarded-for": xff} if xff else {}
    req.client = MagicMock(host=peer) if peer else None
    return req


@pytest.fixture
def trusted(monkeypatch):
    def _set(value: str):
        from api.config import get_settings
        monkeypatch.setattr(get_settings(), "trusted_proxy_cidrs", value)
    return _set


def test_buckets_name_the_proxy_network_never_the_user():
    assert proxy_trust.peer_bucket("100.64.12.7") == "100.64.0.0/10"
    assert proxy_trust.peer_bucket("100.127.255.1") == "100.64.0.0/10"
    assert proxy_trust.peer_bucket("10.1.2.3") == "10.1.0.0/16"
    assert proxy_trust.peer_bucket("fd12:3456:789a::1") == "fd12:3456::/32"
    assert proxy_trust.peer_bucket(None) == "none"
    assert proxy_trust.peer_bucket("not-an-ip") == "unparsed"


def test_without_a_list_it_records_the_peer_network_and_keeps_todays_behaviour(trusted):
    trusted("")
    assert _extract_client_ip(_req("100.64.3.4", "203.0.113.5, 100.64.3.4")) == "203.0.113.5"
    snap = proxy_trust.snapshot()
    assert snap == {"100.64.0.0/10|xff=1|no_list": 1}
    # The client's address never appears in what gets logged.
    assert "203.0.113" not in repr(snap)


def test_a_matching_list_trusts_the_proxy(trusted):
    trusted("100.64.0.0/10")
    assert _extract_client_ip(_req("100.66.0.9", "198.51.100.7, 100.66.0.9")) == "198.51.100.7"
    assert proxy_trust.snapshot() == {"100.64.0.0/10|xff=1|trusted": 1}


def test_a_wrong_list_is_counted_as_the_collapse_signal(trusted):
    # Every user would share the proxy's address: count it loudly.
    trusted("10.0.0.0/8")
    assert _extract_client_ip(_req("100.66.0.9", "198.51.100.7")) == "100.66.0.9"
    snap = proxy_trust.snapshot()
    assert snap["xff_ignored_untrusted_peer"] == 1
    assert snap["100.64.0.0/10|xff=1|untrusted"] == 1


def test_key_count_is_bounded():
    for i in range(100):
        proxy_trust.observe(f"10.{i}.0.1", True, False, True)
    snap = proxy_trust.snapshot()
    assert len(snap) <= proxy_trust._MAX_KEYS + 1
    assert snap["other"] == 100 - proxy_trust._MAX_KEYS


@pytest.mark.asyncio
async def test_the_periodic_stats_line_carries_the_peer_counts(caplog):
    import asyncio

    from api.services import doh_metrics

    proxy_trust.observe("100.64.0.1", True, False, True)
    caplog.set_level(logging.INFO, logger="cleanway.doh")
    task = asyncio.create_task(doh_metrics.stats_logger(every_s=0.01))
    await asyncio.sleep(0.05)
    task.cancel()
    record = next(r for r in caplog.records if r.getMessage() == "doh_stats")
    assert record.proxy_peers == {"100.64.0.0/10|xff=1|no_list": 1}


def test_the_json_log_line_really_carries_the_peer_counts():
    # The formatter prints only whitelisted extras: a LogRecord attribute is
    # not enough (the first deploy logged doh_stats without proxy_peers).
    import json

    from api.services.logger import JsonFormatter

    record = logging.LogRecord("cleanway.doh", logging.INFO, __file__, 1, "doh_stats", None, None)
    record.doh = {"counts": {}}
    record.proxy_peers = {"100.64.0.0/10|xff=1|no_list": 3}
    line = json.loads(JsonFormatter().format(record))
    assert line["proxy_peers"] == {"100.64.0.0/10|xff=1|no_list": 3}

"""Per-IP rate limits key an IPv6 client by its /64, not its full address.

An ISP hands one subscriber a whole /64 (often more), and every device in it
picks fresh addresses on its own (privacy extensions), so "one IPv6 address"
is not "one client": rotating inside the prefix used to get a fresh limit on
every request. IPv4 is unchanged, and an IPv4-mapped IPv6 address
(::ffff:198.51.100.7, what a dual-stack socket reports for an IPv4 peer) is
the IPv4 client it wraps.

Every per-IP key is covered: the generic window limiter (public / blocklist /
billing / unsubscribe / install ceiling), the fresh-analysis budget on
/public/check, the in-process DoH budget and the /health/deep probe guard.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from api.services import rate_limiter as rl


@pytest.fixture
def settings(monkeypatch):
    from api.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "rate_limit_fail_closed", False, raising=False)
    monkeypatch.setattr(s, "trusted_proxy_cidrs", "", raising=False)
    monkeypatch.setattr(s, "benchmark_bypass_token", "", raising=False)
    return s


@pytest.fixture
def limiter_redis(monkeypatch, fake_redis):
    async def _get():
        return fake_redis

    monkeypatch.setattr(rl, "get_redis", _get)
    return fake_redis


@pytest.fixture(autouse=True)
def _quiet_alerts(security_events):
    return security_events


def _req(peer: str, headers=None):
    req = MagicMock()
    req.headers = dict(headers or {})
    req.client = MagicMock(host=peer)
    return req


# ── the key itself ──

@pytest.mark.parametrize("raw, key", [
    ("2001:db8:1:2:aaaa:bbbb:cccc:dddd", "2001:db8:1:2::/64"),
    ("2001:DB8:1:2::1", "2001:db8:1:2::/64"),
    ("[2001:db8:1:2::ffff]", "2001:db8:1:2::/64"),
    (" 2001:db8:1:2::1 ", "2001:db8:1:2::/64"),
    ("fe80::1%eth0", "fe80::/64"),
    ("::1", "::/64"),
    ("198.51.100.7", "198.51.100.7"),
    (" 198.51.100.7 ", "198.51.100.7"),
    ("::ffff:198.51.100.7", "198.51.100.7"),
    ("[::FFFF:198.51.100.7]", "198.51.100.7"),
    ("::ffff:c633:6407", "198.51.100.7"),
    ("", "unknown"),
    (None, "unknown"),
    ("unknown", "unknown"),
    ("not-an-ip", "not-an-ip"),
])
def test_ip_rate_key(raw, key):
    assert rl.ip_rate_key(raw) == key


def test_neighbouring_prefixes_stay_apart():
    assert rl.ip_rate_key("2001:db8:1:2::1") != rl.ip_rate_key("2001:db8:1:3::1")


# ── the generic window limiter ──

@pytest.mark.asyncio
async def test_rotating_inside_one_64_shares_one_limit(settings, limiter_redis):
    for host in ("2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2:dead:beef:0:1"):
        await rl.check_ip_rate_limit(host, "public_check", 3, 60)
    assert limiter_redis._kv == {"rate:ip:public_check:2001:db8:1:2::/64": 3}
    with pytest.raises(HTTPException) as exc:
        await rl.check_ip_rate_limit("2001:db8:1:2:ffff:ffff:ffff:ffff", "public_check", 3, 60)
    assert exc.value.status_code == 429
    # The next /64 over is somebody else.
    assert await rl.check_ip_rate_limit("2001:db8:1:3::1", "public_check", 3, 60) == 2


@pytest.mark.asyncio
async def test_ipv4_mapped_ipv6_is_the_ipv4_client(settings, limiter_redis):
    await rl.check_ip_rate_limit("198.51.100.7", "public_check", 2, 60)
    await rl.check_ip_rate_limit("::ffff:198.51.100.7", "public_check", 2, 60)
    assert limiter_redis._kv == {"rate:ip:public_check:198.51.100.7": 2}
    with pytest.raises(HTTPException):
        await rl.check_ip_rate_limit("[::ffff:198.51.100.7]", "public_check", 2, 60)


@pytest.mark.asyncio
async def test_ipv4_neighbours_keep_their_own_limits(settings, limiter_redis):
    await rl.check_ip_rate_limit("198.51.100.7", "public_check", 1, 60)
    assert await rl.check_ip_rate_limit("198.51.100.8", "public_check", 1, 60) == 0


@pytest.mark.asyncio
async def test_the_ip_dependency_keys_by_prefix(settings, limiter_redis, monkeypatch):
    monkeypatch.setattr(settings, "public_rate_limit_per_window", 2, raising=False)
    dep = rl.rate_limit(category="feedback", mode="ip")
    await dep(_req("2001:db8:9:9::1"))
    await dep(_req("2001:db8:9:9::2"))
    with pytest.raises(HTTPException) as exc:
        await dep(_req("2001:db8:9:9::3"))
    assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_the_install_ceiling_keys_by_prefix(settings, limiter_redis, monkeypatch):
    monkeypatch.setattr(settings, "public_install_rate_limit_per_window", 100, raising=False)
    monkeypatch.setattr(settings, "public_install_ip_ceiling_per_window", 2, raising=False)
    dep = rl.rate_limit(category="public_check", mode="public", install_aware=True)
    installs = ("11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222",
                "33333333-3333-4333-8333-333333333333")
    await dep(_req("2001:db8:7:7::1", {rl.INSTALL_HEADER: installs[0]}))
    await dep(_req("2001:db8:7:7::2", {rl.INSTALL_HEADER: installs[1]}))
    with pytest.raises(HTTPException):
        await dep(_req("2001:db8:7:7::3", {rl.INSTALL_HEADER: installs[2]}))
    assert "rate:ip:public_check:ip_ceiling:2001:db8:7:7::/64" in limiter_redis._kv


@pytest.mark.asyncio
async def test_unsubscribe_limit_keys_by_prefix(settings, limiter_redis, monkeypatch):
    monkeypatch.setattr(settings, "unsubscribe_limit_per_window", 1, raising=False)
    dep = rl.unsubscribe_rate_limit()
    await dep(_req("2001:db8:5:5::1"))
    with pytest.raises(HTTPException):
        await dep(_req("2001:db8:5:5::2"))


# ── /public/check fresh-analysis budget (its own keys) ──

@pytest.mark.asyncio
async def test_fresh_check_budget_keys_by_prefix(settings, fake_redis, monkeypatch):
    from api.routers import public

    monkeypatch.setattr(settings, "public_fresh_checks_per_minute", 2, raising=False)
    await public._enforce_fresh_check_budget(_req("2001:db8:4:4::1"))
    await public._enforce_fresh_check_budget(_req("2001:db8:4:4::2"))
    with pytest.raises(HTTPException) as exc:
        await public._enforce_fresh_check_budget(_req("2001:db8:4:4::3"))
    assert exc.value.status_code == 429
    assert "public_rate:2001:db8:4:4::/64" in fake_redis._kv


@pytest.mark.asyncio
async def test_fresh_check_ip_ceiling_keys_by_prefix(settings, fake_redis, monkeypatch):
    from api.routers import public

    monkeypatch.setattr(settings, "public_fresh_checks_per_minute", 100, raising=False)
    monkeypatch.setattr(settings, "public_fresh_ip_ceiling_per_minute", 1, raising=False)
    await public._enforce_fresh_check_budget(
        _req("::ffff:198.51.100.9", {rl.INSTALL_HEADER: "11111111-1111-4111-8111-111111111111"}))
    with pytest.raises(HTTPException):
        await public._enforce_fresh_check_budget(
            _req("198.51.100.9", {rl.INSTALL_HEADER: "22222222-2222-4222-8222-222222222222"}))
    assert "public_rate:ip_ceiling:198.51.100.9" in fake_redis._kv


# ── in-process budgets ──

def test_doh_budget_keys_by_prefix(settings, monkeypatch):
    from api.services import doh_metrics

    monkeypatch.setattr(settings, "doh_rate_limit_per_window", 2, raising=False)
    monkeypatch.setattr(settings, "doh_rate_limit_window_seconds", 60, raising=False)
    doh_metrics.reset_for_tests()
    try:
        assert rl.doh_rate_check(_req("2001:db8:3:3::1")) is None
        assert rl.doh_rate_check(_req("2001:db8:3:3::2")) is None
        assert rl.doh_rate_check(_req("2001:db8:3:3::3")) is not None
        assert rl.doh_rate_check(_req("2001:db8:3:4::1")) is None
    finally:
        doh_metrics.reset_for_tests()


@pytest.mark.asyncio
async def test_health_deep_probe_guard_keys_by_prefix(settings, monkeypatch):
    """One fresh probe a minute per client: a second address in the same /64,
    past the 30 s result cache, still gets the last result."""
    from api import main
    from api.services import health_deep_guard

    probes = []

    async def _probe():
        probes.append(1)
        return 200, {"status": "ok"}

    clock = {"t": 1000.0}
    monkeypatch.setattr(health_deep_guard, "_now", lambda: clock["t"])
    monkeypatch.setattr(main, "_probe_deep_health", _probe)
    await main.health_deep_check(_req("2001:db8:2:2::1"))
    clock["t"] += 31
    await main.health_deep_check(_req("2001:db8:2:2::2"))
    assert len(probes) == 1
    await main.health_deep_check(_req("2001:db8:2:3::1"))
    assert len(probes) == 2

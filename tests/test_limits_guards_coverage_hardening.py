"""Rate limiting, client-IP trust, body-size guard and security alerts: the
failure paths the main suites leave open.

rate_limiter
  - paid tiers get the paid daily quota (and still a 429 past it);
  - Redis down: check_burst_only and the window limiters honour
    RATE_LIMIT_FAIL_CLOSED (503) / fail open by default; DNS and blocklist
    stay open even when fail-closed;
  - client IP: no TCP peer with a trust list configured never falls back to
    the attacker's X-Forwarded-For; a malformed TRUSTED_PROXY_CIDRS entry
    denies trust instead of crashing; IPv6 peers and blank XFF entries;
  - IPv6 bracket / case spellings of one address share one bucket;
  - the in-process DoH budget: benchmark bypass, 429 with Retry-After;
  - doh / blocklist categories get their own budgets.

proxy_trust: the bucket cache and the outcome set stay bounded.

request_guards: non-HTTP scopes pass through; a garbage or lying
Content-Length; a body that crosses the cap after the app has started its
answer; IPv6 Host headers.

security_alerts: record() never swallows cancellation; without a Resend key
the configured provider is used.
"""
from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from api.models.schemas import AuthUser, UserTier
from api.services import proxy_trust
from api.services import rate_limiter as rl
from api.services import request_guards as rg
from api.services import security_alerts as sa

# Taken at import (collection) time: the autouse `_quiet_alerts` fixture
# below replaces sa.record for every test in this file.
_REAL_RECORD = sa.record


@pytest.fixture
def settings(monkeypatch):
    from api.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "free_tier_daily_limit", 3, raising=False)
    monkeypatch.setattr(s, "paid_tier_daily_limit", 5, raising=False)
    monkeypatch.setattr(s, "burst_limit", 100, raising=False)
    monkeypatch.setattr(s, "burst_window_seconds", 10, raising=False)
    monkeypatch.setattr(s, "rate_limit_fail_closed", False, raising=False)
    monkeypatch.setattr(s, "trusted_proxy_cidrs", "", raising=False)
    monkeypatch.setattr(s, "benchmark_bypass_token", "", raising=False)
    return s


@pytest.fixture
def limiter_redis(monkeypatch, fake_redis):
    """rate_limiter imports get_redis by name: patch it there too."""
    async def _get():
        return fake_redis

    monkeypatch.setattr(rl, "get_redis", _get)
    return fake_redis


@pytest.fixture
def limiter_redis_down(monkeypatch):
    async def _boom():
        raise ConnectionError("simulated Redis outage")

    monkeypatch.setattr(rl, "get_redis", _boom)


@pytest.fixture(autouse=True)
def _quiet_alerts(security_events):
    return security_events


@pytest.fixture(autouse=True)
def _clean_proxy_counters():
    proxy_trust.reset_for_tests()
    yield
    proxy_trust.reset_for_tests()


def _user(tier=UserTier.free, uid="u-1") -> AuthUser:
    return AuthUser(id=uid, email="t@example.com", tier=tier)


def _req(xff=None, cf=None, peer="203.0.113.9", headers=None):
    req = MagicMock()
    h = dict(headers or {})
    if xff is not None:
        h["x-forwarded-for"] = xff
    if cf is not None:
        h["cf-connecting-ip"] = cf
    req.headers = h
    req.client = MagicMock(host=peer) if peer else None
    return req


# ── per-user daily quota by tier ──

@pytest.mark.asyncio
@pytest.mark.parametrize("tier", [UserTier.personal, UserTier.family, UserTier.business])
async def test_paid_tiers_get_the_paid_daily_quota(settings, limiter_redis, tier):
    user = _user(tier)
    for used in range(1, 6):
        assert await rl.check_rate_limit(user) == 5 - used
    with pytest.raises(HTTPException) as exc:
        await rl.check_rate_limit(user)
    assert exc.value.status_code == 429
    assert exc.value.detail["daily_limit"] == 5
    assert exc.value.detail["tier"] == tier.value


@pytest.mark.asyncio
async def test_multi_domain_check_counts_every_domain(settings, limiter_redis):
    user = _user()
    assert await rl.check_rate_limit(user, num_domains=3) == 0
    assert limiter_redis._ttls[next(k for k in limiter_redis._kv if k.startswith("rate:daily:"))] == 90000
    with pytest.raises(HTTPException):
        await rl.check_rate_limit(user, num_domains=1)


# ── Redis down ──

@pytest.mark.asyncio
async def test_burst_only_fails_open_by_default(settings, limiter_redis_down):
    assert await rl.check_burst_only(_user()) is None


@pytest.mark.asyncio
async def test_burst_only_fails_closed_when_configured(settings, limiter_redis_down, monkeypatch):
    monkeypatch.setattr(settings, "rate_limit_fail_closed", True)
    with pytest.raises(HTTPException) as exc:
        await rl.check_burst_only(_user())
    assert exc.value.status_code == 503
    assert exc.value.detail["retry_after_seconds"] == 30


@pytest.mark.asyncio
async def test_burst_only_429s_when_over_the_burst(settings, limiter_redis, monkeypatch):
    monkeypatch.setattr(settings, "burst_limit", 2)
    user = _user()
    await rl.check_burst_only(user)
    await rl.check_burst_only(user)
    with pytest.raises(HTTPException) as exc:
        await rl.check_burst_only(user)
    assert exc.value.status_code == 429
    assert exc.value.detail["retry_after_seconds"] >= 1


@pytest.mark.asyncio
async def test_window_limits_fail_open_by_default(settings, limiter_redis_down):
    assert await rl.check_ip_rate_limit("203.0.113.9", "public_check", 7, 60) == 7
    assert await rl.check_install_rate_limit("a" * 32, "public_check", 9, 60) == 9


@pytest.mark.asyncio
@pytest.mark.parametrize("category", sorted(rl.FAIL_OPEN_CATEGORIES))
async def test_dns_and_blocklist_stay_open_even_when_fail_closed(settings, limiter_redis_down, monkeypatch, category):
    monkeypatch.setattr(settings, "rate_limit_fail_closed", True)
    assert await rl.check_ip_rate_limit("203.0.113.9", category, 50, 60) == 50
    with pytest.raises(HTTPException) as exc:
        await rl.check_ip_rate_limit("203.0.113.9", "public_check", 50, 60)
    assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_redis_error_mid_command_follows_the_same_policy(settings, monkeypatch):
    class _Broken:
        async def eval(self, *a, **k):
            raise TimeoutError("redis read timeout")

    async def _get():
        return _Broken()

    monkeypatch.setattr(rl, "get_redis", _get)
    assert await rl.check_ip_rate_limit("203.0.113.9", "public_check", 4, 60) == 4
    monkeypatch.setattr(settings, "rate_limit_fail_closed", True)
    with pytest.raises(HTTPException) as exc:
        await rl.check_ip_rate_limit("203.0.113.9", "public_check", 4, 60)
    assert exc.value.status_code == 503


# ── one address, one bucket ──

@pytest.mark.asyncio
async def test_ipv6_spellings_of_one_address_share_a_bucket(settings, limiter_redis):
    for spelling in ("2001:DB8::1", "[2001:db8::1]", " 2001:db8::1 "):
        await rl.check_ip_rate_limit(spelling, "public_check", 3, 60)
    assert limiter_redis._kv == {"rate:ip:public_check:2001:db8::/64": 3}
    with pytest.raises(HTTPException):
        await rl.check_ip_rate_limit("[2001:DB8::1]", "public_check", 3, 60)


@pytest.mark.asyncio
async def test_missing_ip_is_its_own_bucket(settings, limiter_redis):
    await rl.check_ip_rate_limit("", "public_check", 2, 60)
    await rl.check_ip_rate_limit(None, "public_check", 2, 60)
    assert limiter_redis._kv == {"rate:ip:public_check:unknown": 2}


# ── client IP trust ──

def test_no_peer_with_a_trust_list_never_trusts_forwarded_headers(settings, monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "100.64.0.0/10")
    req = _req(xff="198.51.100.77", cf="198.51.100.78", peer=None)
    assert rl._extract_client_ip(req) == "unknown"
    assert proxy_trust.snapshot().get("xff_ignored_untrusted_peer") == 1


def test_no_peer_and_no_headers_is_unknown(settings):
    assert rl._extract_client_ip(_req(peer=None)) == "unknown"


@pytest.mark.parametrize("cidrs", ["not-a-cidr", "100.64.0.0/33", "garbage, ,"])
def test_malformed_trust_list_denies_trust_instead_of_crashing(settings, monkeypatch, cidrs):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", cidrs)
    assert rl._extract_client_ip(_req(xff="198.51.100.77", peer="100.66.0.9")) == "100.66.0.9"


def test_one_malformed_entry_does_not_hide_the_valid_ones(settings, monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "not-a-cidr, 100.64.0.0/10")
    assert rl._extract_client_ip(_req(xff="198.51.100.77", peer="100.66.0.9")) == "198.51.100.77"


def test_ipv6_proxy_peer_is_trusted_by_an_ipv6_cidr(settings, monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "fd00:railway::/32")  # malformed: ignored
    assert rl._extract_client_ip(_req(xff="2001:db8::7", peer="fd00::1")) == "fd00::1"
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "fd00::/8")
    assert rl._extract_client_ip(_req(xff="2001:db8::7", peer="fd00::1")) == "2001:db8::7"
    assert rl._extract_client_ip(_req(xff="2001:db8::7, fd00::2", peer="[fd00::1]")) == "2001:db8::7"


def test_spoofed_leftmost_hop_is_not_the_key(settings, monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "100.64.0.0/10")
    req = _req(xff="1.2.3.4, garbage, 198.51.100.77, 100.66.0.10", peer="100.66.0.9")
    assert rl._extract_client_ip(req) == "198.51.100.77"
    # A malformed entry right of the client stops the walk (our edge never writes one).
    req = _req(xff="198.51.100.77, not-an-ip", peer="100.66.0.9")
    assert rl._extract_client_ip(req) == "not-an-ip"


def test_blank_forwarded_entries_fall_back_to_the_peer(settings, monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "100.64.0.0/10")
    assert rl._extract_client_ip(_req(xff=" , ,", peer="100.66.0.9")) == "100.66.0.9"
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "")
    assert rl._extract_client_ip(_req(xff=" ,", peer="203.0.113.9")) == "203.0.113.9"


def test_cf_header_from_an_untrusted_peer_is_ignored(settings, monkeypatch):
    monkeypatch.setattr(settings, "trusted_proxy_cidrs", "100.64.0.0/10")
    assert rl._extract_client_ip(_req(cf="198.51.100.1", peer="203.0.113.50")) == "203.0.113.50"
    assert proxy_trust.snapshot().get("cloudflare_header_ignored") == 1


# ── per-category budgets of the "ip" mode ──

@pytest.mark.asyncio
@pytest.mark.parametrize("category, limit_attr, window_attr", [
    ("doh", "doh_rate_limit_per_window", "doh_rate_limit_window_seconds"),
    ("blocklist", "blocklist_rate_limit_per_window", "blocklist_rate_limit_window_seconds"),
    ("pricing", "public_rate_limit_per_window", "public_rate_limit_window_seconds"),
])
async def test_ip_mode_uses_the_category_budget(settings, monkeypatch, category, limit_attr, window_attr):
    calls = []

    async def _check(ip, cat, limit, window):
        calls.append((ip, cat, limit, window))
        return limit

    monkeypatch.setattr(rl, "check_ip_rate_limit", _check)
    await rl.rate_limit(mode="ip", category=category)(_req(peer="203.0.113.9"))
    assert calls == [("203.0.113.9", category, getattr(settings, limit_attr), getattr(settings, window_attr))]


# ── the in-process DoH budget ──

@pytest.fixture
def tiny_doh_budget(settings, monkeypatch):
    from api.services import doh_metrics

    monkeypatch.setattr(settings, "doh_rate_limit_per_window", 2, raising=False)
    monkeypatch.setattr(settings, "doh_rate_limit_window_seconds", 60, raising=False)
    doh_metrics.reset_for_tests()
    return doh_metrics


@pytest.mark.asyncio
async def test_doh_budget_answers_429_with_retry_after(tiny_doh_budget):
    req = _req(peer="203.0.113.9")
    await rl.doh_rate_limit(req)
    await rl.doh_rate_limit(req)
    with pytest.raises(HTTPException) as exc:
        await rl.doh_rate_limit(req)
    assert exc.value.status_code == 429
    retry = exc.value.detail["retry_after_seconds"]
    assert 1 <= retry <= 60
    assert exc.value.headers == {"Retry-After": str(retry)}
    assert tiny_doh_budget.METRICS.counts["rate_limited"] == 1
    # Another address has its own budget.
    await rl.doh_rate_limit(_req(peer="203.0.113.10"))


@pytest.mark.asyncio
async def test_doh_benchmark_token_skips_the_budget(tiny_doh_budget, settings, monkeypatch):
    monkeypatch.setattr(settings, "benchmark_bypass_token", "bench-token")
    req = _req(peer="203.0.113.9", headers={"X-Cleanway-Benchmark": "bench-token"})
    for _ in range(5):
        assert rl.doh_rate_check(req) is None
    wrong = _req(peer="203.0.113.9", headers={"X-Cleanway-Benchmark": "bench-tokeN"})
    assert rl.doh_rate_check(wrong) is None
    assert rl.doh_rate_check(wrong) is None
    assert rl.doh_rate_check(wrong) is not None


# ── proxy_trust stays bounded ──

def test_bucket_cache_stops_growing_at_its_cap(monkeypatch):
    monkeypatch.setattr(proxy_trust, "_BUCKET_CACHE_MAX", 2)
    assert proxy_trust.peer_bucket("203.0.113.1") == "203.0.0.0/16"
    assert proxy_trust.peer_bucket("198.51.100.1") == "198.51.0.0/16"
    # Full: still labelled correctly, just not remembered.
    assert proxy_trust.peer_bucket("2001:db8::1") == "2001:db8::/32"
    assert len(proxy_trust._bucket_cache) == 2
    assert "2001:db8::1" not in proxy_trust._bucket_cache


def test_peer_bucket_labels():
    assert proxy_trust.peer_bucket(None) == "none"
    assert proxy_trust.peer_bucket("not-an-ip") == "unparsed"
    assert proxy_trust.peer_bucket("100.66.0.9") == "100.64.0.0/10"
    assert proxy_trust.peer_bucket("[2001:db8::1]") == "2001:db8::/32"


def test_unknown_cloudflare_outcome_is_not_counted():
    proxy_trust.observe_cloudflare("cloudflare|client=whatever-the-header-said")
    proxy_trust.observe_cloudflare("cloudflare|client=header")
    assert proxy_trust.snapshot() == {"cloudflare|client=header": 1}


def test_observe_collapses_new_keys_past_the_cap(monkeypatch):
    monkeypatch.setattr(proxy_trust, "_MAX_KEYS", 1)
    proxy_trust.observe("203.0.113.1", True, True, True)
    proxy_trust.observe("198.51.100.1", True, True, False)
    snap = proxy_trust.snapshot()
    assert snap["other"] == 1 and snap["xff_ignored_untrusted_peer"] == 1


# ── body size guard ──

def _asgi_app(record):
    async def app(scope, receive, send):
        record.append(scope["type"])
        if scope["type"] != "http":
            return
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect" or not msg.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    return app


def _run(guarded, scope, chunks):
    sent = []
    queue = list(chunks)

    async def receive():
        return queue.pop(0) if queue else {"type": "http.disconnect"}

    async def send(msg):
        sent.append(msg)

    asyncio.run(guarded(scope, receive, send))
    return sent


def _http(headers=(), path="/x"):
    return {"type": "http", "path": path, "method": "POST", "headers": list(headers)}


@pytest.mark.parametrize("scope_type", ["websocket", "lifespan"])
def test_non_http_scopes_pass_straight_through(scope_type):
    record = []
    guarded = rg.BodySizeLimit(_asgi_app(record), default_limit=1)
    sent = _run(guarded, {"type": scope_type, "path": "/x", "headers": [(b"content-length", b"999")]}, [])
    assert record == [scope_type] and sent == []


@pytest.mark.parametrize("value", [b"abc", b"1e6", b"", b"0x10"])
def test_garbage_content_length_is_400_and_never_reaches_the_app(value):
    record = []
    guarded = rg.BodySizeLimit(_asgi_app(record), default_limit=10)
    sent = _run(guarded, _http([(b"content-length", value)]), [{"type": "http.request", "body": b"x"}])
    assert sent[0]["status"] == 400
    assert b"Invalid Content-Length" in sent[1]["body"]
    assert record == []


@pytest.mark.parametrize("declared", [b"4", b"-1", b"0"])
def test_a_content_length_that_lies_low_is_still_counted(declared):
    record = []
    guarded = rg.BodySizeLimit(_asgi_app(record), default_limit=10)
    chunks = [{"type": "http.request", "body": b"x" * 8, "more_body": True},
              {"type": "http.request", "body": b"x" * 8, "more_body": False}]
    sent = _run(guarded, _http([(b"content-length", declared)]), chunks)
    assert sent[0]["status"] == 413
    assert len(sent) == 2


def test_declared_length_exactly_at_the_cap_is_allowed():
    record = []
    guarded = rg.BodySizeLimit(_asgi_app(record), default_limit=10)
    sent = _run(guarded, _http([(b"content-length", b"10")]), [{"type": "http.request", "body": b"x" * 10}])
    assert sent[0]["status"] == 200


def test_reads_after_the_refusal_see_a_disconnect():
    reads = []

    async def app(scope, receive, send):
        for _ in range(3):
            reads.append((await receive())["type"])

    guarded = rg.BodySizeLimit(app, default_limit=4)
    chunks = [{"type": "http.request", "body": b"x" * 8, "more_body": True},
              {"type": "http.request", "body": b"never read", "more_body": False}]
    sent = _run(guarded, _http(), chunks)
    assert reads == ["http.disconnect"] * 3
    assert sent[0]["status"] == 413


def test_a_client_disconnect_mid_body_reaches_the_app():
    reads = []

    async def app(scope, receive, send):
        for _ in range(2):
            reads.append((await receive())["type"])

    guarded = rg.BodySizeLimit(app, default_limit=100)
    sent = _run(guarded, _http(), [{"type": "http.request", "body": b"x" * 8, "more_body": True},
                                   {"type": "http.disconnect"}])
    assert reads == ["http.request", "http.disconnect"]
    assert sent == []


def test_crossing_the_cap_after_the_app_answered_sends_no_second_response():
    """An app that starts its answer before reading the whole body (streaming
    echo): the guard cannot send a 413 any more, so it cuts the body and drops
    whatever the app sends afterwards."""
    async def app(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        while True:
            msg = await receive()
            if msg["type"] == "http.disconnect":
                break
            await send({"type": "http.response.body", "body": msg.get("body", b""), "more_body": True})
        await send({"type": "http.response.body", "body": b"", "more_body": False})

    guarded = rg.BodySizeLimit(app, default_limit=10)
    chunks = [{"type": "http.request", "body": b"a" * 6, "more_body": True},
              {"type": "http.request", "body": b"b" * 6, "more_body": True}]
    sent = _run(guarded, _http(), chunks)
    assert [m["type"] for m in sent] == ["http.response.start", "http.response.body"]
    assert sent[0]["status"] == 200
    assert sent[1]["body"] == b"a" * 6     # the chunk past the cap never went anywhere


@pytest.mark.parametrize("host, expected", [
    (b"[::1]:8000", "[::1]:8000"),
    (b"[2001:db8::1]", "[2001:db8::1]"),
    (b"DNS.cleanway.ai.:443", "dns.cleanway.ai"),
    (b"api.cleanway.ai", "api.cleanway.ai"),
    (None, ""),
])
def test_host_header_parsing(host, expected):
    headers = [(b"host", host)] if host is not None else []
    assert rg._host({"headers": headers}) == expected


def test_dns_host_guard_ignores_ipv6_hosts_and_non_http():
    record = []
    guarded = rg.DnsHostOnly(_asgi_app(record))
    sent = _run(guarded, _http([(b"host", b"[::1]:8000")], path="/api/v1/pricing"),
                [{"type": "http.request", "body": b""}])
    assert sent[0]["status"] == 200
    _run(guarded, {"type": "websocket", "path": "/api", "headers": [(b"host", b"dns.cleanway.ai")]}, [])
    assert record == ["http", "websocket"]


# ── security_alerts ──

@pytest.mark.asyncio
async def test_record_never_swallows_cancellation(monkeypatch):
    """record() swallows every Redis failure, but a request that is being
    cancelled (client gone, shutdown) must still be cancelled."""
    monkeypatch.delenv("SECURITY_ALERTS_ENABLED", raising=False)
    monkeypatch.setattr(sa, "_last_unavailable_log", float("-inf"))
    started = asyncio.Event()

    async def _slow_redis():
        started.set()
        await asyncio.sleep(10)

    monkeypatch.setattr("api.services.cache.get_redis", _slow_redis)
    task = asyncio.create_task(_REAL_RECORD("ssrf_blocked"))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


def test_without_a_resend_key_the_configured_provider_sends_alerts(monkeypatch):
    from api.services import email as email_service

    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    sentinel = object()
    monkeypatch.setattr(email_service, "get_provider", lambda: sentinel)
    assert sa._email_provider() is sentinel
    monkeypatch.setenv("RESEND_API_KEY", "   ")
    assert sa._email_provider() is sentinel
    monkeypatch.setenv("RESEND_API_KEY", "re_test_not_real")
    assert isinstance(sa._email_provider(), email_service.ResendProvider)

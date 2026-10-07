"""Shared pytest fixtures + environment setup for Cleanway tests."""
from __future__ import annotations

import os
from typing import Any

import pytest


# Set DEBUG before any api.* imports — prevents crash on missing prod-only env vars
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault(
    "SUPABASE_JWT_SECRET", "test-secret-for-development-only-not-for-production-use"
)


# ─── Shared FakeRedis ──────────────────────────────────────────────
#
# Audit finding backend MEDIUM "No conftest.py shared Redis fixture —
# 4 test files define their own FakeRedis with different surfaces,
# creating drift risk".
#
# This is the single source of truth. Tests that want a working Redis
# request the `fake_redis` fixture; tests that want to simulate Redis
# being down request `redis_down` (which patches get_redis to raise).
#
# Test files can still define their own FakeRedis subclass / mock when
# they need behaviour this minimal one doesn't cover (e.g. atomic
# Lua scripts beyond INCR+EXPIRE, sliding windows). The point is: the
# BASIC Redis surface stops drifting across test files.


class FakeRedis:
    """Minimal async Redis-compatible stand-in.

    Covers the surface every Cleanway service actually uses:
      - get / set / setex / delete
      - incr / incrby
      - smembers / sadd (personal whitelist)
      - expire / ttl (rate-limiter window inspection)
      - eval (Lua INCR + EXPIRE atomic helper)

    Internally just a dict + a TTL dict. Doesn't simulate expiry,
    persistence, or any other Redis-specific behaviour. Tests that
    care about those should construct their own.
    """

    def __init__(self) -> None:
        self._kv: dict[str, Any] = {}
        self._ttls: dict[str, int] = {}

    async def get(self, key: str):
        return self._kv.get(key)

    async def set(self, key: str, val: Any, **_kw):
        self._kv[key] = val
        return True

    async def setex(self, key: str, ttl: int, val: Any):
        self._kv[key] = val
        self._ttls[key] = ttl
        return True

    async def delete(self, *keys: str):
        for k in keys:
            self._kv.pop(k, None)
            self._ttls.pop(k, None)
        return len(keys)

    async def incr(self, key: str) -> int:
        self._kv[key] = int(self._kv.get(key, 0)) + 1
        return self._kv[key]

    async def incrby(self, key: str, amount: int) -> int:
        self._kv[key] = int(self._kv.get(key, 0)) + amount
        return self._kv[key]

    async def expire(self, key: str, seconds: int) -> bool:
        self._ttls[key] = seconds
        return True

    async def ttl(self, key: str) -> int:
        return self._ttls.get(key, -1)

    async def smembers(self, key: str):
        v = self._kv.get(key)
        return set(v) if isinstance(v, (list, set, tuple)) else set()

    async def sadd(self, key: str, *members: Any) -> int:
        cur = self._kv.get(key)
        if not isinstance(cur, set):
            cur = set(cur) if isinstance(cur, (list, tuple)) else set()
        added = 0
        for m in members:
            if m not in cur:
                cur.add(m)
                added += 1
        self._kv[key] = cur
        return added

    async def eval(self, _script: str, _numkeys: int, key: str, *args) -> int:
        """Stand-in for the atomic INCR+TTL Lua used by the rate
        limiter. Emulates observable behaviour: increment, set TTL
        on first write, return new count."""
        self._kv[key] = int(self._kv.get(key, 0)) + 1
        if self._kv[key] == 1 and args:
            try:
                self._ttls[key] = int(args[0])
            except (TypeError, ValueError):
                pass
        return self._kv[key]

    async def close(self):  # pragma: no cover — unused in tests
        return None


@pytest.fixture
def fake_redis(monkeypatch) -> FakeRedis:
    """Patch get_redis() to return a fresh FakeRedis instance.

    Use this when your test wants Redis-dependent code to behave
    normally (rate limit, soft-delete flag, whitelist lookup, etc.).
    """
    fake = FakeRedis()

    async def _get():
        return fake

    monkeypatch.setattr("api.services.cache.get_redis", _get)
    return fake


@pytest.fixture
def redis_down(monkeypatch):
    """Patch get_redis() to raise ConnectionError.

    Use this when your test wants to exercise the fail-open / fail-
    closed code paths. Returns nothing — just configures the mock.
    """
    async def _boom():
        raise ConnectionError("simulated Redis outage")

    monkeypatch.setattr("api.services.cache.get_redis", _boom)


# ─── Fake Stripe API ───────────────────────────────────────────────
#
# The billing path (checkout, portal, webhook attribution, account
# deletion, the GDPR purge) talks to Stripe through a handful of async
# resource calls. This stand-in keeps a tiny in-memory Stripe account so
# tests can assert WHICH subscriptions got cancelled and with WHAT
# parameters, without a network call. Plain dicts are fine: the code
# under test reads Stripe objects via dict access (StripeObject is a
# dict subclass).


class FakeStripe:
    def __init__(self) -> None:
        self.subscriptions: dict[str, dict] = {}
        self.charges: dict[str, dict] = {}
        self.cancel_calls: list[tuple[str, dict]] = []
        self.portal_calls: list[dict] = []
        self.list_calls: list[dict] = []
        self.fail_cancel = False
        self.fail_list = False

    def add_subscription(self, sub_id: str, customer: str, status: str = "active", **extra) -> dict:
        sub = {"id": sub_id, "customer": customer, "status": status, "metadata": {}, **extra}
        self.subscriptions[sub_id] = sub
        return sub

    def install(self, monkeypatch) -> "FakeStripe":
        import stripe

        fake = self

        async def sub_list(**params):
            fake.list_calls.append(params)
            if fake.fail_list:
                raise stripe.APIConnectionError("simulated Stripe outage")
            data = [s for s in fake.subscriptions.values() if s["customer"] == params.get("customer")]
            return {"object": "list", "data": data}

        async def sub_retrieve(sub_id, **_params):
            if sub_id not in fake.subscriptions:
                raise stripe.InvalidRequestError(f"No such subscription: {sub_id}", "id")
            return fake.subscriptions[sub_id]

        async def sub_cancel(sub_id, **params):
            if fake.fail_cancel:
                raise stripe.APIConnectionError("simulated Stripe outage")
            fake.cancel_calls.append((sub_id, params))
            fake.subscriptions[sub_id]["status"] = "canceled"
            return fake.subscriptions[sub_id]

        async def charge_retrieve(charge_id, **_params):
            return fake.charges[charge_id]

        class _Portal:
            url = "https://billing.stripe.com/p/session/fake"

        async def portal_create(**params):
            fake.portal_calls.append(params)
            return _Portal()

        async def must_not_search(**_params):
            raise AssertionError("Customer lookup by email is not allowed")

        monkeypatch.setattr(stripe.Subscription, "list_async", sub_list)
        monkeypatch.setattr(stripe.Subscription, "retrieve_async", sub_retrieve)
        monkeypatch.setattr(stripe.Subscription, "cancel_async", sub_cancel)
        monkeypatch.setattr(stripe.Charge, "retrieve_async", charge_retrieve)
        monkeypatch.setattr(stripe.billing_portal.Session, "create_async", portal_create)
        monkeypatch.setattr(stripe.Customer, "list_async", must_not_search)
        return self


@pytest.fixture
def fake_stripe(monkeypatch) -> FakeStripe:
    """In-memory Stripe + a configured secret key."""
    from api import config

    monkeypatch.setattr(config.get_settings(), "stripe_secret_key", "sk_test_dummy", raising=False)
    return FakeStripe().install(monkeypatch)


# ─── Offline analyzer ──────────────────────────────────────────────
#
# analyze_domain() with every network call replaced, so verdict tests are
# hermetic and fast. The scorer and the ML model run for real — they are
# what the tests are about. See tests/test_unreachable_verdicts.py.

# check name → (analyzer attribute, value when the source has NO hit)
_OFFLINE_CHECKS = {
    "safe_browsing": ("check_safe_browsing", False),
    "phishtank": ("check_phishtank", False),
    "urlhaus": ("check_urlhaus", False),
    "phishstats": ("check_phishstats", False),
    "threatfox": ("check_threatfox", False),
    "spamhaus": ("check_spamhaus_dbl", False),
    "surbl": ("check_surbl", False),
    "alienvault": ("check_alienvault_otx", {}),
    "ipqs": ("check_ipqualityscore", {}),
    "malware_bazaar": ("check_malware_bazaar", False),
    "feodo": ("check_feodo_tracker", False),
    "tranco": ("check_tranco_popularity", {"ranked": False, "rank": None, "weight": 0, "label": ""}),
    "favicon": ("check_favicon_brand_clone", {"cloned": False, "brand": None, "weight": 0, "detail": ""}),
    "watchtower": ("check_typosquat_alert", {"matched": False, "weight": 0}),
    "whois": ("check_whois_age", {}),
    "dns": ("check_dns", {"a_count": 1, "ttl": 3600, "ns_count": 2, "has_mx": True}),
}
_REACHABLE_SITE = {
    "check_ssl": {"reachable": True, "has_ssl": True, "issuer": "Test CA",
                  "is_free_ssl": False, "cert_age_days": 400},
    "check_security_headers": {"reachable": True, "present": ["strict-transport-security"],
                               "missing": ["content-security-policy"]},
    "check_redirect_chain": {"reachable": True, "count": 1, "cross_domain": False},
}


class _UnreachableClient:
    """httpx.AsyncClient stand-in for a site that refuses foreign scanners."""

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def _fail(self, url, *args, **kwargs):
        import httpx
        raise httpx.ConnectTimeout("timed out from abroad")

    get = head = _fail


@pytest.fixture
def offline_analyzer(monkeypatch):
    """Returns `configure(**kw)`, which wires analyze_domain for one case:

      exists   True / False (NXDOMAIN) / None (DNS gave no answer)
      site     "unreachable" (the real probes, network refused) or "reachable"
      hits     check name → hit value, e.g. {"urlhaus": True}
      values   check name → value, overriding the no-hit defaults above
      delays   check name (or "exists"/"resolution") → seconds before it answers
      ranks    name → Tranco rank, for lookups outside the "tranco" check
               (the analyzer asks for a registrable domain's rank)
    """
    import asyncio
    import socket

    from api.services import analyzer, site_probes

    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    def _fake(value, delay):
        async def _check(domain):
            if delay:
                await asyncio.sleep(delay)
            return value
        return _check

    def configure(exists=True, site="unreachable", hits=None, values=None, delays=None, ranks=None):
        hits, values, delays, ranks = hits or {}, values or {}, delays or {}, ranks or {}

        async def _exists(domain):
            await asyncio.sleep(delays.get("exists", 0))
            return exists

        async def _resolution(domain):
            await asyncio.sleep(delays.get("resolution", 0))

        async def _rank(name):
            return ranks.get(name)

        monkeypatch.setattr(analyzer, "check_domain_exists", _exists)
        monkeypatch.setattr(analyzer, "validate_domain_resolution", _resolution)
        monkeypatch.setattr(analyzer, "get_tranco_rank", _rank)
        for name, (attr, clean) in _OFFLINE_CHECKS.items():
            value = values.get(name, hits.get(name, clean))
            monkeypatch.setattr(analyzer, attr, _fake(value, delays.get(name, 0)))
        if site == "reachable":
            for attr, value in _REACHABLE_SITE.items():
                monkeypatch.setattr(analyzer, attr, _fake(value, delays.get(attr, 0)))
        else:
            def _refuse(*args, **kwargs):
                raise socket.timeout("timed out from abroad")
            monkeypatch.setattr(site_probes.socket, "create_connection", _refuse)
            monkeypatch.setattr(site_probes.httpx, "AsyncClient", _UnreachableClient)

    return configure


# ─── Site probes over a table instead of the network ───────────────

@pytest.fixture
def probe_web(monkeypatch):
    """Returns `configure(routes, unsafe=())`, which serves the HTTPS probes
    (headers, redirect chain) from `routes` through a real httpx client on a
    mock transport — so redirect handling, URL joining and host encoding are
    httpx's own, not a mock's.

      routes   "https://host/path" → (status, headers); anything else is 200
      unsafe   hosts whose redirect-hop SSRF vetting fails

    `configure` returns the list of (method, url) requested, in order.
    """
    import httpx

    from api.services import site_probes
    from api.services.domain_validator import DomainValidationError

    real_client = httpx.AsyncClient

    def configure(routes, unsafe=()):
        requested = []

        def _handler(request):
            url = str(request.url)
            requested.append((request.method, url))
            status, headers = routes.get(url, (200, {}))
            # Raw UTF-8 bytes, as a server sends a Location with a Unicode host.
            raw = [(k.encode("ascii"), v.encode("utf-8")) for k, v in headers.items()]
            return httpx.Response(status, headers=raw)

        def _client(*args, **kwargs):
            kwargs["transport"] = httpx.MockTransport(_handler)
            return real_client(*args, **kwargs)

        async def _vet(host):
            if host in unsafe:
                raise DomainValidationError(f"{host} resolves to a blocked network")

        monkeypatch.setattr(site_probes.httpx, "AsyncClient", _client)
        monkeypatch.setattr(site_probes, "validate_domain_resolution", _vet)
        return requested

    return configure

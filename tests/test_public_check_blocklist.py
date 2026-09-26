"""The manual check consults our own published blocklist (report 2026-09-25 #9).

The phone blocked gosuslugee.ru; the manual check of the same address said
"caution, 25" — it never looked at the list the phone uses. Now a listed
host (or a subdomain of a listed name) is 'dangerous' at once, reason
`cleanway_blocklist`, verdict_basis 'blocklist', with no analysis — before
the cache, so a verdict cached before the listing cannot outlive it.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.models.schemas import DomainResult, RiskLevel
from api.routers import public as public_router
from api.services import cleanway_blocklist


class _ListRedis:
    """Just enough Redis for the blocklist lookup (pipelined SISMEMBER) and
    the public cache."""

    def __init__(self, listed=(), cached=None):
        self.listed = set(listed)
        self.kv = dict(cached or {})

    def pipeline(self):
        outer = self

        class _Pipe:
            def __init__(self):
                self.names = []

            def sismember(self, key, name):
                assert key == "dangerous_domains"
                self.names.append(name)

            async def execute(self):
                return [name in outer.listed for name in self.names]

        return _Pipe()

    async def get(self, key):
        return self.kv.get(key)

    async def setex(self, key, ttl, value):
        self.kv[key] = value

    async def eval(self, *a, **k):
        return 1

    async def ttl(self, key):
        return 60


@pytest.fixture
def list_redis(monkeypatch):
    def install(**kw):
        fake = _ListRedis(**kw)

        async def _get():
            return fake

        monkeypatch.setattr("api.services.cache.get_redis", _get)
        return fake
    return install


@pytest.fixture
def no_analysis(monkeypatch):
    """Fail loudly if the router runs the analyzer."""
    from api.services import analyzer

    async def _boom(*a, **k):
        raise AssertionError("a listed host must not need an analysis")

    monkeypatch.setattr(analyzer, "analyze_domain", _boom)


MODERN_APP = {"X-Cleanway-Install": "3f2b8c1e-7d4a-4b6e-9a0c-5e1f2d3c4b5a"}


def test_listed_host_is_dangerous_immediately(list_redis, no_analysis):
    list_redis(listed={"gosuslugee.ru"})
    body = TestClient(app).get("/api/v1/public/check/gosuslugee.ru", headers=MODERN_APP).json()
    assert body["level"] == "dangerous"
    assert body["reason_codes"] == ["cleanway_blocklist"]
    assert body["verdict_basis"] == "blocklist"


def test_installed_app_gets_a_code_it_can_translate(list_redis, no_analysis):
    """Android 1.0.1 (no install header) shows the English detail for a code
    it does not know — on the key line of the most important card. It gets
    one it localizes («В доверенных списках мошеннических и спам-сайтов»);
    the basis still says 'blocklist'."""
    list_redis(listed={"gosuslugee.ru"})
    body = TestClient(app).get("/api/v1/public/check/gosuslugee.ru").json()
    assert body["reason_codes"] == ["multi_blocklist"]
    assert body["verdict_basis"] == "blocklist" and body["level"] == "dangerous"


def test_subdomain_of_listed_name_is_covered(list_redis, no_analysis):
    """A listed name covers all its subdomains — the phone's own rule."""
    list_redis(listed={"gosuslugee.ru"})
    body = TestClient(app).get("/api/v1/public/check/lk.gosuslugee.ru").json()
    assert body["verdict_basis"] == "blocklist"


def test_match_through_a_parent_name_says_so(list_redis, no_analysis):
    """Over-broad listings exist (report #17: whole co.pt / zoom.pl). A host
    covered only through its parent must not read as 'this very site is
    known phishing'."""
    list_redis(listed={"gosuslugee.ru"})
    body = TestClient(app).get("/api/v1/public/check/lk.gosuslugee.ru").json()
    assert "parent address gosuslugee.ru" in body["signals"][0]
    exact = TestClient(app).get("/api/v1/public/check/gosuslugee.ru").json()
    assert "parent" not in exact["signals"][0]


def test_listed_as_names_the_nearest_listed_name(list_redis):
    list_redis(listed={"gosuslugee.ru", "lk.gosuslugee.ru"})
    assert asyncio.run(cleanway_blocklist.listed_as("a.lk.gosuslugee.ru")) == "lk.gosuslugee.ru"
    assert asyncio.run(cleanway_blocklist.listed_as("gosuslugee.ru")) == "gosuslugee.ru"
    assert asyncio.run(cleanway_blocklist.listed_as("gosuslugi.ru")) is None


def test_listing_beats_a_stale_cached_verdict(list_redis, no_analysis):
    stale = DomainResult(domain="gosuslugee.ru", score=25, level=RiskLevel.caution, reasons=[])
    list_redis(
        listed={"gosuslugee.ru"},
        cached={public_router._PUBLIC_CACHE_PREFIX + "gosuslugee.ru": stale.model_dump_json()},
    )
    body = TestClient(app).get("/api/v1/public/check/gosuslugee.ru").json()
    assert body["level"] == "dangerous"


def test_popular_site_is_never_darkened_by_the_list(list_redis, no_analysis):
    """Mirrors the phone's popular-domain veto: a bad publish must not turn
    sberbank.ru red."""
    list_redis(listed={"sberbank.ru"})
    body = TestClient(app).get("/api/v1/public/check/sberbank.ru").json()
    assert body["level"] == "safe"


def test_unlisted_host_goes_to_analysis(list_redis, monkeypatch):
    list_redis(listed={"gosuslugee.ru"})
    calls = []

    async def _analyze(domain, *a, **k):
        calls.append(domain)
        return DomainResult(domain=domain, score=10, level=RiskLevel.safe, reasons=[],
                            verdict_basis="heuristics")

    from api.services import analyzer
    monkeypatch.setattr(analyzer, "analyze_domain", _analyze)
    body = TestClient(app).get("/api/v1/public/check/obscure-shop.ru").json()
    assert calls == ["obscure-shop.ru"]
    assert body["verdict_basis"] == "heuristics"


def test_lookup_fails_open_when_redis_is_down(redis_down):
    assert asyncio.run(cleanway_blocklist.is_listed("gosuslugee.ru")) is False


def test_authenticated_check_consults_the_list_too(list_redis, monkeypatch):
    from api.models.schemas import AuthUser, UserTier
    from api.routers import check as check_router
    from api.services.auth import get_current_user_no_disposable

    list_redis(listed={"gosuslugee.ru"})

    async def _no_burst(user):
        return None

    async def _no_analysis(domain):
        raise AssertionError("listed host analysed")

    monkeypatch.setattr(check_router, "check_burst_only", _no_burst)
    monkeypatch.setattr(check_router, "analyze_domain", _no_analysis)
    app.dependency_overrides[get_current_user_no_disposable] = lambda: AuthUser(
        id="u1", email="u@example.com", tier=UserTier.free)
    try:
        resp = TestClient(app).post("/api/v1/check", json={"domains": ["gosuslugee.ru"]})
    finally:
        app.dependency_overrides.clear()
    result = resp.json()["results"][0]
    assert result["level"] == "dangerous" and result["verdict_basis"] == "blocklist"

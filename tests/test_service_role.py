"""SERVICE_ROLE: one image, three jobs (docs/runbooks/dns-service-split.md).

docs/runbooks/capacity.md asks for dns.cleanway.ai in a Railway service of its
own before the iOS launch, so a /check flood cannot take CPU from the DNS of
every phone. The same image now runs as:

  * all (default) — everything, exactly as the single `web` service did;
  * dns — /dns-query and its probes (/health, /health/doh) on every host, 404
    for the rest; no ML warm-up, no retention loop; boots without the API's
    secrets (Supabase, Stripe, webhooks);
  * api — everything but DNS: /dns-query and /health/doh are 404, except under
    dns.cleanway.ai (if that name still points here, phones keep their DNS);
    no in-memory blocklist filter.
"""
from __future__ import annotations

import asyncio

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from api.config import ConfigError, Settings, get_settings, validate_settings
from api.services import request_guards as rg

API = "api.cleanway.ai"
DNS = "dns.cleanway.ai"
RAILWAY = "web-dns-production.up.railway.app"  # a service's own Railway domain


@pytest.fixture
def role(monkeypatch):
    def _set(value: str) -> None:
        monkeypatch.setattr(get_settings(), "service_role", value)
    return _set


def _client(monkeypatch, fast_path: bool = True) -> TestClient:
    """The app with a fake Redis holding a published list and an upstream
    that answers every query."""
    import api.routers.doh as doh_router
    from api.main import app
    from tests.doh_helpers import ArtifactRedis, answer, use_redis

    monkeypatch.setattr(get_settings(), "doh_fast_path", fast_path)
    use_redis(monkeypatch, ArtifactRedis({"phish.example"}))

    async def _up(wire):
        return answer(wire)

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)
    return TestClient(app)


def _dns(c: TestClient, host: str):
    from tests.doh_helpers import b64url, query

    wire = query("example.org")
    return (
        c.get("/dns-query", params={"dns": b64url(wire)}, headers={"host": host}),
        c.post("/dns-query", content=wire, headers={"host": host, "content-type": "application/dns-message"}),
    )


# ── the setting ──

def test_the_default_is_all(monkeypatch):
    monkeypatch.delenv("SERVICE_ROLE", raising=False)
    assert Settings(_env_file=None).service_role == "all"


@pytest.mark.parametrize("raw, value", [("dns", "dns"), (" API ", "api"), ("All", "all"), ("", "all"), ("  ", "all")])
def test_the_env_value_is_normalised(monkeypatch, raw, value):
    monkeypatch.setenv("SERVICE_ROLE", raw)
    assert Settings(_env_file=None).service_role == value


@pytest.mark.parametrize("raw", ["dsn", "billing", "web"])
def test_a_typo_refuses_to_boot(monkeypatch, raw):
    """Railway keeps the old deployment when a new one never passes its health
    check; a DNS service that quietly served the whole API would not."""
    monkeypatch.setenv("SERVICE_ROLE", raw)
    with pytest.raises(ValidationError, match="service_role"):
        Settings(_env_file=None)


@pytest.mark.parametrize("value, api, dns", [("all", True, True), ("api", True, False), ("dns", False, True)])
def test_what_each_role_serves(value, api, dns):
    s = Settings(_env_file=None, service_role=value)
    assert (s.serves_api(), s.serves_dns()) == (api, dns)


# ── which process answers which path ──

@pytest.mark.parametrize("value, host, path, allowed", [
    # all: today's rules — the DNS name serves DNS only, every other name everything
    ("all", API, "/dns-query", True),
    ("all", API, "/health/doh", True),
    ("all", API, "/api/v1/pricing", True),
    ("all", DNS, "/dns-query", True),
    ("all", DNS, "/health", True),
    ("all", DNS, "/api/v1/pricing", False),
    # dns: DNS and its probes under every name, nothing else
    ("dns", RAILWAY, "/dns-query", True),
    ("dns", RAILWAY, "/health", True),
    ("dns", RAILWAY, "/health/doh", True),
    ("dns", RAILWAY, "/health/deep", False),
    ("dns", RAILWAY, "/", False),
    ("dns", API, "/api/v1/check", False),
    ("dns", DNS, "/dns-query", True),
    # api: no DNS under API names; the DNS name is still answered
    ("api", API, "/dns-query", False),
    ("api", API, "/health/doh", False),
    ("api", API, "/health", True),
    ("api", API, "/health/deep", True),
    ("api", API, "/api/v1/pricing", True),
    ("api", RAILWAY, "/dns-query", False),
    ("api", DNS, "/dns-query", True),
    ("api", DNS, "/health/doh", True),
    ("api", DNS, "/api/v1/pricing", False),
])
def test_routing_table(value, host, path, allowed):
    assert rg.serves(value, host, path) is allowed


# ── SERVICE_ROLE=dns through the app ──

@pytest.mark.parametrize("fast_path", [True, False], ids=["fast-path", "fastapi-routes"])
@pytest.mark.parametrize("host", [RAILWAY, DNS, "testserver"])
def test_dns_role_answers_dns_under_every_name(monkeypatch, role, fast_path, host):
    role("dns")
    for resp in _dns(_client(monkeypatch, fast_path), host):
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/dns-message"


@pytest.mark.parametrize("path", [
    "/", "/docs", "/health/deep", "/api/v1/pricing", "/api/v1/blocklist/dns",
    "/api/v1/public/check/google.com", "/dns-query/../api/v1/pricing",
])
def test_dns_role_hides_the_api_under_every_name(monkeypatch, role, path):
    role("dns")
    assert _client(monkeypatch).get(path, headers={"host": RAILWAY}).status_code == 404


def test_dns_role_keeps_its_probes_and_says_which_role_it_is(monkeypatch, role):
    role("dns")
    c = _client(monkeypatch)
    health = c.get("/health", headers={"host": RAILWAY})
    assert health.status_code == 200
    assert health.json()["service_role"] == "dns"
    assert c.get("/health/doh", headers={"host": RAILWAY}).status_code in (200, 503)


# ── SERVICE_ROLE=api through the app ──

@pytest.mark.parametrize("fast_path", [True, False], ids=["fast-path", "fastapi-routes"])
@pytest.mark.parametrize("host", [API, "testserver"])
def test_api_role_serves_no_dns(monkeypatch, role, fast_path, host):
    role("api")
    c = _client(monkeypatch, fast_path)
    assert [r.status_code for r in _dns(c, host)] == [404, 404]
    assert c.get("/health/doh", headers={"host": host}).status_code == 404


@pytest.mark.parametrize("fast_path", [True, False], ids=["fast-path", "fastapi-routes"])
def test_api_role_still_answers_dns_under_the_dns_name(monkeypatch, role, fast_path):
    """SERVICE_ROLE=api set before dns.cleanway.ai moved to its own service:
    the phones' DNS keeps working (slower, without the in-memory filter)."""
    role("api")
    for resp in _dns(_client(monkeypatch, fast_path), DNS):
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/dns-message"


def test_api_role_serves_the_api(monkeypatch, role):
    role("api")
    c = _client(monkeypatch)
    assert c.get("/", headers={"host": API}).status_code == 200
    health = c.get("/health", headers={"host": API})
    assert health.status_code == 200
    assert health.json()["service_role"] == "api"


def test_the_default_health_body_is_unchanged(monkeypatch, role):
    role("all")
    assert "service_role" not in _client(monkeypatch).get("/health").json()


# ── background work per role ──

def _boot(monkeypatch, value: str) -> list[str]:
    """Run api.main's lifespan once; return what it started, in order."""
    from api import main
    from api.services import doh_filter, doh_metrics, retention

    monkeypatch.setattr(get_settings(), "service_role", value)
    started: list[str] = []

    async def _warm():
        started.append("ml_warmup")

    def _stats_logger(*_a, **_k):
        started.append("doh_stats")
        return asyncio.sleep(3600)

    monkeypatch.setattr(main, "_warm_ml_model", _warm)
    monkeypatch.setattr(doh_filter.HOLDER, "start", lambda _every_s: started.append("blocklist_filter"))
    monkeypatch.setattr(doh_metrics, "stats_logger", _stats_logger)
    monkeypatch.setattr(retention, "start_background", lambda: started.append("retention"))

    async def _run():
        async with main.lifespan(main.app):
            pass

    asyncio.run(_run())
    return started


@pytest.mark.parametrize("value, expected", [
    ("all", ["ml_warmup", "blocklist_filter", "doh_stats", "retention"]),
    # The API needs the model and the retention purge, not the DNS filter. The
    # doh_stats line stays: its proxy_peers counts every request's client-IP
    # path (docs/runbooks/cloudflare-proxy.md).
    ("api", ["ml_warmup", "doh_stats", "retention"]),
    # DNS never scores a site and never deletes data.
    ("dns", ["blocklist_filter", "doh_stats"]),
])
def test_each_role_starts_only_its_own_background_work(monkeypatch, value, expected):
    assert _boot(monkeypatch, value) == expected


# ── startup validation ──

def _dns_prod(**overrides) -> Settings:
    values = dict(
        environment="production", debug=False, service_role="dns",
        sentry_dsn="https://abc@sentry.io/prod", trusted_proxy_cidrs="100.64.0.0/10",
        supabase_jwt_secret="", supabase_url="", supabase_service_key="", supabase_secret_key="",
        stripe_secret_key="", stripe_webhook_secret="", rate_limit_fail_closed=False,
    )
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_dns_role_boots_in_production_without_the_api_secrets():
    """The most exposed service should not hold the Supabase server key, the
    Stripe key or the webhook secrets: nothing on the DNS path reads them."""
    validate_settings(_dns_prod())


@pytest.mark.parametrize("field, message", [
    ("sentry_dsn", "Production requires SENTRY_DSN"),
    # The DNS budget is per client IP; without the trust list anyone could
    # pick their own IP in X-Forwarded-For.
    ("trusted_proxy_cidrs", "TRUSTED_PROXY_CIDRS"),
])
def test_dns_role_still_requires_what_the_dns_path_uses(field, message):
    with pytest.raises(ConfigError, match=message):
        validate_settings(_dns_prod(**{field: ""}))


def test_dns_role_refuses_debug_in_production():
    with pytest.raises(ConfigError, match="debug=True is not allowed"):
        validate_settings(_dns_prod(debug=True))


@pytest.mark.parametrize("value", ["api", "all"])
def test_the_api_roles_are_validated_as_before(value):
    with pytest.raises(ConfigError, match="SUPABASE_JWT_SECRET is required"):
        validate_settings(_dns_prod(service_role=value))


# ── Sentry: which service an error came from ──

@pytest.mark.parametrize("environ, tags", [
    ({}, {"role": "api"}),
    ({"SERVICE_ROLE": "all"}, {"role": "api"}),
    ({"SERVICE_ROLE": " DNS "}, {"role": "api", "service_role": "dns"}),
    ({"SERVICE_ROLE": "api"}, {"role": "api", "service_role": "api"}),
    ({"SERVICE_ROLE": "nonsense"}, {"role": "api"}),
])
def test_sentry_events_name_the_service_role_when_there_is_one(environ, tags):
    from api.services.sentry_setup import sentry_tags

    assert sentry_tags(environ) == tags

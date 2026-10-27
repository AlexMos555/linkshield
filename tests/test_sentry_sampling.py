"""Which requests the API's Sentry client traces (api/services/sentry_sampling.py).

Sentry wraps every request, /dns-query included, and sampled 10 % of them:
an iOS DNS profile (~3 000 queries a day, docs/runbooks/capacity.md) would
have sent ~9 000 transactions a month per phone. DNS and the health probes
are never traced now; everything else keeps the rate it had.
"""
from __future__ import annotations

import pytest

from api.services.sentry_sampling import TRACES_SAMPLE_RATE, UNTRACED_PATHS, traces_sampler

DSN = "https://public@o0.ingest.sentry.io/0"


def _ctx(path: str, method: str = "GET", host: str = "api.cleanway.ai", parent_sampled=None) -> dict:
    """The sampling context sentry-sdk 2.x's ASGI middleware passes."""
    return {
        "transaction_context": {"name": path, "op": "http.server"},
        "parent_sampled": parent_sampled,
        "asgi_scope": {"type": "http", "method": method, "path": path,
                       "headers": [(b"host", host.encode())]},
    }


@pytest.fixture
def client_options(monkeypatch):
    """The options of the client the sampler runs under: what
    sentry_init_options starts in production, whatever client another test
    left behind."""
    from types import SimpleNamespace

    import sentry_sdk

    options = {"traces_sample_rate": TRACES_SAMPLE_RATE}
    monkeypatch.setattr(sentry_sdk, "get_client", lambda: SimpleNamespace(options=options))
    return options


# ── unit: the sampler ───────────────────────────────────────────────

@pytest.mark.parametrize("host", ["api.cleanway.ai", "dns.cleanway.ai", "cleanway-dns.up.railway.app"])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_dns_queries_are_never_traced(host, method):
    assert traces_sampler(_ctx("/dns-query", method=method, host=host)) == 0


@pytest.mark.parametrize("path", ["/health", "/health/doh", "/health/deep"])
def test_health_probes_are_never_traced(path):
    assert traces_sampler(_ctx(path)) == 0


@pytest.mark.parametrize("path", ["/dns-query", "/health", "/health/doh", "/health/deep"])
def test_a_sampled_trace_header_cannot_force_a_trace_of_them(path):
    """`sentry-trace: <trace>-<span>-1` from any client made sentry-sdk keep
    the transaction whatever the rate; a DNS client must not be able to."""
    assert traces_sampler(_ctx(path, parent_sampled=True)) == 0


@pytest.mark.parametrize("path", ["/dns-query/", "/health/"])
def test_a_trailing_slash_changes_nothing(path):
    assert traces_sampler(_ctx(path)) == 0


@pytest.mark.parametrize("path", [
    "/", "/api/v1/check", "/api/v1/public/check/{domain}", "/api/v1/pricing",
    "/health/deeper", "/dns-query-stats", "/api/v1/dns-query",
])
def test_everything_else_keeps_the_rate(client_options, path):
    assert traces_sampler(_ctx(path)) == TRACES_SAMPLE_RATE == 0.1


@pytest.mark.parametrize("parent", [True, False])
def test_everything_else_still_follows_an_incoming_trace(parent):
    """What sentry-sdk does without a sampler: the landing's server-side
    fetches carry its decision, and their traces stay whole."""
    assert traces_sampler(_ctx("/api/v1/public/check/{domain}", parent_sampled=parent)) is parent


def test_without_an_asgi_scope_the_transaction_name_decides(client_options):
    assert traces_sampler({"transaction_context": {"name": "/dns-query"}, "parent_sampled": None}) == 0
    assert traces_sampler({"transaction_context": {"name": "http://dns.cleanway.ai/dns-query"},
                           "parent_sampled": None}) == 0
    assert traces_sampler({"transaction_context": {"name": "/api/v1/check"},
                           "parent_sampled": None}) == TRACES_SAMPLE_RATE
    assert traces_sampler({}) == TRACES_SAMPLE_RATE


def test_the_untraced_paths_cover_every_dns_host_path():
    """dns.cleanway.ai answers only these (request_guards.DNS_HOST_PATHS):
    nothing it serves may ever be traced."""
    from api.services.request_guards import DNS_HOST_PATHS

    assert DNS_HOST_PATHS <= UNTRACED_PATHS


def test_the_rest_uses_the_rate_the_client_was_started_with(client_options):
    """No env setting for the rate exists (api/config.py, and sentry-sdk 2.x
    reads none): `traces_sample_rate` in sentry_sdk.init stays the one knob,
    so a test or a later setting that changes it changes the rest's rate."""
    client_options["traces_sample_rate"] = 0.25
    assert traces_sampler(_ctx("/api/v1/check")) == 0.25
    assert traces_sampler(_ctx("/dns-query")) == 0
    client_options.pop("traces_sample_rate")  # a client without one
    assert traces_sampler(_ctx("/api/v1/check")) == TRACES_SAMPLE_RATE


def test_init_options_wire_the_sampler_and_keep_the_rate():
    from api.services.sentry_scrubber import sentry_init_options

    opts = sentry_init_options(DSN, debug=False)
    assert opts["traces_sampler"] is traces_sampler
    assert opts["traces_sample_rate"] == TRACES_SAMPLE_RATE


def test_init_sentry_passes_the_sampler(monkeypatch):
    from types import SimpleNamespace

    import sentry_sdk

    from api.services import sentry_setup

    inits = []
    monkeypatch.setattr(sentry_sdk, "init", lambda **kw: inits.append(kw))
    monkeypatch.setattr(sentry_sdk, "get_global_scope", lambda: SimpleNamespace(set_tag=lambda k, v: None))
    settings = SimpleNamespace(sentry_dsn=DSN, debug=False, environment="production")
    assert sentry_setup.init_sentry(settings) is True
    assert inits[0]["traces_sampler"] is traces_sampler


# ── ASGI: the real app under the real SDK ───────────────────────────

@pytest.mark.parametrize("fast_path", [True, False], ids=["fast-path", "fastapi-routes"])
def test_the_real_app_starts_no_transaction_for_dns_or_health(monkeypatch, fast_path):
    """sentry-sdk's Starlette integration wraps the whole app — outside the
    DoH fast path, the DNS routing and load shedding — so before the sampler
    every DNS query became a transaction candidate. With the rest at 100 %
    here, only the control request may reach the transport."""
    import sentry_sdk
    from fastapi.testclient import TestClient
    from sentry_sdk.transport import Transport

    import api.routers.doh as doh_router
    from api import config
    from api.main import app
    from api.services.sentry_scrubber import sentry_init_options
    from tests.doh_helpers import ArtifactRedis, answer, b64url, query, use_redis

    monkeypatch.setattr(config.get_settings(), "doh_fast_path", fast_path)
    use_redis(monkeypatch, ArtifactRedis({"phish.example"}))

    async def _up(wire):
        return answer(wire)

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)

    sent: list[dict] = []

    class _Capture(Transport):
        def capture_envelope(self, envelope):
            for item in envelope.items:
                if item.type == "transaction":
                    sent.append(item.payload.json)

    sentry_sdk.init(**{**sentry_init_options(DSN, debug=True), "traces_sample_rate": 1.0,
                       "transport": _Capture()})
    try:
        client = TestClient(app)
        wire = query("example.org")
        dns_ct = {"content-type": "application/dns-message"}
        # A client-sent sampled trace header must not force a DNS trace either.
        forced = {"sentry-trace": "771a43a4192642f0b136d5159a501700-b2f4d4e8c1a3f5e7-1"}
        statuses = []
        for host in ("api.cleanway.ai", "dns.cleanway.ai"):
            statuses += [
                client.get("/dns-query", params={"dns": b64url(wire)}, headers={"host": host}).status_code,
                client.post("/dns-query", content=wire, headers={"host": host, **dns_ct}).status_code,
                client.post("/dns-query", content=wire, headers={"host": host, **dns_ct, **forced}).status_code,
            ]
            statuses += [client.get(p, headers={"host": host}).status_code for p in ("/health", "/health/doh")]
        control = client.get("/", headers={"host": "api.cleanway.ai"}).status_code
        sentry_sdk.flush()
    finally:
        sentry_sdk.get_client().close()
        sentry_sdk.get_global_scope().set_client(None)

    assert statuses == [200, 200, 200, 200, 200] * 2  # every request was really answered
    assert control == 200
    assert [t["transaction"] for t in sent] == ["/"]  # the integration ran; DNS and health did not trace

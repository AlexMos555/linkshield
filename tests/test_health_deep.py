"""Tests for /health/deep — the hard healthcheck used by external monitors.

Critical that this endpoint:
  1. Returns 200 only when EVERY downstream is up
  2. Returns 503 when ANY downstream is down
  3. Names the failed component in the body (so on-call sees what to fix
     without ssh'ing into Railway)

Strategy: we mock httpx.AsyncClient + the Redis fake so the test doesn't
need the network. This mirrors how tests/test_payments_webhook.py handles
the same problem.
"""
from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def configured_settings(monkeypatch):
    """Pretend Supabase env is filled in so the deep check tries to probe."""
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_anon_key", "fake_anon_key", raising=False)
    return s


class _FakeRedis:
    """Just enough to satisfy the deep health check."""

    def __init__(self, fail: bool = False):
        self.fail = fail

    async def ping(self):
        if self.fail:
            raise ConnectionError("redis down")
        return True


def _patch_redis(monkeypatch, fail: bool = False):
    fake = _FakeRedis(fail=fail)

    async def _get_redis():
        return fake

    # main.py imports get_redis at module scope, so we have to patch the
    # *consumer's* reference. Patching api.services.cache.get_redis would
    # leave main.py's bound name pointing at the original.
    monkeypatch.setattr("api.main.get_redis", _get_redis)
    return fake


def _patch_httpx(monkeypatch, status_code: int = 200, raises: Exception | None = None):
    """Stub httpx.AsyncClient so the supabase check returns a fixed shape."""
    import httpx as _httpx

    class _Resp:
        def __init__(self, code: int):
            self.status_code = code

    class _Client:
        def __init__(self, *_a, **_k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return None

        async def get(self, url: str, headers: dict[str, Any] | None = None, **_kw):
            if raises:
                raise raises
            return _Resp(status_code)

    monkeypatch.setattr(_httpx, "AsyncClient", _Client)


@pytest.fixture
def client():
    from api.main import app
    return TestClient(app)


# ─── Happy path ──────────────────────────────────────────────────


def test_deep_healthy_returns_200(client, configured_settings, monkeypatch):
    _patch_redis(monkeypatch, fail=False)
    _patch_httpx(monkeypatch, status_code=200)

    resp = client.get("/health/deep")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["components"]["redis"] == {"ok": True}
    assert body["components"]["supabase"]["ok"] is True


def test_deep_supabase_401_still_counts_as_up(client, configured_settings, monkeypatch):
    """A 401 from Supabase means it's reachable + rejecting auth — that's a
    successful CONNECTIVITY probe even if the credentials are bad. We test
    here that this is treated as healthy (i.e. the deep check does NOT page
    on-call when Supabase is up and the anon key happens to be expired)."""
    _patch_redis(monkeypatch, fail=False)
    _patch_httpx(monkeypatch, status_code=401)

    resp = client.get("/health/deep")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["components"]["supabase"]["ok"] is True
    assert body["components"]["supabase"]["status"] == 401


# ─── Failure paths ──────────────────────────────────────────────


def test_deep_redis_down_returns_503(client, configured_settings, monkeypatch):
    _patch_redis(monkeypatch, fail=True)
    _patch_httpx(monkeypatch, status_code=200)

    resp = client.get("/health/deep")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["components"]["redis"]["ok"] is False
    assert body["components"]["redis"]["error"] == "ConnectionError"
    # supabase is still up — make sure deep check pinpoints which one broke
    assert body["components"]["supabase"]["ok"] is True


def test_deep_supabase_500_returns_503(client, configured_settings, monkeypatch):
    _patch_redis(monkeypatch, fail=False)
    _patch_httpx(monkeypatch, status_code=500)

    resp = client.get("/health/deep")
    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["components"]["supabase"]["ok"] is False
    assert body["components"]["supabase"]["status"] == 500
    # redis still up
    assert body["components"]["redis"]["ok"] is True


def test_deep_supabase_network_error_returns_503(client, configured_settings, monkeypatch):
    """If Supabase doesn't even respond (DNS, connection refused, timeout),
    we want the same 503 with error name in the body."""
    _patch_redis(monkeypatch, fail=False)
    _patch_httpx(monkeypatch, raises=ConnectionError("no route to host"))

    resp = client.get("/health/deep")
    assert resp.status_code == 503
    body = resp.json()
    assert body["components"]["supabase"]["ok"] is False
    assert body["components"]["supabase"]["error"] == "ConnectionError"


def test_deep_supabase_not_configured_returns_503(client, monkeypatch):
    """If env is empty (e.g. someone wiped Railway vars), we must page —
    not silently treat as healthy."""
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "", raising=False)
    monkeypatch.setattr(s, "supabase_anon_key", "", raising=False)
    _patch_redis(monkeypatch, fail=False)

    resp = client.get("/health/deep")
    assert resp.status_code == 503
    body = resp.json()
    assert body["components"]["supabase"]["ok"] is False
    assert body["components"]["supabase"]["error"] == "not_configured"


def test_deep_both_down_returns_503(client, configured_settings, monkeypatch):
    _patch_redis(monkeypatch, fail=True)
    _patch_httpx(monkeypatch, raises=ConnectionError("redis went too"))

    resp = client.get("/health/deep")
    assert resp.status_code == 503
    body = resp.json()
    # Both should be flagged ok=False — the JSON body is meant to give a
    # complete picture, not just the first failure encountered.
    assert body["components"]["redis"]["ok"] is False
    assert body["components"]["supabase"]["ok"] is False


# ─── Existing /health is still soft ─────────────────────────────


def test_soft_health_still_returns_200_when_redis_down(client, monkeypatch):
    """Make sure I didn't accidentally break the existing /health endpoint
    while adding /health/deep — it must stay soft (200 even on degradation)
    so Railway doesn't cycle pods on a transient Redis blip."""
    _patch_redis(monkeypatch, fail=True)

    resp = client.get("/health")
    # Soft endpoint never 503's — Railway healthcheck stays green.
    assert resp.status_code == 200
    body = resp.json()
    assert body["redis"] == "down"
    # Status field is informational — "degraded" is a soft signal.
    assert body["status"] in ("ok", "degraded")


# ── ML visibility (fail-soft: reported, never pages) ──────────────────────


def test_deep_reports_the_ml_backend(client, configured_settings, monkeypatch):
    """Without this, a container that silently shipped no model looked healthy
    and identical to one that did."""
    _patch_redis(monkeypatch, fail=False)
    _patch_httpx(monkeypatch, status_code=200)
    monkeypatch.setattr("api.services.ml_scorer.model_status",
                        lambda: {"loaded": True, "backend": "onnx", "model_file": True})
    resp = client.get("/health/deep")
    assert resp.status_code == 200
    assert resp.json()["components"]["ml"] == {"loaded": True, "backend": "onnx", "model_file": True}


def test_a_dead_ml_model_does_not_page(client, configured_settings, monkeypatch):
    """Scoring fail-softs without the model, so a failed load must not 503."""
    _patch_redis(monkeypatch, fail=False)
    _patch_httpx(monkeypatch, status_code=200)
    monkeypatch.setattr("api.services.ml_scorer.model_status",
                        lambda: {"loaded": False, "backend": None, "model_file": False})
    resp = client.get("/health/deep")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["components"]["ml"]["loaded"] is False


# ── Grandma's protection: blocklist + DoH (visible, never paging) ─────────

import base64 as _b64  # noqa: E402
import time as _time  # noqa: E402

from api.services import health_probes  # noqa: E402
from api.services.blocklist_artifact import (  # noqa: E402
    LIST_CANARY,
    MAX_HEALTHY_AGE_S,
    REDIS_META_KEY,
    REDIS_TEXT_KEY,
    meta_for_v2,
    render_artifact_v2,
)


class _ProtectionRedis(_FakeRedis):
    """Serves one published artifact and a `dangerous_domains` set — the two
    things the new components read."""

    def __init__(self, age_s: int = 3600, names=("phish.example",), gateway_set=(LIST_CANARY,)):
        super().__init__()
        blob = render_artifact_v2(list(names), generated=int(_time.time()) - age_s)
        self.meta = meta_for_v2(blob)
        self.text = _b64.b64encode(blob).decode("ascii")
        self.gateway_set = set(gateway_set)

    async def hgetall(self, key):
        return dict(self.meta) if key == REDIS_META_KEY else {}

    async def get(self, key):
        return self.text if key == REDIS_TEXT_KEY else None

    def pipeline(self):
        outer = self

        class _Pipe:
            def __init__(self):
                self.asked = []

            def sismember(self, _key, member):
                self.asked.append(member)
                return self

            async def execute(self):
                return [m in outer.gateway_set for m in self.asked]

        return _Pipe()


def _serve(monkeypatch, fake):
    async def _get_redis():
        return fake

    monkeypatch.setattr("api.main.get_redis", _get_redis)
    monkeypatch.setattr("api.services.cache.get_redis", _get_redis)

    async def _never(_wire):
        raise AssertionError("the health probe must never call the real upstream")

    monkeypatch.setattr("api.routers.doh.proxy_to_upstream", _never)


def test_deep_reports_a_fresh_blocklist_and_a_blocking_gateway(client, configured_settings, monkeypatch):
    _serve(monkeypatch, _ProtectionRedis(age_s=3600))
    _patch_httpx(monkeypatch, status_code=200)
    resp = client.get("/health/deep")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["warnings"] == []
    bl = body["components"]["blocklist"]
    assert bl["ok"] is True
    assert bl["count"] == 2  # phish.example + the list canary
    assert 3500 <= bl["age_s"] <= 3700
    assert bl["max_age_s"] == MAX_HEALTHY_AGE_S
    doh = body["components"]["doh"]
    assert (doh["ok"], doh["rcode"], doh["probe"]) == (True, 3, LIST_CANARY)


def test_the_probe_does_not_log_a_block_a_real_query_does(client, configured_settings, monkeypatch, caplog):
    """The probe's canary block is ours, not a user's: with a monitor polling
    /health/deep it would add hundreds of "DoH blocked qname" lines a day,
    indistinguishable from real blocks."""
    import asyncio
    import logging

    from api.routers.doh import handle_query
    from api.services.health_probes import _canary_query

    _serve(monkeypatch, _ProtectionRedis(age_s=3600))
    _patch_httpx(monkeypatch, status_code=200)
    with caplog.at_level(logging.INFO, logger="api.routers.doh"):
        assert client.get("/health/deep").json()["components"]["doh"]["ok"] is True
    assert not [r for r in caplog.records if r.getMessage() == "DoH blocked qname"]

    with caplog.at_level(logging.INFO, logger="api.routers.doh"):
        _body, status = asyncio.run(handle_query(_canary_query()))
    assert status == 200
    assert [r.getMessage() for r in caplog.records].count("DoH blocked qname") == 1


def test_a_stale_blocklist_is_a_warning_not_a_page(client, configured_settings, monkeypatch):
    """The cron died: phones keep an ageing list. Visible and alertable, but
    Redis and Supabase are fine, so no 503."""
    _serve(monkeypatch, _ProtectionRedis(age_s=MAX_HEALTHY_AGE_S + 600))
    _patch_httpx(monkeypatch, status_code=200)
    resp = client.get("/health/deep")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["warnings"] == ["blocklist"]
    assert body["components"]["blocklist"]["ok"] is False
    assert body["components"]["blocklist"]["error"] == "stale"


def test_a_gateway_that_stopped_filtering_is_a_warning_not_a_page(client, configured_settings, monkeypatch):
    """`dangerous_domains` expired (or lost the canary): the DNS profile blocks
    nothing. The in-process probe sees SERVFAIL from its stub upstream."""
    _serve(monkeypatch, _ProtectionRedis(gateway_set=()))
    _patch_httpx(monkeypatch, status_code=200)
    resp = client.get("/health/deep")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["warnings"] == ["doh"]
    doh = body["components"]["doh"]
    assert doh["ok"] is False
    assert doh["error"] == "listed_name_not_blocked"
    assert doh["rcode"] == 2


def test_no_published_blocklist_is_reported(client, configured_settings, monkeypatch):
    _patch_redis(monkeypatch, fail=False)  # answers PING, holds nothing
    _patch_httpx(monkeypatch, status_code=200)
    resp = client.get("/health/deep")
    assert resp.status_code == 200
    body = resp.json()
    assert body["components"]["blocklist"]["ok"] is False
    assert set(body["warnings"]) == {"blocklist", "doh"}


def test_redis_down_pages_and_still_names_the_protection_checks(client, configured_settings, monkeypatch):
    _patch_redis(monkeypatch, fail=True)
    _patch_httpx(monkeypatch, status_code=200)
    resp = client.get("/health/deep")
    assert resp.status_code == 503
    body = resp.json()
    assert body["components"]["blocklist"]["ok"] is False
    assert body["components"]["doh"]["ok"] is False


@pytest.mark.parametrize(
    "meta,error",
    [
        (None, "unavailable"),
        ({"generated_at": "x", "count": "5"}, "bad_meta"),
        ({"generated_at": "1000", "count": "1", "version": "1000"}, "empty"),   # the canary alone
        ({"generated_at": "1000", "count": "0", "version": "1000"}, "empty"),   # revoked
    ],
)
def test_blocklist_verdict_failures(meta, error):
    out = health_probes.blocklist_verdict(meta, now=2000)
    assert out["ok"] is False
    assert out["error"] == error


def test_blocklist_verdict_threshold_is_the_canarys():
    fresh = {"generated_at": "0", "count": "428612", "version": "0"}
    assert health_probes.blocklist_verdict(fresh, now=MAX_HEALTHY_AGE_S)["ok"] is True
    assert health_probes.blocklist_verdict(fresh, now=MAX_HEALTHY_AGE_S + 1)["error"] == "stale"


def test_the_canary_and_the_health_check_share_one_freshness_threshold():
    import importlib
    import sys
    from pathlib import Path

    scripts = str(Path(__file__).resolve().parents[1] / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    canary = importlib.import_module("dns_canary")
    assert canary.MAX_ARTIFACT_AGE_S == MAX_HEALTHY_AGE_S


@pytest.mark.asyncio
async def test_a_hung_probe_is_cut_off(monkeypatch):
    import asyncio

    monkeypatch.setattr(health_probes, "PROBE_TIMEOUT_S", 0.05)

    async def _hang():
        await asyncio.sleep(5)
        return {"ok": True}

    assert await health_probes._bounded(_hang) == {"ok": False, "error": "timeout"}


@pytest.mark.asyncio
async def test_a_crashing_probe_reports_instead_of_raising():
    async def _boom():
        raise KeyError("sha256")

    assert await health_probes._bounded(_boom) == {"ok": False, "error": "KeyError"}

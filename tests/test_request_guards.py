"""Request guards in front of every route (audit 2026-10-14).

  * a request body is capped before anything parses it — 1 MiB by default,
    more only where a route needs it (the voice upload, the email body);
  * /scam/analyze_voice checks the caller before it parses the multipart
    upload (FastAPI parses declared File/Form parameters BEFORE running
    dependencies, so anyone could make us spool 25 MB);
  * dns.cleanway.ai — the DoH name every DNS-profile phone points at — is
    the same Railway service as the API; it now serves the DNS paths only.
"""
from __future__ import annotations

import asyncio
import io

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier
from api.services import request_guards as rg


@pytest.fixture
def client():
    from api.main import app
    return TestClient(app)


# ── Body size ──

def test_limits_by_route():
    assert rg.body_limit_for("/api/v1/explain") == rg.DEFAULT_BODY_LIMIT == 1024 * 1024
    assert rg.body_limit_for("/api/v1/scam/analyze_voice") > 25 * 1024 * 1024
    assert rg.body_limit_for("/api/v1/email/analyze") > rg.DEFAULT_BODY_LIMIT


@pytest.mark.parametrize("shedding", [True, False], ids=["load-shedding", "guard-alone"])
def test_declared_oversize_body_is_refused_unread(client, monkeypatch, shedding):
    """With load shedding on, LoadShedding (outermost) refuses it before it
    reads the body for a slot; switched off, BodySizeLimit still does."""
    from api.config import get_settings

    monkeypatch.setattr(get_settings(), "load_shed_enabled", shedding)
    called = []
    import api.routers.explainer as explainer

    async def _explain(*a, **k):
        called.append(1)
        return {"category": "x", "locale": "en", "explanation": "x", "source": "template"}

    monkeypatch.setattr(explainer, "explain_scam", _explain)
    body = b'{"signals": ["' + b"a" * (rg.DEFAULT_BODY_LIMIT + 10) + b'"], "locale": "en"}'
    resp = client.post("/api/v1/explain", content=body, headers={"content-type": "application/json"})
    assert resp.status_code == 413
    assert called == []


def test_streamed_oversize_body_without_length_is_refused(client):
    def _chunks():
        for _ in range(20):
            yield b"x" * (128 * 1024)

    resp = client.post("/api/v1/explain", content=_chunks(), headers={"content-type": "application/json"})
    assert resp.status_code == 413


def test_small_bodies_pass(client, monkeypatch):
    async def _down():
        raise RuntimeError("no redis")
    monkeypatch.setattr("api.services.cache.get_redis", _down)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    resp = client.post("/api/v1/explain", json={"signals": ["phishtank"], "locale": "en"})
    assert resp.status_code == 200


def test_middleware_stops_a_stream_midway():
    """Pure ASGI: the app reading past the limit gets 413, never the bytes."""
    seen = []

    async def app(scope, receive, send):
        while True:
            msg = await receive()
            seen.append(len(msg.get("body", b"")))
            if not msg.get("more_body"):
                break
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    guarded = rg.BodySizeLimit(app, default_limit=10)
    chunks = [{"type": "http.request", "body": b"12345678", "more_body": True},
              {"type": "http.request", "body": b"12345678", "more_body": True},
              {"type": "http.request", "body": b"1", "more_body": False}]
    sent = []

    async def receive():
        return chunks.pop(0)

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "path": "/x", "method": "POST", "headers": []}
    asyncio.run(guarded(scope, receive, send))
    assert sent[0]["status"] == 413
    assert sum(seen) == 8  # the chunk that crossed the cap never reached the app
    assert len(sent) == 2  # the 413, and nothing of the app's own answer


def test_middleware_refuses_a_declared_oversize_body_before_the_app():
    """Pure ASGI: BodySizeLimit alone, without a byte read."""
    called = []

    async def app(scope, receive, send):  # pragma: no cover — never reached
        called.append(1)

    guarded = rg.BodySizeLimit(app, default_limit=10)
    sent = []

    async def receive():  # pragma: no cover — nothing is read
        raise AssertionError("the body is never read")

    async def send(msg):
        sent.append(msg)

    scope = {"type": "http", "path": "/x", "method": "POST", "headers": [(b"content-length", b"11")]}
    asyncio.run(guarded(scope, receive, send))
    assert sent[0]["status"] == 413 and called == []


# ── Voice upload: who first, then the body ──

def test_voice_upload_checks_auth_before_parsing(client, monkeypatch):
    from starlette.requests import Request

    parsed = []
    real_form = Request.form

    def _form(self, *a, **k):
        parsed.append(1)
        return real_form(self, *a, **k)

    monkeypatch.setattr(Request, "form", _form)
    resp = client.post(
        "/api/v1/scam/analyze_voice",
        files={"file": ("clip.mp3", io.BytesIO(b"ID3" + b"\0" * 4096), "audio/mpeg")},
    )
    assert resp.status_code == 401
    assert parsed == []


@pytest.fixture
def authed(monkeypatch):
    from api.config import get_settings
    from api.main import app
    from api.services.auth import get_current_user, get_current_user_including_deleted

    async def _user():
        return AuthUser(id="11111111-1111-1111-1111-111111111111", email="u@t.test", tier=UserTier.free)

    app.dependency_overrides[get_current_user] = _user
    app.dependency_overrides[get_current_user_including_deleted] = _user
    monkeypatch.setattr(get_settings(), "supabase_url", "", raising=False)
    yield TestClient(app)
    app.dependency_overrides.clear()


def test_voice_upload_over_the_default_limit_is_accepted(authed):
    audio = io.BytesIO(b"ID3" + b"\0" * (2 * 1024 * 1024))
    resp = authed.post("/api/v1/scam/analyze_voice", files={"file": ("clip.mp3", audio, "audio/mpeg")},
                       data={"language": "en"})
    assert resp.status_code == 200, resp.text
    assert resp.json()["language"] == "en"


def test_voice_upload_without_a_file_is_422(authed):
    resp = authed.post("/api/v1/scam/analyze_voice", data={"language": "en"})
    assert resp.status_code == 422


def test_voice_upload_over_its_limit_is_413_unread(authed):
    resp = authed.post(
        "/api/v1/scam/analyze_voice",
        content=b"x" * 16,
        headers={"content-type": "multipart/form-data; boundary=b",
                 "content-length": str(rg.body_limit_for("/api/v1/scam/analyze_voice") + 1)},
    )
    assert resp.status_code == 413


# ── dns.cleanway.ai serves DNS only ──

@pytest.mark.parametrize("host", ["dns.cleanway.ai", "DNS.Cleanway.AI:443", "dns.cleanway.ai."])
@pytest.mark.parametrize("path", [
    "/api/v1/public/check/google.com", "/", "/docs", "/openapi.json", "/api/v1/pricing",
    "/health/deep", "/dns-query/../api/v1/pricing",
])
def test_dns_host_hides_the_api(client, host, path):
    resp = client.get(path, headers={"host": host})
    assert resp.status_code == 404


@pytest.mark.parametrize("path", ["/health", "/health/doh"])
def test_dns_host_keeps_its_health_probes(client, path):
    resp = client.get(path, headers={"host": "dns.cleanway.ai"})
    assert resp.status_code in (200, 503)


@pytest.mark.parametrize("fast_path", [True, False], ids=["fast-path", "fastapi-routes"])
def test_dns_host_still_answers_dns(monkeypatch, fast_path):
    from api import config
    from api.main import app
    import api.routers.doh as doh_router
    from tests.doh_helpers import ArtifactRedis, answer, b64url, query, use_redis

    monkeypatch.setattr(config.get_settings(), "doh_fast_path", fast_path)
    use_redis(monkeypatch, ArtifactRedis({"phish.example"}))

    async def _up(wire):
        return answer(wire)

    monkeypatch.setattr(doh_router, "proxy_to_upstream", _up)
    c = TestClient(app)
    wire = query("example.org")
    for resp in (
        c.get("/dns-query", params={"dns": b64url(wire)}, headers={"host": "dns.cleanway.ai"}),
        c.post("/dns-query", content=wire,
               headers={"host": "dns.cleanway.ai", "content-type": "application/dns-message"}),
    ):
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/dns-message"


def test_api_host_is_unchanged(client):
    resp = client.get("/", headers={"host": "api.cleanway.ai"})
    assert resp.status_code == 200


# ── /health tells monitors what they need, not which sources we pay for ──

def test_health_reports_status_version_redis_and_blocklist_only(client, monkeypatch):
    async def _down():
        raise ConnectionError("no redis")
    monkeypatch.setattr("api.main.get_redis", _down)
    resp = client.get("/health")
    assert set(resp.json()) == {"status", "version", "redis", "blocklist_version", "blocklist_age_s"}
    for source in ("ipqs", "safe_browsing", "alienvault", "breaker"):
        assert source not in resp.text


def test_health_is_degraded_while_a_breaker_is_open(client, monkeypatch):
    from api.services import circuit_breaker

    monkeypatch.setattr(circuit_breaker, "get_all_breaker_statuses", lambda: [{"name": "x", "state": "open"}])

    class _R:
        async def ping(self):
            return True

    async def _ok():
        return _R()
    monkeypatch.setattr("api.main.get_redis", _ok)
    assert client.get("/health").json()["status"] == "degraded"

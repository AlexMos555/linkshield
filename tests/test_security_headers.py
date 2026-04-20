"""Verify SecurityHeadersMiddleware adds correct hardening headers."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    from api.main import app
    return TestClient(app)


def test_hsts_header_set(client):
    resp = client.get("/health")
    hsts = resp.headers.get("Strict-Transport-Security", "")
    assert "max-age=" in hsts
    assert "includeSubDomains" in hsts
    # max-age must be at least 1 year (31536000) for hstspreload eligibility
    parts = dict(p.strip().split("=", 1) for p in hsts.split(";") if "=" in p)
    assert int(parts["max-age"]) >= 31_536_000


def test_x_content_type_options_nosniff(client):
    resp = client.get("/health")
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"


def test_x_frame_options_deny(client):
    resp = client.get("/health")
    assert resp.headers.get("X-Frame-Options") == "DENY"


def test_referrer_policy(client):
    resp = client.get("/health")
    assert resp.headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"


def test_permissions_policy_denies_dangerous_apis(client):
    resp = client.get("/health")
    pp = resp.headers.get("Permissions-Policy", "")
    # All dangerous APIs must be explicitly denied (=())
    for api in ("camera", "microphone", "geolocation", "payment", "usb"):
        assert f"{api}=()" in pp, f"Permissions-Policy must deny '{api}'"


def test_csp_strict_for_api_routes(client):
    """Plain API responses get strict CSP — no scripts, no inline."""
    resp = client.get("/health")
    csp = resp.headers.get("Content-Security-Policy", "")
    assert "default-src 'none'" in csp
    assert "frame-ancestors 'none'" in csp
    assert "base-uri 'none'" in csp
    # API routes should NOT allow CDN scripts
    assert "jsdelivr" not in csp


def test_csp_loose_for_docs(client):
    """Swagger UI route gets relaxed CSP allowing CDN assets."""
    resp = client.get("/docs")
    if resp.status_code == 404:
        pytest.skip("Docs disabled in this build")
    csp = resp.headers.get("Content-Security-Policy", "")
    # Docs CSP needs the CDN
    assert "cdn.jsdelivr.net" in csp
    assert "frame-ancestors 'none'" in csp


def test_cross_origin_resource_policy(client):
    resp = client.get("/health")
    assert resp.headers.get("Cross-Origin-Resource-Policy") == "cross-origin"


def test_no_server_header_leak(client):
    """We must not leak `server: uvicorn` — info disclosure."""
    resp = client.get("/health")
    server = resp.headers.get("server", "").lower()
    assert "uvicorn" not in server
    assert "python" not in server


def test_error_responses_have_no_store_cache_control(client):
    """4xx/5xx responses must not be cached (defense vs cache poisoning)."""
    resp = client.get("/this-route-does-not-exist")
    assert resp.status_code == 404
    assert "no-store" in resp.headers.get("Cache-Control", "").lower()


def test_security_headers_on_post_routes(client):
    """Headers apply to POST too, not just GET."""
    resp = client.post("/api/v1/check", json={})
    assert resp.headers.get("X-Content-Type-Options") == "nosniff"
    assert resp.headers.get("X-Frame-Options") == "DENY"
    assert "Strict-Transport-Security" in resp.headers

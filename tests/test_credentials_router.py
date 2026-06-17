"""Credential-guardian verified-host allowlist router contract tests."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient


def _client():
    from api.main import app
    return TestClient(app)


# ── Strategy #8 — Honeypot report endpoint ──

@pytest.fixture
def mock_redis(monkeypatch):
    fake = AsyncMock()
    fake.incr = AsyncMock(return_value=1)
    fake.expire = AsyncMock(return_value=True)

    async def _get():
        return fake

    import api.services.cache as cache
    monkeypatch.setattr(cache, "get_redis", _get)
    return fake


def test_honeypot_report_returns_ok(mock_redis):
    """Happy path: valid domain → ok=True + day + quarter counters bumped."""
    resp = _client().post(
        "/api/v1/credentials/report-honeypot",
        json={"domain": "phisher.example"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"ok": True}
    # Day + quarter increments fire.
    assert mock_redis.incr.await_count == 2


def test_honeypot_report_silently_ignores_invalid_domain(mock_redis):
    """Invalid domain → ok=True (no signal to attacker probing
    validation) and NO redis increment."""
    resp = _client().post(
        "/api/v1/credentials/report-honeypot",
        json={"domain": "javascript:alert(1)"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}
    assert mock_redis.incr.await_count == 0


def test_honeypot_report_silently_ignores_missing_dot(mock_redis):
    """A bare label like 'localhost' has no TLD — drop it. Real
    domains must include at least one dot."""
    resp = _client().post(
        "/api/v1/credentials/report-honeypot",
        json={"domain": "localhost"},
    )
    assert resp.status_code == 200
    assert mock_redis.incr.await_count == 0


def test_honeypot_report_redis_outage_still_returns_ok(monkeypatch):
    """If Redis is down the endpoint MUST NOT break the user's
    submit flow. ok=True, no exception."""
    async def _broken():
        raise RuntimeError("redis is down")
    import api.services.cache as cache
    monkeypatch.setattr(cache, "get_redis", _broken)

    resp = _client().post(
        "/api/v1/credentials/report-honeypot",
        json={"domain": "phisher.example"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_honeypot_report_normalises_case_and_strips_whitespace(mock_redis):
    resp = _client().post(
        "/api/v1/credentials/report-honeypot",
        json={"domain": "  Phisher.EXAMPLE  "},
    )
    assert resp.status_code == 200
    # Counter bumped (validation passed after normalisation).
    assert mock_redis.incr.await_count == 2


def test_honeypot_report_rejects_overlong_domain(mock_redis):
    """RFC-1035 caps a full DNS name at 253 chars. Anything longer
    should be dropped silently."""
    long_domain = ("a" * 250) + ".com"  # 254 chars total
    resp = _client().post(
        "/api/v1/credentials/report-honeypot",
        json={"domain": long_domain},
    )
    assert resp.status_code == 200
    assert mock_redis.incr.await_count == 0


def test_honeypot_report_missing_body_field():
    """Pydantic should 422 when `domain` is missing — that's a
    contract failure, not an attacker probe."""
    resp = _client().post(
        "/api/v1/credentials/report-honeypot",
        json={},
    )
    assert resp.status_code == 422


def test_known_brand_returns_hosts():
    """A brand we curate (paypal) returns is_known=True + non-empty hosts."""
    resp = _client().get("/api/v1/credentials/verified", params={"brand": "paypal"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["brand"] == "paypal"
    assert body["is_known"] is True
    assert "paypal.com" in body["hosts"]


def test_unknown_brand_returns_empty_not_404():
    """Unknown brand returns 200 + empty list — never 404. Avoid leaking
    "this brand IS in the allowlist" to enumerators."""
    resp = _client().get(
        "/api/v1/credentials/verified",
        params={"brand": "no_such_brand_anywhere"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["is_known"] is False
    assert body["hosts"] == []


def test_brand_is_lowercased():
    """Hand-curated allowlist keys are lowercase; the endpoint lowers
    the input so PayPal and PAYPAL both hit the paypal row."""
    resp1 = _client().get("/api/v1/credentials/verified", params={"brand": "PayPal"})
    resp2 = _client().get("/api/v1/credentials/verified", params={"brand": "PAYPAL"})
    assert resp1.json()["hosts"] == resp2.json()["hosts"]
    assert resp1.json()["is_known"] is True


def test_pattern_rejects_special_chars():
    """Brand identifier is a strict slug. URLs / dots / spaces are
    rejected at the request-validation layer (422)."""
    bad_inputs = ["paypal.com", "paypal!", "../paypal", "paypal account", ""]
    for bad in bad_inputs:
        resp = _client().get("/api/v1/credentials/verified", params={"brand": bad})
        # Either 422 (pattern reject) or 400 (empty after strip).
        assert resp.status_code in (400, 422), f"{bad!r} returned {resp.status_code}"


def test_response_shape_stable():
    """The extension depends on this exact shape — pin it."""
    resp = _client().get("/api/v1/credentials/verified", params={"brand": "apple"})
    body = resp.json()
    assert set(body.keys()) == {"brand", "hosts", "is_known"}
    assert isinstance(body["hosts"], list)
    assert all(isinstance(h, str) for h in body["hosts"])


def test_multiple_brands_distinct_hosts():
    """Different brands must NOT share hostnames. (Defensive — a
    sloppy edit of the allowlist could otherwise plant the same
    google.com inside multiple keys.)"""
    apple = _client().get("/api/v1/credentials/verified", params={"brand": "apple"}).json()
    google = _client().get("/api/v1/credentials/verified", params={"brand": "google"}).json()
    overlap = set(apple["hosts"]) & set(google["hosts"])
    assert overlap == set(), f"unexpected overlap: {overlap}"

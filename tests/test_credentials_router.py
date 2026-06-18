"""Credential-guardian verified-host allowlist router contract tests."""
from __future__ import annotations


from fastapi.testclient import TestClient


def _client():
    from api.main import app
    return TestClient(app)


# ── Strategy #8 — Honeypot endpoint removed per adversarial review ──
# The /report-honeypot POST was a fingerprint signal via the
# Performance Resource Timing API. The endpoint is GONE.

def test_honeypot_report_endpoint_does_not_exist():
    """Adversarial-review regression: the report-honeypot endpoint
    was removed. A 404 here proves the removal is honest and we
    haven't accidentally re-added it."""
    resp = _client().post(
        "/api/v1/credentials/report-honeypot",
        json={"domain": "phisher.example"},
    )
    assert resp.status_code == 404


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

"""Tests for signed-token unsubscribe flow."""
from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from api.routers import email_unsubscribe as eu


@pytest.fixture(scope="module")
def client() -> TestClient:
    from api.main import app
    return TestClient(app)


class TestTokenSigning:
    def test_mint_and_verify_roundtrip(self):
        token = eu.mint_token(user_id="user-123", email_template="welcome")
        payload = eu.verify_token(token)
        assert payload is not None
        assert payload["uid"] == "user-123"
        assert payload["template"] == "welcome"

    def test_verify_rejects_tampered_payload(self):
        token = eu.mint_token(user_id="user-123", email_template="welcome")
        payload_part, sig = token.split(".", 1)
        mutated = payload_part[:-1] + ("A" if payload_part[-1] != "A" else "B")
        assert eu.verify_token(f"{mutated}.{sig}") is None

    def test_verify_rejects_tampered_signature(self):
        token = eu.mint_token(user_id="user-123", email_template="welcome")
        payload_part, sig = token.split(".", 1)
        mutated_sig = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        assert eu.verify_token(f"{payload_part}.{mutated_sig}") is None

    def test_verify_rejects_garbage(self):
        assert eu.verify_token("garbage") is None
        assert eu.verify_token("garbage.garbage") is None
        assert eu.verify_token("") is None

    def test_verify_rejects_expired(self, monkeypatch):
        # Mint with iat=now-100 days → TTL is 90 days, so it's expired.
        original_time = time.time
        monkeypatch.setattr(time, "time", lambda: original_time() - (100 * 86400))
        token = eu.mint_token(user_id="user-123", email_template="welcome")
        monkeypatch.setattr(time, "time", original_time)
        assert eu.verify_token(token) is None

    def test_verify_rejects_wrong_purpose(self):
        """If purpose field is changed, token must not validate."""
        import base64
        import hashlib
        import hmac
        import json

        payload = {"uid": "u1", "template": "welcome", "iat": int(time.time()), "p": "password_reset"}
        payload_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        secret = eu._get_secret()
        sig = hmac.new(secret, payload_bytes, hashlib.sha256).digest()
        forged = (
            base64.urlsafe_b64encode(payload_bytes).decode().rstrip("=")
            + "."
            + base64.urlsafe_b64encode(sig).decode().rstrip("=")
        )
        assert eu.verify_token(forged) is None


class TestUnsubscribeEndpoints:
    def test_get_landing_valid_token(self, client):
        token = eu.mint_token("user-1", "weekly_report")
        resp = client.get(f"/api/v1/email/unsubscribe/{token}")
        assert resp.status_code == 200
        assert "unsubscribe" in resp.text.lower()
        assert "weekly report" in resp.text.lower()

    def test_get_landing_invalid_token(self, client):
        resp = client.get("/api/v1/email/unsubscribe/not-a-real-token")
        assert resp.status_code == 400

    def test_post_confirms_unsubscribe(self, client):
        token = eu.mint_token("user-2", "welcome")
        resp = client.post(f"/api/v1/email/unsubscribe/{token}")
        assert resp.status_code == 200
        assert "unsubscribed" in resp.text.lower()

    def test_post_one_click_header_variant(self, client):
        """Gmail/Apple POST with List-Unsubscribe=One-Click form body."""
        token = eu.mint_token("user-3", "breach_alert")
        resp = client.post(
            f"/api/v1/email/unsubscribe/{token}",
            data={"List-Unsubscribe": "One-Click"},
        )
        assert resp.status_code == 200

    def test_post_invalid_token_is_400(self, client):
        resp = client.post("/api/v1/email/unsubscribe/not-a-token")
        assert resp.status_code == 400

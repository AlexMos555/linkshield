"""Webhooks never verify against an empty secret (audit 2026-10-14).

stripe.Webhook.construct_event(payload, sig, "") computes HMAC-SHA256 with an
EMPTY key — a value anyone can compute. With STRIPE_WEBHOOK_SECRET unset, a
forged "checkout.session.completed" signed with the empty key was accepted
and granted a paid plan. Unset now means 503 "not configured", logged, and
the signature code is never reached.
"""
from __future__ import annotations

import json
import logging
import time

import pytest
import stripe
from fastapi.testclient import TestClient

from api.config import Settings, _DEBUG_TEST_SECRET, validate_settings


def _forged(secret: str = "") -> tuple[bytes, dict]:
    payload = json.dumps({
        "id": "evt_forged", "type": "checkout.session.completed", "object": "event",
        "data": {"object": {"metadata": {"user_id": "attacker", "plan": "personal"}}},
    }).encode()
    ts = int(time.time())
    sig = stripe.WebhookSignature._compute_signature(f"{ts}.{payload.decode()}", secret)
    return payload, {"stripe-signature": f"t={ts},v1={sig}"}


@pytest.fixture
def client():
    from api.main import app
    return TestClient(app)


@pytest.mark.parametrize("secret", ["", "   "])
def test_stripe_webhook_without_secret_is_503_and_never_verifies(client, monkeypatch, caplog, secret):
    from api import config

    monkeypatch.setattr(config.get_settings(), "stripe_webhook_secret", secret, raising=False)

    def _must_not_run(*a, **k):
        raise AssertionError("construct_event must not run without a secret")

    monkeypatch.setattr(stripe.Webhook, "construct_event", _must_not_run)
    payload, headers = _forged("")
    with caplog.at_level(logging.ERROR):
        resp = client.post("/api/v1/payments/webhook", content=payload, headers=headers)
    assert resp.status_code == 503
    assert any("stripe_webhook_not_configured" in r.getMessage() for r in caplog.records)


def test_forged_event_signed_with_empty_key_is_refused(client, monkeypatch):
    """The real construct_event, the real empty-key signature: refused."""
    from api import config

    monkeypatch.setattr(config.get_settings(), "stripe_webhook_secret", "", raising=False)
    payload, headers = _forged("")
    resp = client.post("/api/v1/payments/webhook", content=payload, headers=headers)
    assert resp.status_code == 503


def test_revenuecat_webhook_without_secret_is_503(client, monkeypatch):
    from api import config

    monkeypatch.setattr(config.get_settings(), "revenuecat_webhook_auth", "", raising=False)
    resp = client.post("/api/v1/webhooks/revenuecat", content=b"{}", headers={"authorization": ""})
    assert resp.status_code == 503


def test_partner_signature_without_key_is_not_configured():
    from api.billing.partner import verify_partner_signature
    from api.billing.service.errors import NotConfigured

    with pytest.raises(NotConfigured):
        verify_partner_signature("", {"x-partner-signature": "anything"}, b"{}")


# ── Startup: production says loudly which webhook secrets are missing ──

def _prod(**overrides) -> Settings:
    values = dict(
        environment="production", debug=False,
        supabase_jwt_secret="prod-long-secret-absolutely-at-least-sixty-four-characters-okayyy",
        supabase_url="https://prod.supabase.co", supabase_service_key="eyJ...prod-svc",
        stripe_secret_key="sk_live_FAKE_FIXTURE_accepted_in_prod",
        stripe_webhook_secret="whsec_FAKEFIXTUREprodwebhooksecret",
        sentry_dsn="https://abc@sentry.io/prod", rate_limit_fail_closed=True,
        trusted_proxy_cidrs="10.0.0.0/8",
        revenuecat_webhook_auth="rc-" + "x" * 40,
    )
    values.update(overrides)
    return Settings(_env_file=None, **values)


def test_production_with_every_webhook_secret_is_quiet(caplog):
    with caplog.at_level(logging.CRITICAL, logger="cleanway.config"):
        validate_settings(_prod())
    assert not [r for r in caplog.records if r.levelno >= logging.CRITICAL]


def test_production_without_revenuecat_secret_logs_critical(caplog):
    with caplog.at_level(logging.CRITICAL):
        validate_settings(_prod(revenuecat_webhook_auth=""))
    assert any(
        r.levelno == logging.CRITICAL and "REVENUECAT_WEBHOOK_AUTH" in r.getMessage() for r in caplog.records
    )


def test_production_without_stripe_at_all_logs_critical_for_the_webhook(caplog):
    with caplog.at_level(logging.CRITICAL):
        validate_settings(_prod(stripe_secret_key="", stripe_webhook_secret=""))
    assert any(
        r.levelno == logging.CRITICAL and "STRIPE_WEBHOOK_SECRET" in r.getMessage() for r in caplog.records
    )


def test_development_stays_quiet_about_webhook_secrets(caplog):
    s = Settings(_env_file=None, environment="development", debug=True,
                 supabase_jwt_secret=_DEBUG_TEST_SECRET, stripe_webhook_secret="", revenuecat_webhook_auth="")
    with caplog.at_level(logging.CRITICAL):
        validate_settings(s)
    assert not [r for r in caplog.records if r.levelno >= logging.CRITICAL]

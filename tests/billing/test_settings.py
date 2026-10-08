"""Billing settings: defaults are the founder's numbers, the flag is off, validation fails fast."""
from __future__ import annotations

import base64
import os

import pytest

from api.billing.settings import BillingSettings, decode_key, validate_billing_settings
from api.config import ConfigError


def _make(**overrides) -> BillingSettings:
    return BillingSettings(_env_file=None, **overrides)


def _b64(n: int) -> str:
    return base64.b64encode(os.urandom(n)).decode()


def test_defaults_are_the_product_rules_and_everything_is_off():
    s = _make()
    assert s.billing_enabled is False and s.role == "api"
    assert s.routes_enabled() is False
    assert (s.billing_price_solo_rub, s.billing_price_family3_rub, s.billing_price_family5_rub) == (99, 270, 399)
    assert s.price_kopecks("solo") == 9900 and s.price_kopecks("family5") == 39900
    assert s.billing_trial_days == 14 and s.billing_grace_days == 7
    assert s.billing_lapse_policy == "basic"
    assert s.retry_days() == (1, 3, 5, 7)
    assert s.billing_fake_provider_enabled is False
    assert s.database_url_billing == ""


def test_flag_alone_does_not_enable_routes():
    assert _make(billing_enabled=True).routes_enabled() is False
    assert _make(billing_enabled=True, role="billing").routes_enabled() is True


def test_env_names(monkeypatch):
    monkeypatch.setenv("ROLE", "billing")
    monkeypatch.setenv("DATABASE_URL_BILLING", "postgresql://x")
    monkeypatch.setenv("BILLING_LAPSE_POLICY", "off")
    monkeypatch.setenv("BILLING_PRICE_FAMILY5_RUB", "450")
    s = _make()
    assert s.role == "billing" and s.database_url_billing == "postgresql://x"
    assert s.billing_lapse_policy == "off" and s.billing_price_family5_rub == 450


def test_validation_is_inert_when_off():
    validate_billing_settings(_make())
    validate_billing_settings(_make(billing_enabled=True))  # role=api → nothing required


def _enabled(**overrides) -> BillingSettings:
    base = dict(
        billing_enabled=True, role="billing", database_url_billing="postgresql://localhost/billing",
        billing_entitlement_private_key=_b64(32), billing_msisdn_key=_b64(32), billing_hmac_key=_b64(32),
        environment="development",
    )
    base.update(overrides)
    return _make(**base)


def test_enabled_role_validates():
    validate_billing_settings(_enabled())


@pytest.mark.parametrize("overrides, match", [
    ({"database_url_billing": ""}, "DATABASE_URL_BILLING"),
    ({"billing_entitlement_private_key": ""}, "PRIVATE_KEY"),
    ({"billing_entitlement_private_key": _b64(16)}, "exactly 32"),
    ({"billing_msisdn_key": _b64(31)}, "exactly 32"),
    ({"billing_hmac_key": _b64(8)}, "at least 32"),
    ({"billing_hmac_key": "not base64!"}, "base64"),
    ({"billing_trial_days": -1}, "TRIAL_DAYS"),
    ({"billing_price_solo_rub": 0}, "positive"),
    ({"billing_retry_days": ""}, "RETRY_DAYS"),
])
def test_enabled_role_fails_fast(overrides, match):
    with pytest.raises(ConfigError, match=match):
        validate_billing_settings(_enabled(**overrides))


def test_production_refuses_mixplat_test_mode_unless_explicitly_allowed():
    """BILLING_MIXPLAT_TEST defaults to true: in production that would take no real money."""
    assert _make().billing_mixplat_test is True
    with pytest.raises(ConfigError, match="BILLING_MIXPLAT_TEST"):
        validate_billing_settings(_enabled(environment="production"))
    validate_billing_settings(_enabled(environment="production", billing_mixplat_test=False))
    validate_billing_settings(_enabled(environment="production", billing_mixplat_test_allowed_in_production=True))
    validate_billing_settings(_enabled(environment="staging"))
    validate_billing_settings(_enabled(environment="development"))


def test_production_refuses_the_fake_provider():
    with pytest.raises(ConfigError, match="BILLING_FAKE_PROVIDER_ENABLED"):
        validate_billing_settings(_enabled(environment="production", billing_mixplat_test=False,
                                           billing_fake_provider_enabled=True))


def test_environment_comes_from_the_shared_env_name(monkeypatch):
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.setenv("BILLING_MIXPLAT_TEST_ALLOWED_IN_PRODUCTION", "true")
    monkeypatch.setenv("BILLING_MIXPLAT_WEBHOOK_IPS", "185.77.232.0/24")
    s = _make()
    assert s.environment == "production" and s.billing_mixplat_test_allowed_in_production is True
    assert s.billing_mixplat_webhook_ips == "185.77.232.0/24"


@pytest.mark.parametrize("value", ["not-an-ip", "10.0.0.0/33"])
def test_a_malformed_webhook_allowlist_fails_fast(value):
    with pytest.raises(ConfigError, match="BILLING_MIXPLAT_WEBHOOK_IPS"):
        validate_billing_settings(_enabled(billing_mixplat_webhook_ips=value))


def test_decode_key():
    raw = decode_key(_b64(40), name="X", min_bytes=32)
    assert len(raw) == 40

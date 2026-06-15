"""Tests that startup config validation refuses dangerous combinations.

Most valuable test in the repo — these guards are the ONLY thing stopping
"oops I shipped dev creds to prod" from becoming a real incident.

Philosophy:
  - Dev is permissive: missing keys, weak secrets, anything goes
  - Staging is strict: full config required, test-mode only
  - Prod is ruthless: sk_live_*, long secrets, Sentry required
  - A mismatch = ConfigError at startup, container never serves requests
"""
from __future__ import annotations

import pytest

from api.config import (
    ConfigError,
    Settings,
    _DEBUG_TEST_SECRET,
    validate_settings,
)


def _make(**overrides) -> Settings:
    defaults = {
        "environment": "development",
        "debug": True,
        "supabase_jwt_secret": _DEBUG_TEST_SECRET,
        "supabase_url": "",
        "supabase_service_key": "",
        "stripe_secret_key": "",
        "sentry_dsn": "",
        "google_safe_browsing_key": "",
    }
    defaults.update(overrides)
    return Settings(_env_file=None, **defaults)


class TestDevelopment:
    def test_empty_config_passes(self):
        settings = _make(supabase_jwt_secret="")
        validate_settings(settings)
        assert settings.supabase_jwt_secret == _DEBUG_TEST_SECRET

    def test_test_secret_tolerated(self):
        settings = _make(supabase_jwt_secret=_DEBUG_TEST_SECRET)
        validate_settings(settings)

    def test_debug_true_allowed(self):
        settings = _make(debug=True)
        validate_settings(settings)

    def test_stripe_test_key_allowed(self):
        settings = _make(stripe_secret_key="sk_test_FAKE_FIXTURE_dev")
        validate_settings(settings)

    def test_stripe_live_key_rejected(self):
        settings = _make(stripe_secret_key="sk_live_FAKE_FIXTURE_blocked_in_dev")
        with pytest.raises(ConfigError, match="FORBIDDEN in environment=development"):
            validate_settings(settings)


class TestStaging:
    def _base(self, **overrides) -> Settings:
        defaults = {
            "environment": "staging",
            "debug": False,
            "supabase_jwt_secret": "staging-specific-secret-at-least-32-chars-long",
            "supabase_url": "https://staging.supabase.co",
            "supabase_service_key": "eyJ...staging-svc",
            "stripe_secret_key": "sk_test_FAKE_FIXTURE_staging",
        }
        defaults.update(overrides)
        return _make(**defaults)

    def test_valid_config_passes(self):
        validate_settings(self._base())

    def test_debug_true_rejected(self):
        with pytest.raises(ConfigError, match="debug=True is not allowed.*staging"):
            validate_settings(self._base(debug=True))

    def test_missing_jwt_rejected(self):
        with pytest.raises(ConfigError, match="SUPABASE_JWT_SECRET is required"):
            validate_settings(self._base(supabase_jwt_secret=""))

    def test_test_secret_rejected(self):
        with pytest.raises(ConfigError, match="Test JWT secret detected"):
            validate_settings(self._base(supabase_jwt_secret=_DEBUG_TEST_SECRET))

    def test_missing_supabase_url_rejected(self):
        with pytest.raises(ConfigError, match="SUPABASE_URL is required"):
            validate_settings(self._base(supabase_url=""))

    def test_missing_service_key_rejected(self):
        with pytest.raises(ConfigError, match="SUPABASE_SERVICE_KEY is required"):
            validate_settings(self._base(supabase_service_key=""))

    def test_stripe_live_key_rejected(self):
        with pytest.raises(ConfigError, match="FORBIDDEN in environment=staging"):
            validate_settings(self._base(stripe_secret_key="sk_live_FAKE_FIXTURE_blocked_in_staging"))

    def test_stripe_test_key_accepted(self):
        validate_settings(self._base(stripe_secret_key="sk_test_FAKE_FIXTURE_fine_in_staging"))


class TestProduction:
    def _base(self, **overrides) -> Settings:
        defaults = {
            "environment": "production",
            "debug": False,
            "supabase_jwt_secret": "prod-long-secret-absolutely-at-least-sixty-four-characters-okayyy",
            "supabase_url": "https://prod.supabase.co",
            "supabase_service_key": "eyJ...prod-svc",
            "stripe_secret_key": "sk_live_FAKE_FIXTURE_accepted_in_prod",
            "sentry_dsn": "https://abc@sentry.io/prod",
            # Audit findings backend-security HIGH: prod must
            # enforce both. Tests covering those guards override
            # explicitly; the happy-path fixture provides them.
            "rate_limit_fail_closed": True,
            "trusted_proxy_cidrs": "10.0.0.0/8",
            # When stripe_secret_key is set, prod also requires the
            # webhook signing secret — without it, webhooks signature-
            # fail silently and subscription state drifts from Stripe.
            "stripe_webhook_secret": "whsec_FAKEFIXTUREprodwebhooksecret",
        }
        defaults.update(overrides)
        return _make(**defaults)

    def test_valid_config_passes(self):
        validate_settings(self._base())

    def test_debug_true_rejected(self):
        with pytest.raises(ConfigError, match="debug=True is not allowed.*production"):
            validate_settings(self._base(debug=True))

    def test_short_jwt_secret_rejected(self):
        short = "x" * 40
        with pytest.raises(ConfigError, match="SUPABASE_JWT_SECRET must be ≥64"):
            validate_settings(self._base(supabase_jwt_secret=short))

    def test_missing_jwt_rejected(self):
        with pytest.raises(ConfigError, match="SUPABASE_JWT_SECRET is required"):
            validate_settings(self._base(supabase_jwt_secret=""))

    def test_test_secret_rejected(self):
        with pytest.raises(ConfigError, match="Test JWT secret detected"):
            validate_settings(self._base(supabase_jwt_secret=_DEBUG_TEST_SECRET))

    def test_stripe_test_mode_rejected(self):
        with pytest.raises(ConfigError, match="Production requires sk_live_"):
            validate_settings(self._base(stripe_secret_key="sk_test_FAKE_FIXTURE_rejected_in_prod"))

    def test_missing_stripe_key_allowed_if_empty(self):
        validate_settings(self._base(stripe_secret_key=""))

    def test_missing_sentry_rejected(self):
        with pytest.raises(ConfigError, match="Production requires SENTRY_DSN"):
            validate_settings(self._base(sentry_dsn=""))

    def test_missing_supabase_url_rejected(self):
        with pytest.raises(ConfigError, match="SUPABASE_URL is required"):
            validate_settings(self._base(supabase_url=""))


def test_unknown_environment_rejected_at_load():
    with pytest.raises(Exception):
        Settings(_env_file=None, environment="prod", supabase_jwt_secret=_DEBUG_TEST_SECRET)


def test_config_error_is_runtime_error():
    assert issubclass(ConfigError, RuntimeError)


class TestProductionFailClosedGuard:
    """Audit backend-security HIGH: production with rate_limit_fail_closed
    off is a footgun — a Redis blip silently disables every quota."""

    def _prod(self, **overrides) -> Settings:
        # Same as TestProduction._base but inlined so we don't entangle
        # the test with future fixture changes.
        defaults = dict(
            environment="production",
            debug=False,
            supabase_jwt_secret="prod-long-secret-absolutely-at-least-sixty-four-characters-okayyy",
            supabase_url="https://prod.supabase.co",
            supabase_service_key="eyJ...prod-svc",
            stripe_secret_key="sk_live_FAKE",
            sentry_dsn="https://abc@sentry.io/prod",
            rate_limit_fail_closed=True,
            trusted_proxy_cidrs="10.0.0.0/8",
            stripe_webhook_secret="whsec_FAKEFIXTUREprodwebhooksecret",
        )
        defaults.update(overrides)
        return _make(**defaults)

    def test_default_false_rejected_in_prod(self):
        with pytest.raises(ConfigError, match="RATE_LIMIT_FAIL_CLOSED=true"):
            validate_settings(self._prod(rate_limit_fail_closed=False))

    def test_empty_trusted_proxy_cidrs_rejected_in_prod(self):
        with pytest.raises(ConfigError, match="TRUSTED_PROXY_CIDRS"):
            validate_settings(self._prod(trusted_proxy_cidrs=""))

    def test_empty_stripe_webhook_secret_rejected_in_prod_with_stripe(self):
        """When stripe_secret_key is set, the webhook secret is also
        required — silent-fail on every webhook would break revenue
        state in production."""
        with pytest.raises(ConfigError, match="STRIPE_WEBHOOK_SECRET"):
            validate_settings(self._prod(stripe_webhook_secret=""))

    def test_stripe_webhook_secret_wrong_format_rejected(self):
        """whsec_ prefix is Stripe's documented signing-secret format —
        a value missing the prefix is almost certainly the publishable
        or restricted key confused for the webhook secret. Catch it
        at startup."""
        with pytest.raises(ConfigError, match="whsec_"):
            validate_settings(self._prod(stripe_webhook_secret="not_a_whsec_value"))

    def test_no_stripe_secret_skips_webhook_secret_check(self):
        """If we're not running Stripe at all, the webhook secret is
        irrelevant — don't fail boot."""
        validate_settings(
            self._prod(stripe_secret_key="", stripe_webhook_secret="")
        )

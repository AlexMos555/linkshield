"""Billing settings — every product number the founder may still change.

Prices, trial length, grace length and the lapse policy are settings, not
constants: the founder has not signed anything with an operator yet, and a
price registered with an operator is changed by re-approval, not by a
deploy. Nothing here is read by the main API unless `billing_enabled` is
true AND the process runs as `ROLE=billing`.

Env names (pydantic-settings, case-insensitive): BILLING_ENABLED, ROLE,
DATABASE_URL_BILLING, BILLING_PRICE_SOLO_RUB, BILLING_PRICE_FAMILY3_RUB,
BILLING_PRICE_FAMILY5_RUB, BILLING_TRIAL_DAYS, BILLING_GRACE_DAYS,
BILLING_LAPSE_POLICY, ... (one per field below).
"""
from __future__ import annotations

import base64
import binascii
import logging
from functools import lru_cache
from typing import Literal, Optional

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings

from api.config import ConfigError

logger = logging.getLogger("cleanway.billing.settings")

Role = Literal["api", "billing"]
LapsePolicyName = Literal["basic", "off"]

# The key material below is base64; these are the decoded lengths we accept.
_ED25519_SEED_BYTES = 32
_AES_256_KEY_BYTES = 32
_HMAC_KEY_MIN_BYTES = 32


class BillingSettings(BaseSettings):
    # ── Feature flag and deployment role ──
    # Both must be on for a single billing route to exist. The flag is the
    # founder's switch; the role keeps the Railway (non-Russian) deployment
    # from ever loading the billing routers even if the flag leaks into its
    # env (the phone-number database must not be reachable from there).
    billing_enabled: bool = False
    role: Role = Field(default="api", validation_alias=AliasChoices("ROLE", "BILLING_ROLE"))

    # ── The separate Russian database (152-ФЗ) ──
    database_url_billing: str = Field(
        default="", validation_alias=AliasChoices("DATABASE_URL_BILLING", "BILLING_DATABASE_URL"),
    )

    # ── Product rules (§2 of the plan) ──
    billing_price_solo_rub: int = 99
    billing_price_family3_rub: int = 270
    billing_price_family5_rub: int = 399
    # The catalogue version new sales are made at. A price change is a NEW
    # version (bump this with the prices); running subscriptions keep being
    # charged the price of the version they signed up for.
    billing_plan_version: int = 1
    billing_trial_days: int = 14
    billing_grace_days: int = 7
    # What a phone keeps after the grace period: `basic` = blocking stays,
    # list refresh weekly, yellow shield; `off` = protection stops. The
    # founder has not decided; both are built, `basic` is the default.
    billing_lapse_policy: LapsePolicyName = "basic"
    # Retry schedule (days after the failed charge's period end): 1, 3, 5, 7.
    billing_retry_days: str = "1,3,5,7"
    # A checkout nobody confirmed by SMS is deleted after this.
    billing_pending_timeout_minutes: int = 30
    # A 6-digit claim code is valid for this long and is single-use.
    billing_claim_code_ttl_hours: int = 24
    # The device pass is re-issued with every blocklist sync; this is the
    # signature's validity, not the subscription's.
    billing_pass_ttl_days: int = 7

    # ── Keys ──
    # Ed25519 seed (base64, 32 bytes) that signs device passes, and its id.
    # Rotation: issue with the new kid, keep the old public key in
    # `billing_entitlement_public_keys` until every issued pass has expired.
    billing_entitlement_private_key: str = ""
    billing_entitlement_key_id: str = "2026-09"
    # JSON {"kid": "<base64 public key>", ...} — every key a verifier accepts.
    # The `api` role needs only this (it never signs).
    billing_entitlement_public_keys: str = ""
    # AES-256-GCM key (base64, 32 bytes) for phone numbers at rest.
    billing_msisdn_key: str = ""
    # HMAC-SHA-256 key (base64, ≥32 bytes) for lookups that must not need the
    # plaintext: phone → subscription, claim codes, trial fingerprints, IPs.
    billing_hmac_key: str = ""

    # ── Providers ──
    # The Fake provider exists for tests and local demos. Never in production.
    billing_fake_provider_enabled: bool = False
    billing_mixplat_project_id: int = 0
    billing_mixplat_api_key: str = ""
    billing_mixplat_test: bool = True
    billing_mixplat_base_url: str = "https://api.mixplat.com"
    billing_mixplat_return_url: str = "https://cleanway.ai/ru/subscription/return"
    # Partner licences (T2 "option" model): HMAC key the partner signs with.
    billing_partner_hmac_key: str = ""

    # ── Consent text version the app must echo back ──
    billing_consent_doc_version: str = "ru/v1"

    # ── Rate limits (the limiter in api/services/rate_limiter.py) ──
    billing_register_per_ip_per_hour: int = 30
    billing_claim_attempts_per_device_per_hour: int = 10
    billing_claim_attempts_per_ip_per_hour: int = 60
    billing_checkout_per_device_per_hour: int = 10
    billing_checkout_per_phone_per_hour: int = 5
    billing_cancel_by_phone_per_ip_per_hour: int = 10
    billing_webhooks_per_ip_per_minute: int = 600

    # populate_by_name: the aliased fields (ROLE, DATABASE_URL_BILLING) can also
    # be passed by their Python name, which is how tests construct settings.
    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore", "populate_by_name": True}

    # ── Derived values ──

    def retry_days(self) -> tuple:
        """The retry schedule as a tuple of ints, ignoring blanks."""
        return tuple(int(d) for d in self.billing_retry_days.split(",") if d.strip())

    def routes_enabled(self) -> bool:
        """True only when this process must serve /billing/v1."""
        return self.billing_enabled and self.role == "billing"

    def price_kopecks(self, plan_code: str) -> int:
        rub = {
            "solo": self.billing_price_solo_rub,
            "family3": self.billing_price_family3_rub,
            "family5": self.billing_price_family5_rub,
        }[plan_code]
        return rub * 100


def decode_key(value: str, *, name: str, min_bytes: int, exact: Optional[int] = None) -> bytes:
    """Base64-decode a key from settings, refusing wrong sizes loudly."""
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as e:
        raise ConfigError(f"{name} is not valid base64: {e}") from e
    if exact is not None and len(raw) != exact:
        raise ConfigError(f"{name} must decode to exactly {exact} bytes, got {len(raw)}")
    if len(raw) < min_bytes:
        raise ConfigError(f"{name} must decode to at least {min_bytes} bytes, got {len(raw)}")
    return raw


def validate_billing_settings(settings: BillingSettings) -> None:
    """Fail fast when the billing role is switched on without what it needs.

    With the flag off nothing is required — the settings are inert.
    """
    if not settings.routes_enabled():
        return
    if not settings.database_url_billing.strip():
        raise ConfigError("BILLING_ENABLED with ROLE=billing requires DATABASE_URL_BILLING.")
    decode_key(settings.billing_entitlement_private_key, name="BILLING_ENTITLEMENT_PRIVATE_KEY",
               min_bytes=_ED25519_SEED_BYTES, exact=_ED25519_SEED_BYTES)
    decode_key(settings.billing_msisdn_key, name="BILLING_MSISDN_KEY",
               min_bytes=_AES_256_KEY_BYTES, exact=_AES_256_KEY_BYTES)
    decode_key(settings.billing_hmac_key, name="BILLING_HMAC_KEY", min_bytes=_HMAC_KEY_MIN_BYTES)
    if settings.billing_trial_days < 0 or settings.billing_grace_days < 0:
        raise ConfigError("BILLING_TRIAL_DAYS and BILLING_GRACE_DAYS must be >= 0.")
    for code in ("solo", "family3", "family5"):
        if settings.price_kopecks(code) <= 0:
            raise ConfigError(f"Price for plan {code} must be positive.")
    if settings.billing_plan_version < 1:
        raise ConfigError("BILLING_PLAN_VERSION must be >= 1.")
    if not settings.retry_days():
        raise ConfigError("BILLING_RETRY_DAYS must list at least one day.")
    logger.info(
        "billing.settings.validated",
        extra={
            "trial_days": settings.billing_trial_days,
            "grace_days": settings.billing_grace_days,
            "lapse_policy": settings.billing_lapse_policy,
            "fake_provider": settings.billing_fake_provider_enabled,
            "mixplat": bool(settings.billing_mixplat_api_key),
        },
    )


@lru_cache
def get_billing_settings() -> BillingSettings:
    return BillingSettings()

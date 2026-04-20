import logging
import warnings
from functools import lru_cache
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger("linkshield.config")

# Minimum acceptable JWT secret length per environment
_MIN_JWT_SECRET_LENGTH_DEV = 32
_MIN_JWT_SECRET_LENGTH_PROD = 64
_DEBUG_TEST_SECRET = "test-secret-for-development-only-not-for-production-use"

# Environment type — literal so typos fail at load time
Environment = Literal["development", "staging", "production"]


class Settings(BaseSettings):
    # App
    app_name: str = "LinkShield API"
    debug: bool = False
    # Environment discriminator — governs validate_settings() rules
    environment: Environment = "development"
    # If true, misconfigured production env crashes the container at startup
    # (paranoid mode — no silent degradation). If false (default), we log an
    # error and continue serving with whatever we have. Set strict_config=true
    # only when you know every prod env var is provisioned. Typical rollout:
    # first deploy with strict_config=false, watch logs for missing vars, set
    # them one by one, flip to true once the error log is clean.
    strict_config: bool = False

    # Supabase
    supabase_url: str = ""
    supabase_anon_key: str = ""
    supabase_service_key: str = ""  # For server-side operations
    supabase_jwt_secret: str = ""

    # CORS — comma-separated allowed origins.
    # Default covers linkshield web + all webmail providers the extension
    # content-script targets. Keep in sync with:
    #   packages/extension-core/src/content/webmail.js  (host allowlist)
    #   extension/manifest.json                         (host_permissions)
    # Production can override via env ALLOWED_ORIGINS="...comma-list..."
    allowed_origins: str = (
        "https://linkshield.io,"
        "https://www.linkshield.io,"
        "https://staging.linkshield.io,"
        "https://mail.google.com,"
        "https://outlook.office.com,"
        "https://outlook.live.com,"
        "https://mail.yahoo.com"
    )

    # Redis
    redis_url: str = "redis://localhost:6379"

    # Google Safe Browsing
    google_safe_browsing_key: str = ""

    # PhishTank (no key needed for free tier, but optional)
    phishtank_api_key: str = ""

    # IPQualityScore (free: 5K/month)
    ipqualityscore_key: str = ""

    # Sentry (error tracking)
    sentry_dsn: str = ""

    # HIBP (breach monitoring)
    hibp_api_key: str = ""

    # Stripe
    stripe_secret_key: str = ""
    stripe_webhook_secret: str = ""
    stripe_publishable_key: str = ""

    # Rate limits — authenticated (per user)
    free_tier_daily_limit: int = 10
    paid_tier_daily_limit: int = 10000
    burst_limit: int = 10           # Max requests per 10-second window
    burst_window_seconds: int = 10

    # Rate limits — public endpoints (per IP address)
    # Applied to /pricing/*, /public/*, unauthenticated /breach/*
    public_rate_limit_per_window: int = 60        # 60 requests per hour per IP
    public_rate_limit_window_seconds: int = 3600  # 1 hour window

    # Rate limits — sensitive actions (per user, stricter)
    # Applied to /payments/create-checkout, /payments/portal, /org/create
    sensitive_action_limit: int = 10               # 10 per hour per user
    sensitive_action_window_seconds: int = 3600    # 1 hour window

    # Rate limits — unsubscribe endpoint (per IP, very strict to prevent abuse)
    unsubscribe_limit_per_window: int = 20         # 20 attempts per hour per IP
    unsubscribe_window_seconds: int = 3600

    # Cache TTLs (seconds)
    cache_ttl_safe: int = 3600      # 1 hour for safe domains
    cache_ttl_suspicious: int = 900  # 15 min for suspicious
    cache_ttl_dangerous: int = 300   # 5 min for dangerous (recheck often)

    # Bloom filter
    bloom_filter_path: str = "./data/bloom_filter.bin"
    bloom_filter_cdn_url: str = ""

    # extra="ignore" позволяет хранить в .env клиентские vars (NEXT_PUBLIC_*, EXPO_PUBLIC_*, sb_publishable_*)
    # и management-only tokens без ошибок загрузки backend config.
    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}

    @field_validator("supabase_jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        """Reject dangerously short JWT secrets. Environment-specific length
        is enforced at startup (validate_settings) because the env isn't known yet here."""
        if v and len(v) < _MIN_JWT_SECRET_LENGTH_DEV:
            raise ValueError(
                f"supabase_jwt_secret must be at least {_MIN_JWT_SECRET_LENGTH_DEV} characters"
            )
        return v

    def get_allowed_origins(self) -> list[str]:
        """Parse comma-separated origins into a list."""
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


class ConfigError(RuntimeError):
    """Fatal misconfiguration — container should not start."""


def _is_safe_nonempty(value: str) -> bool:
    return bool(value and value.strip())


def validate_settings(settings: "Settings") -> None:
    """Run startup validation. Called once during app lifespan.

    Invariants enforced per environment:

    ┌──────────────────────────┬─────────────┬──────────┬────────────┐
    │ Setting                  │ development │ staging  │ production │
    ├──────────────────────────┼─────────────┼──────────┼────────────┤
    │ debug=true allowed?      │ yes         │ no       │ no         │
    │ JWT secret min length    │ 32          │ 32       │ 64         │
    │ JWT secret must be set?  │ no          │ yes      │ yes        │
    │ supabase_url set?        │ optional    │ required │ required   │
    │ stripe sk_live_* allowed │ no          │ no       │ yes only   │
    │ stripe sk_test_* allowed │ yes         │ yes      │ no         │
    │ sentry_dsn set?          │ optional    │ optional │ required   │
    │ Default _DEBUG_SECRET OK │ yes         │ no       │ no         │
    └──────────────────────────┴─────────────┴──────────┴────────────┘

    Dev mode tolerates missing / test credentials by design (developer convenience).
    Staging/prod refuse to boot with wrong config — fail loudly at startup.
    """
    env = settings.environment

    # 1) DEBUG must be off in staging/prod
    if env in ("staging", "production") and settings.debug:
        raise ConfigError(
            f"debug=True is not allowed in environment={env}. "
            "Set DEBUG=false in your env config."
        )

    # 2) JWT secret rules per env
    if env == "development":
        if not settings.supabase_jwt_secret:
            settings.supabase_jwt_secret = _DEBUG_TEST_SECRET
            warnings.warn(
                "DEV MODE: using built-in test JWT secret. Never use this in prod.",
                stacklevel=2,
            )
        # Short secrets OK in dev (validator already enforced >=32)
    else:
        if not _is_safe_nonempty(settings.supabase_jwt_secret):
            raise ConfigError(
                f"SUPABASE_JWT_SECRET is required in environment={env}."
            )
        if settings.supabase_jwt_secret == _DEBUG_TEST_SECRET:
            raise ConfigError(
                f"Test JWT secret detected in environment={env}. "
                "Generate a fresh secret (≥64 chars) and set SUPABASE_JWT_SECRET."
            )
        if env == "production" and len(settings.supabase_jwt_secret) < _MIN_JWT_SECRET_LENGTH_PROD:
            raise ConfigError(
                f"Production SUPABASE_JWT_SECRET must be ≥{_MIN_JWT_SECRET_LENGTH_PROD} chars; "
                f"got {len(settings.supabase_jwt_secret)}."
            )

    # 3) Supabase connection required in staging/prod
    if env in ("staging", "production"):
        if not _is_safe_nonempty(settings.supabase_url):
            raise ConfigError(f"SUPABASE_URL is required in environment={env}.")
        if not _is_safe_nonempty(settings.supabase_service_key):
            raise ConfigError(f"SUPABASE_SERVICE_KEY is required in environment={env}.")

    # 4) Stripe live/test mode must match environment
    if _is_safe_nonempty(settings.stripe_secret_key):
        is_live = settings.stripe_secret_key.startswith("sk_live_")
        is_test = settings.stripe_secret_key.startswith("sk_test_")
        if env == "production" and not is_live:
            raise ConfigError(
                "Production requires sk_live_* Stripe key. "
                "Got one that doesn't start with sk_live_ — would hit Stripe test mode in prod."
            )
        if env in ("development", "staging") and is_live:
            raise ConfigError(
                f"sk_live_* Stripe key is FORBIDDEN in environment={env} "
                "(would charge real customer cards from non-prod)."
            )
        if not (is_live or is_test):
            # Stripe sometimes has rk_test_* restricted keys — accept but warn
            logger.warning("stripe_secret_key doesn't match sk_live_* or sk_test_* format")

    # 5) Sentry DSN required in prod
    if env == "production" and not _is_safe_nonempty(settings.sentry_dsn):
        raise ConfigError(
            "Production requires SENTRY_DSN for error tracking. "
            "Sign up at sentry.io and set the DSN env var."
        )

    # 6) Soft warnings (not fatal)
    if env != "development" and not _is_safe_nonempty(settings.google_safe_browsing_key):
        logger.warning(
            "google_safe_browsing_key not set in environment=%s — detection quality degraded", env
        )

    logger.info(
        "config.validated",
        extra={
            "environment": env,
            "debug": settings.debug,
            "has_supabase": bool(settings.supabase_url),
            "has_stripe": bool(settings.stripe_secret_key),
            "has_sentry": bool(settings.sentry_dsn),
        },
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()

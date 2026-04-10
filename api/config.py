import logging
import warnings

from pydantic_settings import BaseSettings
from pydantic import field_validator
from functools import lru_cache

logger = logging.getLogger("linkshield.config")

# Minimum acceptable JWT secret length
_MIN_JWT_SECRET_LENGTH = 32
_DEBUG_TEST_SECRET = "test-secret-for-development-only-not-for-production-use"


class Settings(BaseSettings):
    # App
    app_name: str = "LinkShield API"
    debug: bool = False

    # Supabase
    supabase_url: str = ""
    supabase_anon_key: str = ""
    supabase_service_key: str = ""  # For server-side operations
    supabase_jwt_secret: str = ""

    # CORS — comma-separated allowed origins
    allowed_origins: str = "https://linkshield.io"

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

    # Rate limits
    free_tier_daily_limit: int = 10
    paid_tier_daily_limit: int = 10000
    burst_limit: int = 10           # Max requests per 10-second window
    burst_window_seconds: int = 10

    # Cache TTLs (seconds)
    cache_ttl_safe: int = 3600      # 1 hour for safe domains
    cache_ttl_suspicious: int = 900  # 15 min for suspicious
    cache_ttl_dangerous: int = 300   # 5 min for dangerous (recheck often)

    # Bloom filter
    bloom_filter_path: str = "./data/bloom_filter.bin"
    bloom_filter_cdn_url: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    @field_validator("supabase_jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        """Reject empty or dangerously short JWT secrets."""
        if not v:
            # Will be caught at startup — see validate_settings()
            return v
        if len(v) < _MIN_JWT_SECRET_LENGTH:
            raise ValueError(
                f"supabase_jwt_secret must be at least {_MIN_JWT_SECRET_LENGTH} characters"
            )
        return v

    def get_allowed_origins(self) -> list[str]:
        """Parse comma-separated origins into a list."""
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]


def validate_settings(settings: "Settings") -> None:
    """
    Run startup validation. Called once during app lifespan.
    Raises RuntimeError if critical config is missing in production.
    """
    if settings.debug:
        if not settings.supabase_jwt_secret:
            settings.supabase_jwt_secret = _DEBUG_TEST_SECRET
            warnings.warn(
                "DEBUG MODE: Using test JWT secret. Never use this in production!",
                stacklevel=2,
            )
        return

    # Production checks
    if not settings.supabase_jwt_secret:
        raise RuntimeError(
            "FATAL: supabase_jwt_secret is not set. "
            "Set SUPABASE_JWT_SECRET env variable (min 32 chars)."
        )

    if not settings.supabase_url:
        logger.warning("supabase_url is not set — tier lookups will be unavailable")

    if not settings.google_safe_browsing_key:
        logger.warning("google_safe_browsing_key is not set — Safe Browsing checks disabled")


@lru_cache
def get_settings() -> Settings:
    return Settings()

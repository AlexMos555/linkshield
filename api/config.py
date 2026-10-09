import logging
import warnings
from functools import lru_cache
from typing import Literal

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings

logger = logging.getLogger("cleanway.config")

# Minimum acceptable JWT secret length per environment
_MIN_JWT_SECRET_LENGTH_DEV = 32
_MIN_JWT_SECRET_LENGTH_PROD = 64
_DEBUG_TEST_SECRET = "test-secret-for-development-only-not-for-production-use"

# Environment type — literal so typos fail at load time
Environment = Literal["development", "staging", "production"]


class Settings(BaseSettings):
    # App
    app_name: str = "Cleanway API"
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
    # Default covers cleanway web + all webmail providers the extension
    # content-script targets. Keep in sync with:
    #   packages/extension-core/src/content/webmail.js  (host allowlist)
    #   extension/manifest.json                         (host_permissions)
    # Production can override via env ALLOWED_ORIGINS="...comma-list..."
    allowed_origins: str = (
        "https://cleanway.ai,"
        "https://www.cleanway.ai,"
        "https://staging.cleanway.ai,"
        "https://mail.google.com,"
        "https://outlook.office.com,"
        "https://outlook.live.com,"
        "https://mail.yahoo.com"
    )

    # Redis
    redis_url: str = "redis://localhost:6379"

    # Google Safe Browsing
    # Accepts both env var spellings — GOOGLE_SAFE_BROWSING_API_KEY is the
    # industry-standard form (Stripe / Supabase / OpenAI all use _API_KEY),
    # GOOGLE_SAFE_BROWSING_KEY is the legacy form we shipped originally.
    # Pydantic's AliasChoices picks whichever is set; if both, the API_KEY
    # form wins (listed first).
    google_safe_browsing_key: str = Field(
        default="",
        validation_alias=AliasChoices(
            "GOOGLE_SAFE_BROWSING_API_KEY",
            "GOOGLE_SAFE_BROWSING_KEY",
        ),
    )

    # Google Web Risk (Lookup API). Set: the analyzer asks Web Risk instead of
    # Safe Browsing v4 — Safe Browsing's terms bar commercial use without a
    # separate agreement, Web Risk is Google's commercial product for the
    # same lookup (api/services/web_risk.py, docs/THIRD_PARTY_FEEDS.md).
    # Unset (default): Safe Browsing v4 as before.
    web_risk_api_key: str = ""

    # Which threat-intel lookups the analyzer consults (api/services/
    # licensed_intel.py). "all" (default) — every source, today's behaviour.
    # "licensed" — without SURBL, the Spamhaus DBL public mirror, ThreatFox,
    # MalwareBazaar and Feodo Tracker, whose free tiers are for
    # non-commercial use. A switched-off source is not consulted at all and
    # leaves the check total, so confidence figures stay honest.
    licensed_intel: Literal["all", "licensed"] = "all"

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
    # Single Stripe price for one extra device, from before the tiered
    # STRIPE_PRICE_EXTRA_DEVICE_T{n}_{INTERVAL} prices (api/services/pricing.py,
    # scripts/create_stripe_prices.py). Still counted by the webhook if set, so
    # a subscription that carries it keeps its devices; new checkouts use the
    # tiered prices.
    stripe_price_extra_device: str = ""

    # Store purchases (Google Play, App Store) via RevenueCat —
    # docs/runbooks/revenuecat.md. REVENUECAT_WEBHOOK_AUTH is the exact
    # Authorization header value set on the webhook in the RevenueCat
    # dashboard (empty → the webhook answers 503 and grants nothing).
    # REVENUECAT_SECRET_API_KEY (sk_…) powers "Restore purchases"
    # (POST /api/v1/me/entitlement/refresh) and the post-TRANSFER sync.
    # REVENUECAT_PRODUCTS: optional JSON overriding the store product → plan
    # map in api/services/revenuecat.py. Sandbox (test) purchases grant a
    # plan only with REVENUECAT_ACCEPT_SANDBOX=true — staging, or production
    # while the founder tests with Play license testers.
    revenuecat_webhook_auth: str = ""
    revenuecat_secret_api_key: str = ""
    revenuecat_products: str = ""
    revenuecat_accept_sandbox: bool = False
    # Android applicationId — the Play "manage subscription" deep link.
    google_play_package_name: str = "ai.cleanway.app"

    # Accounts & devices (docs/ACCOUNTS_BILLING_PLAN.md §1, §5). A paid plan
    # covers PLAN_INCLUDED_DEVICES devices plus any bought extras. A signed-in
    # account WITHOUT a plan may link FREE_ACCOUNT_DEVICE_LIMIT devices: free
    # use needs no account at all, so this only caps how many installs share
    # one free account (2 = "my phone + my browser"; 3 would leave nothing
    # for the plan to add). A plan whose period ended stays effective for
    # ENTITLEMENT_GRACE_HOURS, so one late renewal webhook doesn't lock out a
    # paying person.
    plan_included_devices: int = 3
    free_account_device_limit: int = 2
    entitlement_grace_hours: int = 72

    # Rate limits — authenticated (per user)
    free_tier_daily_limit: int = 10
    paid_tier_daily_limit: int = 10000
    burst_limit: int = 10           # Max requests per 10-second window
    burst_window_seconds: int = 10

    # Rate limits — public endpoints (per IP address)
    # Applied to /pricing/*, /public/*, unauthenticated /breach/*
    public_rate_limit_per_window: int = 60        # 60 requests per hour per IP
    public_rate_limit_window_seconds: int = 3600  # 1 hour window
    # Fresh (uncached, full-analyzer) public checks, per minute. Without an
    # install header this is per IP — the historical 5/min.
    public_fresh_checks_per_minute: int = 5

    # Carrier-grade NAT: Tele2 puts hundreds to thousands of phones behind one
    # public IPv4, so per-IP limits would 429 a whole city at once. A client
    # that sends a valid `X-Cleanway-Install: <random UUID>` header is limited
    # per install instead (same 60/h and 5/min as an IP), under a much higher
    # per-IP ceiling that still bounds one address. Requests without the
    # header keep the per-IP limits above, unchanged.
    public_install_rate_limit_per_window: int = 60
    public_install_ip_ceiling_per_window: int = 1500
    public_fresh_ip_ceiling_per_minute: int = 60
    # The install id is not authenticated, so one address that rotates random
    # ids reaches the ceilings above (1500 fresh analyses an hour instead of
    # 60). The ceilings are that address's bound; the paid sources a fresh
    # analysis may call are bounded for the whole service, per UTC day, by
    # these (api/services/paid_budget.py). 0 turns the source off.
    ipqs_daily_budget: int = 150            # the free plan is 5,000 lookups a month
    llm_judge_daily_budget: int = 300       # live Claude calls (cache hits are free)

    # Wall-clock budget for ONE fresh domain analysis (all sources, the site
    # probes and the LLM judge). Checks still running at the deadline are cut
    # off and named in the verdict's `checks_incomplete`. The phone waits 5 s
    # and the app 6 s, so the verdict must be back well inside that.
    analysis_budget_seconds: float = 3.0

    # Benchmark bypass token. When set (non-empty), a request carrying the
    # matching `X-Cleanway-Benchmark` header skips IP rate limiting on the
    # public endpoints. This exists solely so the weekly fresh-URL benchmark
    # (scripts/eval_fresh_urls.py, run from CI) can measure real recall on a
    # large sample without being throttled by its own 5/min IP cap — which
    # would otherwise force a 65s-cooldown + 16s-interval crawl that overruns
    # the CI timeout. Default empty = no bypass (production behaviour). Rotate
    # by changing the value in both the Railway env and the GH Actions secret.
    benchmark_bypass_token: str = ""

    # DoH resolver rate limit (per IP). A DNS resolver serves dozens of
    # queries per page load, so the 60/hour public limit would break real
    # resolution. 5000/hour ≈ ~1.4/sec sustained per IP — generous enough
    # for a household behind one NAT while still bounding abuse/amplification.
    # Per public IP. Mobile carriers put hundreds of handsets behind one
    # CGNAT IPv4; 5000/h (~1.4 qps) was exhausted by a handful of phones.
    doh_rate_limit_per_window: int = 20000
    doh_rate_limit_window_seconds: int = 3600
    # DoH gateway runtime (docs/runbooks/doh-gateway.md). Upstreams are tried
    # in order with hedged failover; comma-separated RFC 8484 URLs. Empty =
    # Cloudflare by name, then by IP (api/services/doh_upstream.DEFAULT_UPSTREAMS);
    # add Quad9 here only after the privacy policy names it for DoH.
    doh_upstreams: str = ""
    # Per-worker response cache (entries, TTL cap, RFC 8767 serve-stale window).
    doh_cache_max_entries: int = 20000
    doh_cache_max_ttl_s: int = 3600
    doh_serve_stale_s: int = 6 * 3600
    # How often each worker checks the published blocklist artifact's sha.
    doh_filter_refresh_s: float = 30.0
    # Deadline for the rare Redis calls left on the DNS path (confirming a
    # blocklist hit; the cold-start fallback). Past it the query fails open.
    doh_redis_timeout_ms: int = 150
    # Serve /dns-query from the raw-ASGI fast path (api/services/doh_fastpath).
    doh_fast_path: bool = True

    # Blocklist artifact for phones (GET /api/v1/blocklist/dns). Conditional
    # requests every ~2h per phone, many phones per CGNAT IP.
    blocklist_rate_limit_per_window: int = 3000
    blocklist_rate_limit_window_seconds: int = 3600
    # Bandwidth guard for GET /blocklist/dns. Counts ONLY full-artifact sends
    # (~2.6 MB); 304s and deltas are free, so a phone that already has a list is
    # never counted. Sized so no realistic CGNAT gateway can reach it — 600
    # first-ever syncs from ONE IPv4 inside an hour — while a scraper pulling
    # multi-GB is still bounded. Fails OPEN (category is in FAIL_OPEN_CATEGORIES):
    # if Redis is down, users get their blocklist.
    blocklist_full_sends_per_ip_per_hour: int = 600

    # Android update check (GET /api/v1/mobile/version). Bump these when a new
    # signed APK is published (Railway env overrides them without a code deploy).
    # Defaults describe the latest published GitHub release, so a phone on an
    # older build is nudged to it and a phone on it sees no spurious prompt.
    mobile_latest_version_code: int = 103
    mobile_latest_version_name: str = "1.0.3"
    # Below this, the app should refuse to run old/insecure builds and require
    # an update. 0 = never force. Keep <= latest.
    mobile_min_supported_version_code: int = 0
    # The phone compares embedded version NAMES (expo Constants.version, no
    # native dep). latest_version_name above drives the optional nudge; this
    # drives the hard "you must update" gate. Empty = never force.
    mobile_min_supported_version_name: str = ""
    # Where the app sends the user to update. Empty → the app falls back to the
    # /android download page.
    mobile_apk_url: str = (
        "https://github.com/AlexMos555/linkshield/releases/download/"
        "v1.0.3/cleanway-1.0.3-103-arm.apk"
    )
    mobile_release_notes: str = ""

    # Remote switches for the app's on-phone checks, sent with the update check
    # (`remote_config` in GET /api/v1/mobile/version) so a bad on-device model
    # can be turned off without shipping an APK. The phone keeps the last answer
    # it got (native SharedPreferences) and falls back to these defaults only
    # when it has never heard from us — so an outage never flips a switch.
    # SMS_TEXT_MODEL_ENABLED=false: the SMS text model stops scoring messages;
    # the message rules and the link check keep working.
    sms_text_model_enabled: bool = True
    # Optional, 0 < x < 1. Unset = the thresholds shipped in the APK. The phone
    # only ever RAISES a threshold with these (MessageAnalyzer: quieter, never
    # louder), so a typo cannot turn every SMS into a warning. A value that is
    # not a number in range is ignored with a warning, never a failed boot.
    sms_text_model_caution_threshold_override: float | None = None
    sms_text_model_danger_threshold_override: float | None = None

    # Rate limits — sensitive actions (per user, stricter)
    # Applied to /payments/checkout, /payments/portal, /org/create
    sensitive_action_limit: int = 10               # 10 per hour per user
    sensitive_action_window_seconds: int = 3600    # 1 hour window

    # Rate limiter behavior when Redis is unreachable.
    #
    # `false` (DEFAULT) — fail OPEN: log a warning and allow the request.
    #   This is the right default for dev / staging — a Redis blip
    #   shouldn't take down the whole API.
    #
    # `true` (PRODUCTION) — fail CLOSED: respond 503 to the request.
    #   Set RATE_LIMIT_FAIL_CLOSED=true in Railway prod env so a Redis
    #   outage doesn't silently disable abuse protection. Without this,
    #   an attacker who notices Redis is down can hammer the free tier
    #   and burn our 3rd-party API quotas (Google Safe Browsing, IPQS,
    #   etc.) until we notice.
    rate_limit_fail_closed: bool = False

    # Comma-separated CIDRs whose X-Forwarded-For header we trust. Empty
    # in dev/local (the legacy "leftmost XFF" behaviour kicks in so
    # tests and `uvicorn --host 0.0.0.0` work unchanged). Production
    # MUST set this to the egress range of the proxy in front of us
    # (Railway / Vercel / Cloudflare). Without it, any caller can
    # fake their rate-limit key by sending a fresh X-Forwarded-For
    # on every request and bypass per-IP quotas entirely.
    # See _extract_client_ip() in api/services/rate_limiter.py.
    # validate_settings() enforces this is set when env=production.
    trusted_proxy_cidrs: str = ""

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

    @field_validator(
        "sms_text_model_caution_threshold_override",
        "sms_text_model_danger_threshold_override",
        mode="before",
    )
    @classmethod
    def lenient_threshold_override(cls, v: object) -> float | None:
        """A kill-switch env var must never stop the API from booting: blank,
        junk or out-of-range values mean "no override" (logged)."""
        if v is None or (isinstance(v, str) and not v.strip()):
            return None
        try:
            value = float(v)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            logger.warning("sms_text_model threshold override %r is not a number; ignored", v)
            return None
        if not (0.0 < value < 1.0):  # NaN fails this too
            logger.warning("sms_text_model threshold override %r is outside (0, 1); ignored", v)
            return None
        return value

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

    # 5b) Rate limiter fail-mode in prod (audit backend HIGH).
    #
    # When Redis is unreachable the limiter has two failure modes:
    #   fail-OPEN  → log and let the request through with full quota
    #   fail-CLOSED → return 503 so the abuse path stays blocked
    #
    # The default is fail-OPEN so dev / staging never get a wedged
    # local box when their redis container is down. Production must
    # opt in to fail-CLOSED — without it, anyone who notices Redis
    # is flaky can drain our entire paid-API budget (Safe Browsing,
    # IPQS, etc.) without ever hitting a quota wall.
    if env == "production" and not settings.rate_limit_fail_closed:
        raise ConfigError(
            "Production requires RATE_LIMIT_FAIL_CLOSED=true. "
            "Without it, a Redis outage silently disables every per-user "
            "and per-IP quota and lets attackers burn through our paid "
            "API budget. Set the env var on Railway and redeploy."
        )

    # 5c) X-Forwarded-For trust list in prod (audit backend-security HIGH).
    if env == "production" and not _is_safe_nonempty(settings.trusted_proxy_cidrs):
        raise ConfigError(
            "Production requires TRUSTED_PROXY_CIDRS (comma-separated). "
            "Without it the rate limiter trusts whatever X-Forwarded-For "
            "value the client sends — an attacker can rotate IPs in the "
            "header and bypass per-IP quotas. Set this to Railway's "
            "egress CIDR (or your fronting proxy's range) and redeploy."
        )

    # 5d) Stripe webhook secret in prod (audit backend MEDIUM).
    #
    # The /payments/webhook endpoint verifies the Stripe signature using
    # stripe_webhook_secret. If the secret is empty, every webhook event
    # we receive will fail signature verification and we silently drop
    # legitimate subscription / charge events — revenue + access state
    # quietly diverge from Stripe. Worse: an attacker who finds the
    # endpoint can fire fake events without ever needing the secret.
    if env == "production" and _is_safe_nonempty(settings.stripe_secret_key):
        if not _is_safe_nonempty(settings.stripe_webhook_secret):
            raise ConfigError(
                "Production requires STRIPE_WEBHOOK_SECRET when "
                "STRIPE_SECRET_KEY is set. Without it every webhook "
                "event will fail signature verification and silently "
                "drop, breaking subscription state sync."
            )
        if not settings.stripe_webhook_secret.startswith("whsec_"):
            raise ConfigError(
                "STRIPE_WEBHOOK_SECRET must start with 'whsec_' (Stripe "
                "webhook signing secret format). Got something that "
                "doesn't — likely confused with the publishable key."
            )

    # 6) Soft warnings (not fatal)
    if env != "development" and not (
        _is_safe_nonempty(settings.google_safe_browsing_key) or _is_safe_nonempty(settings.web_risk_api_key)
    ):
        logger.warning(
            "neither google_safe_browsing_key nor web_risk_api_key set in environment=%s — "
            "detection quality degraded", env
        )
    # RevenueCat: a guessable webhook secret lets anyone grant themselves a
    # plan; a public SDK key (goog_ / appl_) in place of the secret one makes
    # every "Restore purchases" fail with 401.
    if settings.revenuecat_webhook_auth and len(settings.revenuecat_webhook_auth) < 32:
        logger.warning("revenuecat_webhook_auth is shorter than 32 characters — use a long random value")
    if settings.revenuecat_secret_api_key and not settings.revenuecat_secret_api_key.startswith("sk_"):
        logger.warning("revenuecat_secret_api_key doesn't look like a secret key (sk_...)")

    logger.info(
        "config.validated",
        extra={
            "environment": env,
            "debug": settings.debug,
            "has_supabase": bool(settings.supabase_url),
            "has_stripe": bool(settings.stripe_secret_key),
            "has_revenuecat": bool(settings.revenuecat_webhook_auth),
            "has_sentry": bool(settings.sentry_dsn),
        },
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()

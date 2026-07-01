import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from api.services.security_headers import SecurityHeadersMiddleware

from api import __version__, __service_name__
from api.config import get_settings, validate_settings
from api.routers.check import router as check_router
from api.routers.payments import router as payments_router
from api.routers.user import router as user_router
from api.routers.feedback import router as feedback_router
from api.routers.public import router as public_router
from api.routers.breach import router as breach_router
from api.routers.referral import router as referral_router
from api.routers.org import router as org_router
from api.routers.pricing import router as pricing_router
from api.routers.email_unsubscribe import router as email_unsubscribe_router
from api.routers.family import router as family_router
from api.routers.email import router as email_router
from api.routers.phone import router as phone_router
from api.routers.scam import router as scam_router
from api.routers.auth import router as auth_router
from api.routers.credentials import router as credentials_router
from api.routers.transparency import router as transparency_router
from api.routers.explainer import router as explainer_router
from api.routers.doh import router as doh_router
from api.routers.mobileconfig import router as mobileconfig_router
from api.routers.watchtower import router as watchtower_router
from api.services.cache import close_redis, get_redis
from api.services.logger import setup_logging

# Initialize structured logging before anything else
setup_logging(debug=get_settings().debug)
logger = logging.getLogger("cleanway.app")

# Initialize Sentry (error tracking) with PII scrubbing.
# Sentry retains events for up to 90 days; raw emails / JWTs / Stripe
# IDs would contradict our privacy-first marketing. The scrubber walks
# every event + breadcrumb payload before Sentry sees it. See
# api/services/sentry_scrubber.py for the redaction rules.
_sentry_dsn = get_settings().sentry_dsn
if _sentry_dsn:
    try:
        import sentry_sdk

        from api.services.sentry_scrubber import before_breadcrumb, before_send

        sentry_sdk.init(
            dsn=_sentry_dsn,
            traces_sample_rate=0.1,
            environment="production" if not get_settings().debug else "development",
            # send_default_pii is False by default in modern sentry-sdk but
            # we set it explicitly so a future SDK version bumping the
            # default to True doesn't silently leak.
            send_default_pii=False,
            before_send=before_send,
            before_breadcrumb=before_breadcrumb,
        )
        logger.info("Sentry initialized with PII scrubber")
    except ImportError:
        logger.debug("sentry-sdk not installed, skipping")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──
    settings = get_settings()
    # Misconfiguration mode:
    #   strict_config=true  → validate_settings crashes the container (old
    #     behaviour, safest for prod once everything is wired).
    #   strict_config=false → log the error loudly and keep serving with
    #     whatever we have. Prevents a missing optional secret from taking
    #     down the whole pod during rollout.
    try:
        validate_settings(settings)
    except Exception as e:
        if settings.strict_config:
            logger.critical("startup_validation_failed_strict", extra={"error": str(e)})
            raise
        logger.error(
            "startup_validation_failed_lax_mode",
            extra={"error": str(e), "environment": settings.environment},
        )
    logger.info(
        "Cleanway API starting",
        extra={
            "debug": settings.debug,
            "environment": settings.environment,
            "origins": settings.get_allowed_origins(),
            "strict_config": settings.strict_config,
        },
    )
    yield
    # ── Shutdown ──
    await close_redis()
    logger.info("Cleanway API shutdown complete")


app = FastAPI(
    title=__service_name__,
    description="Phishing protection API. Checks domains for safety. Your browsing data lives on your device — we only see domain names.",
    version=__version__,
    lifespan=lifespan,
)

# CORS — origins loaded from env, never wildcard in production
_settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.get_allowed_origins(),
    allow_credentials=True,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Security headers — HSTS, CSP, X-Frame-Options, etc. Defense in depth.
# Order matters: SecurityHeaders runs LAST in request flow → FIRST in response flow,
# so it's the last middleware added (Starlette wraps in reverse order).
# hsts_preload=True so api.cleanway.ai matches landing (cleanway.ai already
# ships `preload`). Required for hstspreload.org submission of the whole
# cleanway.ai zone. Railway TLS-terminates; HTTPS-only by construction.
app.add_middleware(SecurityHeadersMiddleware, hsts_preload=True)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next):
    """Log every request with timing + request ID. Never log sensitive data."""
    import uuid
    request_id = str(uuid.uuid4())[:8]
    start = time.monotonic()
    response = await call_next(request)
    elapsed_ms = round((time.monotonic() - start) * 1000, 1)

    # Add tracing headers
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time"] = f"{elapsed_ms}ms"
    # X-Powered-By intentionally omitted: Mozilla Observatory + general
    # security hygiene deduct for software fingerprinting. Branding lives
    # in the response body, not in headers.

    # Scrub sensitive path parameters that should never appear in
    # access logs. Strategy #13: the 5-char SHA-1 prefix in
    # /api/v1/breach/check/{prefix} is documented as never leaving
    # Redis — but logged path params would leak it into Sentry
    # breadcrumbs + structured-logging downstreams. Same surgical
    # treatment for any other path-segment-of-secret endpoints we
    # add in the future.
    logged_path = _scrub_path_for_logs(request.url.path)
    logger.info(
        "request",
        extra={
            "method": request.method,
            "path": logged_path,
            "status": response.status_code,
            "elapsed_ms": elapsed_ms,
            "request_id": request_id,
        },
    )
    return response


def _scrub_path_for_logs(path: str) -> str:
    """Replace privacy-sensitive path parameters with their placeholder
    name. Keeps the route-shape visible to ops while preventing the
    actual parameter value from reaching the structured log sink
    (Sentry / Datadog).
    """
    if not path:
        return path
    # /api/v1/breach/check/{prefix} → /api/v1/breach/check/{prefix}
    if path.startswith("/api/v1/breach/check/"):
        return "/api/v1/breach/check/{prefix}"
    # /api/v1/breach/passwords/{prefix} (future shape) — same treatment
    if path.startswith("/api/v1/breach/passwords/"):
        return "/api/v1/breach/passwords/{prefix}"
    # /api/v1/public/check/{domain} — the domain the user is checking is
    # itself sensitive URL context; strip it from the logged path so Sentry
    # / Datadog only sees the route shape.
    if path.startswith("/api/v1/public/check/"):
        return "/api/v1/public/check/{domain}"
    # /api/v1/check/{domain} — same treatment for the authenticated variant.
    if path.startswith("/api/v1/check/"):
        return "/api/v1/check/{domain}"
    return path


# Routers
app.include_router(check_router)
app.include_router(payments_router)
app.include_router(user_router)
app.include_router(feedback_router)
app.include_router(public_router)
app.include_router(breach_router)
app.include_router(referral_router)
app.include_router(org_router)
app.include_router(pricing_router)
app.include_router(email_unsubscribe_router)
app.include_router(family_router)
app.include_router(email_router)
app.include_router(phone_router)
app.include_router(scam_router)
app.include_router(auth_router)
app.include_router(credentials_router)
app.include_router(transparency_router)
app.include_router(explainer_router)
app.include_router(doh_router)
app.include_router(mobileconfig_router)
app.include_router(watchtower_router)


@app.get("/health")
async def health_check():
    """
    Health check used by Railway's healthcheck probe + external monitors.

    Returns HTTP 200 as long as the process is alive and can handle requests.
    Dependency state (Redis, circuit breakers) is reported in the JSON body
    so humans / dashboards can still see degradation, but we don't fail the
    probe on it — Redis-less rate limiter falls open, and all breakers are
    "closed" by default, so a cold boot without Redis is still a working
    server from the user's perspective.

    If a dependency is fundamentally broken (e.g., the process itself can't
    serve), that surfaces as a crash / TCP failure and Railway will mark the
    pod unhealthy anyway.
    """
    from api.services.circuit_breaker import get_all_breaker_statuses

    redis_ok = False
    try:
        r = await get_redis()
        await r.ping()
        redis_ok = True
    except Exception:
        pass

    breakers = get_all_breaker_statuses()
    any_open = any(b["state"] == "open" for b in breakers)

    # status is INFORMATIONAL — we always return 200 OK so Railway's HTTP
    # healthcheck succeeds. "degraded" is a soft signal, not a failure.
    if not redis_ok or any_open:
        status = "degraded"
    else:
        status = "ok"

    return {
        "status": status,
        "version": __version__,
        "redis": "ok" if redis_ok else "down",
        "circuit_breakers": breakers,
    }


@app.get("/health/deep")
async def health_deep_check():
    """
    Deep health check — pings every downstream we depend on and FAILS HARD
    (HTTP 503) when any of them is unreachable.

    Different semantics from /health:
      - /health      → "is this Railway pod alive enough to serve?". Always
                       200 unless the pod itself is dead. Used by Railway's
                       healthcheck probe so a transient Supabase blip doesn't
                       cycle pods.
      - /health/deep → "is the WHOLE system actually serving real users?".
                       This is what an external monitor / StatusPage hits to
                       page on-call when something downstream actually broke.

    Checks:
      - Supabase REST: HEAD against /rest/v1/ with anon key. We don't care
        about response body, just that a TCP+TLS+auth handshake succeeds.
        2-second timeout — Supabase EU is on the same continent so anything
        slower is already a problem worth flagging.
      - Redis: PING. We separate this from the Supabase check so the JSON
        body can pinpoint which one failed.

    Per-component results in the body even on the failure path so a human
    debugging the 503 sees instantly which one broke.
    """
    settings = get_settings()
    components: dict[str, dict] = {}

    # ── Redis ──
    try:
        r = await get_redis()
        # asyncio.wait_for guards against a hung connection — without it a
        # half-open Redis socket can block the request indefinitely and the
        # Railway probe times out instead of getting our clean 503.
        import asyncio

        await asyncio.wait_for(r.ping(), timeout=2.0)
        components["redis"] = {"ok": True}
    except Exception as e:
        components["redis"] = {"ok": False, "error": type(e).__name__}

    # ── Supabase REST ──
    if not settings.supabase_url or not settings.supabase_anon_key:
        components["supabase"] = {"ok": False, "error": "not_configured"}
    else:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=2.0) as client:
                # The /rest/v1/ root returns 200 with `{"swagger":"2.0",...}`
                # when the project is up. HEAD would be lighter but Supabase
                # rejects HEAD on the schema route, so a GET is the
                # well-known canonical probe.
                resp = await client.get(
                    f"{settings.supabase_url.rstrip('/')}/rest/v1/",
                    headers={
                        "apikey": settings.supabase_anon_key,
                        "Authorization": f"Bearer {settings.supabase_anon_key}",
                    },
                )
                if resp.status_code in (200, 401):
                    # 401 means "Supabase is up and rejected our anon as
                    # expected" — which from a connectivity standpoint is
                    # still a successful probe. We're not testing auth here.
                    components["supabase"] = {"ok": True, "status": resp.status_code}
                else:
                    components["supabase"] = {
                        "ok": False,
                        "status": resp.status_code,
                    }
        except Exception as e:
            components["supabase"] = {"ok": False, "error": type(e).__name__}

    all_ok = all(c.get("ok") for c in components.values())
    body = {"status": "ok" if all_ok else "degraded", "components": components}
    if all_ok:
        return body
    # Fail HARD on degraded so external monitors page someone.
    from fastapi.responses import JSONResponse

    return JSONResponse(status_code=503, content=body)


@app.get("/")
async def root():
    return {
        "service": __service_name__,
        "version": __version__,
        "privacy": "We see domain names only. Your browsing history lives on your device.",
        "docs": "/docs",
    }

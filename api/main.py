import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from api.services.security_headers import SecurityHeadersMiddleware

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
from api.routers.email import router as email_router
from api.routers.phone import router as phone_router
from api.routers.scam import router as scam_router
from api.services.cache import close_redis, get_redis
from api.services.logger import setup_logging

# Initialize structured logging before anything else
setup_logging(debug=get_settings().debug)
logger = logging.getLogger("linkshield.app")

# Initialize Sentry (error tracking)
_sentry_dsn = get_settings().sentry_dsn
if _sentry_dsn:
    try:
        import sentry_sdk
        sentry_sdk.init(dsn=_sentry_dsn, traces_sample_rate=0.1, environment="production" if not get_settings().debug else "development")
        logger.info("Sentry initialized")
    except ImportError:
        logger.debug("sentry-sdk not installed, skipping")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──
    settings = get_settings()
    validate_settings(settings)  # Raises RuntimeError if critical config missing
    logger.info(
        "LinkShield API starting",
        extra={"debug": settings.debug, "origins": settings.get_allowed_origins()},
    )
    yield
    # ── Shutdown ──
    await close_redis()
    logger.info("LinkShield API shutdown complete")


app = FastAPI(
    title="LinkShield API",
    description="Phishing protection API. Checks domains for safety. Your browsing data lives on your device — we only see domain names.",
    version="0.1.0",
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
app.add_middleware(SecurityHeadersMiddleware)


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
    response.headers["X-Powered-By"] = "LinkShield"

    logger.info(
        "request",
        extra={
            "method": request.method,
            "path": request.url.path,
            "status": response.status_code,
            "elapsed_ms": elapsed_ms,
            "request_id": request_id,
        },
    )
    return response


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
app.include_router(email_router)
app.include_router(phone_router)
app.include_router(scam_router)


@app.get("/health")
async def health_check():
    """Health check that verifies dependencies and circuit breaker states."""
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

    if not redis_ok:
        status = "degraded"
    elif any_open:
        status = "degraded"
    else:
        status = "ok"

    return {
        "status": status,
        "version": "0.2.0",
        "redis": "ok" if redis_ok else "down",
        "circuit_breakers": breakers,
    }


@app.get("/")
async def root():
    return {
        "service": "LinkShield API",
        "version": "0.1.0",
        "privacy": "We see domain names only. Your browsing history lives on your device.",
        "docs": "/docs",
    }

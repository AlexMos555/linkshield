"""
Security headers middleware.

Adds defense-in-depth HTTP headers to every response:
  - HSTS: force HTTPS for 1 year, include subdomains, preload-ready
  - X-Content-Type-Options: prevent MIME-sniffing
  - X-Frame-Options: deny framing (clickjacking defense)
  - Referrer-Policy: strict-origin-when-cross-origin
  - Permissions-Policy: deny dangerous APIs we don't use
  - Cross-Origin-*-Policy: isolate our origin
  - Content-Security-Policy: lock down what the browser can load

The CSP is tuned for our API — mostly a JSON backend with an optional
Swagger UI at /docs. Swagger loads CSS + JS from jsdelivr.net via CDN,
so we allowlist it but only for those specific paths.

Rationale: we're protecting people from scammers. If OUR server gets
compromised (session hijack, MITM, supply-chain), we become the phish.
These headers narrow the blast radius.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp


# Strict CSP for JSON API responses — no scripts, no frames, no inline.
# The / and /docs routes loosen this since Swagger UI needs CDN assets.
_API_CSP = (
    "default-src 'none'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'; "
    "form-action 'none'"
)

# Swagger UI (served at /docs) needs jsdelivr CDN for css + js.
# NOTE: FastAPI inlines some init JS — 'unsafe-inline' only applies to /docs.
_DOCS_CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; "
    "font-src 'self' https://cdn.jsdelivr.net; "
    "connect-src 'self'; "
    "frame-ancestors 'none'; "
    "base-uri 'none'"
)

# Permissions-Policy — deny all the browser APIs an API backend doesn't need.
_PERMISSIONS_POLICY = (
    "accelerometer=(), ambient-light-sensor=(), autoplay=(), "
    "battery=(), camera=(), cross-origin-isolated=(), display-capture=(), "
    "document-domain=(), encrypted-media=(), execution-while-not-rendered=(), "
    "execution-while-out-of-viewport=(), fullscreen=(), geolocation=(), "
    "gyroscope=(), hid=(), idle-detection=(), magnetometer=(), microphone=(), "
    "midi=(), navigation-override=(), payment=(), picture-in-picture=(), "
    "publickey-credentials-get=(), screen-wake-lock=(), serial=(), "
    "sync-xhr=(), usb=(), web-share=(), xr-spatial-tracking=()"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach hardening headers to every response.

    Args:
        app: downstream ASGI application.
        hsts_max_age: HSTS max-age in seconds (default 1 year).
        hsts_preload: include the `preload` directive (only enable after
            submitting to hstspreload.org).
        enable_in_debug: still send headers when DEBUG=true. Default: True,
            because we want to catch header-related bugs in dev too.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        hsts_max_age: int = 31_536_000,
        hsts_preload: bool = False,
        enable_in_debug: bool = True,
    ) -> None:
        super().__init__(app)
        self._hsts_max_age = hsts_max_age
        self._hsts_preload = hsts_preload
        self._enable_in_debug = enable_in_debug

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Never cache error responses (defense against cache-poisoning CSRF)
        if response.status_code >= 400:
            response.headers.setdefault("Cache-Control", "no-store")

        # ── Transport security ─────────────────────────────────
        hsts = f"max-age={self._hsts_max_age}; includeSubDomains"
        if self._hsts_preload:
            hsts += "; preload"
        response.headers["Strict-Transport-Security"] = hsts

        # ── Content / framing defense ──────────────────────────
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = _PERMISSIONS_POLICY

        # ── Cross-origin isolation ─────────────────────────────
        # resource-policy: cross-origin (allows extensions to fetch — we need this)
        # opener-policy: same-origin (prevent cross-window attacks on docs page)
        response.headers["Cross-Origin-Resource-Policy"] = "cross-origin"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

        # ── CSP — path-based to allow Swagger UI CDN ───────────
        path = request.url.path
        if path.startswith("/docs") or path.startswith("/redoc") or path == "/openapi.json":
            response.headers["Content-Security-Policy"] = _DOCS_CSP
        else:
            response.headers["Content-Security-Policy"] = _API_CSP

        # ── Remove server fingerprint if present ───────────────
        # uvicorn already started with --no-server-header, belt + suspenders.
        if "server" in response.headers:
            del response.headers["server"]

        return response

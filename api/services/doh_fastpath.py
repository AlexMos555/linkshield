"""Raw-ASGI fast path for /dns-query.

A DNS query through the full FastAPI stack paid for two BaseHTTPMiddleware
layers (security headers, request logging — the latter also wrote one access
line per DNS query), CORS, route matching across ~150 routes and dependency
injection before reaching ~20 lines of real work. This middleware sits
outermost and answers GET/POST /dns-query itself, calling the same
api.routers.doh.resolve() the FastAPI routes use. Everything else — and
/dns-query too when DOH_FAST_PATH=false — goes down the normal stack.

It sets the same transport/hardening headers the rest of the API sends, and
never logs anything per request.
"""
from __future__ import annotations

import json
import logging
from urllib.parse import parse_qsl

from api.services.security_headers import _API_CSP

logger = logging.getLogger(__name__)

_SECURITY_HEADERS = [
    (b"strict-transport-security", b"max-age=31536000; includeSubDomains; preload"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", _API_CSP.encode()),
    (b"cross-origin-resource-policy", b"cross-origin"),
]


class DohFastPath:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope["path"] != "/dns-query" or scope["method"] not in ("GET", "POST"):
            await self.app(scope, receive, send)
            return
        from api.config import get_settings
        if not get_settings().doh_fast_path:
            await self.app(scope, receive, send)
            return
        status, body, headers = await _serve(scope, receive)
        await send({"type": "http.response.start", "status": status,
                    "headers": headers + [(b"content-length", str(len(body)).encode())] + _SECURITY_HEADERS})
        await send({"type": "http.response.body", "body": body})


def _plain(status: int, body: bytes = b"", extra: list | None = None) -> tuple[int, bytes, list]:
    headers = [(b"cache-control", b"no-store")] + (extra or [])
    if body:
        headers.append((b"content-type", b"application/json"))
    return status, body, headers


async def _read_body(scope, receive, limit: int) -> bytes | None:
    """The request body, or None when it exceeds `limit`."""
    for name, value in scope.get("headers", ()):
        if name == b"content-length":
            try:
                if int(value) > limit:
                    return None
            except ValueError:
                return None
    chunks, size = [], 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            break
        chunk = message.get("body", b"")
        size += len(chunk)
        if size > limit:
            return None
        chunks.append(chunk)
        if not message.get("more_body"):
            break
    return b"".join(chunks)


async def _serve(scope, receive) -> tuple[int, bytes, list]:
    from starlette.requests import Request

    from api.routers import doh
    from api.services.rate_limiter import doh_rate_check

    wire = None
    try:
        request = Request(scope)
        retry = doh_rate_check(request)
        if retry is not None:
            detail = {"detail": {"error": "Too many DNS queries from this IP.", "retry_after_seconds": retry}}
            return _plain(429, json.dumps(detail).encode(), [(b"retry-after", str(retry).encode())])
        if scope["method"] == "POST":
            if not doh._content_type_ok(request.headers.get("content-type")):
                return _plain(415)
            wire = await _read_body(scope, receive, doh.MAX_QUERY_BYTES)
            if wire is None:
                return _plain(413)
        else:
            params = dict(parse_qsl(scope.get("query_string", b"").decode("latin-1"), keep_blank_values=True))
            wire = doh.decode_get_param(params.get("dns"))
            if wire is None:
                return _plain(400)
        answer = await doh.resolve(wire)
    except Exception:  # noqa: BLE001 — fail open: forward the query untouched
        logger.warning("doh_fastpath_error", exc_info=True)
        if not wire:
            return _plain(500)
        upstream = await doh.proxy_to_upstream(wire)
        answer = (doh.DohAnswer(upstream, 200, 0) if upstream is not None
                  else doh.DohAnswer(doh.make_servfail_response(wire), 200, 0))
    if answer.status != 200:
        return _plain(answer.status)
    return 200, answer.body, [
        (b"content-type", b"application/dns-message"),
        (b"cache-control", f"max-age={answer.max_age}".encode()),
    ]

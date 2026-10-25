"""Raw-ASGI guards that run before routing, auth and body parsing.

BodySizeLimit
    Every request body is capped: 1 MiB by default, more only for the routes
    that need it. A declared Content-Length over the cap is refused before a
    byte is read; a body without one (chunked) is counted as it arrives and
    refused the moment it passes the cap. Without it, any route that parses
    a body (JSON, multipart) would read whatever it is sent first.

DnsRouting
    Which paths this process answers, by host name and SERVICE_ROLE
    (api/config.py, docs/runbooks/dns-service-split.md); everything else
    gets 404 before it reaches the app:
      * dns.cleanway.ai — what every DNS-profile phone talks to — serves DNS
        and its health probes, nothing else, whatever the role;
      * SERVICE_ROLE=dns serves the same paths under every other name too
        (its Railway domain included);
      * SERVICE_ROLE=api serves no DNS (/dns-query, /health/doh) under API
        names. Under dns.cleanway.ai it still does: if the founder flips the
        role before that name has moved to the DNS service, phones keep
        their DNS.
    It sits outside the DoH fast path, which would otherwise answer
    /dns-query first.
"""

from __future__ import annotations

import json

from api.config import get_settings

DEFAULT_BODY_LIMIT = 1024 * 1024

# Routes allowed more. Keep each next to the route's own limit.
_BODY_LIMITS = {
    # api/routers/scam.py MAX_VOICE_BYTES (25 MB) + multipart framing.
    "/api/v1/scam/analyze_voice": 26 * 1024 * 1024,
    # api/routers/email.py: 100k chars of text + 500k of HTML; JSON escapes a
    # non-ASCII character as up to 6 bytes.
    "/api/v1/email/analyze": 4 * 1024 * 1024,
}

# Routes that check the caller before they read their body
# (api/routers/scam.py analyze_voice). Load shedding reads none of it ahead
# of the route, so an anonymous upload is answered 401 with no byte read.
_READ_AFTER_AUTH = frozenset({"/api/v1/scam/analyze_voice"})

DNS_ONLY_HOSTS = frozenset({"dns.cleanway.ai"})
# /health is the Railway probe and the uptime monitor's; /health/doh the
# DoH-specific probe (scripts/dns_canary.py, docs/runbooks/monitoring.md).
DNS_HOST_PATHS = frozenset({"/dns-query", "/health", "/health/doh"})
# Of those, the ones that exist only for DNS. /health stays everywhere: it is
# every service's Railway health check.
DNS_ONLY_PATHS = DNS_HOST_PATHS - {"/health"}


def body_limit_for(path: str) -> int:
    return _BODY_LIMITS.get(path.rstrip("/") or "/", DEFAULT_BODY_LIMIT)


def reads_body_after_auth(path: str) -> bool:
    return (path.rstrip("/") or "/") in _READ_AFTER_AUTH


def _header(scope, name: bytes) -> bytes | None:
    for key, value in scope.get("headers", ()):
        if key == name:
            return value
    return None


async def _send_json(send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": status, "headers": [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        (b"cache-control", b"no-store"),
    ]})
    await send({"type": "http.response.body", "body": body})


class BodySizeLimit:
    def __init__(self, app, default_limit: int = DEFAULT_BODY_LIMIT) -> None:
        self.app = app
        self.default_limit = default_limit

    def _limit(self, path: str) -> int:
        return _BODY_LIMITS.get(path.rstrip("/") or "/", self.default_limit)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        limit = self._limit(scope.get("path", ""))
        declared = _header(scope, b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > limit
            except ValueError:
                await _send_json(send, 400, "Invalid Content-Length")
                return
            if too_big:
                await _send_json(send, 413, "Request body too large")
                return

        received = 0
        started = False      # the app began its response
        refused = False      # we answered 413 ourselves

        async def limited_receive():
            nonlocal received, refused
            if refused:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    # Answer 413 now and tell the app the client is gone, so
                    # it stops reading. (Raising here does not work: the
                    # BaseHTTPMiddleware layers read through a task group, so
                    # the app would see an ExceptionGroup and answer 400.)
                    refused = True
                    if not started:
                        await _send_json(send, 413, "Request body too large")
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message):
            nonlocal started
            if refused:
                return  # the 413 already went out; drop the app's answer
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        await self.app(scope, limited_receive, guarded_send)


def _host(scope) -> str:
    raw = (_header(scope, b"host") or b"").decode("latin-1").strip().lower()
    if raw.startswith("["):
        return raw
    return raw.rsplit(":", 1)[0].rstrip(".") if ":" in raw else raw.rstrip(".")


def serves(role: str, host: str, path: str) -> bool:
    """Whether a process with SERVICE_ROLE `role` answers `path` under `host`."""
    if host in DNS_ONLY_HOSTS or role == "dns":
        return path in DNS_HOST_PATHS
    if role == "api":
        return path not in DNS_ONLY_PATHS
    return True


class DnsRouting:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "http":
            role = get_settings().service_role
            path = scope.get("path", "")
            # A DNS query outside the api role is always answered: skip the
            # Host header on the hot path.
            if not (role != "api" and path in DNS_HOST_PATHS) and not serves(role, _host(scope), path):
                await _send_json(send, 404, "Not Found")
                return
        await self.app(scope, receive, send)

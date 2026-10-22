"""An httpx transport that connects only to vetted public addresses.

For every request — the first one and each redirect hop the caller follows —
it resolves the host ONCE, checks the port and every address
(domain_validator.resolve_public_sync), then connects to the checked address
itself. The request keeps its Host header and TLS keeps the original name
(SNI + certificate verification), so the site sees an ordinary request.

Without this, httpx would resolve the name a second time when connecting: a
DNS server answering 1.2.3.4 to our check and 127.0.0.1 a moment later (DNS
rebinding) would get us talking to ourselves.

Keep-alive is off: the connection pool is keyed by address, and one address
can serve many names — a connection opened with one name's SNI must never
carry a request for another.
"""

from __future__ import annotations

from typing import Awaitable, Callable, Optional

import httpx

from api.services import security_alerts
from api.services.domain_validator import DomainValidationError, SSRFBlocked, resolve_public
from api.services.tls_contexts import client_tls_context

Resolver = Callable[[str, int], Awaitable[list[str]]]


class BlockedDestination(httpx.ConnectError):
    """The host, its port or one of its addresses is not one we connect to."""


class PinnedTransport(httpx.AsyncBaseTransport):
    def __init__(self, resolver: Optional[Resolver] = None, inner: Optional[httpx.AsyncBaseTransport] = None):
        self._resolver = resolver
        self._inner = inner or httpx.AsyncHTTPTransport(
            verify=client_tls_context(),
            limits=httpx.Limits(max_keepalive_connections=0), retries=0,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.scheme not in ("http", "https"):
            raise BlockedDestination(f"scheme {url.scheme!r} is not allowed", request=request)
        port = url.port or (443 if url.scheme == "https" else 80)
        host = (url.raw_host or b"").decode("ascii", "replace").lower().rstrip(".")
        resolve = self._resolver or resolve_public
        try:
            addresses = await resolve(host, port)
        except DomainValidationError as exc:
            if isinstance(exc, SSRFBlocked):
                # Usually DNS rebinding: the name passed an earlier check.
                await security_alerts.record("ssrf_blocked")
            raise BlockedDestination(str(exc), request=request) from exc
        extensions = dict(request.extensions)
        if url.scheme == "https":
            extensions["sni_hostname"] = host
        pinned = httpx.Request(
            request.method,
            url.copy_with(host=addresses[0]),
            headers=request.headers,  # carries Host: <original name>
            stream=request.stream,
            extensions=extensions,
        )
        return await self._inner.handle_async_request(pinned)

    async def aclose(self) -> None:
        await self._inner.aclose()


def pinned_client(**kwargs) -> httpx.AsyncClient:
    """An AsyncClient over PinnedTransport. Redirects are never followed
    automatically: callers follow them by hand and vet every hop."""
    kwargs.setdefault("transport", PinnedTransport())
    kwargs["follow_redirects"] = False
    return httpx.AsyncClient(**kwargs)

"""Fake RFC 8484 upstream (the one in scripts/doh_loadtest.py) as an ASGI app
for hypercorn, so it speaks HTTP/2 over TLS like Cloudflare (over plain HTTP
httpx falls back to HTTP/1.1, which behaves very differently under load). Requests with
Accept: application/dns-json get a JSON answer (stands in for
family.cloudflare-dns.com, which the public check asks on every response)."""
import asyncio
import os
import sys

sys.path.insert(0, os.environ.get("REPO_SCRIPTS", "/repo/scripts"))
from doh_loadtest import make_upstream_app  # noqa: E402

DELAY = float(os.environ.get("UPSTREAM_DELAY_MS", "10")) / 1000
_wire = make_upstream_app(DELAY * 1000)
_JSON = b'{"Status":0,"Answer":[{"name":"x","type":1,"TTL":300,"data":"192.0.2.1"}]}'


async def app(scope, receive, send):
    if scope["type"] == "http" and dict(scope["headers"]).get(b"accept") == b"application/dns-json":
        await asyncio.sleep(DELAY)
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/dns-json"),
                                (b"content-length", str(len(_JSON)).encode())]})
        await send({"type": "http.response.body", "body": _JSON})
        return
    await _wire(scope, receive, send)

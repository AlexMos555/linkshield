"""Fake RFC 8484 upstream (the one in scripts/doh_loadtest.py) as an ASGI app
for hypercorn, so it speaks HTTP/2 over TLS like Cloudflare (over plain HTTP
httpx falls back to HTTP/1.1, which behaves very differently under load). Requests with
Accept: application/dns-json get a JSON answer (stands in for
family.cloudflare-dns.com, which the public check asks on every response).

UPSTREAM_SLOW_SUFFIX + UPSTREAM_SLOW_MS: a query (the gateway POSTs them) for
a name ending in the suffix waits that long first — a zone whose servers
never answer (the `r<hex>.example.net` names, ~10 % of loadgen's doh mix),
while the other names answer as usual."""
import asyncio
import os
import sys

sys.path.insert(0, os.environ.get("REPO_SCRIPTS", "/repo/scripts"))
from doh_loadtest import make_upstream_app  # noqa: E402

DELAY = float(os.environ.get("UPSTREAM_DELAY_MS", "10")) / 1000
SLOW_SUFFIX = os.environ.get("UPSTREAM_SLOW_SUFFIX", "").encode()
SLOW = float(os.environ.get("UPSTREAM_SLOW_MS", "0")) / 1000
_wire = make_upstream_app(DELAY * 1000)
_JSON = b'{"Status":0,"Answer":[{"name":"x","type":1,"TTL":300,"data":"192.0.2.1"}]}'


def _qname(wire: bytes) -> bytes:
    labels, pos = [], 12
    while pos < len(wire) and wire[pos]:
        labels.append(wire[pos + 1:pos + 1 + wire[pos]])
        pos += wire[pos] + 1
    return b".".join(labels).lower()


async def app(scope, receive, send):
    if scope["type"] == "http" and dict(scope["headers"]).get(b"accept") == b"application/dns-json":
        await asyncio.sleep(DELAY)
        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"application/dns-json"),
                                (b"content-length", str(len(_JSON)).encode())]})
        await send({"type": "http.response.body", "body": _JSON})
        return
    if SLOW_SUFFIX and scope["type"] == "http" and scope["method"] == "POST":
        body = b""
        while True:
            message = await receive()
            body += message.get("body", b"")
            if not message.get("more_body"):
                break
        if _qname(body).endswith(SLOW_SUFFIX):
            await asyncio.sleep(SLOW)

        async def replay():  # the body once more, for the wire app
            return {"type": "http.request", "body": body, "more_body": False}
        receive = replay
    await _wire(scope, receive, send)

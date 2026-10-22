"""One TLS client context per process, instead of one per outbound request.

`httpx.AsyncClient()` builds a fresh `ssl.SSLContext` and parses the whole
certifi bundle (~140 CAs) into it every time — measured at ~40-50 ms of CPU
per client in the production image, on the event loop. The public check
created one per response (the Cloudflare Families comparison), so a cache
hit cost ~45 ms of CPU and one vCPU served ~20 of them a second; a fresh
analysis created about a dozen. See docs/runbooks/capacity.md.

`client_tls_context()` verifies exactly as before: it is what httpx builds by
default (certifi, or SSL_CERT_FILE / SSL_CERT_DIR when set). Sharing it is
safe: it is only read when a connection is wrapped (httpcore sets the ALPN
list right before each wrap, synchronously, so two event-loop tasks never
interleave there), OpenSSL's SSL_CTX is thread-safe for that, and a shared
context also lets TLS sessions resume. Nothing may mutate the returned context.

(The site certificate probe, site_probes._check_ssl_sync, still builds its
own: it runs in a worker thread, not on the event loop.)
"""
from __future__ import annotations

import functools
import ssl

import httpx


@functools.lru_cache(maxsize=1)
def client_tls_context() -> ssl.SSLContext:
    """httpx's default verification context, built once."""
    return httpx.create_ssl_context()


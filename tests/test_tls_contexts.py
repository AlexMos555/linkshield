"""Outbound clients on the hot paths reuse one TLS context (and the public
check's Cloudflare comparison one pooled client) instead of building a new
SSLContext — ~45 ms of CPU on the event loop — per request.
See docs/runbooks/capacity.md."""
from __future__ import annotations

import asyncio
import ssl
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from api.services import analyzer, pinned_http, tls_contexts
from api.services import competitor_verdicts as cv


def test_client_context_is_built_once_and_verifies():
    a = tls_contexts.client_tls_context()
    assert a is tls_contexts.client_tls_context()
    assert a.verify_mode == ssl.CERT_REQUIRED and a.check_hostname is True
    # The same trust store httpx uses by default (certifi has >100 roots).
    assert len(a.get_ca_certs()) > 100


def test_client_context_honours_ssl_cert_file_like_httpx(monkeypatch, tmp_path):
    import certifi
    bundle = tmp_path / "ca.pem"
    bundle.write_text(open(certifi.where()).read().split("-----END CERTIFICATE-----")[0]
                      + "-----END CERTIFICATE-----\n")
    monkeypatch.setenv("SSL_CERT_FILE", str(bundle))
    tls_contexts.client_tls_context.cache_clear()
    try:
        assert len(tls_contexts.client_tls_context().get_ca_certs()) == 1
    finally:
        tls_contexts.client_tls_context.cache_clear()


def _answer(status=0, answers=({"type": 1, "data": "1.2.3.4"},)):
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"Status": status, "Answer": list(answers)}
    return resp


def test_competitor_lookup_reuses_one_pooled_client(monkeypatch):
    built = []

    def _factory(*args, **kwargs):
        built.append(kwargs)
        client = MagicMock()
        client.get = AsyncMock(return_value=_answer())
        client.aclose = AsyncMock()
        return client

    monkeypatch.setattr(cv.httpx, "AsyncClient", _factory)

    async def _three():
        out = [await cv.check_cloudflare_families(f"shop{i}.example.com") for i in range(3)]
        await cv.close_client()
        return out

    verdicts = asyncio.run(_three())
    assert [v.verdict for v in verdicts] == ["safe"] * 3
    assert len(built) == 1
    assert built[0]["verify"] is tls_contexts.client_tls_context()
    assert built[0]["timeout"] == cv.TIMEOUT_S


def test_competitor_client_is_per_event_loop(monkeypatch):
    built = []

    def _factory(*args, **kwargs):
        client = MagicMock()
        client.get = AsyncMock(return_value=_answer())
        built.append(client)
        return client

    monkeypatch.setattr(cv.httpx, "AsyncClient", _factory)
    asyncio.run(cv.check_cloudflare_families("a.example.com"))
    asyncio.run(cv.check_cloudflare_families("b.example.com"))
    assert len(built) == 2


def test_competitor_failure_is_still_unknown(monkeypatch):
    def _factory(*args, **kwargs):
        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("down"))
        return client

    monkeypatch.setattr(cv.httpx, "AsyncClient", _factory)
    out = asyncio.run(cv.check_cloudflare_families("a.example.com"))
    assert (out.verdict, out.detail) == ("unknown", "err:ConnectError")


@pytest.mark.parametrize("check", [
    analyzer.check_phishtank, analyzer.check_urlhaus, analyzer.check_whois_age,
    analyzer.check_phishstats, analyzer.check_threatfox, analyzer.check_malware_bazaar,
    analyzer.check_alienvault_otx,
])
def test_analyzer_sources_use_the_shared_context(monkeypatch, check):
    seen = []

    class _Client:
        def __init__(self, *a, verify=True, **k):
            seen.append(verify)

        async def __aenter__(self):
            raise httpx.ConnectError("offline")

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(analyzer.httpx, "AsyncClient", _Client)
    with pytest.raises(httpx.ConnectError):
        asyncio.run(check("obscure-shop.ru"))
    assert seen == [tls_contexts.client_tls_context()]


def test_pinned_transport_uses_the_shared_context(monkeypatch):
    seen = []
    real = httpx.AsyncHTTPTransport

    def _transport(*a, **k):
        seen.append(k.get("verify"))
        return real(*a, **k)

    monkeypatch.setattr(pinned_http.httpx, "AsyncHTTPTransport", _transport)
    pinned_http.PinnedTransport()
    assert seen == [tls_contexts.client_tls_context()]

"""Redirect chain: apex->www must NOT count as a cross-domain redirect.

check_redirect_chain used to compare raw hostnames, so the ubiquitous
`example.com -> www.example.com` redirect set cross_domain=True and scoring added
+20 "Redirects to a different domain — possible phishing redirect". That fired on
most of the web — it pushed barclays.co.uk (a real bank) to caution/27 in prod.
The fix compares the PSL-aware registrable domain (eTLD+1), so only a genuine
cross-site landing counts. These tests pin both halves: no FP on apex->www /
subdomain hops, and the real signal still fires on a different registrable domain.
"""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from api.services.analyzer import check_redirect_chain


def _fake_client(final_host: str):
    """An httpx.AsyncClient stand-in whose GET lands on `final_host`."""
    resp = MagicMock()
    resp.history = []
    resp.url = MagicMock()
    resp.url.host = final_host

    client = MagicMock()
    client.get = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=False)
    return client


def _cross_domain(source: str, final_host: str) -> bool:
    with patch(
        "api.services.analyzer.httpx.AsyncClient",
        return_value=_fake_client(final_host),
    ):
        return asyncio.run(check_redirect_chain(source))["cross_domain"]


def test_apex_to_www_is_not_cross_domain():
    # The regression that flagged real banks/sites as "possible phishing redirect".
    assert _cross_domain("barclays.co.uk", "www.barclays.co.uk") is False
    assert _cross_domain("google.com", "www.google.com") is False
    assert _cross_domain("apple.com.cn", "www.apple.com.cn") is False


def test_same_registrable_subdomain_hop_is_not_cross_domain():
    assert _cross_domain("example.com", "login.example.com") is False


def test_different_registrable_domain_still_flags():
    # The real signal must survive: a genuine cross-site landing is suspicious.
    assert _cross_domain("bit.ly", "evil.com") is True
    assert _cross_domain("paypal.com", "paypal-verify.xyz") is True
    assert _cross_domain("evil.tk", "phish.ru") is True

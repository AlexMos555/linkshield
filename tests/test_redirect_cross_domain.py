"""Redirect chain: apex->www must NOT count as a cross-domain redirect.

check_redirect_chain used to compare raw hostnames, so the ubiquitous
`example.com -> www.example.com` redirect set cross_domain=True and scoring added
+20 "Redirects to a different domain — possible phishing redirect". That fired on
most of the web — it pushed barclays.co.uk (a real bank) to caution/27 in prod.
The fix compares the PSL-aware registrable domain (eTLD+1), so only a genuine
cross-site landing counts. These tests pin both halves: no FP on apex->www /
subdomain hops, and the real signal still fires on a different registrable domain.

The site is served from a table through httpx's own transport machinery
(the `probe_web` fixture), so redirects are followed exactly as in production.
"""
import asyncio

from api.services.analyzer import check_redirect_chain


def _cross_domain(probe_web, source: str, final_host: str) -> bool:
    probe_web({f"https://{source}/": (301, {"location": f"https://{final_host}/"})})
    return asyncio.run(check_redirect_chain(source))["cross_domain"]


def test_apex_to_www_is_not_cross_domain(probe_web):
    # The regression that flagged real banks/sites as "possible phishing redirect".
    assert _cross_domain(probe_web, "barclays.co.uk", "www.barclays.co.uk") is False
    assert _cross_domain(probe_web, "google.com", "www.google.com") is False
    assert _cross_domain(probe_web, "apple.com.cn", "www.apple.com.cn") is False


def test_same_registrable_subdomain_hop_is_not_cross_domain(probe_web):
    assert _cross_domain(probe_web, "example.com", "login.example.com") is False


def test_different_registrable_domain_still_flags(probe_web):
    # The real signal must survive: a genuine cross-site landing is suspicious.
    assert _cross_domain(probe_web, "bit.ly", "evil.com") is True
    assert _cross_domain(probe_web, "paypal.com", "paypal-verify.xyz") is True
    assert _cross_domain(probe_web, "evil.tk", "phish.ru") is True


def test_no_redirect_is_not_cross_domain(probe_web):
    probe_web({})
    out = asyncio.run(check_redirect_chain("example.com"))
    assert out["cross_domain"] is False and out["count"] == 0

"""Checks that open a connection to the site itself: TLS, security headers, redirects.

They run from our server abroad, and many Russian banks and government sites
refuse foreign connections: президент.рф, rosreestr.gov.ru and bankspb.ru time
out or reset from the scanner while working normally inside Russia. The old
probes read "could not connect" as "no HTTPS" (+40) and "no security headers"
(+15) — +55, past the 'dangerous' line at 51, from nothing but a firewall
(report 2026-09-25 #1).

So every probe now reports WHETHER it reached the site separately from WHAT it
found:

  {"reachable": True,  ...measurements...}   the numbers are real
  {"reachable": False, "error": <kind>}      nothing was measured

and the scorer only penalises measurements. A TLS failure (untrusted
certificate, broken handshake) is "not reached" too: a Russian site signed by
the national CA fails verification here and is perfectly normal at home.

Only HTTPS is probed. The old plain-HTTP fallback judged whatever a site shows
foreign visitors on port 80 — often a stub or a block page.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

# Below the analysis budget (config.analysis_budget_seconds, 3 s) so a site
# that never answers is reported as unreachable, not merely cut off.
SITE_PROBE_TIMEOUT_S = 2.0

_SECURITY_HEADERS = (
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options", "referrer-policy",
)
_FREE_ISSUERS = ("let's encrypt", "zerossl", "buypass", "ssl.com")


def failure_kind(exc: BaseException) -> str:
    """A short, stable name for why a connection failed."""
    cause = exc
    # httpx wraps the socket/TLS error; the original says what really happened.
    if isinstance(exc, httpx.HTTPError) and (exc.__cause__ or exc.__context__):
        cause = exc.__cause__ or exc.__context__
    if isinstance(exc, httpx.TooManyRedirects):
        return "too_many_redirects"
    if isinstance(cause, ssl.SSLCertVerificationError):
        return "tls_certificate"
    if isinstance(cause, ssl.SSLError):
        return "tls_handshake"
    if isinstance(cause, (socket.timeout, TimeoutError)) or isinstance(exc, httpx.TimeoutException):
        return "timeout"
    if isinstance(cause, ConnectionRefusedError):
        return "refused"
    if isinstance(cause, ConnectionResetError):
        return "reset"
    if isinstance(cause, socket.gaierror):
        return "dns"
    return "network"


def _unreachable(exc: BaseException, **extra) -> dict:
    return {"reachable": False, "error": failure_kind(exc), **extra}


def ascii_host(host: str) -> str:
    """The wire (punycode) form of a hostname.

    httpx reports `resp.url.host` DECODED — 'мойбизнес.рф' for a request to
    xn--90aifddrld7a.xn--p1ai — so comparing it with the punycode we asked
    for invented a cross-domain redirect (+20) on every .рф site that
    answered at all.
    """
    h = (host or "").strip().lower().rstrip(".")
    try:
        return h.encode("idna").decode("ascii")
    except UnicodeError:
        return h


# ── TLS certificate ──

async def check_ssl(domain: str) -> dict:
    try:
        return await asyncio.to_thread(_check_ssl_sync, domain)
    except Exception as exc:  # the thread itself failed to run
        return _unreachable(exc)


def _check_ssl_sync(domain: str) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=SITE_PROBE_TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except Exception as exc:
        return _unreachable(exc)
    return _describe_certificate(cert or {})


def _describe_certificate(cert: dict) -> dict:
    issuer = dict(x[0] for x in cert.get("issuer", []))
    issuer_org = issuer.get("organizationName", "Unknown")
    issuer_cn = issuer.get("commonName", "")
    is_free = any(fi in issuer_org.lower() or fi in issuer_cn.lower() for fi in _FREE_ISSUERS)
    return {
        "reachable": True,
        "has_ssl": True,
        "issuer": issuer_org,
        "is_free_ssl": is_free,
        "cert_age_days": _cert_age_days(cert.get("notBefore")),
    }


def _cert_age_days(not_before: Optional[str]) -> Optional[int]:
    if not not_before:
        return None
    try:
        # Format: "Mon DD HH:MM:SS YYYY GMT"
        issued = datetime.strptime(not_before, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    return (datetime.now(timezone.utc) - issued).days


# ── Security headers ──

async def check_security_headers(domain: str) -> dict:
    try:
        async with httpx.AsyncClient(
            timeout=SITE_PROBE_TIMEOUT_S, follow_redirects=True, max_redirects=3,
        ) as client:
            resp = await client.head(f"https://{domain}/")
    except Exception as exc:
        return _unreachable(exc, missing=None)
    return {
        "reachable": True,
        "present": [h for h in _SECURITY_HEADERS if h in resp.headers],
        "missing": [h for h in _SECURITY_HEADERS if h not in resp.headers],
    }


# ── Redirect chain ──

async def check_redirect_chain(domain: str) -> dict:
    """Follow redirects and compare where we land with where we started.

    Many hops suggest obfuscation; landing on a different REGISTRABLE domain
    suggests a phishing redirect. Registrable (eTLD+1), not raw host, so the
    ubiquitous apex->www hop (barclays.co.uk -> www.barclays.co.uk) is not
    counted; wire form on both sides, so an IDN is not "redirected" to its own
    Unicode spelling.
    """
    try:
        async with httpx.AsyncClient(
            timeout=SITE_PROBE_TIMEOUT_S, follow_redirects=True, max_redirects=5,
        ) as client:
            resp = await client.get(f"https://{domain}/")
    except Exception as exc:
        return _unreachable(exc, count=0, cross_domain=False)

    from api.services.doh_gateway import _registrable_domain

    visited = {ascii_host(urlparse(r.headers.get("location", "")).hostname or "")
               for r in resp.history if "://" in r.headers.get("location", "")}
    final_host = ascii_host(resp.url.host or "")
    cross_domain = bool(final_host) and (
        _registrable_domain(final_host) != _registrable_domain(ascii_host(domain))
    )
    if cross_domain:
        visited.add(final_host)
    return {
        "reachable": True,
        "count": len(resp.history),
        "cross_domain": cross_domain,
        "domains_visited": sorted(h for h in visited if h),
        "final_url": str(resp.url),
    }


def site_reachability(*probe_results: dict) -> Optional[bool]:
    """True if any probe reached the site, False if the ones that finished all
    failed to, None if none finished (cut off, or never run)."""
    seen = [r.get("reachable") for r in probe_results if r]
    if any(v is True for v in seen):
        return True
    if any(v is False for v in seen):
        return False
    return None


def first_failure(*probe_results: dict) -> Optional[str]:
    """The failure kind to show the person — the TLS probe's, when it has one."""
    for r in probe_results:
        if r and r.get("reachable") is False:
            return r.get("error")
    return None

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

and the scorer only penalises measurements. What counts as measured is
narrow on purpose:

  * a certificate from an authority we do not know (a Russian site signed by
    the national CA fails verification here and is perfectly normal at home)
    is "not reached";
  * an EXPIRED, SELF-SIGNED or WRONG-NAME certificate is a finding — every
    browser shows a full-page warning for it, wherever it is opened from;
  * a site that refuses HTTPS outright (connection refused, or no TLS on port
    443) but serves a page over plain HTTP is a finding — "no HTTPS" — and not
    a firewall. A timeout or a reset stays "not reached": that is what
    firewalls do.

The headers and redirect probes speak HTTPS only; the old plain-HTTP fallback
judged whatever a site shows foreign visitors on port 80. They follow
redirects BY HAND and vet every hop's address first: httpx's automatic
following would connect to a 30x pointing at 127.0.0.1 or an internal
address, which the analyzer's SSRF guard (first host only) never sees.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlsplit

import httpx

from api.services.domain_validator import DomainValidationError, validate_domain_resolution

logger = logging.getLogger("cleanway.site_probes")

# Per connection phase (connect, read, …), below the analysis budget
# (config.analysis_budget_seconds, 3 s), so a site that never answers is
# reported as unreachable, not merely cut off.
SITE_PROBE_TIMEOUT_S = 2.0
# Whole probe, all phases and hops together: httpx's timeout is per phase, so
# a server that trickles a byte a second would otherwise never time out.
SITE_PROBE_TOTAL_S = 2.5

_SECURITY_HEADERS = (
    "strict-transport-security", "content-security-policy",
    "x-frame-options", "x-content-type-options", "referrer-policy",
)
_FREE_ISSUERS = ("let's encrypt", "zerossl", "buypass", "ssl.com")
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})

# OpenSSL verify codes that mean "this certificate is broken", as opposed to
# "issued by an authority we do not have" (20/21, and 19 — a self-signed ROOT
# in the chain, which is how a chain to the Russian national CA can look).
_CERTIFICATE_PROBLEMS = {
    9: "not_yet_valid",
    10: "expired",
    18: "self_signed",     # the site's own certificate is self-signed
    62: "wrong_host",      # valid chain, issued for another name
}

_HTTP_PROBE_HEAD_LIMIT = 8192
# The same User-Agent the HTTPS probes send, so port 80 is asked the same way.
_USER_AGENT = f"python-httpx/{httpx.__version__}"


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
    if (isinstance(cause, (socket.timeout, TimeoutError, asyncio.TimeoutError))
            or isinstance(exc, httpx.TimeoutException)):
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
    """The wire (punycode) form of a hostname typed in Unicode.

    For hosts that came off the wire use `wire_host` instead: this re-encodes
    with Python's IDNA 2003 codec, which folds ß to "ss" and ς to "σ", so a
    decode + re-encode round trip does not give back the name we asked for.
    """
    h = (host or "").strip().lower().rstrip(".")
    try:
        return h.encode("idna").decode("ascii")
    except UnicodeError:
        return h


def wire_host(url: httpx.URL) -> str:
    """The host of `url` exactly as it goes on the wire.

    httpx reports `url.host` DECODED — 'мойбизнес.рф' for a request to
    xn--90aifddrld7a.xn--p1ai — and re-encoding that is lossy for IDNA 2008
    names (straße.de is xn--strae-oqa.de, but re-encodes to strasse.de), which
    invented a cross-domain redirect (+20) on sites that never redirected.
    `raw_host` is the encoded form httpx actually connects to.
    """
    raw = url.raw_host or b""
    return raw.decode("ascii", "replace").lower().rstrip(".")


# ── TLS certificate ──

async def check_ssl(domain: str) -> dict:
    # The thread keeps its own deadline (SITE_PROBE_TOTAL_S from when it
    # starts); this outer limit only catches a handshake that ignores it, and
    # leaves the thread a moment to be scheduled.
    try:
        return await asyncio.wait_for(
            asyncio.to_thread(_check_ssl_sync, domain), timeout=SITE_PROBE_TOTAL_S + 0.25,
        )
    except Exception as exc:  # the thread failed to run, or the probe overran
        return _unreachable(exc)


def _check_ssl_sync(domain: str) -> dict:
    deadline = time.monotonic() + SITE_PROBE_TOTAL_S
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=SITE_PROBE_TIMEOUT_S) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        problem = _CERTIFICATE_PROBLEMS.get(getattr(exc, "verify_code", None))
        if problem:
            return {"reachable": True, "has_ssl": True, "certificate_problem": problem}
        return _unreachable(exc)
    except Exception as exc:
        if _may_have_no_https(exc) and _serves_plain_http(domain, deadline):
            return {"reachable": True, "has_ssl": False, "http_only": True}
        return _unreachable(exc)
    return _describe_certificate(cert or {})


def _may_have_no_https(exc: BaseException) -> bool:
    """Port 443 answered, but not with TLS for this name: an outright refusal,
    or a server that speaks something other than a TLS handshake. A timeout,
    a reset or a connection dropped mid-handshake is what a firewall does,
    and is never read as "no HTTPS"."""
    if isinstance(exc, ConnectionRefusedError):
        return True
    return isinstance(exc, ssl.SSLError) and not isinstance(
        exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError, ssl.SSLCertVerificationError),
    )


def _serves_plain_http(domain: str, deadline: float) -> bool:
    """True when port 80 serves a real page over plain HTTP.

    A 2xx, or a redirect that stays on plain HTTP. A redirect to https:// means
    the site wants HTTPS and we simply could not reach it; an error status is
    as likely to be a foreign-visitor block page as anything — neither is
    evidence of "no HTTPS".
    """
    head = _plain_http_head(domain, deadline)
    if head is None:
        return False
    status, location = head
    if 200 <= status < 300:
        return True
    if status in _REDIRECT_CODES and location:
        return urlsplit(location).scheme.lower() != "https"
    return False


def _plain_http_head(domain: str, deadline: float) -> Optional[tuple[int, Optional[str]]]:
    """(status, Location) of `GET http://<domain>/`, or None if port 80 did not
    answer HTTP by `deadline`. One request, no redirects followed: nothing but
    the domain the SSRF guard already vetted is ever contacted."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return None
    request = (
        f"GET / HTTP/1.1\r\nHost: {domain}\r\nUser-Agent: {_USER_AGENT}\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode("ascii", "ignore")
    try:
        with socket.create_connection((domain, 80), timeout=min(SITE_PROBE_TIMEOUT_S, remaining)) as sock:
            sock.sendall(request)
            raw = _read_head(sock, deadline)
    except OSError:
        return None
    return _parse_head(raw)


def _read_head(sock: socket.socket, deadline: float) -> bytes:
    """The response head, read until its blank line, a size cap or the
    deadline — a server trickling a byte at a time must not hold this
    thread (the async side stops waiting at SITE_PROBE_TOTAL_S; the thread
    would not)."""
    raw = b""
    while b"\r\n\r\n" not in raw and len(raw) < _HTTP_PROBE_HEAD_LIMIT:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(min(SITE_PROBE_TIMEOUT_S, remaining))
        chunk = sock.recv(2048)
        if not chunk:
            break
        raw += chunk
    return raw


def _parse_head(raw: bytes) -> Optional[tuple[int, Optional[str]]]:
    lines = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
    status_line = lines[0].split(" ", 2) if lines else []
    if len(status_line) < 2 or not status_line[0].startswith("HTTP/") or not status_line[1].isdigit():
        return None
    location = None
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "location":
            location = value.strip()
            break
    return int(status_line[1]), location


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


# ── Redirects, followed by hand ──

async def _hop_is_safe(host: str) -> bool:
    """The SSRF guard for one redirect hop: False when `host` resolves to a
    private, loopback, link-local or otherwise internal address."""
    try:
        await validate_domain_resolution(host)
        return True
    except DomainValidationError:
        logger.warning("redirect_hop_blocked", extra={"host": host})
        return False


async def _fetch(
    client: httpx.AsyncClient, method: str, domain: str, max_redirects: int,
) -> tuple[httpx.Response, list[str], Optional[str]]:
    """`method` https://<domain>/, following up to `max_redirects` redirects.

    Returns (last response, the hosts redirected to in order, why following
    stopped early: None, "unsafe_hop" or "too_many_redirects"). A hop to an
    unsafe host or to a non-web scheme is recorded but never contacted.
    """
    send = client.head if method == "HEAD" else client.get
    url = f"https://{domain}/"
    hosts: list[str] = []
    while True:
        resp = await send(url)
        location = resp.headers.get("location")
        if resp.status_code not in _REDIRECT_CODES or not location:
            return resp, hosts, None
        if len(hosts) >= max_redirects:
            return resp, hosts, "too_many_redirects"
        target = httpx.URL(url).join(location)
        hosts.append(wire_host(target))
        if target.scheme not in ("http", "https") or not await _hop_is_safe(hosts[-1]):
            return resp, hosts, "unsafe_hop"
        url = str(target)


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=SITE_PROBE_TIMEOUT_S, follow_redirects=False)


# ── Security headers ──

async def check_security_headers(domain: str) -> dict:
    try:
        return await asyncio.wait_for(_security_headers(domain), timeout=SITE_PROBE_TOTAL_S)
    except Exception as exc:
        return _unreachable(exc, missing=None)


async def _security_headers(domain: str) -> dict:
    async with _client() as client:
        resp, _, stopped = await _fetch(client, "HEAD", domain, max_redirects=3)
    if stopped:
        # The site answered, but we never saw the page its headers belong to.
        return {"reachable": True, "present": [], "missing": None}
    return {
        "reachable": True,
        "present": [h for h in _SECURITY_HEADERS if h in resp.headers],
        "missing": [h for h in _SECURITY_HEADERS if h not in resp.headers],
    }


# ── Redirect chain ──

_MAX_REDIRECTS = 5


async def check_redirect_chain(domain: str) -> dict:
    """Follow redirects and compare where we land with where we started.

    Many hops suggest obfuscation; landing on a different REGISTRABLE domain
    suggests a phishing redirect. Registrable (eTLD+1), not raw host, so the
    ubiquitous apex->www hop (barclays.co.uk -> www.barclays.co.uk) is not
    counted; wire form on both sides (`wire_host`), so an IDN is never
    "redirected" to its own Unicode spelling. A redirect loop is a finding —
    more hops than we follow — not a failure to reach the site.
    """
    try:
        return await asyncio.wait_for(_redirect_chain(domain), timeout=SITE_PROBE_TOTAL_S)
    except Exception as exc:
        return _unreachable(exc, count=0, cross_domain=False)


async def _redirect_chain(domain: str) -> dict:
    from api.services.doh_gateway import _registrable_domain

    async with _client() as client:
        resp, hosts, stopped = await _fetch(client, "GET", domain, max_redirects=_MAX_REDIRECTS)
    start = ascii_host(domain)
    final_host = hosts[-1] if hosts else start
    cross_domain = bool(final_host) and _registrable_domain(final_host) != _registrable_domain(start)
    count = len(hosts) + (1 if stopped == "too_many_redirects" else 0)
    return {
        "reachable": True,
        "count": count,
        "cross_domain": cross_domain,
        "domains_visited": sorted({h for h in hosts if h}),
        "final_url": str(resp.url) if stopped is None else None,
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

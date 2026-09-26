"""What the site probes MEASURE, as opposed to "could not reach" (review 2026-09-27).

The first fix for report #1 made every failed connection "not reached", and
with it three real findings went dark:

  * an HTTP-only site (443 refused, a page on port 80) was scored as a
    geo-blocking bank — `no_https` could never fire again, and
    sber-vyplata-kompensacii.ru came back 'safe, 11' with the text "many banks
    block foreign connections";
  * an expired, self-signed or wrong-name certificate — a full-page browser
    warning anywhere in the world — got the same geo-blocking explanation;
  * a redirect loop was "unreachable".

Plus two probe bugs: redirects were followed to any host (a 30x to an
internal address was requested, unvetted), and a host whose IDNA 2008 name
re-encodes differently (straße.de) "redirected" to itself (+20).
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import time

import pytest

from api.models.schemas import RiskLevel
from api.services import site_probes
from api.services.analyzer import analyze_domain


def _codes(result) -> set[str]:
    return {r.signal for r in result.reasons}


# ── Plain HTTP on port 80, when 443 refuses ──

class _Port80:
    """A socket that answers one HTTP request with `head`."""

    def __init__(self, head: bytes):
        self._head = head
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def sendall(self, data):
        self.sent += data

    def settimeout(self, value):
        pass

    def recv(self, n):
        chunk, self._head = self._head[:n], self._head[n:]
        return chunk


def _network(port443_error, port80_head=None):
    """create_connection stand-in: 443 fails with `port443_error`; port 80
    answers `port80_head`, or refuses when that is None."""
    port80 = _Port80(port80_head) if port80_head is not None else None

    def _connect(address, timeout=None):
        _host, port = address
        if port == 443:
            raise port443_error
        if port80 is None:
            raise ConnectionRefusedError()
        return port80

    return _connect, port80


@pytest.mark.parametrize("port443_error", [
    ConnectionRefusedError(),
    ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number"),
    ssl.SSLError(1, "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure"),
])
def test_http_only_site_is_measured_as_no_https(monkeypatch, port443_error):
    connect, port80 = _network(port443_error, b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>")
    monkeypatch.setattr(site_probes.socket, "create_connection", connect)
    out = asyncio.run(site_probes.check_ssl("sber-vyplata-kompensacii.ru"))
    assert out == {"reachable": True, "has_ssl": False, "http_only": True}
    assert port80.sent.startswith(b"GET / HTTP/1.1\r\nHost: sber-vyplata-kompensacii.ru\r\n")


def test_plain_http_that_stays_on_http_counts(monkeypatch):
    connect, _ = _network(ConnectionRefusedError(), b"HTTP/1.1 302 Found\r\nLocation: /cabinet\r\n\r\n")
    monkeypatch.setattr(site_probes.socket, "create_connection", connect)
    assert asyncio.run(site_probes.check_ssl("x-shop.ru"))["has_ssl"] is False


@pytest.mark.parametrize("head", [
    b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://bankspb.ru/\r\n\r\n",  # wants HTTPS
    b"HTTP/1.1 403 Forbidden\r\n\r\nAccess from your country is denied",        # a block page
    b"SSH-2.0-OpenSSH_9.6\r\n",                                                  # not HTTP at all
])
def test_port_80_that_is_not_a_plain_http_site_proves_nothing(monkeypatch, head):
    connect, _ = _network(ConnectionRefusedError(), head)
    monkeypatch.setattr(site_probes.socket, "create_connection", connect)
    out = asyncio.run(site_probes.check_ssl("bankspb.ru"))
    assert out == {"reachable": False, "error": "refused"}


@pytest.mark.parametrize("port443_error", [
    socket.timeout("timed out"),          # a firewall that drops
    ConnectionResetError(),               # a firewall that resets
    ssl.SSLEOFError(8, "EOF occurred in violation of protocol"),  # dropped mid-handshake
])
def test_firewall_like_failures_never_try_port_80(monkeypatch, port443_error):
    """A foreign-visitor firewall must not be read as "no HTTPS", whatever
    port 80 would show us."""
    connect, port80 = _network(port443_error, b"HTTP/1.1 200 OK\r\n\r\n")
    monkeypatch.setattr(site_probes.socket, "create_connection", connect)
    out = asyncio.run(site_probes.check_ssl("rosreestr.gov.ru"))
    assert out["reachable"] is False
    assert port80.sent == b""


def test_parse_head():
    assert site_probes._parse_head(b"HTTP/1.0 200 OK\r\nServer: x\r\n\r\n") == (200, None)
    assert site_probes._parse_head(b"HTTP/1.1 302 Found\r\nlocation:  http://a.ru/ \r\n\r\n") == (302, "http://a.ru/")
    assert site_probes._parse_head(b"") is None
    assert site_probes._parse_head(b"garbage") is None


def test_trickling_port_80_cannot_hold_the_thread():
    """One byte at a time forever: the read gives up at the probe's total
    budget instead of pinning a worker thread for hours."""
    class _Trickle(_Port80):
        def recv(self, n):
            time.sleep(0.01)
            return b"x"

    t0 = time.monotonic()
    raw = site_probes._read_head(_Trickle(b""), time.monotonic() + 0.2)
    assert time.monotonic() - t0 < 1.0
    assert b"\r\n\r\n" not in raw


# ── Certificates: broken is measured, unknown authority is not ──

def _cert_error(code: int, message: str) -> ssl.SSLCertVerificationError:
    err = ssl.SSLCertVerificationError(1, f"[SSL: CERTIFICATE_VERIFY_FAILED] {message}")
    err.verify_code = code
    err.verify_message = message
    return err


class _Tcp:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.mark.parametrize("code, message, problem", [
    (10, "certificate has expired", "expired"),
    (18, "self signed certificate", "self_signed"),
    (62, "Hostname mismatch, certificate is not valid for 'x.ru'", "wrong_host"),
    (9, "certificate is not yet valid", "not_yet_valid"),
])
def test_broken_certificate_is_a_finding(monkeypatch, code, message, problem):
    monkeypatch.setattr(site_probes.socket, "create_connection", lambda *a, **k: _Tcp())
    ctx = ssl.create_default_context()

    def _wrap(sock, server_hostname=None):
        raise _cert_error(code, message)

    monkeypatch.setattr(ctx, "wrap_socket", _wrap)
    monkeypatch.setattr(site_probes.ssl, "create_default_context", lambda: ctx)
    out = asyncio.run(site_probes.check_ssl("x.ru"))
    assert out == {"reachable": True, "has_ssl": True, "certificate_problem": problem}


@pytest.mark.parametrize("code", [20, 21, 19])
def test_unknown_authority_is_not_a_finding(monkeypatch, code):
    """Russian sites signed by the national CA fail verification here and are
    fine at home: "not reached", never a penalty."""
    monkeypatch.setattr(site_probes.socket, "create_connection", lambda *a, **k: _Tcp())
    ctx = ssl.create_default_context()

    def _wrap(sock, server_hostname=None):
        raise _cert_error(code, "unable to get local issuer certificate")

    monkeypatch.setattr(ctx, "wrap_socket", _wrap)
    monkeypatch.setattr(site_probes.ssl, "create_default_context", lambda: ctx)
    assert asyncio.run(site_probes.check_ssl("sberbank-partner.ru")) == {
        "reachable": False, "error": "tls_certificate",
    }


# ── End to end: the findings reach the verdict, with honest reasons ──

def test_http_only_phishing_page_is_no_longer_safe(offline_analyzer, monkeypatch):
    offline_analyzer(site="unreachable")
    connect, _ = _network(ConnectionRefusedError(), b"HTTP/1.1 200 OK\r\n\r\n")
    monkeypatch.setattr(site_probes.socket, "create_connection", connect)
    result = asyncio.run(analyze_domain("sber-vyplata-kompensacii.ru", budget_s=5.0))
    assert "no_https" in _codes(result)
    assert "unreachable_from_scanner" not in _codes(result)
    assert result.level != RiskLevel.safe
    assert result.has_ssl is False
    assert result.verdict_basis not in {"unreachable", "blocklist", "threat_intel"}


def test_expired_certificate_is_explained_as_such(offline_analyzer, monkeypatch):
    offline_analyzer(site="unreachable")
    monkeypatch.setattr(site_probes.socket, "create_connection", lambda *a, **k: _Tcp())
    ctx = ssl.create_default_context()

    def _wrap(sock, server_hostname=None):
        raise _cert_error(10, "certificate has expired")

    monkeypatch.setattr(ctx, "wrap_socket", _wrap)
    monkeypatch.setattr(site_probes.ssl, "create_default_context", lambda: ctx)
    result = asyncio.run(analyze_domain("old-shop.ru", budget_s=5.0))
    reason = next(r for r in result.reasons if r.signal == "invalid_certificate")
    assert reason.weight > 0 and "expired" in reason.detail
    assert "unreachable_from_scanner" not in _codes(result)


# ── Redirects: followed by hand, every hop vetted ──

def test_redirect_to_an_internal_address_is_never_requested(probe_web):
    requested = probe_web(
        {"https://evil.example/": (302, {"location": "http://169.254.169.254/latest/meta-data/"})},
        unsafe={"169.254.169.254"},
    )
    out = asyncio.run(site_probes.check_redirect_chain("evil.example"))
    assert [u for _, u in requested] == ["https://evil.example/"]
    assert out["reachable"] is True and out["cross_domain"] is True


def test_headers_probe_never_follows_to_an_internal_address(probe_web):
    requested = probe_web(
        {"https://evil.example/": (301, {"location": "https://127.0.0.1:6379/"})},
        unsafe={"127.0.0.1"},
    )
    out = asyncio.run(site_probes.check_security_headers("evil.example"))
    assert [u for _, u in requested] == ["https://evil.example/"]
    assert out == {"reachable": True, "present": [], "missing": None}


def test_redirect_loop_is_a_finding_not_unreachable(probe_web):
    probe_web({
        "https://loop.example/": (302, {"location": "https://loop.example/a"}),
        "https://loop.example/a": (302, {"location": "https://loop.example/"}),
    })
    out = asyncio.run(site_probes.check_redirect_chain("loop.example"))
    assert out["reachable"] is True
    assert out["count"] > 5  # past what we follow → "suspicious redirect chain"


def test_headers_are_read_after_the_redirects(probe_web):
    probe_web({
        "https://shop.example/": (301, {"location": "https://www.shop.example/"}),
        "https://www.shop.example/": (200, {"strict-transport-security": "max-age=1"}),
    })
    out = asyncio.run(site_probes.check_security_headers("shop.example"))
    assert out["present"] == ["strict-transport-security"]


@pytest.mark.parametrize("domain", [
    "xn--strae-oqa.de",   # straße.de — IDNA 2003 would re-encode it as strasse.de
    "xn--fa-hia.de",      # faß.de
    "xn--mxa8ab.gr",      # a final sigma
])
def test_idna2008_host_does_not_redirect_to_itself(probe_web, domain):
    probe_web({})
    out = asyncio.run(site_probes.check_redirect_chain(domain))
    assert out["cross_domain"] is False and out["domains_visited"] == []


def test_idna2008_hop_to_own_www_is_not_cross_domain(probe_web):
    probe_web({"https://xn--strae-oqa.de/": (301, {"location": "https://www.straße.de/"})})
    out = asyncio.run(site_probes.check_redirect_chain("xn--strae-oqa.de"))
    assert out["cross_domain"] is False
    assert out["domains_visited"] == ["www.xn--strae-oqa.de"]


# ── A probe has a TOTAL time limit, not only per phase ──

def test_slow_trickling_site_is_cut_at_the_probe_total(monkeypatch):
    class _Slow:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url):
            await asyncio.sleep(30)

        head = get

    monkeypatch.setattr(site_probes.httpx, "AsyncClient", _Slow)
    monkeypatch.setattr(site_probes, "SITE_PROBE_TOTAL_S", 0.2)
    t0 = time.monotonic()
    out = asyncio.run(site_probes.check_redirect_chain("slow.example"))
    assert time.monotonic() - t0 < 1.0
    assert out["reachable"] is False and out["error"] == "timeout"

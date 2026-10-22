"""SSRF guard and site probes: the edges tests/test_ssrf_hardening.py and
tests/test_site_probe_findings.py leave open.

domain_validator
  - user input normalisation: URLs with credentials / ports / paths, IPv6
    literals, octal / hex / decimal IPv4 spellings, overlong names;
  - more non-public address forms (IPv4-compatible IPv6, IPv4-translated,
    6to4 / NAT64 wrapping private space, CGNAT behind ::ffff:);
  - resolver answers that are unusable, empty, or mix public and private;
  - the IANA TLD list missing: names are no longer checked against the root
    zone, but every address still is;
  - the real resolver seam asks for TCP only.

site_probes
  - a completed TLS handshake is described (issuer, free CA, certificate age);
  - a handshake that hangs is cut at the probe total;
  - failure kinds, IDNA edge cases, aggregate reachability helpers.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from api.services import domain_validator as dv
from api.services import site_probes

# Captured at import (collection) time, before the autouse fixture in
# tests/conftest.py swaps the resolver seam for a hermetic one.
_REAL_GETADDRINFO = dv._getaddrinfo


def _answers(*addresses):
    def _gai(host, port):
        out = []
        for a in addresses:
            fam = socket.AF_INET6 if ":" in a else socket.AF_INET
            sockaddr = (a, port, 0, 0) if fam == socket.AF_INET6 else (a, port)
            out.append((fam, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
        return out
    return _gai


# ── validate_domain: what a user may submit for analysis ──

@pytest.mark.parametrize("raw, expected", [
    ("https://Example.com/login?x=1", "example.com"),
    ("http://user:pw@shop.example.com:8080/a", "shop.example.com"),
    ("example.com:8443", "example.com"),
    ("  EXAMPLE.org/ ", "example.org"),
    ("8.8.8.8", "8.8.8.8"),                       # a public IP literal may be analysed
    ("https://8.8.8.8/", "8.8.8.8"),
])
def test_validate_domain_normalises_user_input(raw, expected):
    assert dv.validate_domain(raw) == expected


@pytest.mark.parametrize("raw", [
    "http://127.0.0.1/",
    "http://user:pw@127.0.0.1:80/",               # credentials do not hide the host
    "HTTP://169.254.169.254/latest/meta-data",
    "http://evil.example@10.0.0.1/",              # userinfo trick: the host is 10.0.0.1
    "192.168.0.1:8080",
    "0.0.0.0",
    "localhost",
    "http://localhost:6379/",
])
def test_validate_domain_refuses_internal_targets_as_ssrf(raw):
    with pytest.raises(dv.SSRFBlocked):
        dv.validate_domain(raw)


@pytest.mark.parametrize("raw", [
    "010.0.0.1",          # leading zero: octal 8.0.0.1 to some parsers, 10.0.0.1 to others
    "0177.0.0.1",         # octal loopback
    "0x7f.0.0.1",         # hex loopback
    "0x7f000001",
    "2130706433",         # decimal loopback
    "017700000001",
    "127.1",              # short form
    "999.1.1.1",
    "http://[::1]/",
    "[::ffff:127.0.0.1]",
    "::ffff:169.254.169.254",
    "a" * 250 + ".com",   # over 253 characters
    "http://",            # nothing left after normalisation
    "https://:443/",
])
def test_validate_domain_refuses_obfuscated_or_malformed_hosts(raw):
    with pytest.raises(dv.DomainValidationError):
        dv.validate_domain(raw)


def test_leading_zero_ip_is_not_read_as_octal_or_decimal():
    with pytest.raises(dv.DomainValidationError, match="Invalid IP address"):
        dv.validate_domain("010.0.0.1")


# ── which addresses are public (forms not pinned elsewhere) ──

@pytest.mark.parametrize("address", [
    "::7f00:1", "::127.0.0.1",                    # IPv4-compatible (deprecated) loopback
    "::ffff:0:7f00:1", "::ffff:0:a00:1",          # IPv4-translated
    "::ffff:100.64.0.1",                          # CGNAT behind IPv4-mapped
    "::ffff:0.0.0.0",
    "2002:c0a8:0101::1",                          # 6to4 wrapping 192.168.1.1
    "64:ff9b::c0a8:101",                          # NAT64 wrapping 192.168.1.1
    "64:ff9b::",                                  # NAT64 of 0.0.0.0
    "2002::",                                     # 6to4 of 0.0.0.0
    "ff05::1",                                    # site-local multicast
    "100::1",                                     # discard-only
    "2001:2::1", "2001:10::1",                    # benchmarking / ORCHID
])
def test_more_non_public_addresses_are_refused(address):
    assert dv.is_public_address(ipaddress.ip_address(address)) is False


def test_scoped_ipv6_is_never_public():
    assert dv.is_public_address(ipaddress.ip_address("2606:4700::1%eth0")) is False


# ── resolve_public_sync ──

@pytest.mark.parametrize("literal, expected", [
    ("8.8.8.8", ["8.8.8.8"]),
    ("[2606:4700:4700::1111]", ["2606:4700:4700::1111"]),
    ("2606:4700:4700::1111", ["2606:4700:4700::1111"]),
])
def test_public_ip_literals_are_returned_without_a_lookup(monkeypatch, literal, expected):
    def _never(host, port):
        raise AssertionError("an IP literal must not be looked up")
    monkeypatch.setattr(dv, "_getaddrinfo", _never)
    assert dv.resolve_public_sync(literal, 443) == expected


@pytest.mark.parametrize("host", [
    "0177.0.0.1", "0x7f000001", "2130706433", "127.1", "[::ffff:127.0.0.1]", "[fe80::1%25eth0]", "::", "0.0.0.0",
])
def test_obfuscated_loopback_spellings_never_connect(monkeypatch, host):
    looked_up = []

    def _gai(h, port):
        looked_up.append(h)
        return _answers("127.0.0.1")(h, port)
    monkeypatch.setattr(dv, "_getaddrinfo", _gai)
    with pytest.raises(dv.DomainValidationError):
        dv.resolve_public_sync(host, 443)
    assert looked_up == []


@pytest.mark.parametrize("host", ["", "   ", "."])
def test_empty_host_is_refused(host):
    with pytest.raises(dv.DomainValidationError):
        dv.check_hostname_policy(host)
    with pytest.raises(dv.DomainValidationError):
        dv.resolve_public_sync(host, 443)


def test_unparsable_resolver_answer_is_blocked(monkeypatch):
    monkeypatch.setattr(dv, "_getaddrinfo", _answers("93.184.216.34", "not-an-address"))
    with pytest.raises(dv.SSRFBlocked, match="unusable address"):
        dv.resolve_public_sync("odd.example.com", 443)


def test_resolver_with_no_answers_is_host_not_found(monkeypatch):
    monkeypatch.setattr(dv, "_getaddrinfo", lambda host, port: [])
    with pytest.raises(dv.HostNotFound):
        dv.resolve_public_sync("empty.example.com", 443)


def test_name_the_idna_codec_cannot_encode_is_host_not_found(monkeypatch):
    def _gai(host, port):
        raise UnicodeError("label too long")
    monkeypatch.setattr(dv, "_getaddrinfo", _gai)
    with pytest.raises(dv.HostNotFound):
        dv.resolve_public_sync("x.example.com", 443)


@pytest.mark.parametrize("answers", [
    ("2606:4700::1", "::1"),
    ("93.184.216.34", "::ffff:10.0.0.1"),
    ("93.184.216.34", "fd00::1"),
    ("2606:4700::1", "64:ff9b::a9fe:a9fe"),     # NAT64 to the metadata address
])
def test_dual_stack_answer_with_one_private_family_is_refused(monkeypatch, answers):
    monkeypatch.setattr(dv, "_getaddrinfo", _answers(*answers))
    with pytest.raises(dv.SSRFBlocked):
        dv.resolve_public_sync("dual.example.com", 443)


def test_plain_http_port_is_allowed(monkeypatch):
    monkeypatch.setattr(dv, "_getaddrinfo", _answers("93.184.216.34"))
    assert dv.resolve_public_sync("example.com", 80) == ["93.184.216.34"]


def test_analyzer_gate_lets_a_missing_name_through(monkeypatch):
    def _nx(host, port):
        raise socket.gaierror(socket.EAI_NONAME, "unknown")
    monkeypatch.setattr(dv, "_getaddrinfo", _nx)
    assert asyncio.run(dv.validate_domain_resolution("does-not-exist.example.com")) is None


def test_analyzer_gate_refuses_a_private_answer(monkeypatch):
    monkeypatch.setattr(dv, "_getaddrinfo", _answers("10.0.0.5"))
    with pytest.raises(dv.SSRFBlocked):
        asyncio.run(dv.validate_domain_resolution("rebind.example.com"))


# ── degraded mode: data/iana_tlds.txt missing ──

def test_missing_tld_list_is_logged_and_empty(monkeypatch, caplog):
    monkeypatch.setattr(dv, "__file__", "/nonexistent/api/services/domain_validator.py")
    with caplog.at_level("WARNING", logger="cleanway.domain_validator"):
        assert dv._load_known_tlds() == frozenset()
    assert "iana_tlds.txt missing" in caplog.text


def test_without_the_tld_list_addresses_are_still_checked(monkeypatch):
    monkeypatch.setattr(dv, "_KNOWN_TLDS", frozenset())
    dv.check_hostname_policy("intranet.corp")         # no root zone to check against
    monkeypatch.setattr(dv, "_getaddrinfo", _answers("10.1.2.3"))
    with pytest.raises(dv.SSRFBlocked):
        dv.resolve_public_sync("intranet.corp", 443)
    # Private suffixes are refused regardless of the list.
    with pytest.raises(dv.SSRFBlocked):
        dv.check_hostname_policy("redis.railway.internal")


# ── the real resolver seam ──

def test_real_resolver_asks_for_tcp_stream_answers_only(monkeypatch):
    seen = {}

    def _gai(host, port, family, type_, proto):
        seen.update(host=host, port=port, family=family, type=type_, proto=proto)
        return []
    monkeypatch.setattr(dv.socket, "getaddrinfo", _gai)
    assert _REAL_GETADDRINFO("example.com", 443) == []
    assert seen == {"host": "example.com", "port": 443, "family": 0,
                    "type": socket.SOCK_STREAM, "proto": socket.IPPROTO_TCP}


# ── site_probes: a completed TLS handshake ──

class _Tcp:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _TlsSock(_Tcp):
    def __init__(self, cert):
        self._cert = cert

    def getpeercert(self):
        return self._cert


def _handshake(monkeypatch, cert):
    """TCP + TLS succeed and the server presents `cert`. Returns the list of
    (address, port) connected to and the SNI names sent."""
    connected, sni = [], []

    def _connect(address, timeout=None):
        connected.append(address)
        return _Tcp()
    ctx = ssl.create_default_context()

    def _wrap(sock, server_hostname=None):
        sni.append(server_hostname)
        return _TlsSock(cert)
    monkeypatch.setattr(ctx, "wrap_socket", _wrap)
    monkeypatch.setattr(site_probes.ssl, "create_default_context", lambda: ctx)
    monkeypatch.setattr(site_probes.socket, "create_connection", _connect)
    return connected, sni


def _not_before(days_ago: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime("%b %d %H:%M:%S %Y GMT")


def test_completed_handshake_describes_the_certificate(monkeypatch):
    cert = {
        "issuer": ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),), (("commonName", "R11"),)),
        "notBefore": _not_before(40),
    }
    connected, sni = _handshake(monkeypatch, cert)
    out = asyncio.run(site_probes.check_ssl("shop.example.com"))
    assert out == {"reachable": True, "has_ssl": True, "issuer": "Let's Encrypt", "is_free_ssl": True,
                   "cert_age_days": 40}
    # Connected to the vetted address (conftest resolves every name to it), SNI is the name.
    assert connected == [("93.184.216.34", 443)]
    assert sni == ["shop.example.com"]


def test_free_ca_is_recognised_by_its_common_name(monkeypatch):
    cert = {"issuer": ((("organizationName", "Example Trust"),), (("commonName", "ZeroSSL RSA CA"),)),
            "notBefore": _not_before(1)}
    _handshake(monkeypatch, cert)
    out = asyncio.run(site_probes.check_ssl("x.example.com"))
    assert out["is_free_ssl"] is True and out["issuer"] == "Example Trust"


@pytest.mark.parametrize("cert", [None, {}, {"notBefore": "yesterday-ish"}, {"notBefore": None}])
def test_sparse_or_odd_certificate_is_reported_without_guessing(monkeypatch, cert):
    _handshake(monkeypatch, cert)
    out = asyncio.run(site_probes.check_ssl("x.example.com"))
    assert out == {"reachable": True, "has_ssl": True, "issuer": "Unknown", "is_free_ssl": False,
                   "cert_age_days": None}


def test_tls_probe_to_an_internal_answer_reports_not_connectable(monkeypatch):
    monkeypatch.setattr(dv, "_getaddrinfo", _answers("::ffff:127.0.0.1"))

    def _connect(*a, **k):
        raise AssertionError("must not connect")
    monkeypatch.setattr(site_probes.socket, "create_connection", _connect)
    assert asyncio.run(site_probes.check_ssl("rebind.example.com")) == {"reachable": False, "error": "network"}


def test_tls_probe_for_a_missing_name_is_dns(monkeypatch):
    def _nx(host, port):
        raise socket.gaierror(socket.EAI_NONAME, "unknown")
    monkeypatch.setattr(dv, "_getaddrinfo", _nx)
    assert asyncio.run(site_probes.check_ssl("nx.example.com")) == {"reachable": False, "error": "dns"}


def test_a_handshake_that_hangs_is_cut_at_the_probe_total(monkeypatch):
    def _hang(domain):
        time.sleep(0.8)
        return {"reachable": True}
    monkeypatch.setattr(site_probes, "_check_ssl_sync", _hang)
    monkeypatch.setattr(site_probes, "SITE_PROBE_TOTAL_S", 0.05)

    async def _timed():
        t0 = time.monotonic()
        out = await site_probes.check_ssl("slow.example.com")
        return out, time.monotonic() - t0

    # (asyncio.run itself then waits for the worker thread to finish.)
    out, elapsed = asyncio.run(_timed())
    assert elapsed < 0.7
    assert out == {"reachable": False, "error": "timeout"}


def test_port_80_is_not_tried_once_the_deadline_has_passed(monkeypatch):
    def _connect(*a, **k):
        raise AssertionError("no time left: nothing may be contacted")
    monkeypatch.setattr(site_probes.socket, "create_connection", _connect)
    assert site_probes._plain_http_head("x.example.com", "93.184.216.34", time.monotonic() - 1) is None
    assert site_probes._serves_plain_http("x.example.com", "93.184.216.34", time.monotonic() - 1) is False


# ── failure kinds ──

def _wrapped(httpx_exc_cls, cause):
    try:
        try:
            raise cause
        except BaseException as inner:
            raise httpx_exc_cls("wrapped") from inner
    except httpx.HTTPError as exc:
        return exc


@pytest.mark.parametrize("exc, kind", [
    (httpx.TooManyRedirects("loop"), "too_many_redirects"),
    (_wrapped(httpx.ConnectError, socket.gaierror(socket.EAI_NONAME, "unknown")), "dns"),
    (_wrapped(httpx.ConnectError, ConnectionRefusedError()), "refused"),
    (_wrapped(httpx.ReadError, ConnectionResetError()), "reset"),
    (_wrapped(httpx.ConnectError, ssl.SSLError(1, "handshake failure")), "tls_handshake"),
    (httpx.ConnectTimeout("slow"), "timeout"),
    (asyncio.TimeoutError(), "timeout"),
    (RuntimeError("thread pool gone"), "network"),
])
def test_failure_kind(exc, kind):
    assert site_probes.failure_kind(exc) == kind


# ── host spelling ──

def test_ascii_host_keeps_a_name_idna_cannot_encode():
    long_label = "a" * 64 + ".example.com"            # a label over 63 octets
    assert site_probes.ascii_host(long_label.upper() + ".") == long_label
    assert site_probes.ascii_host("Пример.РФ") == "xn--e1afmkfd.xn--p1ai"
    assert site_probes.ascii_host(None) == ""


# ── aggregating probe results ──

def test_site_reachability():
    up, down = {"reachable": True}, {"reachable": False, "error": "timeout"}
    assert site_probes.site_reachability(down, up) is True
    assert site_probes.site_reachability(down, {}, None) is False
    assert site_probes.site_reachability({}, None) is None
    assert site_probes.site_reachability() is None


def test_first_failure_prefers_the_first_probe_that_failed():
    tls = {"reachable": False, "error": "tls_certificate"}
    headers = {"reachable": False, "error": "timeout"}
    assert site_probes.first_failure(None, {"reachable": True}, tls, headers) == "tls_certificate"
    assert site_probes.first_failure({"reachable": True}, {}, None) is None
    assert site_probes.first_failure() is None

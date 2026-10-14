"""SSRF hardening (audit 2026-10-14).

The guard used to be a fixed list of IPv4/IPv6 ranges, checked once before
the probes connected BY NAME. That let through:

  * IPv6 forms that carry an internal IPv4 address (::ffff:127.0.0.1, 6to4
    2002:7f00:1::, NAT64 64:ff9b::a9fe:a9fe) and Teredo;
  * DNS rebinding — the probes resolved the name again at connect time;
  * redirects to any port (https://evil.example:6379/);
  * internal names (redis.railway.internal): the anonymous public check
    answered "resolves to a blocked network", which maps our private
    network by name.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl

import httpx
import pytest

from api.services import domain_validator as dv
from api.services import site_probes
from api.services.pinned_http import BlockedDestination, PinnedTransport


def _answers(*addresses):
    """A getaddrinfo stand-in answering `addresses` for every name."""
    calls = []

    def _gai(host, port):
        calls.append((host, port))
        out = []
        for a in addresses:
            fam = socket.AF_INET6 if ":" in a else socket.AF_INET
            sockaddr = (a, port, 0, 0) if fam == socket.AF_INET6 else (a, port)
            out.append((fam, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", sockaddr))
        return out

    return _gai, calls


# ── Which addresses are public ──

@pytest.mark.parametrize("address", [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1",
    "169.254.169.254",                    # cloud metadata
    "100.64.0.1", "100.127.255.254",      # CGNAT (Railway's private network uses it)
    "0.0.0.0", "224.0.0.1", "240.0.0.1", "255.255.255.255",
    "198.18.0.1", "192.0.0.8", "192.0.2.1",
    "::1", "::", "fc00::1", "fd12:3456:789a::1", "fe80::1", "ff02::1", "fec0::1",
    "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:169.254.169.254",   # IPv4-mapped
    "2002:7f00:1::1", "2002:a9fe:a9fe::1", "2002:0a00:0001::",          # 6to4
    "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::a00:1",         # NAT64
    "64:ff9b:1::808:808",                                               # local-use NAT64
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",                             # Teredo
    "2001:db8::1",                                                      # documentation
])
def test_non_public_addresses_are_refused(address):
    assert dv.is_public_address(ipaddress.ip_address(address)) is False


@pytest.mark.parametrize("address", [
    "8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111",
    "::ffff:8.8.8.8", "2002:0808:0808::1", "64:ff9b::808:808",
])
def test_public_addresses_pass(address):
    assert dv.is_public_address(ipaddress.ip_address(address)) is True


# ── Which names may be connected to ──

@pytest.mark.parametrize("host", [
    "redis.railway.internal", "postgres.internal", "printer.local", "app.localhost",
    "localhost", "redis", "router.home.arpa", "1.0.0.127.in-addr.arpa",
    "foo.notarealtld", "evil.corp", "x.lan",
])
def test_private_or_unknown_names_are_refused(host):
    with pytest.raises(dv.DomainValidationError):
        dv.check_hostname_policy(host)


@pytest.mark.parametrize("host", [
    "example.com", "www.barclays.co.uk", "xn--e1afmkfd.xn--p1ai", "EXAMPLE.COM.", "93.184.216.34",
])
def test_public_names_pass(host):
    dv.check_hostname_policy(host)


def test_a_refused_name_is_never_looked_up(monkeypatch):
    gai, calls = _answers("93.184.216.34")
    monkeypatch.setattr(dv, "_getaddrinfo", gai)
    with pytest.raises(dv.DomainValidationError):
        dv.resolve_public_sync("redis.railway.internal", 443)
    assert calls == []


# ── Resolution: every answer must be public ──

def test_public_answers_are_returned(monkeypatch):
    monkeypatch.setattr(dv, "_getaddrinfo", _answers("93.184.216.34", "2606:4700::1", "93.184.216.34")[0])
    assert dv.resolve_public_sync("example.com", 443) == ["93.184.216.34", "2606:4700::1"]


@pytest.mark.parametrize("answers", [
    ("10.0.0.5",),
    ("93.184.216.34", "127.0.0.1"),          # one bad answer spoils the lot
    ("::ffff:169.254.169.254",),
    ("2002:7f00:1::1",),
    ("64:ff9b::7f00:1",),
    ("2001:0:4136:e378:8000:63bf:3fff:fdd2",),
    ("fe80::1%eth0",),                        # scoped link-local
    ("100.64.12.7",),
])
def test_any_internal_answer_is_refused(monkeypatch, answers):
    monkeypatch.setattr(dv, "_getaddrinfo", _answers(*answers)[0])
    with pytest.raises(dv.DomainValidationError) as err:
        dv.resolve_public_sync("rebind.example.com", 443)
    assert not isinstance(err.value, dv.HostNotFound)


def test_a_name_that_does_not_resolve_is_host_not_found(monkeypatch):
    def _nx(host, port):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    monkeypatch.setattr(dv, "_getaddrinfo", _nx)
    with pytest.raises(dv.HostNotFound):
        dv.resolve_public_sync("nothing-here.com", 443)
    # The analyzer's gate lets a dead name through to the WHOIS/reputation checks.
    asyncio.run(dv.validate_domain_resolution("nothing-here.com"))


@pytest.mark.parametrize("port", [22, 6379, 8080, 5432, 0])
def test_only_web_ports(port):
    with pytest.raises(dv.DomainValidationError):
        dv.resolve_public_sync("example.com", port)


@pytest.mark.parametrize("literal", ["127.0.0.1", "[::1]", "::ffff:10.0.0.1", "169.254.169.254"])
def test_internal_ip_literals_are_refused(literal):
    with pytest.raises(dv.DomainValidationError):
        dv.resolve_public_sync(literal, 443)


def test_the_analyzer_gate_refuses_internal_names_and_answers():
    with pytest.raises(dv.DomainValidationError):
        asyncio.run(dv.validate_domain_resolution("redis.railway.internal"))


# ── The transport connects to the address it checked ──

class _Recorder(httpx.AsyncBaseTransport):
    def __init__(self):
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request):
        self.requests.append(request)
        return httpx.Response(200, request=request)


def _resolver(mapping):
    async def _resolve(host, port):
        answer = mapping[host]
        if isinstance(answer, Exception):
            raise answer
        return answer
    return _resolve


def test_https_request_is_pinned_with_host_and_sni():
    inner = _Recorder()
    transport = PinnedTransport(resolver=_resolver({"shop.example.com": ["93.184.216.34"]}), inner=inner)

    async def go():
        async with httpx.AsyncClient(transport=transport) as c:
            return await c.get("https://shop.example.com/login?x=1")

    resp = asyncio.run(go())
    sent = inner.requests[0]
    assert sent.url.host == "93.184.216.34"
    assert sent.url.raw_path == b"/login?x=1"
    assert sent.headers["host"] == "shop.example.com"
    assert sent.extensions["sni_hostname"] == "shop.example.com"
    assert str(resp.url) == "https://shop.example.com/login?x=1"  # callers see the name


def test_ipv6_answer_is_pinned():
    inner = _Recorder()
    transport = PinnedTransport(resolver=_resolver({"v6.example.com": ["2606:4700::1"]}), inner=inner)

    async def go():
        async with httpx.AsyncClient(transport=transport) as c:
            await c.get("http://v6.example.com/")

    asyncio.run(go())
    sent = inner.requests[0]
    assert sent.url.host == "2606:4700::1" and sent.url.scheme == "http"
    assert "sni_hostname" not in sent.extensions
    assert sent.headers["host"] == "v6.example.com"


def test_rebinding_answer_is_never_contacted():
    """The name's answer at connect time is internal: nothing is sent."""
    inner = _Recorder()
    transport = PinnedTransport(
        resolver=_resolver({"rebind.example.com": dv.DomainValidationError("resolves to 127.0.0.1")}),
        inner=inner,
    )

    async def go():
        async with httpx.AsyncClient(transport=transport) as c:
            await c.get("https://rebind.example.com/")

    with pytest.raises(BlockedDestination):
        asyncio.run(go())
    assert inner.requests == []


def test_transport_uses_the_real_guard_by_default(monkeypatch):
    """No resolver injected: the domain_validator guard decides (port too)."""
    inner = _Recorder()
    transport = PinnedTransport(inner=inner)
    monkeypatch.setattr(dv, "_getaddrinfo", _answers("127.0.0.1")[0])

    async def go(url):
        async with httpx.AsyncClient(transport=transport) as c:
            await c.get(url)

    for url in ("https://loopback.example.com/", "https://example.com:6379/", "http://10.0.0.1/"):
        with pytest.raises(BlockedDestination):
            asyncio.run(go(url))
    assert inner.requests == []


# ── Site probes ──

def test_tls_probe_connects_to_the_vetted_address(monkeypatch):
    monkeypatch.setattr(dv, "_getaddrinfo", _answers("93.184.216.34")[0])
    seen = {}

    class _Tcp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _connect(address, timeout=None):
        seen["address"] = address
        return _Tcp()

    ctx = ssl.create_default_context()

    def _wrap(sock, server_hostname=None):
        seen["sni"] = server_hostname
        raise ssl.SSLEOFError(8, "EOF")

    monkeypatch.setattr(ctx, "wrap_socket", _wrap)
    monkeypatch.setattr(site_probes.ssl, "create_default_context", lambda: ctx)
    monkeypatch.setattr(site_probes.socket, "create_connection", _connect)
    asyncio.run(site_probes.check_ssl("shop.example.com"))
    assert seen == {"address": ("93.184.216.34", 443), "sni": "shop.example.com"}


def test_plain_http_fallback_uses_the_same_address(monkeypatch):
    monkeypatch.setattr(dv, "_getaddrinfo", _answers("93.184.216.34")[0])
    addresses = []

    class _Port80:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def sendall(self, data):
            self.sent = data

        def settimeout(self, value):
            pass

        def recv(self, n):
            return b"HTTP/1.1 200 OK\r\n\r\n" if not hasattr(self, "done") and not setattr(self, "done", 1) else b""

    def _connect(address, timeout=None):
        addresses.append(address)
        if address[1] == 443:
            raise ConnectionRefusedError()
        return _Port80()

    monkeypatch.setattr(site_probes.socket, "create_connection", _connect)
    out = asyncio.run(site_probes.check_ssl("http-only.example.com"))
    assert out["http_only"] is True
    assert addresses == [("93.184.216.34", 443), ("93.184.216.34", 80)]


@pytest.mark.parametrize("answer", ["127.0.0.1", "::ffff:169.254.169.254", "100.100.0.1"])
def test_tls_probe_never_connects_to_an_internal_answer(monkeypatch, answer):
    monkeypatch.setattr(dv, "_getaddrinfo", _answers(answer)[0])

    def _connect(*a, **k):
        raise AssertionError("must not connect")

    monkeypatch.setattr(site_probes.socket, "create_connection", _connect)
    assert asyncio.run(site_probes.check_ssl("rebind.example.com")) == {"reachable": False, "error": "network"}


@pytest.mark.parametrize("location", [
    "https://evil.example:6379/",       # Redis port
    "http://evil.example:22/",
    "https://evil.example:8443/",
    "ftp://evil.example/",
])
def test_redirects_to_other_ports_or_schemes_are_never_followed(probe_web, location):
    requested = probe_web({"https://start.example/": (302, {"location": location})})
    out = asyncio.run(site_probes.check_redirect_chain("start.example"))
    assert [u for _, u in requested] == ["https://start.example/"]
    assert out["reachable"] is True and out["final_url"] is None


def test_redirect_to_an_internal_name_is_refused_before_any_lookup(monkeypatch):
    gai, calls = _answers("93.184.216.34")
    monkeypatch.setattr(dv, "_getaddrinfo", gai)
    for url in ("http://redis.railway.internal/", "https://printer.local/", "https://intranet/"):
        assert asyncio.run(site_probes.target_is_safe(httpx.URL(url))) is False
    assert calls == []


def test_redirect_hop_is_vetted_on_its_own_port(monkeypatch):
    gai, calls = _answers("93.184.216.34")
    monkeypatch.setattr(dv, "_getaddrinfo", gai)
    assert asyncio.run(site_probes.target_is_safe(httpx.URL("http://www.example.com/"))) is True
    assert calls == [("www.example.com", 80)]


# ── The answer for an internal name is the answer for a missing one ──

def test_internal_name_gets_the_not_found_verdict(offline_analyzer, monkeypatch):
    from api.services import analyzer

    offline_analyzer(exists=True)

    async def _blocked(domain):
        raise dv.DomainValidationError("Domain resolves to a blocked IP range")

    monkeypatch.setattr(analyzer, "validate_domain_resolution", _blocked)
    blocked = asyncio.run(analyzer.analyze_domain("redis.railway.internal", budget_s=5.0))

    offline_analyzer(exists=False)
    missing = asyncio.run(analyzer.analyze_domain("redis.railway.internal", budget_s=5.0))
    assert blocked.model_dump() == missing.model_dump()
    assert "ssrf_blocked" not in {r.signal for r in blocked.reasons}


def test_public_check_cannot_tell_internal_from_missing(monkeypatch, redis_down):
    """GET /api/v1/public/check/<name>: an internal name and a name that does
    not exist get byte-identical answers (but the domain itself)."""
    from fastapi.testclient import TestClient

    from api.main import app
    from api.routers import public as public_router
    from api.services import analyzer, dns_checks

    async def _not_listed(domain):
        return None

    monkeypatch.setattr(public_router, "listed_as", _not_listed)

    async def _exists(domain):
        return domain.endswith(".internal")   # the internal one resolves

    monkeypatch.setattr(analyzer, "check_domain_exists", _exists)
    monkeypatch.setattr(dns_checks, "check_domain_exists", _exists)
    monkeypatch.setattr(dv, "_getaddrinfo", _answers("fd12:a1b2::5")[0])  # Railway private v6

    client = TestClient(app)
    internal = client.get("/api/v1/public/check/redis.railway.internal")
    missing = client.get("/api/v1/public/check/redis.railway.nowhere-xyz.com")
    assert internal.status_code == missing.status_code == 200
    a, b = internal.json(), missing.json()
    a.pop("domain"), b.pop("domain")
    for body in (a, b):
        body.pop("checked_at", None)
        body["verdict"] = body["verdict"].replace("redis.railway.internal", "X").replace("redis.railway.nowhere-xyz.com", "X")
    assert a == b
    assert "blocked" not in internal.text.lower()

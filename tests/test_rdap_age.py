"""Domain age and registrar from RDAP (analyzer.check_whois_age).

Until 2026-10-26 the lookup asked https://rdap.org/domain/<name> and did not
follow redirects. rdap.org answers EVERY name with a 302 to the registry's
own server (rdap.org/domain/example.com → rdap.verisign.com/com/v1/domain/
example.com), so the check returned {} for every name since the first
release: domain_new, domain_very_new, free_ssl_new_domain and the registrar
rules never fired.

Now the registry's server comes from IANA's RDAP bootstrap file (RFC 9224,
data.iana.org/rdap/dns.json), kept in memory. rdap.org is not asked at all;
it redirects to the very same servers. What the tests pin:
  * the registrable name is asked (registries answer 404 for a host under it);
  * a hosting / dynamic-DNS tenant is never given its platform's age and
    registrar (vercel.app: 2020, Tucows);
  * a zone with no RDAP server (.ru, .su, .рф, .io, .de …) asks nothing;
  * the registry is contacted over the SSRF-pinned client: https only, public
    addresses only, its redirects never followed;
  * a registry or bootstrap failure is an unmeasured check (it raises),
    never "no data"; a 404 is the registry's real answer and reads as {}.
"""
from __future__ import annotations

import asyncio
import json
import socket
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from api.services import analyzer, domain_validator, pinned_http, scoring

IANA = "https://data.iana.org/rdap/dns.json"
VERISIGN_COM = "https://rdap.verisign.com/com/v1/"
GOOGLE = "https://pubapi.registry.google/rdap/"
BOOTSTRAP = {
    "version": "1.0",
    "publication": "2026-10-22T23:00:04Z",
    "services": [
        [["com"], [VERISIGN_COM]],
        [["app", "dev", "page"], [GOOGLE]],
        [["example"], ["http://rdap.example/", "ftp://rdap.example/"]],
    ],
}


def _record(days_ago: int = 400, registrar: str = "MarkMonitor Inc.", date_text=None) -> dict:
    """A registry's answer, shaped like Verisign's for github.com."""
    registered = datetime.now(timezone.utc) - timedelta(days=days_ago)
    entities = []
    if registrar is not None:
        entities.append({
            "objectClassName": "entity",
            "roles": ["registrar"],
            "publicIds": [{"type": "IANA Registrar ID", "identifier": "292"}],
            "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", registrar]]],
        })
    return {
        "objectClassName": "domain",
        "ldhName": "EXAMPLE.COM",
        "events": [
            {"eventAction": "registration",
             "eventDate": date_text or registered.strftime("%Y-%m-%dT%H:%M:%SZ")},
            {"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
        ],
        "entities": entities,
    }


class _Net:
    """The internet as these tests see it: url → (status, headers, body).

    Every client the lookup opens is a real httpx client on a mock
    transport; behind the SSRF-pinned client the pinning itself stays real
    (the request reaches the mock addressed to the vetted IP, with the name
    in the Host header), so `requested` lists the URL by name."""

    def __init__(self):
        self.routes: dict[str, tuple[int, dict, bytes]] = {
            IANA: (200, {"content-type": "application/json"}, json.dumps(BOOTSTRAP).encode()),
            # rdap.org exactly as it answers live (2026-10-26).
            "https://rdap.org/domain/example.com": (302, {"location": VERISIGN_COM + "domain/example.com"}, b""),
        }
        self.requested: list[str] = []
        self.addressed: list[str] = []
        self.clients = 0

    def serve(self, url: str, status: int = 200, body=None, headers=None) -> None:
        raw = body if isinstance(body, bytes) else json.dumps(body if body is not None else {}).encode()
        self.routes[url] = (status, {"content-type": "application/rdap+json", **(headers or {})}, raw)

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url.copy_with(host=request.headers["host"]))
        self.requested.append(url)
        self.addressed.append(request.url.host)
        status, headers, body = self.routes.get(url, (404, {}, b""))
        return httpx.Response(status, headers=headers, content=body)


@pytest.fixture
def net(monkeypatch) -> _Net:
    the_net = _Net()
    real_client = httpx.AsyncClient

    def _client(*args, **kwargs):
        the_net.clients += 1
        mock = httpx.MockTransport(the_net.handler)
        transport = kwargs.get("transport")
        if isinstance(transport, pinned_http.PinnedTransport):
            transport._inner = mock
        else:
            kwargs["transport"] = mock
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", _client)
    return the_net


def _lookup(domain: str) -> dict:
    return asyncio.run(analyzer.check_whois_age(domain))


# ── What is asked, and of whom ──

def test_age_and_registrar_come_from_the_registry_rdap_org_redirects_to(net):
    """rdap.org answers 302 to the registry; the registry answers 200. The
    lookup now gets the registry's answer."""
    net.serve(VERISIGN_COM + "domain/example.com", body=_record(days_ago=400))

    out = _lookup("example.com")

    assert out["age_days"] == 400
    assert out["registrar"] == "MarkMonitor Inc."
    assert out["registered"].endswith("Z")
    assert net.requested == [IANA, VERISIGN_COM + "domain/example.com"]


def test_the_registrable_name_is_asked_not_the_host(net):
    """Verisign answers 404 for www.github.com: registries only know what they register."""
    net.serve(VERISIGN_COM + "domain/example.com", body=_record(days_ago=12))

    assert _lookup("login.secure.example.com")["age_days"] == 12
    assert net.requested[-1] == VERISIGN_COM + "domain/example.com"


def test_a_young_domain_is_measured_young(net):
    net.serve(VERISIGN_COM + "domain/example.com", body=_record(days_ago=3))
    assert _lookup("example.com")["age_days"] == 3


@pytest.mark.parametrize("domain", ["obscure-shop.ru", "shop.spb.ru", "xn--d1acc2adacm.xn--p1ai", "google.io"])
def test_a_zone_without_an_rdap_server_asks_nothing(net, domain):
    """.ru, .su, .рф, .io, .de have no RDAP server in IANA's file (rdap.org
    answers 404 for them too). Age stays unknown, as it was."""
    assert _lookup(domain) == {}
    assert net.requested == [IANA]


@pytest.mark.parametrize("domain", ["my-shop.vercel.app", "x.github.io", "gedivan.duckdns.org", "b.blogspot.com"])
def test_a_platform_tenant_is_not_given_its_platform_age(net, domain):
    """vercel.app was registered in 2020 through Tucows: neither says anything
    about one customer's site under it."""
    net.serve(GOOGLE + "domain/vercel.app", body=_record(days_ago=2100, registrar="Tucows Domains Inc"))
    assert _lookup(domain) == {}
    assert net.requested == []


def test_the_platform_itself_is_looked_up(net):
    net.serve(GOOGLE + "domain/vercel.app", body=_record(days_ago=2100, registrar="Tucows Domains Inc"))
    assert _lookup("vercel.app")["age_days"] == 2100


@pytest.mark.parametrize("domain", ["93.184.216.34", "2606:4700::1"])
def test_an_address_asks_nothing(net, domain):
    assert _lookup(domain) == {}
    assert net.clients == 0


def test_an_http_only_server_in_the_bootstrap_is_not_used(net):
    """RFC 9224 lets a zone list http:// servers; the name would travel in
    the clear and could be rewritten on the way. Treated as no server."""
    assert _lookup("shop.example") == {}
    assert net.requested == [IANA]


# ── The registry's answer ──

def test_registry_not_found_reads_as_no_data(net):
    net.serve(VERISIGN_COM + "domain/example.com", status=404, body=b"")
    assert _lookup("example.com") == {}
    assert net.requested[-1] == VERISIGN_COM + "domain/example.com"


@pytest.mark.parametrize("status", [400, 429, 500, 503])
def test_registry_failure_is_an_unmeasured_check(net, status):
    """Not 'age unknown': the breaker counts it, and the check is not measured."""
    net.serve(VERISIGN_COM + "domain/example.com", status=status, body={"errorCode": status})
    with pytest.raises(httpx.HTTPStatusError):
        _lookup("example.com")


def test_registry_redirect_is_not_followed(net):
    net.serve(VERISIGN_COM + "domain/example.com", status=302,
              headers={"location": "http://169.254.169.254/latest/meta-data/"})
    with pytest.raises(httpx.HTTPStatusError):
        _lookup("example.com")
    assert all("169.254.169.254" not in url for url in net.requested)


def test_registry_on_a_private_address_is_never_contacted(net, monkeypatch):
    """A poisoned bootstrap or DNS answer must not turn the lookup into a
    request to our own network: the pinned client vets the address."""
    bootstrap = {"services": [[["com"], ["https://rdap.evil-registry.com/"]]]}
    net.routes[IANA] = (200, {}, json.dumps(bootstrap).encode())

    def _gai(host, port):
        address = "10.0.0.7" if host == "rdap.evil-registry.com" else "93.184.216.34"
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, port))]

    monkeypatch.setattr(domain_validator, "_getaddrinfo", _gai)
    with pytest.raises(httpx.ConnectError):
        _lookup("example.com")
    assert "10.0.0.7" not in net.addressed
    assert net.requested == [IANA]


def test_registry_is_contacted_at_the_vetted_address(net):
    net.serve(VERISIGN_COM + "domain/example.com", body=_record())
    _lookup("example.com")
    # conftest's hermetic resolver answers 93.184.216.34 for every name.
    assert net.addressed[-1] == "93.184.216.34"


def test_registry_answer_that_is_not_json_is_an_unmeasured_check(net):
    net.serve(VERISIGN_COM + "domain/example.com", body=b"<html>maintenance</html>")
    with pytest.raises(ValueError):
        _lookup("example.com")


@pytest.mark.parametrize("date_text", [
    "2014-03-20T12:59:17.0Z",        # CentralNic
    "2020-01-28T03:03:04.240Z",      # Google Registry
    "2025-10-29T03:51:11.009091Z",   # Nominet
    "2020-01-01T00:00:00",           # no zone: read as UTC
])
def test_registration_dates_as_registries_write_them(net, date_text):
    net.serve(VERISIGN_COM + "domain/example.com", body=_record(date_text=date_text))
    registered = datetime.fromisoformat(date_text.replace("Z", "+00:00"))
    if registered.tzinfo is None:
        registered = registered.replace(tzinfo=timezone.utc)
    assert _lookup("example.com")["age_days"] == (datetime.now(timezone.utc) - registered).days


def test_a_registration_date_in_the_future_reads_as_new_today(net):
    net.serve(VERISIGN_COM + "domain/example.com", body=_record(days_ago=-2))
    assert _lookup("example.com")["age_days"] == 0


@pytest.mark.parametrize("body", [
    {"events": [{"eventAction": "registration", "eventDate": "not a date"}]},
    {"events": "nonsense", "entities": [{"roles": ["registrar"], "vcardArray": ["vcard"]}]},
    {"entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn"]]]}]},
    [],
])
def test_a_malformed_record_gives_what_it_can(net, body):
    net.serve(VERISIGN_COM + "domain/example.com", body=body)
    assert _lookup("example.com") == {}
    assert net.requested[-1] == VERISIGN_COM + "domain/example.com"


def test_a_record_without_a_registrar_gives_the_age(net):
    """registro.br is registry and registrar at once: no registrar entity."""
    net.serve(VERISIGN_COM + "domain/example.com", body=_record(days_ago=9000, registrar=None))
    out = _lookup("example.com")
    assert out["age_days"] == 9000 and "registrar" not in out


# ── The bootstrap file ──

def test_the_bootstrap_is_fetched_once(net):
    net.serve(VERISIGN_COM + "domain/example.com", body=_record())
    net.serve(GOOGLE + "domain/example.app", body=_record())

    async def go():
        await asyncio.gather(*(analyzer.check_whois_age(d) for d in
                               ("example.com", "a.example.com", "example.app", "b.example.app")))
        await analyzer.check_whois_age("example.com")

    asyncio.run(go())
    assert net.requested.count(IANA) == 1


def test_a_failed_bootstrap_is_an_unmeasured_check_and_is_retried(net):
    net.routes[IANA] = (503, {}, b"")
    with pytest.raises(httpx.HTTPStatusError):
        _lookup("example.com")

    net.routes[IANA] = (200, {}, json.dumps(BOOTSTRAP).encode())
    net.serve(VERISIGN_COM + "domain/example.com", body=_record(days_ago=5))
    assert _lookup("example.com")["age_days"] == 5
    assert net.requested.count(IANA) == 2


def test_a_bootstrap_without_servers_is_not_kept(net):
    """A captive portal or a broken mirror answering 200 must not switch age
    off for a day."""
    net.routes[IANA] = (200, {}, b'{"services": []}')
    with pytest.raises(ValueError):
        _lookup("example.com")


def test_a_day_old_bootstrap_is_refreshed_without_waiting(net, monkeypatch):
    from api.services import rdap

    net.serve(VERISIGN_COM + "domain/example.com", body=_record())
    clock = [1000.0]
    monkeypatch.setattr(rdap, "_clock", lambda: clock[0])
    _lookup("example.com")
    clock[0] += rdap.BOOTSTRAP_MAX_AGE_S + 1

    async def stale_then_refreshed():
        first = await analyzer.check_whois_age("example.com")  # answered from the old file
        await asyncio.sleep(0)
        while rdap._bootstrap.refresh is not None and not rdap._bootstrap.refresh.done():
            await asyncio.sleep(0)
        return first

    assert asyncio.run(stale_then_refreshed())["age_days"] == 400
    assert net.requested.count(IANA) == 2


def test_a_failed_refresh_keeps_the_old_file_and_waits_before_retrying(net, monkeypatch):
    from api.services import rdap

    net.serve(VERISIGN_COM + "domain/example.com", body=_record())
    clock = [1000.0]
    monkeypatch.setattr(rdap, "_clock", lambda: clock[0])
    _lookup("example.com")
    net.routes[IANA] = (503, {}, b"")
    clock[0] += rdap.BOOTSTRAP_MAX_AGE_S + 1

    async def several():
        for _ in range(3):
            assert (await analyzer.check_whois_age("example.com"))["age_days"] == 400
            while rdap._bootstrap.refresh is not None and not rdap._bootstrap.refresh.done():
                await asyncio.sleep(0)

    asyncio.run(several())
    assert net.requested.count(IANA) == 2  # the first fetch and ONE failed refresh


# ── Wired into the analyzer ──

def test_measured_age_and_registrar_reach_the_scorer(net):
    # example.com itself is in the top-100k allowlist, which answers before any rule.
    net.serve(VERISIGN_COM + "domain/quiet-garden-tools.com",
              body=_record(days_ago=3, registrar="NameCheap, Inc."))
    whois = _lookup("quiet-garden-tools.com")
    signals = analyzer._build_signals("quiet-garden-tools.com", "quiet-garden-tools.com", False,
                                      {"whois": (whois, True)})
    assert (signals["domain_age_days"], signals["registrar"]) == (3, "NameCheap, Inc.")
    _, _, reasons = scoring.calculate_score(signals)
    fired = {r.signal for r in reasons}
    assert {"domain_very_new", "abused_registrar"} <= fired


def test_registries_are_asked_over_http2(net, monkeypatch):
    """TWNIC (.tw) answers 426 Upgrade Required over HTTP/1.1 — measured
    2026-10-26 on so-net.net.tw and cpu.edu.tw, which then lost their
    'safe' as a partial analysis. HTTP/2 is offered; HTTP/1.1 servers
    (Verisign) still answer over 1.1."""
    offered = []
    real_transport = httpx.AsyncHTTPTransport

    def _transport(*args, **kwargs):
        offered.append(kwargs.get("http2", False))
        return real_transport(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncHTTPTransport", _transport)
    net.serve(VERISIGN_COM + "domain/example.com", body=_record())
    _lookup("example.com")
    assert offered == [True]


# ── Registrar reputation, now that it is measured ──
#
# data/abused_registrars.json ranks registrars by the phishing domains
# registered through them — names used within days of registration. On the
# 2026-10-26 replay the rule fired on 192 of 376 real sites whose age RDAP
# gave (Namecheap, GoDaddy, Tucows: ncfr.org, 28 years) and on 124 of 527
# phishing hosts: more often on real sites. It now counts only while the
# registration is recent.

def _registrar_signals(age, registrar="NameCheap, Inc."):
    return {"domain": "quiet-garden-tools.com", "raw_url": "quiet-garden-tools.com",
            "domain_age_days": age, "registrar": registrar}


def _fired(signals) -> dict[str, int]:
    _, _, reasons = scoring.calculate_score(signals)
    return {r.signal: r.weight for r in reasons}


@pytest.mark.parametrize("age", [0, 12, 55, 89])
def test_a_recent_registration_through_an_abused_registrar_counts(age):
    assert _fired(_registrar_signals(age))["abused_registrar"] == 12
    assert _fired(_registrar_signals(age, "GoDaddy.com, LLC"))["risky_registrar"] == 5


@pytest.mark.parametrize("age", [90, 400, 10331])
def test_an_old_registration_says_nothing_about_its_registrar(age):
    fired = _fired(_registrar_signals(age))
    assert "abused_registrar" not in fired and "risky_registrar" not in fired
    fired = _fired(_registrar_signals(age, "GoDaddy.com, LLC"))
    assert "abused_registrar" not in fired and "risky_registrar" not in fired


def test_a_registrar_without_a_registration_date_says_nothing():
    fired = _fired(_registrar_signals(None))
    assert "abused_registrar" not in fired and "risky_registrar" not in fired

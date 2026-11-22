"""Every DNS and API question of the weekly benchmark is about the URL's own host.

Until the fourth review of #395 the benchmark asked about the host with "www."
cut off (domain_of, which is for the sample's dedup). www.ershoujian.com, a
seed-42 phishing URL on 2026-11-03, had public A and AAAA addresses, while
ershoujian.com had only an SOA: the existence probe asked the apex, found no
address, and the row was 'non_public', not found for every resolver, though
anyone could open the page. Cleanway and Families were asked the apex too. The
extension asks a page's hostname as it is (extension/src/background/index.js).
"""
from __future__ import annotations

import asyncio
import importlib
import sys
from pathlib import Path
from types import SimpleNamespace

import httpx

URL = "https://www.x.example/login?email=a@b.c"
WWW, APEX = "www.x.example", "x.example"
PUBLIC_A = "93.184.216.34"


def _eval():
    scripts = Path(__file__).resolve().parent.parent / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    return importlib.import_module("eval_fresh_urls")


def test_url_host_keeps_www_and_drops_the_trailing_dot():
    ev = _eval()
    assert ev.url_host("https://WWW.Ershoujian.com./?email=x") == "www.ershoujian.com"
    assert ev.url_host("www.x.example") == "www.x.example"
    assert ev.url_host("http://user@www.x.example:8443/path") == "www.x.example"
    assert ev.url_host("http://[2606:4700::1]/") == "2606:4700::1"
    assert ev.url_host("") == ""
    # domain_of still drops "www.": it serves the sample's dedup only.
    assert ev.domain_of("https://www.ershoujian.com/") == "ershoujian.com"


class _Net:
    """DoH and Cleanway behind one MockTransport. The apex has no record (an
    SOA only), www has a public A; Families blocks www with an NXDOMAIN. Every
    request is recorded as (host, name asked)."""

    def __init__(self) -> None:
        self.asked: list[tuple[str, str, str]] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == httpx.URL(_eval().CLEANWAY_API).host:
            name = request.url.path.rsplit("/", 1)[-1]
            self.asked.append(("cleanway", name, ""))
            if name == WWW:
                return httpx.Response(200, json={"level": "dangerous", "verdict_basis": "blocklist",
                                                 "reason_codes": ["cleanway_blocklist"]})
            return httpx.Response(200, json={"level": "caution", "verdict_basis": "not_found", "exists": False})
        name, rtype = request.url.params["name"], request.url.params["type"]
        self.asked.append((host, name, rtype))
        if host == "family.cloudflare-dns.com":
            return httpx.Response(200, json={"Status": 3})
        if name == WWW and rtype == "A":
            return httpx.Response(200, json={"Status": 0, "Answer": [{"type": 1, "data": PUBLIC_A}]})
        if name in (WWW, APEX):
            return httpx.Response(200, json={"Status": 0})
        return httpx.Response(200, json={"Status": 3})

    def run(self, check, url: str = URL):
        async def go():
            async with httpx.AsyncClient(transport=httpx.MockTransport(self.handler)) as client:
                return await check(client, url)
        return asyncio.run(go())


def test_the_probe_asks_the_www_host_and_a_live_www_is_live():
    ev = _eval()
    net = _Net()
    out = net.run(ev.probe_existence)
    assert net.asked == [("cloudflare-dns.com", WWW, "A")]     # a public A: no AAAA question
    assert (out.exists, out.addresses) == (True, [PUBLIC_A])
    assert ev.benchmark_method.row_existence(out.exists, [], addresses=out.addresses) == "resolves"


def test_cleanway_is_asked_the_www_host(monkeypatch):
    ev = _eval()
    monkeypatch.setattr(ev, "BENCHMARK_BYPASS_TOKEN", "tok")   # no install pacing
    net = _Net()
    out = net.run(ev.check_cleanway)
    assert net.asked == [("cleanway", WWW, "")]
    assert (out.verdict, out.verdict_basis) == ("dangerous", "blocklist")


def test_families_and_its_control_query_are_asked_the_www_host():
    ev = _eval()
    net = _Net()
    out = net.run(ev.check_cloudflare_families)
    assert net.asked == [("family.cloudflare-dns.com", WWW, "A"), ("cloudflare-dns.com", WWW, "A")]
    assert (out.verdict, out.detail, out.exists) == ("dangerous", "status=3 blocked", True)


def test_the_in_process_analyzer_is_asked_the_www_host(monkeypatch):
    ev = _eval()
    seen: list[tuple[str, str]] = []

    async def analyze(domain, raw_url=None):
        seen.append((domain, raw_url))
        return SimpleNamespace(level="safe", score=0, verdict_basis="heuristics", checks_incomplete=[], exists=True)

    monkeypatch.setattr(ev, "_analyze_domain", analyze)
    out = asyncio.run(ev.check_cleanway_local(None, URL))
    assert seen == [(WWW, URL)]
    assert (out.verdict, out.verdict_basis) == ("safe", "heuristics")

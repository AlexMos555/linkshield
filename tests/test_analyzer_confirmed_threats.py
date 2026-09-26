"""analyze_domain feeds Safe-Browsing-confirmed hosts to the blocklist publisher.

Pinned end to end through the real scorer: with publishing switched on, a
Safe Browsing phishing hit that ends DANGEROUS is recorded in
`dangerous_domains:confirmed`; a verdict from sources we do not trust for DNS
blocking is not, and nothing is recorded while publishing is off (default).
"""
from __future__ import annotations

import pytest

from api.services import analyzer, confirmed_threats

_BREAKERS = (
    "safe_browsing_breaker", "phishtank_breaker", "urlhaus_breaker", "phishstats_breaker",
    "threatfox_breaker", "spamhaus_breaker", "surbl_breaker", "alienvault_breaker", "ipqs_breaker",
    "malware_bazaar_breaker", "feodo_breaker", "tranco_breaker", "favicon_breaker",
    "watchtower_breaker", "whois_breaker", "ssl_breaker", "headers_breaker", "dns_breaker",
    "redirect_breaker",
)


class _Breaker:
    """Answers like a circuit breaker: (value, ok)."""

    def __init__(self, value):
        self.value = value

    async def call(self, fn, domain):
        return self.value, True


class _Pipe:
    def __init__(self, r):
        self.r, self.calls = r, []

    def __getattr__(self, name):
        def queue(*a, **kw):
            self.calls.append((name, a, kw))
            return self
        return queue

    async def execute(self):
        for name, a, kw in self.calls:
            if name == "zadd":
                self.r.z.update(a[1])


class _Redis:
    def __init__(self):
        self.z: dict = {}

    def pipeline(self, transaction=True):
        return _Pipe(self)


def _world(monkeypatch, hits: dict) -> _Redis:
    monkeypatch.setattr(analyzer, "validate_domain", lambda d: d)

    async def _resolves(_d):
        return None

    monkeypatch.setattr(analyzer, "validate_domain_resolution", _resolves)
    dict_checks = {"alienvault_breaker", "ipqs_breaker", "tranco_breaker", "favicon_breaker",
                   "watchtower_breaker", "whois_breaker", "ssl_breaker", "headers_breaker",
                   "dns_breaker", "redirect_breaker"}
    for name in _BREAKERS:
        default = {} if name in dict_checks else False
        monkeypatch.setattr(analyzer, name, _Breaker(hits.get(name, default)))
    r = _Redis()

    async def _get():
        return r

    monkeypatch.setattr("api.services.cache.get_redis", _get)

    async def _phishing(_host):
        return frozenset({"SOCIAL_ENGINEERING"})

    monkeypatch.setattr(confirmed_threats, "_safe_browsing_types", _phishing)
    return r


@pytest.fixture
def publishing_on(monkeypatch):
    monkeypatch.setenv(confirmed_threats.ENABLE_ENV, "1")


@pytest.mark.asyncio
async def test_a_safe_browsing_verdict_is_recorded_for_the_blocklist(monkeypatch, publishing_on):
    r = _world(monkeypatch, {"safe_browsing_breaker": True})
    result = await analyzer.analyze_domain("login.fresh-phish.example")
    assert result.level.value == "dangerous"
    assert set(r.z) == {"login.fresh-phish.example"}


@pytest.mark.asyncio
async def test_nothing_is_recorded_while_publishing_is_off(monkeypatch):
    """Off by default: redistributing Safe Browsing verdicts is a licence
    decision (feed-licence audit of 2026-09-21), not a code default."""
    monkeypatch.delenv(confirmed_threats.ENABLE_ENV, raising=False)
    r = _world(monkeypatch, {"safe_browsing_breaker": True})
    result = await analyzer.analyze_domain("login.fresh-phish.example")
    assert result.level.value == "dangerous"
    assert r.z == {}


@pytest.mark.parametrize("breaker", ["threatfox_breaker", "malware_bazaar_breaker", "urlhaus_breaker",
                                     "phishtank_breaker"])
@pytest.mark.asyncio
async def test_a_hit_that_is_not_an_exact_live_host_listing_is_not_recorded(monkeypatch, publishing_on, breaker):
    """Each of these alone ends DANGEROUS, but none says "this host is
    malicious now": ThreatFox's IOC search is a wildcard, MalwareBazaar's is
    uploader-set tags, URLhaus /host/ counts offline URLs, and PhishTank is
    our held-out benchmark."""
    r = _world(monkeypatch, {breaker: True})
    result = await analyzer.analyze_domain("bank-shop.example")
    assert result.level.value == "dangerous"
    assert r.z == {}


@pytest.mark.asyncio
async def test_a_verdict_from_untrusted_sources_is_not_recorded(monkeypatch, publishing_on):
    # Spamhaus + SURBL push the score over the line, but they list spam, not
    # phishing, and their terms are non-commercial: no DNS block from them.
    r = _world(monkeypatch, {"spamhaus_breaker": True, "surbl_breaker": True})
    result = await analyzer.analyze_domain("newsletter.example")
    assert result.level.value == "dangerous"
    assert r.z == {}


@pytest.mark.asyncio
async def test_a_clean_verdict_is_not_recorded(monkeypatch, publishing_on):
    r = _world(monkeypatch, {})
    await analyzer.analyze_domain("plain.example")
    assert r.z == {}

"""lookalike_generator: which certificate names imitate a Russian brand, and
what evidence may publish one.

The name rules are the scorer's own (pinned in test_ru_brand_typosquats.py,
test_ru_lure_combos.py, test_ru_heuristic_fps.py); these tests pin that the
generator hands each rule the name in the scorer's form — a Cyrillic .рф
name from a certificate arrives as punycode and must still be compared as
Cyrillic — that brand-owned and popular names never become candidates, and
that a name alone never publishes anything.
"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from api.services import lookalike_generator as lg
from tests.test_ct_tiles import LEAVES, precert_record, san_extension, tbs, x509_record
from api.services import ct_tiles


def _match(name: str):
    host = lg.normalise(name)
    assert host, name
    assert lg.skip_reason(host) is None, name
    return lg.match(host)


# ── Names as certificates carry them ──

@pytest.mark.parametrize("raw, host", [
    ("*.sberbank-bonus.ru", "sberbank-bonus.ru"),
    ("WWW.Sberbamk.RU.", "www.sberbamk.ru"),
    ("госуслуги-лк.рф", "xn----etbaulcdt1aavc.xn--p1ai"),
    ("*.xfpgmur-xyb21941.us-west-2.aws.snowflake.app", "xfpgmur-xyb21941.us-west-2.aws.snowflake.app"),
])
def test_certificate_names_become_wire_hosts(raw, host):
    assert lg.normalise(raw) == host


@pytest.mark.parametrize("raw", ["", "10.0.0.1", "localhost", "a b.ru", "x@y.ru", "evil.ru/path",
                                 "-bad-.ru", "x" * 64 + ".ru", "host.1"])
def test_non_hosts_are_dropped(raw):
    assert lg.normalise(raw) is None


# ── Real Russian-brand lookalikes ──

@pytest.mark.parametrize("name, brand, imitates, method", [
    ("sberbamk.ru", "sber", "sberbank.ru", "character substitution"),
    ("t1nkoff.ru", "tbank", "tinkoff.ru", "character substitution"),
    ("0zon.ru", "ozon", "ozon.ru", "character substitution"),
    ("sber-bank.ru", "sber", "sberbank.ru", "hyphen injection"),
    ("ozon.ru.com", "ozon", "ozon.ru", "TLD confusion"),
    ("yandex.ru.net", "yandex", "yandex.ru", "TLD confusion"),
    ("sberbank-login.com", "sber", "sberbank.ru", "combosquatting"),
    ("vk-login.nov.ru", "vk", "vk.com", "combosquatting"),
    ("www.sberbamk.ru", "sber", "sberbank.ru", "character substitution"),  # the www. of a cert
])
def test_typosquats_of_russian_brands_are_candidates(name, brand, imitates, method):
    m = _match(name)
    assert m is not None, name
    assert (m.brand, m.imitates, m.method) == (brand, imitates, method)


@pytest.mark.parametrize("name, brand", [
    # PR #64's lure words: transliterated, glued, either order, any TLD.
    ("sberbank-bonus.ru", "sber"), ("sberbankbonus.ru", "sber"), ("ozon-priz.com", "ozon"),
    ("avito-dostavka.info", "avito"), ("cdek-dostavka.info", "cdek"), ("yandex-doctavym.website", "yandex"),
    ("gosuslugi-lk.ru", "gosuslugi"), ("lk-gosuslugi.online", "gosuslugi"), ("tinkoff-vhod.xyz", "tbank"),
    ("tinkoff-bank-vhod.ru", "tbank"), ("wildberries-priz.ru", "wildberries"), ("tele2-podarok.ru", "t2"),
    ("mts-bonus.msk.ru", "mts"),                 # the open-zone check takes the same words
    # Cyrillic names — a certificate carries them as punycode.
    ("госуслуги-лк.рф", "gosuslugi"), ("www.госуслуги-лк.рф", "gosuslugi"), ("сбербанк-бонус.рф", "sber"),
    ("почтароссии-оплата.рф", "russianpost"), ("тинькофф-бонус.рф", "tbank"),
])
def test_brand_plus_lure_word_is_a_candidate_labelled_as_such(name, brand):
    m = _match(name)
    assert m is not None, name
    assert m.brand == brand
    assert m.method.endswith(lg.LURE_METHOD), m.method


def test_a_cyrillic_name_is_compared_decoded_not_as_punycode():
    # The regression: comparing 'xn----etbaulcdt1aavc.xn--p1ai' matched nothing.
    assert lg.comparison_base("xn----etbaulcdt1aavc.xn--p1ai") == "госуслуги-лк.рф"
    assert lg.comparison_base("www.sberbamk.ru") == "sberbamk.ru"


@pytest.mark.parametrize("name", [
    "sberbank-online.ru",    # 'online' lures for Sber, but it is the bank's product word, not ru_lures'
    "sberbank-login.com",    # an English keyword: the scorer's older combo
])
def test_other_combos_are_not_labelled_as_lure_words(name):
    m = _match(name)
    assert m is not None and m.method == "combosquatting"


@pytest.mark.parametrize("name", [
    "vkusvill-bonus.ru",         # VkusVill's, not VK's: the brand must be a whole word
    "paypal-login.com",          # a global brand: the feeds we ship cover it
    "example.org", "snowflake.app", "quickbeam.acm.aws.dev",
    "sberbank-bonus.vercel.app",  # a tenant name: the scorer compares the platform
    "pochta-rossii-dostavka.ru",
])
def test_names_that_imitate_no_russian_brand_are_not_candidates(name):
    host = lg.normalise(name)
    assert host is None or lg.skip_reason(host) or lg.match(host) is None, name


def test_the_recorded_ct_names_match_nothing():
    hosts = {lg.normalise(n) for leaf in ct_tiles.iter_leaves(LEAVES) for n in ct_tiles.dns_names(leaf.certificate)}
    assert lg.match_many(hosts - {None}, workers=1) == {}


def test_a_tile_with_lookalikes_yields_matches_end_to_end():
    blob = (precert_record(tbs(san_extension("sberbank-bonus.ru", "www.sberbank-bonus.ru")))
            + x509_record(tbs(san_extension("xn----etbaulcdt1aavc.xn--p1ai")))
            + x509_record(tbs(san_extension("www.sberbank.ru", "sberbank.ru")))   # Sber's own
            + LEAVES)
    hosts = {lg.normalise(n) for leaf in ct_tiles.iter_leaves(blob) for n in ct_tiles.dns_names(leaf.certificate)}
    found = lg.match_many(hosts - {None}, workers=1)
    assert set(found) == {"sberbank-bonus.ru", "www.sberbank-bonus.ru", "xn----etbaulcdt1aavc.xn--p1ai"}
    assert {m.brand for m in found.values()} == {"sber", "gosuslugi"}


# ── False-positive pre-gates ──

@pytest.mark.parametrize("host", [
    "sberbank.ru", "online.sberbank.ru", "sber.ru", "sberbank.com", "gosuslugi.ru", "esia.gosuslugi.ru",
    "tbank.ru", "tinkoff.ru", "www.vk.com",
    "mts-bonus.ru", "ozon-dostavka.ru",  # brand-owned names WITH a lure word (PR #64's FP pass)
    "xn--d1acpjx3f.xn--p1ai",            # яндекс.рф, Yandex's own
])
def test_brand_owned_names_are_never_candidates(host):
    assert lg.skip_reason(host) == "brand_owned"
    assert lg.match_many([host], workers=1) == {}


@pytest.mark.parametrize("host", ["mail.google.com", "vercel.app", "github.io", "pages.dev"])
def test_popular_names_and_platform_apexes_are_never_candidates(host):
    assert lg.skip_reason(host) == "trusted_top"
    assert lg.match_many([host], workers=1) == {}


# ── Evidence: a name alone never publishes ──

M = lg.Match("sberbank-bonus.ru", "sber", "sberbank.ru", "combosquatting, lure word")
LOGIN = '<form><input type="password" name="p"></form><title>СберБанк Онлайн — вход</title>'


def _signals(**kw):
    base = {"listed": None, "level": None, "verdict_basis": None, "page_html": None}
    return lg.signals(M, **{**base, **kw})


def test_a_name_match_alone_is_not_publishable():
    found = _signals()
    assert found == ()
    assert not lg.publishable(found)


def test_a_password_form_naming_the_brand_is_the_independent_signal():
    found = _signals(page_html=LOGIN)
    assert found == (lg.SIGNAL_CREDENTIAL_FORM,)
    assert lg.publishable(found) and not lg.covered(found)


@pytest.mark.parametrize("html", [
    '<form><input type="password"></form><title>Router admin</title>',  # a log-in page, no brand
    "<h1>Сбербанк снизил ставки</h1>",                                    # the brand, no password form
    "", None,
])
def test_half_of_the_page_evidence_is_no_evidence(html):
    assert not lg.publishable(_signals(page_html=html))


def test_a_third_party_listing_is_recorded_but_never_publishes():
    # Publishing on it would derive our list from theirs (licence).
    found = _signals(level="dangerous", verdict_basis="threat_intel")
    assert found == (lg.SIGNAL_THREAT_INTEL,)
    assert not lg.publishable(found)


@pytest.mark.parametrize("level, basis", [
    ("dangerous", "heuristics"), ("dangerous", "ml_and_heuristics"), ("caution", "threat_intel"),
    ("safe", "allowlist"), (None, None),
])
def test_heuristic_verdicts_are_not_signals(level, basis):
    assert lg.signal_from_verdict(level, basis) is None


def test_our_own_list_is_coverage_never_confirmation():
    # The published list carries our own sets: a host must not confirm itself.
    for found in (_signals(listed="sberbank-bonus.ru"), _signals(level="dangerous", verdict_basis="blocklist")):
        assert lg.covered(found)
        assert not lg.publishable(found)


# ── Fetching the page (no network: a mock transport) ──

def _client(routes: dict, seen: list):
    def handler(request):
        seen.append(str(request.url))
        status, headers, body = routes.get(str(request.url), (404, {}, b""))
        return httpx.Response(status, headers=headers, content=body)
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


@pytest.fixture
def every_hop_safe(monkeypatch):
    async def _safe(_host):
        return True
    monkeypatch.setattr(lg, "_hop_is_safe", _safe)


def test_a_lookalike_serving_a_branded_password_form_is_confirmed(every_hop_safe):
    seen: list = []
    routes = {"https://sberbank-bonus.ru/": (200, {"content-type": "text/html; charset=utf-8"}, LOGIN.encode())}

    async def go():
        async with _client(routes, seen) as http:
            return await lg.fetch_page("sberbank-bonus.ru", http)

    html = asyncio.run(go())
    assert lg.publishable(_signals(page_html=html))


def test_a_redirect_to_the_brands_own_site_ends_the_fetch(every_hop_safe):
    # A defensive registration forwarding to Sber must never be 'confirmed'
    # by Sber's own password field.
    seen: list = []
    routes = {
        "https://sberbank-bonus.ru/": (301, {"location": "https://online.sberbank.ru/login"}, b""),
        "https://online.sberbank.ru/login": (200, {"content-type": "text/html"}, LOGIN.encode()),
    }

    async def go():
        async with _client(routes, seen) as http:
            return await lg.fetch_page("sberbank-bonus.ru", http)

    assert asyncio.run(go()) is None
    assert seen == ["https://sberbank-bonus.ru/"]


def test_an_unsafe_host_is_never_contacted(monkeypatch):
    async def _unsafe(_host):
        return False
    monkeypatch.setattr(lg, "_hop_is_safe", _unsafe)
    seen: list = []

    async def go():
        async with _client({}, seen) as http:
            return await lg.fetch_page("sberbank-bonus.ru", http)

    assert asyncio.run(go()) is None
    assert seen == []


def test_non_html_and_errors_yield_nothing(every_hop_safe):
    seen: list = []
    routes = {
        "https://a-sberbank-bonus.ru/": (200, {"content-type": "application/zip"}, b"PK"),
        "https://b-sberbank-bonus.ru/": (500, {"content-type": "text/html"}, LOGIN.encode()),
    }

    async def go():
        async with _client(routes, seen) as http:
            return [await lg.fetch_page(h, http) for h in ("a-sberbank-bonus.ru", "b-sberbank-bonus.ru")]

    assert asyncio.run(go()) == [None, None]

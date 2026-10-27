"""The weekly favicon cron must refresh a brand whose first host serves HTML.

Measured 2026-10-27: linkedin.com/favicon.ico answers 200 with a 20-21 KB HTML
page to every client while www.linkedin.com/favicon.ico is the real ICO;
www.fedex.com/favicon.ico is a 172 KB "Page Not Found" page and the real icon
is the one fedex.com's <link rel="shortcut icon"> names. The cron used to
fetch only hosts[0]/favicon.ico, so after #348 (HTML is never hashed) these
brands could never refresh themselves.
"""
from __future__ import annotations

import json
import logging

import httpx
import pytest

from tests.test_favicon_hash import AKAMAI_DENIED, ICON_SAMPLES
from tests.test_favicon_refresh_drift import _load_script

ERROR_PAGE = b"<!DOCTYPE html><html><head><title>Page Not Found</title></head><body></body></html>"
FEDEX_HOME = (
    b'<!DOCTYPE html><html><head><title>FedEx</title>'
    b'<link rel="stylesheet" href="/etc/site.css"/>'
    b'<link rel="shortcut icon" type="image/x-icon" href="/etc/fx-favicon.ico"/>'
    b"</head><body></body></html>"
)


@pytest.fixture
def run_cron(monkeypatch, tmp_path):
    """Run the cron's main() over a one-brand gallery against `routes`
    ({(host, path): body, or a str: a 301 to that Location}; anything else
    is the error page)."""
    script = _load_script()
    real_client = httpx.AsyncClient  # once: a test may run the cron twice

    async def _run(brand: dict, routes: dict, slug: str = "brand") -> tuple[dict, list[str]]:
        gal = tmp_path / "gal.json"
        gal.write_text(json.dumps({slug: brand}))
        monkeypatch.setattr(script, "GALLERY_PATH", gal)
        asked: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            asked.append(f"{request.url.host}{request.url.path}")
            body = routes.get((request.url.host, request.url.path), ERROR_PAGE)
            if isinstance(body, str):
                return httpx.Response(301, headers={"location": body})
            return httpx.Response(200, content=body)

        monkeypatch.setattr(
            script.httpx, "AsyncClient",
            lambda **kw: real_client(transport=httpx.MockTransport(_handler), **kw),
        )
        await script.main(dry_run=False)
        return json.loads(gal.read_text())[slug], asked

    return _run


def _digest(body: bytes) -> str:
    return _load_script()._hash_bytes(body)


@pytest.mark.asyncio
async def test_a_brand_whose_first_host_serves_html_takes_the_next_hosts_icon(run_cron):
    brand, _ = await run_cron(
        {"verified_hosts": ["linkedin.com", "www.linkedin.com"], "known_favicon_hashes": []},
        {("linkedin.com", "/favicon.ico"): b"<!DOCTYPE html><html><body>auth wall</body></html>",
         ("www.linkedin.com", "/favicon.ico"): ICON_SAMPLES["ico"]},
        slug="linkedin",
    )
    assert brand["known_favicon_hashes"] == [_digest(ICON_SAMPLES["ico"])]


@pytest.mark.asyncio
async def test_no_favicon_ico_anywhere_falls_back_to_the_link_rel_icon(run_cron):
    brand, asked = await run_cron(
        {"verified_hosts": ["fedex.com", "www.fedex.com"], "known_favicon_hashes": []},
        {("fedex.com", "/"): FEDEX_HOME, ("fedex.com", "/etc/fx-favicon.ico"): ICON_SAMPLES["ico"]},
        slug="fedex",
    )
    assert brand["known_favicon_hashes"] == [_digest(ICON_SAMPLES["ico"])]
    # /favicon.ico on every host comes first: that is what the runtime hashes.
    assert asked[:2] == ["fedex.com/favicon.ico", "www.fedex.com/favicon.ico"]


@pytest.mark.asyncio
async def test_a_link_rel_icon_off_the_brands_hosts_is_not_fetched(run_cron):
    """A link names any URL; the gallery only takes bytes from the brand's
    own hosts, which is what the review step of the cron's PR relies on."""
    home = b'<html><head><link rel="icon" href="https://cdn.other.example/i.ico"></head></html>'
    brand, asked = await run_cron(
        {"verified_hosts": ["brand.example"], "known_favicon_hashes": []},
        {("brand.example", "/"): home, ("cdn.other.example", "/i.ico"): ICON_SAMPLES["png"]},
    )
    assert brand["known_favicon_hashes"] == []
    assert "cdn.other.example/i.ico" not in asked


@pytest.mark.asyncio
async def test_a_brand_left_without_any_image_hash_is_a_warning(run_cron, caplog):
    caplog.set_level(logging.INFO, logger="brand-favicons")
    brand, _ = await run_cron(
        {"verified_hosts": ["ups.com", "www.ups.com"], "known_favicon_hashes": []},
        {("ups.com", "/favicon.ico"): AKAMAI_DENIED, ("www.ups.com", "/favicon.ico"): AKAMAI_DENIED},
        slug="ups",
    )
    assert brand["known_favicon_hashes"] == []
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("ups" in w and "no favicon hash" in w for w in warnings), warnings


# ── Redirects: bytes from the brand's hosts only ──
# The gallery's review step trusts that every hash came from a host listed
# for the brand. A verified host that redirects elsewhere (a CDN, a parked or
# expired asset domain, an open redirect) must not get the bytes it lands on
# filed as the brand's icon, on any path the cron fetches.

@pytest.mark.parametrize("location", [
    "https://parked.example/i.ico",
    "//parked.example/i.ico",
    "https://brand.example.parked.example/i.ico",
    "http://brand.example/i.ico",
    "https://brand.example@parked.example/i.ico",
    "https://brand.example\\@parked.example/i.ico",
])
@pytest.mark.asyncio
async def test_a_favicon_ico_redirecting_off_the_brands_hosts_is_not_filed(run_cron, location):
    brand, asked = await run_cron(
        {"verified_hosts": ["brand.example"], "known_favicon_hashes": []},
        {("brand.example", "/favicon.ico"): location,
         ("parked.example", "/i.ico"): ICON_SAMPLES["png"],
         ("brand.example.parked.example", "/i.ico"): ICON_SAMPLES["png"],
         ("brand.example", "/i.ico"): ICON_SAMPLES["png"]},
    )
    assert brand["known_favicon_hashes"] == []
    assert not [a for a in asked if "parked" in a]


@pytest.mark.asyncio
async def test_every_hop_of_a_redirect_chain_must_stay_on_the_brands_hosts(run_cron):
    brand, asked = await run_cron(
        {"verified_hosts": ["brand.example", "www.brand.example"], "known_favicon_hashes": []},
        {("brand.example", "/favicon.ico"): "https://www.brand.example/favicon.ico",
         ("www.brand.example", "/favicon.ico"): "https://parked.example/i.ico",
         ("parked.example", "/i.ico"): ICON_SAMPLES["png"]},
    )
    assert brand["known_favicon_hashes"] == []
    assert "parked.example/i.ico" not in asked


@pytest.mark.asyncio
async def test_a_favicon_ico_redirect_between_the_brands_hosts_is_followed(run_cron):
    """paypal.com, apple.com, google.com and most others redirect
    /favicon.ico to their www host (dry run 2026-10-27)."""
    brand, _ = await run_cron(
        {"verified_hosts": ["brand.example", "www.brand.example"], "known_favicon_hashes": []},
        {("brand.example", "/favicon.ico"): "https://www.brand.example/favicon.ico",
         ("www.brand.example", "/favicon.ico"): ICON_SAMPLES["ico"]},
    )
    assert brand["known_favicon_hashes"] == [_digest(ICON_SAMPLES["ico"])]


@pytest.mark.asyncio
async def test_a_redirect_to_a_declared_asset_host_of_the_brand_is_followed(run_cron):
    """www.bankofamerica.com/favicon.ico redirects to www.bac-assets.com, Bank
    of America's own asset domain; the gallery declares it per brand."""
    routes = {("bank.example", "/favicon.ico"): "https://www.bank-assets.example/fav.ico",
              ("www.bank-assets.example", "/fav.ico"): ICON_SAMPLES["ico"]}

    declared, _ = await run_cron(
        {"verified_hosts": ["bank.example"], "asset_hosts": ["www.bank-assets.example"],
         "known_favicon_hashes": []},
        routes,
    )
    undeclared, asked = await run_cron({"verified_hosts": ["bank.example"], "known_favicon_hashes": []}, routes)

    assert declared["known_favicon_hashes"] == [_digest(ICON_SAMPLES["ico"])]
    assert declared["asset_hosts"] == ["www.bank-assets.example"]  # kept as written
    assert undeclared["known_favicon_hashes"] == []
    assert "www.bank-assets.example/fav.ico" not in asked


@pytest.mark.asyncio
async def test_a_redirect_loop_on_the_brands_hosts_gives_up(run_cron):
    script = _load_script()
    brand, asked = await run_cron(
        {"verified_hosts": ["brand.example"], "known_favicon_hashes": []},
        {("brand.example", "/favicon.ico"): "https://brand.example/favicon.ico"},
    )
    assert brand["known_favicon_hashes"] == []
    assert asked.count("brand.example/favicon.ico") == script.MAX_REDIRECTS + 1


@pytest.mark.asyncio
async def test_a_home_page_redirecting_off_the_brands_hosts_is_not_read(run_cron):
    """The page names the icon, so it must come from the brand too: an open
    redirect on the brand's host could otherwise pick any file there (an
    upload, an avatar) as the brand's icon."""
    other_home = b'<html><head><link rel="icon" href="https://brand.example/u/avatar.png"></head></html>'
    brand, asked = await run_cron(
        {"verified_hosts": ["brand.example"], "known_favicon_hashes": []},
        {("brand.example", "/"): "https://other.example/home",
         ("other.example", "/home"): other_home,
         ("brand.example", "/u/avatar.png"): ICON_SAMPLES["png"]},
    )
    assert brand["known_favicon_hashes"] == []
    assert "other.example/home" not in asked


@pytest.mark.asyncio
async def test_a_linked_icon_redirect_between_the_brands_hosts_is_followed(run_cron):
    home = b'<html><head><link rel="icon" href="/i.ico"></head></html>'
    brand, _ = await run_cron(
        {"verified_hosts": ["brand.example", "www.brand.example"], "known_favicon_hashes": []},
        {("brand.example", "/"): home,
         ("brand.example", "/i.ico"): "https://www.brand.example/static/i.ico",
         ("www.brand.example", "/static/i.ico"): ICON_SAMPLES["ico"]},
    )
    assert brand["known_favicon_hashes"] == [_digest(ICON_SAMPLES["ico"])]


@pytest.mark.asyncio
async def test_a_linked_icon_redirecting_off_the_brands_hosts_is_not_filed(run_cron):
    home = b'<html><head><link rel="icon" href="/i.ico"></head></html>'
    brand, asked = await run_cron(
        {"verified_hosts": ["brand.example"], "known_favicon_hashes": []},
        {("brand.example", "/"): home,
         ("brand.example", "/i.ico"): "https://cdn.other.example/i.ico",
         ("cdn.other.example", "/i.ico"): ICON_SAMPLES["png"]},
    )
    assert brand["known_favicon_hashes"] == []
    assert "cdn.other.example/i.ico" not in asked


# Where gallery brands' /favicon.ico redirect to, measured 2026-10-27 (dry run
# with httpx, every hop logged). A hop the gallery does not allow would stop
# the brand's refresh. www.bac-assets.com: EV certificate to "Bank of America
# Corporation" with the same registration number (2927442) as
# www.bankofamerica.com's, registrar CSC Corporate Domains; it serves the
# gallery's Bank of America hash 1776ec2d. www.santander.com serves Santander's
# a8b5b507; santander.co.uk and santanderbank.com redirect to their www hosts.
MEASURED_ICON_HOPS = {
    "bankofamerica": ["www.bankofamerica.com", "www.bac-assets.com"],
    "santander": ["www.santander.com", "www.santander.co.uk", "www.santanderbank.com"],
    "paypal": ["www.paypal.com"],
    "apple": ["www.apple.com"],
    "stripe": ["stripe.com"],
}


def test_the_production_gallery_allows_where_its_brands_icons_redirect():
    gallery = json.loads(_load_script().GALLERY_PATH.read_text(encoding="utf-8"))
    for slug, hops in MEASURED_ICON_HOPS.items():
        brand = gallery[slug]
        allowed = set(brand["verified_hosts"]) | set(brand.get("asset_hosts") or [])
        assert set(hops) <= allowed, (slug, set(hops) - allowed)
        # An asset host is never a page people visit; one that is belongs in verified_hosts.
        assert not set(brand.get("asset_hosts") or []) & set(brand["verified_hosts"]), slug

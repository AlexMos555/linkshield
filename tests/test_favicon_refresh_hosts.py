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
    ({(host, path): body}; anything else is the error page)."""
    script = _load_script()

    async def _run(brand: dict, routes: dict, slug: str = "brand") -> tuple[dict, list[str]]:
        gal = tmp_path / "gal.json"
        gal.write_text(json.dumps({slug: brand}))
        monkeypatch.setattr(script, "GALLERY_PATH", gal)
        asked: list[str] = []

        def _handler(request: httpx.Request) -> httpx.Response:
            asked.append(f"{request.url.host}{request.url.path}")
            return httpx.Response(200, content=routes.get((request.url.host, request.url.path), ERROR_PAGE))

        real_client = httpx.AsyncClient
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

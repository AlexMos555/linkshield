"""Favicon brand-clone detection tests.

Strategy doc Top-20 #2 (partial). Pin the brand-vs-imposter
distinction, the cache MISS path, and the calculate_score wiring.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from api.services.favicon_hash import (
    _fetch_favicon,
    _hash_bytes,
    check_favicon_brand_clone,
    looks_like_favicon,
)

# Bodies that real sites returned for /favicon.ico with "200 OK" on 2026-10-25.
AKAMAI_DENIED = (
    b'<html><head><title>Access Denied</title></head><body><h1>Access Denied</h1>'
    b'You don\'t have permission to access "/favicon.ico" on this server.<br/>'
    b'0.7fb6d68.1793107707.caa77d6</body></html>'
)
WAF_DOWN = (
    b'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">\n'
    b'<HTML><HEAD><TITLE>Brand | System Down</TITLE></HEAD><BODY></BODY></HTML>'
)
ICON_SAMPLES = {
    "ico": b"\x00\x00\x01\x00\x04\x00\x10\x10" + b"\x00" * 32,
    "cur": b"\x00\x00\x02\x00\x01\x00" + b"\x00" * 16,
    "png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + b"\x00" * 16,
    "gif": b"GIF89a\x10\x00\x10\x00" + b"\x00" * 16,
    "jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 16,
    "bmp": b"BM6\x03\x00\x00" + b"\x00" * 16,
    "webp": b"RIFF\x24\x00\x00\x00WEBPVP8 " + b"\x00" * 16,
    "svg": b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16"/>',
    "svg-xml": b'\xef\xbb\xbf<?xml version="1.0"?>\n<svg xmlns="http://www.w3.org/2000/svg"/>',
    "svg-doctype": b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "x"><svg xmlns="http://www.w3.org/2000/svg"/>',
    # The <svg tag may sit far into the first KB, after a prolog and a comment.
    "svg-late-tag": b'<?xml version="1.0"?><!-- ' + b"x" * 900 + b' --><svg xmlns="http://www.w3.org/2000/svg"/>',
}
NOT_ICONS = {
    "akamai-denied": AKAMAI_DENIED,
    "waf-down": WAF_DOWN,
    "html-with-inline-svg": b"<!doctype html><html><body><svg></svg></body></html>",
    # Pages that pass the SVG prefix check and contain an <svg>: only the
    # <html guard turns them away.
    "xhtml-with-svg": (
        b'<?xml version="1.0"?><!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "x">'
        b'<html xmlns="http://www.w3.org/1999/xhtml"><body><svg/></body></html>'
    ),
    "comment-html-svg": b"<!-- x --><html><body><svg/></body></html>",
    "xml-not-svg": b'<?xml version="1.0"?><error>denied</error>',
    "json": b'{"error": "forbidden"}',
    "text": b"Forbidden",
    "empty": b"",
}


# ───────────────────────────────────────────────────────────────
# Fixtures
# ───────────────────────────────────────────────────────────────

class _FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}

    async def get(self, key):
        return self.store.get(key)

    async def setex(self, key, ttl, value):
        self.store[key] = value


@pytest.fixture
def fake_redis(monkeypatch):
    fake = _FakeRedis()

    async def _get():
        return fake

    import api.services.favicon_hash as mod
    monkeypatch.setattr(mod, "get_redis", _get)
    return fake


@pytest.fixture
def isolated_gallery(monkeypatch, tmp_path):
    """Swap in a one-brand gallery so tests are deterministic and
    don't depend on the production brand_favicons.json contents."""
    gallery = {
        "paypal": {
            "verified_hosts": ["paypal.com", "www.paypal.com"],
            "known_favicon_hashes": ["abcdef012345fedcba987654"],
        },
    }
    p = tmp_path / "gal.json"
    p.write_text(json.dumps(gallery))
    import api.services.favicon_hash as mod
    monkeypatch.setattr(mod, "GALLERY_PATH", p)
    monkeypatch.setattr(mod, "_gallery_cache", None)  # force reload
    return gallery


@pytest.fixture
def stub_favicon(monkeypatch):
    """Replace the live HTTP fetch with a deterministic stub."""
    import api.services.favicon_hash as mod
    state = {"payload": None}

    async def _fake(domain):
        return state["payload"]

    monkeypatch.setattr(mod, "_fetch_favicon", _fake)
    return state


# ───────────────────────────────────────────────────────────────
# _hash_bytes
# ───────────────────────────────────────────────────────────────

def test_hash_bytes_is_deterministic():
    assert _hash_bytes(b"hello") == _hash_bytes(b"hello")


def test_hash_bytes_is_96_bits():
    """24 hex chars = 96 bits. Wider than the original 48-bit prefix
    so a motivated attacker can't brute-force a second-preimage on
    consumer GPUs in operational timeframes."""
    h = _hash_bytes(b"any-payload")
    assert len(h) == 24
    assert all(c in "0123456789abcdef" for c in h)


def test_hash_bytes_matches_refresh_script_width():
    """The ops refresh script populates the gallery using the same
    HASH_HEX_LEN constant. Mismatched widths would make every
    runtime lookup miss against ops-populated hashes."""
    from api.services.favicon_hash import HASH_HEX_LEN
    assert HASH_HEX_LEN == 24
    assert len(_hash_bytes(b"x")) == HASH_HEX_LEN


def test_hash_bytes_differs_on_one_byte_change():
    a = _hash_bytes(b"abc")
    b = _hash_bytes(b"abd")
    assert a != b, "Even single-byte changes must change the hash"


# ───────────────────────────────────────────────────────────────
# looks_like_favicon / _fetch_favicon
# ───────────────────────────────────────────────────────────────

@pytest.mark.parametrize("kind", sorted(ICON_SAMPLES))
def test_looks_like_favicon_accepts_image_formats(kind):
    assert looks_like_favicon(ICON_SAMPLES[kind])


@pytest.mark.parametrize("kind", sorted(NOT_ICONS))
def test_looks_like_favicon_rejects_error_pages(kind):
    assert not looks_like_favicon(NOT_ICONS[kind])


@pytest.fixture
def mock_favicon_server(monkeypatch):
    """Route _fetch_favicon's pinned client to an in-process handler."""
    import httpx

    import api.services.pinned_http as pinned_http
    state = {"status": 200, "body": b""}

    def _handler(request):
        return httpx.Response(state["status"], content=state["body"])

    def _client(**kwargs):
        kwargs["transport"] = httpx.MockTransport(_handler)
        return httpx.AsyncClient(**kwargs)

    monkeypatch.setattr(pinned_http, "pinned_client", _client)
    return state


@pytest.mark.asyncio
async def test_fetch_favicon_returns_image_bytes(mock_favicon_server):
    mock_favicon_server["body"] = ICON_SAMPLES["ico"]
    assert await _fetch_favicon("brand.example") == ICON_SAMPLES["ico"]


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [AKAMAI_DENIED, WAF_DOWN])
async def test_fetch_favicon_treats_200_error_page_as_missing(mock_favicon_server, body):
    """A bot wall's "200 OK" HTML must not get a hash: a static error page
    shared by many sites would otherwise match them all."""
    mock_favicon_server["body"] = body
    assert await _fetch_favicon("brand.example") is None


@pytest.mark.asyncio
async def test_error_page_is_cached_as_miss(fake_redis, mock_favicon_server):
    from api.services.favicon_hash import get_favicon_hash

    mock_favicon_server["body"] = AKAMAI_DENIED
    assert await get_favicon_hash("brand.example") is None
    assert fake_redis.store["favicon:hash:brand.example"] == "MISS"


# ───────────────────────────────────────────────────────────────
# check_favicon_brand_clone
# ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clone_detected_when_hash_matches_off_brand(
    fake_redis, isolated_gallery, stub_favicon, monkeypatch
):
    """Crafted favicon bytes whose hash matches PayPal's known
    fingerprint on a non-PayPal domain → cloned=True."""
    import api.services.favicon_hash as mod
    # Forge bytes that hash to the known PayPal fingerprint.
    monkeypatch.setattr(mod, "_hash_bytes", lambda b: "abcdef012345fedcba987654")
    stub_favicon["payload"] = b"fake-payload"

    out = await check_favicon_brand_clone("paypal-secure-login.example")
    assert out["cloned"] is True
    assert out["brand"] == "paypal"
    assert out["weight"] == 35
    assert "paypal" in out["detail"]


@pytest.mark.asyncio
async def test_no_clone_when_brands_own_host(
    fake_redis, isolated_gallery, stub_favicon, monkeypatch
):
    """Same hash, BUT the host IS in verified_hosts → not a clone."""
    import api.services.favicon_hash as mod
    monkeypatch.setattr(mod, "_hash_bytes", lambda b: "abcdef012345fedcba987654")
    stub_favicon["payload"] = b"fake"

    out = await check_favicon_brand_clone("paypal.com")
    assert out["cloned"] is False
    assert out["brand"] == "paypal"  # we still know what we matched
    assert out["weight"] == 0


@pytest.mark.asyncio
async def test_no_clone_when_hash_unknown(
    fake_redis, isolated_gallery, stub_favicon, monkeypatch
):
    import api.services.favicon_hash as mod
    monkeypatch.setattr(mod, "_hash_bytes", lambda b: "deadbeefcafe")
    stub_favicon["payload"] = b"some-bytes"

    out = await check_favicon_brand_clone("legit-business.example")
    assert out["cloned"] is False
    assert out["brand"] is None
    assert out["weight"] == 0


@pytest.mark.asyncio
async def test_no_clone_when_favicon_missing(
    fake_redis, isolated_gallery, stub_favicon
):
    """Domain serves no favicon → no hash → no signal. Crucial:
    this MUST NOT crash and MUST NOT default to clone=True."""
    stub_favicon["payload"] = None

    out = await check_favicon_brand_clone("no-favicon.example")
    assert out["cloned"] is False
    assert out["weight"] == 0


@pytest.mark.asyncio
async def test_empty_gallery_returns_neutral(
    fake_redis, monkeypatch, tmp_path, stub_favicon
):
    """If the gallery file is missing the brand-clone check must
    still return a well-formed dict, not raise."""
    import api.services.favicon_hash as mod
    monkeypatch.setattr(mod, "GALLERY_PATH", tmp_path / "missing.json")
    monkeypatch.setattr(mod, "_gallery_cache", None)
    stub_favicon["payload"] = b"x"

    out = await check_favicon_brand_clone("anywhere.example")
    assert out == {
        "cloned": False, "brand": None, "matched_hash": None,
        "weight": 0, "detail": "",
    }


@pytest.mark.asyncio
async def test_case_insensitive_host_match(
    fake_redis, isolated_gallery, stub_favicon, monkeypatch
):
    """User submits PayPal.com (mixed case) — must still match the
    lowercase verified_hosts entry."""
    import api.services.favicon_hash as mod
    monkeypatch.setattr(mod, "_hash_bytes", lambda b: "abcdef012345fedcba987654")
    stub_favicon["payload"] = b"x"

    out = await check_favicon_brand_clone("PayPal.COM")
    assert out["cloned"] is False


# ───────────────────────────────────────────────────────────────
# Integration with calculate_score
# ───────────────────────────────────────────────────────────────

def test_favicon_clone_signal_wires_into_calculate_score():
    """End-to-end: favicon_cloned=True in signals dict must add a
    favicon_brand_clone DomainReason and bump score by 35."""
    from api.services.scoring import calculate_score

    signals = {
        "domain": "paypal-secure-login.example",
        "raw_url": "paypal-secure-login.example",
        "blocklist_hits": 0,
        "favicon_cloned": True,
        "favicon_brand": "paypal",
        "favicon_detail": "Serves paypal favicon off-brand",
        "checks_succeeded": 18,
        "total_checks": 18,
    }
    _, _, reasons = calculate_score(signals)
    clone_reasons = [r for r in reasons if r.signal == "favicon_brand_clone"]
    assert len(clone_reasons) == 1
    assert clone_reasons[0].weight == 35


# ───────────────────────────────────────────────────────────────
# Production gallery sanity
# ───────────────────────────────────────────────────────────────

def test_production_gallery_loads_and_has_known_brands():
    """The shipped JSON file must parse and contain entries for the
    high-value brands we promised to defend."""
    p = pathlib.Path(__file__).resolve().parent.parent / "api" / "data" / "brand_favicons.json"
    with open(p, "r", encoding="utf-8") as f:
        gallery = json.load(f)
    for required in ("paypal", "apple", "google", "microsoft", "chase"):
        assert required in gallery, f"Missing critical brand: {required}"
        entry = gallery[required]
        assert entry.get("verified_hosts"), f"{required} has no verified_hosts"
        # known_favicon_hashes may be empty for now — ops will fill.
        assert isinstance(entry.get("known_favicon_hashes", []), list)


# sha256[:24] of https://www.fedex.com/etc.clientlibs/designs/fedex-common/images/
# resources/fx-favicon.ico, the icon fedex.com's <link rel="shortcut icon"> names:
# 5430 B ICO (16x16 + 32x32), fetched 2026-10-27 and identical in the Wayback
# Machine's 2025-01-03 capture. www.fedex.com/favicon.ico is a "Page Not Found"
# HTML page (every one of 24 Wayback captures in June 2026 is text/html).
FEDEX_ICON = "eab1b9a0ef942d84e3a8ed8c"
# Hashes of bot-wall pages the cron filed before it checked for images
# (#174, #233 and the 2026-06-16 local run). Each page carries a per-request
# incident id, so no fetch ever produces them again.
DEAD_HTML_HASHES = {
    "ups": {"5c2b47f43cadef4d9e8727e3", "279419b97fa7c89075bb3145"},
    "fedex": {"f644a556676907e89b2144cf", "ece22f1455bba697ca6b50db", "437ef929a63eac5b2c5be708"},
    "linkedin": {"19afb2a51408c29a7c654967", "254a2a36f43cc539cb6864b9"},
}


@pytest.mark.asyncio
async def test_fedex_icon_on_an_off_brand_host_is_a_clone(monkeypatch):
    import api.services.favicon_hash as mod
    monkeypatch.setattr(mod, "_gallery_cache", None)  # the shipped gallery

    async def _hash(domain):
        return FEDEX_ICON

    monkeypatch.setattr(mod, "get_favicon_hash", _hash)
    out = await check_favicon_brand_clone("fedex-track-parcel.example")
    assert out["cloned"] is True and out["brand"] == "fedex", out


def test_production_gallery_has_no_bot_wall_hashes():
    p = pathlib.Path(__file__).resolve().parent.parent / "api" / "data" / "brand_favicons.json"
    gallery = json.loads(p.read_text(encoding="utf-8"))
    for brand, dead in DEAD_HTML_HASHES.items():
        known = set(gallery[brand]["known_favicon_hashes"])
        assert not known & dead, brand
        assert known, f"{brand} has no image hash left"

"""Favicon brand-clone detection tests.

Strategy doc Top-20 #2 (partial). Pin the brand-vs-imposter
distinction, the cache MISS path, and the calculate_score wiring.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from api.services.favicon_hash import (
    _hash_bytes,
    check_favicon_brand_clone,
)


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
            "known_favicon_hashes": ["abcdef012345"],
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


def test_hash_bytes_is_12_chars():
    h = _hash_bytes(b"any-payload")
    assert len(h) == 12
    assert all(c in "0123456789abcdef" for c in h)


def test_hash_bytes_differs_on_one_byte_change():
    a = _hash_bytes(b"abc")
    b = _hash_bytes(b"abd")
    assert a != b, "Even single-byte changes must change the hash"


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
    monkeypatch.setattr(mod, "_hash_bytes", lambda b: "abcdef012345")
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
    monkeypatch.setattr(mod, "_hash_bytes", lambda b: "abcdef012345")
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
    monkeypatch.setattr(mod, "_hash_bytes", lambda b: "abcdef012345")
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

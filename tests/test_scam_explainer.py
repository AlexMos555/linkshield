"""Cultural scam-explainer tests — Strategy doc Top-20 #15."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.services.scam_explainer import (
    CATEGORIES,
    LOCALES,
    _CULTURAL,
    _cache_key,
    _deterministic_explanation,
    _llm_available,
    categorise,
    explain_scam,
)


# ─────────────────────────────────────────────────────────────────
# Categorisation
# ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "signals, expected",
    [
        (["credential_form_mismatch"], "credential_phishing"),
        (["favicon_brand_clone", "typosquat_brand_match"], "credential_phishing"),
        (["chase_brand"], "bank_impostor"),
        (["dhl_brand"], "package_delivery_scam"),
        (["metamask_brand"], "crypto_drainer"),
        (["random_unknown_signal"], "generic_suspicious"),
        ([], "generic_suspicious"),
        # Specificity: credential beats bank since rules are in order
        (["credential_form_mismatch", "chase_brand"], "credential_phishing"),
    ],
)
def test_categorise(signals, expected):
    assert categorise(signals) == expected


# ─────────────────────────────────────────────────────────────────
# Cultural payload integrity
# ─────────────────────────────────────────────────────────────────

def test_all_locales_have_all_categories():
    """Every shipped locale must define a hint for every category —
    otherwise we'd surface English fragments on a Hindi user's
    screen, defeating the whole 'culturally aware' story."""
    for locale in LOCALES:
        assert locale in _CULTURAL, f"missing locale {locale}"
        for category in CATEGORIES:
            entry = _CULTURAL[locale].get(category)
            assert entry, f"{locale} missing {category}"
            for field in ("bait", "action", "safe_action"):
                assert entry.get(field), f"{locale}/{category} missing {field}"


def test_cultural_brands_are_locale_native():
    """Spot check: Russian should reference СберБанк, Spanish should
    reference Santander/BBVA, German should reference Sparkasse. If
    these slip into English we have a translation drift."""
    assert "СберБанк" in _CULTURAL["ru"]["credential_phishing"]["bait"]
    assert "BBVA" in _CULTURAL["es"]["bank_impostor"]["bait"] or \
           "BBVA" in _CULTURAL["es"]["credential_phishing"]["bait"]
    assert "Sparkasse" in _CULTURAL["de"]["credential_phishing"]["bait"]
    assert "PIX" in _CULTURAL["pt"]["credential_phishing"]["bait"]


# ─────────────────────────────────────────────────────────────────
# Deterministic explainer (the fallback)
# ─────────────────────────────────────────────────────────────────

def test_deterministic_explanation_is_locale_specific():
    en = _deterministic_explanation("bank_impostor", "en")
    ru = _deterministic_explanation("bank_impostor", "ru")
    assert en != ru
    assert "Сбер" in ru or "Тинькофф" in ru or "банк" in ru
    assert "bank" in en.lower() or "credentials" in en.lower()


def test_deterministic_explanation_unknown_locale_falls_back_to_en():
    explanation = _deterministic_explanation("bank_impostor", "klingon")
    en = _deterministic_explanation("bank_impostor", "en")
    assert explanation == en


def test_deterministic_explanation_unknown_category_falls_back_generic():
    explanation = _deterministic_explanation("never_seen_category", "en")
    generic = _deterministic_explanation("generic_suspicious", "en")
    assert explanation == generic


# ─────────────────────────────────────────────────────────────────
# Cache key
# ─────────────────────────────────────────────────────────────────

def test_cache_key_stable_across_signal_order():
    a = _cache_key("bank_impostor", ["a", "b", "c"], "en")
    b = _cache_key("bank_impostor", ["c", "a", "b"], "en")
    assert a == b


def test_cache_key_differs_by_locale():
    a = _cache_key("bank_impostor", ["a", "b"], "en")
    b = _cache_key("bank_impostor", ["a", "b"], "ru")
    assert a != b


def test_cache_key_differs_by_category():
    a = _cache_key("bank_impostor", ["a"], "en")
    b = _cache_key("crypto_drainer", ["a"], "en")
    assert a != b


def test_cache_key_no_domain_in_key():
    """The key is a hash — but verify the inputs are JUST category,
    signals, locale. Adding a domain later would break per-domain
    cache hits."""
    key = _cache_key("bank_impostor", ["a"], "en")
    assert key.startswith("explainer:v1:")
    assert len(key) <= len("explainer:v1:") + 24


# ─────────────────────────────────────────────────────────────────
# explain_scam orchestrator
# ─────────────────────────────────────────────────────────────────

@pytest.fixture
def no_redis(monkeypatch):
    async def _broken():
        raise RuntimeError("no redis in test")
    import api.services.cache as cache
    monkeypatch.setattr(cache, "get_redis", _broken)


@pytest.fixture
def fake_redis(monkeypatch):
    fake = MagicMock()
    fake.get = AsyncMock(return_value=None)
    fake.setex = AsyncMock()

    async def _get():
        return fake

    import api.services.cache as cache
    monkeypatch.setattr(cache, "get_redis", _get)
    return fake


@pytest.mark.asyncio
async def test_explain_falls_back_to_template_without_llm(no_redis, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = await explain_scam(["chase_brand"], "ru")
    assert result["category"] == "bank_impostor"
    assert result["locale"] == "ru"
    assert result["source"] == "template"
    assert "Сбер" in result["explanation"] or "Тинькофф" in result["explanation"]


@pytest.mark.asyncio
async def test_explain_uses_cache_on_hit(monkeypatch):
    fake = MagicMock()
    fake.get = AsyncMock(return_value="CACHED EXPLANATION")
    fake.setex = AsyncMock()

    async def _get():
        return fake
    import api.services.cache as cache
    monkeypatch.setattr(cache, "get_redis", _get)

    result = await explain_scam(["dhl_brand"], "en")
    assert result["source"] == "cache"
    assert result["explanation"] == "CACHED EXPLANATION"
    fake.setex.assert_not_called()


@pytest.mark.asyncio
async def test_explain_writes_cache_on_template_miss(fake_redis, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    await explain_scam(["dhl_brand"], "en")
    fake_redis.setex.assert_awaited_once()


@pytest.mark.asyncio
async def test_explain_unknown_locale_falls_back_to_en(no_redis):
    result = await explain_scam(["chase_brand"], "klingon")
    assert result["locale"] == "en"


@pytest.mark.asyncio
async def test_explain_empty_signals_returns_generic_localised(no_redis, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = await explain_scam([], "ru")
    assert result["category"] == "generic_suspicious"
    assert "страниц" in result["explanation"].lower() or \
           "приложение" in result["explanation"].lower()


@pytest.mark.asyncio
async def test_explain_llm_failure_falls_back_to_template(fake_redis, monkeypatch):
    """If the LLM key is set but the call throws, we must still
    return a usable answer — never propagate the exception to the
    extension."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    # Sabotage the LLM path so it raises.
    async def _broken_llm(*args, **kwargs):
        raise RuntimeError("simulated LLM outage")

    import api.services.scam_explainer as mod
    monkeypatch.setattr(mod, "_llm_explanation", _broken_llm)

    result = await explain_scam(["chase_brand"], "ru")
    assert result["source"] == "template"
    assert result["explanation"]


# ─────────────────────────────────────────────────────────────────
# Router integration
# ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_explainer_route_smoke(monkeypatch):
    """End-to-end: POST /api/v1/explain returns a localised
    explanation."""
    from fastapi.testclient import TestClient
    from api.main import app

    # Avoid touching real Redis.
    async def _broken():
        raise RuntimeError("test")
    import api.services.cache as cache
    monkeypatch.setattr(cache, "get_redis", _broken)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    client = TestClient(app)
    resp = client.post(
        "/api/v1/explain",
        json={"signals": ["chase_brand"], "locale": "ru"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["category"] == "bank_impostor"
    assert data["locale"] == "ru"
    assert data["source"] == "template"
    assert data["explanation"]


def test_llm_available_reflects_env(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert _llm_available() is False
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    assert _llm_available() is True

"""LLM Judge tests — Strategy #21.

The judge is privacy-load-bearing (domain never reaches the LLM)
and hot-path-load-bearing (must never break analyze_domain). Pin
both surfaces with strict tests.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.services.llm_judge import (
    CAUTION_LOWER,
    CAUTION_UPPER,
    LLM_MAX_SHIFT,
    LLM_MIN_CONFIDENCE,
    _apply_shift_cap,
    _cache_key,
    _extract_judge_features,
    _llm_available,
    _score_band,
    _shift_for_verdict,
    judge_ambiguous_verdict,
)


# ─────────────────────────────────────────────────────────────────
# Privacy: feature extraction strips domain / url
# ─────────────────────────────────────────────────────────────────

def test_feature_extraction_drops_domain_field():
    """The signals dict includes 'domain' and 'raw_url' — both
    MUST be stripped before the payload reaches the LLM."""
    signals = {
        "domain": "phisher.example",
        "raw_url": "https://phisher.example/login?user=alice",
        "blocklist_hits": 0,
        "tranco_ranked": False,
    }
    features = _extract_judge_features(signals, 45)
    assert "domain" not in features
    assert "raw_url" not in features
    assert "phisher" not in str(features)
    assert "alice" not in str(features)


def test_feature_extraction_preserves_safe_signals():
    signals = {
        "domain": "phisher.example",
        "blocklist_hits": 0,
        "tranco_ranked": True,
        "tranco_weight": -15,
        "favicon_cloned": True,
        "favicon_brand": "paypal",
        "no_https": False,
        "domain_age_days": 5,
    }
    features = _extract_judge_features(signals, 55)
    assert features["blocklist_hits"] == 0
    assert features["tranco_ranked"] is True
    assert features["favicon_cloned"] is True
    assert features["favicon_brand"] == "paypal"
    assert features["domain_age_days"] == 5
    assert features["heuristic_score"] == 55


def test_feature_extraction_silently_drops_unknown_signals():
    """A new signal added by future analyzer work MUST NOT silently
    leak to the LLM. Whitelist-based extraction = explicit gate."""
    signals = {
        "domain": "x",
        "blocklist_hits": 0,
        "secret_internal_signal": "should-not-leak",
        "raw_response_body": "<html>also-leaky</html>",
    }
    features = _extract_judge_features(signals, 40)
    assert "secret_internal_signal" not in features
    assert "raw_response_body" not in features


def test_feature_extraction_clamps_score():
    """Score outside [0,100] could break LLM JSON parsing if it
    cascaded — clamp at the boundary."""
    assert _extract_judge_features({}, -5)["heuristic_score"] == 0
    assert _extract_judge_features({}, 150)["heuristic_score"] == 100


def test_feature_extraction_drops_nested_objects():
    """Lists of primitives ok; nested dicts dropped."""
    signals = {
        "missing_security_headers": ["X-Frame-Options", "CSP"],
        "complex_object": {"key": "value"},  # not whitelisted anyway
    }
    features = _extract_judge_features(signals, 50)
    assert features["missing_security_headers"] == ["X-Frame-Options", "CSP"]
    assert "complex_object" not in features


# ─────────────────────────────────────────────────────────────────
# Cache key stability
# ─────────────────────────────────────────────────────────────────

def test_cache_key_stable_across_dict_order():
    a = _cache_key({"a": 1, "b": 2, "heuristic_score": 50})
    b = _cache_key({"b": 2, "a": 1, "heuristic_score": 50})
    assert a == b


def test_cache_key_differs_by_score():
    a = _cache_key({"heuristic_score": 40})
    b = _cache_key({"heuristic_score": 60})
    assert a != b


def test_cache_key_format():
    key = _cache_key({"heuristic_score": 50})
    assert key.startswith("llm_judge:v1:")


# ─────────────────────────────────────────────────────────────────
# Verdict → score shift
# ─────────────────────────────────────────────────────────────────

def test_shift_for_dangerous_pushes_toward_70():
    assert _shift_for_verdict("dangerous", 45) == 20
    # Capped at LLM_MAX_SHIFT.
    assert _shift_for_verdict("dangerous", 30) == LLM_MAX_SHIFT
    # Already above threshold → 0.
    assert _shift_for_verdict("dangerous", 75) == 0


def test_shift_for_safe_pushes_toward_29():
    """Negative shift toward the safe band."""
    assert _shift_for_verdict("safe", 50) == -20
    # Already safe → 0.
    assert _shift_for_verdict("safe", 10) == 0
    # Capped at -LLM_MAX_SHIFT for extreme cases.
    assert _shift_for_verdict("safe", 65) == -LLM_MAX_SHIFT


def test_shift_for_caution_is_zero():
    assert _shift_for_verdict("caution", 50) == 0
    assert _shift_for_verdict("caution", 30) == 0


def test_apply_shift_cap_clamps_oversize_cache_entry():
    """If LLM_MAX_SHIFT was lowered between cache write and read,
    cached shifts must be re-capped on read."""
    cached = {"score_shift": 50}
    assert _apply_shift_cap(cached, 30)["score_shift"] == LLM_MAX_SHIFT
    cached = {"score_shift": -50}
    assert _apply_shift_cap(cached, 30)["score_shift"] == -LLM_MAX_SHIFT


# ─────────────────────────────────────────────────────────────────
# Score-band helper
# ─────────────────────────────────────────────────────────────────

def test_score_band():
    assert _score_band(0) == "safe"
    assert _score_band(CAUTION_LOWER - 1) == "safe"
    assert _score_band(CAUTION_LOWER) == "caution"
    assert _score_band(CAUTION_UPPER - 1) == "caution"
    assert _score_band(CAUTION_UPPER) == "dangerous"
    assert _score_band(100) == "dangerous"


# ─────────────────────────────────────────────────────────────────
# Orchestrator gates
# ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_judge_skips_non_caution_level(monkeypatch):
    """Rule-based verdict was safe or dangerous → no LLM call."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    call_count = {"n": 0}
    async def _broken_llm(_):
        call_count["n"] += 1
        return {"verdict": "dangerous", "confidence": 0.9, "one_line_reason": "x"}

    import api.services.llm_judge as mod
    monkeypatch.setattr(mod, "_call_claude", _broken_llm)

    out = await judge_ambiguous_verdict({"blocklist_hits": 0}, 10, "safe")
    assert out is None
    out = await judge_ambiguous_verdict({"blocklist_hits": 0}, 95, "dangerous")
    assert out is None
    assert call_count["n"] == 0


@pytest.mark.asyncio
async def test_judge_skips_when_blocklist_already_hit(monkeypatch):
    """If a blocklist source already flagged, the verdict is hard
    evidence — don't second-guess with an LLM."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    call_count = {"n": 0}
    async def _llm(_):
        call_count["n"] += 1
        return None

    import api.services.llm_judge as mod
    monkeypatch.setattr(mod, "_call_claude", _llm)

    out = await judge_ambiguous_verdict({"blocklist_hits": 2}, 50, "caution")
    assert out is None
    assert call_count["n"] == 0


@pytest.mark.asyncio
async def test_judge_skips_when_no_api_key(monkeypatch):
    """Without ANTHROPIC_API_KEY the judge is a no-op."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = await judge_ambiguous_verdict({"blocklist_hits": 0}, 50, "caution")
    assert out is None


# ─────────────────────────────────────────────────────────────────
# Live (mocked) LLM path
# ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_judge_dangerous_verdict_applies_positive_shift(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    async def _llm(_):
        return {
            "verdict": "dangerous",
            "confidence": 0.85,
            "one_line_reason": "Fresh domain + free TLD + Let's Encrypt + brand-clone favicon — classic kit signature.",
        }

    async def _broken_redis():
        raise RuntimeError("no redis in test")

    import api.services.llm_judge as mod
    import api.services.cache as cache
    monkeypatch.setattr(mod, "_call_claude", _llm)
    monkeypatch.setattr(cache, "get_redis", _broken_redis)

    out = await judge_ambiguous_verdict(
        {"blocklist_hits": 0, "favicon_cloned": True}, 50, "caution",
    )
    assert out is not None
    assert out["verdict"] == "dangerous"
    assert out["score_shift"] == 20  # caps at LLM_MAX_SHIFT (70-50)
    assert "kit" in out["one_line_reason"].lower()


@pytest.mark.asyncio
async def test_judge_low_confidence_returns_none(monkeypatch):
    """If the model itself is uncertain, don't shift the verdict."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    async def _llm(_):
        return {
            "verdict": "dangerous",
            "confidence": LLM_MIN_CONFIDENCE - 0.1,
            "one_line_reason": "unsure",
        }

    async def _broken_redis():
        raise RuntimeError("no redis")
    import api.services.llm_judge as mod
    import api.services.cache as cache
    monkeypatch.setattr(mod, "_call_claude", _llm)
    monkeypatch.setattr(cache, "get_redis", _broken_redis)

    out = await judge_ambiguous_verdict({"blocklist_hits": 0}, 50, "caution")
    assert out is None


@pytest.mark.asyncio
async def test_judge_llm_failure_returns_none(monkeypatch):
    """LLM crash MUST be silent — analyzer hot path proceeds with
    rule verdict."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    async def _crashing_llm(_):
        raise RuntimeError("simulated SDK outage")

    async def _broken_redis():
        raise RuntimeError("no redis")
    import api.services.llm_judge as mod
    import api.services.cache as cache
    monkeypatch.setattr(mod, "_call_claude", _crashing_llm)
    monkeypatch.setattr(cache, "get_redis", _broken_redis)

    out = await judge_ambiguous_verdict({"blocklist_hits": 0}, 50, "caution")
    assert out is None


# ─────────────────────────────────────────────────────────────────
# Cache integration
# ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_judge_cache_hit_skips_llm(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    import json as _json
    cached_payload = _json.dumps({
        "verdict": "dangerous",
        "confidence": 0.9,
        "one_line_reason": "from cache",
        "score_shift": 15,
    })
    fake_redis = MagicMock()
    fake_redis.get = AsyncMock(return_value=cached_payload)
    fake_redis.setex = AsyncMock()

    async def _get():
        return fake_redis
    import api.services.cache as cache
    monkeypatch.setattr(cache, "get_redis", _get)

    call_count = {"n": 0}
    async def _llm_should_not_run(_):
        call_count["n"] += 1
        return None
    import api.services.llm_judge as mod
    monkeypatch.setattr(mod, "_call_claude", _llm_should_not_run)

    out = await judge_ambiguous_verdict({"blocklist_hits": 0}, 50, "caution")
    assert out is not None
    assert out["source"] == "cache"
    assert out["one_line_reason"] == "from cache"
    assert call_count["n"] == 0


@pytest.mark.asyncio
async def test_judge_writes_cache_on_llm_path(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    fake_redis = MagicMock()
    fake_redis.get = AsyncMock(return_value=None)
    fake_redis.setex = AsyncMock()

    async def _get():
        return fake_redis
    import api.services.cache as cache
    monkeypatch.setattr(cache, "get_redis", _get)

    async def _llm(_):
        return {
            "verdict": "safe",
            "confidence": 0.9,
            "one_line_reason": "popular site features",
        }
    import api.services.llm_judge as mod
    monkeypatch.setattr(mod, "_call_claude", _llm)

    out = await judge_ambiguous_verdict({"blocklist_hits": 0}, 50, "caution")
    assert out is not None
    fake_redis.setex.assert_awaited_once()


# ─────────────────────────────────────────────────────────────────
# llm_available helper
# ─────────────────────────────────────────────────────────────────

def test_llm_available_reflects_env(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert _llm_available() is False
    monkeypatch.setenv("ANTHROPIC_API_KEY", "x")
    assert _llm_available() is True


# ─────────────────────────────────────────────────────────────────
# Tiered model routing — Opus primary, Haiku fallback
# ─────────────────────────────────────────────────────────────────

def test_default_primary_model_is_opus(monkeypatch):
    """The judge defaults to Opus 4.8 (the strongest reasoner).
    Haiku is the fallback, not the primary."""
    # Re-import to get the env-derived value with a clean env.
    import importlib
    import api.services.llm_judge as mod
    importlib.reload(mod)
    assert mod.LLM_JUDGE_MODEL_PRIMARY == "claude-opus-4-8"
    assert "haiku" in mod.LLM_JUDGE_MODEL_FALLBACK.lower()


def test_model_choice_overridable_via_env(monkeypatch):
    monkeypatch.setenv("LLM_JUDGE_MODEL_PRIMARY", "claude-sonnet-4-6")
    import importlib
    import api.services.llm_judge as mod
    importlib.reload(mod)
    assert mod.LLM_JUDGE_MODEL_PRIMARY == "claude-sonnet-4-6"


@pytest.mark.asyncio
async def test_call_claude_uses_primary_first(monkeypatch):
    """The orchestrator MUST hit the primary model first; only
    falls back to Haiku if primary returns None."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    import importlib
    import api.services.llm_judge as mod
    importlib.reload(mod)

    calls: list[str] = []

    async def _fake_call(model, features, max_tokens=280):
        calls.append(model)
        if "opus" in model:
            return {
                "verdict": "dangerous", "confidence": 0.9,
                "one_line_reason": "from primary", "model": model,
            }
        return None

    monkeypatch.setattr(mod, "_call_one_model", _fake_call)
    out = await mod._call_claude({"x": 1})
    assert out is not None
    assert "opus" in calls[0]
    assert len(calls) == 1  # fallback NOT triggered on primary success
    assert out["one_line_reason"] == "from primary"


@pytest.mark.asyncio
async def test_call_claude_falls_back_on_primary_failure(monkeypatch):
    """When Opus is unavailable / times out, Haiku takes over."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    import importlib
    import api.services.llm_judge as mod
    importlib.reload(mod)

    calls: list[str] = []

    async def _fake_call(model, features, max_tokens=280):
        calls.append(model)
        if "opus" in model:
            return None  # primary fails
        return {
            "verdict": "safe", "confidence": 0.8,
            "one_line_reason": "from fallback", "model": model,
        }

    monkeypatch.setattr(mod, "_call_one_model", _fake_call)
    out = await mod._call_claude({"x": 1})
    assert out is not None
    assert out["one_line_reason"] == "from fallback"
    assert len(calls) == 2
    assert "opus" in calls[0]
    assert "haiku" in calls[1]


@pytest.mark.asyncio
async def test_call_claude_no_double_call_when_primary_equals_fallback(
    monkeypatch,
):
    """If ops set both env vars to the same model, we MUST NOT call
    the same model twice on failure."""
    monkeypatch.setenv("LLM_JUDGE_MODEL_PRIMARY", "claude-haiku-4-5-20251001")
    monkeypatch.setenv("LLM_JUDGE_MODEL_FALLBACK", "claude-haiku-4-5-20251001")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    import importlib
    import api.services.llm_judge as mod
    importlib.reload(mod)

    calls: list[str] = []

    async def _fake_call(model, features, max_tokens=280):
        calls.append(model)
        return None

    monkeypatch.setattr(mod, "_call_one_model", _fake_call)
    await mod._call_claude({"x": 1})
    assert len(calls) == 1


# ─────────────────────────────────────────────────────────────────
# Prompt engineering integrity — chain-of-thought / few-shot / categories
# ─────────────────────────────────────────────────────────────────

def test_system_prompt_has_category_breakdown():
    """The system prompt must walk Claude through the 6 signal
    categories — that's the chain-of-thought scaffold."""
    import api.services.llm_judge as mod
    prompt = mod._SYSTEM_PROMPT.lower()
    for category in (
        "threat intel", "popularity", "brand identity",
        "domain age", "content", "structure",
    ):
        assert category in prompt, f"category {category!r} missing from prompt"


def test_system_prompt_has_few_shot_examples():
    """Three examples (safe / dangerous / ambiguous) anchor the
    model's calibration."""
    import api.services.llm_judge as mod
    # We count INPUT: blocks (which precede each example).
    assert mod._SYSTEM_PROMPT.count("INPUT:") >= 3


def test_system_prompt_demands_self_critique():
    """The model must consider the strongest counter-argument
    before committing — guards against motivated-reasoning bias."""
    import api.services.llm_judge as mod
    assert "counter-argument" in mod._SYSTEM_PROMPT.lower()


def test_system_prompt_locks_output_to_strict_json():
    import api.services.llm_judge as mod
    p = mod._SYSTEM_PROMPT
    assert "STRICT JSON" in p
    assert '"verdict"' in p
    assert '"confidence"' in p
    assert '"one_line_reason"' in p


def test_system_prompt_forbids_inventing_features():
    """Anti-hallucination guard: the model must never claim signals
    we didn't send."""
    import api.services.llm_judge as mod
    p = mod._SYSTEM_PROMPT.lower()
    assert "never" in p
    # The 'INPUT' / 'OUTPUT' contract makes this explicit.
    assert "you never see the actual url" in p


def test_system_prompt_calibrated_confidence_rubric():
    """The 0.6 floor is baked into the prompt so the model
    explicitly outputs lower confidence when uncertain instead
    of pretending."""
    import api.services.llm_judge as mod
    p = mod._SYSTEM_PROMPT
    assert "0.60" in p or "0.6" in p
    assert "rubric" in p.lower() or "CONFIDENCE RUBRIC" in p

"""The block page's explanation speaks of a suspicion, never a certainty.

Every block page whose reasons include Google's (safe_browsing) asks
/api/v1/explain, and Google's hit maps to credential_phishing. The template
then read "the criminals running this page will use it within minutes to
drain accounts" — under "Advisory provided by Google", whose rules
(docs.cloud.google.com/web-risk/docs/user-warnings, read 2026-11-04) bar
leading people to believe a page "is, without a doubt, an unsafe web
resource" and ask for words such as "may" or "suspected". The same goes for
the other categories: every one of them is a guess from signals.

Now every `action` fragment in every locale is hedged, the LLM is told the
site is only suspected, and the explanations cached under the old wording
(seven days) are retired by a new cache-key version.
"""
from __future__ import annotations

import pytest

from api.services import scam_explainer
from api.services.scam_explainer import CATEGORIES, LOCALES, _CULTURAL, _deterministic_explanation

# A word in each language that says "may / could / might".
HEDGES = {
    "en": ("may ", "could ", "might "),
    "ru": ("может", "могут"),
    "es": ("puede", "pueden", "podría", "podrían"),
    "pt": ("pode", "podem", "poderia", "poderiam"),
    "fr": ("peut", "peuvent", "pourrait", "pourraient"),
    "de": ("kann", "können", "könnte", "könnten"),
    "it": ("può", "possono", "potrebbe", "potrebbero"),
    "id": ("bisa", "dapat", "mungkin"),
    "hi": ("सकता", "सकती", "सकते"),
    "ar": ("قد ",),
}

# What the old fragments said as fact.
CERTAIN_EN = ("will use", "will ", " drains ", "harvests ", "passes them", "empties ")


def test_every_locale_has_its_hedge_words():
    assert set(HEDGES) == set(LOCALES)


@pytest.mark.parametrize("locale", LOCALES)
@pytest.mark.parametrize("category", CATEGORIES)
def test_every_action_is_a_possibility(locale, category):
    action = _CULTURAL[locale][category]["action"]
    assert any(h in action for h in HEDGES[locale]), f"{locale}/{category}: {action!r} states a certainty"


@pytest.mark.parametrize("category", CATEGORIES)
def test_english_template_states_no_certainty(category):
    text = _deterministic_explanation(category, "en")
    for phrase in CERTAIN_EN:
        assert phrase not in text, f"{category}: {text!r}"


def test_google_hit_explanation_is_hedged():
    """What the block page shows under Google's credit when no LLM key is set."""
    text = _deterministic_explanation(scam_explainer.categorise(["safe_browsing"]), "en")
    assert "could" in text or "may" in text
    assert "criminals running this page" not in text


def test_llm_is_told_the_site_is_only_suspected():
    prompt = scam_explainer.SYSTEM_PROMPT
    assert "suspected" in prompt
    assert "may" in prompt and "possibly" in prompt
    assert "never" in prompt.lower() and "certain" in prompt.lower()
    # The old instruction asked it to explain "why a flagged page is dangerous".
    assert "is dangerous" not in prompt


def test_explanations_cached_under_the_old_wording_are_retired():
    assert scam_explainer._cache_key("credential_phishing", ["safe_browsing"], "en").startswith("explainer:v2:")
    assert scam_explainer._category_cache_key("credential_phishing", "en").startswith("explainer:v2:")


def test_the_llm_call_sends_that_prompt(monkeypatch):
    import asyncio
    import sys
    import types

    seen: dict = {}

    class _Messages:
        async def create(self, **kwargs):
            seen.update(kwargs)
            return types.SimpleNamespace(content=[types.SimpleNamespace(type="text", text="It may be a fake.")])

    class _Client:
        def __init__(self, *a, **k):
            self.messages = _Messages()

    monkeypatch.setitem(sys.modules, "anthropic", types.SimpleNamespace(AsyncAnthropic=_Client))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    out = asyncio.run(scam_explainer._llm_explanation("credential_phishing", ["safe_browsing"], "en"))
    assert out == "It may be a fake."
    assert seen["system"] == scam_explainer.SYSTEM_PROMPT

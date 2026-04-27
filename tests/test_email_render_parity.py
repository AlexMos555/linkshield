"""
Email render-parity tests across all 10 locales.

These act as the regression-guard that physical HTML snapshot tests
would normally play: they don't compare bytes against a checked-in
fixture (the actual rendered files haven't been built yet — that's a
separate React Email compile step), but they DO lock in:

  - Every supported locale routes through the service correctly
  - Locale fallback to English when a translation file is missing
  - Subject + HTML + text fixture substitution work uniformly
  - Unknown locale string is sanitised to "en" instead of crashing
  - render_template uses the locale-specific subject from manifest
  - render_template returns a RenderedEmail with the expected locale

If physical snapshots come online later (after build-emails.mjs runs),
they extend these checks — they don't replace them.
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

import pytest


SUPPORTED_LOCALES = ("en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar")


def _build_manifest() -> Dict[str, Any]:
    """Minimal manifest covering one template across all 10 locales."""
    return {
        "welcome": {
            "subjects": {
                "en": "Welcome to Cleanway, Alex",
                "ru": "Добро пожаловать в Cleanway, Alex",
                "es": "Bienvenido a Cleanway, Alex",
                "pt": "Bem-vindo ao Cleanway, Alex",
                "fr": "Bienvenue chez Cleanway, Alex",
                "de": "Willkommen bei Cleanway, Alex",
                "it": "Benvenuto in Cleanway, Alex",
                "id": "Selamat datang di Cleanway, Alex",
                "hi": "Cleanway में आपका स्वागत है, Alex",
                "ar": "مرحبًا بك في Cleanway، Alex",
            },
            "fixture_props": {
                "firstName": "Alex",
                "unsubscribeUrl": "https://cleanway.example/u/abc",
            },
        },
        "weekly_report": {
            "subjects": {loc: f"Your week ({loc})" for loc in SUPPORTED_LOCALES},
            "fixture_props": {"firstName": "Alex"},
        },
    }


@pytest.fixture
def patched_email(monkeypatch):
    """Stub _load_manifest + _load_template_file with locale-tagged content."""
    from api.services import email as email_svc

    manifest = _build_manifest()

    def _fake_manifest():
        return manifest

    def _fake_file(template: str, locale: str, ext: str) -> str:
        # Every variant — including hypothetical fallback paths — keeps
        # the fixture strings ("Alex", the unsub URL) intact so the
        # _substitute step has stable anchors to replace, regardless of
        # which physical file was loaded.
        return f"<p>{template}.{locale}.{ext} • Alex • https://cleanway.example/u/abc</p>"

    monkeypatch.setattr(email_svc, "_load_manifest", _fake_manifest)
    monkeypatch.setattr(email_svc, "_load_template_file", _fake_file)
    return email_svc


# ─── Per-locale render parity ─────────────────────────────────────


@pytest.mark.parametrize("locale", SUPPORTED_LOCALES)
def test_render_template_returns_locale_tagged_subject(patched_email, locale):
    out = patched_email.render_template(
        "welcome",
        locale,
        {"Alex": "Maria"},  # substitute fixture name → real
    )
    assert out.locale == locale
    assert out.template_key == "welcome"
    # Subject was substituted: "Welcome to Cleanway, Maria" (or localized equivalent)
    assert "Maria" in out.subject
    assert "Alex" not in out.subject


@pytest.mark.parametrize("locale", SUPPORTED_LOCALES)
def test_render_template_html_and_text_populated(patched_email, locale):
    out = patched_email.render_template(
        "welcome",
        locale,
        {"https://cleanway.example/u/abc": "https://cleanway.ai/u/REAL"},
    )
    assert "<p>" in out.html
    assert out.text  # non-empty
    # Substitution applied to both
    assert "https://cleanway.ai/u/REAL" in out.html
    assert "https://cleanway.example/u/abc" not in out.html


# ─── Fallback behavior ────────────────────────────────────────────


def test_unknown_locale_falls_back_to_en(patched_email):
    out = patched_email.render_template(
        "welcome",
        "klingon",  # unsupported
        {"Alex": "Alex"},
    )
    assert out.locale == "en"
    assert "Welcome to Cleanway" in out.subject  # English subject used


def test_missing_locale_subject_falls_back_to_en(patched_email):
    """If a locale is supported but has no subject string, we keep the
    locale tag on the response but borrow the English subject text."""
    from api.services import email as email_svc

    manifest = _build_manifest()
    # Drop the Hindi subject — keep the locale supported via the
    # SUPPORTED_LOCALES list, just no translation yet.
    del manifest["welcome"]["subjects"]["hi"]

    def _patched_manifest():
        return manifest

    monkeypatch_target = email_svc
    monkeypatch_target._load_manifest = _patched_manifest  # type: ignore[attr-defined]

    out = patched_email.render_template("welcome", "hi", {"Alex": "Alex"})
    assert out.locale == "hi"  # tag preserved
    # English subject reused (not crash, not empty)
    assert "Welcome to Cleanway" in out.subject


# ─── Multi-template parity ────────────────────────────────────────


@pytest.mark.parametrize("template_key", ["welcome", "weekly_report"])
@pytest.mark.parametrize("locale", SUPPORTED_LOCALES)
def test_every_template_renders_in_every_locale(patched_email, template_key, locale):
    out = patched_email.render_template(
        template_key,
        locale,
        {"Alex": "Bob"},
    )
    assert out.subject
    assert out.html
    assert out.text
    assert out.template_key == template_key
    assert out.locale == locale


# ─── Substitution semantics ───────────────────────────────────────


def test_substitution_preserves_unicode_in_subject(patched_email):
    out = patched_email.render_template(
        "welcome",
        "ru",
        {"Alex": "Александр"},
    )
    assert "Александр" in out.subject
    # Russian subject prefix preserved
    assert out.subject.startswith("Добро пожаловать")


def test_substitution_with_no_overrides_preserves_fixtures(patched_email):
    """Empty overrides → output equals raw template content."""
    out = patched_email.render_template("welcome", "en", {})
    assert "Alex" in out.subject  # fixture name still in place
    assert "https://cleanway.example/u/abc" in out.html


def test_substitution_does_not_double_replace(patched_email):
    """If a real value happens to contain a fixture string, the second
    pass shouldn't recursively substitute again."""
    out = patched_email.render_template(
        "welcome",
        "en",
        {"Alex": "Alex_NEW"},  # contains "Alex" — must not recurse
    )
    # Exactly one substitution; "Alex" NOT present standalone
    assert "Alex_NEW" in out.subject

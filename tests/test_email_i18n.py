"""Test that all email.* keys exist in all 10 locales with placeholders preserved.

Why this test exists: if someone adds a new email string to en.json but forgets
the other 9 files, build-i18n.py will warn but not fail. Here we fail hard.

Also validates:
  - Every placeholder in the EN string appears in every translation
    (otherwise backend substitution silently drops a user's name)
  - Trust invariants are present in every locale (no breakdown of "blocking is
    free" messaging just because one translator took creative license)
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
I18N_DIR = ROOT / "packages" / "i18n-strings" / "src"

LOCALES = ["en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar"]

EMAIL_TEMPLATES = [
    "welcome",
    "receipt",
    "weekly_report",
    "family_invite",
    "breach_alert",
    "subscription_cancel",
    "granny_mode_invite",
]


def _load(locale: str) -> dict:
    return json.loads((I18N_DIR / f"{locale}.json").read_text(encoding="utf-8"))


def _leaves(node, prefix: str = "") -> dict:
    """Return {dotted.key: entry} for every leaf (has 'text' key)."""
    out: dict = {}
    if isinstance(node, dict):
        if "text" in node and isinstance(node["text"], str):
            out[prefix] = node
        else:
            for k, v in node.items():
                out.update(_leaves(v, f"{prefix}.{k}" if prefix else k))
    return out


@pytest.fixture(scope="module")
def en_email() -> dict:
    """{dotted_key: entry} for email.* namespace in English."""
    en = _load("en")
    return _leaves(en.get("email", {}), "email")


# ═══════════════════════════════════════════════════════════════
# Structural tests — every locale has every email key
# ═══════════════════════════════════════════════════════════════


@pytest.mark.parametrize("locale", LOCALES)
def test_all_email_keys_present_in_locale(locale, en_email):
    data = _load(locale)
    leaves = _leaves(data.get("email", {}), "email")
    missing = [k for k in en_email if k not in leaves]
    assert not missing, f"[{locale}] missing email keys: {missing[:5]}{'...' if len(missing) > 5 else ''}"


@pytest.mark.parametrize("locale", LOCALES)
def test_each_template_has_subject(locale):
    data = _load(locale).get("email", {})
    for tpl in EMAIL_TEMPLATES:
        assert tpl in data, f"[{locale}] template '{tpl}' missing"
        assert "subject" in data[tpl], f"[{locale}] email.{tpl}.subject missing"
        subject = data[tpl]["subject"]["text"]
        assert subject.strip(), f"[{locale}] email.{tpl}.subject is empty"
        assert len(subject) <= 120, f"[{locale}] email.{tpl}.subject too long ({len(subject)} chars)"


# ═══════════════════════════════════════════════════════════════
# Placeholder parity — if EN says $NAME$, every locale must too
# ═══════════════════════════════════════════════════════════════


def _find_placeholders(text: str):
    return set(re.findall(r"\$([A-Z_]+)\$", text))


@pytest.mark.parametrize("locale", [l for l in LOCALES if l != "en"])
def test_placeholders_preserved_in_translation(locale, en_email):
    data = _load(locale)
    leaves = _leaves(data.get("email", {}), "email")
    errors = []
    for key, en_entry in en_email.items():
        en_placeholders = _find_placeholders(en_entry["text"])
        if not en_placeholders:
            continue
        if key not in leaves:
            continue  # caught by structural test
        loc_text = leaves[key]["text"]
        loc_placeholders = _find_placeholders(loc_text)
        missing = en_placeholders - loc_placeholders
        if missing:
            errors.append(f"{key}: missing {missing} in {locale} text")
    assert not errors, f"[{locale}] placeholder parity broken:\n  " + "\n  ".join(errors[:10])


# ═══════════════════════════════════════════════════════════════
# Brand / trust invariants
# ═══════════════════════════════════════════════════════════════


@pytest.mark.parametrize("locale", LOCALES)
def test_unsubscribe_link_present(locale):
    data = _load(locale).get("email", {}).get("common", {})
    assert "unsubscribe_link" in data, f"[{locale}] email.common.unsubscribe_link missing"
    text = data["unsubscribe_link"]["text"].strip()
    assert text, f"[{locale}] unsubscribe_link is empty"
    assert len(text) < 80, f"[{locale}] unsubscribe_link suspiciously long"


@pytest.mark.parametrize("locale", LOCALES)
def test_subscription_cancel_preserves_free_invariant(locale):
    """subscription_cancel must reaffirm 'blocking keeps working'.

    Ethical invariant — user reading cancel email must understand blocking continues.
    We enforce via structure + non-trivial length (translator can't blank it out).
    """
    data = _load(locale).get("email", {}).get("subscription_cancel", {})
    assert "body_p1" in data
    assert "body_p2_keep_free" in data
    for key in ("body_p1", "body_p2_keep_free"):
        text = data[key]["text"].strip()
        assert len(text) > 20, f"[{locale}] email.subscription_cancel.{key} suspiciously short"


# ═══════════════════════════════════════════════════════════════
# Count parity
# ═══════════════════════════════════════════════════════════════


def test_all_locales_have_same_leaf_count():
    en_leaves = _leaves(_load("en").get("email", {}), "email")
    en_count = len(en_leaves)
    for locale in LOCALES:
        data = _load(locale)
        locale_leaves = _leaves(data.get("email", {}), "email")
        assert len(locale_leaves) == en_count, (
            f"[{locale}] has {len(locale_leaves)} email keys, EN has {en_count}"
        )

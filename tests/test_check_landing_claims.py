"""scripts/check-landing-claims.py — the guard against false landing promises.

The review of the landing-honesty fix found two gaps in the guard itself:
most rules only looked at English or Russian, so "nunca sale de tu
dispositivo" could come back in Spanish with CI green; and nothing tied the
privacy policy's "from version 1.0.2 …" to the app that actually ships. These
tests pin both, using sentences that really were on the site.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

GUARD_PATH = Path(__file__).resolve().parent.parent / "scripts" / "check-landing-claims.py"


def _load_guard() -> ModuleType:
    """Import the hyphenated script as a module (dataclasses need it in sys.modules)."""
    name = "check_landing_claims"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, GUARD_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


guard = _load_guard()
ALL_RULES = (*guard.STRING_RULES, *guard.CHROME_CTA_RULES)
RELEASED = (1, 0, 1)


def _findings(locale: str, landing: dict) -> list[str]:
    return guard.check_strings(ALL_RULES, {locale: landing})


def _policy(text: str) -> dict:
    return {"privacy_policy": {"sections": [{"title": "3.", "paragraphs": [text]}]}}


def test_committed_strings_are_clean() -> None:
    sources = guard.load_sources()
    assert set(sources) == set(guard.LOCALES)
    assert guard.check_strings(ALL_RULES, sources) == []
    assert guard.check_app_version(sources, guard.released_app_version()) == []


def test_every_claim_is_spelled_for_every_locale() -> None:
    for claim in (*guard.CLAIMS, guard.CHROME_CTA):
        assert set(claim.patterns) == set(guard.LOCALES), claim.why


# Sentences that were live on cleanway.ai (main @067c5ff) or in the first
# version of this branch, one per locale the old guard ignored.
NEVER_LEAVES = {
    "es": "Tu historial de navegación nunca sale del dispositivo.",
    "pt": "Seu histórico de navegação nunca sai do seu dispositivo.",
    "fr": "Votre historique de navigation ne quitte jamais votre appareil.",
    "de": "Ihr Browserverlauf verlässt nie Ihr Gerät.",
    "it": "La tua cronologia di navigazione non lascia mai il tuo dispositivo.",
    "id": "Riwayat penjelajahan Anda tidak pernah meninggalkan perangkat Anda.",
    "hi": "आपका ब्राउज़िंग इतिहास कभी आपके डिवाइस से बाहर नहीं जाता।",
    "ar": "سجل التصفح لا يغادر جهازك أبداً.",
}


@pytest.mark.parametrize("locale,text", sorted(NEVER_LEAVES.items()))
def test_never_leaves_claim_is_caught_in_every_language(locale: str, text: str) -> None:
    assert _findings(locale, {"faq": {"items": [{"a": text}]}}), f"{locale} over-claim passed"


ADD_TO_CHROME = {
    "es": "Añadir a Chrome — gratis",
    "pt": "Adicionar ao Chrome — grátis",
    "fr": "Ajouter à Chrome — gratuit",
    "de": "Zu Chrome hinzufügen — kostenlos",
    "it": "Aggiungi a Chrome — gratis",
    "id": "Tambahkan ke Chrome — gratis",
    "hi": "Chrome में जोड़ें — मुफ़्त",
    "ar": "إضافة إلى Chrome — مجاني",
}


@pytest.mark.parametrize("locale,text", sorted(ADD_TO_CHROME.items()))
def test_chrome_cta_is_caught_in_every_language(locale: str, text: str) -> None:
    assert _findings(locale, {"hero": {"cta_primary": text}})


@pytest.mark.parametrize("locale,text", [
    ("ru", "В открытом виде он не хранится; там, где нужна запись, мы храним только укороченный хеш."),
    ("en", "It is not stored as is; where a record is needed, we keep only a shortened hash."),
    ("de", "Sie wird nicht im Klartext gespeichert."),
    ("fr", "Elle n'est pas conservée telle quelle."),
])
def test_ip_never_stored_claim_is_caught(locale: str, text: str) -> None:
    assert _findings(locale, {"privacy_policy": {"sections": [{"after": [text]}]}})


@pytest.mark.parametrize("locale,text", [
    ("ru", "Перед отправкой мы убираем из них имена сайтов и адреса."),
    ("en", "Before sending, we remove site names and addresses from them."),
    ("es", "Antes de enviarlos quitamos de ellos los nombres de sitios y las direcciones."),
])
def test_sentry_strips_sites_claim_is_caught(locale: str, text: str) -> None:
    assert _findings(locale, {"privacy_policy": {"sections": [{"paragraphs": [text]}]}})


@pytest.mark.parametrize("locale,text", [
    ("ru", "На экране блокировки нажмите «Это не мошенники»."),
    ("en", 'On the block screen, tap "Not a scam".'),
    ("de", "Tippe auf dem Sperrbildschirm auf „Kein Betrug“."),
    ("ar", "في شاشة الحظر انقر «ليس احتيالًا»."),
])
def test_nonexistent_block_screen_is_caught_on_support(locale: str, text: str) -> None:
    assert _findings(locale, {"support": {"a_fp": text}})


def test_badge_may_not_call_the_server_verdict_blocking() -> None:
    assert _findings("ru", {"hero": {"badge": "{recall}% свежих фишинг-URL заблокированы (замерено)"}})
    assert _findings("en", {"hero": {"badge": "{recall}% of fresh phishing links blocked"}})
    assert not _findings("ru", {"hero": {"badge": "В последнем замере наш сервер назвал опасными {recall}%"}})


def test_policy_must_name_the_released_app_version() -> None:
    assert guard.check_app_version({"ru": _policy("В версии приложения 1.0.1 запросы идут в Cloudflare.")},
                                   RELEASED) == []
    missing = guard.check_app_version({"ru": _policy("Запросы идут в Cloudflare.")}, RELEASED)
    assert len(missing) == 1 and "does not describe the released app 1.0.1" in missing[0]


def test_bumping_the_app_trips_the_policy() -> None:
    """The 1.0.2 release must rewrite the policy in the same change."""
    stale = _policy("В версии приложения 1.0.1 запросы идут в Cloudflare (1.1.1.1).")
    findings = guard.check_app_version({"ru": stale}, (1, 0, 2))
    assert findings and "released app 1.0.2" in findings[0]


def test_unreleased_version_is_caught_anywhere_on_the_site() -> None:
    landing = {**_policy("В версии 1.0.1 — Cloudflare."), "support": {"a_vpn": "Начиная с версии 1.0.2 — DNS оператора."}}
    findings = guard.check_app_version({"ru": landing}, RELEASED)
    assert len(findings) == 1 and "names app version 1.0.2" in findings[0]


def test_ip_addresses_are_not_versions() -> None:
    landing = _policy("В версии 1.0.1: Cloudflare (1.1.1.1), Quad9 (9.9.9.9), 10.0.0.2.")
    assert guard.check_app_version({"ru": landing}, RELEASED) == []

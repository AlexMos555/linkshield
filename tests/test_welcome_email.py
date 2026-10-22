"""The welcome email every web sign-up receives — what is really in it.

2026-10-22 review (backlog rank 10): the endpoint passed
``{"unsubscribe_url": ...}`` as the override, but ``_substitute`` replaces
fixture VALUES, so nothing was replaced. Every sign-up got "Привет, Alex!",
links to cleanway.example (the CTA, the unsubscribe link and "view in
browser"), an unsubscribe header on cleanway.ai/api/... that returns 404, a
mailto: to an address nobody routes, a San Francisco address, and the claim
that browsing data never leaves the device.

Pinned here, against the committed templates in packages/email-templates/out/:
  - no fixture is left after the substitution the endpoint really performs;
  - every link goes to cleanway.ai or api.cleanway.ai, and the unsubscribe
    link is the signed one on the API (the only host that serves the route);
  - the footer names the company that runs Cleanway;
  - send_template refuses to mail anything that still carries a fixture.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier
from tests.supabase_rest_stub import FakeSupabase

LOCALES = ("en", "ru", "es", "pt", "fr", "de", "it", "id", "hi", "ar")
UNSUB = "https://api.cleanway.ai/api/v1/email/unsubscribe/payload.signature"
USER = AuthUser(id="user-777", email="new@example.com", tier=UserTier.free)
HREF = re.compile(r'href="([^"]+)"')
OUT_DIR = Path(__file__).resolve().parent.parent / "packages" / "email-templates" / "out"


def _render(locale: str):
    from api.services.email import fixture_overrides_for, render_template

    return render_template("welcome", locale, fixture_overrides_for("welcome", unsubscribeUrl=UNSUB))


def _check_url(locale: str) -> str:
    return "https://cleanway.ai/check" if locale == "en" else f"https://cleanway.ai/{locale}/check"


@pytest.mark.parametrize("locale", LOCALES)
def test_no_fixture_value_survives_the_substitution(locale):
    out = _render(locale)
    for part in (out.subject, out.html, out.text):
        assert "cleanway.example" not in part
        assert "Alex" not in part
        assert "abc123" not in part


@pytest.mark.parametrize("locale", LOCALES)
def test_every_link_is_ours_and_the_unsubscribe_link_is_the_signed_one(locale):
    out = _render(locale)
    hrefs = HREF.findall(out.html)
    assert hrefs, "the welcome email has no links at all"
    assert all(h.startswith(("https://cleanway.ai/", "https://api.cleanway.ai/")) for h in hrefs), hrefs
    assert UNSUB in hrefs
    assert UNSUB in out.text
    # The CTA opens the site check in the reader's own language.
    assert _check_url(locale) in hrefs


@pytest.mark.parametrize("locale", LOCALES)
def test_the_footer_names_the_operator_not_san_francisco(locale):
    out = _render(locale)
    assert "ACECORE GLOBAL TECHNOLOGIES – FZCO" in out.text
    assert "43029-001" in out.text
    assert "San Francisco" not in out.html and "سان فرانسيسكو" not in out.html


def test_the_plain_text_unsubscribe_link_ends_at_whitespace():
    # A plain-text client finds a link by reading to the next whitespace. The
    # footer once read "…/unsubscribe/<token>·Contact support": the separator
    # and the next word joined the link and verify_token refused it. The
    # footer is shared, so check every template and locale that carries it.
    from api.services.email import _load_manifest

    fixture = "https://cleanway.example/u/abc123"
    checked = 0
    for template, entry in _load_manifest().items():
        if entry["fixture_props"].get("unsubscribeUrl") != fixture:
            continue
        for locale in LOCALES:
            text = (OUT_DIR / template / f"{locale}.txt").read_text(encoding="utf-8")
            end = text.index(fixture) + len(fixture)
            assert end == len(text) or text[end].isspace(), f"{template}/{locale}: {text[end:end + 20]!r}"
            checked += 1
    assert checked >= 70, checked


def test_the_false_device_only_claim_is_gone():
    # PRIVACY_COPY_AUDIT row 3: site names go to our server and on to Google
    # Safe Browsing and others, so "never leaves your device" cannot stay.
    assert not re.search(r"never leaves|stays on your device", _render("en").text, re.IGNORECASE)
    assert "никогда не покида" not in _render("ru").text
    assert "остаются на устройстве" not in _render("ru").text


def test_fixture_overrides_for_names_a_real_fixture():
    from api.services.email import fixture_overrides_for

    overrides = fixture_overrides_for("welcome", unsubscribeUrl=UNSUB)
    (fixture,) = overrides
    assert "cleanway.example" in fixture and overrides[fixture] == UNSUB
    with pytest.raises(KeyError):
        fixture_overrides_for("welcome", unsubscribe_url=UNSUB)  # the key the endpoint used to pass


# ─── send_template ───────────────────────────────────────────────


class _Provider:
    def __init__(self):
        self.sent: list[dict] = []

    async def send(self, **kw):
        from api.services.email import SendResult

        self.sent.append(kw)
        return SendResult(ok=True, provider_message_id="m-1", error=None, send_id="s-1")


@pytest.fixture
def provider(monkeypatch) -> _Provider:
    from api.services import email as email_svc

    p = _Provider()
    monkeypatch.setattr(email_svc, "get_provider", lambda: p)
    return p


@pytest.mark.asyncio
async def test_an_email_with_an_unfilled_fixture_is_not_sent(provider):
    from api.services.email import send_template

    # The pre-fix call: a key that is not a fixture value replaces nothing.
    result = await send_template(
        to="new@example.com",
        template="welcome",
        locale="ru",
        fixture_overrides={"unsubscribe_url": UNSUB},
        unsubscribe_url=UNSUB,
    )
    assert result.ok is False and result.error == "unfilled_placeholder"
    assert provider.sent == []


@pytest.mark.asyncio
async def test_an_unfilled_email_does_not_use_up_the_send_budget(provider, fake_redis, monkeypatch):
    # Welcome allows one send per user per 7 days. The placeholder guard used
    # to run after that send was counted, so the retry on the next sign-in was
    # skipped as rate_limited (ok=True) and the endpoint marked the email sent.
    from api.services.email import fixture_overrides_for, send_template

    async def _subscribed(*_a):
        return False

    monkeypatch.setattr("api.routers.email_unsubscribe.is_unsubscribed", _subscribed)
    common = dict(to="new@example.com", user_id=USER.id, template="welcome", locale="ru", unsubscribe_url=UNSUB)

    first = await send_template(fixture_overrides={"unsubscribe_url": UNSUB}, **common)
    assert first.ok is False and first.error == "unfilled_placeholder"
    retry = await send_template(fixture_overrides=fixture_overrides_for("welcome", unsubscribeUrl=UNSUB), **common)
    assert retry.ok is True and retry.skipped is False
    assert len(provider.sent) == 1


@pytest.mark.asyncio
async def test_list_unsubscribe_offers_only_the_link_that_works(provider):
    from api.services.email import fixture_overrides_for, send_template

    result = await send_template(
        to="new@example.com",
        template="welcome",
        locale="en",
        fixture_overrides=fixture_overrides_for("welcome", unsubscribeUrl=UNSUB),
        unsubscribe_url=UNSUB,
    )
    assert result.ok is True
    (mail,) = provider.sent
    # No mailto: unsubscribe@ is not an Email Routing address, so a client
    # that picks the mailto would send the request nowhere.
    assert mail["headers"]["List-Unsubscribe"] == f"<{UNSUB}>"
    assert mail["headers"]["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"


# ─── POST /api/v1/user/welcome, end to end ───────────────────────


@pytest.fixture
def client(fake_redis, monkeypatch):
    from api import config
    from api.main import app
    from api.services import rate_limiter
    from api.services.auth import (
        get_current_user,
        get_current_user_including_deleted,
        get_current_user_no_disposable,
    )

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)

    async def _redis():
        return fake_redis

    async def _user():
        return USER

    monkeypatch.setattr(rate_limiter, "get_redis", _redis)
    for dep in (get_current_user, get_current_user_including_deleted, get_current_user_no_disposable):
        app.dependency_overrides[dep] = _user
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.mark.parametrize("locale", ["ru", "en"])
def test_welcome_endpoint_mails_a_filled_email_with_a_working_unsubscribe_link(
    client, provider, monkeypatch, locale
):
    import httpx

    from api.routers.email_unsubscribe import verify_token
    from api.services import email as email_svc

    monkeypatch.setenv("UNSUBSCRIBE_HMAC_KEY", "welcome-test-key")
    sb = FakeSupabase()
    sb.on("GET", "/rest/v1/user_settings", body=[])
    sb.on("GET", "/rest/v1/users", body=[{"preferred_locale": locale}])
    monkeypatch.setattr(httpx, "AsyncClient", sb.client())

    async def _within_budget(*_a):
        return True

    async def _subscribed(*_a):
        return False

    monkeypatch.setattr(email_svc, "_check_email_rate_limit", _within_budget)
    monkeypatch.setattr("api.routers.email_unsubscribe.is_unsubscribed", _subscribed)

    assert client.post("/api/v1/user/welcome").json() == {"sent": True, "reason": None}

    (mail,) = provider.sent
    link = re.search(r"<(https://[^>]+)>", mail["headers"]["List-Unsubscribe"]).group(1)
    prefix = "https://api.cleanway.ai/api/v1/email/unsubscribe/"
    assert link.startswith(prefix)
    assert verify_token(link[len(prefix):])["template"] == "welcome"
    assert link in HREF.findall(mail["html"]) and link in mail["text"]
    for part in (mail["subject"], mail["html"], mail["text"]):
        assert "cleanway.example" not in part and "Alex" not in part
    assert _check_url(locale) in HREF.findall(mail["html"])


def test_a_rate_limited_welcome_is_not_marked_sent(client, provider, monkeypatch):
    # A rate-limited call sent nothing. Writing welcome_sent_at would stop the
    # retry for good, e.g. after the provider failed on the counted attempt;
    # left unset, the next sign-in after the window sends it.
    import httpx

    from api.services import email as email_svc

    sb = FakeSupabase()
    sb.on("GET", "/rest/v1/user_settings", body=[{"settings": {"theme": "dark"}}])
    sb.on("GET", "/rest/v1/users", body=[{"preferred_locale": "ru"}])
    monkeypatch.setattr(httpx, "AsyncClient", sb.client())

    async def _over_budget(*_a):
        return False

    async def _subscribed(*_a):
        return False

    monkeypatch.setattr(email_svc, "_check_email_rate_limit", _over_budget)
    monkeypatch.setattr("api.routers.email_unsubscribe.is_unsubscribed", _subscribed)

    assert client.post("/api/v1/user/welcome").json() == {"sent": False, "reason": "rate_limited"}
    assert provider.sent == []
    assert sb.writes() == []

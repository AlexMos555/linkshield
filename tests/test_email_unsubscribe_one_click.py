"""POST /api/v1/email/unsubscribe/{token}: who may unsubscribe, and how.

Two senders POST to this URL:

  * a mail client's built-in "Unsubscribe" button (RFC 8058 one-click). The
    List-Unsubscribe-Post header of every email tells it to send the form
    field ``List-Unsubscribe=One-Click``, urlencoded (RFC 8058 §8.1) or as
    multipart/form-data (§8.3);
  * the confirmation page GET serves to a reader who clicked the link in the
    email body. Its form has only an unnamed submit button, so a browser
    posts an EMPTY body.

The handler used to declare the field as ``List_Unsubscribe`` with no alias,
so the ``List-Unsubscribe`` field a mail client sends never reached it and
both senders looked the same. These tests pin what each request gets.

The signed token in the URL is the only authority: a valid token
unsubscribes whatever the body says, an invalid one never does, and GET
(what link scanners and prefetchers send) only renders the page.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import logging
import re
import time

import pytest
from fastapi.testclient import TestClient

from api.routers import email_unsubscribe as eu
from api.services.logger import JsonFormatter

URL = "/api/v1/email/unsubscribe/{}"


@pytest.fixture(scope="module")
def client() -> TestClient:
    from api.main import app

    return TestClient(app, follow_redirects=False)


@pytest.fixture(autouse=True)
def _fresh_rate_limit_window(fake_redis, monkeypatch):
    """A fresh Redis per test: the unsubscribe limits (per subscription for a
    valid link, per IP for one that does not verify) never carry over
    between tests, and no test depends on a real Redis.
    rate_limiter imported get_redis by name, so patch it there too."""
    from api.services import rate_limiter

    async def _get():
        return fake_redis

    monkeypatch.setattr(rate_limiter, "get_redis", _get)
    return fake_redis


@pytest.fixture
def recorded(monkeypatch) -> list[tuple[str, str, str | None]]:
    """Every unsubscribe the handler records, as (uid, template, source)."""
    calls: list[tuple[str, str, str | None]] = []

    async def fake(payload, source=None):
        calls.append((payload["uid"], payload["template"], source))

    monkeypatch.setattr(eu, "_process_unsubscribe", fake)
    return calls


def _sign(payload: dict, key: bytes | None = None) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    sig = hmac.new(key or eu._get_secret(), raw, hashlib.sha256).digest()
    enc = lambda b: base64.urlsafe_b64encode(b).decode().rstrip("=")  # noqa: E731
    return f"{enc(raw)}.{enc(sig)}"


# ─── RFC 8058 one-click from a mail client ─────────────────────────


def test_one_click_urlencoded_post_is_recognised(client, recorded):
    """RFC 8058 §8.1 verbatim: the field, urlencoded."""
    token = eu.mint_token("user-oc-1", "weekly_report")
    resp = client.post(
        URL.format(token),
        content=b"List-Unsubscribe=One-Click",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200  # RFC 8058 §3.1: never a redirect
    assert "unsubscribed" in resp.text.lower()
    assert recorded == [("user-oc-1", "weekly_report", "one_click")]


def test_one_click_multipart_post_is_recognised(client, recorded):
    """RFC 8058 §8.3: the same field as multipart/form-data (the encoding
    the RFC says a mail client SHOULD use)."""
    token = eu.mint_token("user-oc-2", "breach_alert")
    resp = client.post(URL.format(token), files={"List-Unsubscribe": (None, "One-Click")})
    assert resp.status_code == 200
    assert recorded == [("user-oc-2", "breach_alert", "one_click")]


def test_one_click_post_is_logged_with_its_source(client, monkeypatch, caplog):
    """The real recorder (no Supabase configured → log only) says which path
    the unsubscribe came through, so ops can see one-click reaching us."""
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    token = eu.mint_token("user-oc-3", "welcome")
    with caplog.at_level(logging.INFO, logger="cleanway.email.unsubscribe"):
        resp = client.post(URL.format(token), data={"List-Unsubscribe": "One-Click"})
    assert resp.status_code == 200
    recorded = [r for r in caplog.records if r.getMessage() == "email.unsubscribe.recorded"]
    assert len(recorded) == 1
    line = json.loads(JsonFormatter().format(recorded[0]))  # what production prints
    assert line["source"] == "one_click"
    assert line["template"] == "welcome"


def test_unexpected_one_click_value_still_unsubscribes_and_is_flagged(client, recorded, caplog):
    """Decision: a valid token is the whole authorisation. A List-Unsubscribe
    field with any value other than One-Click is not RFC 8058, but refusing
    it would keep mailing someone who asked us to stop, while the same token
    with an empty body unsubscribes anyway — so it is honoured and logged."""
    token = eu.mint_token("user-oc-4", "welcome")
    sent = "Two-Click <script>"
    with caplog.at_level(logging.WARNING, logger="cleanway.email.unsubscribe"):
        resp = client.post(URL.format(token), data={"List-Unsubscribe": sent})
    assert resp.status_code == 200
    assert recorded == [("user-oc-4", "welcome", "unexpected")]
    flagged = [r for r in caplog.records if r.getMessage() == "email.unsubscribe.bad_one_click_value"]
    assert len(flagged) == 1
    line = JsonFormatter().format(flagged[0])
    assert json.loads(line)["bytes"] == len(sent)
    assert "Two-Click" not in line  # the sender's text is never logged


# ─── The confirmation page's own form (browser) ─────────────────────


def test_browser_form_on_the_landing_page_unsubscribes(client, recorded):
    """Submit the form exactly as the GET page renders it. Its only control
    is an unnamed button, so the browser sends an empty urlencoded body —
    no List-Unsubscribe field — and that must keep unsubscribing."""
    token = eu.mint_token("user-page-1", "weekly_report")
    page = client.get(URL.format(token))
    assert page.status_code == 200

    form = re.search(r'<form method="POST" action="([^"]+)">(.*?)</form>', page.text, re.S)
    assert form is not None
    assert " name=" not in form.group(2)  # nothing named → empty body
    action = html.unescape(form.group(1))
    assert action == URL.format(token)
    assert recorded == []  # rendering the page did not unsubscribe

    resp = client.post(
        action,
        content=b"",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert resp.status_code == 200
    assert "unsubscribed" in resp.text.lower()
    assert recorded == [("user-page-1", "weekly_report", "page")]


def test_post_without_any_body_counts_as_the_page(client, recorded):
    token = eu.mint_token("user-page-2", "welcome")
    resp = client.post(URL.format(token))
    assert resp.status_code == 200
    assert recorded == [("user-page-2", "welcome", "page")]


# ─── Wrong or missing token ────────────────────────────────────────


def _bad_tokens() -> dict[str, str]:
    now = int(time.time())
    fresh = {"uid": "u", "template": "welcome", "iat": now, "p": "email_unsubscribe_v1"}
    payload_part, sig = _sign(fresh).split(".", 1)
    return {
        "garbage": "not-a-token",
        "tampered_signature": f"{payload_part}.{('A' if sig[0] != 'A' else 'B') + sig[1:]}",
        "foreign_key": _sign(fresh, key=b"not-one-of-our-keys"),
        "other_purpose": _sign({**fresh, "p": "password_reset"}),
        "expired": _sign({**fresh, "iat": now - 91 * 86400}),
    }


@pytest.mark.parametrize("kind", sorted(_bad_tokens()))
@pytest.mark.parametrize("body", ["one_click", "page"])
def test_invalid_token_never_unsubscribes(client, recorded, kind, body):
    token = _bad_tokens()[kind]
    data = {"List-Unsubscribe": "One-Click"} if body == "one_click" else None
    resp = client.post(URL.format(token), data=data)
    assert resp.status_code == 400
    assert recorded == []


@pytest.mark.parametrize("path", ["/api/v1/email/unsubscribe/", "/api/v1/email/unsubscribe"])
def test_missing_token_never_unsubscribes(client, recorded, path):
    resp = client.post(path, data={"List-Unsubscribe": "One-Click"})
    assert resp.status_code in (404, 405)
    assert recorded == []


# ─── GET never unsubscribes ────────────────────────────────────────


@pytest.mark.parametrize("query", ["", "?List-Unsubscribe=One-Click"])
def test_get_only_renders_the_page(client, recorded, query):
    """Link scanners and prefetchers GET every URL in a message; only an
    explicit POST may opt the reader out."""
    token = eu.mint_token("user-get-1", "welcome")
    resp = client.get(URL.format(token) + query)
    assert resp.status_code == 200
    assert '<form method="POST"' in resp.text
    assert recorded == []


def test_head_never_unsubscribes(client, recorded):
    token = eu.mint_token("user-get-2", "welcome")
    client.head(URL.format(token))
    assert recorded == []

"""Unsubscribe links behind shared provider addresses (review of #312).

RFC 8058 one-click POSTs come from Gmail's and Yahoo's shared egress
addresses, and link scanners (Microsoft Safe Links, Proofpoint) GET every
link from small pools of their own. Both endpoints used to share one per-IP
budget (20/hour), so at volume scanner GETs and other people's one-clicks
spent it and a real one-click got 429: the unsubscribe was lost, which Gmail
and Yahoo's bulk-sender rules do not allow.

Now a link that verifies is limited per subscription (user + template),
GET and POST counted apart, never per IP; only a link that does not verify
(forged, tampered, expired) is limited per IP, against brute force.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.routers import email_unsubscribe as eu
from api.services import rate_limiter

GMAIL = {"x-forwarded-for": "209.85.220.41"}
SAFE_LINKS = {"x-forwarded-for": "40.107.22.5"}
ONE_CLICK = {"List-Unsubscribe": "One-Click"}


@pytest.fixture
def client() -> TestClient:
    from api.main import app
    return TestClient(app)


@pytest.fixture
def limiter_redis(monkeypatch, fake_redis):
    async def _get():
        return fake_redis

    monkeypatch.setattr(rate_limiter, "get_redis", _get)
    return fake_redis


@pytest.fixture
def settings(monkeypatch, limiter_redis, security_events):
    from api.config import get_settings

    s = get_settings()
    monkeypatch.setattr(s, "rate_limit_fail_closed", False)
    monkeypatch.setattr(s, "trusted_proxy_cidrs", "")
    monkeypatch.setattr(s, "unsubscribe_limit_per_window", 3)
    return s


@pytest.fixture
def link_limit(settings, monkeypatch) -> int:
    monkeypatch.setattr(settings, "unsubscribe_link_limit_per_window", 3)
    return 3


@pytest.fixture
def recorded(monkeypatch) -> list[tuple[str, str]]:
    """Unsubscribes that reached the persistence step (no Supabase here)."""
    seen: list[tuple[str, str]] = []

    async def _record(payload):
        seen.append((payload["uid"], payload["template"]))

    monkeypatch.setattr(eu, "_process_unsubscribe", _record)
    return seen


def _one_click(client, token, headers=GMAIL):
    return client.post(f"/api/v1/email/unsubscribe/{token}", data=ONE_CLICK, headers=headers)


def _scan(client, token, headers=SAFE_LINKS):
    return client.get(f"/api/v1/email/unsubscribe/{token}", headers=headers)


def _ip(n: int) -> dict:
    return {"x-forwarded-for": f"198.51.100.{n}"}


# ── Valid links are not limited per IP ──

def test_one_click_posts_from_one_provider_address_all_succeed(client, settings, recorded):
    tokens = [eu.mint_token(f"user-{i}", "weekly_report") for i in range(10)]

    statuses = [_one_click(client, t).status_code for t in tokens]

    assert statuses == [200] * 10
    assert len(recorded) == 10


def test_scanner_gets_leave_one_clicks_from_the_same_address_alone(client, settings, recorded):
    tokens = [eu.mint_token(f"user-{i}", "weekly_report") for i in range(10)]

    assert [_scan(client, t).status_code for t in tokens] == [200] * 10
    assert [_one_click(client, t, SAFE_LINKS).status_code for t in tokens[:5]] == [200] * 5
    assert len(recorded) == 5


def test_a_link_scanned_past_its_get_budget_still_unsubscribes(client, link_limit, recorded):
    token = eu.mint_token("user-1", "weekly_report")

    scans = [_scan(client, token).status_code for _ in range(link_limit + 2)]

    assert scans == [200] * link_limit + [429, 429]
    assert _one_click(client, token, SAFE_LINKS).status_code == 200
    assert recorded == [("user-1", "weekly_report")]


def test_junk_from_a_shared_address_leaves_valid_links_alone(client, settings, recorded):
    junk = [_scan(client, f"not-a-token-{i}").status_code for i in range(5)]

    assert junk == [400, 400, 400, 429, 429]
    assert _one_click(client, eu.mint_token("user-1", "welcome"), SAFE_LINKS).status_code == 200


def test_a_valid_link_never_touches_a_per_ip_counter(client, settings, recorded, limiter_redis):
    uid = "6f1c2b9e-0d4a-4b7e-9a51-3c8d2e7f1a00"
    token = eu.mint_token(uid, "weekly_report")

    assert _scan(client, token).status_code == 200
    assert _one_click(client, token).status_code == 200

    keys = list(limiter_redis._kv)
    assert keys, "the link's own counters are missing"
    assert not [k for k in keys if k.startswith("rate:ip:")]
    # The counters are keyed by a hash: neither the user id nor the link.
    assert not [k for k in keys if uid in k or token.split(".")[0] in k]


# ── A valid link still has a budget of its own ──

def test_one_link_hammered_from_many_addresses_is_still_capped(client, link_limit, recorded):
    token = eu.mint_token("user-1", "weekly_report")

    statuses = [_one_click(client, token, _ip(n)).status_code for n in range(link_limit + 2)]

    assert statuses == [200] * link_limit + [429, 429]
    assert len(recorded) == link_limit


def test_respellings_of_one_link_share_its_budget(client, link_limit, recorded):
    """base64 decoding here is lenient (extra padding, characters outside the
    alphabet), so one link has many spellings that verify. They must not be
    fresh budgets."""
    token = eu.mint_token("user-1", "weekly_report")
    payload, sig = token.split(".")
    spellings = [token, token + "=", token + "==", f"{payload}=.{sig}", f"{payload[:5]}~{payload[5:]}.{sig}"]
    assert all(eu.verify_token(s) is not None for s in spellings)

    statuses = [_one_click(client, s, _ip(n)).status_code for n, s in enumerate(spellings)]

    assert statuses == [200] * link_limit + [429, 429]


def test_a_link_rate_limited_log_names_neither_the_user_nor_the_link(client, link_limit, recorded, caplog):
    uid = "6f1c2b9e-0d4a-4b7e-9a51-3c8d2e7f1a00"
    token = eu.mint_token(uid, "weekly_report")
    for n in range(link_limit + 1):
        _one_click(client, token, _ip(n))

    hits = [r for r in caplog.records if r.getMessage() == "ip_rate_limit_exceeded"]
    assert hits
    for record in hits:
        printed = repr(vars(record))
        assert uid not in printed
        assert token.split(".")[0] not in printed


# ── Links that do not verify are limited per IP ──

def test_invalid_token_posts_from_one_address_get_429_after_the_limit(client, settings, recorded):
    good = eu.mint_token("user-1", "welcome")
    forged = good.split(".")[0] + ".AAAA" + good.split(".")[1][4:]
    tokens = ["not-a-token", forged, "x.y", "garbage", "still.garbage"]

    statuses = [_one_click(client, t).status_code for t in tokens]

    assert statuses == [400, 400, 400, 429, 429]
    assert recorded == []


def test_invalid_tokens_from_another_address_have_their_own_budget(client, settings, recorded):
    for _ in range(4):
        _one_click(client, "not-a-token", GMAIL)

    assert _one_click(client, "not-a-token", SAFE_LINKS).status_code == 400


# ── Redis down ──

def test_valid_links_fail_open_when_redis_is_down(client, settings, recorded, monkeypatch):
    """An unsubscribe must not be lost to a Redis blip: the signed link is
    the credential. A link that does not verify keeps the fail-closed
    posture production runs with."""
    async def _down():
        raise ConnectionError("simulated Redis outage")

    monkeypatch.setattr(rate_limiter, "get_redis", _down)
    monkeypatch.setattr(settings, "rate_limit_fail_closed", True)

    assert _one_click(client, eu.mint_token("user-1", "welcome")).status_code == 200
    assert _scan(client, eu.mint_token("user-2", "welcome")).status_code == 200
    assert _one_click(client, "not-a-token").status_code == 503
    assert recorded == [("user-1", "welcome")]

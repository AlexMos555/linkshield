"""
Tests for the unsubscribe PERSISTENCE path (Supabase write) and the
send-side suppression check.

The token-signing + HTTP-endpoint behavior is covered by
test_email_unsubscribe.py; this file specifically locks in:

  - _process_unsubscribe merges email_optout into existing settings JSONB,
    preserving other keys (theme, weekly_report, etc.)
  - Read-then-write race: existing email_optout entries are preserved
  - Best-effort: Supabase outage / 500 logs but doesn't raise
  - is_unsubscribed returns True/False from the same JSONB shape
  - send_template suppresses when is_unsubscribed is True (skipped=True)
  - send_template proceeds normally when user_id is None (transactional)
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest


# ─── Shared fakes ──────────────────────────────────────────────────


class FakeUserSettingsTable:
    """Minimal Supabase user_settings stand-in."""

    def __init__(self, initial_settings: Optional[Dict[str, Any]] = None):
        self.row: Optional[Dict[str, Any]] = (
            {"settings": initial_settings} if initial_settings is not None else None
        )
        self.posted: List[Dict[str, Any]] = []

    def build(self):
        fake = self

        class _Resp:
            def __init__(self, status: int, body: Any):
                self.status_code = status
                self._body = body

            def json(self):
                return self._body

        class _MockClient:
            def __init__(self, *_a, **_k):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return None

            async def get(self, url, params=None, headers=None):
                return _Resp(200, [fake.row] if fake.row else [])

            async def post(self, url, json=None, headers=None, params=None):
                fake.posted.append(json or {})
                # Upsert merges into the canonical row
                merged_settings = json.get("settings") if json else None
                fake.row = {"settings": merged_settings}
                return _Resp(201, "")

        return _MockClient


@pytest.fixture
def supabase_env(monkeypatch):
    monkeypatch.setenv("SUPABASE_URL", "https://fake.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_KEY", "service-key-test")


@pytest.fixture
def fake_table(monkeypatch):
    import httpx as _httpx

    fake = FakeUserSettingsTable()
    monkeypatch.setattr(_httpx, "AsyncClient", fake.build())
    return fake


# ─── _process_unsubscribe ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_process_unsubscribe_persists_when_settings_empty(supabase_env, fake_table):
    from api.routers.email_unsubscribe import _process_unsubscribe

    await _process_unsubscribe({"uid": "u1", "template": "weekly_report"})

    assert len(fake_table.posted) == 1
    posted = fake_table.posted[0]
    assert posted["user_id"] == "u1"
    assert posted["settings"]["email_optout"] == {"weekly_report": True}


@pytest.mark.asyncio
async def test_process_unsubscribe_preserves_existing_settings_keys(monkeypatch, supabase_env):
    """Existing theme/weekly_report flags must NOT be overwritten."""
    import httpx as _httpx

    fake = FakeUserSettingsTable(
        initial_settings={
            "theme": "dark",
            "weekly_report": True,
            "sensitivity": "balanced",
        }
    )
    monkeypatch.setattr(_httpx, "AsyncClient", fake.build())

    from api.routers.email_unsubscribe import _process_unsubscribe

    await _process_unsubscribe({"uid": "u2", "template": "breach_alert"})

    posted = fake.posted[0]["settings"]
    assert posted["theme"] == "dark"
    assert posted["weekly_report"] is True
    assert posted["sensitivity"] == "balanced"
    assert posted["email_optout"] == {"breach_alert": True}


@pytest.mark.asyncio
async def test_process_unsubscribe_merges_with_existing_optout(monkeypatch, supabase_env):
    """Subsequent unsubscribes accumulate, not replace."""
    import httpx as _httpx

    fake = FakeUserSettingsTable(
        initial_settings={"email_optout": {"weekly_report": True}}
    )
    monkeypatch.setattr(_httpx, "AsyncClient", fake.build())

    from api.routers.email_unsubscribe import _process_unsubscribe

    await _process_unsubscribe({"uid": "u3", "template": "breach_alert"})

    posted = fake.posted[0]["settings"]
    assert posted["email_optout"] == {
        "weekly_report": True,
        "breach_alert": True,
    }


@pytest.mark.asyncio
async def test_process_unsubscribe_skips_when_supabase_unconfigured(monkeypatch, caplog):
    """Without env vars: log warning, no exception, no DB write attempted."""
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SERVICE_KEY", raising=False)

    from api.routers.email_unsubscribe import _process_unsubscribe

    # Should not raise
    await _process_unsubscribe({"uid": "u4", "template": "welcome"})


@pytest.mark.asyncio
async def test_process_unsubscribe_swallows_persist_failure(monkeypatch, supabase_env, caplog):
    """Supabase 500 must not crash the unsubscribe handler."""
    import httpx as _httpx

    class _FailClient:
        def __init__(self, *_a, **_k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return None

        async def get(self, *_a, **_k):
            class R:
                status_code = 200

                def json(self):
                    return []

            return R()

        async def post(self, *_a, **_k):
            class R:
                status_code = 500

                def json(self):
                    return {}

            return R()

    monkeypatch.setattr(_httpx, "AsyncClient", _FailClient)

    from api.routers.email_unsubscribe import _process_unsubscribe

    # No exception — best-effort path
    await _process_unsubscribe({"uid": "u5", "template": "welcome"})


# ─── is_unsubscribed ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_is_unsubscribed_true_when_flagged(monkeypatch, supabase_env):
    import httpx as _httpx

    fake = FakeUserSettingsTable(
        initial_settings={"email_optout": {"weekly_report": True}}
    )
    monkeypatch.setattr(_httpx, "AsyncClient", fake.build())

    from api.routers.email_unsubscribe import is_unsubscribed

    assert await is_unsubscribed("u1", "weekly_report") is True


@pytest.mark.asyncio
async def test_is_unsubscribed_false_for_other_template(monkeypatch, supabase_env):
    import httpx as _httpx

    fake = FakeUserSettingsTable(
        initial_settings={"email_optout": {"weekly_report": True}}
    )
    monkeypatch.setattr(_httpx, "AsyncClient", fake.build())

    from api.routers.email_unsubscribe import is_unsubscribed

    # different template, same user — must not bleed over
    assert await is_unsubscribed("u1", "breach_alert") is False


@pytest.mark.asyncio
async def test_is_unsubscribed_false_when_supabase_unconfigured(monkeypatch):
    monkeypatch.delenv("SUPABASE_URL", raising=False)
    monkeypatch.delenv("SUPABASE_SERVICE_KEY", raising=False)

    from api.routers.email_unsubscribe import is_unsubscribed

    assert await is_unsubscribed("u-anyone", "weekly_report") is False


@pytest.mark.asyncio
async def test_is_unsubscribed_false_when_no_row(monkeypatch, supabase_env):
    """User has no user_settings row yet — definitely not unsubscribed."""
    import httpx as _httpx

    fake = FakeUserSettingsTable()  # row is None
    monkeypatch.setattr(_httpx, "AsyncClient", fake.build())

    from api.routers.email_unsubscribe import is_unsubscribed

    assert await is_unsubscribed("u-no-row", "weekly_report") is False


# ─── send_template suppression path ────────────────────────────────


@pytest.mark.asyncio
async def test_send_template_skips_when_user_unsubscribed(monkeypatch):
    from api.services import email as email_svc

    async def _fake_unsub(uid, tpl):
        return uid == "u-out" and tpl == "weekly_report"

    monkeypatch.setattr(
        "api.routers.email_unsubscribe.is_unsubscribed", _fake_unsub, raising=False
    )
    # Provider should not be invoked when skipping
    bad_provider_called = {"v": False}

    class _NoopProvider:
        async def send(self, **_kw):
            bad_provider_called["v"] = True
            return email_svc.SendResult(ok=True, provider_message_id="x", error=None, send_id="x")

    monkeypatch.setattr(email_svc, "get_provider", lambda: _NoopProvider())

    result = await email_svc.send_template(
        to="user@test.com",
        user_id="u-out",
        template="weekly_report",
        locale="en",
        fixture_overrides={"unsubscribe_url": "https://cleanway.ai/u/x"},
        unsubscribe_url="https://cleanway.ai/u/x",
    )

    assert result.skipped is True
    assert result.skip_reason == "user_unsubscribed"
    assert result.ok is True  # skip is not an error
    assert bad_provider_called["v"] is False


@pytest.mark.asyncio
async def test_send_template_no_user_id_does_not_check_unsubscribe(monkeypatch):
    """Transactional sends (receipts, password reset) skip the suppression check entirely."""
    from api.services import email as email_svc

    check_called = {"v": False}

    async def _spy_unsub(uid, tpl):
        check_called["v"] = True
        return True  # would suppress if called

    monkeypatch.setattr(
        "api.routers.email_unsubscribe.is_unsubscribed", _spy_unsub, raising=False
    )

    # Stub render + provider so the test doesn't hit the file system / network
    monkeypatch.setattr(
        email_svc,
        "render_template",
        lambda *a, **k: email_svc.RenderedEmail(
            subject="s", html="<p>h</p>", text="t", template_key="receipt", locale="en"
        ),
    )

    sent = {"v": False}

    class _OkProvider:
        async def send(self, **_kw):
            sent["v"] = True
            return email_svc.SendResult(ok=True, provider_message_id="msg-1", error=None, send_id="s-1")

    monkeypatch.setattr(email_svc, "get_provider", lambda: _OkProvider())

    result = await email_svc.send_template(
        to="user@test.com",
        # no user_id
        template="receipt",
        locale="en",
        fixture_overrides={"unsubscribe_url": "https://cleanway.ai/u/x"},
        unsubscribe_url="https://cleanway.ai/u/x",
    )

    assert check_called["v"] is False
    assert sent["v"] is True
    assert result.skipped is False

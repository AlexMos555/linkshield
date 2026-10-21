"""New Supabase API keys (sb_secret_ / sb_publishable_) vs legacy JWT keys.

The backend talks to Supabase (PostgREST, GoTrue admin, Storage) with a
server key. It must prefer SUPABASE_SECRET_KEY over the legacy service_role
JWT, never send an sb_ key as a Bearer token (it isn't a JWT — Supabase only
tolerates it there when it equals `apikey`, and recommends leaving the
header out), and refuse to start with a publishable / anon key in the
server slot. Runbook: docs/runbooks/supabase-jwt-signing-keys.md.
"""
from __future__ import annotations

import base64
import json

import pytest

from api.config import ConfigError, Settings, _DEBUG_TEST_SECRET, validate_settings
from api.services import supabase_keys as sk

SECRET = "sb_secret_AbCdEf0123456789_xyzXYZ"
PUBLISHABLE = "sb_publishable_AbCdEf0123456789_xyz"


def _jwt(role: str) -> str:
    def seg(obj: dict) -> str:
        raw = base64.urlsafe_b64encode(json.dumps(obj).encode()).decode()
        return raw.rstrip("=")

    return f"{seg({'alg': 'HS256', 'typ': 'JWT'})}.{seg({'role': role, 'iss': 'supabase'})}.c2lnbmF0dXJl"


SERVICE_JWT = _jwt("service_role")
ANON_JWT = _jwt("anon")


def _settings(**overrides) -> Settings:
    base = {
        "environment": "development",
        "debug": True,
        "supabase_jwt_secret": _DEBUG_TEST_SECRET,
        "supabase_url": "https://x.supabase.co",
        "supabase_service_key": "",
        "supabase_secret_key": "",
        "supabase_anon_key": "",
        "supabase_publishable_key": "",
        "stripe_secret_key": "",
        "sentry_dsn": "",
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


class TestKeyKind:
    def test_kinds(self):
        assert sk.key_kind(SECRET) == "secret"
        assert sk.key_kind(PUBLISHABLE) == "publishable"
        assert sk.key_kind(SERVICE_JWT) == "legacy_service_role"
        assert sk.key_kind(ANON_JWT) == "legacy_anon"
        assert sk.key_kind("") == "missing"
        assert sk.key_kind("  ") == "missing"
        assert sk.key_kind("svc-key-for-tests") == "unknown"
        assert sk.key_kind("eyJ.not-base64!.x") == "legacy_jwt"

    def test_non_string_is_missing(self):
        # Tests elsewhere hand MagicMock settings around; a mock attribute
        # must never be mistaken for a key.
        from unittest.mock import MagicMock

        assert sk.key_kind(MagicMock()) == "missing"


class TestServerKey:
    def test_prefers_secret_key(self):
        s = _settings(supabase_secret_key=SECRET, supabase_service_key=SERVICE_JWT)
        assert sk.server_key(s) == SECRET

    def test_falls_back_to_legacy_service_key(self):
        s = _settings(supabase_service_key=SERVICE_JWT)
        assert sk.server_key(s) == SERVICE_JWT

    def test_strips_whitespace(self):
        s = _settings(supabase_secret_key=f"  {SECRET}\n")
        assert sk.server_key(s) == SECRET

    def test_empty_when_nothing_set(self):
        assert sk.server_key(_settings()) == ""

    def test_tolerates_mock_settings(self):
        from unittest.mock import MagicMock

        s = MagicMock()
        s.supabase_service_key = "svc"
        # supabase_secret_key is an auto MagicMock attribute — ignored.
        assert sk.server_key(s) == "svc"

    def test_reads_env_when_no_settings(self, monkeypatch):
        monkeypatch.setenv("SUPABASE_SECRET_KEY", SECRET)
        monkeypatch.setenv("SUPABASE_SERVICE_KEY", SERVICE_JWT)
        assert sk.server_key_from_env() == SECRET
        monkeypatch.delenv("SUPABASE_SECRET_KEY")
        assert sk.server_key_from_env() == SERVICE_JWT


class TestPublicKey:
    def test_prefers_publishable(self):
        s = _settings(supabase_publishable_key=PUBLISHABLE, supabase_anon_key=ANON_JWT)
        assert sk.public_key(s) == PUBLISHABLE

    def test_falls_back_to_anon(self):
        assert sk.public_key(_settings(supabase_anon_key=ANON_JWT)) == ANON_JWT


class TestHeaders:
    def test_secret_key_goes_in_apikey_only(self):
        h = sk.api_key_headers(SECRET)
        assert h == {"apikey": SECRET}
        assert "Authorization" not in h

    def test_publishable_key_goes_in_apikey_only(self):
        assert sk.api_key_headers(PUBLISHABLE) == {"apikey": PUBLISHABLE}

    def test_legacy_jwt_also_sent_as_bearer(self):
        h = sk.api_key_headers(SERVICE_JWT)
        assert h == {"apikey": SERVICE_JWT, "Authorization": f"Bearer {SERVICE_JWT}"}

    def test_non_sb_key_keeps_bearer(self):
        # Anything that is not a new sb_ key keeps the old behaviour.
        assert sk.api_key_headers("service-key-test")["Authorization"] == "Bearer service-key-test"

    def test_extra_headers_merged(self):
        h = sk.api_key_headers(SECRET, **{"Content-Type": "application/json", "Prefer": "return=minimal"})
        assert h == {"apikey": SECRET, "Content-Type": "application/json", "Prefer": "return=minimal"}

    def test_user_token_bearer_kept_with_new_key(self):
        # A user's own JWT in Authorization is the documented pattern.
        h = sk.api_key_headers(PUBLISHABLE, Authorization="Bearer user-jwt")
        assert h == {"apikey": PUBLISHABLE, "Authorization": "Bearer user-jwt"}

    def test_server_headers_use_preferred_key(self):
        s = _settings(supabase_secret_key=SECRET, supabase_service_key=SERVICE_JWT)
        assert sk.server_headers(s) == {"apikey": SECRET}

    def test_server_headers_legacy(self):
        s = _settings(supabase_service_key=SERVICE_JWT)
        assert sk.server_headers(s)["Authorization"] == f"Bearer {SERVICE_JWT}"


class TestValidation:
    def test_publishable_in_secret_slot_rejected(self):
        with pytest.raises(ConfigError, match="SUPABASE_SECRET_KEY"):
            validate_settings(_settings(supabase_secret_key=PUBLISHABLE))

    def test_non_sb_secret_in_secret_slot_rejected(self):
        with pytest.raises(ConfigError, match="sb_secret_"):
            validate_settings(_settings(supabase_secret_key=SERVICE_JWT))

    def test_publishable_in_legacy_service_slot_rejected(self):
        with pytest.raises(ConfigError, match="SUPABASE_SERVICE_KEY"):
            validate_settings(_settings(supabase_service_key=PUBLISHABLE))

    def test_anon_jwt_in_service_slot_rejected(self):
        with pytest.raises(ConfigError, match="anon"):
            validate_settings(_settings(supabase_service_key=ANON_JWT))

    def test_secret_in_publishable_slot_rejected(self):
        with pytest.raises(ConfigError, match="SUPABASE_PUBLISHABLE_KEY"):
            validate_settings(_settings(supabase_publishable_key=SECRET))

    def test_secret_in_anon_slot_rejected(self):
        with pytest.raises(ConfigError, match="SUPABASE_ANON_KEY"):
            validate_settings(_settings(supabase_anon_key=SECRET))

    def test_service_role_jwt_in_anon_slot_rejected(self):
        with pytest.raises(ConfigError, match="SUPABASE_ANON_KEY"):
            validate_settings(_settings(supabase_anon_key=SERVICE_JWT))

    def test_valid_new_keys_pass(self):
        validate_settings(_settings(supabase_secret_key=SECRET, supabase_publishable_key=PUBLISHABLE))

    def test_sb_secret_in_legacy_slot_accepted(self):
        # Founder may paste the new key into the old variable — it works.
        validate_settings(_settings(supabase_service_key=SECRET))

    def _prod(self, **overrides) -> Settings:
        base = {
            "environment": "production",
            "debug": False,
            "supabase_jwt_secret": "prod-long-secret-absolutely-at-least-sixty-four-characters-okayyy",
            "supabase_url": "https://prod.supabase.co",
            "supabase_service_key": "",
            "supabase_secret_key": "",
            "stripe_secret_key": "",
            "sentry_dsn": "https://abc@sentry.io/1",
            "rate_limit_fail_closed": True,
            "trusted_proxy_cidrs": "10.0.0.0/8",
        }
        base.update(overrides)
        return Settings(_env_file=None, **base)

    def test_prod_accepts_secret_key_alone(self):
        validate_settings(self._prod(supabase_secret_key=SECRET))

    def test_prod_requires_some_server_key(self):
        with pytest.raises(ConfigError, match="SUPABASE_SECRET_KEY"):
            validate_settings(self._prod())

    def test_prod_legacy_key_warns(self, caplog):
        with caplog.at_level("WARNING"):
            validate_settings(self._prod(supabase_service_key=SERVICE_JWT))
        assert any("legacy" in r.getMessage() for r in caplog.records)
        # The key itself is never logged.
        assert all(SERVICE_JWT not in r.getMessage() for r in caplog.records)


class _Resp:
    def __init__(self, code: int):
        self.status_code = code


def _fake_httpx(monkeypatch, *, status: int = 200, raises: Exception | None = None):
    import httpx

    seen: list[dict] = []

    class _Client:
        def __init__(self, *_a, **_k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return None

        async def get(self, url, headers=None, params=None, **_kw):
            seen.append({"url": url, "headers": headers or {}, "params": params or {}})
            if raises:
                raise raises
            return _Resp(status)

    monkeypatch.setattr(httpx, "AsyncClient", _Client)
    return seen


class TestProbe:
    """/health/deep reports whether the server key really acts as
    service_role on the Auth admin API — the founder's check after
    switching Railway to SUPABASE_SECRET_KEY."""

    @pytest.mark.asyncio
    async def test_secret_key_probe_ok(self, monkeypatch):
        seen = _fake_httpx(monkeypatch, status=200)
        out = await sk.probe_server_key(_settings(supabase_secret_key=SECRET))
        assert out == {"ok": True, "kind": "secret", "status": 200}
        call = seen[0]
        assert call["url"] == "https://x.supabase.co/auth/v1/admin/users"
        assert call["params"] == {"page": 1, "per_page": 1}
        assert call["headers"] == {"apikey": SECRET}

    @pytest.mark.asyncio
    async def test_rejected_key_reported(self, monkeypatch):
        _fake_httpx(monkeypatch, status=401)
        out = await sk.probe_server_key(_settings(supabase_service_key=SERVICE_JWT))
        assert out == {"ok": False, "kind": "legacy_service_role", "status": 401}

    @pytest.mark.asyncio
    async def test_network_error_reported(self, monkeypatch):
        _fake_httpx(monkeypatch, raises=ConnectionError("down"))
        out = await sk.probe_server_key(_settings(supabase_secret_key=SECRET))
        assert out == {"ok": False, "kind": "secret", "error": "ConnectionError"}

    @pytest.mark.asyncio
    async def test_not_configured(self, monkeypatch):
        seen = _fake_httpx(monkeypatch)
        out = await sk.probe_server_key(_settings())
        assert out == {"ok": False, "kind": "missing", "error": "not_configured"}
        assert seen == []


@pytest.mark.asyncio
async def test_watchtower_job_uses_secret_key_without_bearer(monkeypatch):
    """scripts/refresh_watchtower.py runs from GitHub Actions with its own
    env; it must prefer the sb_secret_ key the same way."""
    import importlib.util
    import pathlib

    path = pathlib.Path(__file__).resolve().parent.parent / "scripts" / "refresh_watchtower.py"
    spec = importlib.util.spec_from_file_location("refresh_watchtower_under_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    monkeypatch.setenv("SUPABASE_URL", "https://x.supabase.co")
    monkeypatch.setenv("SUPABASE_SERVICE_KEY", SERVICE_JWT)
    monkeypatch.setenv("SUPABASE_SECRET_KEY", SECRET)

    sent: dict = {}

    class _Http:
        async def request(self, method, url, headers=None, **kw):
            sent.update(method=method, url=url, headers=headers, **kw)
            return _Resp(200)

    await mod._supabase(_Http(), "GET", "brand_watchlist", params={"select": "x"}, headers={"Prefer": "count=none"})
    assert sent["url"] == "https://x.supabase.co/rest/v1/brand_watchlist"
    assert sent["headers"] == {"apikey": SECRET, "Content-Type": "application/json", "Prefer": "count=none"}
    assert sent["params"] == {"select": "x"}


def test_scrubber_redacts_new_keys():
    from api.services.sentry_scrubber import _scrub_string as scrub_string

    out = scrub_string(f"upstream said no for {SECRET} and {PUBLISHABLE}")
    assert SECRET not in out and PUBLISHABLE not in out

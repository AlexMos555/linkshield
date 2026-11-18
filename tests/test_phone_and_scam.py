"""
Tests for Phase H endpoint stubs:
- /api/v1/phone/report + /api/v1/phone/lookup/{hash}
- /api/v1/scam/analyze_text
- /api/v1/scam/analyze_voice (stub — returns pending verdict)

These endpoints are in-scope for Phase H but ship with heuristic-only or
stub implementations until Anthropic/Whisper keys are wired. Tests lock
the contracts so clients can integrate now.
"""
from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier
from api.routers.phone import _verdict_for_counts


# ─── Unit tests on verdict math ──────────────────────────────────────────────


class TestVerdictForCounts:
    def test_unknown_below_threshold(self):
        assert _verdict_for_counts(1, 0, 0) == "unknown"
        assert _verdict_for_counts(0, 2, 0) == "unknown"

    def test_scam_dominates(self):
        # 2 scams weighted = 4, beats spam+legit = 3
        assert _verdict_for_counts(2, 2, 1) == "scam"

    def test_legit_wins_over_small_noise(self):
        assert _verdict_for_counts(0, 1, 10) == "legit"

    def test_spam_dominates(self):
        assert _verdict_for_counts(0, 10, 2) == "spam"

    def test_empty_is_unknown(self):
        assert _verdict_for_counts(0, 0, 0) == "unknown"


# ─── HTTP integration ────────────────────────────────────────────────────────


@pytest.fixture
def authed_client():
    from api.main import app
    from api.services.auth import get_current_user, get_current_user_including_deleted, get_optional_user

    async def _user():
        return AuthUser(id="11111111-1111-1111-1111-111111111111", email="u@t.test", tier=UserTier.free)

    app.dependency_overrides[get_current_user] = _user
    app.dependency_overrides[get_current_user_including_deleted] = _user
    app.dependency_overrides[get_optional_user] = _user
    yield TestClient(app)
    app.dependency_overrides.clear()


@pytest.fixture
def supabase_off(monkeypatch):
    """Force Supabase-degraded mode so writes no-op without network."""
    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "", raising=False)
    return settings


# ─── /phone/report ───────────────────────────────────────────────────────────


SAMPLE_HASH = "a" * 64


class TestPhoneReport:
    def test_accepts_valid_scam_report(self, authed_client, supabase_off):
        resp = authed_client.post(
            "/api/v1/phone/report",
            json={
                "phone_hash": SAMPLE_HASH,
                "country_code": "US",
                "kind": "scam",
                "tag": "bank_fraud",
            },
        )
        assert resp.status_code == 200
        # Supabase unavailable → accepted: False is fine
        assert "accepted" in resp.json()

    def test_rejects_bad_hash_length(self, authed_client, supabase_off):
        resp = authed_client.post(
            "/api/v1/phone/report",
            json={"phone_hash": "short", "country_code": "US", "kind": "scam"},
        )
        assert resp.status_code == 422

    def test_rejects_non_hex_hash(self, authed_client, supabase_off):
        resp = authed_client.post(
            "/api/v1/phone/report",
            json={"phone_hash": "z" * 64, "country_code": "US", "kind": "scam"},
        )
        assert resp.status_code == 422

    def test_rejects_bad_kind(self, authed_client, supabase_off):
        resp = authed_client.post(
            "/api/v1/phone/report",
            json={"phone_hash": SAMPLE_HASH, "country_code": "US", "kind": "dangerous"},
        )
        assert resp.status_code == 422

    def test_rejects_unknown_tag(self, authed_client, supabase_off):
        resp = authed_client.post(
            "/api/v1/phone/report",
            json={
                "phone_hash": SAMPLE_HASH,
                "country_code": "US",
                "kind": "scam",
                "tag": "something_made_up",
            },
        )
        assert resp.status_code == 422


# ─── /phone/lookup/{hash} ────────────────────────────────────────────────────


class TestPhoneLookup:
    def test_unknown_when_supabase_off(self, authed_client, supabase_off):
        resp = authed_client.get(f"/api/v1/phone/lookup/{SAMPLE_HASH}?cc=US")
        assert resp.status_code == 200
        body = resp.json()
        assert body["known"] is False
        assert body["verdict"] == "unknown"

    def test_rejects_malformed_hash(self, authed_client, supabase_off):
        resp = authed_client.get("/api/v1/phone/lookup/not-a-hash?cc=US")
        assert resp.status_code == 422

    def test_rejects_bad_cc(self, authed_client, supabase_off):
        resp = authed_client.get(f"/api/v1/phone/lookup/{SAMPLE_HASH}?cc=usa")
        assert resp.status_code == 422

    def test_no_cc_is_valid(self, authed_client, supabase_off):
        resp = authed_client.get(f"/api/v1/phone/lookup/{SAMPLE_HASH}")
        assert resp.status_code == 200


class _FakeResp:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        return self._payload


class _FakeSupabase:
    """Stands in for httpx.AsyncClient: records writes, serves canned rows."""

    calls: list = []
    crowd_rows: list = []
    verified_rows: list = []

    def __init__(self, *a, **kw):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def post(self, url, **kw):
        type(self).calls.append(("POST", url))
        return _FakeResp(204, None)

    async def get(self, url, **kw):
        type(self).calls.append(("GET", url))
        if url.endswith("/verified_numbers"):
            return _FakeResp(200, type(self).verified_rows)
        return _FakeResp(200, type(self).crowd_rows)


@pytest.fixture
def fake_supabase(monkeypatch):
    import httpx

    from api import config

    settings = config.get_settings()
    monkeypatch.setattr(settings, "supabase_url", "https://db.test", raising=False)
    monkeypatch.setattr(settings, "supabase_service_key", "k", raising=False)
    _FakeSupabase.calls = []
    _FakeSupabase.crowd_rows = []
    _FakeSupabase.verified_rows = []
    monkeypatch.setattr(httpx, "AsyncClient", _FakeSupabase)
    return _FakeSupabase


class TestCrowdVerdictsOffByDefault:
    """
    Report of 2026-11-13: the tally has no per-reporter identity, so one
    account could label any number "scam" (3 votes) or wipe a real warning
    ("legit" votes). Until votes are counted once per reporter, the crowd
    tally is neither written nor served.
    """

    def test_setting_defaults_to_off(self):
        from api.config import Settings

        assert Settings().phone_crowd_reports_enabled is False

    def test_report_is_not_stored(self, authed_client, fake_supabase):
        resp = authed_client.post(
            "/api/v1/phone/report",
            json={"phone_hash": SAMPLE_HASH, "country_code": "US", "kind": "scam"},
        )
        assert resp.status_code == 200
        assert resp.json() == {"accepted": False, "reason": "disabled"}
        assert fake_supabase.calls == []

    def test_report_still_validates_input(self, authed_client, fake_supabase):
        resp = authed_client.post(
            "/api/v1/phone/report",
            json={"phone_hash": SAMPLE_HASH, "country_code": "US", "kind": "dangerous"},
        )
        assert resp.status_code == 422

    def test_lookup_ignores_crowd_tally(self, authed_client, fake_supabase):
        fake_supabase.crowd_rows = [
            {"scam_count": 3, "spam_count": 0, "legit_count": 0, "tags": {"bank_fraud": 3}}
        ]
        resp = authed_client.get(f"/api/v1/phone/lookup/{SAMPLE_HASH}?cc=US")
        assert resp.status_code == 200
        body = resp.json()
        assert body["known"] is False
        assert body["verdict"] == "unknown"
        assert body["scam_count"] == 0
        assert body["top_tags"] == []
        assert not any(u.endswith("/phone_reports") for _, u in fake_supabase.calls)

    def test_lookup_still_serves_verified_numbers(self, authed_client, fake_supabase):
        fake_supabase.verified_rows = [{"org_name": "Example Bank", "org_category": "bank"}]
        resp = authed_client.get(f"/api/v1/phone/lookup/{SAMPLE_HASH}?cc=US")
        body = resp.json()
        assert body["verdict"] == "verified_legit"
        assert body["org_name"] == "Example Bank"

    def test_switch_on_restores_old_behaviour(self, authed_client, fake_supabase, monkeypatch):
        from api import config

        monkeypatch.setattr(config.get_settings(), "phone_crowd_reports_enabled", True, raising=False)
        fake_supabase.crowd_rows = [
            {"scam_count": 3, "spam_count": 0, "legit_count": 0, "tags": {}}
        ]
        assert authed_client.get(f"/api/v1/phone/lookup/{SAMPLE_HASH}?cc=US").json()["verdict"] == "scam"
        resp = authed_client.post(
            "/api/v1/phone/report",
            json={"phone_hash": SAMPLE_HASH, "country_code": "US", "kind": "scam"},
        )
        assert resp.json() == {"accepted": True}


# ─── /scam/analyze_text ──────────────────────────────────────────────────────


class TestScamAnalyzeText:
    def test_clean_text_is_safe(self, authed_client, supabase_off):
        resp = authed_client.post(
            "/api/v1/scam/analyze_text",
            json={"text": "Hi, lunch at 12 works for me. See you then."},
        )
        assert resp.status_code == 200
        assert resp.json()["verdict"] == "safe"

    def test_classic_scam_is_flagged(self, authed_client, supabase_off):
        resp = authed_client.post(
            "/api/v1/scam/analyze_text",
            json={
                "text": "URGENT: Your account will be locked. Verify your password immediately to avoid suspension.",
                "source": "sms",
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["verdict"] in ("suspicious", "scam")
        assert body["risk_score"] >= 25
        # Both urgency + credential_request must appear
        assert "urgency" in body["reason_codes"]
        assert "credential_request" in body["reason_codes"]

    def test_investment_pattern_detected(self, authed_client, supabase_off):
        resp = authed_client.post(
            "/api/v1/scam/analyze_text",
            json={
                "text": "Great investment opportunity with guaranteed returns. Earn $5000 per week with crypto trading signals.",
            },
        )
        body = resp.json()
        assert "investment_pattern" in body["reason_codes"]
        assert "crypto_pattern" in body["reason_codes"]

    def test_delivery_impersonation_detected(self, authed_client, supabase_off):
        resp = authed_client.post(
            "/api/v1/scam/analyze_text",
            json={
                "text": "Your package cannot be delivered. Pay $2.99 customs fee at http://dhl-fake.test/pay",
                "source": "sms",
            },
        )
        body = resp.json()
        assert "impersonation_delivery" in body["reason_codes"]

    def test_empty_text_rejected(self, authed_client, supabase_off):
        resp = authed_client.post(
            "/api/v1/scam/analyze_text",
            json={"text": "   "},
        )
        assert resp.status_code == 422

    def test_oversized_text_rejected(self, authed_client, supabase_off):
        resp = authed_client.post(
            "/api/v1/scam/analyze_text",
            json={"text": "x" * 20_000},
        )
        assert resp.status_code == 422


# ─── /scam/analyze_voice (stub) ──────────────────────────────────────────────


class TestScamAnalyzeVoice:
    def test_valid_audio_returns_pending(self, authed_client, supabase_off):
        audio = io.BytesIO(b"ID3" + b"\x00" * 2048)
        resp = authed_client.post(
            "/api/v1/scam/analyze_voice",
            files={"file": ("clip.mp3", audio, "audio/mpeg")},
            data={"language": "en"},
        )
        assert resp.status_code == 200
        body = resp.json()
        # Stub returns explicit "pending" verdict + 0 score so UIs don't
        # render a misleading "suspicious" indicator on legit voice
        # memos. Summary carries the human-readable explanation.
        assert body["verdict"] == "transcription_pending"
        assert body["risk_score"] == 0
        assert "transcription" in body["summary"].lower()

    def test_rejects_non_audio_mime(self, authed_client, supabase_off):
        resp = authed_client.post(
            "/api/v1/scam/analyze_voice",
            files={"file": ("clip.txt", b"hello", "text/plain")},
        )
        assert resp.status_code == 415

    def test_rejects_empty_upload(self, authed_client, supabase_off):
        resp = authed_client.post(
            "/api/v1/scam/analyze_voice",
            files={"file": ("empty.mp3", b"", "audio/mpeg")},
        )
        assert resp.status_code == 422

"""api/routers/user.py — the non-GDPR endpoints, failure paths first.

Supabase is replaced by tests/supabase_rest_stub.FakeSupabase (real
httpx.Response objects, recorded requests). Pinned here:

  - weekly aggregates / score are written to the columns the table really
    has (supabase/migrations/001: week_start, security_score — the router
    used to write `week` / `score` / `total_warnings`, which PostgREST
    rejects, and answered "ok" anyway);
  - an upstream reject or timeout is never reported as stored;
  - every read/write is scoped to the caller's id (no IDOR via body/path);
  - degraded modes (no database, Redis down, garbage rows) answer safe
    defaults instead of 500s;
  - the welcome email is idempotent and never clobbers user_settings
    (opt-outs) when the settings row can't be read.
"""
from __future__ import annotations

from datetime import date, datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from api.models.schemas import AuthUser, UserTier
from tests.supabase_rest_stub import FakeSupabase

USER = AuthUser(id="user-501", email="eve@example.com", tier=UserTier.free)


@pytest.fixture
def sb(monkeypatch) -> FakeSupabase:
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "https://fake.supabase.co", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "fake-key", raising=False)
    stub = FakeSupabase()
    monkeypatch.setattr(httpx, "AsyncClient", stub.client())
    return stub


@pytest.fixture
def no_db(monkeypatch):
    from api import config

    s = config.get_settings()
    monkeypatch.setattr(s, "supabase_url", "", raising=False)
    monkeypatch.setattr(s, "supabase_service_key", "", raising=False)
    monkeypatch.setattr(s, "supabase_secret_key", "", raising=False)


@pytest.fixture
def client(fake_redis, monkeypatch):
    from api.main import app
    from api.services import rate_limiter
    from api.services.auth import (
        get_current_user,
        get_current_user_including_deleted,
        get_current_user_no_disposable,
    )

    async def _fake():
        return fake_redis

    monkeypatch.setattr(rate_limiter, "get_redis", _fake)

    async def _user():
        return USER

    for dep in (get_current_user, get_current_user_including_deleted, get_current_user_no_disposable):
        app.dependency_overrides[dep] = _user
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


def _is_this_weeks_monday(value: str) -> bool:
    d = date.fromisoformat(value)
    today = datetime.now(timezone.utc).date()
    return d.weekday() == 0 and 0 <= (today - d).days < 7


# ─── POST /aggregates ────────────────────────────────────────────


def test_aggregate_is_written_to_the_real_schema_columns(client, sb):
    resp = client.post(
        "/api/v1/user/aggregates",
        # A foreign user_id in the body is not part of the model: ignored.
        json={"total_checks": 40, "total_blocks": 3, "total_warnings": 2, "total_trackers": 9,
              "score": 81, "user_id": "someone-else"},
    )
    assert resp.status_code == 200, resp.text
    assert _is_this_weeks_monday(resp.json()["week"])

    (write,) = sb.to("POST", "/rest/v1/weekly_aggregates")
    body = write["json"]
    assert body["user_id"] == USER.id
    assert _is_this_weeks_monday(body["week_start"])
    assert body["security_score"] == 81
    assert body["total_checks"] == 40 and body["total_blocks"] == 3 and body["total_trackers"] == 9
    # Columns the table does not have are never sent (PostgREST 400s on them).
    assert not {"week", "score", "total_warnings"} & set(body)
    assert "merge-duplicates" in write["headers"]["Prefer"]


@pytest.mark.parametrize("failure", [
    {"status": 400, "body": {"code": "PGRST204", "message": "column not found"}},
    {"exc": httpx.ReadTimeout("supabase slow")},
])
def test_aggregate_not_stored_is_never_reported_as_ok(client, sb, failure):
    sb.on("POST", "/rest/v1/weekly_aggregates", **failure)
    resp = client.post("/api/v1/user/aggregates", json={"total_checks": 1, "total_blocks": 0})
    assert resp.status_code == 500
    assert resp.json()["detail"] == "Failed to submit aggregate"


def test_aggregate_without_database_is_503(client, no_db):
    assert client.post("/api/v1/user/aggregates", json={"total_checks": 1, "total_blocks": 0}).status_code == 503


@pytest.mark.parametrize("body", [
    {"total_checks": -1, "total_blocks": 0},
    {"total_checks": 1, "total_blocks": 0, "score": 101},
    {"total_blocks": 0},
])
def test_aggregate_validation(client, sb, body):
    assert client.post("/api/v1/user/aggregates", json=body).status_code == 422
    assert sb.calls == []


# ─── POST /score ─────────────────────────────────────────────────


def test_score_is_written_to_security_score_for_this_week(client, sb):
    resp = client.post("/api/v1/user/score", json={"score": 64})
    assert resp.json() == {"status": "ok", "score": 64}
    (write,) = sb.to("POST", "/rest/v1/weekly_aggregates")
    assert write["json"]["user_id"] == USER.id
    assert write["json"]["security_score"] == 64
    assert _is_this_weeks_monday(write["json"]["week_start"])
    assert "score" not in write["json"] and "week" not in write["json"]


@pytest.mark.parametrize("failure", [{"status": 400}, {"exc": httpx.ConnectError("down")}])
def test_score_sync_failure_says_it_will_retry(client, sb, failure):
    sb.on("POST", "/rest/v1/weekly_aggregates", **failure)
    resp = client.post("/api/v1/user/score", json={"score": 64})
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok", "note": "Score sync failed, will retry"}


def test_score_without_database_is_not_persisted(client, no_db):
    assert "not persisted" in client.post("/api/v1/user/score", json={"score": 5}).json()["note"]


def test_score_out_of_range_is_422(client, sb):
    assert client.post("/api/v1/user/score", json={"score": 101}).status_code == 422


# ─── GET /percentile ─────────────────────────────────────────────


def _percentile_rows(sb: FakeSupabase, mine, everyone):
    sb.on("GET", "user_id=eq.", body=mine)
    sb.on("GET", "limit=50000", body=[{"total_blocks": b} for b in everyone])


@pytest.mark.parametrize("mine, everyone, percentile, bracket", [
    (10, [1, 5, 10, 20], 50, "top 50%"),
    (0, [0] * 10, 99, "top 1%"),            # capped at 99
    (5, [5] * 19 + [4], 95, "top 5%"),
    (5, [5] * 9 + [4], 90, "top 10%"),
    (5, [5] * 3 + [4], 75, "top 25%"),
    (20, [1, 5, 10, 20], 25, "bottom 50%"),
])
def test_percentile_brackets(client, sb, fake_redis, mine, everyone, percentile, bracket):
    _percentile_rows(sb, [{"total_blocks": mine}], everyone)
    body = client.get("/api/v1/user/percentile").json()
    assert body == {"percentile": percentile, "total_blocks": mine, "bracket": bracket}
    # Queries filter on the real column and are bounded.
    for call in sb.to("GET", "/rest/v1/weekly_aggregates"):
        assert "week_start=eq." in call["url"] and "&week=" not in call["url"]
    assert f"user_id=eq.{USER.id}" in sb.to("GET", "user_id=eq.")[0]["url"]
    # Result cached for the user.
    assert f"percentile:{USER.id}" in fake_redis._kv


def test_percentile_with_no_data_this_week(client, sb):
    _percentile_rows(sb, [], [])
    assert client.get("/api/v1/user/percentile").json() == {
        "percentile": 50, "total_blocks": 0, "bracket": "top 50%",
    }


def test_percentile_served_from_cache_without_database_reads(client, sb, fake_redis):
    import asyncio
    import json

    cached = {"percentile": 91, "total_blocks": 4, "bracket": "top 10%"}
    asyncio.run(fake_redis.setex(f"percentile:{USER.id}", 3600, json.dumps(cached)))
    assert client.get("/api/v1/user/percentile").json() == cached
    assert sb.calls == []


def test_percentile_still_computes_when_redis_is_down(client, sb, redis_down):
    _percentile_rows(sb, [{"total_blocks": 10}], [1, 5, 10, 20])
    assert client.get("/api/v1/user/percentile").json()["percentile"] == 50


@pytest.mark.parametrize("failure", [
    {"exc": httpx.ReadTimeout("slow")},
    {"status": 500, "body": {"message": "boom"}},
])
def test_percentile_upstream_failure_is_a_neutral_placeholder(client, sb, failure):
    sb.on("GET", "/rest/v1/weekly_aggregates", **failure)
    assert client.get("/api/v1/user/percentile").json() == {
        "percentile": 50, "total_blocks": 0, "bracket": "calculating...",
    }


def test_percentile_without_database_is_an_estimate(client, no_db):
    assert client.get("/api/v1/user/percentile").json()["bracket"] == "top 25%"


# ─── POST /device (legacy) ───────────────────────────────────────


def test_legacy_device_rejects_a_malformed_install_id(client, account_store, sb):
    resp = client.post("/api/v1/user/device", json={"device_hash": "short", "platform": "ios"})
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "invalid_device_id"
    assert account_store.register_calls == []


def test_legacy_device_unlinked_install_is_403(client, account_store, sb):
    account_store.add_device(USER.id, "legacy-install-revoked-1", revoked_at="2026-10-01T00:00:00+00:00")
    resp = client.post("/api/v1/user/device", json={"device_hash": "legacy-install-revoked-1", "platform": "chrome"})
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "device_revoked"


def test_legacy_device_store_outage_is_503_not_ok(client, account_store, sb):
    account_store.fail = True
    resp = client.post("/api/v1/user/device", json={"device_hash": "legacy-install-outage-1", "platform": "ios"})
    assert resp.status_code == 503
    assert resp.json()["detail"]["code"] == "account_unavailable"
    assert account_store.devices == []


# ─── GET/PUT /settings ───────────────────────────────────────────

_DEFAULTS = {"skill_level": "regular", "preferred_locale": "en", "voice_alerts_enabled": False,
             "font_scale": 1.0, "parental_pin_set": False}


@pytest.mark.parametrize("route", [
    {"status": 500, "body": {"message": "boom"}},
    {"status": 200, "body": []},
    {"status": 200, "body": [{"skill_level": "wizard"}]},
    {"status": 200, "body": [{"font_scale": "huge"}]},
])
def test_settings_read_problems_fall_back_to_defaults(client, sb, route):
    sb.on("GET", "/rest/v1/users", **route)
    resp = client.get("/api/v1/user/settings")
    assert resp.status_code == 200
    assert resp.json() == _DEFAULTS


def test_settings_read_is_scoped_and_never_returns_the_pin_hash(client, sb):
    sb.on("GET", "/rest/v1/users", body=[{"skill_level": "granny", "parental_pin_hash": "$2b$12$secret"}])
    body = client.get("/api/v1/user/settings").json()
    assert body["skill_level"] == "granny" and body["parental_pin_set"] is True
    assert "secret" not in str(body)
    assert sb.to("GET", "/rest/v1/users")[0]["params"]["id"] == f"eq.{USER.id}"


def test_settings_update_rejected_upstream_is_500(client, sb):
    sb.on("PATCH", "/rest/v1/users", status=400)
    resp = client.put("/api/v1/user/settings", json={"skill_level": "pro"})
    assert resp.status_code == 500


def test_settings_update_without_pin_writes_no_audit_row(client, sb):
    resp = client.put("/api/v1/user/settings", json={"skill_level": "pro", "voice_alerts_enabled": True})
    assert resp.status_code == 200
    (patch,) = sb.to("PATCH", "/rest/v1/users")
    assert patch["params"] == {"id": f"eq.{USER.id}"}
    assert patch["json"] == {"skill_level": "pro", "voice_alerts_enabled": True}
    assert sb.to("POST", "/rest/v1/audit_log") == []


def test_settings_update_with_nothing_to_change_does_not_write(client, sb):
    assert client.put("/api/v1/user/settings", json={}).status_code == 200
    assert sb.writes() == []


def test_settings_update_without_database_is_503(client, no_db):
    assert client.put("/api/v1/user/settings", json={"skill_level": "pro"}).status_code == 503


# ─── GET /profile ────────────────────────────────────────────────


def test_profile_counts_linked_devices_of_this_user_only(client, sb):
    sb.on("GET", "/rest/v1/devices", status=206, headers={"Content-Range": "0-0/3"})
    sb.on("GET", "/rest/v1/users", body=[{"created_at": "2026-01-02T03:04:05+00:00"}])
    resp = client.get("/api/v1/user/profile")
    assert resp.json() == {"id": USER.id, "email": USER.email, "tier": "free", "devices": 3,
                           "member_since": "2026-01-02T03:04:05+00:00"}
    (dev,) = sb.to("GET", "/rest/v1/devices")
    assert dev["params"] == {"user_id": f"eq.{USER.id}", "revoked_at": "is.null", "select": "id"}
    assert sb.to("GET", "/rest/v1/users")[0]["params"]["id"] == f"eq.{USER.id}"


def test_profile_survives_one_failed_lookup(client, sb):
    sb.on("GET", "/rest/v1/devices", exc=httpx.ReadTimeout("slow"))
    sb.on("GET", "/rest/v1/users", body=[{"created_at": "2026-01-02T03:04:05+00:00"}])
    body = client.get("/api/v1/user/profile").json()
    assert body["devices"] == 0 and body["member_since"] == "2026-01-02T03:04:05+00:00"


@pytest.mark.parametrize("content_range", ["*/*", "0-0", ""])
def test_profile_unreadable_count_is_zero(client, sb, content_range):
    sb.on("GET", "/rest/v1/devices", headers={"Content-Range": content_range})
    sb.on("GET", "/rest/v1/users", status=500, body={"message": "boom"})
    body = client.get("/api/v1/user/profile").json()
    assert body["devices"] == 0 and body["member_since"] is None


@pytest.mark.parametrize("users_body", [b"<html>502 Bad Gateway</html>", [], [{"created_at": None}]])
def test_profile_odd_users_answer_leaves_member_since_empty(client, sb, users_body):
    sb.on("GET", "/rest/v1/devices", status=206, headers={"Content-Range": "0-0/2"})
    sb.on("GET", "/rest/v1/users", body=users_body)
    resp = client.get("/api/v1/user/profile")
    assert resp.status_code == 200
    assert resp.json()["devices"] == 2 and resp.json()["member_since"] is None


def test_profile_without_database(client, no_db):
    body = client.get("/api/v1/user/profile").json()
    assert body["devices"] == 0 and body["member_since"] is None and body["id"] == USER.id


# ─── threats counter ─────────────────────────────────────────────


def test_threat_status_read_failure_is_an_ungated_zero(client, sb):
    sb.on("GET", "/rest/v1/user_settings", status=503, body={"message": "down"})
    body = client.get("/api/v1/user/threats/status").json()
    assert body["threats_blocked_lifetime"] == 0 and body["gated"] is False


def test_threat_increment_not_persisted_is_500(client, sb):
    sb.on("GET", "/rest/v1/user_settings", body=[{"threats_blocked_lifetime": 49}])
    sb.on("POST", "/rest/v1/user_settings", status=409)
    resp = client.post("/api/v1/user/threats/increment", json={"count": 1})
    assert resp.status_code == 500
    (write,) = sb.to("POST", "/rest/v1/user_settings")
    assert write["json"]["user_id"] == USER.id and write["json"]["threats_blocked_lifetime"] == 50


# ─── device skill: effective / overrides ─────────────────────────

DEVICE = "device-hash-0001"


def test_effective_skill_falls_back_to_safe_defaults_when_reads_fail(client, sb):
    sb.on("GET", "/rest/v1/users", status=500, body={"message": "boom"})
    sb.on("GET", "/rest/v1/devices", status=401, body={"message": "jwt"})
    body = client.get(f"/api/v1/user/device/{DEVICE}/effective").json()
    assert body == {"device_hash": DEVICE, "skill_level": "regular", "voice_alerts_enabled": False,
                    "font_scale": 1.0, "skill_source": "user_default", "voice_source": "user_default",
                    "font_source": "user_default"}


def test_effective_skill_reads_overrides_of_this_users_device_only(client, sb):
    sb.on("GET", "/rest/v1/devices", body=[{"skill_level_override": "granny", "voice_alerts_enabled": True,
                                            "font_scale": 1.6}])
    body = client.get(f"/api/v1/user/device/{DEVICE}/effective").json()
    assert body["skill_level"] == "granny" and body["font_scale"] == 1.6
    assert body["skill_source"] == body["voice_source"] == body["font_source"] == "device_override"
    (read,) = sb.to("GET", "/rest/v1/devices")
    assert read["params"]["user_id"] == f"eq.{USER.id}" and read["params"]["device_hash"] == f"eq.{DEVICE}"


def test_effective_skill_without_database(client, no_db):
    assert client.get(f"/api/v1/user/device/{DEVICE}/effective").json()["skill_level"] == "regular"


def test_clearing_overrides_resets_them_on_this_users_device_only(client, sb):
    resp = client.patch(f"/api/v1/user/device/{DEVICE}/overrides",
                        json={"clear_overrides": True, "skill_level_override": "kids"})
    assert resp.status_code == 200
    (patch,) = sb.to("PATCH", "/rest/v1/devices")
    # clear wins over any field sent with it
    assert patch["json"] == {"skill_level_override": None, "voice_alerts_enabled": False, "font_scale": 1.0}
    # Authorization is the filter: another account's device with the same hash is never matched.
    assert patch["params"] == {"user_id": f"eq.{USER.id}", "device_hash": f"eq.{DEVICE}"}


def test_partial_override_writes_only_the_fields_sent(client, sb):
    client.patch(f"/api/v1/user/device/{DEVICE}/overrides", json={"voice_alerts_enabled": True, "font_scale": 2.5})
    (patch,) = sb.to("PATCH", "/rest/v1/devices")
    assert patch["json"] == {"voice_alerts_enabled": True, "font_scale": 2.5}


def test_override_with_nothing_to_change_does_not_write(client, sb):
    assert client.patch(f"/api/v1/user/device/{DEVICE}/overrides", json={}).status_code == 200
    assert sb.writes() == []


@pytest.mark.parametrize("font", [0.79, 2.51])
def test_override_font_scale_bounds(client, sb, font):
    assert client.patch(f"/api/v1/user/device/{DEVICE}/overrides", json={"font_scale": font}).status_code == 422
    assert sb.calls == []


def test_override_rejected_upstream_is_500(client, sb):
    sb.on("PATCH", "/rest/v1/devices", status=400)
    resp = client.patch(f"/api/v1/user/device/{DEVICE}/overrides", json={"skill_level_override": "pro"})
    assert resp.status_code == 500


def test_override_without_database_is_503(client, no_db):
    assert client.patch(f"/api/v1/user/device/{DEVICE}/overrides", json={"font_scale": 1.2}).status_code == 503


# ─── POST /welcome ───────────────────────────────────────────────


class _Mailer:
    def __init__(self, ok=True, skipped=False, skip_reason=None, exc=None):
        self.sent: list[dict] = []
        self.ok, self.skipped, self.skip_reason, self.exc = ok, skipped, skip_reason, exc

    async def __call__(self, **kw):
        from api.services.email import SendResult

        self.sent.append(kw)
        if self.exc:
            raise self.exc
        return SendResult(ok=self.ok, provider_message_id=None, error=None, send_id="s-1",
                          skipped=self.skipped, skip_reason=self.skip_reason)


@pytest.fixture
def mailer(monkeypatch):
    m = _Mailer()
    monkeypatch.setattr("api.services.email.send_template", m)
    return m


def test_welcome_sends_in_the_users_locale_and_keeps_other_settings(client, sb, mailer):
    sb.on("GET", "/rest/v1/user_settings",
          body=[{"settings": {"theme": "dark", "email_optout": {"weekly_report": True}}}])
    sb.on("GET", "/rest/v1/users", body=[{"preferred_locale": "ru"}])

    assert client.post("/api/v1/user/welcome").json() == {"sent": True, "reason": None}

    (mail,) = mailer.sent
    assert mail["locale"] == "ru" and mail["to"] == USER.email and mail["template"] == "welcome"
    assert mail["unsubscribe_url"].startswith("https://cleanway.ai/api/v1/email/unsubscribe/")
    # The locale column lives on users (migration 003), not user_settings.
    assert sb.to("GET", "/rest/v1/user_settings")[0]["params"]["select"] == "settings"
    assert sb.to("GET", "/rest/v1/users")[0]["params"]["id"] == f"eq.{USER.id}"
    (write,) = sb.to("POST", "/rest/v1/user_settings")
    saved = write["json"]["settings"]
    assert saved["theme"] == "dark" and saved["email_optout"] == {"weekly_report": True}
    assert saved["welcome_sent_at"]
    assert write["json"]["user_id"] == USER.id


def test_welcome_is_sent_only_once(client, sb, mailer):
    sb.on("GET", "/rest/v1/user_settings", body=[{"settings": {"welcome_sent_at": "2026-10-01T00:00:00+00:00"}}])
    assert client.post("/api/v1/user/welcome").json() == {"sent": False, "reason": "already_sent"}
    assert mailer.sent == [] and sb.writes() == []


@pytest.mark.parametrize("failure", [{"status": 400, "body": {"message": "bad column"}},
                                     {"exc": httpx.ReadTimeout("slow")}])
def test_welcome_unreadable_settings_neither_sends_nor_overwrites(client, sb, mailer, failure):
    # Sending blind would repeat on every sign-in, and the upsert would replace
    # the whole settings JSONB — dropping the user's email opt-outs.
    sb.on("GET", "/rest/v1/user_settings", **failure)
    assert client.post("/api/v1/user/welcome").json() == {"sent": False, "reason": "storage_unavailable"}
    assert mailer.sent == [] and sb.writes() == []


def test_welcome_locale_lookup_failure_defaults_to_english(client, sb, mailer):
    sb.on("GET", "/rest/v1/users", status=500, body={"message": "boom"})
    assert client.post("/api/v1/user/welcome").json()["sent"] is True
    assert mailer.sent[0]["locale"] == "en"


def test_welcome_send_exception_is_retried_next_time(client, sb, monkeypatch):
    monkeypatch.setattr("api.services.email.send_template", _Mailer(exc=RuntimeError("smtp down")))
    assert client.post("/api/v1/user/welcome").json() == {"sent": False, "reason": "send_error"}
    assert sb.writes() == []  # welcome_sent_at not marked


def test_welcome_provider_failure_is_not_marked_sent(client, sb, monkeypatch):
    monkeypatch.setattr("api.services.email.send_template", _Mailer(ok=False))
    assert client.post("/api/v1/user/welcome").json() == {"sent": False, "reason": "send_failed"}
    assert sb.writes() == []


def test_welcome_suppressed_send_is_reported_as_not_sent(client, sb, monkeypatch):
    monkeypatch.setattr("api.services.email.send_template", _Mailer(skipped=True, skip_reason="user_unsubscribed"))
    assert client.post("/api/v1/user/welcome").json() == {"sent": False, "reason": "user_unsubscribed"}


def test_welcome_persist_failure_still_answers(client, sb, mailer):
    sb.on("POST", "/rest/v1/user_settings", status=500)
    assert client.post("/api/v1/user/welcome").json()["sent"] is True


def test_welcome_without_database(client, no_db, mailer):
    assert client.post("/api/v1/user/welcome").json() == {"sent": False, "reason": "storage_unavailable"}
    assert mailer.sent == []

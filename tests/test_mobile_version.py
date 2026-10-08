"""GET /api/v1/mobile/version — the Android update check for sideloaded users."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api.main import app


def test_version_shape_and_cache():
    r = TestClient(app).get("/api/v1/mobile/version")
    assert r.status_code == 200
    body = r.json()
    for k in ("latest_version_code", "latest_version_name", "min_supported_version_code",
              "min_supported_version_name"):
        assert k in body, k
    assert isinstance(body["latest_version_code"], int)
    assert "apk_url" in body and "release_notes" in body  # nullable
    assert "max-age" in r.headers.get("cache-control", "")


def test_defaults_dont_force_a_spurious_update():
    """Out of the box (nothing configured) min_supported must be 0 so a fresh
    install is never told it's too old."""
    body = TestClient(app).get("/api/v1/mobile/version").json()
    assert body["min_supported_version_code"] <= body["latest_version_code"]


def test_env_overrides_are_reflected(monkeypatch):
    from api import config
    settings = config.get_settings()
    monkeypatch.setattr(settings, "mobile_latest_version_code", 130, raising=False)
    monkeypatch.setattr(settings, "mobile_apk_url", "https://get.cleanway.ai/cleanway-130.apk", raising=False)
    body = TestClient(app).get("/api/v1/mobile/version").json()
    assert body["latest_version_code"] == 130
    assert body["apk_url"] == "https://get.cleanway.ai/cleanway-130.apk"


# ── remote_config: the SMS text model kill switch ─────────────────────────


def test_remote_config_defaults_keep_the_model_on():
    """Nothing configured → model on, no overrides. The phone reads a missing
    block as "keep what you had", so the default answer must be the safe ON."""
    body = TestClient(app).get("/api/v1/mobile/version").json()
    assert body["remote_config"] == {
        "sms_text_model_enabled": True,
        "sms_text_model_caution_threshold_override": None,
        "sms_text_model_danger_threshold_override": None,
    }


def test_remote_config_follows_settings(monkeypatch):
    from api import config
    settings = config.get_settings()
    monkeypatch.setattr(settings, "sms_text_model_enabled", False, raising=False)
    monkeypatch.setattr(settings, "sms_text_model_danger_threshold_override", 0.97, raising=False)
    rc = TestClient(app).get("/api/v1/mobile/version").json()["remote_config"]
    assert rc["sms_text_model_enabled"] is False
    assert rc["sms_text_model_danger_threshold_override"] == 0.97
    assert rc["sms_text_model_caution_threshold_override"] is None


def test_kill_switch_env_vars_are_read(monkeypatch):
    """The exact env names ops sets in Railway."""
    from api.config import Settings
    monkeypatch.setenv("SMS_TEXT_MODEL_ENABLED", "false")
    monkeypatch.setenv("SMS_TEXT_MODEL_CAUTION_THRESHOLD_OVERRIDE", "0.9")
    monkeypatch.setenv("SMS_TEXT_MODEL_DANGER_THRESHOLD_OVERRIDE", "0.95")
    s = Settings(_env_file=None)
    assert s.sms_text_model_enabled is False
    assert s.sms_text_model_caution_threshold_override == 0.9
    assert s.sms_text_model_danger_threshold_override == 0.95


@pytest.mark.parametrize("raw", ["", "  ", "abc", "0", "1", "1.5", "-0.2", "nan", "inf"])
def test_bad_threshold_override_is_ignored_not_fatal(monkeypatch, raw):
    """A typo in a kill-switch env var must not stop the API from booting."""
    from api.config import Settings
    monkeypatch.setenv("SMS_TEXT_MODEL_DANGER_THRESHOLD_OVERRIDE", raw)
    assert Settings(_env_file=None).sms_text_model_danger_threshold_override is None

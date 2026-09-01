"""GET /api/v1/mobile/version — the Android update check for sideloaded users."""
from __future__ import annotations

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

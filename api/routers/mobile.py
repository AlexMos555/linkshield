"""Android app version / update check.

Sideloaded users (the Tele2 direct-APK funnel) have no store to push updates,
so the app asks here on launch whether a newer build exists and, if the running
build is below the minimum supported version, prompts a required update. Values
come from settings (env), so the founder bumps them at release time with no code
deploy. Public, cacheable, tiny — no per-IP limit for the same CGNAT reason as
the blocklist endpoint.
"""
from __future__ import annotations

from fastapi import APIRouter, Response

from api.config import get_settings

router = APIRouter(prefix="/api/v1/mobile", tags=["mobile"])


@router.get("/version")
async def mobile_version(response: Response) -> dict:
    s = get_settings()
    response.headers["Cache-Control"] = "public, max-age=900"
    return {
        "latest_version_code": s.mobile_latest_version_code,
        "latest_version_name": s.mobile_latest_version_name,
        "min_supported_version_code": s.mobile_min_supported_version_code,
        "min_supported_version_name": s.mobile_min_supported_version_name or None,
        "apk_url": s.mobile_apk_url or None,
        "release_notes": s.mobile_release_notes or None,
    }
